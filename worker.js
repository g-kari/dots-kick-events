// dots-kick-events — MCP Events server that wakes dots (ChatGPT) via webhooks.
//
// Implements the OpenAI "MCP Events" guide:
//   https://developers.openai.com/plugins/build/mcp-events
// - Advertises `events` capability via `initialize` (Streamable HTTP) and
//   `server/discover` (MCP 2.0, protocol 2026-07-28).
// - events/list, events/subscribe (with signed callback challenge verification),
//   events/unsubscribe on the same MCP endpoint as the tools.
// - Webhook delivery uses Standard Webhooks signatures (HMAC-SHA256).
// - Requests ("依頼") are persisted with delivered/acknowledged/completed
//   states so dots can reconcile unfinished work via tools.
//
// Authorization (OAuth 2.1, MCP authorization spec
// https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization):
// - The MCP endpoint is a protected resource. Every /mcp call needs a Bearer
//   access token; unauthenticated calls get 401 + WWW-Authenticate pointing
//   at the RFC 9728 protected-resource metadata.
// - A minimal authorization server is hosted on the same origin (the spec
//   allows the AS to be hosted with the resource server): RFC 8414 metadata,
//   RFC 7591 dynamic client registration, authorization-code flow with
//   mandatory PKCE (S256), RFC 9207 `iss` in authorization responses,
//   rotating refresh tokens, RFC 7009 revocation. The single resource owner
//   signs in with a password (hash in a Worker secret) and consents on a
//   page served by this Worker — no external IdP tenant is required. See
//   README.md "認証（OAuth 2.1）" for the rationale and trade-offs.
// - Access/refresh tokens are opaque, stored (hashed) in the Durable Object,
//   and validated on every request: issuer, audience (= this resource),
//   expiry, token kind, and per-method scope. Subscriptions are bound to the
//   token's principal; one principal cannot touch another's subscription.
// - POST /trigger is a separate machine-to-machine admin endpoint. It is NOT
//   part of the OAuth flow: it authenticates with TRIGGER_KEY only. The
//   requester identity therefore comes from possession of that key, never
//   from fields inside the payload. (The whsec_ webhook signature, in turn,
//   only proves a delivery came from this server — it says nothing about who
//   originally filed the request.)
//
// Storage: a single Durable Object ("Store", SQLite-backed) holds
// subscriptions, requests, OAuth clients, authorization codes and tokens.
// (This Cloudflare connection has no KV/D1 permissions, so storage lives
// inside the Worker platform itself.)
//
// Bindings:
//   STORE              — Durable Object namespace (class Store)
//   TRIGGER_KEY        — secret text; admin key for POST /trigger
//   OWNER_PASSWORD_HASH— secret text; hex SHA-256 of the owner's login
//                        password for the OAuth consent flow (set by owner)
//   AUTH_SECRET        — secret text; HMAC key for owner session cookies
//   TEST_ECHO          — optional plain var; when "1", enables POST /test-echo
//   TEST_ECHO_SECRET   — optional plain var; throwaway whsec_ used only by /test-echo

import { DurableObject } from "cloudflare:workers";

const EVENT_NAME = "kick";
const SERVER_NAME = "dots-kick-events";
const SERVER_VERSION = "1.1.0";
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MIN_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const VERIFY_CACHE_MS = 24 * 60 * 60 * 1000; // 24 hours
const PREV_SECRET_WINDOW_MS = 10 * 60 * 1000; // sign with old+new key briefly after rotation
const MAX_BODY_BYTES = 256 * 1024;

// ---------- OAuth constants ----------

// The one and only resource owner. Only a person who knows the owner
// password can complete the consent flow, so every issued token carries
// this principal. (Multi-user support is intentionally out of scope.)
const OWNER_PRINCIPAL = "owner";
const LEGACY_PRINCIPAL = "anonymous"; // pre-OAuth subscriptions (test data)

// Scopes (least privilege per operation; all are listed in the metadata and
// in the WWW-Authenticate challenge so clients request exactly these).
const SCOPES = [
  "events:read", // events/list
  "events:subscribe", // events/subscribe, events/unsubscribe
  "requests:read", // tools/call list_pending_requests
  "requests:update", // tools/call update_request_status
];
const SCOPE_DESCRIPTIONS = {
  "events:read": "イベント定義（kick）の読み取り",
  "events:subscribe": "kick イベントの購読・解除",
  "requests:read": "未完了の依頼の一覧取得",
  "requests:update": "依頼の受領・完了ステータス更新",
};
const AUTH_CODE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const PENDING_AUTHZ_TTL_MS = 10 * 60 * 1000; // 10 minutes
const ACCESS_TOKEN_TTL_MS = 60 * 60 * 1000; // 1 hour
const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const SESSION_TTL_MS = 30 * 60 * 1000; // 30 minutes

const KICK_EVENT = {
  name: EVENT_NAME,
  description:
    "A wake-up request for dots. Fired when a new request (依頼) is registered for dots; the payload carries the request id and text so dots can start working on it and reconcile its state with the list_pending_requests / update_request_status tools.",
  delivery: ["webhook"],
  inputSchema: {
    type: "object",
    properties: {
      topic: {
        type: "string",
        description:
          "Optional topic filter. When set, only requests whose topic matches are delivered. When omitted, all requests are delivered.",
      },
    },
    required: [],
    additionalProperties: false,
  },
  payloadSchema: {
    type: "object",
    properties: {
      request_id: { type: "string" },
      text: { type: "string" },
      topic: { type: "string" },
      created_at: { type: "string" },
    },
    required: ["request_id", "text", "created_at"],
    additionalProperties: false,
  },
};

const TOOLS = [
  {
    name: "list_pending_requests",
    description:
      "List requests (依頼) that are not completed yet, newest first. Use this to reconcile work that may have been missed while offline. Each request has a status: pending (not yet delivered), delivered (webhook acknowledged), acknowledged (dots marked receipt).",
    inputSchema: {
      type: "object",
      properties: {
        limit: {
          type: "integer",
          minimum: 1,
          maximum: 100,
          description: "Maximum number of requests to return (default 20).",
        },
      },
      required: [],
      additionalProperties: false,
    },
  },
  {
    name: "update_request_status",
    description:
      "Mark a request as acknowledged (received / being worked on) or completed (done). Idempotent: repeating the same update is safe.",
    inputSchema: {
      type: "object",
      properties: {
        request_id: { type: "string", description: "The request id, e.g. req_..." },
        status: {
          type: "string",
          enum: ["acknowledged", "completed"],
          description: "New status for the request.",
        },
        note: {
          type: "string",
          description: "Optional free-text note stored with the update.",
        },
      },
      required: ["request_id", "status"],
      additionalProperties: false,
    },
  },
];

// ---------- Durable Object storage ----------

export class Store extends DurableObject {
  async fetch(request) {
    const url = new URL(request.url);
    const s = this.ctx.storage;
    if (url.pathname === "/get") {
      const v = await s.get(url.searchParams.get("key"));
      return v === undefined
        ? new Response(null, { status: 404 })
        : new Response(v, { headers: { "Content-Type": "text/plain" } });
    }
    if (url.pathname === "/put") {
      const { key, value } = await request.json();
      await s.put(key, value);
      return new Response("ok");
    }
    if (url.pathname === "/delete") {
      const { key } = await request.json();
      await s.delete(key);
      return new Response("ok");
    }
    if (url.pathname === "/list") {
      const map = await s.list({ prefix: url.searchParams.get("prefix") || "" });
      return Response.json({ keys: [...map.keys()] });
    }
    if (url.pathname === "/take") {
      // Atomic get+delete (single-use values: authorization codes, refresh
      // tokens). blockConcurrencyWhile makes the pair indivisible even if
      // two callers race.
      const key = url.searchParams.get("key");
      let v;
      await this.ctx.blockConcurrencyWhile(async () => {
        v = await s.get(key);
        if (v !== undefined) await s.delete(key);
      });
      return v === undefined
        ? new Response(null, { status: 404 })
        : new Response(v, { headers: { "Content-Type": "text/plain" } });
    }
    if (url.pathname === "/create") {
      // Atomic put-if-absent. Used for client-supplied request_id dedup so a
      // retried /trigger can never create (and deliver) the same request
      // twice, even when two sends arrive at the same time.
      const { key, value } = await request.json();
      let created = false;
      let current = value;
      await this.ctx.blockConcurrencyWhile(async () => {
        const existing = await s.get(key);
        if (existing === undefined) {
          await s.put(key, value);
          created = true;
        } else {
          current = existing;
        }
      });
      return Response.json({ created, value: current });
    }
    return new Response("not found", { status: 404 });
  }
}

// Thin KV-like adapter over the single global Store instance.
function store(env) {
  const stub = env.STORE.get(env.STORE.idFromName("global"));
  return {
    async get(key) {
      const r = await stub.fetch(
        "https://store/get?key=" + encodeURIComponent(key)
      );
      if (r.status === 404) return null;
      return r.text();
    },
    async put(key, value) {
      await stub.fetch("https://store/put", {
        method: "POST",
        body: JSON.stringify({ key, value }),
      });
    },
    async delete(key) {
      await stub.fetch("https://store/delete", {
        method: "POST",
        body: JSON.stringify({ key }),
      });
    },
    async listKeys(prefix) {
      const r = await stub.fetch(
        "https://store/list?prefix=" + encodeURIComponent(prefix)
      );
      const j = await r.json();
      return j.keys || [];
    },
    // Atomically fetch-and-delete a key; returns the value or null.
    async take(key) {
      const r = await stub.fetch(
        "https://store/take?key=" + encodeURIComponent(key)
      );
      if (r.status === 404) return null;
      return r.text();
    },
    // Atomically store only if absent; returns { created, value } where
    // value is the stored (possibly pre-existing) record.
    async create(key, value) {
      const r = await stub.fetch("https://store/create", {
        method: "POST",
        body: JSON.stringify({ key, value }),
      });
      return r.json();
    },
  };
}

// ---------- small helpers ----------

function jsonResponse(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...extraHeaders },
  });
}

function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id, code, message, data) {
  const err = { code, message };
  if (data !== undefined) err.data = data;
  return { jsonrpc: "2.0", id: id ?? null, error: err };
}

function canonicalJSON(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJSON).join(",") + "]";
  const keys = Object.keys(value).sort();
  return (
    "{" +
    keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(value[k])).join(",") +
    "}"
  );
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text)
  );
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64encode(bytes) {
  let s = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

function b64decode(str) {
  const bin = atob(String(str).trim());
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function b64urlEncode(bytes) {
  return b64encode(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlDecode(str) {
  let s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return b64decode(s);
}

function randomToken(prefix) {
  return prefix + b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
}

// Constant-time string comparison (for challenges / admin key / hashes).
function timingSafeEqualStr(a, b) {
  const ea = new TextEncoder().encode(String(a));
  const eb = new TextEncoder().encode(String(b));
  let diff = ea.length ^ eb.length;
  const len = Math.max(ea.length, eb.length);
  for (let i = 0; i < len; i++) {
    diff |= (ea[i] || 0) ^ (eb[i] || 0);
  }
  return diff === 0;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------- Standard Webhooks signing ----------

async function hmacKey(secret) {
  const raw = b64decode(String(secret).replace(/^whsec_/, ""));
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function signBody(secret, msgId, timestampSec, body) {
  const key = await hmacKey(secret);
  const signed = new TextEncoder().encode(`${msgId}.${timestampSec}.${body}`);
  const sig = await crypto.subtle.sign("HMAC", key, signed);
  return "v1," + b64encode(new Uint8Array(sig));
}

async function verifyBody(secret, msgId, timestampSec, body, signatureHeader) {
  try {
    const key = await hmacKey(secret);
    const signed = new TextEncoder().encode(`${msgId}.${timestampSec}.${body}`);
    for (const part of String(signatureHeader || "").split(" ")) {
      const [version, b64] = part.split(",");
      if (version !== "v1" || !b64) continue;
      const ok = await crypto.subtle.verify(
        "HMAC",
        key,
        b64decode(b64),
        signed
      );
      if (ok) return true;
    }
  } catch (_) {
    /* fall through */
  }
  return false;
}

// Build the webhook-signature header, including the previous secret during
// the short rotation window (space-separated signatures, per the guide).
async function signatureHeader(subscription, msgId, timestampSec, body) {
  const parts = [await signBody(subscription.secret, msgId, timestampSec, body)];
  if (
    subscription.secretPrev &&
    subscription.secretPrevUntil &&
    Date.parse(subscription.secretPrevUntil) > Date.now()
  ) {
    parts.push(await signBody(subscription.secretPrev, msgId, timestampSec, body));
  }
  return parts.join(" ");
}

// ---------- callback URL validation (SSRF basics) ----------
// Workers fetch resolves DNS inside Cloudflare's network, so we cannot pin
// the resolved address; we enforce HTTPS and reject local/private literals.
function validateCallbackUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch (_) {
    return "invalid_url";
  }
  if (u.protocol !== "https:") return "not_https";
  const host = u.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".local") || host.endsWith(".internal"))
    return "blocked_host";
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (
      a === 0 || a === 10 || a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a >= 224
    )
      return "private_address";
  }
  if (host.includes(":")) {
    if (
      host === "::1" ||
      host.startsWith("fe8") || host.startsWith("fe9") ||
      host.startsWith("fea") || host.startsWith("feb") ||
      host.startsWith("fc") || host.startsWith("fd") ||
      host.startsWith("::ffff:")
    )
      return "private_address";
  }
  return null;
}

async function postSigned(url, subscription, msgId, body) {
  const timestampSec = Math.floor(Date.now() / 1000);
  const signature = await signatureHeader(subscription, msgId, timestampSec, body);
  return fetch(url, {
    method: "POST",
    // Workers fetch has no redirect:"error"; "manual" + requiring 2xx gives
    // the same do-not-follow-redirects behavior the guide asks for.
    redirect: "manual",
    signal: AbortSignal.timeout(10_000),
    headers: {
      "Content-Type": "application/json",
      "webhook-id": msgId,
      "webhook-timestamp": String(timestampSec),
      "webhook-signature": signature,
      "X-MCP-Subscription-Id": subscription.id,
    },
    body,
  });
}

// ---------- subscriptions ----------
// A subscription belongs to the authenticated principal that created it: the
// principal is part of the deterministic subscription ID, and the record
// stores it, so a different principal computing the same (url, name, args)
// triple lands on a different ID and can neither read nor delete this one.

async function subscriptionId(principal, url, name, args) {
  const hash = await sha256Hex(
    [principal, url, name, canonicalJSON(args || {})].join("\n")
  );
  return "sub_" + hash.slice(0, 32);
}

async function listSubscriptions(db) {
  const subs = [];
  for (const key of await db.listKeys("sub:")) {
    const raw = await db.get(key);
    if (raw) {
      try {
        subs.push(JSON.parse(raw));
      } catch (_) {
        /* ignore corrupt record */
      }
    }
  }
  return subs;
}

function grantedTtlMs(ttlMs) {
  if (ttlMs === undefined) return DEFAULT_TTL_MS;
  if (ttlMs === null) return MAX_TTL_MS; // never grant infinite; return finite expiration
  if (typeof ttlMs === "number" && Number.isFinite(ttlMs)) {
    return Math.min(Math.max(ttlMs, MIN_TTL_MS), MAX_TTL_MS);
  }
  return DEFAULT_TTL_MS;
}

function validateSecret(secret) {
  if (typeof secret !== "string" || !secret.startsWith("whsec_")) return false;
  try {
    const bytes = b64decode(secret.slice("whsec_".length));
    return bytes.length >= 24 && bytes.length <= 64;
  } catch (_) {
    return false;
  }
}

async function handleSubscribe(db, id, params, principal) {
  const name = params?.name;
  const args = params?.arguments ?? {};
  const delivery = params?.delivery ?? {};

  if (name !== EVENT_NAME) {
    return rpcError(id, -32602, `Unknown event: ${String(name)}`);
  }
  if (typeof args !== "object" || args === null || Array.isArray(args)) {
    return rpcError(id, -32602, "arguments must be an object");
  }
  for (const key of Object.keys(args)) {
    if (key !== "topic") {
      return rpcError(id, -32602, `Unknown filter argument: ${key}`);
    }
  }
  if (args.topic !== undefined && typeof args.topic !== "string") {
    return rpcError(id, -32602, "topic must be a string");
  }
  if (delivery.mode !== "webhook") {
    return rpcError(id, -32602, "Only webhook delivery is supported");
  }
  const urlProblem = validateCallbackUrl(delivery.url || "");
  if (urlProblem) {
    return rpcError(id, -32015, "Callback endpoint error", { reason: urlProblem });
  }
  if (!validateSecret(delivery.secret)) {
    return rpcError(
      id,
      -32602,
      "delivery.secret must be a whsec_ signing secret (24-64 bytes, base64)"
    );
  }

  const subId = await subscriptionId(principal, delivery.url, name, args);
  const existingRaw = await db.get("sub:" + subId);
  const existing = existingRaw ? JSON.parse(existingRaw) : null;

  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  const refreshBefore = new Date(now + grantedTtlMs(params?.ttlMs)).toISOString();

  const subscription = {
    id: subId,
    principal,
    name,
    arguments: args,
    callbackUrl: delivery.url,
    secret: delivery.secret,
    createdAt: existing?.createdAt || nowIso,
    updatedAt: nowIso,
    refreshBefore,
    verifiedAt: existing?.verifiedAt || null,
    verifiedUntil: existing?.verifiedUntil || null,
  };
  // Secret rotation: keep the previous secret for a short dual-sign window.
  if (existing && existing.secret && existing.secret !== delivery.secret) {
    subscription.secretPrev = existing.secret;
    subscription.secretPrevUntil = new Date(now + PREV_SECRET_WINDOW_MS).toISOString();
  } else if (existing?.secretPrev && Date.parse(existing.secretPrevUntil) > now) {
    subscription.secretPrev = existing.secretPrev;
    subscription.secretPrevUntil = existing.secretPrevUntil;
  }

  const verificationCached =
    existing &&
    existing.callbackUrl === delivery.url &&
    existing.verifiedUntil &&
    Date.parse(existing.verifiedUntil) > now;

  if (!verificationCached) {
    const challenge = b64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
    const verifyBodyText = JSON.stringify({ type: "verification", challenge });
    const verifyMsgId = "msg_verification_" + randomHex(12);
    let response;
    try {
      response = await postSigned(delivery.url, subscription, verifyMsgId, verifyBodyText);
    } catch (e) {
      return rpcError(id, -32015, "Callback endpoint error", {
        reason: e && e.name === "TimeoutError" ? "timeout" : "challenge_failed",
      });
    }
    if (!response.ok) {
      return rpcError(id, -32015, "Callback endpoint error", {
        reason: "challenge_failed",
      });
    }
    let echoed = null;
    try {
      const parsed = await response.json();
      echoed = parsed?.challenge;
    } catch (_) {
      echoed = null;
    }
    if (!echoed || !timingSafeEqualStr(echoed, challenge)) {
      return rpcError(id, -32015, "Callback endpoint error", {
        reason: "challenge_failed",
      });
    }
    subscription.verifiedAt = nowIso;
    subscription.verifiedUntil = new Date(now + VERIFY_CACHE_MS).toISOString();
  }

  await db.put("sub:" + subId, JSON.stringify(subscription));
  return rpcResult(id, {
    id: subId,
    refreshBefore,
    cursor: null,
    truncated: false,
  });
}

async function handleUnsubscribe(db, id, params, principal) {
  const name = params?.name;
  const args = params?.arguments ?? {};
  const url = params?.delivery?.url;
  if (name && url) {
    const subId = await subscriptionId(principal, url, name, args);
    const raw = await db.get("sub:" + subId);
    if (raw) {
      const record = JSON.parse(raw);
      // Ownership check (defense in depth — the ID already embeds the
      // principal): never delete a subscription owned by someone else.
      if (!record.principal || record.principal === principal) {
        await db.delete("sub:" + subId);
      }
    }
  }
  // Idempotent: always an empty result, whether or not anything matched.
  return rpcResult(id, {});
}

// ---------- requests (依頼) ----------

async function listRequests(db) {
  const out = [];
  for (const key of await db.listKeys("req:")) {
    const raw = await db.get(key);
    if (raw) {
      try {
        out.push(JSON.parse(raw));
      } catch (_) {
        /* ignore corrupt record */
      }
    }
  }
  out.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  return out;
}

async function deliverToSubscriptions(db, request) {
  const subs = await listSubscriptions(db);
  const now = Date.now();
  const results = [];
  for (const sub of subs) {
    if (sub.name !== EVENT_NAME) continue;
    // Pre-OAuth subscriptions (principal "anonymous" or missing) were
    // self-verification artifacts; they no longer receive deliveries.
    if (!sub.principal || sub.principal === LEGACY_PRINCIPAL) continue;
    if (sub.refreshBefore && Date.parse(sub.refreshBefore) <= now) continue;
    const filterTopic = sub.arguments?.topic;
    if (filterTopic && request.topic && filterTopic !== request.topic) continue;
    if (filterTopic && !request.topic) continue;

    // The eventId is deterministic per (request, subscription) and stable
    // across retries, so the receiver can dedupe re-deliveries. A webhook
    // 2xx only acknowledges receipt — completion is reported separately
    // through update_request_status.
    const eventId =
      "evt_" +
      (await sha256Hex(request.id + ":" + sub.id)).slice(0, 32);
    const data = {
      request_id: request.id,
      text: request.text,
      created_at: request.createdAt,
    };
    if (request.topic) data.topic = request.topic;
    const body = JSON.stringify({
      eventId,
      name: EVENT_NAME,
      timestamp: request.createdAt,
      data,
      cursor: null,
    });

    let ok = false;
    let status = null;
    let attempts = 0;
    for (let attempt = 0; attempt < 3 && !ok; attempt++) {
      attempts++;
      try {
        const res = await postSigned(sub.callbackUrl, sub, eventId, body);
        status = res.status;
        if (res.ok) ok = true;
        if (status === 410 || status === 413) break; // do not retry, per guide
      } catch (_) {
        status = null;
      }
      if (!ok && attempt < 2) {
        await new Promise((r) => setTimeout(r, attempt === 0 ? 500 : 1500));
      }
    }
    results.push({
      subscriptionId: sub.id,
      eventId,
      ok,
      status,
      attempts,
      at: new Date().toISOString(),
    });
  }
  return results;
}

// ---------- OAuth: identifiers, metadata, tokens ----------

// The issuer is this Worker's origin; the protected resource is the MCP
// endpoint URL on that origin. Deriving both from the request keeps the
// custom domain and workers.dev deployments consistent, and makes tokens
// issued on one origin invalid on the other (issuer/audience checks below).
function issuerOf(request) {
  return new URL(request.url).origin;
}
function resourceOf(request) {
  return issuerOf(request) + "/mcp";
}
function oauthConfigured(env) {
  return Boolean(env.OWNER_PASSWORD_HASH && env.AUTH_SECRET);
}

function protectedResourceMetadata(request) {
  return {
    resource: resourceOf(request),
    authorization_servers: [issuerOf(request)],
    scopes_supported: SCOPES,
    bearer_methods_supported: ["header"],
    resource_documentation: issuerOf(request) + "/",
  };
}

function authorizationServerMetadata(request) {
  const iss = issuerOf(request);
  return {
    issuer: iss,
    authorization_endpoint: iss + "/oauth/authorize",
    token_endpoint: iss + "/oauth/token",
    registration_endpoint: iss + "/oauth/register",
    revocation_endpoint: iss + "/oauth/revoke",
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: SCOPES,
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: false,
    service_documentation: iss + "/",
  };
}

function wwwAuthenticate(request, extra = {}) {
  const parts = [
    `Bearer resource_metadata="${issuerOf(request)}/.well-known/oauth-protected-resource/mcp"`,
  ];
  if (extra.error) parts.push(`error="${extra.error}"`);
  parts.push(`scope="${(extra.scope || SCOPES).join(" ")}"`);
  return parts.join(", ");
}

function unauthorized(request, error) {
  return jsonResponse(
    { error: error || "unauthorized" },
    401,
    {
      "WWW-Authenticate": wwwAuthenticate(request, {
        error: error ? "invalid_token" : undefined,
      }),
      "Cache-Control": "no-store",
    }
  );
}

// Tokens are opaque; only their SHA-256 hash is used as the storage key, so
// a storage leak does not leak usable credentials.
async function tokenKey(token) {
  return "token:" + (await sha256Hex(token));
}

async function issueTokenPair(db, request, { principal, clientId, scope }) {
  const now = Date.now();
  const accessToken = randomToken("at_");
  const refreshToken = randomToken("rt_");
  const base = {
    principal,
    clientId,
    scope,
    aud: resourceOf(request),
    iss: issuerOf(request),
  };
  await db.put(
    await tokenKey(accessToken),
    JSON.stringify({
      ...base,
      kind: "access",
      exp: now + ACCESS_TOKEN_TTL_MS,
      createdAt: new Date(now).toISOString(),
    })
  );
  await db.put(
    await tokenKey(refreshToken),
    JSON.stringify({
      ...base,
      kind: "refresh",
      exp: now + REFRESH_TOKEN_TTL_MS,
      createdAt: new Date(now).toISOString(),
    })
  );
  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: Math.floor(ACCESS_TOKEN_TTL_MS / 1000),
    scope: scope.join(" "),
    refresh_token: refreshToken,
  };
}

// Validate a Bearer access token for this resource. Checks: existence,
// kind (a refresh token is not an access token), expiry, issuer, audience.
// Returns { principal, clientId, scope:Set } or null.
async function authenticate(db, request) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const token = auth.slice("Bearer ".length).trim();
  if (!token) return null;
  const raw = await db.get(await tokenKey(token));
  if (!raw) return null;
  let rec;
  try {
    rec = JSON.parse(raw);
  } catch (_) {
    return null;
  }
  if (rec.kind !== "access") return null;
  if (typeof rec.exp !== "number" || rec.exp <= Date.now()) return null;
  if (rec.iss !== issuerOf(request)) return null;
  if (rec.aud !== resourceOf(request)) return null;
  return {
    principal: rec.principal,
    clientId: rec.clientId,
    scope: new Set(Array.isArray(rec.scope) ? rec.scope : []),
  };
}

// ---------- owner session (consent flow login) ----------

async function signSession(env, payloadB64) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.AUTH_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payloadB64)
  );
  return b64urlEncode(new Uint8Array(sig));
}

async function makeSessionCookie(env) {
  const payload = b64urlEncode(
    new TextEncoder().encode(
      JSON.stringify({ sub: OWNER_PRINCIPAL, exp: Date.now() + SESSION_TTL_MS })
    )
  );
  const sig = await signSession(env, payload);
  return {
    value: payload + "." + sig,
    header: `dke_session=${payload}.${sig}; HttpOnly; Secure; SameSite=Lax; Path=/oauth; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`,
  };
}

async function hasOwnerSession(env, request) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(/(?:^|;\s*)dke_session=([^;]+)/);
  if (!m) return false;
  const [payload, sig] = m[1].split(".");
  if (!payload || !sig) return false;
  const expected = await signSession(env, payload);
  if (!timingSafeEqualStr(sig, expected)) return false;
  try {
    const data = JSON.parse(new TextDecoder().decode(b64urlDecode(payload)));
    return data.sub === OWNER_PRINCIPAL && data.exp > Date.now();
  } catch (_) {
    return false;
  }
}

// ---------- tools ----------

function toolText(obj, isError = false) {
  const result = {
    content: [{ type: "text", text: JSON.stringify(obj, null, 2) }],
  };
  if (isError) result.isError = true;
  return result;
}

async function handleToolsCall(db, id, params) {
  const name = params?.name;
  const args = params?.arguments ?? {};
  if (name === "list_pending_requests") {
    const limit = Math.min(Math.max(Number(args.limit) || 20, 1), 100);
    const all = await listRequests(db);
    const pending = all
      .filter((r) => r.status !== "completed")
      .slice(0, limit);
    return rpcResult(id, toolText({ requests: pending, count: pending.length }));
  }
  if (name === "update_request_status") {
    const requestId = args.request_id;
    const status = args.status;
    if (typeof requestId !== "string" || !requestId) {
      return rpcResult(id, toolText({ error: "request_id is required" }, true));
    }
    if (status !== "acknowledged" && status !== "completed") {
      return rpcResult(
        id,
        toolText({ error: "status must be acknowledged or completed" }, true)
      );
    }
    const raw = await db.get("req:" + requestId);
    if (!raw) {
      return rpcResult(id, toolText({ error: "request not found" }, true));
    }
    const record = JSON.parse(raw);
    record.status = status;
    record.updatedAt = new Date().toISOString();
    if (typeof args.note === "string" && args.note) {
      record.notes = record.notes || [];
      record.notes.push({ status, note: args.note, at: record.updatedAt });
    }
    await db.put("req:" + requestId, JSON.stringify(record));
    return rpcResult(id, toolText(record));
  }
  return rpcError(id, -32602, `Unknown tool: ${String(name)}`);
}

// ---------- MCP endpoint (protected resource) ----------

// Scope required per JSON-RPC method (null = any valid token). tools/call is
// resolved per tool name.
function requiredScope(msg) {
  const { method, params } = msg || {};
  switch (method) {
    case "events/list":
      return "events:read";
    case "events/subscribe":
    case "events/unsubscribe":
      return "events:subscribe";
    case "tools/call":
      if (params?.name === "list_pending_requests") return "requests:read";
      if (params?.name === "update_request_status") return "requests:update";
      return "requests:read";
    default:
      return null;
  }
}

async function handleRpc(db, msg, auth) {
  const { id, method, params } = msg || {};
  const isNotification = id === undefined || id === null;

  switch (method) {
    case "initialize": {
      const requested = params?.protocolVersion;
      const supported = ["2025-06-18", "2025-03-26", "2024-11-05"];
      return rpcResult(id, {
        protocolVersion: supported.includes(requested) ? requested : "2025-03-26",
        capabilities: { tools: {}, events: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      });
    }
    case "server/discover":
      return rpcResult(id, {
        resultType: "complete",
        supportedVersions: ["2026-07-28"],
        capabilities: { tools: {}, events: {} },
      });
    case "ping":
      return rpcResult(id, {});
    case "tools/list":
      return rpcResult(id, { tools: TOOLS });
    case "tools/call":
      return handleToolsCall(db, id, params || {});
    case "events/list":
      return rpcResult(id, { events: [KICK_EVENT] });
    case "events/subscribe":
      return handleSubscribe(db, id, params || {}, auth.principal);
    case "events/unsubscribe":
      return handleUnsubscribe(db, id, params || {}, auth.principal);
    default:
      if (isNotification) return null; // notifications need no response
      return rpcError(id, -32601, `Method not found: ${String(method)}`);
  }
}

async function handleMcp(db, request, env) {
  const text = await request.text();
  if (text.length > MAX_BODY_BYTES) {
    return jsonResponse(rpcError(null, -32600, "Request too large"), 413);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch (_) {
    return jsonResponse(rpcError(null, -32700, "Parse error"), 400);
  }

  // Every MCP call must carry a valid access token for this resource.
  const presented = (request.headers.get("Authorization") || "").startsWith("Bearer ");
  const auth = await authenticate(db, request);
  if (!auth) return unauthorized(request, presented);

  const messages = Array.isArray(parsed) ? parsed : [parsed];
  const responses = [];
  for (const msg of messages) {
    const need = requiredScope(msg);
    if (need && !auth.scope.has(need)) {
      const errBody = rpcError(msg?.id ?? null, -32003, "insufficient_scope", {
        error: "insufficient_scope",
        scope: need,
      });
      if (!Array.isArray(parsed)) {
        // Single request: signal step-up authorization at the HTTP layer.
        return jsonResponse(errBody, 403, {
          "WWW-Authenticate": wwwAuthenticate(request, {
            error: "insufficient_scope",
            scope: [need],
          }),
        });
      }
      responses.push(errBody);
      continue;
    }
    const res = await handleRpc(db, msg, auth);
    if (res) responses.push(res);
  }
  if (!Array.isArray(parsed)) {
    const isNotification = parsed.id === undefined || parsed.id === null;
    if (responses.length === 0 || isNotification) {
      return new Response(null, { status: 202 });
    }
    return jsonResponse(responses[0]);
  }
  if (responses.length === 0) return new Response(null, { status: 202 });
  return jsonResponse(responses);
}

// ---------- OAuth endpoints (authorization server) ----------

const NO_STORE = { "Cache-Control": "no-store", Pragma: "no-cache" };

function oauthJsonError(status, error, description) {
  return jsonResponse(
    { error, ...(description ? { error_description: description } : {}) },
    status,
    NO_STORE
  );
}

function htmlPage(title, bodyHtml, status = 200) {
  return new Response(
    `<!doctype html><html lang="ja"><head><meta charset="utf-8">` +
      `<meta name="viewport" content="width=device-width, initial-scale=1">` +
      `<title>${escapeHtml(title)}</title>` +
      `<style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:3rem auto;padding:0 1rem;line-height:1.6}input[type=password]{width:100%;padding:.5rem;font-size:1rem}button{padding:.5rem 1.2rem;font-size:1rem;margin:.4rem .4rem .4rem 0}.err{color:#b00020}code{background:#eee;padding:.1rem .3rem;border-radius:.25rem}li{margin:.2rem 0}</style>` +
      `</head><body>${bodyHtml}</body></html>`,
    { status, headers: { "Content-Type": "text/html; charset=utf-8", ...NO_STORE } }
  );
}

function redirectResponse(location, extraHeaders = {}) {
  return new Response(null, {
    status: 303,
    headers: { Location: location, ...NO_STORE, ...extraHeaders },
  });
}

// Error redirect to an already-validated redirect_uri (RFC 9207: always
// include iss so the client can detect authorization-server mix-ups).
function authorizeErrorRedirect(request, redirectUri, error, state, description) {
  const u = new URL(redirectUri);
  u.searchParams.set("error", error);
  if (description) u.searchParams.set("error_description", description);
  if (state) u.searchParams.set("state", state);
  u.searchParams.set("iss", issuerOf(request));
  return redirectResponse(u.toString());
}

function validRedirectUri(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch (_) {
    return false;
  }
  if (u.protocol === "https:") return true;
  // http is only acceptable for local development clients.
  if (
    u.protocol === "http:" &&
    (u.hostname === "localhost" || u.hostname === "127.0.0.1" || u.hostname === "[::1]")
  )
    return true;
  return false;
}

// --- Dynamic client registration (RFC 7591) ---
async function handleRegister(db, request) {
  let body;
  try {
    body = await request.json();
  } catch (_) {
    return oauthJsonError(400, "invalid_client_metadata", "JSON body required");
  }
  const redirectUris = body?.redirect_uris;
  if (
    !Array.isArray(redirectUris) ||
    redirectUris.length === 0 ||
    !redirectUris.every((u) => typeof u === "string" && validRedirectUri(u))
  ) {
    return oauthJsonError(
      400,
      "invalid_redirect_uri",
      "redirect_uris must be a non-empty array of https URLs (http allowed only for localhost)"
    );
  }
  const grantTypes = body?.grant_types ?? ["authorization_code"];
  if (
    !Array.isArray(grantTypes) ||
    !grantTypes.every((g) => g === "authorization_code" || g === "refresh_token")
  ) {
    return oauthJsonError(400, "invalid_client_metadata", "unsupported grant_types");
  }
  if (body?.response_types !== undefined) {
    const rt = body.response_types;
    if (!Array.isArray(rt) || !rt.every((r) => r === "code")) {
      return oauthJsonError(400, "invalid_client_metadata", "only response_type=code is supported");
    }
  }
  const authMethod = body?.token_endpoint_auth_method ?? "none";
  if (authMethod !== "none") {
    return oauthJsonError(
      400,
      "invalid_client_metadata",
      "only token_endpoint_auth_method=none (public client + PKCE) is supported"
    );
  }
  let scope = SCOPES;
  if (typeof body?.scope === "string" && body.scope.trim()) {
    scope = body.scope.split(" ").filter((s) => SCOPES.includes(s));
    if (scope.length === 0) {
      return oauthJsonError(400, "invalid_client_metadata", "no supported scope requested");
    }
  }
  const clientId = "client_" + randomHex(16);
  const record = {
    clientId,
    clientName: typeof body?.client_name === "string" ? body.client_name.slice(0, 128) : null,
    redirectUris,
    grantTypes,
    scope,
    createdAt: new Date().toISOString(),
  };
  await db.put("client:" + clientId, JSON.stringify(record));
  return jsonResponse(
    {
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: record.clientName,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: ["code"],
      token_endpoint_auth_method: "none",
      scope: scope.join(" "),
    },
    201,
    NO_STORE
  );
}

// --- Authorization endpoint: owner login + consent ---
function loginPage(pendingId, errorMessage) {
  return htmlPage(
    "dots-kick-events ログイン",
    `<h1>dots-kick-events</h1>` +
      `<p>接続を許可するには、所有者パスワードでログインしてください。</p>` +
      (errorMessage ? `<p class="err">${escapeHtml(errorMessage)}</p>` : "") +
      `<form method="post" action="/oauth/login">` +
      `<input type="hidden" name="pending" value="${escapeHtml(pendingId)}">` +
      `<p><input type="password" name="password" autocomplete="current-password" required autofocus></p>` +
      `<p><button type="submit">ログイン</button></p></form>`
  );
}

function consentPage(pending, client) {
  const scopeItems = pending.scope
    .map((s) => `<li><code>${escapeHtml(s)}</code> — ${escapeHtml(SCOPE_DESCRIPTIONS[s] || "")}</li>`)
    .join("");
  let redirectHost = pending.redirectUri;
  try {
    redirectHost = new URL(pending.redirectUri).host;
  } catch (_) {
    /* keep raw */
  }
  return htmlPage(
    "接続の許可 — dots-kick-events",
    `<h1>接続の許可</h1>` +
      `<p>クライアント <strong>${escapeHtml(client.clientName || client.clientId)}</strong> が ` +
      `この MCP サーバー（<code>${escapeHtml(pending.resource)}</code>）への接続を求めています。</p>` +
      `<p>許可すると次の権限が付与されます:</p><ul>${scopeItems}</ul>` +
      `<p>認可後の戻り先: <code>${escapeHtml(redirectHost)}</code></p>` +
      `<form method="post" action="/oauth/consent">` +
      `<input type="hidden" name="pending" value="${escapeHtml(pending.id)}">` +
      `<input type="hidden" name="csrf" value="${escapeHtml(pending.csrf)}">` +
      `<p><button type="submit" name="decision" value="approve">許可する</button>` +
      `<button type="submit" name="decision" value="deny">拒否する</button></p></form>`
  );
}

async function loadPending(db, pendingId) {
  if (typeof pendingId !== "string" || !pendingId) return null;
  const raw = await db.get("authz:" + pendingId);
  if (!raw) return null;
  try {
    const p = JSON.parse(raw);
    if (p.expiresAt <= Date.now()) return null;
    return p;
  } catch (_) {
    return null;
  }
}

async function handleAuthorize(env, db, request) {
  const url = new URL(request.url);
  let pending;
  const pendingId = url.searchParams.get("pending");
  if (pendingId) {
    pending = await loadPending(db, pendingId);
    if (!pending) {
      return htmlPage("エラー", `<h1>認可リクエストの有効期限が切れました</h1><p>最初からやり直してください。</p>`, 400);
    }
  } else {
    // Fresh authorization request: validate everything that determines
    // where the user/agent is sent BEFORE any redirect happens.
    const clientId = url.searchParams.get("client_id");
    const redirectUri = url.searchParams.get("redirect_uri");
    const clientRaw = clientId ? await db.get("client:" + clientId) : null;
    if (!clientRaw) {
      return htmlPage("エラー", `<h1>不明なクライアントです</h1><p>client_id が登録されていません。</p>`, 400);
    }
    const client = JSON.parse(clientRaw);
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      return htmlPage("エラー", `<h1>戻り先が不正です</h1><p>redirect_uri が登録内容と一致しません。</p>`, 400);
    }
    const state = url.searchParams.get("state") || undefined;
    if (url.searchParams.get("response_type") !== "code") {
      return authorizeErrorRedirect(request, redirectUri, "unsupported_response_type", state);
    }
    const challenge = url.searchParams.get("code_challenge");
    if (!challenge || url.searchParams.get("code_challenge_method") !== "S256") {
      return authorizeErrorRedirect(
        request, redirectUri, "invalid_request", state,
        "PKCE with code_challenge_method=S256 is required"
      );
    }
    let scope = SCOPES.slice();
    const scopeParam = url.searchParams.get("scope");
    if (scopeParam) {
      scope = scopeParam.split(" ").filter(Boolean);
      if (scope.some((s) => !SCOPES.includes(s))) {
        return authorizeErrorRedirect(request, redirectUri, "invalid_scope", state);
      }
    }
    const resource = url.searchParams.get("resource");
    if (resource && resource !== resourceOf(request)) {
      return authorizeErrorRedirect(request, redirectUri, "invalid_target", state);
    }
    pending = {
      id: randomHex(16),
      clientId,
      redirectUri,
      scope,
      state: state || null,
      codeChallenge: challenge,
      resource: resourceOf(request),
      csrf: randomHex(16),
      expiresAt: Date.now() + PENDING_AUTHZ_TTL_MS,
    };
    await db.put("authz:" + pending.id, JSON.stringify(pending));
  }

  const clientRaw = await db.get("client:" + pending.clientId);
  if (!clientRaw) {
    return htmlPage("エラー", `<h1>不明なクライアントです</h1>`, 400);
  }
  const client = JSON.parse(clientRaw);
  if (!(await hasOwnerSession(env, request))) {
    return loginPage(pending.id, null);
  }
  return consentPage(pending, client);
}

async function handleLogin(env, db, request) {
  const form = await request.formData();
  const pendingId = String(form.get("pending") || "");
  const password = String(form.get("password") || "");
  const pending = await loadPending(db, pendingId);
  if (!pending) {
    return htmlPage("エラー", `<h1>認可リクエストの有効期限が切れました</h1><p>最初からやり直してください。</p>`, 400);
  }
  const hash = await sha256Hex(password);
  if (!timingSafeEqualStr(hash, String(env.OWNER_PASSWORD_HASH).toLowerCase())) {
    const page = loginPage(pending.id, "パスワードが違います。");
    return new Response(page.body, { status: 401, headers: page.headers });
  }
  const cookie = await makeSessionCookie(env);
  return redirectResponse(
    issuerOf(request) + "/oauth/authorize?pending=" + encodeURIComponent(pending.id),
    { "Set-Cookie": cookie.header }
  );
}

async function handleConsent(env, db, request) {
  const form = await request.formData();
  const pendingId = String(form.get("pending") || "");
  if (!(await hasOwnerSession(env, request))) {
    return redirectResponse(
      issuerOf(request) + "/oauth/authorize?pending=" + encodeURIComponent(pendingId)
    );
  }
  // Take (consume) the pending request so it cannot be replayed.
  const raw = await db.take("authz:" + pendingId);
  if (!raw) {
    return htmlPage("エラー", `<h1>認可リクエストの有効期限が切れました</h1><p>最初からやり直してください。</p>`, 400);
  }
  const pending = JSON.parse(raw);
  if (
    pending.expiresAt <= Date.now() ||
    !timingSafeEqualStr(String(form.get("csrf") || ""), pending.csrf)
  ) {
    return htmlPage("エラー", `<h1>認可リクエストが不正です</h1><p>最初からやり直してください。</p>`, 400);
  }
  if (String(form.get("decision") || "") !== "approve") {
    return authorizeErrorRedirect(request, pending.redirectUri, "access_denied", pending.state);
  }
  const code = randomToken("code_");
  const record = {
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    scope: pending.scope,
    aud: pending.resource,
    codeChallenge: pending.codeChallenge,
    principal: OWNER_PRINCIPAL,
    exp: Date.now() + AUTH_CODE_TTL_MS,
  };
  await db.put("code:" + (await sha256Hex(code)), JSON.stringify(record));
  const u = new URL(pending.redirectUri);
  u.searchParams.set("code", code);
  if (pending.state) u.searchParams.set("state", pending.state);
  u.searchParams.set("iss", issuerOf(request));
  return redirectResponse(u.toString());
}

// --- Token endpoint ---
async function handleToken(db, request) {
  const form = await request.formData();
  const grantType = String(form.get("grant_type") || "");
  const clientId = String(form.get("client_id") || "");

  if (grantType === "authorization_code") {
    const code = String(form.get("code") || "");
    if (!code) return oauthJsonError(400, "invalid_request", "code is required");
    // Atomic take: a code can be exchanged exactly once, even under races.
    const raw = await db.take("code:" + (await sha256Hex(code)));
    if (!raw) return oauthJsonError(400, "invalid_grant", "unknown or already-used code");
    const rec = JSON.parse(raw);
    if (rec.exp <= Date.now()) return oauthJsonError(400, "invalid_grant", "code expired");
    if (!clientId || rec.clientId !== clientId) {
      return oauthJsonError(400, "invalid_grant", "client_id does not match the code");
    }
    const redirectUri = String(form.get("redirect_uri") || "");
    if (redirectUri !== rec.redirectUri) {
      return oauthJsonError(400, "invalid_grant", "redirect_uri does not match the authorization request");
    }
    const resource = String(form.get("resource") || "");
    if (resource && resource !== rec.aud) {
      return oauthJsonError(400, "invalid_target", "resource does not match the authorization request");
    }
    const verifier = String(form.get("code_verifier") || "");
    if (!verifier) return oauthJsonError(400, "invalid_request", "code_verifier is required");
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(verifier)
    );
    const computed = b64urlEncode(new Uint8Array(digest));
    if (!timingSafeEqualStr(computed, rec.codeChallenge)) {
      return oauthJsonError(400, "invalid_grant", "PKCE verification failed");
    }
    const pair = await issueTokenPair(db, request, {
      principal: rec.principal,
      clientId: rec.clientId,
      scope: rec.scope,
    });
    return jsonResponse(pair, 200, NO_STORE);
  }

  if (grantType === "refresh_token") {
    const presented = String(form.get("refresh_token") || "");
    if (!presented) return oauthJsonError(400, "invalid_request", "refresh_token is required");
    // Rotation: atomically take the old refresh token. Presenting it again
    // (replay / theft) fails because the record no longer exists.
    const raw = await db.take(await tokenKey(presented));
    if (!raw) return oauthJsonError(400, "invalid_grant", "unknown or already-rotated refresh token");
    const rec = JSON.parse(raw);
    if (rec.kind !== "refresh" || rec.exp <= Date.now()) {
      return oauthJsonError(400, "invalid_grant", "refresh token expired");
    }
    if (!clientId || rec.clientId !== clientId) {
      return oauthJsonError(400, "invalid_grant", "client_id does not match the refresh token");
    }
    if (rec.iss !== issuerOf(request) || rec.aud !== resourceOf(request)) {
      return oauthJsonError(400, "invalid_grant", "refresh token was issued for a different server");
    }
    const pair = await issueTokenPair(db, request, {
      principal: rec.principal,
      clientId: rec.clientId,
      scope: rec.scope,
    });
    return jsonResponse(pair, 200, NO_STORE);
  }

  return oauthJsonError(400, "unsupported_grant_type", "only authorization_code and refresh_token are supported");
}

// --- Revocation endpoint (RFC 7009) ---
async function handleRevoke(db, request) {
  const form = await request.formData();
  const token = String(form.get("token") || "");
  const clientId = String(form.get("client_id") || "");
  if (token) {
    const key = await tokenKey(token);
    const raw = await db.get(key);
    if (raw) {
      const rec = JSON.parse(raw);
      if (!clientId || rec.clientId === clientId) {
        await db.delete(key);
      }
    }
  }
  // RFC 7009: 200 even when the token is unknown.
  return new Response(null, { status: 200, headers: NO_STORE });
}

// ---------- trigger endpoint (admin, NOT OAuth) ----------
//
// This endpoint authenticates the *sender* with TRIGGER_KEY alone, outside
// the OAuth flow: only the server owner holds that key, so the sender's
// identity is established by the key — never by payload fields. Accordingly
// only a whitelist of payload fields is read (text, topic, request_id);
// anything else a caller sends (e.g. status, callback_url, deliver_to,
// report_to) is ignored and cannot change delivery targets, request status,
// or permissions.
//
// The delivered `text` is untrusted external input for the receiver. It is
// transported verbatim as data (payloadSchema-typed string) and the payload
// carries no fields that could widen what the receiver may do with it.
//
// Replay / duplication: callers may supply their own request_id. Creation is
// atomic (put-if-absent in the Durable Object), so a re-sent trigger — even
// two copies arriving at the same time — returns the existing record and
// never delivers twice. (Without a supplied request_id, each call creates
// a fresh server-generated ID, as before.)
const REQUEST_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

async function handleTrigger(env, db, request) {
  const key = env.TRIGGER_KEY;
  if (!key) return jsonResponse({ error: "trigger not configured" }, 500);
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
  const headerKey = request.headers.get("X-Trigger-Key") || "";
  if (
    !timingSafeEqualStr(bearer, key) &&
    !timingSafeEqualStr(headerKey, key)
  ) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "invalid JSON body" }, 400);
  }
  const text = typeof body?.text === "string" ? body.text.trim() : "";
  if (!text) return jsonResponse({ error: "text is required" }, 400);
  if (text.length > 8000) return jsonResponse({ error: "text too long" }, 400);
  const topic =
    typeof body?.topic === "string" && body.topic ? body.topic : undefined;
  const suppliedId =
    typeof body?.request_id === "string" && REQUEST_ID_PATTERN.test(body.request_id)
      ? body.request_id
      : undefined;
  if (body?.request_id !== undefined && suppliedId === undefined) {
    return jsonResponse({ error: "request_id format is invalid" }, 400);
  }

  const nowIso = new Date().toISOString();
  const record = {
    id: suppliedId || "req_" + randomHex(16),
    text,
    status: "pending",
    createdAt: nowIso,
    updatedAt: nowIso,
    deliveries: [],
    origin: "trigger",
  };
  if (topic) record.topic = topic;

  if (suppliedId) {
    const { created, value } = await db.create(
      "req:" + suppliedId,
      JSON.stringify(record)
    );
    if (!created) {
      const existing = JSON.parse(value);
      const deliveries = Array.isArray(existing.deliveries) ? existing.deliveries : [];
      return jsonResponse({
        request_id: existing.id,
        status: existing.status,
        deduplicated: true,
        subscriptions_matched: deliveries.length,
        delivered: deliveries.filter((r) => r.ok).length,
      });
    }
  } else {
    await db.put("req:" + record.id, JSON.stringify(record));
  }

  const results = await deliverToSubscriptions(db, record);
  record.deliveries = results;
  if (results.some((r) => r.ok)) record.status = "delivered";
  record.updatedAt = new Date().toISOString();
  await db.put("req:" + record.id, JSON.stringify(record));

  return jsonResponse({
    request_id: record.id,
    status: record.status,
    deduplicated: false,
    subscriptions_matched: results.length,
    delivered: results.filter((r) => r.ok).length,
    results: results.map((r) => ({
      subscription_id: r.subscriptionId,
      ok: r.ok,
      status: r.status,
      attempts: r.attempts,
    })),
  });
}

// ---------- test echo (only when TEST_ECHO=1; used for self-verification) ----------

async function handleTestEcho(env, db, request) {
  const rawBody = await request.text();
  let body = {};
  try {
    body = JSON.parse(rawBody);
  } catch (_) {
    /* keep {} */
  }
  const msgId = request.headers.get("webhook-id") || "";
  let signatureValid = false;
  if (env.TEST_ECHO_SECRET) {
    signatureValid = await verifyBody(
      env.TEST_ECHO_SECRET,
      msgId,
      request.headers.get("webhook-timestamp") || "",
      rawBody,
      request.headers.get("webhook-signature") || ""
    );
    // Verdict via status code: 2xx only when the signature verifies, so the
    // caller's delivery result proves end-to-end signature correctness.
    if (!signatureValid) {
      return jsonResponse({ ok: false, error: "invalid signature" }, 403);
    }
  }
  await db.put(
    "echo:" + msgId,
    JSON.stringify({
      receivedAt: new Date().toISOString(),
      subscriptionId: request.headers.get("X-MCP-Subscription-Id") || null,
      signatureValid,
      body,
    })
  );
  if (body?.type === "verification") {
    return jsonResponse({ challenge: body.challenge });
  }
  return jsonResponse({ ok: true });
}

// ---------- router ----------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      const db = store(env);

      // --- Discovery metadata (public; contains no secrets) ---
      if (
        url.pathname === "/.well-known/oauth-protected-resource" ||
        url.pathname === "/.well-known/oauth-protected-resource/mcp"
      ) {
        if (request.method !== "GET") return jsonResponse({ error: "not found" }, 404);
        return jsonResponse(protectedResourceMetadata(request), 200, {
          "Cache-Control": "public, max-age=300",
        });
      }
      if (
        url.pathname === "/.well-known/oauth-authorization-server" ||
        url.pathname === "/.well-known/openid-configuration"
      ) {
        if (request.method !== "GET") return jsonResponse({ error: "not found" }, 404);
        return jsonResponse(authorizationServerMetadata(request), 200, {
          "Cache-Control": "public, max-age=300",
        });
      }

      // --- Authorization server endpoints ---
      if (url.pathname.startsWith("/oauth/")) {
        if (!oauthConfigured(env)) {
          return oauthJsonError(
            503,
            "server_error",
            "OAuth is not configured on this server (OWNER_PASSWORD_HASH / AUTH_SECRET secrets are missing)"
          );
        }
        if (url.pathname === "/oauth/register" && request.method === "POST") {
          return handleRegister(db, request);
        }
        if (url.pathname === "/oauth/authorize" && request.method === "GET") {
          return handleAuthorize(env, db, request);
        }
        if (url.pathname === "/oauth/login" && request.method === "POST") {
          return handleLogin(env, db, request);
        }
        if (url.pathname === "/oauth/consent" && request.method === "POST") {
          return handleConsent(env, db, request);
        }
        if (url.pathname === "/oauth/token" && request.method === "POST") {
          return handleToken(db, request);
        }
        if (url.pathname === "/oauth/revoke" && request.method === "POST") {
          return handleRevoke(db, request);
        }
        return jsonResponse({ error: "not found" }, 404);
      }

      // --- MCP endpoint (protected resource) ---
      if (url.pathname === "/mcp") {
        if (request.method === "POST") return handleMcp(db, request, env);
        return jsonResponse(rpcError(null, -32600, "Method not allowed"), 405);
      }
      if (url.pathname === "/trigger" && request.method === "POST") {
        return handleTrigger(env, db, request);
      }
      if (
        url.pathname === "/test-echo" &&
        request.method === "POST" &&
        env.TEST_ECHO === "1"
      ) {
        return handleTestEcho(env, db, request);
      }
      if (url.pathname === "/" && request.method === "GET") {
        return jsonResponse({ ok: true, service: SERVER_NAME, version: SERVER_VERSION });
      }
      return jsonResponse({ error: "not found" }, 404);
    } catch (e) {
      return jsonResponse({ error: "internal error", detail: String(e).slice(0, 200) }, 500);
    }
  },
};
