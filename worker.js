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
//   at the RFC 9728 protected-resource metadata, whose
//   `authorization_servers` names the authorization server below.
// - The authorization server is the owner's own IdP, **0g0-id**
//   (https://id.0g0.xyz) — this Worker never issues tokens. 0g0-id mints
//   ES256 JWT access tokens whose audience is bound to this MCP endpoint
//   through the RFC 8707 `resource` parameter (the URI must be registered
//   in 0g0-id's resource_servers registry), and supports RFC 7591 dynamic
//   client registration so MCP clients (ChatGPT) can self-register.
// - Every request is validated against the IdP's JWKS
//   (https://id.0g0.xyz/.well-known/jwks.json): signature (ES256, key
//   selected by `kid`, cache with rotation refetch), issuer, audience
//   (= this resource), expiry, and per-method scope. Subscriptions are
//   bound to the token's subject (`sub`); one principal cannot touch
//   another's subscription. Opaque (non-JWT) tokens are rejected.
// - POST /trigger is a separate machine-to-machine admin endpoint. It is NOT
//   part of the OAuth flow: it authenticates with TRIGGER_KEY only. The
//   requester identity therefore comes from possession of that key, never
//   from fields inside the payload. (The whsec_ webhook signature, in turn,
//   only proves a delivery came from this server — it says nothing about who
//   originally filed the request.)
//
// Storage: a single Durable Object ("Store", SQLite-backed) holds
// subscriptions and requests. (This Cloudflare connection has no KV/D1
// permissions, so storage lives inside the Worker platform itself.)
//
// Bindings:
//   STORE              — Durable Object namespace (class Store)
//   TRIGGER_KEY        — secret text; admin key for POST /trigger
//   IDP_ISSUER         — optional plain var; authorization server issuer
//                        (default https://id.0g0.xyz)
//   JWKS_URI           — optional plain var; JWKS endpoint of the IdP
//                        (default <IDP_ISSUER>/.well-known/jwks.json)
//   RESOURCE_URI       — optional plain var; audience this resource
//                        requires (default: this Worker's own /mcp URL)
//   TEST_ECHO          — optional plain var; when "1", enables POST /test-echo
//   TEST_ECHO_SECRET   — optional plain var; throwaway whsec_ used only by /test-echo

import { DurableObject } from "cloudflare:workers";

const EVENT_NAME = "kick";
const SERVER_NAME = "dots-kick-events";
const SERVER_VERSION = "1.2.0";
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MIN_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const VERIFY_CACHE_MS = 24 * 60 * 60 * 1000; // 24 hours
const PREV_SECRET_WINDOW_MS = 10 * 60 * 1000; // sign with old+new key briefly after rotation
const MAX_BODY_BYTES = 256 * 1024;

// ---------- OAuth constants (resource server) ----------

const LEGACY_PRINCIPAL = "anonymous"; // pre-auth subscriptions (self-verification era); excluded from delivery

// Scopes (least privilege per operation; all are listed in the metadata and
// in the WWW-Authenticate challenge so clients request exactly these).
const SCOPES = [
  "events:read", // events/list
  "events:subscribe", // events/subscribe, events/unsubscribe
  "requests:read", // tools/call list_pending_requests
  "requests:update", // tools/call update_request_status
];
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

// ---------- OAuth: resource-server side (0g0-id is the authorization server) ----------

// Authorization is delegated to the owner's own IdP, 0g0-id
// (https://id.0g0.xyz). This Worker is a pure OAuth 2.1 resource server: it
// never issues tokens. Access tokens are ES256 JWTs minted by 0g0-id with
// the audience bound to this MCP endpoint via the RFC 8707 `resource`
// parameter, validated on every request against the IdP's JWKS.
const DEFAULT_IDP_ISSUER = "https://id.0g0.xyz";
const JWKS_CACHE_MS = 10 * 60 * 1000; // 10 minutes
const JWKS_REFETCH_MIN_MS = 1000; // minimum gap between forced refetches (unknown kid)

function idpIssuer(env) {
  return (env && env.IDP_ISSUER) || DEFAULT_IDP_ISSUER;
}
function jwksUri(env) {
  return (env && env.JWKS_URI) || idpIssuer(env) + "/.well-known/jwks.json";
}
// The audience this resource requires. 0g0-id binds it from the `resource`
// parameter, so it must exactly match the URI registered for this server in
// 0g0-id's resource_servers registry. Defaults to this Worker's own /mcp
// URL; RESOURCE_URI overrides it (used by tests).
function expectedAudience(request, env) {
  if (env && env.RESOURCE_URI) return env.RESOURCE_URI;
  return new URL(request.url).origin + "/mcp";
}

function protectedResourceMetadata(request, env) {
  const origin = new URL(request.url).origin;
  return {
    resource: expectedAudience(request, env),
    authorization_servers: [idpIssuer(env)],
    scopes_supported: SCOPES,
    bearer_methods_supported: ["header"],
    resource_documentation: origin + "/",
  };
}

function wwwAuthenticate(request, env, extra = {}) {
  const origin = new URL(request.url).origin;
  const parts = [
    `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"`,
  ];
  if (extra.error) parts.push(`error="${extra.error}"`);
  parts.push(`scope="${(extra.scope || SCOPES).join(" ")}"`);
  return parts.join(", ");
}

function unauthorized(request, env, error) {
  return jsonResponse(
    { error: error || "unauthorized" },
    401,
    {
      "WWW-Authenticate": wwwAuthenticate(request, env, {
        error: error ? "invalid_token" : undefined,
      }),
      "Cache-Control": "no-store",
    }
  );
}

// ---------- JWT validation against the IdP JWKS ----------

let jwksCache = { keys: null, fetchedAt: 0, lastForcedRefetch: 0 };

async function fetchJwks(env) {
  const res = await fetch(jwksUri(env), {
    headers: { Accept: "application/json" },
  });
  if (!res.ok) throw new Error("JWKS fetch failed: " + res.status);
  const doc = await res.json();
  if (!doc || !Array.isArray(doc.keys)) {
    throw new Error("JWKS document has no keys");
  }
  jwksCache = {
    keys: doc.keys,
    fetchedAt: Date.now(),
    lastForcedRefetch: jwksCache.lastForcedRefetch,
  };
  return doc.keys;
}

async function getJwk(env, kid) {
  const now = Date.now();
  let keys = jwksCache.keys;
  if (!keys || now - jwksCache.fetchedAt > JWKS_CACHE_MS) {
    keys = await fetchJwks(env);
  }
  let jwk = keys.find((k) => k.kid === kid);
  if (!jwk && now - jwksCache.lastForcedRefetch > JWKS_REFETCH_MIN_MS) {
    // Unknown kid: the IdP may have rotated its signing key. Refetch once.
    jwksCache.lastForcedRefetch = now;
    keys = await fetchJwks(env);
    jwk = keys.find((k) => k.kid === kid);
  }
  return jwk || null;
}

const keyCache = new Map(); // kid -> CryptoKey

async function jwkToKey(jwk) {
  if (keyCache.has(jwk.kid)) return keyCache.get(jwk.kid);
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  keyCache.set(jwk.kid, key);
  return key;
}

// Validate a Bearer access token issued by 0g0-id. Checks: JWS structure,
// alg (ES256 only), signature against the JWKS key selected by kid, issuer,
// audience (= this resource), expiry / not-before, subject presence, and
// scope claims. Returns { principal, clientId, scope:Set } or null. The
// subscription owner is the token subject.
async function authenticate(env, request) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return null;
  const token = auth.slice("Bearer ".length).trim();
  const parts = token.split(".");
  if (parts.length !== 3) return null; // opaque tokens are not accepted
  let header, claims;
  try {
    header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])));
    claims = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])));
  } catch (_) {
    return null;
  }
  if (header.alg !== "ES256" || typeof header.kid !== "string" || !header.kid) {
    return null;
  }
  let jwk;
  try {
    jwk = await getJwk(env, header.kid);
  } catch (_) {
    return null;
  }
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256") return null;
  let signatureOk = false;
  try {
    const key = await jwkToKey(jwk);
    signatureOk = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      b64urlDecode(parts[2]),
      new TextEncoder().encode(parts[0] + "." + parts[1])
    );
  } catch (_) {
    return null;
  }
  if (!signatureOk) return null;

  const nowSec = Math.floor(Date.now() / 1000);
  if (claims.iss !== idpIssuer(env)) return null;
  const expected = expectedAudience(request, env);
  const aud = claims.aud;
  if (!(aud === expected || (Array.isArray(aud) && aud.includes(expected)))) {
    return null;
  }
  if (typeof claims.exp !== "number" || claims.exp <= nowSec) return null;
  if (typeof claims.nbf === "number" && claims.nbf > nowSec) return null;
  if (typeof claims.sub !== "string" || !claims.sub) return null;

  const scope = new Set();
  if (typeof claims.scope === "string") {
    for (const s of claims.scope.split(" ")) if (s) scope.add(s);
  }
  if (Array.isArray(claims.scp)) {
    for (const s of claims.scp) if (typeof s === "string" && s) scope.add(s);
  }
  return {
    principal: claims.sub,
    clientId:
      typeof claims.cid === "string"
        ? claims.cid
        : typeof claims.client_id === "string"
          ? claims.client_id
          : null,
    scope,
  };
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
  const auth = await authenticate(env, request);
  if (!auth) return unauthorized(request, env, presented);

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
          "WWW-Authenticate": wwwAuthenticate(request, env, {
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
        return jsonResponse(protectedResourceMetadata(request, env), 200, {
          "Cache-Control": "public, max-age=300",
        });
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
