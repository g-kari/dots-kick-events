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
// Storage: a single Durable Object ("Store", SQLite-backed) holds
// subscriptions and requests. (This Cloudflare connection has no KV/D1
// permissions, so storage lives inside the Worker platform itself.)
//
// Bindings:
//   STORE         — Durable Object namespace (class Store)
//   TRIGGER_KEY   — secret text; admin key for POST /trigger
//   TEST_ECHO     — optional plain var; when "1", enables POST /test-echo
//   TEST_ECHO_SECRET — optional plain var; throwaway whsec_ used only by /test-echo
//
// Note: this endpoint currently has no OAuth layer (the MCP endpoint is open).
// See README.md "制限・未確認事項".

import { DurableObject } from "cloudflare:workers";

const EVENT_NAME = "kick";
const SERVER_NAME = "dots-kick-events";
const SERVER_VERSION = "1.0.0";
const DEFAULT_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
const MIN_TTL_MS = 60 * 60 * 1000; // 1 hour
const MAX_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const VERIFY_CACHE_MS = 24 * 60 * 60 * 1000; // 24 hours
const PREV_SECRET_WINDOW_MS = 10 * 60 * 1000; // sign with old+new key briefly after rotation
const MAX_BODY_BYTES = 256 * 1024;

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
  };
}

// ---------- small helpers ----------

function jsonResponse(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json" },
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

// Constant-time string comparison (for challenges / admin key).
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

async function handleSubscribe(db, id, params) {
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

  const principal = "anonymous"; // no OAuth layer yet; see README
  const subId = await subscriptionId(principal, delivery.url, name, args);
  const existingRaw = await db.get("sub:" + subId);
  const existing = existingRaw ? JSON.parse(existingRaw) : null;

  const now = Date.now();
  const nowIso = new Date(now).toISOString();
  const refreshBefore = new Date(now + grantedTtlMs(params?.ttlMs)).toISOString();

  const subscription = {
    id: subId,
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
    const challenge = b64encode(crypto.getRandomValues(new Uint8Array(32)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
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

async function handleUnsubscribe(db, id, params) {
  const name = params?.name;
  const args = params?.arguments ?? {};
  const url = params?.delivery?.url;
  if (name && url) {
    const subId = await subscriptionId("anonymous", url, name, args);
    await db.delete("sub:" + subId);
  }
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
    if (sub.refreshBefore && Date.parse(sub.refreshBefore) <= now) continue;
    const filterTopic = sub.arguments?.topic;
    if (filterTopic && request.topic && filterTopic !== request.topic) continue;
    if (filterTopic && !request.topic) continue;

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

// ---------- MCP endpoint ----------

async function handleRpc(db, msg) {
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
      return handleSubscribe(db, id, params || {});
    case "events/unsubscribe":
      return handleUnsubscribe(db, id, params || {});
    default:
      if (isNotification) return null; // notifications need no response
      return rpcError(id, -32601, `Method not found: ${String(method)}`);
  }
}

async function handleMcp(db, request) {
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
  if (Array.isArray(parsed)) {
    const responses = [];
    for (const msg of parsed) {
      const res = await handleRpc(db, msg);
      if (res) responses.push(res);
    }
    if (responses.length === 0) return new Response(null, { status: 202 });
    return jsonResponse(responses);
  }
  const isNotification = parsed.id === undefined || parsed.id === null;
  const res = await handleRpc(db, parsed);
  if (res === null || isNotification) return new Response(null, { status: 202 });
  return jsonResponse(res);
}

// ---------- trigger endpoint (admin) ----------

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

  const nowIso = new Date().toISOString();
  const record = {
    id: "req_" + randomHex(16),
    text,
    status: "pending",
    createdAt: nowIso,
    updatedAt: nowIso,
    deliveries: [],
  };
  if (topic) record.topic = topic;
  await db.put("req:" + record.id, JSON.stringify(record));

  const results = await deliverToSubscriptions(db, record);
  record.deliveries = results;
  if (results.some((r) => r.ok)) record.status = "delivered";
  record.updatedAt = new Date().toISOString();
  await db.put("req:" + record.id, JSON.stringify(record));

  return jsonResponse({
    request_id: record.id,
    status: record.status,
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
      if (url.pathname === "/mcp") {
        if (request.method === "POST") return handleMcp(db, request);
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
