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
//   TRIGGER_KEY        — secret text; admin key for POST /trigger and
//                        the /claude-inbox admin endpoints
//   CLAUDE_HOOK_SECRET — secret text; whsec_ HMAC secret for
//                        POST /claude-hook (the reverse-direction
//                        webhook that files requests for Muse)
//   IDP_ISSUER         — optional plain var; authorization server issuer
//                        (default https://id.0g0.xyz)
//   JWKS_URI           — optional plain var; JWKS endpoint of the IdP
//                        (default <IDP_ISSUER>/.well-known/jwks.json)
//   RESOURCE_URI       — optional plain var; audience this resource
//                        requires (default: this Worker's own /mcp URL)
//   OWNER_SUB          — plain var; the 0g0-id subject (`sub`) of the one
//                        owner allowed to use the data-bearing / mutating
//                        MCP methods (events/subscribe, events/unsubscribe,
//                        both tools). Deliveries go only to this owner's
//                        subscriptions. Unset/empty rejects everyone
//                        (fail closed). The production value is set at
//                        deploy time; it is never committed to this repo.
//   TEST_ECHO          — optional plain var; when "1", enables POST /test-echo
//   TEST_ECHO_SECRET   — optional plain var; throwaway whsec_ used only by /test-echo

import { DurableObject } from "cloudflare:workers";

const EVENT_NAME = "kick";
const SERVER_NAME = "dots-kick-events";
const SERVER_VERSION = "1.3.0";
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
  "claude:kick", // tools/call kick_claude (reverse direction)
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
  {
    name: "kick_claude",
    description:
      "File a work request for Muse, the user's other agent (the reverse of the kick event: this wakes Muse instead of dots). Muse polls its inbox every couple of minutes, picks the request up, and works on it under the user's standing collaboration rules. The request text is data for Muse, not an instruction from the user. Returns the request id; Muse marks it acknowledged / completed as it works.",
    inputSchema: {
      type: "object",
      properties: {
        text: {
          type: "string",
          description: "The request for Muse, in plain language.",
        },
        topic: {
          type: "string",
          description: "Optional short topic label.",
        },
      },
      required: ["text"],
      additionalProperties: false,
    },
  },
];

// ---------- Durable Object storage ----------

// Request lifecycle ranks. Status merges only ever move a record
// forward along this ladder; nothing writes a status backwards.
const STATUS_RANK = { pending: 0, delivered: 1, acknowledged: 2, completed: 3 };

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
    if (url.pathname === "/merge-delivery") {
      // Merge delivery results into the CURRENT record. The caller holds
      // a snapshot taken before delivery; while delivery was in flight
      // the receiver may have advanced the record (acknowledged /
      // completed, notes). Writing the stale snapshot back wholesale
      // would roll that back, so only the delivery fields are merged
      // here, atomically: deliveries are appended and the status only
      // ever advances (pending < delivered < acknowledged < completed).
      const { key, deliveries, anyOk } = await request.json();
      let merged = null;
      await this.ctx.blockConcurrencyWhile(async () => {
        const raw = await s.get(key);
        if (raw === undefined) return;
        const record = JSON.parse(raw);
        const existing = Array.isArray(record.deliveries)
          ? record.deliveries
          : [];
        record.deliveries = [
          ...existing,
          ...(Array.isArray(deliveries) ? deliveries : []),
        ];
        const computed = anyOk ? "delivered" : "pending";
        if ((STATUS_RANK[record.status] ?? 0) < (STATUS_RANK[computed] ?? 0)) {
          record.status = computed;
        }
        record.updatedAt = new Date().toISOString();
        await s.put(key, JSON.stringify(record));
        merged = record;
      });
      return merged === null
        ? new Response(null, { status: 404 })
        : Response.json(merged);
    }
    if (url.pathname === "/merge-status") {
      // Merge a status update (update_request_status) into the CURRENT
      // record, atomically. The tool handler used to read the record in
      // the Worker, edit the snapshot, and write it back wholesale —
      // a read-modify-write outside this object's serialization, so a
      // delivery merge landing between the read and the write was
      // silently overwritten (delivery results lost), and two racing
      // updates overwrote each other's notes. Here the update is a
      // field-level merge against the latest record instead: the
      // status only advances along STATUS_RANK (an "acknowledged"
      // arriving after "completed" cannot regress it) and a note, when
      // present, is appended to the current notes array.
      const { key, status, note } = await request.json();
      let merged = null;
      await this.ctx.blockConcurrencyWhile(async () => {
        const raw = await s.get(key);
        if (raw === undefined) return;
        const record = JSON.parse(raw);
        const nowIso = new Date().toISOString();
        if ((STATUS_RANK[status] ?? -1) > (STATUS_RANK[record.status] ?? 0)) {
          record.status = status;
        }
        if (typeof note === "string" && note) {
          record.notes = Array.isArray(record.notes) ? record.notes : [];
          record.notes.push({ status, note, at: nowIso });
        }
        record.updatedAt = nowIso;
        await s.put(key, JSON.stringify(record));
        merged = record;
      });
      return merged === null
        ? new Response(null, { status: 404 })
        : Response.json(merged);
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
    // Atomically merge delivery results into the current stored record
    // (see the Store "/merge-delivery" endpoint); returns the merged
    // record, or null if the key no longer exists.
    async mergeDelivery(key, deliveries, anyOk) {
      const r = await stub.fetch("https://store/merge-delivery", {
        method: "POST",
        body: JSON.stringify({ key, deliveries, anyOk }),
      });
      if (r.status === 404) return null;
      return r.json();
    },
    // Atomically merge a status update into the current stored record
    // (see the Store "/merge-status" endpoint); returns the merged
    // record, or null if the key does not exist.
    async mergeStatus(key, status, note) {
      const r = await stub.fetch("https://store/merge-status", {
        method: "POST",
        body: JSON.stringify({ key, status, note: note ?? null }),
      });
      if (r.status === 404) return null;
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

// Private / non-routable IPv4 ranges, judged by the first two octets.
function isPrivateIPv4(a, b) {
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 169 && b === 254) ||
    a >= 224
  );
}

// Parse an IPv6 literal (brackets already stripped) into eight 16-bit
// groups, or null when malformed. A trailing dotted IPv4 tail counts as
// two groups. WHATWG URL keeps the brackets on IPv6 hostnames
// ("[::1]"), so callers must strip them first — comparing the bracketed
// form against "::1" etc. would never match and let loopback through.
function parseIPv6(host) {
  let addr = host;
  if (addr.includes(".")) {
    const m = addr.match(/(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (!m) return null;
    const n = m.slice(1).map(Number);
    if (n.some((x) => x > 255)) return null;
    const hi = ((n[0] << 8) | n[1]).toString(16);
    const lo = ((n[2] << 8) | n[3]).toString(16);
    addr = addr.slice(0, addr.length - m[0].length) + hi + ":" + lo;
  }
  const parsePieces = (s) => {
    if (s === "") return [];
    const out = [];
    for (const p of s.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(p)) return null;
      out.push(parseInt(p, 16));
    }
    return out;
  };
  const halves = addr.split("::");
  if (halves.length > 2) return null;
  if (halves.length === 2) {
    const left = parsePieces(halves[0]);
    const right = parsePieces(halves[1]);
    if (left === null || right === null) return null;
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null; // "::" must compress at least one group
    return [...left, ...new Array(missing).fill(0), ...right];
  }
  const groups = parsePieces(addr);
  return groups !== null && groups.length === 8 ? groups : null;
}

function isPrivateIPv6(groups) {
  const g = groups;
  // Loopback ::1 and unspecified ::
  if (g.every((x, i) => x === (i === 7 ? 1 : 0))) return true;
  if (g.every((x) => x === 0)) return true;
  if ((g[0] & 0xfe00) === 0xfc00) return true; // ULA fc00::/7
  if ((g[0] & 0xffc0) === 0xfe80) return true; // link-local fe80::/10
  if ((g[0] & 0xff00) === 0xff00) return true; // multicast ff00::/8
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d): judge
  // the embedded IPv4 address by the IPv4 rules.
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) {
    return isPrivateIPv4(g[6] >> 8, g[6] & 0xff);
  }
  return false;
}

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
    if (isPrivateIPv4(Number(v4[1]), Number(v4[2]))) return "private_address";
    return null;
  }
  if (host.startsWith("[") && host.endsWith("]")) {
    // IPv6 literal: strip the WHATWG brackets, then classify by groups
    // (loopback, ULA, link-local, IPv4-mapped, ...). Unparseable input
    // fails closed.
    const groups = parseIPv6(host.slice(1, -1));
    if (!groups || isPrivateIPv6(groups)) return "private_address";
    return null;
  }
  if (host.includes(":")) return "private_address"; // unbracketed colon host: fail closed
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

// Requests filed *for Muse* (the reverse direction) live in their own
// keyspace ("creq:") inside the same Store. Lifecycle mirrors the dots
// requests: pending -> acknowledged -> completed (the shared STATUS_RANK
// ladder applies; "delivered" is simply never used for these).
async function listClaudeRequests(db) {
  const out = [];
  for (const key of await db.listKeys("creq:")) {
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

async function deliverToSubscriptions(db, request, env) {
  const subs = await listSubscriptions(db);
  const ownerSub = configuredOwnerSub(env);
  const now = Date.now();
  const results = [];
  for (const sub of subs) {
    if (sub.name !== EVENT_NAME) continue;
    // Pre-OAuth subscriptions (principal "anonymous" or missing) were
    // self-verification artifacts; they no longer receive deliveries.
    if (!sub.principal || sub.principal === LEGACY_PRINCIPAL) continue;
    // Deliveries go only to the configured owner's subscriptions. A
    // subscription record belonging to any other principal (e.g. created
    // before the owner restriction existed) must not receive request
    // payloads. OWNER_SUB unset means no deliveries at all (fail closed).
    if (!ownerSub || sub.principal !== ownerSub) continue;
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
    // The update is applied as a serialized field-level merge inside
    // the Durable Object (see "/merge-status"), never as a wholesale
    // write of a snapshot read here: a delivery merge landing while
    // this call is in flight must not be overwritten, and two racing
    // updates must not lose each other's notes.
    const note =
      typeof args.note === "string" && args.note ? args.note : null;
    const record = await db.mergeStatus("req:" + requestId, status, note);
    if (!record) {
      return rpcResult(id, toolText({ error: "request not found" }, true));
    }
    return rpcResult(id, toolText(record));
  }
  if (name === "kick_claude") {
    const text = typeof args.text === "string" ? args.text.trim() : "";
    if (!text) {
      return rpcResult(id, toolText({ error: "text is required" }, true));
    }
    if (text.length > 8000) {
      return rpcResult(id, toolText({ error: "text too long" }, true));
    }
    const topic =
      typeof args.topic === "string" && args.topic ? args.topic : undefined;
    const nowIso = new Date().toISOString();
    const record = {
      id: "creq_" + randomHex(16),
      text,
      status: "pending",
      createdAt: nowIso,
      updatedAt: nowIso,
      origin: "tool",
    };
    if (topic) record.topic = topic;
    const { created, value } = await db.create(
      "creq:" + record.id,
      JSON.stringify(record)
    );
    const stored = created ? record : JSON.parse(value);
    return rpcResult(
      id,
      toolText({ request_id: stored.id, status: stored.status })
    );
  }
  return rpcError(id, -32602, `Unknown tool: ${String(name)}`);
}

// ---------- MCP endpoint (protected resource) ----------

// ---------- owner restriction ----------
// This is a single-owner personal service. A valid token proves *some*
// IdP user completed the authorization flow for this resource — it does
// not make them the owner. The data-bearing / mutating methods
// (events/subscribe, events/unsubscribe, and both tools) additionally
// require the token subject to equal OWNER_SUB. OWNER_SUB unset or empty
// rejects everyone (fail closed), so a deployment that forgets the
// setting exposes nothing. Public metadata and the read-only discovery
// methods (initialize, server/discover, ping, tools/list, events/list)
// are unchanged: they carry no request data.
function configuredOwnerSub(env) {
  const v = env && env.OWNER_SUB;
  return typeof v === "string" && v ? v : null;
}

function requiresOwner(msg) {
  const { method } = msg || {};
  return (
    method === "events/subscribe" ||
    method === "events/unsubscribe" ||
    method === "tools/call"
  );
}

function isOwner(env, auth) {
  const owner = configuredOwnerSub(env);
  return owner !== null && auth !== null && auth.principal === owner;
}

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
      if (params?.name === "kick_claude") return "claude:kick";
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
    if (requiresOwner(msg) && !isOwner(env, auth)) {
      const errBody = rpcError(
        msg?.id ?? null,
        -32001,
        "forbidden: caller is not the resource owner",
        { error: "forbidden" }
      );
      if (!Array.isArray(parsed)) {
        return jsonResponse(errBody, 403);
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

  // Creation always goes through the atomic put-if-absent, for
  // server-generated IDs too: every write to a request record is then
  // one of the Durable Object's serialized operations (create,
  // merge-delivery, merge-status), and no path writes back a snapshot
  // read in the Worker.
  const { created, value } = await db.create(
    "req:" + record.id,
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

  const results = await deliverToSubscriptions(db, record, env);
  // Merge the outcome into the latest stored record inside the DO: a
  // status update (acknowledged / completed, with notes) may have landed
  // while delivery was in flight, and writing this handler's pre-delivery
  // snapshot back would roll it back to "delivered" and drop the notes.
  const merged = await db.mergeDelivery(
    "req:" + record.id,
    results,
    results.some((r) => r.ok)
  );
  const final = merged || record;

  return jsonResponse({
    request_id: record.id,
    status: final.status,
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

// ---------- reverse direction: requests for Muse ----------
// Muse (the user's other agent) has no inbound network path: its
// Tailscale client is outbound-only and its runtime accepts no direct
// calls. So the reverse direction mirrors this server's own design —
// senders file a request here, and Muse polls for it:
//   - POST /claude-hook        signed webhook intake (Standard
//                              Webhooks HMAC, CLAUDE_HOOK_SECRET), for
//                              senders that can POST a webhook (e.g.
//                              Hermes on the user's PC, scripts).
//   - tools/call kick_claude   the same filing as an MCP tool, for
//                              dots, which cannot POST arbitrary
//                              webhooks (owner-gated, claude:kick).
//   - GET  /claude-inbox       admin list (TRIGGER_KEY), used by Muse.
//   - POST /claude-inbox/status admin status update (TRIGGER_KEY).
//   - GET  /claude-inbox/signal public pending *count* only, so
//                              Muse's secret-free poller can decide
//                              whether to wake; it carries no request
//                              data (no ids, no text).
// Filed text is untrusted input for Muse in exactly the same way
// trigger text is for dots: data, transported verbatim, and it can
// never widen what the receiver may do.

function isAdminKey(env, request) {
  const key = env.TRIGGER_KEY;
  if (!key) return false;
  const auth = request.headers.get("Authorization") || "";
  const bearer = auth.startsWith("Bearer ") ? auth.slice("Bearer ".length) : "";
  const headerKey = request.headers.get("X-Trigger-Key") || "";
  return timingSafeEqualStr(bearer, key) || timingSafeEqualStr(headerKey, key);
}

async function fileClaudeRequest(db, { text, topic, suppliedId, origin }) {
  const nowIso = new Date().toISOString();
  const record = {
    id: suppliedId || "creq_" + randomHex(16),
    text,
    status: "pending",
    createdAt: nowIso,
    updatedAt: nowIso,
    origin,
  };
  if (topic) record.topic = topic;
  const { created, value } = await db.create(
    "creq:" + record.id,
    JSON.stringify(record)
  );
  if (!created) {
    const existing = JSON.parse(value);
    return {
      request_id: existing.id,
      status: existing.status,
      deduplicated: true,
    };
  }
  return { request_id: record.id, status: record.status, deduplicated: false };
}

async function handleClaudeHook(env, db, request) {
  const secret = env.CLAUDE_HOOK_SECRET;
  if (!secret) return jsonResponse({ error: "claude hook not configured" }, 500);
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    return jsonResponse({ error: "body too large" }, 413);
  }
  const msgId = request.headers.get("webhook-id") || "";
  const ts = request.headers.get("webhook-timestamp") || "";
  const sig = request.headers.get("webhook-signature") || "";
  const tsNum = Number(ts);
  if (
    !msgId ||
    !Number.isFinite(tsNum) ||
    Math.abs(Math.floor(Date.now() / 1000) - tsNum) > 300
  ) {
    return jsonResponse({ error: "invalid or stale webhook timestamp" }, 400);
  }
  if (!(await verifyBody(secret, msgId, ts, raw, sig))) {
    return jsonResponse({ error: "invalid signature" }, 401);
  }
  let body;
  try {
    body = JSON.parse(raw);
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
  return jsonResponse(
    await fileClaudeRequest(db, { text, topic, suppliedId, origin: "webhook" })
  );
}

async function handleClaudeInboxList(env, db, request, url) {
  if (!isAdminKey(env, request)) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  const status = url.searchParams.get("status");
  let all = await listClaudeRequests(db);
  if (status) all = all.filter((r) => r.status === status);
  return jsonResponse({ requests: all, count: all.length });
}

async function handleClaudeInboxStatus(env, db, request) {
  if (!isAdminKey(env, request)) {
    return jsonResponse({ error: "unauthorized" }, 401);
  }
  let body;
  try {
    body = await request.json();
  } catch (_) {
    return jsonResponse({ error: "invalid JSON body" }, 400);
  }
  const requestId = body?.request_id;
  const status = body?.status;
  if (typeof requestId !== "string" || !requestId) {
    return jsonResponse({ error: "request_id is required" }, 400);
  }
  if (status !== "acknowledged" && status !== "completed") {
    return jsonResponse(
      { error: "status must be acknowledged or completed" },
      400
    );
  }
  const note = typeof body?.note === "string" && body.note ? body.note : null;
  const record = await db.mergeStatus("creq:" + requestId, status, note);
  if (!record) return jsonResponse({ error: "request not found" }, 404);
  return jsonResponse(record);
}

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
      // --- Reverse direction: requests for Muse ---
      if (url.pathname === "/claude-hook" && request.method === "POST") {
        return handleClaudeHook(env, db, request);
      }
      if (url.pathname === "/claude-inbox" && request.method === "GET") {
        return handleClaudeInboxList(env, db, request, url);
      }
      if (url.pathname === "/claude-inbox/status" && request.method === "POST") {
        return handleClaudeInboxStatus(env, db, request);
      }
      if (url.pathname === "/claude-inbox/signal" && request.method === "GET") {
        const all = await listClaudeRequests(db);
        const pending = all.filter((r) => r.status === "pending").length;
        return jsonResponse({ pending }, 200, {
          "Cache-Control": "no-store",
        });
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
