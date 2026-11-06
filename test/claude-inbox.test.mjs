// Tests for the reverse direction (requests *for* Muse) added in 1.3.0:
//   - POST /claude-hook        signed webhook intake (Standard Webhooks)
//   - tools/call kick_claude   owner-gated, claude:kick scope
//   - GET  /claude-inbox       admin list (TRIGGER_KEY)
//   - POST /claude-inbox/status admin status updates (TRIGGER_KEY)
//   - GET  /claude-inbox/signal public pending count only
// Runs fully locally on Miniflare with a synthetic IdP, like auth.test.mjs.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createHmac,
  createSign,
  generateKeyPairSync,
  createPublicKey,
  randomBytes,
} from "node:crypto";
import { Miniflare } from "miniflare";

const ORIGIN = "https://dots-events.test";
const RESOURCE = ORIGIN + "/mcp";
const ISSUER = "https://idp.example.test";
const TRIGGER_KEY = "test-trigger-key";
const HOOK_SECRET = "whsec_" + randomBytes(32).toString("base64");

const b64url = (buf) =>
  Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

function makeKey(kid) {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  return { kid, privateKey, publicJwk: { ...jwk, kid, use: "sig", alg: "ES256" } };
}
const key1 = makeKey("test-key-1");

function mintJwt(claims = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: key1.kid };
  const payload = {
    iss: ISSUER,
    aud: RESOURCE,
    sub: "user-1",
    scope: "events:read events:subscribe requests:read requests:update claude:kick",
    cid: "test-client",
    iat: now,
    exp: now + 900,
    ...claims,
  };
  const input = b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(payload));
  const sig = createSign("SHA256")
    .update(input)
    .sign({ key: key1.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + b64url(sig);
}

async function outboundService(req) {
  if (req.url === ISSUER + "/.well-known/jwks.json") {
    return Response.json({ keys: [key1.publicJwk] });
  }
  return new Response("not found", { status: 404 });
}

let mf;
before(async () => {
  mf = new Miniflare({
    modules: true,
    scriptPath: new URL("../worker.js", import.meta.url).pathname,
    compatibilityDate: "2025-11-01",
    durableObjects: { STORE: "Store" },
    bindings: {
      TRIGGER_KEY,
      CLAUDE_HOOK_SECRET: HOOK_SECRET,
      IDP_ISSUER: ISSUER,
      RESOURCE_URI: RESOURCE,
      OWNER_SUB: "user-1",
    },
    outboundService,
  });
  await mf.ready;
});
after(async () => {
  await mf.dispose();
});

function signHook(secret, msgId, ts, body) {
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const sig = createHmac("sha256", key).update(`${msgId}.${ts}.${body}`).digest("base64");
  return "v1," + sig;
}

async function hook(bodyObj, { secret = HOOK_SECRET, tsOffsetSec = 0, msgId = "msg_test_1" } = {}) {
  const body = JSON.stringify(bodyObj);
  const ts = String(Math.floor(Date.now() / 1000) + tsOffsetSec);
  const res = await mf.dispatchFetch(ORIGIN + "/claude-hook", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "webhook-id": msgId,
      "webhook-timestamp": ts,
      "webhook-signature": signHook(secret, msgId, ts, body),
    },
    body,
  });
  return { status: res.status, json: await res.json() };
}

async function signal() {
  const res = await mf.dispatchFetch(ORIGIN + "/claude-inbox/signal");
  return { status: res.status, json: await res.json() };
}

async function inbox(params = "", key = TRIGGER_KEY) {
  const headers = {};
  if (key) headers.Authorization = "Bearer " + key;
  const res = await mf.dispatchFetch(ORIGIN + "/claude-inbox" + params, { headers });
  return { status: res.status, json: await res.json() };
}

async function inboxStatus(bodyObj, key = TRIGGER_KEY) {
  const headers = { "Content-Type": "application/json" };
  if (key) headers.Authorization = "Bearer " + key;
  const res = await mf.dispatchFetch(ORIGIN + "/claude-inbox/status", {
    method: "POST",
    headers,
    body: JSON.stringify(bodyObj),
  });
  return { status: res.status, json: await res.json() };
}

async function rpc(payload, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  const res = await mf.dispatchFetch(ORIGIN + "/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    /* empty */
  }
  return { status: res.status, json };
}

function toolJson(rpcRes) {
  const text = rpcRes.json?.result?.content?.[0]?.text;
  return text ? JSON.parse(text) : null;
}

test("claude-hook accepts a correctly signed webhook and files a pending request", async () => {
  const before0 = await signal();
  const r = await hook({ text: "webhook からの依頼テスト", request_id: "hook-req-1" });
  assert.equal(r.status, 200);
  assert.equal(r.json.request_id, "hook-req-1");
  assert.equal(r.json.status, "pending");
  assert.equal(r.json.deduplicated, false);
  const after1 = await signal();
  assert.equal(after1.json.pending, before0.json.pending + 1);
});

test("claude-hook deduplicates a repeated request_id", async () => {
  const r = await hook({ text: "同じ依頼の再送", request_id: "hook-req-1" });
  assert.equal(r.status, 200);
  assert.equal(r.json.deduplicated, true);
  assert.equal(r.json.request_id, "hook-req-1");
});

test("claude-hook rejects a bad signature with 401", async () => {
  const body = JSON.stringify({ text: "署名が違う" });
  const ts = String(Math.floor(Date.now() / 1000));
  const res = await mf.dispatchFetch(ORIGIN + "/claude-hook", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "webhook-id": "msg_bad",
      "webhook-timestamp": ts,
      "webhook-signature": signHook("whsec_" + randomBytes(32).toString("base64"), "msg_bad", ts, body),
    },
    body,
  });
  assert.equal(res.status, 401);
});

test("claude-hook rejects a stale timestamp with 400", async () => {
  const r = await hook({ text: "古い" }, { tsOffsetSec: -3600 });
  assert.equal(r.status, 400);
});

test("claude-hook rejects a missing text with 400", async () => {
  const r = await hook({ topic: "text なし" });
  assert.equal(r.status, 400);
});

test("claude-inbox requires the admin key and lists filed requests", async () => {
  const noKey = await inbox("", null);
  assert.equal(noKey.status, 401);
  const wrongKey = await inbox("", "not-the-key");
  assert.equal(wrongKey.status, 401);
  const ok = await inbox();
  assert.equal(ok.status, 200);
  const found = ok.json.requests.find((r) => r.id === "hook-req-1");
  assert.ok(found);
  assert.equal(found.origin, "webhook");
  assert.equal(found.status, "pending");
});

test("claude-inbox status updates move pending -> acknowledged -> completed and move the signal", async () => {
  const ack = await inboxStatus({ request_id: "hook-req-1", status: "acknowledged" });
  assert.equal(ack.status, 200);
  assert.equal(ack.json.status, "acknowledged");
  const sig = await signal();
  assert.equal(sig.json.pending, 0);
  const done = await inboxStatus({ request_id: "hook-req-1", status: "completed", note: "done" });
  assert.equal(done.status, 200);
  assert.equal(done.json.status, "completed");
  const missing = await inboxStatus({ request_id: "no-such", status: "acknowledged" });
  assert.equal(missing.status, 404);
  const badStatus = await inboxStatus({ request_id: "hook-req-1", status: "pending" });
  assert.equal(badStatus.status, 400);
});

test("signal exposes only a count, no request data", async () => {
  const s = await signal();
  assert.equal(s.status, 200);
  assert.deepEqual(Object.keys(s.json), ["pending"]);
});

test("kick_claude files a request for the owner with the claude:kick scope", async () => {
  const token = mintJwt();
  const r = await rpc(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "kick_claude", arguments: { text: "dots からの依頼", topic: "test" } },
    },
    token
  );
  assert.equal(r.status, 200);
  const out = toolJson(r);
  assert.ok(out?.request_id?.startsWith("creq_"));
  assert.equal(out.status, "pending");
  const list = await inbox();
  const found = list.json.requests.find((x) => x.id === out.request_id);
  assert.ok(found);
  assert.equal(found.origin, "tool");
  assert.equal(found.topic, "test");
});

test("kick_claude without the claude:kick scope is 403", async () => {
  const token = mintJwt({ scope: "events:read requests:update" });
  const r = await rpc(
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "kick_claude", arguments: { text: "スコープ不足" } },
    },
    token
  );
  assert.equal(r.status, 403);
});

test("kick_claude from a non-owner subject is rejected", async () => {
  const token = mintJwt({ sub: "user-2" });
  const r = await rpc(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "kick_claude", arguments: { text: "他人からの依頼" } },
    },
    token
  );
  assert.notEqual(r.status, 200);
  const list = await inbox();
  assert.equal(list.json.requests.some((x) => x.text === "他人からの依頼"), false);
});

test("PRM advertises the claude:kick scope", async () => {
  const res = await mf.dispatchFetch(ORIGIN + "/.well-known/oauth-protected-resource");
  const j = await res.json();
  assert.ok(j.scopes_supported.includes("claude:kick"));
});

test("tools/list includes kick_claude", async () => {
  const token = mintJwt();
  const r = await rpc({ jsonrpc: "2.0", id: 4, method: "tools/list", params: {} }, token);
  const names = r.json.result.tools.map((t) => t.name);
  assert.ok(names.includes("kick_claude"));
});
