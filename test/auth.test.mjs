// Automated tests for dots-kick-events as an OAuth 2.1 *resource server*
// backed by 0g0-id: JWT/JWKS validation, per-method scopes, subscription
// ownership, trigger authentication + request_id dedup, webhook signature
// verification, and kick compatibility. Runs fully locally on Miniflare —
// no production access, synthetic keys and credentials only.
//
//   npm test
//
// The IdP (0g0-id) is simulated by minting ES256 JWTs with a synthetic key
// pair and serving its public half as a JWKS document through Miniflare's
// outboundService. The same stub simulates the ChatGPT callback receiver:
// it verifies Standard Webhooks signatures with Node's crypto, echoes
// verification challenges, and records event deliveries for assertions.

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
const RECEIVER = "https://receiver.example.test/callback";
const TRIGGER_KEY = "test-trigger-key";
const WHSEC = "whsec_" + randomBytes(32).toString("base64");
const ECHO_SECRET = "whsec_" + randomBytes(32).toString("base64");
const ALL_SCOPES = "events:read events:subscribe requests:read requests:update";

const b64url = (buf) =>
  Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

// --- synthetic IdP signing keys ---
function makeKey(kid) {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  return {
    kid,
    privateKey,
    publicJwk: { ...jwk, kid, use: "sig", alg: "ES256" },
  };
}
const key1 = makeKey("test-key-1");
const key2 = makeKey("test-key-2"); // introduced later (rotation test)
const attackerKey = makeKey("test-key-1"); // same kid, different key material
let jwksKeys = [key1.publicJwk]; // served by the stub; mutated by rotation test

function mintJwt(key, claims = {}) {
  const now = Math.floor(Date.now() / 1000);
  const header = { alg: "ES256", typ: "JWT", kid: key.kid };
  const payload = {
    iss: ISSUER,
    aud: RESOURCE,
    sub: "user-1",
    scope: ALL_SCOPES,
    cid: "test-client",
    iat: now,
    exp: now + 900,
    ...claims,
  };
  const input = b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(payload));
  const sig = createSign("SHA256")
    .update(input)
    .sign({ key: key.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + b64url(sig);
}

// --- simulated IdP JWKS endpoint + ChatGPT callback receiver ---
const deliveries = []; // event deliveries only (verification posts excluded)
function verifyStdWebhook(secret, msgId, ts, body, sigHeader) {
  const keyBytes = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const expected = createHmac("sha256", keyBytes)
    .update(`${msgId}.${ts}.${body}`)
    .digest("base64");
  return String(sigHeader || "")
    .split(" ")
    .some((part) => {
      const [v, b64] = part.split(",");
      return v === "v1" && b64 === expected;
    });
}
async function outboundService(req) {
  const bodyText = await req.text();
  if (req.url === ISSUER + "/.well-known/jwks.json") {
    return Response.json({ keys: jwksKeys });
  }
  if (req.url.startsWith(RECEIVER)) {
    const sigValid = verifyStdWebhook(
      WHSEC,
      req.headers.get("webhook-id"),
      req.headers.get("webhook-timestamp"),
      bodyText,
      req.headers.get("webhook-signature")
    );
    let parsed = {};
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      /* ignore */
    }
    if (parsed.type === "verification") {
      if (!sigValid) return new Response("bad signature", { status: 403 });
      return Response.json({ challenge: parsed.challenge });
    }
    deliveries.push({
      url: req.url,
      subscriptionId: req.headers.get("x-mcp-subscription-id"),
      signatureValid: sigValid,
      body: parsed,
    });
    return Response.json({ ok: true });
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
      IDP_ISSUER: ISSUER,
      RESOURCE_URI: RESOURCE,
      TEST_ECHO: "1",
      TEST_ECHO_SECRET: ECHO_SECRET,
    },
    outboundService,
  });
  await mf.ready;
});
after(async () => {
  await mf.dispose();
});

// --- helpers ---
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
  return { status: res.status, headers: res.headers, json };
}
async function trigger(body, key = TRIGGER_KEY) {
  const headers = { "Content-Type": "application/json" };
  if (key) headers.Authorization = "Bearer " + key;
  const res = await mf.dispatchFetch(ORIGIN + "/trigger", {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}
function subscribeCall(token) {
  return rpc(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "events/subscribe",
      params: {
        name: "kick",
        arguments: {},
        delivery: { mode: "webhook", url: RECEIVER, secret: WHSEC },
      },
    },
    token
  );
}

// ---------------- metadata ----------------

test("protected resource metadata names 0g0-id as the authorization server; built-in AS is gone", async () => {
  const res = await mf.dispatchFetch(ORIGIN + "/.well-known/oauth-protected-resource");
  assert.equal(res.status, 200);
  const meta = await res.json();
  assert.equal(meta.resource, RESOURCE);
  assert.deepEqual(meta.authorization_servers, [ISSUER]);
  assert.deepEqual(meta.scopes_supported, ALL_SCOPES.split(" "));

  for (const path of [
    "/.well-known/oauth-authorization-server",
    "/.well-known/openid-configuration",
    "/oauth/authorize",
    "/oauth/token",
    "/oauth/register",
  ]) {
    const r = await mf.dispatchFetch(ORIGIN + path);
    assert.equal(r.status, 404, path);
  }
});

// ---------------- token validation ----------------

test("unauthenticated /mcp call is 401 with a resource_metadata challenge", async () => {
  const res = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} });
  assert.equal(res.status, 401);
  const wa = res.headers.get("www-authenticate") || "";
  assert.ok(wa.includes('resource_metadata="'), wa);
  assert.ok(wa.includes("events:subscribe"), wa);
});

test("opaque (non-JWT) tokens are rejected", async () => {
  const res = await rpc(
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    "at_opaque_token_value"
  );
  assert.equal(res.status, 401);
});

test("valid 0g0-id JWT passes initialize, server/discover and events/list (kick schema unchanged)", async () => {
  const token = mintJwt(key1);
  const init = await rpc(
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } },
    token
  );
  assert.equal(init.status, 200, JSON.stringify(init.json));
  assert.deepEqual(init.json.result.capabilities.events, {});

  const discover = await rpc({ jsonrpc: "2.0", id: 2, method: "server/discover" }, token);
  assert.equal(discover.status, 200);
  assert.deepEqual(discover.json.result.supportedVersions, ["2026-07-28"]);

  const list = await rpc({ jsonrpc: "2.0", id: 3, method: "events/list", params: {} }, token);
  assert.equal(list.status, 200);
  assert.equal(list.json.result.events.length, 1);
  const ev = list.json.result.events[0];
  assert.equal(ev.name, "kick");
  assert.deepEqual(ev.delivery, ["webhook"]);
  assert.deepEqual(ev.payloadSchema.required, ["request_id", "text", "created_at"]);
  assert.deepEqual(Object.keys(ev.payloadSchema.properties).sort(), [
    "created_at",
    "request_id",
    "text",
    "topic",
  ]);
});

test("bad signature is rejected", async () => {
  const forged = mintJwt(attackerKey); // same kid, wrong key material
  const res = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, forged);
  assert.equal(res.status, 401);
});

test("tampered payload is rejected", async () => {
  const genuine = mintJwt(key1);
  const [h, , s] = genuine.split(".");
  const now = Math.floor(Date.now() / 1000);
  const tamperedPayload = b64url(
    JSON.stringify({ iss: ISSUER, aud: RESOURCE, sub: "admin", scope: ALL_SCOPES, exp: now + 900 })
  );
  const res = await rpc(
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    `${h}.${tamperedPayload}.${s}`
  );
  assert.equal(res.status, 401);
});

test("expired token is rejected", async () => {
  const now = Math.floor(Date.now() / 1000);
  const expired = mintJwt(key1, { iat: now - 2000, exp: now - 1000 });
  const res = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, expired);
  assert.equal(res.status, 401);
});

test("wrong issuer is rejected", async () => {
  const token = mintJwt(key1, { iss: "https://evil.example.test" });
  const res = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, token);
  assert.equal(res.status, 401);
});

test("wrong audience is rejected", async () => {
  const token = mintJwt(key1, { aud: "https://other.example.test/mcp" });
  const res = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, token);
  assert.equal(res.status, 401);
});

test("insufficient scope is 403 with an insufficient_scope step-up challenge", async () => {
  const readOnly = mintJwt(key1, { scope: "events:read" });
  const list = await rpc({ jsonrpc: "2.0", id: 1, method: "events/list", params: {} }, readOnly);
  assert.equal(list.status, 200);

  const denied = await subscribeCall(readOnly);
  assert.equal(denied.status, 403);
  const wa = denied.headers.get("www-authenticate") || "";
  assert.ok(wa.includes('error="insufficient_scope"'), wa);
  assert.ok(wa.includes("events:subscribe"), wa);
});

test("key rotation: a token signed with a newly published kid validates after JWKS refetch", async () => {
  const token = mintJwt(key2);
  const beforeRotation = await rpc(
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    token
  );
  assert.equal(beforeRotation.status, 401); // kid unknown at first

  jwksKeys = [key1.publicJwk, key2.publicJwk]; // IdP publishes the new key
  // The worker rate-limits forced JWKS refetches (unknown kid) to 1/second.
  await new Promise((r) => setTimeout(r, 1100));
  const afterRotation = await rpc(
    { jsonrpc: "2.0", id: 1, method: "initialize", params: {} },
    token
  );
  assert.equal(afterRotation.status, 200);
});

// ---------------- lifecycle with a valid token ----------------

test("subscribe -> trigger (signed delivery) -> status tools -> unsubscribe", async () => {
  const token = mintJwt(key1);
  const before = deliveries.length;

  const sub = await subscribeCall(token);
  assert.equal(sub.status, 200, JSON.stringify(sub.json));
  assert.ok(sub.json.result.id.startsWith("sub_"));
  assert.ok(sub.json.result.refreshBefore);

  const fired = await trigger({ text: "お願いします", request_id: "req-flow-1" });
  assert.equal(fired.status, 200);
  assert.equal(fired.json.request_id, "req-flow-1");
  assert.equal(fired.json.delivered, 1);
  assert.equal(deliveries.length, before + 1);
  const delivery = deliveries[deliveries.length - 1];
  assert.equal(delivery.signatureValid, true);
  assert.equal(delivery.subscriptionId, sub.json.result.id);
  assert.equal(delivery.body.name, "kick");
  assert.equal(delivery.body.data.request_id, "req-flow-1");
  assert.equal(delivery.body.data.text, "お願いします");

  const list = await rpc(
    { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "list_pending_requests", arguments: {} } },
    token
  );
  const found = JSON.parse(list.json.result.content[0].text).requests.find(
    (r) => r.id === "req-flow-1"
  );
  assert.equal(found.status, "delivered");

  for (const status of ["acknowledged", "completed"]) {
    const upd = await rpc(
      {
        jsonrpc: "2.0",
        id: 3,
        method: "tools/call",
        params: { name: "update_request_status", arguments: { request_id: "req-flow-1", status } },
      },
      token
    );
    assert.equal(JSON.parse(upd.json.result.content[0].text).status, status);
  }

  const unsub = await rpc(
    {
      jsonrpc: "2.0",
      id: 4,
      method: "events/unsubscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER } },
    },
    token
  );
  assert.equal(unsub.status, 200);
  const after = await trigger({ text: "もう届かないはず", request_id: "req-flow-2" });
  assert.equal(after.json.subscriptions_matched, 0);
  assert.equal(deliveries.length, before + 1);
});

test("another principal cannot remove someone else's subscription", async () => {
  const owner = mintJwt(key1, { sub: "user-1" });
  const stranger = mintJwt(key1, { sub: "user-2" });
  const sub = await subscribeCall(owner);
  assert.equal(sub.status, 200);

  const attempt = await rpc(
    {
      jsonrpc: "2.0",
      id: 9,
      method: "events/unsubscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER } },
    },
    stranger
  );
  assert.equal(attempt.status, 200); // idempotent response...

  const before = deliveries.length; // ...but the subscription must still fire
  const fired = await trigger({ text: "所有者確認", request_id: "req-owner-1" });
  assert.equal(fired.json.delivered, 1);
  assert.equal(deliveries.length, before + 1);

  // cleanup
  await rpc(
    {
      jsonrpc: "2.0",
      id: 10,
      method: "events/unsubscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER } },
    },
    owner
  );
});

// ---------------- trigger endpoint ----------------

test("trigger requires the admin key (separate from IdP tokens)", async () => {
  const noKey = await trigger({ text: "x" }, null);
  assert.equal(noKey.status, 401);
  const wrongKey = await trigger({ text: "x" }, "not-the-key");
  assert.equal(wrongKey.status, 401);
  // An IdP access token is not a trigger credential.
  const withJwt = await trigger({ text: "x" }, mintJwt(key1));
  assert.equal(withJwt.status, 401);
});

test("duplicate request_id is deduplicated atomically: one delivery, no overwrite", async () => {
  const token = mintJwt(key1);
  const sub = await subscribeCall(token);
  assert.equal(sub.status, 200);
  const before = deliveries.length;

  const first = await trigger({
    text: "一回だけ届く",
    request_id: "req-dup-1",
    status: "completed", // payload must not be able to overwrite state
    deliveries: [{ ok: true }],
  });
  assert.equal(first.status, 200);
  assert.equal(first.json.deduplicated, false);
  assert.equal(first.json.status, "delivered");

  const second = await trigger({ text: "一回だけ届く", request_id: "req-dup-1" });
  assert.equal(second.json.deduplicated, true);
  assert.equal(second.json.request_id, "req-dup-1");
  assert.equal(deliveries.length, before + 1);

  // The stored record kept the server-managed lifecycle, not the payload's.
  const list = await rpc(
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "list_pending_requests", arguments: {} } },
    token
  );
  const found = JSON.parse(list.json.result.content[0].text).requests.find(
    (r) => r.id === "req-dup-1"
  );
  assert.equal(found.status, "delivered");

  await rpc(
    {
      jsonrpc: "2.0",
      id: 6,
      method: "events/unsubscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER } },
    },
    token
  );
});

// ---------------- test echo (webhook signature verdict) ----------------

test("/test-echo accepts correctly signed webhooks and rejects tampered ones", async () => {
  const body = JSON.stringify({ type: "verification", challenge: "abc" });
  const msgId = "msg_test_1";
  const ts = String(Math.floor(Date.now() / 1000));
  const keyBytes = Buffer.from(ECHO_SECRET.replace(/^whsec_/, ""), "base64");
  const sig = createHmac("sha256", keyBytes).update(`${msgId}.${ts}.${body}`).digest("base64");

  const okRes = await mf.dispatchFetch(ORIGIN + "/test-echo", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "webhook-id": msgId,
      "webhook-timestamp": ts,
      "webhook-signature": "v1," + sig,
    },
    body,
  });
  assert.equal(okRes.status, 200);
  assert.deepEqual(await okRes.json(), { challenge: "abc" });

  const badRes = await mf.dispatchFetch(ORIGIN + "/test-echo", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "webhook-id": msgId,
      "webhook-timestamp": ts,
      "webhook-signature": "v1," + sig,
    },
    body: body + " ", // tampered
  });
  assert.equal(badRes.status, 403);
});
