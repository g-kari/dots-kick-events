// Automated tests for dots-kick-events: OAuth 2.1 authorization, subscription
// ownership, trigger authentication + request_id dedup, webhook signature
// verification, and kick compatibility. Runs fully locally on Miniflare —
// no production access, synthetic credentials only.
//
//   npm test
//
// The ChatGPT callback receiver is simulated by Miniflare's outboundService:
// it verifies Standard Webhooks signatures with Node's crypto, echoes
// verification challenges, and records event deliveries for assertions.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { Miniflare } from "miniflare";

const ORIGIN = "https://dots-events.test";
const RESOURCE = ORIGIN + "/mcp";
const RECEIVER = "https://receiver.example.test/callback";
const REDIRECT_URI = "https://chatgpt.com/connector/oauth/test-callback";
const OWNER_PASSWORD = "test-owner-password";
const TRIGGER_KEY = "test-trigger-key";
const WHSEC = "whsec_" + randomBytes(32).toString("base64");
const ECHO_SECRET = "whsec_" + randomBytes(32).toString("base64");

const sha256hex = (s) => createHash("sha256").update(s).digest("hex");
const b64url = (buf) =>
  Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// --- simulated ChatGPT callback receiver ---
const deliveries = []; // event deliveries only (verification posts excluded)
function verifyStdWebhook(secret, msgId, ts, body, sigHeader) {
  const key = Buffer.from(secret.replace(/^whsec_/, ""), "base64");
  const expected = createHmac("sha256", key).update(`${msgId}.${ts}.${body}`).digest();
  for (const part of String(sigHeader || "").split(" ")) {
    const [v, b64] = part.split(",");
    if (v !== "v1" || !b64) continue;
    const got = Buffer.from(b64, "base64");
    if (got.length === expected.length && createHmac("sha256", key).update(`${msgId}.${ts}.${body}`).digest("base64") === b64) return true;
  }
  return false;
}
async function outboundService(req) {
  const bodyText = await req.text();
  if (req.url.startsWith(RECEIVER)) {
    const sigValid = verifyStdWebhook(
      WHSEC,
      req.headers.get("webhook-id"),
      req.headers.get("webhook-timestamp"),
      bodyText,
      req.headers.get("webhook-signature")
    );
    let parsed = {};
    try { parsed = JSON.parse(bodyText); } catch { /* ignore */ }
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
let storeStub;

before(async () => {
  mf = new Miniflare({
    modules: true,
    scriptPath: new URL("../worker.js", import.meta.url).pathname,
    compatibilityDate: "2025-11-01",
    durableObjects: { STORE: "Store" },
    bindings: {
      TRIGGER_KEY,
      OWNER_PASSWORD_HASH: sha256hex(OWNER_PASSWORD),
      AUTH_SECRET: "test-auth-secret-0123456789abcdef",
      TEST_ECHO: "1",
      TEST_ECHO_SECRET: ECHO_SECRET,
    },
    outboundService,
  });
  await mf.ready;
  const ns = await mf.getDurableObjectNamespace("STORE");
  storeStub = ns.get(ns.idFromName("global"));
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
  try { json = JSON.parse(text); } catch { /* empty */ }
  return { status: res.status, headers: res.headers, json };
}

async function registerClient() {
  const res = await mf.dispatchFetch(ORIGIN + "/oauth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Test Client",
      redirect_uris: [REDIRECT_URI],
      grant_types: ["authorization_code", "refresh_token"],
      token_endpoint_auth_method: "none",
    }),
  });
  assert.equal(res.status, 201);
  const body = await res.json();
  return body.client_id;
}

// Runs the full authorization-code + PKCE flow the way ChatGPT does:
// authorize -> owner password login -> consent -> code -> token exchange.
async function runAuthFlow(clientId, { verifier, password = OWNER_PASSWORD } = {}) {
  verifier = verifier || b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const q = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: "S256",
    scope: "events:read events:subscribe requests:read requests:update",
    state: "state-123",
    resource: RESOURCE,
  });
  const loginRes = await mf.dispatchFetch(ORIGIN + "/oauth/authorize?" + q);
  assert.equal(loginRes.status, 200);
  const loginHtml = await loginRes.text();
  const pending = loginHtml.match(/name="pending" value="([0-9a-f]+)"/)?.[1];
  assert.ok(pending, "login page carries a pending id");

  const loginPost = await mf.dispatchFetch(ORIGIN + "/oauth/login", {
    method: "POST",
    body: new URLSearchParams({ pending, password }),
    redirect: "manual",
  });
  if (password !== OWNER_PASSWORD) {
    return { loginStatus: loginPost.status };
  }
  assert.equal(loginPost.status, 303);
  const cookie = (loginPost.headers.getSetCookie?.()[0] || "").split(";")[0];
  assert.ok(cookie.startsWith("dke_session="), "session cookie issued");

  const consentRes = await mf.dispatchFetch(ORIGIN + "/oauth/authorize?pending=" + pending, {
    headers: { Cookie: cookie },
  });
  assert.equal(consentRes.status, 200);
  const consentHtml = await consentRes.text();
  const csrf = consentHtml.match(/name="csrf" value="([0-9a-f]+)"/)?.[1];
  assert.ok(csrf, "consent page carries a csrf token");

  const consentPost = await mf.dispatchFetch(ORIGIN + "/oauth/consent", {
    method: "POST",
    headers: { Cookie: cookie },
    body: new URLSearchParams({ pending, csrf, decision: "approve" }),
    redirect: "manual",
  });
  assert.equal(consentPost.status, 303);
  const loc = new URL(consentPost.headers.get("location"));
  assert.equal(loc.searchParams.get("iss"), ORIGIN, "RFC 9207 iss is returned");
  assert.equal(loc.searchParams.get("state"), "state-123");
  const code = loc.searchParams.get("code");
  assert.ok(code, "authorization code issued");

  const exchange = async (v) => {
    const res = await mf.dispatchFetch(ORIGIN + "/oauth/token", {
      method: "POST",
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        redirect_uri: REDIRECT_URI,
        code_verifier: v,
        resource: RESOURCE,
      }),
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };
  return { exchange, verifier };
}

async function getTokens(clientId) {
  const flow = await runAuthFlow(clientId);
  const { status, body } = await flow.exchange(flow.verifier);
  assert.equal(status, 200, JSON.stringify(body));
  return body;
}

// Writes a token record directly into the store (simulating tokens minted
// under other conditions: expired, wrong audience, another principal, ...).
async function forgeToken(record) {
  const token = "at_forged_" + randomBytes(16).toString("hex");
  const res = await storeStub.fetch("https://store/put", {
    method: "POST",
    body: JSON.stringify({
      key: "token:" + sha256hex(token),
      value: JSON.stringify({
        kind: "access",
        principal: "owner",
        clientId: "client_forged",
        scope: ["events:read", "events:subscribe", "requests:read", "requests:update"],
        aud: RESOURCE,
        iss: ORIGIN,
        exp: Date.now() + 3600_000,
        ...record,
      }),
    }),
  });
  assert.equal(res.status, 200);
  return token;
}

const deliveriesFor = (requestId) =>
  deliveries.filter((d) => d.body?.data?.request_id === requestId);

// --- tests ---

test("discovery metadata: RFC 9728 + RFC 8414 documents are consistent", async () => {
  for (const path of ["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"]) {
    const res = await mf.dispatchFetch(ORIGIN + path);
    assert.equal(res.status, 200, path);
    const doc = await res.json();
    assert.equal(doc.resource, RESOURCE);
    assert.deepEqual(doc.authorization_servers, [ORIGIN]);
    for (const s of ["events:read", "events:subscribe", "requests:read", "requests:update"]) {
      assert.ok(doc.scopes_supported.includes(s), s);
    }
  }
  const res = await mf.dispatchFetch(ORIGIN + "/.well-known/oauth-authorization-server");
  assert.equal(res.status, 200);
  const meta = await res.json();
  assert.equal(meta.issuer, ORIGIN);
  assert.ok(meta.code_challenge_methods_supported.includes("S256"));
  assert.ok(meta.registration_endpoint.endsWith("/oauth/register"));
  assert.ok(meta.authorization_endpoint.endsWith("/oauth/authorize"));
  assert.ok(meta.token_endpoint.endsWith("/oauth/token"));
  assert.equal(meta.authorization_response_iss_parameter_supported, true);
});

test("unauthenticated MCP calls get 401 + WWW-Authenticate challenge", async () => {
  const anon = await rpc({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }, null);
  assert.equal(anon.status, 401);
  const wa = anon.headers.get("www-authenticate") || "";
  assert.ok(wa.includes(`resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp"`), wa);
  assert.ok(wa.includes("events:read"), wa);

  const bogus = await rpc({ jsonrpc: "2.0", id: 1, method: "events/list" }, "at_does_not_exist");
  assert.equal(bogus.status, 401);
  assert.ok((bogus.headers.get("www-authenticate") || "").includes('error="invalid_token"'));
});

test("auth flow: wrong password rejected, PKCE enforced, code is single-use", async () => {
  const clientId = await registerClient();

  const bad = await runAuthFlow(clientId, { password: "wrong-password" });
  assert.equal(bad.loginStatus, 401);

  const flow = await runAuthFlow(clientId);
  const wrongVerifier = await flow.exchange("not-the-right-verifier");
  assert.equal(wrongVerifier.status, 400);
  assert.equal(wrongVerifier.body.error, "invalid_grant");
  // The failed exchange consumed the code: even the right verifier now fails.
  const replay = await flow.exchange(flow.verifier);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, "invalid_grant");

  const tokens = await getTokens(clientId);
  assert.ok(tokens.access_token.startsWith("at_"));
  assert.ok(tokens.refresh_token.startsWith("rt_"));
  assert.equal(tokens.expires_in, 3600);
});

test("authenticated MCP works and the kick schema is unchanged", async () => {
  const clientId = await registerClient();
  const tokens = await getTokens(clientId);

  const init = await rpc(
    { jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-03-26" } },
    tokens.access_token
  );
  assert.equal(init.status, 200);
  assert.equal(init.json.result.capabilities.events !== undefined, true);

  const list = await rpc({ jsonrpc: "2.0", id: 2, method: "events/list" }, tokens.access_token);
  assert.equal(list.status, 200);
  const kick = list.json.result.events[0];
  assert.equal(kick.name, "kick");
  assert.deepEqual(kick.delivery, ["webhook"]);
  assert.deepEqual(
    Object.keys(kick.payloadSchema.properties).sort(),
    ["created_at", "request_id", "text", "topic"]
  );
  assert.deepEqual(kick.payloadSchema.required.sort(), ["created_at", "request_id", "text"]);
  assert.ok(kick.inputSchema.properties.topic);
});

test("expired, wrong-audience, wrong-issuer and refresh tokens are rejected", async () => {
  const cases = [
    await forgeToken({ exp: Date.now() - 1000 }),
    await forgeToken({ aud: "https://other.example/mcp" }),
    await forgeToken({ iss: "https://other.example" }),
    await forgeToken({ kind: "refresh" }),
  ];
  for (const token of cases) {
    const res = await rpc({ jsonrpc: "2.0", id: 1, method: "events/list" }, token);
    assert.equal(res.status, 401);
  }
});

test("insufficient scope gets a 403 step-up challenge", async () => {
  const token = await forgeToken({ scope: ["events:read"] });
  const ok = await rpc({ jsonrpc: "2.0", id: 1, method: "events/list" }, token);
  assert.equal(ok.status, 200);
  const denied = await rpc(
    {
      jsonrpc: "2.0", id: 2, method: "events/subscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER, secret: WHSEC } },
    },
    token
  );
  assert.equal(denied.status, 403);
  const wa = denied.headers.get("www-authenticate") || "";
  assert.ok(wa.includes('error="insufficient_scope"'), wa);
  assert.ok(wa.includes("events:subscribe"), wa);
});

// Shared state for the lifecycle tests below.
const life = {};

test("subscribe -> trigger -> signed delivery -> status reconciliation", async () => {
  const clientId = await registerClient();
  const tokens = await getTokens(clientId);
  life.clientId = clientId;
  life.tokens = tokens;

  const sub = await rpc(
    {
      jsonrpc: "2.0", id: 1, method: "events/subscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER, secret: WHSEC } },
    },
    tokens.access_token
  );
  assert.equal(sub.status, 200, JSON.stringify(sub.json));
  assert.ok(sub.json.result.id.startsWith("sub_"));
  assert.ok(sub.json.result.refreshBefore);
  life.subId = sub.json.result.id;

  // Trigger requires the admin key (separate from OAuth).
  const noKey = await mf.dispatchFetch(ORIGIN + "/trigger", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: "should not fire" }),
  });
  assert.equal(noKey.status, 401);

  const fire = await mf.dispatchFetch(ORIGIN + "/trigger", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + TRIGGER_KEY },
    body: JSON.stringify({ text: "テスト依頼です", request_id: "test-req-001" }),
  });
  assert.equal(fire.status, 200);
  const fired = await fire.json();
  assert.equal(fired.request_id, "test-req-001");
  assert.equal(fired.deduplicated, false);
  assert.equal(fired.delivered, 1);

  const got = deliveriesFor("test-req-001");
  assert.equal(got.length, 1, "exactly one delivery");
  assert.equal(got[0].signatureValid, true, "Standard Webhooks signature verifies");
  assert.equal(got[0].subscriptionId, life.subId);
  assert.equal(got[0].body.data.text, "テスト依頼です");
  assert.equal(got[0].body.name, "kick");

  // Duplicate trigger (same client request_id): no second delivery.
  const dup = await mf.dispatchFetch(ORIGIN + "/trigger", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + TRIGGER_KEY },
    body: JSON.stringify({ text: "テスト依頼です", request_id: "test-req-001" }),
  });
  const dupBody = await dup.json();
  assert.equal(dupBody.deduplicated, true);
  assert.equal(deliveriesFor("test-req-001").length, 1);

  // Concurrent duplicates: still exactly one creation + one delivery.
  const mk = () =>
    mf.dispatchFetch(ORIGIN + "/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + TRIGGER_KEY },
      body: JSON.stringify({ text: "同時送信", request_id: "test-req-002" }),
    }).then((r) => r.json());
  const [a, b] = await Promise.all([mk(), mk()]);
  assert.ok(a.deduplicated !== b.deduplicated, "exactly one of the pair created the request");
  assert.equal(deliveriesFor("test-req-002").length, 1);

  // Reconciliation via tools.
  const pending = await rpc(
    { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "list_pending_requests", arguments: {} } },
    tokens.access_token
  );
  const mine = pending.json.result.content[0].text;
  const parsed = JSON.parse(mine);
  const rec = parsed.requests.find((r) => r.id === "test-req-001");
  assert.ok(rec, "request is listed as pending work");
  assert.equal(rec.status, "delivered", "2xx means receipt, not completion");

  for (const status of ["acknowledged", "completed"]) {
    const upd = await rpc(
      {
        jsonrpc: "2.0", id: 4, method: "tools/call",
        params: { name: "update_request_status", arguments: { request_id: "test-req-001", status } },
      },
      tokens.access_token
    );
    assert.equal(upd.status, 200);
  }
  const after = await rpc(
    { jsonrpc: "2.0", id: 5, method: "tools/call", params: { name: "list_pending_requests", arguments: {} } },
    tokens.access_token
  );
  const afterParsed = JSON.parse(after.json.result.content[0].text);
  assert.ok(!afterParsed.requests.some((r) => r.id === "test-req-001"), "completed requests leave the pending list");
});

test("another principal cannot unsubscribe or hijack the owner's subscription", async () => {
  const mallory = await forgeToken({ principal: "mallory" });

  // Mallory's unsubscribe with identical (name, args, url) must not remove
  // the owner's subscription.
  const unsub = await rpc(
    {
      jsonrpc: "2.0", id: 1, method: "events/unsubscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER } },
    },
    mallory
  );
  assert.equal(unsub.status, 200);

  // Mallory subscribing the same triple yields a different subscription id.
  const mallorySub = await rpc(
    {
      jsonrpc: "2.0", id: 2, method: "events/subscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER, secret: WHSEC } },
    },
    mallory
  );
  assert.equal(mallorySub.status, 200);
  assert.notEqual(mallorySub.json.result.id, life.subId);
  life.mallorySubId = mallorySub.json.result.id;

  const fire = await mf.dispatchFetch(ORIGIN + "/trigger", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + TRIGGER_KEY },
    body: JSON.stringify({ text: "所有者確認", request_id: "test-req-003" }),
  });
  assert.equal(fire.status, 200);
  const ownerDeliveries = deliveriesFor("test-req-003").filter((d) => d.subscriptionId === life.subId);
  assert.equal(ownerDeliveries.length, 1, "owner subscription still receives deliveries");

  // Cleanup: mallory removes only their own subscription.
  await rpc(
    {
      jsonrpc: "2.0", id: 3, method: "events/unsubscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER } },
    },
    mallory
  );
});

test("trigger payload cannot override status or delivery targets", async () => {
  const fire = await mf.dispatchFetch(ORIGIN + "/trigger", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + TRIGGER_KEY },
    body: JSON.stringify({
      text: "override attempt",
      request_id: "test-req-override",
      status: "completed",
      callback_url: "https://evil.example.test/x",
      deliver_to: "https://evil.example.test/x",
      report_to: "mallory",
    }),
  });
  assert.equal(fire.status, 200);
  const body = await fire.json();
  assert.notEqual(body.status, "completed", "payload cannot set request status");

  const got = deliveriesFor("test-req-override");
  assert.ok(got.length >= 1);
  assert.ok(got.every((d) => d.url === RECEIVER), "deliveries only go to subscribed callbacks");

  const pending = await rpc(
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "list_pending_requests", arguments: {} } },
    life.tokens.access_token
  );
  const parsed = JSON.parse(pending.json.result.content[0].text);
  const rec = parsed.requests.find((r) => r.id === "test-req-override");
  assert.ok(rec, "request still pending (not force-completed)");
  assert.equal(rec.status, "delivered");
});

test("owner unsubscribe stops further deliveries", async () => {
  const unsub = await rpc(
    {
      jsonrpc: "2.0", id: 1, method: "events/unsubscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url: RECEIVER } },
    },
    life.tokens.access_token
  );
  assert.equal(unsub.status, 200);
  const fire = await mf.dispatchFetch(ORIGIN + "/trigger", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: "Bearer " + TRIGGER_KEY },
    body: JSON.stringify({ text: "after unsubscribe", request_id: "test-req-004" }),
  });
  const body = await fire.json();
  assert.equal(body.subscriptions_matched, 0);
  assert.equal(deliveriesFor("test-req-004").length, 0);
});

test("tampered webhook bodies are rejected (signature verification)", async () => {
  const body = JSON.stringify({ type: "verification", challenge: "abc" });
  const msgId = "msg_test_1";
  const ts = String(Math.floor(Date.now() / 1000));
  const key = Buffer.from(ECHO_SECRET.replace(/^whsec_/, ""), "base64");
  const sig = "v1," + createHmac("sha256", key).update(`${msgId}.${ts}.${body}`).digest("base64");
  const headers = {
    "Content-Type": "application/json",
    "webhook-id": msgId,
    "webhook-timestamp": ts,
    "webhook-signature": sig,
  };
  const ok = await mf.dispatchFetch(ORIGIN + "/test-echo", { method: "POST", headers, body });
  assert.equal(ok.status, 200);

  const tampered = await mf.dispatchFetch(ORIGIN + "/test-echo", {
    method: "POST",
    headers,
    body: body.replace("abc", "abd"),
  });
  assert.equal(tampered.status, 403);
});

test("refresh tokens rotate (old one cannot be replayed) and revocation works", async () => {
  const clientId = await registerClient();
  const tokens = await getTokens(clientId);

  const refresh = async (rt) => {
    const res = await mf.dispatchFetch(ORIGIN + "/oauth/token", {
      method: "POST",
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: rt, client_id: clientId }),
    });
    return { status: res.status, body: await res.json().catch(() => ({})) };
  };
  const rotated = await refresh(tokens.refresh_token);
  assert.equal(rotated.status, 200, JSON.stringify(rotated.body));
  assert.notEqual(rotated.body.access_token, tokens.access_token);

  const replay = await refresh(tokens.refresh_token);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, "invalid_grant");

  const works = await rpc({ jsonrpc: "2.0", id: 1, method: "events/list" }, rotated.body.access_token);
  assert.equal(works.status, 200);

  const revoke = await mf.dispatchFetch(ORIGIN + "/oauth/revoke", {
    method: "POST",
    body: new URLSearchParams({ token: rotated.body.access_token, client_id: clientId }),
  });
  assert.equal(revoke.status, 200);
  const after = await rpc({ jsonrpc: "2.0", id: 2, method: "events/list" }, rotated.body.access_token);
  assert.equal(after.status, 401);
});
