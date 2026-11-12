// Tests for per-(request, subscription) delivery idempotency, added in
// 1.4.0. Background: the MCP 2026-07-28 revision removed SSE
// resumability (Last-Event-ID redelivery) from the transport, so when
// a connection breaks, in-flight work is lost and callers re-issue —
// there is no protocol-level replay/dedup safety net left. The only
// thing standing between a re-sent /trigger and a duplicated kick is
// this server's own dedup. Ingestion dedup (atomic put-if-absent on
// the request record) existed already; these tests cover the delivery
// ledger added on top of it: a persistent per-(request, subscription)
// record inside the Durable Object that is claimed before each POST
// and settled with the outcome, so re-driving delivery for a request
// never POSTs the same kick to the same subscription twice.
//
// Runs fully locally on Miniflare with a synthetic IdP, like the
// other suites. The receiver stub counts event POSTs per request id;
// assertions are made on those counts, not on server claims.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  createHmac,
  createSign,
  generateKeyPairSync,
  createPublicKey,
  randomBytes,
} from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Miniflare } from "miniflare";

const ORIGIN = "https://dots-events.test";
const RESOURCE = ORIGIN + "/mcp";
const ISSUER = "https://idp.example.test";
const RECEIVER_OK = "https://receiver.example.test/callback";
const RECEIVER_FAIL = "https://receiver.example.test/fail-callback";
const RECEIVER_SLOW = "https://receiver.example.test/slow-callback";
const TRIGGER_KEY = "test-trigger-key";
const WHSEC = "whsec_" + randomBytes(32).toString("base64");
const ALL_SCOPES =
  "events:read events:subscribe requests:read requests:update claude:kick";

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
    scope: ALL_SCOPES,
    cid: "test-client",
    iat: now,
    exp: now + 900,
    ...claims,
  };
  const input =
    b64url(JSON.stringify(header)) + "." + b64url(JSON.stringify(payload));
  const sig = createSign("SHA256")
    .update(input)
    .sign({ key: key1.privateKey, dsaEncoding: "ieee-p1363" });
  return input + "." + b64url(sig);
}

// --- simulated IdP JWKS endpoint + callback receivers ---
const posts = []; // event deliveries only (verification posts excluded)
let failMode = "fail"; // RECEIVER_FAIL behavior: "fail" -> 500, "ok" -> 200

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
    return Response.json({ keys: [key1.publicJwk] });
  }
  if (req.url.startsWith("https://receiver.example.test/")) {
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
    posts.push({
      url: req.url,
      subscriptionId: req.headers.get("x-mcp-subscription-id"),
      webhookId: req.headers.get("webhook-id"),
      requestId: parsed?.data?.request_id,
      signatureValid: sigValid,
    });
    if (req.url.startsWith(RECEIVER_SLOW)) {
      // Hold the response back so a test can re-send the trigger while
      // the first delivery is still in flight.
      await new Promise((r) => setTimeout(r, 900));
      return Response.json({ ok: true });
    }
    if (req.url.startsWith(RECEIVER_FAIL) && failMode === "fail") {
      return new Response("receiver unavailable", { status: 500 });
    }
    return Response.json({ ok: true });
  }
  return new Response("not found", { status: 404 });
}

function bindings() {
  return {
    TRIGGER_KEY,
    IDP_ISSUER: ISSUER,
    RESOURCE_URI: RESOURCE,
    OWNER_SUB: "user-1",
  };
}

let mf;
before(async () => {
  mf = new Miniflare({
    modules: true,
    scriptPath: new URL("../worker.js", import.meta.url).pathname,
    compatibilityDate: "2025-11-01",
    durableObjects: { STORE: "Store" },
    bindings: bindings(),
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
  return { status: res.status, json };
}

async function trigger(body) {
  const res = await mf.dispatchFetch(ORIGIN + "/trigger", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + TRIGGER_KEY,
    },
    body: JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

async function subscribeTo(token, url) {
  const res = await rpc(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "events/subscribe",
      params: {
        name: "kick",
        arguments: {},
        delivery: { mode: "webhook", url, secret: WHSEC },
      },
    },
    token
  );
  assert.equal(res.status, 200, JSON.stringify(res.json));
  return res.json.result.id;
}

async function unsubscribe(token, url) {
  await rpc(
    {
      jsonrpc: "2.0",
      id: 9,
      method: "events/unsubscribe",
      params: { name: "kick", arguments: {}, delivery: { mode: "webhook", url } },
    },
    token
  );
}

async function storeStub() {
  const ns = await mf.getDurableObjectNamespace("STORE");
  return ns.get(ns.idFromName("global"));
}

async function putRaw(key, value) {
  const stub = await storeStub();
  await stub.fetch("https://store/put", {
    method: "POST",
    body: JSON.stringify({ key, value }),
  });
}

async function getRaw(key) {
  const stub = await storeStub();
  const res = await stub.fetch(
    "https://store/get?key=" + encodeURIComponent(key)
  );
  return res.status === 404 ? null : res.text();
}

function postsFor(requestId) {
  return posts.filter((p) => p.requestId === requestId);
}

async function listPending(token) {
  const res = await rpc(
    {
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "list_pending_requests", arguments: {} },
    },
    token
  );
  return JSON.parse(res.json.result.content[0].text).requests;
}

// ---------------- the disconnect / resend scenarios ----------------

test("resend after a failed drive: the re-drive delivers exactly once, and a third send POSTs nothing", async () => {
  const token = mintJwt();
  const subId = await subscribeTo(token, RECEIVER_FAIL);
  assert.ok(subId.startsWith("sub_"));

  // First drive: the receiver is down (500). The in-invocation retry
  // loop exhausts itself; the pair settles as "failed" in the ledger
  // and the request stays pending.
  failMode = "fail";
  const first = await trigger({ text: "回線断のあと再送される依頼", request_id: "req-redrive-1" });
  assert.equal(first.status, 200);
  assert.equal(first.json.deduplicated, false);
  assert.equal(first.json.delivered, 0);
  assert.equal(first.json.status, "pending");
  const afterFail = postsFor("req-redrive-1").length;
  assert.ok(afterFail >= 1, "the failed drive did reach the receiver");

  // The caller never saw a success and re-sends the identical trigger
  // (this is the production disconnect case). The request is still
  // pending, so delivery is re-driven; the ledger re-claims the failed
  // pair and the kick lands — once.
  failMode = "ok";
  const resend = await trigger({ text: "回線断のあと再送される依頼", request_id: "req-redrive-1" });
  assert.equal(resend.json.deduplicated, true);
  assert.equal(resend.json.delivered, 1);
  assert.equal(resend.json.status, "delivered");
  assert.equal(postsFor("req-redrive-1").length, afterFail + 1);
  assert.equal(
    postsFor("req-redrive-1").filter((p) => p.signatureValid).length,
    afterFail + 1
  );

  // A further resend finds the request delivered and POSTs nothing.
  const third = await trigger({ text: "回線断のあと再送される依頼", request_id: "req-redrive-1" });
  assert.equal(third.json.deduplicated, true);
  assert.equal(postsFor("req-redrive-1").length, afterFail + 1);

  await unsubscribe(token, RECEIVER_FAIL);
});

test("a duplicate trigger arriving while delivery is in flight does not POST a second time", async () => {
  const token = mintJwt();
  await subscribeTo(token, RECEIVER_SLOW);

  const firstPromise = trigger({ text: "配送中に再送が重なる依頼", request_id: "req-inflight-1" });
  // Wait until the first delivery has actually reached the receiver;
  // its response is held back (~900ms), so the delivery — and its
  // ledger claim — are in flight.
  for (let i = 0; i < 200; i++) {
    if (postsFor("req-inflight-1").length > 0) break;
    await new Promise((r) => setTimeout(r, 25));
  }
  assert.equal(postsFor("req-inflight-1").length, 1);

  // The duplicate arrives now: the record is still pending, so the
  // re-drive runs — but the pair's claim is fresh, so it is skipped.
  const dup = await trigger({ text: "配送中に再送が重なる依頼", request_id: "req-inflight-1" });
  assert.equal(dup.json.deduplicated, true);
  assert.equal(postsFor("req-inflight-1").length, 1);

  const first = await firstPromise;
  assert.equal(first.json.delivered, 1);
  assert.equal(postsFor("req-inflight-1").length, 1);

  await unsubscribe(token, RECEIVER_SLOW);
});

test("lost outcome: ledger says delivered but the record is still pending — a resend POSTs nothing and reconciles the status", async () => {
  const token = mintJwt();
  // File the request before any subscription exists: it stays pending
  // with no delivery recorded — the state a request is left in when a
  // drive's outcome never got merged back into the record.
  const filed = await trigger({ text: "結果が記録されなかった依頼", request_id: "req-lost-1" });
  assert.equal(filed.json.subscriptions_matched, 0);
  assert.equal(filed.json.status, "pending");

  const subId = await subscribeTo(token, RECEIVER_OK);
  // Simulate the lost write: the webhook in fact succeeded and the
  // outcome was settled into the persistent ledger, but the record
  // merge is what got lost.
  await putRaw(
    "dlv:req-lost-1",
    JSON.stringify({
      [subId]: {
        state: "delivered",
        eventId: "evt_seeded",
        attempts: 1,
        claimedAt: new Date().toISOString(),
        claimedAtMs: Date.now(),
        lastStatus: 200,
        settledAt: new Date().toISOString(),
      },
    })
  );

  const resend = await trigger({ text: "結果が記録されなかった依頼", request_id: "req-lost-1" });
  assert.equal(resend.json.deduplicated, true);
  assert.equal(postsFor("req-lost-1").length, 0); // never POSTed again
  assert.equal(resend.json.status, "delivered"); // record reconciled

  const found = (await listPending(token)).find((r) => r.id === "req-lost-1");
  assert.equal(found.status, "delivered");

  await unsubscribe(token, RECEIVER_OK);
});

test("a stale claim left by a dead drive does not wedge the request: a resend takes over and delivers once", async () => {
  const token = mintJwt();
  const filed = await trigger({ text: "死んだ配送の残した依頼", request_id: "req-stale-1" });
  assert.equal(filed.json.status, "pending");

  const subId = await subscribeTo(token, RECEIVER_OK);
  // Seed the ledger the way a killed invocation would have left it:
  // an "attempting" entry whose claim is far past the lease.
  const staleMs = Date.now() - 10 * 60 * 1000;
  await putRaw(
    "dlv:req-stale-1",
    JSON.stringify({
      [subId]: {
        state: "attempting",
        eventId: "evt_seeded",
        attempts: 1,
        claimedAt: new Date(staleMs).toISOString(),
        claimedAtMs: staleMs,
        lastStatus: null,
      },
    })
  );

  const resend = await trigger({ text: "死んだ配送の残した依頼", request_id: "req-stale-1" });
  assert.equal(resend.json.deduplicated, true);
  assert.equal(resend.json.delivered, 1);
  assert.equal(postsFor("req-stale-1").length, 1);

  const ledger = JSON.parse(await getRaw("dlv:req-stale-1"));
  assert.equal(ledger[subId].state, "delivered");
  assert.equal(ledger[subId].attempts, 2); // takeover incremented the count

  await unsubscribe(token, RECEIVER_OK);
});

test("dedup is per (request, subscription): two different requests to the same subscription both deliver", async () => {
  const token = mintJwt();
  await subscribeTo(token, RECEIVER_OK);

  const a = await trigger({ text: "別の依頼A", request_id: "req-pair-a" });
  const b = await trigger({ text: "別の依頼B", request_id: "req-pair-b" });
  assert.equal(a.json.delivered, 1);
  assert.equal(b.json.delivered, 1);
  assert.equal(postsFor("req-pair-a").length, 1);
  assert.equal(postsFor("req-pair-b").length, 1);
  // Distinct kicks keep distinct webhook ids (the receiver's dedup key).
  assert.notEqual(postsFor("req-pair-a")[0].webhookId, postsFor("req-pair-b")[0].webhookId);

  await unsubscribe(token, RECEIVER_OK);
});

test("the dedup state lives in persistent storage, not Worker memory: a fresh instance still suppresses the resend", async () => {
  const persistDir = mkdtempSync(join(tmpdir(), "dots-events-dedup-"));
  const makeInstance = () =>
    new Miniflare({
      modules: true,
      scriptPath: new URL("../worker.js", import.meta.url).pathname,
      compatibilityDate: "2025-11-01",
      durableObjects: { STORE: "Store" },
      durableObjectsPersist: persistDir,
      bindings: bindings(),
      outboundService,
    });

  const mf1 = makeInstance();
  try {
    await mf1.ready;
    const call = async (path, init) => {
      const res = await mf1.dispatchFetch(ORIGIN + path, init);
      return { status: res.status, json: await res.json() };
    };
    const token = mintJwt();
    const sub = await call("/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + token },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "events/subscribe",
        params: {
          name: "kick",
          arguments: {},
          delivery: { mode: "webhook", url: RECEIVER_OK, secret: WHSEC },
        },
      }),
    });
    assert.equal(sub.status, 200, JSON.stringify(sub.json));
    const fired = await call("/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + TRIGGER_KEY },
      body: JSON.stringify({ text: "再起動をまたぐ依頼", request_id: "req-restart-1" }),
    });
    assert.equal(fired.json.delivered, 1);
    assert.equal(postsFor("req-restart-1").length, 1);
  } finally {
    await mf1.dispose();
  }

  // A brand-new Worker instance (fresh isolate, empty memory) over the
  // same stored state: the resend must still be suppressed.
  const mf2 = makeInstance();
  try {
    await mf2.ready;
    const res = await mf2.dispatchFetch(ORIGIN + "/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: "Bearer " + TRIGGER_KEY },
      body: JSON.stringify({ text: "再起動をまたぐ依頼", request_id: "req-restart-1" }),
    });
    const json = await res.json();
    assert.equal(json.deduplicated, true);
    assert.equal(json.status, "delivered");
    assert.equal(postsFor("req-restart-1").length, 1);
  } finally {
    await mf2.dispose();
  }
});
