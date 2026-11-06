// TEMPORARY test-only echo worker (deleted after verification).
// Verifies Standard Webhooks signatures with a throwaway secret and
// echoes verification challenges. Returns 403 on invalid signatures.
function b64decode(str) {
  const bin = atob(String(str).trim());
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
export default {
  async fetch(request, env) {
    if (request.method !== "POST") return new Response("ok");
    const rawBody = await request.text();
    let body = {};
    try { body = JSON.parse(rawBody); } catch (_) {}
    const msgId = request.headers.get("webhook-id") || "";
    const ts = request.headers.get("webhook-timestamp") || "";
    const sigHeader = request.headers.get("webhook-signature") || "";
    let valid = false;
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        b64decode(String(env.ECHO_SECRET).replace(/^whsec_/, "")),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"]
      );
      const signed = new TextEncoder().encode(`${msgId}.${ts}.${rawBody}`);
      for (const part of sigHeader.split(" ")) {
        const [v, b64] = part.split(",");
        if (v === "v1" && b64 && (await crypto.subtle.verify("HMAC", key, b64decode(b64), signed))) {
          valid = true;
        }
      }
    } catch (_) {}
    if (!valid) return Response.json({ ok: false, error: "invalid signature" }, { status: 403 });
    if (body && body.type === "verification") {
      return Response.json({ challenge: body.challenge });
    }
    return Response.json({ ok: true, sig_valid: true });
  },
};
