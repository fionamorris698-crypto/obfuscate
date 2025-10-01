// worker.js (Cloudflare Worker - modules syntax)
// AES-GCM opaque tokens. Expects env.LINK_OBFUSCATOR_SECRET binding.

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const IV_LEN = 12; // AES-GCM iv length

function base64UrlEncode(buf) {
  const bytes = new Uint8Array(buf);
  let binary = "";
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  const b64 = btoa(binary);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function base64UrlDecode(b64url) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const binary = atob(b64);
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function deriveAesKey(secret) {
  const secretBytes = encoder.encode(secret);
  const hash = await crypto.subtle.digest("SHA-256", secretBytes);
  return crypto.subtle.importKey("raw", hash, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

async function encryptPayload(payloadStr, secret) {
  const key = await deriveAesKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const plaintext = encoder.encode(payloadStr);
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
  const cipherBytes = new Uint8Array(cipherBuf);
  const out = new Uint8Array(IV_LEN + cipherBytes.length);
  out.set(iv, 0);
  out.set(cipherBytes, IV_LEN);
  return base64UrlEncode(out.buffer);
}

async function decryptToken(token, secret) {
  try {
    const dataBuf = base64UrlDecode(token);
    const dataBytes = new Uint8Array(dataBuf);
    if (dataBytes.length <= IV_LEN) throw new Error("Token too short");
    const iv = dataBytes.subarray(0, IV_LEN);
    const cipher = dataBytes.subarray(IV_LEN);
    const key = await deriveAesKey(secret);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    const plainStr = decoder.decode(plainBuf);
    return JSON.parse(plainStr);
  } catch (e) {
    throw new Error("Decryption failed");
  }
}

function isValidHttpUrl(str) {
  try {
    const u = new URL(str);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch (e) {
    return false;
  }
}

function jsonResponse(obj, status = 200, cors = "*") {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": cors,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}
function textResponse(text, status = 200, cors = "*") {
  return new Response(text, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Access-Control-Allow-Origin": cors,
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const secret = env.LINK_OBFUSCATOR_SECRET;
    if (!secret) return textResponse("Worker misconfigured: missing secret", 500);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type"
        }
      });
    }

    try {
      // POST /encode -> returns { obfuscated, token }
      if (request.method === "POST" && url.pathname === "/encode") {
        const body = await request.json().catch(() => null);
        if (!body || !body.url) return jsonResponse({ error: "Missing url in body" }, 400);

        const targetUrl = String(body.url).trim();
        if (!isValidHttpUrl(targetUrl)) return jsonResponse({ error: "Invalid URL" }, 400);

        let expiryTs = null;
        if (body.expiry) {
          const secs = Number(body.expiry);
          if (!Number.isFinite(secs) || secs <= 0) return jsonResponse({ error: "Invalid expiry" }, 400);
          expiryTs = Math.floor(Date.now() / 1000) + Math.floor(secs);
        }

        const payload = { u: targetUrl };
        if (expiryTs) payload.e = expiryTs;

        const token = await encryptPayload(JSON.stringify(payload), secret);
        const obfuscatedPath = `/o/${encodeURIComponent(token)}`;
        const publicBase = url.origin;
        const final = `${publicBase}${obfuscatedPath}`;

        return jsonResponse({ obfuscated: final, token }, 200);
      }

      // GET /o/:token -> decrypt & redirect
      if (request.method === "GET" && url.pathname.startsWith("/o/")) {
        const encodedToken = url.pathname.slice(3);
        if (!encodedToken) return textResponse("Missing token", 400);

        let payload;
        try {
          payload = await decryptToken(decodeURIComponent(encodedToken), secret);
        } catch (e) {
          return textResponse("Invalid or tampered token", 400);
        }

        if (payload.e && Number.isFinite(payload.e)) {
          const now = Math.floor(Date.now() / 1000);
          if (now > payload.e) return textResponse("Link expired", 410);
        }

        const target = payload.u;
        if (!isValidHttpUrl(target)) return textResponse("Invalid target url", 400);

        // Optional: fire-and-forget logging here
        return Response.redirect(target, 302);
      }

      // health/help
      if (request.method === "GET" && (url.pathname === "/" || url.pathname === "")) {
        return jsonResponse({
          usage: {
            encode_POST: { path: "/encode", body: { url: "https://example.com", expiry: "(optional seconds from now)" } },
            redirect_GET: "/o/{token}"
          },
          note: "Keep LINK_OBFUSCATOR_SECRET secret. This worker returns CORS headers."
        }, 200);
      }

      return textResponse("Not found", 404);
    } catch (err) {
      return textResponse(String(err.message || err), 500);
    }
  }
};
