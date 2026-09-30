// Origin allowlist — one list, shared by resolve-domain.js, send-otp.js and
// verify-otp.js (bundled into each by esbuild, like free-providers.js).
//
// Stops other websites from calling these functions from a visitor's browser.
// It is not authentication: a script outside a browser can send any Origin
// header it likes. send-otp's rate limits remain the backstop there.

const ALLOWED_ORIGINS = [
  "https://resurface.cyberrestart.com",
  "https://hilarious-moonbeam-2ed725.netlify.app",
  "http://localhost:8888", // netlify dev
];

// Origin header, falling back to Referer (Netlify lower-cases header names).
function requestOrigin(event) {
  const h = event.headers || {};
  return String(h.origin || h.referer || "").trim();
}

// Prefix match that respects the host boundary: the value must be the origin
// itself or the origin followed by "/" (a Referer with a path or query).
// A plain startsWith would let "https://resurface.cyberrestart.com.evil.net" in.
function matchAllowedOrigin(value) {
  return ALLOWED_ORIGINS.find((o) => value === o || value.startsWith(`${o}/`)) || null;
}

function corsHeaders(origin) {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    Vary: "Origin",
  };
}

// Wraps a Netlify handler: rejects disallowed origins with 403 before the
// handler runs, answers the CORS preflight for allowed ones, and adds CORS
// headers (echoing the caller's origin, never "*") to every allowed response.
function withOriginCheck(handler) {
  return async (event, context) => {
    const origin = matchAllowedOrigin(requestOrigin(event));
    if (!origin) {
      return {
        statusCode: 403,
        headers: { "Content-Type": "application/json", Vary: "Origin" },
        body: JSON.stringify({ error: "Forbidden" }),
      };
    }
    if (event.httpMethod === "OPTIONS") {
      return { statusCode: 204, headers: corsHeaders(origin), body: "" };
    }
    const res = await handler(event, context);
    return { ...res, headers: { ...(res.headers || {}), ...corsHeaders(origin) } };
  };
}

module.exports = { ALLOWED_ORIGINS, matchAllowedOrigin, withOriginCheck };
