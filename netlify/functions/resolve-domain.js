// POST {query} -> {domain} | {domain: null, error}
// Accepts any way a visitor might identify their organisation. Checked in
// this order, cheapest first — only the last case costs a Groq call:
//   raw IP address           -> rejected (IP scans need a full engagement)
//   email / @domain          -> domain after the @ (personal providers rejected)
//   full URL                 -> its hostname
//   bare domain              -> used directly
//   anything else            -> org name or freeform description, via Groq

const { withOriginCheck } = require("../lib/allowed-origins");
const { isFreeProvider } = require("../lib/free-providers");

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODEL = "openai/gpt-oss-120b";
const TIMEOUT_MS = 8000;
// gpt-oss is a reasoning model: its reasoning tokens count against this
// budget, so 20 tokens can leave nothing for the answer. The answer itself
// is still a single domain; the headroom is for the (low-effort) reasoning.
const MAX_TOKENS = 256;
const MAX_QUERY_LENGTH = 200;

const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
// IPv6 literal: 2–7 colons between hex groups, optionally bracketed with a port.
const IPV6_RE = /^\[?(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?(?::\d+)?$/i;

const ERR_IP = "Please enter a domain or organisation name. IP-based scans are available with a full engagement.";
const ERR_UNKNOWN = "We couldn't identify a specific organisation from that. Try adding the name, location, or sector — or enter the domain directly.";
const ERR_INVALID = "That doesn't look like a valid domain. Check the spelling, or describe the organisation instead.";
const ERR_FREE_EMAIL = "That's a personal email provider, not your organisation's domain. Enter your work email domain, the organisation name, or its website.";

const json = (statusCode, body) => ({
  statusCode,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

const fail = (statusCode, error) => json(statusCode, { domain: null, error });

function isIpAddress(text) {
  const host = String(text).trim().replace(/^\[|\]$/g, "");
  return IPV4_RE.test(host.replace(/:\d+$/, "")) || IPV6_RE.test(text.trim());
}

// Hostname from anything domain-shaped: strips scheme, credentials, www.,
// port, path, query, fragment and trailing dots.
function normaliseHost(text) {
  return String(text)
    .trim()
    .toLowerCase()
    .replace(/[`"'<>]/g, "")
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, "")
    .replace(/^[^/@]*@/, "")
    .replace(/^www\./, "")
    .split(/[/?#\s]/)[0]
    .replace(/:\d+$/, "")
    .replace(/\.+$/, "");
}

// Returns {domain} or {error, status} for the non-AI cases, or null when the
// query needs Groq.
function resolveLocally(query) {
  if (isIpAddress(query)) return { error: ERR_IP, status: 422 };

  // Email address or bare "@company.com"
  const email = query.match(/^[^\s@]*@([^\s@]+)$/);
  if (email) {
    const host = normaliseHost(email[1]);
    if (isIpAddress(host)) return { error: ERR_IP, status: 422 };
    if (!DOMAIN_RE.test(host)) return { error: ERR_INVALID, status: 422 };
    if (isFreeProvider(host)) return { error: ERR_FREE_EMAIL, status: 422 };
    return { domain: host };
  }

  // Full URL (scheme present), or a bare domain with or without a path.
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(query);
  if (hasScheme || (query.includes(".") && !/\s/.test(query))) {
    const host = normaliseHost(query);
    if (isIpAddress(host)) return { error: ERR_IP, status: 422 };
    if (!DOMAIN_RE.test(host)) return { error: ERR_INVALID, status: 422 };
    return { domain: host };
  }

  return null; // organisation name or freeform description
}

async function resolveWithGroq(query) {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) throw new Error("GROQ_API_KEY not set");

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(GROQ_URL, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        temperature: 0,
        max_tokens: MAX_TOKENS,
        reasoning_effort: "low",
        messages: [
          {
            role: "user",
            content:
              "You resolve any description of an organisation to its primary website domain. " +
              "The input may be a domain, a URL, an email domain, an exact organisation name, " +
              "or a freeform description such as 'the biggest fintech in Lagos' or 'the telecoms " +
              "company MTN operates in South Africa'. Use your knowledge to identify the single " +
              "most likely organisation and return ONLY its primary registered website domain — " +
              "lowercase, no www, no protocol, no path, nothing else. If you genuinely cannot " +
              "identify a specific organisation with reasonable confidence, return exactly: UNKNOWN\n" +
              `Input: ${query}`,
          },
        ],
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      throw new Error(`Groq HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    }
    const data = await res.json();
    return data?.choices?.[0]?.message?.content || "";
  } finally {
    clearTimeout(timer);
  }
}

// Origin allowlist + CORS preflight are handled by withOriginCheck (lib/allowed-origins.js).
exports.handler = withOriginCheck(async (event) => {
  if (event.httpMethod !== "POST") return fail(405, "Method not allowed");

  let query;
  try {
    query = String(JSON.parse(event.body || "{}").query || "").trim();
  } catch {
    return fail(400, "Invalid JSON body");
  }
  if (!query) return fail(400, "Enter your domain or any detail about your organisation.");
  if (query.length > MAX_QUERY_LENGTH) return fail(400, "That's a bit long — try a shorter description.");

  const local = resolveLocally(query);
  if (local) return local.domain ? json(200, { domain: local.domain }) : fail(local.status, local.error);

  try {
    const raw = (await resolveWithGroq(query)).trim();
    if (/^unknown\.?$/i.test(raw)) return fail(422, ERR_UNKNOWN);

    // Take the first domain-shaped token, in case the model adds words anyway.
    const candidate = (raw.match(/[a-z0-9.-]+\.[a-z]{2,63}/i) || [""])[0];
    const domain = normaliseHost(candidate);
    if (!DOMAIN_RE.test(domain)) {
      console.warn("resolve-domain: unusable model output", { query, raw });
      return fail(422, ERR_UNKNOWN);
    }
    return json(200, { domain });
  } catch (err) {
    const timedOut = err.name === "AbortError";
    console.error("resolve-domain failed:", timedOut ? "timeout" : err.message);
    return fail(timedOut ? 504 : 502, "Domain lookup is unavailable right now. Try entering the domain directly.");
  }
});
