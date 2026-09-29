// POST {query} -> {domain}
// A domain-shaped query is normalised and returned as-is; anything else
// (an organisation name) is resolved to its primary domain via Groq.

const GROQ_URL = "https://api.groq.com/openai/v1/chat/completions";
const GROQ_MODEL = "openai/gpt-oss-120b";
const TIMEOUT_MS = 8000;
// gpt-oss is a reasoning model: its reasoning tokens count against this
// budget, so 20 tokens can leave nothing for the answer. The answer itself
// is still a single domain; the headroom is for the (low-effort) reasoning.
const MAX_TOKENS = 256;
const MAX_QUERY_LENGTH = 200;

const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

const json = (statusCode, body) => ({
  statusCode,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

function isLikelyDomain(text) {
  return text.includes(".") && !/\s/.test(text);
}

function normaliseDomain(text) {
  return String(text)
    .trim()
    .toLowerCase()
    .replace(/[`"'<>]/g, "")
    .replace(/^[a-z]+:\/\//, "")
    .replace(/^www\./, "")
    .split(/[/?#:\s]/)[0]
    .replace(/\.+$/, "");
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
              "Return only the primary website domain for this organisation. " +
              "Reply with just the domain, nothing else, no www prefix. " +
              `Organisation: ${query}`,
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

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, body: "" };
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  let query;
  try {
    query = String(JSON.parse(event.body || "{}").query || "").trim();
  } catch {
    return json(400, { error: "Invalid JSON body" });
  }
  if (!query) return json(400, { error: "Enter a domain or organisation name" });
  if (query.length > MAX_QUERY_LENGTH) return json(400, { error: "Query too long" });

  if (isLikelyDomain(query)) {
    const domain = normaliseDomain(query);
    if (!DOMAIN_RE.test(domain)) return json(422, { error: "That doesn't look like a valid domain" });
    return json(200, { domain });
  }

  try {
    const raw = await resolveWithGroq(query);
    // Take the first domain-shaped token, in case the model adds words anyway.
    const candidate = (raw.match(/[a-z0-9.-]+\.[a-z]{2,63}/i) || [""])[0];
    const domain = normaliseDomain(candidate);
    if (!DOMAIN_RE.test(domain)) {
      console.warn("resolve-domain: unusable model output", { query, raw });
      return json(422, { error: "Couldn't identify a domain for that organisation. Try entering the domain directly." });
    }
    return json(200, { domain });
  } catch (err) {
    const timedOut = err.name === "AbortError";
    console.error("resolve-domain failed:", timedOut ? "timeout" : err.message);
    return json(timedOut ? 504 : 502, {
      error: "Domain lookup is unavailable right now. Try entering the domain directly.",
    });
  }
};
