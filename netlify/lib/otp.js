// Shared OTP helpers for send-otp.js / verify-otp.js (bundled into each by esbuild).
//
// Why a signed token as well as the Map: Netlify runs each function in its own
// bundle and instance, so a module-level Map written by send-otp is never
// visible to verify-otp. The Map is kept (per spec) for single-use and
// attempt tracking within a warm instance; the HMAC token is what actually
// carries the code check across functions. Both are temporary until the
// Azure backend's otp_codes table replaces them (see PLATFORM_ARCHITECTURE.md).

const crypto = require("crypto");
const { isFreeProvider } = require("./free-providers");

const OTP_TTL_MS = 10 * 60 * 1000;
const MAX_ATTEMPTS = 5;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const DOMAIN_RE = /^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

// Module-level store: email -> {code, domain, expires, used, attempts}
const otpStore = new Map();

const json = (statusCode, body) => ({
  statusCode,
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

// Returns an error string, or "" if the pair is acceptable.
function validateEmailAndDomain(email, domain) {
  if (!EMAIL_RE.test(email)) return "Enter a valid email address";
  if (isFreeProvider(email)) return "Please use your work email — personal email providers aren't accepted";
  if (!DOMAIN_RE.test(domain)) return "Invalid target domain";
  return "";
}

function getSecret() {
  const secret = process.env.OTP_SECRET;
  if (!secret || secret.length < 32) throw new Error("OTP_SECRET not set (need 32+ chars)");
  return secret;
}

function sign(payload, code) {
  return crypto.createHmac("sha256", getSecret()).update(`${payload}.${code}`).digest("base64url");
}

function createToken({ email, domain, code, expires }) {
  const payload = Buffer.from(JSON.stringify({ e: email, d: domain, x: expires })).toString("base64url");
  return `${payload}.${sign(payload, code)}`;
}

// Checks a submitted code against a token. Returns "" if valid, else a reason.
function checkToken(token, { email, domain, code }) {
  const [payload, mac] = String(token || "").split(".");
  if (!payload || !mac) return "missing token";
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  } catch {
    return "malformed token";
  }
  if (data.e !== email || data.d !== domain) return "token/email mismatch";
  if (Date.now() > data.x) return "expired";
  const expected = Buffer.from(sign(payload, code));
  const given = Buffer.from(mac);
  if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return "wrong code";
  return "";
}

async function sendEmail({ to, subject, html, text }) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error("RESEND_API_KEY not set");
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: "ReSurface <noreply@cyberrestart.com>",
      to: Array.isArray(to) ? to : [to],
      subject,
      ...(html ? { html } : {}),
      ...(text ? { text } : {}),
    }),
  });
  if (!res.ok) throw new Error(`Resend HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
  return res.json();
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

module.exports = {
  OTP_TTL_MS,
  MAX_ATTEMPTS,
  otpStore,
  json,
  validateEmailAndDomain,
  getSecret,
  createToken,
  checkToken,
  sendEmail,
  escapeHtml,
};
