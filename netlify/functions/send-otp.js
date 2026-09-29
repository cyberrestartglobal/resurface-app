// POST {email, domain} -> {sent: true, token}
// Generates a 6-digit code, stores it, and emails it via Resend.

const crypto = require("crypto");
const {
  OTP_TTL_MS,
  otpStore,
  json,
  validateEmailAndDomain,
  getSecret,
  createToken,
  sendEmail,
  escapeHtml,
} = require("../lib/otp");

// Temporary rate limiting until the Azure backend. Module-level, so it only
// holds within one warm function instance — a cold start or a second
// instance starts from zero. Enough to stop casual abuse, not a determined one.
const RATE_WINDOW_MS = 10 * 60 * 1000;
const MAX_SENDS_PER_EMAIL = 3;
const MAX_SENDS_GLOBAL = 50;
const sendLog = new Map(); // email -> [send timestamps within the window]
let globalSends = [];      // send timestamps within the window, all emails

// Returns true if this send is allowed, and records it.
function allowSend(email) {
  const cutoff = Date.now() - RATE_WINDOW_MS;
  globalSends = globalSends.filter((t) => t > cutoff);
  for (const [key, times] of sendLog) {
    const recent = times.filter((t) => t > cutoff);
    if (recent.length) sendLog.set(key, recent);
    else sendLog.delete(key);
  }

  const emailSends = sendLog.get(email) || [];
  if (emailSends.length >= MAX_SENDS_PER_EMAIL || globalSends.length >= MAX_SENDS_GLOBAL) {
    return false;
  }
  const now = Date.now();
  sendLog.set(email, [...emailSends, now]);
  globalSends.push(now);
  return true;
}

function otpEmailHtml(code, domain) {
  const d = escapeHtml(domain);
  return `<!doctype html>
<html><body style="margin:0;padding:0;background:#09090f;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#09090f;padding:40px 16px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#0d0d14;border:1px solid #1e1e2e;border-radius:16px;">
<tr><td style="padding:40px;font-family:Inter,Helvetica,Arial,sans-serif;">
<p style="margin:0 0 24px;color:#06b6d4;font-size:12px;letter-spacing:0.2em;text-transform:uppercase;font-weight:600;">CyberRestart ReSurface</p>
<h1 style="margin:0 0 24px;color:#f8fafc;font-size:22px;font-weight:700;">Your verification code</h1>
<p style="margin:0 0 24px;text-align:center;font-family:'JetBrains Mono',Menlo,Consolas,monospace;font-size:36px;letter-spacing:0.3em;color:#06b6d4;font-weight:700;">${code}</p>
<p style="margin:0 0 16px;text-align:center;color:#475569;font-size:13px;">Expires in 10 minutes</p>
<p style="margin:0;color:#94a3b8;font-size:14px;line-height:1.6;">You requested a scan of <span style="font-family:'JetBrains Mono',Menlo,Consolas,monospace;color:#06b6d4;">${d}</span>. If this wasn't you, ignore this email.</p>
</td></tr>
</table>
<p style="margin:24px 0 0;font-family:Inter,Helvetica,Arial,sans-serif;color:#475569;font-size:12px;"><a href="https://cyberrestart.com" style="color:#475569;text-decoration:none;">cyberrestart.com</a></p>
</td></tr>
</table>
</body></html>`;
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, body: "" };
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  let email, domain;
  try {
    const body = JSON.parse(event.body || "{}");
    email = String(body.email || "").trim().toLowerCase();
    domain = String(body.domain || "").trim().toLowerCase();
  } catch {
    return json(400, { error: "Invalid JSON body" });
  }

  const invalid = validateEmailAndDomain(email, domain);
  if (invalid) return json(400, { error: invalid });

  try {
    getSecret();
  } catch (err) {
    console.error("send-otp:", err.message);
    return json(500, { error: "Verification is temporarily unavailable" });
  }

  if (!allowSend(email)) {
    console.warn("send-otp: rate limited", { email });
    return json(429, { error: "Too many requests. Try again later." });
  }

  const code = String(crypto.randomInt(100000, 1000000));
  const expires = Date.now() + OTP_TTL_MS;
  otpStore.set(email, { code, domain, expires, used: false, attempts: 0 });

  try {
    await sendEmail({
      to: email,
      subject: "Your ReSurface verification code",
      html: otpEmailHtml(code, domain),
    });
  } catch (err) {
    console.error("send-otp: email failed:", err.message);
    otpStore.delete(email);
    return json(502, { error: "We couldn't send the code. Please try again." });
  }

  return json(200, { sent: true, token: createToken({ email, domain, code, expires }) });
};
