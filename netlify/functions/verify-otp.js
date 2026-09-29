// POST {email, otp, domain, token} -> {verified: true, ref} | {verified: false, error}
// On success, logs the scan request and notifies engage@cyberrestart.com.

const crypto = require("crypto");
const { MAX_ATTEMPTS, otpStore, json, checkToken, sendEmail } = require("../lib/otp");

const NOTIFY_TO = "engage@cyberrestart.com";
const REF_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no 0/O/1/I

function makeRef() {
  let s = "";
  for (let i = 0; i < 6; i++) s += REF_ALPHABET[crypto.randomInt(REF_ALPHABET.length)];
  return `CR-${s}`;
}

const reject = (statusCode = 400) => json(statusCode, { verified: false, error: "Invalid or expired code" });

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, body: "" };
  if (event.httpMethod !== "POST") return json(405, { error: "Method not allowed" });

  let email, otp, domain, token;
  try {
    const body = JSON.parse(event.body || "{}");
    email = String(body.email || "").trim().toLowerCase();
    otp = String(body.otp || "").trim();
    domain = String(body.domain || "").trim().toLowerCase();
    token = String(body.token || "");
  } catch {
    return json(400, { verified: false, error: "Invalid JSON body" });
  }
  if (!/^\d{6}$/.test(otp)) return reject();

  // Best-effort per-instance tracking (see lib/otp.js for why this alone isn't enough).
  const entry = otpStore.get(email);
  if (entry) {
    if (entry.used || Date.now() > entry.expires) return reject();
    entry.attempts += 1;
    if (entry.attempts > MAX_ATTEMPTS) {
      otpStore.delete(email);
      return reject(429);
    }
  }

  let reason;
  try {
    reason = checkToken(token, { email, domain, code: otp });
  } catch (err) {
    console.error("verify-otp:", err.message);
    return json(500, { verified: false, error: "Verification is temporarily unavailable" });
  }
  if (reason) {
    console.warn("verify-otp: rejected", { email, domain, reason });
    return reject();
  }

  otpStore.set(email, { ...(entry || {}), domain, used: true, expires: 0 });

  const ref = makeRef();
  const timestamp = new Date().toISOString();
  console.log("SCAN REQUEST:", { ref, domain, email, timestamp });

  // This email is the only hand-off to a human in the Netlify-only setup, so a
  // failure is logged loudly — the console.log above is the fallback record.
  try {
    await sendEmail({
      to: NOTIFY_TO,
      subject: `New ReSurface scan request — ${domain}`,
      text: [
        "New ReSurface scan request",
        "",
        `Reference: ${ref}`,
        `Domain:    ${domain}`,
        `Email:     ${email}`,
        `Timestamp: ${timestamp}`,
      ].join("\n"),
    });
  } catch (err) {
    console.error("verify-otp: NOTIFICATION FAILED — scan request only in logs:", { ref, domain, email, error: err.message });
  }

  return json(200, { verified: true, ref });
};
