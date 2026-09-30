// Personal / free email providers — one list, shared by resolve-domain.js and
// send-otp.js (via lib/otp.js), bundled into each by esbuild. index.html keeps
// a copy for its instant client-side check; update both together.

// Exact domains.
const FREE_PROVIDER_DOMAINS = [
  "gmail.com", "googlemail.com",
  "yahoo.com", "ymail.com",
  "hotmail.com", "outlook.com", "live.com", "msn.com",
  "icloud.com", "me.com", "mac.com",
  "aol.com",
  "protonmail.com", "proton.me", "pm.me",
  "gmx.com", "gmx.net",
  "yandex.com",
  "mail.com",
  "zoho.com",
];

// Regional variants of the large providers: brand + a country-style ending
// only (yahoo.co.uk, hotmail.fr, gmx.de, yandex.ru). Deliberately anchored so
// a company subdomain such as mail.company.com or live.company.org is never caught.
const FREE_PROVIDER_BRANDS = ["gmail", "googlemail", "yahoo", "hotmail", "outlook", "live", "msn", "aol", "gmx", "yandex"];

const DOMAIN_SET = new Set(FREE_PROVIDER_DOMAINS);
const BRAND_RE = new RegExp(`^(?:${FREE_PROVIDER_BRANDS.join("|")})\\.(?:[a-z]{2,3}|(?:co|com)\\.[a-z]{2})$`);

// Accepts a bare domain or a full email address.
function isFreeProvider(domainOrEmail) {
  const host = String(domainOrEmail).trim().toLowerCase().split("@").pop();
  return DOMAIN_SET.has(host) || BRAND_RE.test(host);
}

module.exports = { FREE_PROVIDER_DOMAINS, FREE_PROVIDER_BRANDS, isFreeProvider };
