// Tricky negatives: the request host is fixed, configured, or validated.

async function fixedHost(req) {
  return fetch(`https://api.example.com/v1/items/${encodeURIComponent(req.params.id)}`); // ok: ssrf (fixed host, encoded path)
}

async function envUrl() {
  return fetch(process.env.API_URL); // ok: ssrf (operator configuration)
}

async function constant() {
  return fetch("https://example.com/health"); // ok: ssrf (literal)
}

async function allowlisted(req) {
  const hosts = { a: "https://a.example.com", b: "https://b.example.com" };
  return fetch(hosts[req.query.h]); // ok: ssrf (allow-list lookup)
}

const ALLOWED = new Set(["a.example.com"]);

async function validated(req) {
  const u = new URL(req.query.url);
  if (!ALLOWED.has(u.hostname)) throw new Error("host not allowed");
  return fetch(u); // ok: ssrf (hostname checked against an allow-list)
}

module.exports = { fixedHost, envUrl, constant, allowlisted, validated };
