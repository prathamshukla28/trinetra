// Tricky negatives: names that look secret-ish, but no secret values.

const passwordField = "password"; // ok: hardcoded-secret (a form field name)

const tokenUrl = "https://auth.example.com/oauth/token"; // ok: hardcoded-secret (an endpoint URL)

const API_KEY_ENV = "MY_SERVICE_API_KEY"; // ok: hardcoded-secret (an env var name)

const apiKey = process.env.API_KEY; // ok: hardcoded-secret (read from the environment)

const secret = "changeme"; // ok: hardcoded-secret (placeholder)

const password = "${DB_PASSWORD}"; // ok: hardcoded-secret (interpolation placeholder)

const token = "xxxxxxxxxxxxxxxx"; // ok: hardcoded-secret (masked value)

const PEM_HEADER = "-----BEGIN " + "PRIVATE KEY-----"; // ok: hardcoded-secret (a PEM format marker, no key material)

module.exports = { passwordField, tokenUrl, API_KEY_ENV, apiKey, secret, password, token, PEM_HEADER };
