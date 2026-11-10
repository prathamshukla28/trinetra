// Tricky negatives: strong algorithms, or MD5 in a non-security role.
const crypto = require("crypto");

function strong(d) {
  return crypto.createHash("sha256").update(d).digest("hex"); // ok: weak-hash (SHA-256)
}

function etag(body) {
  return crypto.createHash("md5").update(body).digest("base64"); // ok: weak-hash (HTTP ETag cache validator, not security)
}

function mac(key, d) {
  return crypto.createHmac("sha512", key).update(d).digest(); // ok: weak-hash (HMAC-SHA-512)
}

module.exports = { strong, etag, mac };
