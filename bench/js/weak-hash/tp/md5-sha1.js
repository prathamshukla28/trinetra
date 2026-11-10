// MD5 / SHA-1 used where collision resistance matters.
const crypto = require("crypto");
const { createHash } = require("node:crypto");

function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex"); // expect: weak-hash
}

function signPayload(data, key) {
  return createHash("sha1").update(key + data).digest("hex"); // expect: weak-hash
}

module.exports = { hashPassword, signPayload };
