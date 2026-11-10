// Weak hashing the analyzer is expected to miss (documented limits).
const crypto = require("crypto");
const md5 = require("md5");

const ALG = "md5";

function digest(pw) {
  return crypto.createHash(ALG).update(pw).digest("hex"); // expect: weak-hash (algorithm held in a constant)
}

function legacyPassword(pw) {
  return md5(pw); // expect: weak-hash (the md5 npm package)
}

module.exports = { digest, legacyPassword };
