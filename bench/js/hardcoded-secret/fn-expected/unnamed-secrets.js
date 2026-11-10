// Secrets the analyzer is expected to miss (documented limits).

const conn = "postgres://app:Pa55w0rd-prod@db.internal:5432/app"; // expect: hardcoded-secret (password embedded in a connection URL)

const pw = "hunter2hunter2"; // expect: hardcoded-secret (variable name too short to recognise)

const cryptoKey = "a1b2c3d4e5f6a7b8c9d0e1f2"; // expect: hardcoded-secret (encryption key under a name the rule does not match)

module.exports = { conn, pw, cryptoKey };
