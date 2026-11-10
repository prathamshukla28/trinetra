// Tricky negatives: sanitized, guarded, numeric, or fixed paths.
const fs = require("fs");
const path = require("path");

function basenameOnly(req) {
  return fs.readFileSync(path.join("/srv/files", path.basename(req.query.name))); // ok: path-traversal (basename)
}

function guarded(req) {
  const root = "/srv/files";
  const p = path.resolve(root, req.query.name);
  if (!p.startsWith(root + path.sep)) throw new Error("bad path");
  return fs.readFileSync(p); // ok: path-traversal (prefix check after resolve)
}

function numericId(req) {
  return fs.readFileSync(`/srv/reports/${Number(req.params.id)}.pdf`); // ok: path-traversal (coerced to a number)
}

function fixed() {
  return fs.readFileSync(path.join(__dirname, "data.json")); // ok: path-traversal (fixed path)
}

function allowlist(req) {
  const files = { a: "a.txt", b: "b.txt" };
  return fs.readFileSync(files[req.query.k]); // ok: path-traversal (allow-list lookup)
}

module.exports = { basenameOnly, guarded, numericId, fixed, allowlist };
