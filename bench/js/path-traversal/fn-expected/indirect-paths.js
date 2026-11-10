// Path traversal the analyzer is expected to miss (documented limits).
const fs = require("fs");

function readHelper(p) {
  return fs.readFileSync(p, "utf8"); // expect: path-traversal (taint arrives through a parameter)
}

function handler(req) {
  return readHelper(req.query.file);
}

function viaObject(req) {
  const opts = {};
  opts.file = req.query.file;
  return fs.readFileSync(opts.file); // expect: path-traversal (taint stored in an object property)
}

module.exports = { handler, viaObject };
