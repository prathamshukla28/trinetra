// SSRF the analyzer is expected to miss (documented limits).
const needle = require("needle");
const got = require("got");

function research(req) {
  return needle.get(req.query.url + req.query.symbol); // expect: ssrf (needle is not a modelled client)
}

async function viaGot(req) {
  return got(req.query.url); // expect: ssrf (got is not a modelled client)
}

async function viaHelper(u) {
  return fetch(u); // expect: ssrf (taint arrives through a parameter)
}

function handler(req) {
  return viaHelper(req.query.url);
}

module.exports = { research, viaGot, handler };
