// Tricky negatives: every module path is fixed or allow-listed.
const path = require("path");

async function lazy() {
  return import("./heavy.js"); // ok: dynamic-require (literal specifier)
}

const cfg = require(path.join(__dirname, "config.json")); // ok: dynamic-require (fixed at authoring time)

const pkg = require(require.resolve("./package.json")); // ok: dynamic-require (require.resolve of a literal)

const LOCALES = { en: "./en.js", fr: "./fr.js" };

function allowlisted(req) {
  return require(LOCALES[req.query.lang] ?? "./en.js"); // ok: dynamic-require (allow-list lookup)
}

module.exports = { lazy, cfg, pkg, allowlisted };
