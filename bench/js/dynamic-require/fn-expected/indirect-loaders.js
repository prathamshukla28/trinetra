// Dynamic module loading the analyzer is expected to miss (documented limits).
const Module = require("module");

function viaCreateRequire(req) {
  const r = Module.createRequire(__filename);
  return r(req.query.mod); // expect: dynamic-require (createRequire result is not tracked)
}

function viaModuleRequire(req) {
  return module.require(req.query.mod); // expect: dynamic-require (module.require is not modelled)
}

module.exports = { viaCreateRequire, viaModuleRequire };
