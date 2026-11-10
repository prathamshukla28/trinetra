// Real code execution that the analyzer is expected to miss (documented limits).

function later(req) {
  setTimeout(req.query.code, 10); // expect: dynamic-eval (string-form setTimeout is not modelled)
}

function indirect(req) {
  return (0, eval)(req.body.expr); // expect: dynamic-eval (indirect eval through a sequence expression)
}

function aliased(req) {
  const run = eval;
  return run(req.body.expr); // expect: dynamic-eval (eval aliased to a local)
}

function viaGlobal(req) {
  return globalThis.eval(req.body.expr); // expect: dynamic-eval (globalThis.eval is not resolved)
}

module.exports = { later, indirect, aliased, viaGlobal };
