// Tricky negatives: none of these execute attacker-influenced code.
const vm = require("vm");

function constant() {
  return eval("1 + 2"); // ok: dynamic-eval (literal string)
}

const getGlobal = new Function("return this"); // ok: dynamic-eval (literal body)

function parse(req) {
  return JSON.parse(req.body.payload); // ok: dynamic-eval (JSON.parse is not code execution)
}

function match(re, s) {
  return re.exec(s); // ok: dynamic-eval (RegExp.prototype.exec)
}

function fixedScript(ctx) {
  return vm.runInNewContext("a + b", ctx); // ok: dynamic-eval (literal script, data only in the context)
}

function constProp() {
  const expr = "6 * 7";
  return eval(expr); // ok: dynamic-eval (constant held in a const binding)
}

module.exports = { constant, getGlobal, parse, match, fixedScript, constProp };
