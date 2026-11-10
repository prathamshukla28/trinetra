// Server-side JavaScript injection: request data reaches eval / Function / vm.
const vm = require("vm");

function calc(req, res) {
  const result = eval(req.body.expression); // expect: dynamic-eval
  res.json({ result });
}

function makeFilter(req) {
  return new Function("row", "return " + req.query.filter); // expect: dynamic-eval
}

function sandbox(req) {
  const code = req.body.code;
  const script = code.trim(); // taint carried across two assignments
  return vm.runInNewContext(script, {}); // expect: dynamic-eval
}

function template(req) {
  const { tpl } = req.query;
  return eval(`\`${tpl}\``); // expect: dynamic-eval
}

function compile(req) {
  return new vm.Script(req.body.source); // expect: dynamic-eval
}

module.exports = { calc, makeFilter, sandbox, template, compile };
