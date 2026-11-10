// Command injection the analyzer is expected to miss (documented limits).
const { spawn, execFile } = require("child_process");
const childProcess = require("child_process");

function viaSh(req) {
  return spawn("sh", ["-c", req.query.cmd]); // expect: command-injection (shell passed explicitly as argv[0])
}

function optsInVariable(req) {
  const opts = { shell: true };
  return execFile("find", [req.query.dir], opts); // expect: command-injection (shell option held in a variable)
}

const run = childProcess.exec;

function aliasExec(req) {
  return run("ping -c 1 " + req.query.host); // expect: command-injection (exec aliased via a member read)
}

module.exports = { viaSh, optsInVariable, aliasExec };
