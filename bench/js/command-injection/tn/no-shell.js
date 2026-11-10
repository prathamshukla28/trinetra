// Tricky negatives: no shell interprets attacker input here.
const { spawn, execFile, execFileSync, exec } = require("child_process");

function noShell(req) {
  return spawn("ls", ["-la", req.query.dir]); // ok: command-injection (args array, no shell)
}

function execFileArgs(req) {
  return execFile("git", ["log", "--author", req.query.author]); // ok: command-injection (execFile, no shell)
}

function literal() {
  return exec("ls -la /tmp"); // ok: command-injection (literal command)
}

function shellFalse(req) {
  return execFileSync("cat", [req.query.f], { shell: false }); // ok: command-injection (shell explicitly off)
}

function regex(input) {
  const re = /(\d+)-(\d+)/g;
  return re.exec(input); // ok: command-injection (RegExp.prototype.exec)
}

function constCmd() {
  const cmd = "uptime";
  return exec(cmd); // ok: command-injection (constant held in a const binding)
}

const db = { exec: (q) => q };

function notChildProcess(req) {
  return db.exec(req.query.q); // ok: command-injection (an unrelated method named exec)
}

module.exports = { noShell, execFileArgs, literal, shellFalse, regex, constCmd, notChildProcess };
