// Shell command strings built from untrusted input.
const { exec, execSync, spawn } = require("child_process");
const cp = require("node:child_process");

function list(req, res) {
  exec(`ls -la ${req.query.dir}`, (err, out) => res.send(out)); // expect: command-injection
}

function gitLog() {
  const branch = process.argv[2];
  return execSync("git log --oneline " + branch).toString(); // expect: command-injection
}

function archive(req) {
  let cmd = "tar czf /tmp/out.tgz ";
  cmd += req.body.path; // taint across a compound assignment
  return cp.exec(cmd); // expect: command-injection
}

function shellSpawn(req) {
  return spawn("convert " + req.query.file + " out.png", { shell: true }); // expect: command-injection
}

function shellArgs(req) {
  return spawn("grep", [req.query.pattern, "log.txt"], { shell: true }); // expect: command-injection
}

module.exports = { list, gitLog, archive, shellSpawn, shellArgs };
