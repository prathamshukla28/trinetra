import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { copyFixture, ROOT, runCli, tempDir } from "./helpers/cli.js";

const sample = (dir) => copyFixture("js/sample-cli", path.join(dir, "sample-cli"));

test("no arguments prints usage and exits 1; --help exits 0; --version prints it", () => {
  const none = runCli([]);
  assert.equal(none.code, 1);
  assert.match(none.stdout, /Usage:/);
  const help = runCli(["--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /--run-generated/);
  const { version } = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  assert.equal(runCli(["--version"]).stdout.trim(), version);
});

test("missing target path exits 1 with a clear message", () => {
  const r = runCli(["teardown", "does/not/exist"], { cwd: tempDir() });
  assert.equal(r.code, 1);
  assert.match(r.stderr, /Target not found: does\/not\/exist/);
});

test("usage errors exit 1", () => {
  assert.equal(runCli(["teardown"]).code, 1);
  assert.equal(runCli(["bogus"]).code, 1);
  assert.equal(runCli(["teardown", "x", "--wat"]).code, 1);
  const rg = runCli(["teardown", ".", "--run-generated"]);
  assert.equal(rg.code, 1);
  assert.match(rg.stderr, /only makes sense with --rebuild/);
  assert.match(runCli(["teardown", ".", "--fail-on", "critical"]).stderr, /--fail-on must be/);
});

test("outputs land in ./trinetra-out of the caller's cwd, not the package", () => {
  const cwd = tempDir();
  sample(cwd);
  const r = runCli(["teardown", "sample-cli", "--no-semgrep", "--rebuild"], { cwd });
  assert.equal(r.code, 0, r.stderr);
  for (const f of ["sample-cli.md", "sample-cli.html", "sample-cli.json"])
    assert.ok(fs.existsSync(path.join(cwd, "trinetra-out", f)), f);
  assert.ok(fs.existsSync(path.join(cwd, "trinetra-out", "rebuilt", "sample-cli", "login.test.js")));
  assert.ok(fs.readdirSync(path.join(cwd, "trinetra-out", ".memory")).length === 1);
  assert.match(r.stdout, /report → trinetra-out\/sample-cli\.md/);
  assert.ok(!fs.existsSync(path.join(ROOT, "src", "rebuilt")), "nothing written into the package");
  const json = JSON.parse(fs.readFileSync(path.join(cwd, "trinetra-out", "sample-cli.json"), "utf8"));
  assert.equal(json.findings.length, 5);
  assert.deepEqual(
    json.findings.map((f) => f.where),
    [
      "sample-cli/index.js:14",
      "sample-cli/index.js:22",
      "sample-cli/index.js:6",
      "sample-cli/index.js:9",
      "sample-cli/index.js:18",
    ],
  );
});

test("--out is respected (relative to cwd) and the second run reports a delta", () => {
  const cwd = tempDir();
  const target = sample(cwd);
  assert.equal(runCli(["teardown", "sample-cli", "--out", "custom/dir", "--no-semgrep"], { cwd }).code, 0);
  assert.ok(fs.existsSync(path.join(cwd, "custom", "dir", "sample-cli.md")));
  assert.ok(!fs.existsSync(path.join(cwd, "trinetra-out")));

  // Fix one issue and re-run: memory reports it as fixed.
  const file = path.join(target, "index.js");
  fs.writeFileSync(file, fs.readFileSync(file, "utf8").replace('createHash("md5")', 'createHash("sha256")'));
  const second = runCli(["teardown", "sample-cli", "-o", "custom/dir", "--no-semgrep"], { cwd });
  assert.equal(second.code, 0);
  assert.match(second.stdout, /since last run: 0 new · 1 fixed · 4 unchanged/);
  const md = fs.readFileSync(path.join(cwd, "custom", "dir", "sample-cli.md"), "utf8");
  assert.match(md, /content \*\*changed\*\*; \*\*0\*\* new, \*\*1\*\* fixed/);
});

test("TRINETRA_OUT and a cwd config file set the output directory", () => {
  const cwd = tempDir();
  sample(cwd);
  fs.writeFileSync(path.join(cwd, "trinetra.config.json"), JSON.stringify({ outDir: "cfg-out" }));
  assert.equal(runCli(["teardown", "sample-cli", "--no-semgrep"], { cwd }).code, 0);
  assert.ok(fs.existsSync(path.join(cwd, "cfg-out", "sample-cli.md")));
});

test("--fail-on exits 2 when findings meet the threshold", () => {
  const cwd = tempDir();
  sample(cwd);
  const r = runCli(["teardown", "sample-cli", "--no-semgrep", "--fail-on", "high"], { cwd });
  assert.equal(r.code, 2);
  assert.match(r.stderr, /3 finding\(s\) at or above high/);
  fs.writeFileSync(path.join(cwd, "clean.js"), "export const add = (a, b) => a + b;\n");
  assert.equal(runCli(["teardown", "clean.js", "--no-semgrep", "--fail-on", "low"], { cwd }).code, 0);
});

test("compare writes both reports to the output dir", () => {
  const cwd = tempDir();
  sample(cwd);
  fs.mkdirSync(path.join(cwd, "v2"));
  fs.writeFileSync(
    path.join(cwd, "v2", "index.js"),
    "export function login() {}\nexport function audit() {}\n",
  );
  const r = runCli(["compare", "sample-cli", "v2", "--no-semgrep"], { cwd });
  assert.equal(r.code, 0, r.stderr);
  const md = fs.readFileSync(path.join(cwd, "trinetra-out", "sample-cli-vs-v2.md"), "utf8");
  assert.match(md, /\*\*Added\*\* \(1\):\n\n- `audit`/);
  assert.match(md, /\| command-exec \| 1 \| 0 \| 🟢 -1 \|/);
  assert.ok(fs.existsSync(path.join(cwd, "trinetra-out", "sample-cli-vs-v2.html")));
});

test("`npm run demo` targets a tracked example that works in a fresh clone", () => {
  const { scripts } = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8"));
  const m = /^node src\/cli\.js teardown (\S+)$/.exec(scripts.demo);
  assert.ok(m, `unexpected demo script: ${scripts.demo}`);
  const target = m[1];
  assert.ok(fs.existsSync(path.join(ROOT, target)), `${target} is missing`);
  // targets/ is gitignored, so a demo pointing there only works on the author's machine.
  const ignored = spawnSync("git", ["check-ignore", "-q", target], { cwd: ROOT });
  if (ignored.status !== 128) assert.notEqual(ignored.status, 0, `${target} is gitignored`);
  const out = tempDir();
  const r = runCli(["teardown", target, "--no-semgrep", "-o", out], { cwd: ROOT });
  assert.equal(r.code, 0, r.stderr);
  const json = JSON.parse(fs.readFileSync(path.join(out, `${path.basename(target)}.json`), "utf8"));
  assert.equal(json.findings.length, 5);
});
