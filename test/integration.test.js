// End-to-end: the real CLI drives the real adapters, which execute recorded
// stand-ins for REA and Semgrep (test/fixtures/bin) that replay genuine engine
// output. Exercises process invocation, parsing, correlation and reporting.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { buildElf } from "./helpers/binaries.js";
import { copyFixture, FAKE_REA, FAKE_SEMGREP, hermeticEnv, runCli, tempDir } from "./helpers/cli.js";

const engines = (extra = {}) =>
  hermeticEnv({ TRINETRA_REA_BIN: FAKE_REA, TRINETRA_SEMGREP_BIN: FAKE_SEMGREP, ...extra });

test("source target: REA graph + Semgrep findings correlate with Trinetra's own", () => {
  const cwd = tempDir();
  copyFixture("js/sample-cli", path.join(cwd, "sample-cli"));
  const log = path.join(cwd, "rea.log");
  const r = runCli(["teardown", "sample-cli"], { cwd, env: engines({ FAKE_REA_LOG: log }) });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /found 4 function\(s\) via rea-javascript-application/);

  const calls = fs.readFileSync(log, "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(calls[0][0], "analyze-javascript-application");
  assert.ok(path.isAbsolute(calls[0][1]), "REA receives an absolute target path");
  assert.deepEqual(calls[0].slice(-2), ["--format", "json"]);

  const json = JSON.parse(fs.readFileSync(path.join(cwd, "trinetra-out", "sample-cli.json"), "utf8"));
  assert.equal(json.engine, "rea-javascript-application");
  const byWhere = Object.fromEntries(json.findings.map((f) => [f.where, f]));
  // Semgrep's three hits merge into the AST findings at the same place.
  for (const where of ["sample-cli/index.js:6", "sample-cli/index.js:9", "sample-cli/index.js:18"]) {
    assert.deepEqual(byWhere[where].engines.sort(), ["semgrep", "trinetra-ast"], where);
    assert.equal(byWhere[where].confidence, "high");
  }
  assert.equal(json.findings.length, 5);
  const semgrepRow = json.engines.find((e) => e.name.startsWith("Semgrep"));
  assert.equal(semgrepRow.status, "ran (3 raw finding(s))");
  assert.equal(json.engines.find((e) => e.name.startsWith("REA")).status, "used");
});

test("native target: Trinetra hardening + REA decompilation + pseudocode rules", () => {
  const cwd = tempDir();
  fs.writeFileSync(path.join(cwd, "vuln"), buildElf({ type: 2, pieFlag: false, imports: ["gets", "puts"] }));
  const log = path.join(cwd, "rea.log");
  const r = runCli(["teardown", "vuln"], { cwd, env: engines({ FAKE_REA_LOG: log }) });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /found 3 procedure\(s\) via rea-native/);

  const [call] = fs.readFileSync(log, "utf8").trim().split("\n").map(JSON.parse);
  assert.equal(call[0], "decompile-all");
  assert.equal(
    call[call.indexOf("--output") + 1],
    path.join(cwd, "trinetra-out", ".work", "rea-decomp", "vuln"),
  );

  const json = JSON.parse(fs.readFileSync(path.join(cwd, "trinetra-out", "vuln.json"), "utf8"));
  const rules = new Set(json.findings.map((f) => f.rule));
  assert.ok(rules.has("binary-gets-import"), "own binary checks ran");
  assert.ok(rules.has("binary-no-pie"));
  // The recorded /bin/echo pseudocode is clean, so the rules run but match nothing.
  assert.equal(json.engines.find((e) => e.name === "Pseudocode line rules").status, "ran");
  const md = fs.readFileSync(path.join(cwd, "trinetra-out", "vuln.md"), "utf8");
  assert.match(md, /Sample decompiled function — `entry`/);
  assert.match(md, /### Binary hardening/);

  // A second run must clear REA's previous output dir (decompile-all refuses existing dirs).
  assert.equal(runCli(["teardown", "vuln"], { cwd, env: engines() }).code, 0);
});

test("REA failures degrade gracefully to Trinetra's own analysis", () => {
  const cwd = tempDir();
  fs.writeFileSync(path.join(cwd, "app.js"), "export const f = (x) => eval(x);\n");
  const broken = path.join(cwd, "broken-rea.mjs");
  fs.writeFileSync(
    broken,
    'console.log(JSON.stringify({code:"E_X",category:"engine",message:"boom"})); process.exit(3);\n',
  );
  const r = runCli(["teardown", "app.js", "--no-semgrep"], {
    cwd,
    env: engines({ TRINETRA_REA_BIN: broken }),
  });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /REA unavailable for this target: REA E_X: boom/);
  const json = JSON.parse(fs.readFileSync(path.join(cwd, "trinetra-out", "app.js.json"), "utf8"));
  assert.equal(json.engine, "trinetra-ast");
  assert.equal(json.findings[0].rule, "dynamic-eval");
});

test("--rebuild without an API key scaffolds, never calls the model, and runs nothing", () => {
  const cwd = tempDir();
  copyFixture("js/sample-cli", path.join(cwd, "sample-cli"));
  const r = runCli(["teardown", "sample-cli", "--rebuild", "--no-semgrep", "--no-rea"], { cwd });
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /scaffolded 8 file\(s\)/);
  assert.doesNotMatch(r.stdout, /sending .* to Claude/);
});
