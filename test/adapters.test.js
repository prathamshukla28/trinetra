// Adapter parsing against output recorded from the real engines
// (rea-agents 6.8.0, semgrep 1.181.0) — see test/fixtures/.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import {
  parseDecompileDir,
  parseReaJsRecord,
  parseReaStdout,
  resolveReaBin,
  isReaAvailable,
} from "../src/adapters/rea.js";
import { parseSemgrepOutput, resolveSemgrepBin, runSemgrep } from "../src/adapters/semgrep.js";
import { which, commandFor } from "../src/util/exec.js";
import { FAKE_SEMGREP, FIXTURES, tempDir, copyFixture } from "./helpers/cli.js";

const readFixture = (rel) => fs.readFileSync(path.join(FIXTURES, rel), "utf8");

test("REA stdout: progress records are skipped, the last record is the result", () => {
  const out = [
    JSON.stringify({ rea_progress: { phase: "a" } }),
    JSON.stringify({ evidence_id: "ev_1" }),
    JSON.stringify({ rea_progress: { phase: "b" } }),
    "",
  ].join("\n");
  assert.deepEqual(parseReaStdout(out), { evidence_id: "ev_1" });
});

test("REA stdout: structured errors become exceptions; empty output is an error", () => {
  const err = JSON.stringify({ code: "E_ENGINE", category: "environment", message: "Ghidra not found" });
  assert.throws(() => parseReaStdout(err), /REA E_ENGINE: Ghidra not found/);
  assert.throws(() => parseReaStdout(""), /no result record/);
});

test("REA analyze-javascript-application record maps to units + provenance", () => {
  const r = parseReaJsRecord(JSON.parse(readFixture("rea/analyze-javascript-application.json")));
  assert.deepEqual(
    r.units.map((u) => [u.name, u.file, u.line]),
    [
      ["runUserCommand", "index.js", 13],
      ["evalExpression", "index.js", 21],
      ["makeToken", "index.js", 17],
      ["login", "index.js", 8],
    ],
  );
  assert.equal(r.provenance.provider, "REA JavaScript application analyzer");
  assert.match(r.provenance.sha256, /^[0-9a-f]{64}$/);
  assert.match(r.provenance.evidenceId, /^ev_/);
  assert.equal(r.reaFindings, 8);
});

test("REA decompile-all index maps to procedures, hashes and a sample", () => {
  const dir = copyFixture("rea/decompile", path.join(tempDir(), "decomp"));
  const r = parseDecompileDir(dir, "/bin/echo");
  assert.equal(r.statistics.procedures, 3);
  assert.equal(r.statistics.external, 2);
  assert.equal(r.sampleName, "entry");
  assert.match(r.overview, /undefined8 entry\(/);
  assert.equal(r.provenance.provider, "Ghidra");
  assert.equal(Object.keys(r.fnHashes).length, 3);
  assert.equal(r.decompDir, dir);
});

test("Semgrep JSON maps to findings; redacted snippets are re-read from disk", () => {
  const target = copyFixture("js/sample-cli", path.join(tempDir(), "sample-cli"));
  const json = readFixture("semgrep/sample-cli.json").replaceAll("<target>", target);
  const f = parseSemgrepOutput(json);
  assert.deepEqual(
    f.map((x) => [x.rule, x.severity, x.where.replace(target, "T")]),
    [
      ["node_api_key", "high", "T/index.js:6"],
      ["node_md5", "medium", "T/index.js:9"],
      ["node_insecure_random_generator", "medium", "T/index.js:18"],
    ],
  );
  assert.match(f[0].evidence, /^const API_KEY = /); // "requires login" replaced by the real line
  assert.equal(f[0].cwe, "cwe-798");
  assert.ok(f.every((x) => x.engine === "semgrep"));
});

test("runSemgrep reads stdout even when semgrep exits non-zero", () => {
  const target = copyFixture("js/sample-cli", path.join(tempDir(), "sample-cli"));
  const f = runSemgrep(target, { env: { ...process.env, TRINETRA_SEMGREP_BIN: FAKE_SEMGREP } });
  assert.equal(f.length, 3);
});

test("REA bin: env override, then the installed rea-agents package, then PATH", () => {
  assert.equal(resolveReaBin({ env: { TRINETRA_REA_BIN: "/definitely/missing" } }), null);
  assert.equal(isReaAvailable({ env: { TRINETRA_REA_BIN: "/definitely/missing" } }), false);
  // rea-agents is a dependency, so it resolves through the module graph, not ./node_modules/.bin.
  const bin = resolveReaBin({ env: { PATH: "" } });
  assert.ok(bin && bin.endsWith(path.join("rea-agents", "scripts", "rea.mjs")), bin);
  assert.deepEqual(commandFor(bin), { command: process.execPath, args: [bin] });
});

test("which() finds executables on PATH; semgrep override must exist", () => {
  const dir = tempDir();
  const exe = path.join(dir, "mytool");
  fs.writeFileSync(exe, "#!/bin/sh\n");
  fs.chmodSync(exe, 0o755);
  assert.equal(which("mytool", { env: { PATH: dir } }), exe);
  assert.equal(which("mytool", { env: { PATH: "" } }), null);
  assert.equal(resolveSemgrepBin({ env: { TRINETRA_SEMGREP_BIN: exe } }), exe);
  assert.equal(resolveSemgrepBin({ env: { TRINETRA_SEMGREP_BIN: "/nope" } }), null);
});
