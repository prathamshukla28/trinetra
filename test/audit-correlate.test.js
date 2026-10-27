import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { audit, correlate } from "../src/stages/audit.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("correlate merges the same issue reported by two engines", () => {
  const merged = correlate([
    { rule: "insecure-random", severity: "low", title: "Insecure randomness", why: "", where: "a.js:10", evidence: "", engine: "builtin" },
    { rule: "node_insecure_random_generator", severity: "medium", title: "insecure random generator", why: "", where: "a.js:10", evidence: "", engine: "semgrep" },
  ]);
  assert.equal(merged.length, 1);
  assert.deepEqual(merged[0].engines.sort(), ["builtin", "semgrep"]);
  assert.equal(merged[0].severity, "medium"); // keeps the higher severity
});

test("correlate keeps distinct issues separate", () => {
  const merged = correlate([
    { rule: "dynamic-eval", severity: "high", title: "eval", why: "", where: "a.js:1", evidence: "", engine: "builtin" },
    { rule: "weak-hash", severity: "medium", title: "md5", why: "", where: "a.js:2", evidence: "", engine: "builtin" },
  ]);
  assert.equal(merged.length, 2);
});

test("native rules flag dangerous C calls in decompiled pseudocode", async () => {
  const dir = path.join(ROOT, "reports", ".test-decomp");
  const fnDir = path.join(dir, "functions");
  fs.mkdirSync(fnDir, { recursive: true });
  fs.writeFileSync(path.join(fnDir, "vuln.c"), `void f(char *s){ char b[8]; _strcpy(b,s); _system("ls"); }`);
  try {
    const findings = await audit({ decompDir: "reports/.test-decomp" }, {});
    const rules = findings.map((x) => x.rule);
    assert.ok(rules.includes("native-command-exec"));
    assert.ok(rules.includes("native-unsafe-string"));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
