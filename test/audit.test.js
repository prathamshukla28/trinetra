import test from "node:test";
import assert from "node:assert/strict";
import { audit } from "../src/stages/audit.js";

// target is omitted so Semgrep is skipped — these assert the built-in engine.
const inspectionFrom = (text) => ({ raw: [{ file: "sample.js", text }] });

test("flags a hardcoded secret", async () => {
  const f = await audit(inspectionFrom(`const API_KEY = "sk_live_abcd1234efgh";`), {});
  assert.ok(f.some((x) => x.rule === "hardcoded-secret" && x.severity === "high"));
});

test("flags dynamic eval and shell execution", async () => {
  const f = await audit(inspectionFrom(`eval(userInput); execSync(cmd);`), {});
  const rules = f.map((x) => x.rule);
  assert.ok(rules.includes("dynamic-eval"));
  assert.ok(rules.includes("shell-injection"));
});

test("flags weak hashing and insecure randomness", async () => {
  const f = await audit(inspectionFrom(`crypto.createHash("md5"); Math.random();`), {});
  const rules = f.map((x) => x.rule);
  assert.ok(rules.includes("weak-hash"));
  assert.ok(rules.includes("insecure-random"));
});

test("sorts findings high → low", async () => {
  const f = await audit(inspectionFrom(`Math.random(); eval(x);`), {});
  const order = { high: 0, medium: 1, low: 2 };
  for (let i = 1; i < f.length; i++) {
    assert.ok(order[f[i - 1].severity] <= order[f[i].severity]);
  }
});

test("clean source yields no findings", async () => {
  const f = await audit(inspectionFrom(`export const add = (a, b) => a + b;`), {});
  assert.equal(f.length, 0);
});
