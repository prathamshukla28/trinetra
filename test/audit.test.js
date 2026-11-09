import test from "node:test";
import assert from "node:assert/strict";
import { audit } from "../src/stages/audit.js";
import { analyzeJs } from "../src/analysis/js-ast.js";

// No target is passed, so Semgrep never runs — these assert Trinetra's own rules.
const inspectionFrom = (text) => ({ raw: [{ file: "sample.js", text }], js: [analyzeJs(text, "sample.js")] });

test("flags a hardcoded secret", async () => {
  const f = await audit(inspectionFrom(`const API_KEY = "sk_live_abcd1234efgh";`), {});
  assert.ok(f.some((x) => x.rule === "hardcoded-secret" && x.severity === "high"));
});

test("flags dynamic eval and shell execution", async () => {
  const f = await audit(
    inspectionFrom(`import { execSync } from "node:child_process";\neval(userInput);\nexecSync(cmd);`),
    {},
  );
  const rules = f.map((x) => x.rule);
  assert.ok(rules.includes("dynamic-eval"));
  assert.ok(rules.includes("command-injection"));
});

test("flags weak hashing and security-relevant insecure randomness", async () => {
  const f = await audit(
    inspectionFrom(`crypto.createHash("md5");\nfunction newToken() { return Math.random(); }`),
    {},
  );
  const rules = f.map((x) => x.rule);
  assert.ok(rules.includes("weak-hash"));
  assert.ok(rules.includes("insecure-random"));
});

test("sorts findings high → low", async () => {
  const f = await audit(
    inspectionFrom(`const sessionKey = Math.random();\neval(x);\ncrypto.createHash("sha1");`),
    {},
  );
  const order = { high: 0, medium: 1, low: 2 };
  assert.ok(f.length >= 3);
  for (let i = 1; i < f.length; i++) assert.ok(order[f[i - 1].severity] <= order[f[i].severity]);
});

test("clean source yields no findings", async () => {
  const f = await audit(inspectionFrom(`export const add = (a, b) => a + b;`), {});
  assert.equal(f.length, 0);
});

test("includes binary hardening findings and reports Semgrep as not applicable", async () => {
  const f = await audit(
    {
      raw: [],
      binary: {
        findings: [
          {
            rule: "binary-no-pie",
            severity: "medium",
            title: "No PIE",
            why: "",
            where: "bin",
            evidence: "",
            engine: "trinetra-binary",
          },
        ],
      },
    },
    {},
    "bin",
  );
  assert.equal(f.length, 1);
  assert.equal(f.engines.semgrep, "not applicable");
});

test("Semgrep can be disabled and its absence is reported", async () => {
  const insp = inspectionFrom(`const x = 1;`);
  const off = await audit(insp, {}, "sample.js", { useSemgrep: false });
  assert.equal(off.engines.semgrep, "disabled (--no-semgrep)");
  const missing = await audit(insp, {}, "sample.js", {
    ctx: { env: { TRINETRA_SEMGREP_BIN: "/nonexistent/semgrep" }, rel: (p) => p, cwd: process.cwd() },
  });
  assert.equal(missing.engines.semgrep, "not installed");
});
