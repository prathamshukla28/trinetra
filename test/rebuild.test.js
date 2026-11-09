import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { rebuild, safeIdent } from "../src/stages/rebuild.js";
import { createContext } from "../src/context.js";
import { tempDir } from "./helpers/cli.js";

const ctxFor = (env = {}) => createContext({ cwd: tempDir(), env });
const inspection = { raw: [{ file: "/t/calc.js", text: "export const add = (a,b) => a+b;" }] };
const map = { behaviors: [] };

const good = async () => ({
  impl: "export const add = (a, b) => a + b;\n",
  test: 'import test from "node:test";\nimport assert from "node:assert/strict";\nimport { add } from "./calc.js";\ntest("add", () => assert.equal(add(1, 2), 3));\n',
  notes: "",
});

test("default --rebuild writes generated code but does not execute it", async () => {
  const ctx = ctxFor();
  const r = await rebuild({ name: "app", map, inspection }, ctx, { reimplement: good });
  assert.equal(r.mode, "llm");
  assert.equal(r.executed, false);
  assert.deepEqual(r.verified, [
    { name: "calc", status: "not-run", passed: null, reason: "pass --run-generated to execute" },
  ]);
  assert.ok(fs.existsSync(path.join(ctx.rebuiltDir, "app", "calc.test.js")));
  assert.ok(r.outDir.startsWith(ctx.outDir), "rebuild output lives under the run's output dir");
});

test("--run-generated executes in the sandbox", async () => {
  const r = await rebuild({ name: "app", map, inspection }, ctxFor(), {
    reimplement: good,
    runGenerated: true,
  });
  assert.equal(r.verified[0].status, "passed");
  assert.equal(r.verified[0].isolation.env, "stripped");
});

test("generated code that uses child_process / env is blocked even with --run-generated", async () => {
  const marker = path.join(tempDir(), "pwned");
  const evil = async () => ({
    impl: `import { execSync } from "node:child_process";\nexport const add = () => execSync("touch ${marker}");\n`,
    test: `import { add } from "./calc.js";\nimport test from "node:test";\ntest("x", () => { add(); console.log(process.env.ANTHROPIC_API_KEY); });\n`,
  });
  const r = await rebuild({ name: "app", map, inspection }, ctxFor(), {
    reimplement: evil,
    runGenerated: true,
  });
  assert.equal(r.verified[0].status, "blocked");
  assert.match(r.verified[0].reason, /child_process/);
  assert.match(r.verified[0].reason, /environment/);
  assert.ok(!fs.existsSync(marker));
});

test("a failing generated test gets exactly one retry with the failure fed back", async () => {
  const calls = [];
  const flaky = async (req) => {
    calls.push(req);
    const r = await good();
    return calls.length === 1 ? { ...r, impl: "export const add = () => 0;\n" } : r;
  };
  const r = await rebuild({ name: "app", map, inspection }, ctxFor(), {
    reimplement: flaky,
    runGenerated: true,
  });
  assert.equal(calls.length, 2);
  assert.match(calls[1].priorError, /not ok|fail/i);
  assert.equal(r.verified[0].status, "passed");
});

test("without credentials it scaffolds stubs; untrusted names can't inject code", async () => {
  const ctx = ctxFor({});
  const r = await rebuild(
    {
      name: "app",
      inspection,
      map: {
        behaviors: [
          { name: "delete", summary: "x" },
          { name: "9lives", summary: "y" },
          { name: "evil", summary: 'ok\nimport "child_process"; process.exit(1) //' },
          { name: "evil", summary: "duplicate" },
        ],
      },
    },
    ctx,
  );
  assert.equal(r.mode, "scaffold");
  const names = fs.readdirSync(r.outDir).sort();
  assert.deepEqual(names, [
    "_9lives.js",
    "_9lives.test.js",
    "delete_.js",
    "delete_.test.js",
    "evil.js",
    "evil.test.js",
  ]);
  const evilTest = fs.readFileSync(path.join(r.outDir, "evil.test.js"), "utf8");
  assert.equal(evilTest.split("\n")[0].startsWith("// TEST FIRST."), true);
  assert.ok(
    !/^import "child_process"/m.test(evilTest),
    "newline in untrusted text must not start a code line",
  );
});

test("safeIdent produces valid identifiers", () => {
  assert.equal(safeIdent("my-func"), "my_func");
  assert.equal(safeIdent("class"), "class_");
  assert.equal(safeIdent("1x"), "_1x");
  assert.equal(safeIdent(""), "unit");
});
