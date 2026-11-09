import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildNodeArgs,
  buildSandboxEnv,
  permissionFlag,
  reviewGeneratedCode,
  runInSandbox,
} from "../src/sandbox.js";

// A canary secret in the *parent* process: generated code must never see it.
process.env.ANTHROPIC_API_KEY = "sk-ant-canary-must-not-leak";
process.env.AWS_SECRET_ACCESS_KEY = "aws-canary";

const IMPL = "export const add = (a, b) => a + b;\n";
const testFile = (body) =>
  `import test from "node:test";\nimport assert from "node:assert/strict";\nimport { add } from "./unit.js";\n${body}\n`;
const run = (body, opts) =>
  runInSandbox({ "unit.js": IMPL, "unit.test.js": testFile(body) }, "unit.test.js", opts);

test("sandbox env is built from scratch: no secrets, HOME/TMPDIR in the sandbox dir", () => {
  const env = buildSandboxEnv("/tmp/sbx");
  assert.equal(env.HOME, "/tmp/sbx");
  assert.equal(env.TMPDIR, "/tmp/sbx");
  for (const k of Object.keys(env))
    assert.doesNotMatch(k, /KEY|TOKEN|SECRET|PASSWORD|ANTHROPIC|AWS|NODE_OPTIONS/);
  assert.ok(!Object.values(env).includes("sk-ant-canary-must-not-leak"));
});

test("node args grant only fs read/write scoped to the sandbox dir", () => {
  const args = buildNodeArgs("/tmp/sbx", "/tmp/sbx/unit.test.js");
  assert.deepEqual(args, [
    permissionFlag(),
    "--allow-fs-read=/tmp/sbx",
    "--allow-fs-write=/tmp/sbx",
    "/tmp/sbx/unit.test.js",
  ]);
  assert.ok(!args.some((a) => /allow-(child-process|worker|addons|wasi)/.test(a)));
  assert.ok(process.allowedNodeEnvironmentFlags.has(permissionFlag()), "flag exists on this Node");
});

test("a passing generated test passes in the sandbox", () => {
  const r = run(`test("adds", () => assert.equal(add(2, 3), 5));`);
  assert.equal(r.passed, true, r.output);
  assert.equal(r.isolation.permissionModel, true);
  assert.equal(r.isolation.env, "stripped");
});

test("a failing generated test fails", () => {
  const r = run(`test("wrong", () => assert.equal(add(2, 3), 6));`);
  assert.equal(r.passed, false);
});

test("generated code cannot read the parent's API key from process.env", () => {
  const r = run(
    `test("exfil", () => assert.equal(process.env.ANTHROPIC_API_KEY, "sk-ant-canary-must-not-leak"));`,
  );
  assert.equal(r.passed, false, "the key must not be visible inside the sandbox");
  assert.ok(!r.output.includes("sk-ant-canary-must-not-leak") || /expected/.test(r.output));
  const leak = run(`test("dump", () => { console.log("ENV=" + JSON.stringify(process.env)); });`);
  assert.equal(leak.passed, true);
  assert.ok(!leak.output.includes("canary"), "no canary values in the child environment");
});

test("generated code cannot spawn processes", () => {
  const r = run(
    `import { execSync } from "node:child_process";\ntest("spawn", () => { execSync("echo pwned > /tmp/trinetra-pwned"); });`,
  );
  assert.equal(r.passed, false);
  assert.match(r.output, /ERR_ACCESS_DENIED/);
  assert.ok(!fs.existsSync("/tmp/trinetra-pwned"));
});

test("generated code cannot start worker threads", () => {
  const r = run(
    `import { Worker } from "node:worker_threads";\ntest("w", () => { new Worker("x", { eval: true }); });`,
  );
  assert.equal(r.passed, false);
  assert.match(r.output, /ERR_ACCESS_DENIED/);
});

test("generated code cannot read or write outside its directory", () => {
  const secret = path.join(fs.realpathSync(os.tmpdir()), `trinetra-secret-${process.pid}.txt`);
  fs.writeFileSync(secret, "top secret");
  try {
    const read = run(
      `import fs from "node:fs";\ntest("r", () => { fs.readFileSync(${JSON.stringify(secret)}); });`,
    );
    assert.equal(read.passed, false);
    assert.match(read.output, /ERR_ACCESS_DENIED/);
    const write = run(
      `import fs from "node:fs";\ntest("w", () => { fs.writeFileSync(${JSON.stringify(secret)}, "x"); });`,
    );
    assert.equal(write.passed, false);
    assert.equal(fs.readFileSync(secret, "utf8"), "top secret");
    const home = run(
      `import fs from "node:fs";\ntest("h", () => { fs.readdirSync(${JSON.stringify(os.homedir())}); });`,
    );
    assert.equal(home.passed, false);
  } finally {
    fs.rmSync(secret, { force: true });
  }
});

test("generated code can use its own directory", () => {
  const r = run(
    `import fs from "node:fs";\ntest("own", () => { fs.writeFileSync("scratch.txt", "ok"); assert.equal(fs.readFileSync("scratch.txt", "utf8"), "ok"); });`,
  );
  assert.equal(r.passed, true, r.output);
});

test("runaway generated code is killed at the timeout", () => {
  const r = run(`test("spin", () => { for (;;) {} });`, { timeoutMs: 1500 });
  assert.equal(r.passed, false);
  assert.equal(r.timedOut, true);
});

test(
  "network is blocked when the OS sandbox is available",
  { skip: process.platform !== "darwin" && process.platform !== "linux" },
  () => {
    const r = run(
      `test("net", async () => { await fetch("http://example.com", { signal: AbortSignal.timeout(4000) }); });`,
      { timeoutMs: 15000 },
    );
    if (r.isolation.network === "not restricted") return; // documented limitation on this host
    assert.equal(r.passed, false);
  },
);

test("static review refuses code that reaches for process/network/env APIs", () => {
  assert.deepEqual(reviewGeneratedCode(IMPL), []);
  assert.deepEqual(reviewGeneratedCode(testFile(`test("a", () => assert.ok(add));`)), []);
  assert.ok(
    reviewGeneratedCode(`import { exec } from "child_process"; exec(x);`).includes("imports child_process"),
  );
  assert.ok(
    reviewGeneratedCode(`export const k = () => process.env.ANTHROPIC_API_KEY;`).includes(
      "reads environment variables",
    ),
  );
  assert.ok(
    reviewGeneratedCode(`export const f = () => fetch("https://evil.example");`).includes(
      "makes network requests",
    ),
  );
  assert.ok(reviewGeneratedCode(`const m = require(name);`).length > 0);
  assert.ok(reviewGeneratedCode(`eval(payload)`).length > 0);
  assert.match(reviewGeneratedCode(`this is not js (`)[0], /could not be parsed/);
});
