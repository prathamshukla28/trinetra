import test from "node:test";
import assert from "node:assert/strict";
import { analyzeJs, isStaticString, parseJs } from "../src/analysis/js-ast.js";

const find = (src) => analyzeJs(src, "t.js").findings;
const ruleSet = (src) => find(src).map((f) => f.rule);
const has = (src, rule) => ruleSet(src).includes(rule);

// --- command execution ------------------------------------------------------

test("exec/execSync with a non-literal argument is flagged", () => {
  assert.ok(has(`import { execSync } from "child_process"; execSync(cmd);`, "command-injection"));
  assert.ok(has(`const cp = require("node:child_process"); cp.exec("ls " + dir);`, "command-injection"));
  assert.ok(has('import * as cp from "child_process"; cp.exec(`git ${x}`);', "command-injection"));
  assert.ok(has(`require("child_process").execSync(cmd);`, "command-injection"));
  assert.ok(has(`const { exec: run } = require("child_process"); run(cmd);`, "command-injection"));
});

test("exec with a literal command is not flagged", () => {
  assert.ok(!has(`import { execSync } from "child_process"; execSync("git status");`, "command-injection"));
  assert.ok(!has('import { exec } from "child_process"; exec(`ls -la`);', "command-injection"));
  assert.ok(!has(`import { exec } from "child_process"; exec("ls " + "-la");`, "command-injection"));
});

test("RegExp.prototype.exec and unrelated exec() are never command execution", () => {
  const src = `
    const re = /a(b)/g; re.exec(input); /x/.exec(s);
    const m = pattern.exec(line);
    function exec(x) { return x; } exec(userInput);
  `;
  assert.deepEqual(ruleSet(src), []);
});

test("spawn/execFile with array args and no shell are not flagged; shell:true is", () => {
  const base = `import { spawn, execFile, spawnSync } from "node:child_process";\n`;
  assert.ok(!has(`${base}spawn("ls", ["-la", dir]);`, "command-injection"));
  assert.ok(!has(`${base}execFile("git", ["status"], { cwd });`, "command-injection"));
  assert.ok(!has(`${base}spawn("ls", [dir], { shell: false });`, "command-injection"));
  const shell = find(`${base}spawn("ls " + dir, { shell: true });`).find(
    (f) => f.rule === "command-injection",
  );
  assert.equal(shell.severity, "high");
  const staticShell = find(`${base}spawnSync("ls -la", { shell: true });`).find(
    (f) => f.rule === "command-injection",
  );
  assert.equal(staticShell.severity, "medium");
});

// --- taint ------------------------------------------------------------------

test("taint from process.argv reaches exec through variables and templates", () => {
  const f = find(`
    import { exec } from "child_process";
    const [, , target] = process.argv;
    const cmd = \`ping -c 1 \${target}\`;
    exec(cmd);
  `).find((x) => x.rule === "command-injection");
  assert.equal(f.confidence, "high");
  assert.deepEqual(f.taint, { source: "process.argv", sink: "command-injection" });
  assert.match(f.why, /process\.argv/);
});

test("taint from req.query/params/body inside a handler", () => {
  const src = `
    const fs = require("fs"); const path = require("path");
    app.get("/f", (req, res) => {
      const { file } = req.query;
      fs.readFile(path.join(__dirname, file), cb);
      el.innerHTML = req.body.html;
      db.query(\`SELECT * FROM t WHERE id = \${req.params.id}\`);
      fetch(req.query.url);
    });
  `;
  const by = Object.fromEntries(find(src).map((f) => [f.rule, f]));
  assert.equal(by["path-traversal"].taint.source, "req.query");
  assert.equal(by["dom-xss"].severity, "high");
  assert.equal(by["sql-injection"].taint.source, "req.params");
  assert.equal(by.ssrf.taint.source, "req.query");
  assert.equal(by["path-traversal"].function, "GET /f handler");
});

test("path.basename sanitizes; untainted fs paths are not flagged", () => {
  const src = `
    const fs = require("fs"); const path = require("path");
    const name = path.basename(process.argv[2]);
    fs.readFileSync(path.join("/data", name));
    fs.readFileSync(configPath);
  `;
  assert.ok(!has(src, "path-traversal"));
});

test("reassignment with a clean value clears taint", () => {
  const src = `import { exec } from "child_process"; let c = process.argv[2]; c = "ls"; exec(c);`;
  const f = find(src).find((x) => x.rule === "command-injection");
  assert.equal(f.taint, undefined); // still non-literal, but no proven flow
  assert.equal(f.confidence, "medium");
});

// --- eval / require / DOM ---------------------------------------------------

test("eval / new Function / vm with non-literal input", () => {
  assert.ok(has(`eval(expr);`, "dynamic-eval"));
  assert.ok(has(`new Function("a", body);`, "dynamic-eval"));
  assert.ok(has(`const vm = require("vm"); vm.runInNewContext(code);`, "dynamic-eval"));
  assert.ok(!has(`eval("1 + 1");`, "dynamic-eval"));
  assert.ok(!has(`new Function("return 1");`, "dynamic-eval"));
  assert.ok(!has(`obj.eval(x);`, "dynamic-eval"));
});

test("dynamic require / import with a computed path", () => {
  assert.ok(has(`require(name);`, "dynamic-require"));
  assert.ok(has("import(`./plugins/${p}.js`);", "dynamic-require"));
  assert.ok(!has(`require("fs"); import("./x.js");`, "dynamic-require"));
});

test("innerHTML / document.write with non-literal values", () => {
  assert.ok(has(`el.innerHTML = msg;`, "dom-xss"));
  assert.ok(has(`document.write(location.hash);`, "dom-xss"));
  assert.ok(!has(`el.innerHTML = "<b>static</b>";`, "dom-xss"));
  assert.ok(!has(`el.textContent = msg;`, "dom-xss"));
  assert.equal(find(`el.innerHTML = location.search;`)[0].severity, "high");
});

// --- crypto, secrets, randomness ---------------------------------------------

test("weak hashes via crypto.createHash", () => {
  assert.ok(has(`import crypto from "crypto"; crypto.createHash("md5");`, "weak-hash"));
  assert.ok(has(`const { createHash } = require("crypto"); createHash("sha1");`, "weak-hash"));
  assert.ok(!has(`crypto.createHash("sha256");`, "weak-hash"));
});

test("hardcoded secrets: known formats anywhere, plausible values by name, redacted evidence", () => {
  const known = find(`connect({ k: "AKIAABCDEFGHIJKLMNOP" });\ncall("ghp_${"a".repeat(36)}");`);
  assert.equal(known.filter((f) => f.rule === "hardcoded-secret").length, 2);
  const named = find(`const dbPassword = "hunter2hunter2";`)[0];
  assert.equal(named.confidence, "medium");
  assert.ok(!named.evidence.includes("hunter2hunter2"), "secret must be redacted in evidence");
  assert.match(named.evidence, /redacted/);
});

test("secret-ish names with non-secret values are not flagged", () => {
  const src = `
    const passwordField = "password_input_box";
    const API_KEY = process.env.API_KEY;
    const token = "";
    const secretName = "prod/db";
    const apiKey = "YOUR_API_KEY_HERE";
    const tokenUrl = "https://example.com/oauth/token";
    const password = "changeme";
  `;
  assert.deepEqual(ruleSet(src), []);
});

test("Math.random only flagged where the value is security-relevant", () => {
  assert.ok(has(`function makeToken() { return Math.random().toString(36); }`, "insecure-random"));
  assert.ok(has(`const sessionId = Math.random();`, "insecure-random"));
  assert.ok(!has(`function jitter() { return Math.random() * 100; }`, "insecure-random"));
});

// --- facts for UNDERSTAND ----------------------------------------------------

test("collects imports, exports and per-function capabilities", () => {
  const a = analyzeJs(
    `
    import fs from "node:fs";
    const { exec } = require("child_process");
    export function save(p, d) { fs.writeFileSync(p, d); }
    function run(c) { exec(c); }
    export default run;
    module.exports.helper = () => process.env.HOME;
  `,
    "m.js",
  );
  assert.deepEqual(
    a.imports.map((i) => [i.module, i.kind]),
    [
      ["node:fs", "import"],
      ["child_process", "require"],
    ],
  );
  assert.deepEqual(a.exports, ["helper", "run", "save"]);
  const save = a.functions.find((f) => f.name === "save");
  assert.equal(save.exported, true);
  assert.deepEqual(save.capabilities, { "writes to the filesystem": ["fs.writeFileSync"] });
  assert.deepEqual(a.functions.find((f) => f.name === "run").capabilities, {
    "runs shell commands / processes": ["child_process.exec"],
  });
  assert.deepEqual(a.functions.find((f) => f.name === "helper").capabilities, {
    "reads environment variables": ["process.env"],
  });
});

test("CommonJS scripts and JSX parse; TypeScript falls back to regex checks", () => {
  assert.ok(analyzeJs(`with (o) { x = 1 }`, "s.js").parsed); // sloppy-mode script
  assert.ok(analyzeJs(`const App = () => <div className="x">{name}</div>;`, "a.jsx").parsed);
  const ts = analyzeJs(`const key: string = "AKIAABCDEFGHIJKLMNOP"; createHash("md5")`, "a.ts");
  assert.equal(ts.parsed, false);
  assert.deepEqual(
    ts.findings.map((f) => [f.rule, f.engine]),
    [
      ["hardcoded-secret", "trinetra-regex"],
      ["weak-hash", "trinetra-regex"],
    ],
  );
});

test("isStaticString", () => {
  const expr = (s) => parseJs(`(${s})`).body[0].expression;
  assert.equal(isStaticString(expr(`"a"`)), true);
  assert.equal(isStaticString(expr("`a`")), true);
  assert.equal(isStaticString(expr(`"a" + "b"`)), true);
  assert.equal(isStaticString(expr("`a${b}`")), false);
  assert.equal(isStaticString(expr(`"a" + b`)), false);
  assert.equal(isStaticString(expr(`42`)), false);
});
