import test from "node:test";
import assert from "node:assert/strict";
import { analyzeJs, isStaticString, looksLikeSecretValue, parseJs } from "../src/analysis/js-ast.js";

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

// --- regressions found by the accuracy benchmark (bench/) ---------------------

test("a concatenated string literal no longer crashes the analyzer", () => {
  // Was: TypeError in checkSecret (staticValue returned null for "a" + "b"),
  // which aborted analysis of the whole file (NodeGoat session.js, ws, minimatch).
  const r = analyzeJs(`const password = "Tr0ub4dor" + "&3xyz-prod";`, "t.js");
  assert.equal(r.parsed, true);
  const f = r.findings.find((x) => x.rule === "hardcoded-secret");
  assert.ok(f, "concatenated secret is still reported");
  assert.doesNotMatch(f.evidence, /Tr0ub4dor|3xyz-prod/, "evidence stays redacted");
});

test("PEM: a bare header is a format marker, a header with key material is a secret", () => {
  const header = ["-----BEGIN", "PRIVATE KEY-----"].join(" ");
  assert.equal(looksLikeSecretValue(header), false);
  assert.equal(looksLikeSecretValue(`${header}\n${"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC".repeat(2)}`), true);
  assert.ok(!has(`if (pem.indexOf("${header}") !== 0) throw new Error("bad");`, "hardcoded-secret"));
});

test("token patterns need a boundary: AKIA… inside a base64 blob is not a key", () => {
  const key = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
  assert.equal(looksLikeSecretValue(key), true);
  assert.equal(looksLikeSecretValue(`data:application/wasm;base64,AGFzbQEAhAB${key}QQYQJ`), false);
});

test("constants: const-bound literals, __dirname paths and require.resolve are not dynamic", () => {
  const cp = `const { exec } = require("child_process");`;
  assert.ok(!has(`${cp} const cmd = "uptime"; exec(cmd);`, "command-injection"));
  assert.ok(!has(`const expr = "6 * " + 7; eval(expr);`, "dynamic-eval"));
  assert.ok(
    !has(`const path = require("path"); require(path.join(__dirname, "config.json"));`, "dynamic-require"),
  );
  assert.ok(!has(`require(require.resolve("./package.json"));`, "dynamic-require"));
  assert.ok(!has(`require(__dirname + "/../config/env/all.js");`, "dynamic-require"));
});

test("constants: let/var, parameters and inner redeclarations still count as dynamic", () => {
  const cp = `const { exec } = require("child_process");`;
  assert.ok(has(`${cp} let cmd = "uptime"; exec(cmd);`, "command-injection"));
  assert.ok(has(`${cp} const cmd = "uptime"; function f(cmd) { exec(cmd); }`, "command-injection"));
  assert.ok(
    has(`${cp} const cmd = "uptime"; function f(x) { let cmd = x; exec(cmd); }`, "command-injection"),
  );
  assert.ok(has(`const name = process.argv[2]; require("./plugins/" + name);`, "dynamic-require"));
});

test("weak-hash resolves an algorithm held in a const", () => {
  assert.ok(has(`const crypto = require("crypto"); const ALG = "md5"; crypto.createHash(ALG);`, "weak-hash"));
  assert.ok(
    !has(`const crypto = require("crypto"); const ALG = "sha256"; crypto.createHash(ALG);`, "weak-hash"),
  );
});

test("sql-injection follows a query string built in a variable, but not parameterized forms", () => {
  assert.ok(
    has(
      `function h(req, db) { const sql = "SELECT * FROM t WHERE id = " + req.query.id; return db.query(sql); }`,
      "sql-injection",
    ),
  );
  assert.ok(
    has(
      `function h(req, db) { let sql = "SELECT * FROM t WHERE a = 1"; sql += " AND b = " + req.body.b; return db.query(sql); }`,
      "sql-injection",
    ),
  );
  assert.ok(
    !has(
      `function h(req, db) { const sql = "SELECT * FROM t WHERE id = $1"; return db.query(sql, [req.query.id]); }`,
      "sql-injection",
    ),
  );
  assert.ok(
    !has(
      `function h(req, db) { return db.query({ text: "SELECT $1", values: [req.query.id] }); }`,
      "sql-injection",
    ),
  );
});

test("DOM sinks: an explicit sanitizer call is not XSS; raw values still are", () => {
  assert.ok(!has(`el.innerHTML = DOMPurify.sanitize(location.hash);`, "dom-xss"));
  assert.ok(!has(`el.innerHTML = escapeHtml(s);`, "dom-xss"));
  assert.ok(!has(`document.write(escapeHtml(location.search));`, "dom-xss"));
  assert.ok(has(`el.innerHTML = location.hash;`, "dom-xss"));
  assert.ok(has(`el.innerHTML = render(s);`, "dom-xss"));
});
