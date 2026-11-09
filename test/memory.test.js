import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { Memory, fingerprint } from "../src/memory.js";
import { createContext } from "../src/context.js";
import { tempDir } from "./helpers/cli.js";

const f = (rule, where, evidence, title = rule) => ({ rule, title, severity: "high", where, evidence });

test("first run has nothing to recall; later runs report new / fixed / unchanged", () => {
  const cwd = tempDir();
  const ctx = createContext({ cwd, env: {} });
  const root = path.join(cwd, "app");
  const m1 = new Memory(ctx, root);
  assert.equal(m1.recall(), null);
  assert.equal(m1.diff({ sha256: "a", findings: [] }), null);
  m1.save({
    sha256: "a",
    findings: [f("dynamic-eval", "app/x.js:3", "eval(x)"), f("weak-hash", "app/x.js:9", "md5")],
    at: "T1",
  });

  const m2 = new Memory(ctx, root);
  assert.equal(m2.recall().at, "T1");
  const d = m2.diff({
    sha256: "b",
    findings: [f("dynamic-eval", "app/x.js:30", "eval(x)"), f("command-injection", "app/y.js:1", "exec(c)")],
  });
  assert.equal(d.previousAt, "T1");
  assert.equal(d.contentChanged, true);
  assert.equal(d.unchanged, 1, "a finding that only moved lines is the same finding");
  assert.deepEqual(
    d.new.map((x) => x.rule),
    ["command-injection"],
  );
  assert.deepEqual(
    d.fixed.map((x) => x.rule),
    ["weak-hash"],
  );
});

test("memory is keyed by target path and lives under the output dir", () => {
  const cwd = tempDir();
  const ctx = createContext({ cwd, env: {} });
  const a = new Memory(ctx, path.join(cwd, "a", "app"));
  const b = new Memory(ctx, path.join(cwd, "b", "app"));
  assert.notEqual(a.file, b.file, "same basename, different targets → separate memories");
  a.save({ sha256: "x", findings: [] });
  assert.ok(a.file.startsWith(ctx.memoryDir));
  assert.ok(fs.existsSync(a.file));
  assert.equal(new Memory(ctx, path.join(cwd, "b", "app")).recall(), null);
  assert.equal(JSON.parse(fs.readFileSync(a.file, "utf8")).runs, 1);
});

test("fingerprints ignore line numbers and whitespace but not location or category", () => {
  const base = fingerprint(f("weak-hash", "app/x.js:1", "createHash('md5')"), "app");
  assert.equal(fingerprint(f("weak-hash", "app/x.js:99", "  createHash('md5') "), "app"), base);
  assert.notEqual(fingerprint(f("weak-hash", "app/y.js:1", "createHash('md5')"), "app"), base);
  assert.notEqual(fingerprint(f("dynamic-eval", "app/x.js:1", "createHash('md5')"), "app"), base);
});
