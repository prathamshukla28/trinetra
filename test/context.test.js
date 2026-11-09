import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createContext, resolveConfig, safeName, DEFAULT_OUT_DIR } from "../src/context.js";
import { reaEnv } from "../src/adapters/rea.js";
import { tempDir } from "./helpers/cli.js";

const writeConfig = (dir, obj) =>
  fs.writeFileSync(path.join(dir, "trinetra.config.json"), JSON.stringify(obj));

test("outputs resolve from the caller's cwd, never the package dir", () => {
  const cwd = tempDir();
  const ctx = createContext({ cwd, env: {} });
  assert.equal(ctx.outDir, path.join(cwd, DEFAULT_OUT_DIR));
  assert.equal(ctx.memoryDir, path.join(cwd, DEFAULT_OUT_DIR, ".memory"));
  assert.equal(ctx.rebuiltDir, path.join(cwd, DEFAULT_OUT_DIR, "rebuilt"));
  assert.equal(ctx.rel(path.join(cwd, "a", "b.md")), path.join("a", "b.md"));
  assert.equal(ctx.rel("/elsewhere/x"), "/elsewhere/x");
});

test("--out beats TRINETRA_OUT beats config outDir beats default", () => {
  const cwd = tempDir();
  writeConfig(cwd, { outDir: "from-config" });
  assert.equal(createContext({ cwd, env: {} }).outDir, path.join(cwd, "from-config"));
  assert.equal(createContext({ cwd, env: { TRINETRA_OUT: "from-env" } }).outDir, path.join(cwd, "from-env"));
  assert.equal(
    createContext({ cwd, env: { TRINETRA_OUT: "from-env" }, out: "flag" }).outDir,
    path.join(cwd, "flag"),
  );
});

test("environment variables win over the config file", () => {
  const cwd = tempDir();
  writeConfig(cwd, { ghidraInstallDir: "/cfg/ghidra", javaBinDir: "/cfg/jdk/bin" });
  const fromFile = resolveConfig({ cwd, env: {} });
  assert.equal(fromFile.ghidraInstallDir, "/cfg/ghidra");
  assert.equal(fromFile.javaBinDir, "/cfg/jdk/bin");
  assert.equal(fromFile.source, path.join(cwd, "trinetra.config.json"));

  const fromEnv = resolveConfig({ cwd, env: { GHIDRA_INSTALL_DIR: "/env/ghidra", JAVA_HOME: "/env/jdk" } });
  assert.equal(fromEnv.ghidraInstallDir, "/env/ghidra");
  assert.equal(fromEnv.javaBinDir, path.join("/env/jdk", "bin"));
});

test("relative config paths resolve against the config's directory (cwd)", () => {
  const cwd = tempDir();
  writeConfig(cwd, { ghidraInstallDir: "tools/ghidra" });
  assert.equal(resolveConfig({ cwd, env: {} }).ghidraInstallDir, path.join(cwd, "tools", "ghidra"));
});

test("no config file is fine; a malformed or missing explicit one is an error", () => {
  const cwd = tempDir();
  assert.deepEqual(resolveConfig({ cwd, env: {} }).ghidraInstallDir, null);
  fs.writeFileSync(path.join(cwd, "trinetra.config.json"), "{ nope");
  assert.throws(() => resolveConfig({ cwd, env: {} }), /Invalid JSON/);
  assert.throws(
    () => resolveConfig({ cwd: tempDir(), env: {}, configFile: "missing.json" }),
    /Cannot read config/,
  );
});

test("reaEnv never overrides the user's GHIDRA_INSTALL_DIR", () => {
  const env = reaEnv(
    { ghidraInstallDir: "/cfg/ghidra", javaBinDir: "/jdk/bin" },
    { GHIDRA_INSTALL_DIR: "/mine", PATH: "/usr/bin" },
  );
  assert.equal(env.GHIDRA_INSTALL_DIR, "/mine");
  assert.equal(env.PATH, `/jdk/bin${path.delimiter}/usr/bin`);
  assert.equal(
    reaEnv({ ghidraInstallDir: "/cfg/ghidra" }, { PATH: "/usr/bin" }).GHIDRA_INSTALL_DIR,
    "/cfg/ghidra",
  );
});

test("safeName", () => {
  assert.equal(safeName("my app/v1"), "my_app_v1");
  assert.equal(safeName(".."), "target");
  assert.equal(safeName(""), "target");
  assert.equal(safeName("echo-arm64e"), "echo-arm64e");
});
