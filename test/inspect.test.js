import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { inspect, findBundleExecutable, isAppBundle, thinFatBinary } from "../src/stages/inspect.js";
import { detectFormat } from "../src/binary/magic.js";
import { parseMachO } from "../src/binary/macho.js";
import { FileSource } from "../src/binary/source.js";
import { createContext } from "../src/context.js";
import { buildElf, buildFat, buildMachO } from "./helpers/binaries.js";
import { tempDir } from "./helpers/cli.js";

const NO_ENGINES = { TRINETRA_REA_BIN: "/nonexistent/rea", TRINETRA_SEMGREP_BIN: "/nonexistent/semgrep" };
const ctxIn = (cwd) => createContext({ cwd, env: NO_ENGINES });

test("extensionless text files (Makefile, shell scripts) are not treated as binaries", async () => {
  const dir = tempDir();
  fs.writeFileSync(path.join(dir, "Makefile"), "all:\n\tcc -o app main.c\n");
  fs.writeFileSync(path.join(dir, "deploy"), '#!/bin/sh\nexport API_TOKEN="ghp_' + "a".repeat(36) + '"\n');
  assert.equal(detectFormat(path.join(dir, "Makefile")), null);
  const insp = await inspect(path.join(dir, "deploy"), ctxIn(dir));
  assert.equal(insp.kind, "source");
  assert.equal(insp.js[0].parsed, false);
  assert.equal(insp.js[0].findings[0].rule, "hardcoded-secret", "text files still get credential checks");
});

test("a binary is detected by content even with a misleading extension", async () => {
  const dir = tempDir();
  const file = path.join(dir, "notes.txt");
  fs.writeFileSync(file, buildElf({ imports: ["gets"] }));
  const insp = await inspect(file, ctxIn(dir));
  assert.equal(insp.kind, "native");
  assert.equal(insp.engine, "trinetra-binary");
  assert.equal(insp.binary.format, "elf");
  assert.deepEqual(
    insp.units.map((u) => u.name),
    ["gets"],
  );
  assert.match(insp.notes.join(" "), /REA \(rea-agents\) was not found/);
  assert.match(insp.provenance.sha256, /^[0-9a-f]{64}$/);
});

test("--no-decompile and --no-rea are honoured for natives", async () => {
  const dir = tempDir();
  const file = path.join(dir, "app");
  fs.writeFileSync(file, buildMachO());
  assert.match((await inspect(file, ctxIn(dir), { decompile: false })).notes[0], /--no-decompile/);
  assert.match((await inspect(file, ctxIn(dir), { useRea: false })).notes[0], /--no-rea/);
});

function makeBundle(dir, { plistExe = "MyApp", fileName = "MyApp" } = {}) {
  const app = path.join(dir, "MyApp.app");
  fs.mkdirSync(path.join(app, "Contents", "MacOS"), { recursive: true });
  fs.writeFileSync(
    path.join(app, "Contents", "Info.plist"),
    `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>${plistExe}</string></dict></plist>`,
  );
  fs.writeFileSync(path.join(app, "Contents", "MacOS", fileName), buildMachO({ imports: ["_system"] }));
  fs.writeFileSync(path.join(app, "Contents", "MacOS", "helper.sh"), "#!/bin/sh\n");
  return app;
}

test(".app bundles are directories resolved to their main executable", async () => {
  const dir = tempDir();
  const app = makeBundle(dir);
  assert.ok(isAppBundle(app));
  assert.equal(findBundleExecutable(app), path.join(app, "Contents", "MacOS", "MyApp"));
  const insp = await inspect(app, ctxIn(dir));
  assert.equal(insp.kind, "native");
  assert.equal(insp.root, app);
  assert.ok(insp.binary.findings.some((f) => f.rule === "binary-command-exec-import"));
});

test(".app bundle falls back to the bundle-named executable; errors when none", () => {
  const dir = tempDir();
  const app = makeBundle(dir, { plistExe: "Missing" });
  assert.equal(findBundleExecutable(app), path.join(app, "Contents", "MacOS", "MyApp"));
  const broken = makeBundle(tempDir(), { plistExe: "Nope", fileName: "Other" });
  assert.throws(() => findBundleExecutable(broken), /Could not locate the main executable/);
});

test("fat binaries are thinned in JS to the preferred slice", () => {
  const dir = tempDir();
  const fatFile = path.join(dir, "uni");
  const x86 = buildMachO({ cputype: 0x01000007, imports: ["_x86_only"] });
  const arm = buildMachO({ cputype: 0x0100000c, imports: ["_arm_only"] });
  fs.writeFileSync(
    fatFile,
    buildFat([
      { cputype: 0x01000007, data: x86 },
      { cputype: 0x0100000c, data: arm },
    ]),
  );
  const thin = thinFatBinary(fatFile, path.join(dir, "thin"), ["arm64", "x86_64"]);
  assert.equal(thin.arch, "arm64");
  const src = new FileSource(thin.path);
  try {
    assert.deepEqual(parseMachO(src).imports, ["arm_only"]);
  } finally {
    src.close();
  }
  assert.deepEqual(fs.readFileSync(thin.path), arm);
});

test("source directories are analyzed with the AST engine; node_modules is skipped", async () => {
  const dir = tempDir();
  fs.mkdirSync(path.join(dir, "node_modules", "dep"), { recursive: true });
  fs.writeFileSync(path.join(dir, "node_modules", "dep", "index.js"), "eval(x)");
  fs.writeFileSync(path.join(dir, "a.js"), "export function f(x) { return eval(x); }");
  const insp = await inspect(dir, ctxIn(dir), { useRea: false });
  assert.equal(insp.engine, "trinetra-ast");
  assert.deepEqual(insp.files, [path.join(dir, "a.js")]);
  assert.deepEqual(
    insp.units.map((u) => u.name),
    ["f"],
  );
});

test("missing targets fail clearly", async () => {
  const dir = tempDir();
  await assert.rejects(inspect("nope", ctxIn(dir)), /Target not found: nope/);
});
