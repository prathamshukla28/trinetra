// Helpers for spawning the real CLI in tests.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
export const CLI = path.join(ROOT, "src", "cli.js");
export const FIXTURES = path.join(ROOT, "test", "fixtures");
export const FAKE_REA = path.join(FIXTURES, "bin", "fake-rea.mjs");
export const FAKE_SEMGREP = path.join(FIXTURES, "bin", "fake-semgrep.mjs");

export function tempDir(prefix = "trinetra-test-") {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
}

// Environment without the developer's engines or credentials, so tests are
// hermetic: REA/Semgrep point at nothing unless a test opts into the fakes.
export function hermeticEnv(extra = {}) {
  const env = { ...process.env };
  for (const k of Object.keys(env)) {
    if (/^(ANTHROPIC_|TRINETRA_|GHIDRA_|JAVA_HOME)/.test(k)) delete env[k];
  }
  env.TRINETRA_REA_BIN = path.join(os.tmpdir(), "trinetra-no-rea-here");
  env.TRINETRA_SEMGREP_BIN = path.join(os.tmpdir(), "trinetra-no-semgrep-here");
  env.NO_COLOR = "1";
  return { ...env, ...extra };
}

export function runCli(args, { cwd, env = hermeticEnv() } = {}) {
  const res = spawnSync(process.execPath, [CLI, ...args], { cwd, env, encoding: "utf8", timeout: 60_000 });
  return { code: res.status, stdout: res.stdout, stderr: res.stderr };
}

export function copyFixture(rel, dest) {
  fs.cpSync(path.join(FIXTURES, rel), dest, { recursive: true });
  return dest;
}
