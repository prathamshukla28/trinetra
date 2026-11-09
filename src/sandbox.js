// Sandbox for executing AI-generated code (REBUILD's test run).
//
// Generated code is derived from an untrusted target and may carry
// prompt-injected payloads, so it never runs in Trinetra's own process or
// environment. Layers, all applied together:
//   1. a fresh temp directory (realpath'd) as cwd, HOME and TMPDIR;
//   2. an environment built from scratch — no API keys, tokens, or inherited
//      variables (NODE_OPTIONS included), just a minimal PATH;
//   3. Node's permission model: filesystem read/write limited to that directory,
//      and no child processes, worker threads, addons, or WASI (none granted);
//   4. a hard timeout (SIGKILL);
//   5. network denial where the OS offers it unprivileged — sandbox-exec on
//      macOS, `unshare -rn` on Linux. Node 22's permission model does not cover
//      network access, so where neither is available the run is reported as
//      "network: not restricted".
// Before any of that, generated code is statically reviewed and refused if it
// reaches for process/network/env APIs at all.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { analyzeJs } from "./analysis/js-ast.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const MACOS_NO_NET = "(version 1)(allow default)(deny network*)";

// Which flag enables the permission model on this Node (renamed in 22.13+).
export function permissionFlag(flags = process.allowedNodeEnvironmentFlags) {
  return flags.has("--permission") ? "--permission" : "--experimental-permission";
}

// An environment containing nothing inherited from the caller.
export function buildSandboxEnv(dir) {
  const env = {
    PATH: process.platform === "win32" ? "C:\\Windows\\System32" : "/usr/bin:/bin",
    HOME: dir,
    USERPROFILE: dir,
    TMPDIR: dir,
    TMP: dir,
    TEMP: dir,
    LANG: "C.UTF-8",
    NODE_ENV: "test",
    NO_COLOR: "1",
  };
  if (process.platform === "win32" && process.env.SystemRoot) env.SystemRoot = process.env.SystemRoot;
  return env;
}

// Node arguments for a sandboxed run of `entry` inside `dir`. Only fs read and
// write are granted, both scoped to `dir`; nothing else is allowed.
export function buildNodeArgs(dir, entry) {
  return [permissionFlag(), `--allow-fs-read=${dir}`, `--allow-fs-write=${dir}`, entry];
}

let networkIsolation;
// Detect (once) an unprivileged way to deny network access.
export function detectNetworkIsolation() {
  if (networkIsolation !== undefined) return networkIsolation;
  networkIsolation = null;
  const probe = (cmd, args) => {
    try {
      return spawnSync(cmd, args, { stdio: "ignore", timeout: 5000 }).status === 0;
    } catch {
      return false;
    }
  };
  if (process.platform === "darwin" && fs.existsSync("/usr/bin/sandbox-exec")) {
    if (probe("/usr/bin/sandbox-exec", ["-p", MACOS_NO_NET, "/usr/bin/true"]))
      networkIsolation = {
        name: "sandbox-exec",
        wrap: (c, a) => ["/usr/bin/sandbox-exec", ["-p", MACOS_NO_NET, c, ...a]],
      };
  } else if (process.platform === "linux") {
    if (probe("unshare", ["-rn", "true"]))
      networkIsolation = { name: "unshare -rn", wrap: (c, a) => ["unshare", ["-rn", c, ...a]] };
  }
  return networkIsolation;
}

// Static review: generated code that touches these is refused before it runs.
const FORBIDDEN_MODULES =
  /^(node:)?(child_process|net|dgram|tls|http|https|http2|worker_threads|cluster|vm|inspector|module|dns)$/;

export function reviewGeneratedCode(code, file = "generated.js") {
  const a = analyzeJs(code, file);
  if (!a.parsed) return [`could not be parsed (${a.error})`];
  const reasons = new Set();
  for (const i of a.imports) if (FORBIDDEN_MODULES.test(i.module)) reasons.add(`imports ${i.module}`);
  for (const fn of [a.topLevel, ...a.functions]) {
    for (const cap of Object.keys(fn.capabilities)) {
      if (/environment|network|shell|dynamic code|workers|sockets/.test(cap)) reasons.add(cap);
    }
  }
  for (const f of a.findings)
    if (["dynamic-eval", "dynamic-require", "command-injection"].includes(f.rule)) reasons.add(f.title);
  return [...reasons];
}

// Create an isolated directory containing the given files ({ name: source }).
export function prepareSandbox(files) {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "trinetra-sbx-")));
  for (const [name, content] of Object.entries(files)) {
    const safe = path.basename(name);
    fs.writeFileSync(path.join(dir, safe), content);
  }
  return dir;
}

/**
 * Run `entry` (a test file inside `dir`) under the sandbox.
 * @returns {{passed:boolean, timedOut:boolean, output:string, isolation:object}}
 */
export function runSandboxed(dir, entry, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const target = path.join(dir, path.basename(entry));
  let command = process.execPath;
  let args = buildNodeArgs(dir, target);
  const net = detectNetworkIsolation();
  if (net) [command, args] = net.wrap(command, args);

  const res = spawnSync(command, args, {
    cwd: dir,
    env: buildSandboxEnv(dir),
    timeout: timeoutMs,
    killSignal: "SIGKILL",
    maxBuffer: 8 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const timedOut = res.error?.code === "ETIMEDOUT" || res.signal === "SIGKILL";
  return {
    passed: res.status === 0 && !timedOut,
    timedOut,
    output: `${res.stdout?.toString() ?? ""}${res.stderr?.toString() ?? ""}${timedOut ? "\n[killed: timeout]" : ""}`,
    isolation: {
      permissionModel: true,
      fs: dir,
      env: "stripped",
      network: net ? `blocked (${net.name})` : "not restricted",
      timeoutMs,
    },
  };
}

// Convenience: copy files into a fresh sandbox, run, clean up.
export function runInSandbox(files, entry, opts) {
  const dir = prepareSandbox(files);
  try {
    return runSandboxed(dir, entry, opts);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
