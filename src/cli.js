#!/usr/bin/env node
// Trinetra — command-line entry point.

import fs from "node:fs";
import { parseArgs } from "node:util";
import { createRequire } from "node:module";
import { teardown, compare } from "./pipeline.js";
import { createContext, DEFAULT_OUT_DIR } from "./context.js";

const require = createRequire(import.meta.url);
const { version } = require("../package.json");

const HELP = `Trinetra ${version} — reverse-engineer, audit, and rebuild software.

Usage:
  trinetra teardown <target> [options]   inspect, map, audit and report on a target
  trinetra compare  <targetA> <targetB>  diff two targets (units + findings)

Options:
  -o, --out <dir>       output directory (default: ./${DEFAULT_OUT_DIR}; env TRINETRA_OUT)
      --config <file>   config file (default: ./trinetra.config.json if present)
      --rebuild         generate a test-first reimplementation (writes files only)
      --run-generated   with --rebuild: execute the generated tests in a sandbox
      --no-rea          don't use REA (Trinetra's own analysis only)
      --no-decompile    skip Ghidra decompilation of native binaries
      --no-semgrep      don't run Semgrep even if installed
      --fail-on <sev>   exit 2 if any finding is at least high|medium|low
  -h, --help            show this help
  -v, --version         print the version

Targets: a source directory or file, a packaged .asar app, a native binary
(ELF / Mach-O / universal / PE, detected by content), or a macOS .app bundle.`;

const OPTIONS = {
  out: { type: "string", short: "o" },
  config: { type: "string" },
  rebuild: { type: "boolean" },
  "run-generated": { type: "boolean" },
  "no-rea": { type: "boolean" },
  "no-decompile": { type: "boolean" },
  "no-semgrep": { type: "boolean" },
  "fail-on": { type: "string" },
  help: { type: "boolean", short: "h" },
  version: { type: "boolean", short: "v" },
};

const SEV_RANK = { high: 0, medium: 1, low: 2 };

class UsageError extends Error {}

function fail(message, code = 1) {
  console.error(`✖ ${message}`);
  process.exit(code);
}

async function main(argv) {
  let parsed;
  try {
    parsed = parseArgs({ args: argv, options: OPTIONS, allowPositionals: true, strict: true });
  } catch (err) {
    throw new UsageError(err.message);
  }
  const { values: v, positionals } = parsed;
  if (v.version) return console.log(version);
  const [command, ...rest] = positionals;
  if (v.help || !command) {
    console.log(HELP);
    return process.exit(command || v.help ? 0 : 1);
  }

  if (v["run-generated"] && !v.rebuild)
    throw new UsageError("--run-generated only makes sense with --rebuild");
  if (v["fail-on"] && !(v["fail-on"] in SEV_RANK))
    throw new UsageError("--fail-on must be high, medium, or low");

  const ctx = createContext({ out: v.out, configFile: v.config });
  const common = {
    ctx,
    useRea: !v["no-rea"],
    decompile: !v["no-decompile"],
    useSemgrep: !v["no-semgrep"],
  };
  const requireTarget = (t) => {
    if (!t) throw new UsageError(`missing target\n\n${HELP}`);
    if (!fs.existsSync(t)) throw new Error(`Target not found: ${t}`);
  };

  let findings = [];
  if (command === "teardown") {
    if (rest.length !== 1) throw new UsageError(`teardown takes exactly one target\n\n${HELP}`);
    requireTarget(rest[0]);
    ({ findings } = await teardown(rest[0], {
      ...common,
      rebuild: Boolean(v.rebuild),
      runGenerated: Boolean(v["run-generated"]),
    }));
  } else if (command === "compare") {
    if (rest.length !== 2) throw new UsageError(`compare takes exactly two targets\n\n${HELP}`);
    rest.forEach(requireTarget);
    await compare(rest[0], rest[1], common);
  } else {
    throw new UsageError(`unknown command "${command}"\n\n${HELP}`);
  }

  if (v["fail-on"]) {
    const limit = SEV_RANK[v["fail-on"]];
    const hits = findings.filter((f) => SEV_RANK[f.severity] <= limit).length;
    if (hits) fail(`${hits} finding(s) at or above ${v["fail-on"]} severity`, 2);
  }
}

main(process.argv.slice(2)).catch((err) => {
  if (err instanceof UsageError) fail(err.message, 1);
  fail(`Trinetra failed: ${err.message}`, 1);
});
