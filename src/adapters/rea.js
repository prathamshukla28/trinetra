// Adapter for the REA reverse-engineering engine (`rea-agents`, morluto/rea).
//
// Trinetra delegates two jobs to REA and talks to it only through this file:
//   - `analyze-javascript-application` — semantic graph of a JS/Electron app
//   - `decompile-all` — Ghidra decompilation of every function in a binary
// Process execution and output parsing are separate so the parsers can be
// tested against recorded REA output.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { commandFor, which } from "../util/exec.js";

const require = createRequire(import.meta.url);

/**
 * Locate the REA CLI. Order: $TRINETRA_REA_BIN → the `rea-agents` package this
 * module resolves (works for source checkouts *and* global/npx installs, where
 * dependencies may be hoisted) → `rea` on PATH. Returns null if none is found.
 */
export function resolveReaBin({ env = process.env } = {}) {
  if (env.TRINETRA_REA_BIN) return fs.existsSync(env.TRINETRA_REA_BIN) ? env.TRINETRA_REA_BIN : null;
  try {
    const pkgFile = require.resolve("rea-agents/package.json");
    const pkg = JSON.parse(fs.readFileSync(pkgFile, "utf8"));
    const rel = typeof pkg.bin === "string" ? pkg.bin : (pkg.bin?.rea ?? pkg.bin?.["rea-agents"]);
    if (rel) {
      const bin = path.join(path.dirname(pkgFile), rel);
      if (fs.existsSync(bin)) return bin;
    }
  } catch {
    /* not installed alongside Trinetra */
  }
  return which("rea", { env });
}

export const isReaAvailable = (opts) => resolveReaBin(opts) !== null;

export const REA_MISSING =
  "REA (rea-agents) was not found. Install it with `npm install -g rea-agents`, " +
  "or point TRINETRA_REA_BIN at the `rea` executable.";

// Environment for REA. The user's own environment always wins; config-file
// values only fill gaps (see context.js for the precedence rules).
export function reaEnv(config = {}, env = process.env) {
  const out = { ...env };
  if (!out.GHIDRA_INSTALL_DIR && config.ghidraInstallDir) out.GHIDRA_INSTALL_DIR = config.ghidraInstallDir;
  if (config.javaBinDir) out.PATH = `${config.javaBinDir}${path.delimiter}${out.PATH ?? ""}`;
  return out;
}

// REA streams `rea_progress` records; the last other record is the result (or
// a structured error).
export function parseReaStdout(stdout) {
  const records = String(stdout)
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean)
    .filter((l) => !l.includes('"rea_progress"'));
  if (records.length === 0) throw new Error("REA produced no result record");
  const rec = JSON.parse(records.at(-1));
  if (rec.code && rec.category) throw new Error(`REA ${rec.code}: ${rec.message}`);
  return rec;
}

function runReaCommand(args, ctx) {
  const bin = resolveReaBin({ env: ctx.env });
  if (!bin) throw new Error(REA_MISSING);
  const { command, args: pre } = commandFor(bin);
  let out;
  try {
    out = execFileSync(command, [...pre, ...args, "--format", "json"], {
      cwd: ctx.cwd,
      env: reaEnv(ctx.config, ctx.env),
      maxBuffer: 256 * 1024 * 1024,
      timeout: Number(ctx.env.TRINETRA_REA_TIMEOUT_MS) || 30 * 60 * 1000,
      stdio: ["ignore", "pipe", "pipe"],
    }).toString();
  } catch (err) {
    // REA reports structured errors on stdout even when it exits non-zero.
    out = err.stdout?.toString() ?? "";
    if (!out.trim()) {
      const detail = err.stderr?.toString().trim().split("\n").pop() || err.message;
      throw new Error(`REA failed: ${detail}`);
    }
  }
  return parseReaStdout(out);
}

// Turn a decompile-all output directory into Trinetra's inspection fields.
export function parseDecompileDir(outDir, target) {
  const index = JSON.parse(fs.readFileSync(path.join(outDir, "decompile-index.json"), "utf8"));
  const fns = index.functions ?? [];
  const local = fns.filter((f) => f.status === "written" && f.relative_path);
  const units = local.map((f) => ({ name: f.name, file: target, line: 0, source: f.address }));

  // Pick a representative function (prefer the entry point) to show in the report.
  const sample = local.find((f) => f.name === "entry") || local[0];
  let samplePseudo = "";
  if (sample) {
    try {
      samplePseudo = fs.readFileSync(path.join(outDir, sample.relative_path), "utf8");
    } catch {
      /* the index can outlive a partially-written run */
    }
  }

  return {
    units,
    provenance: { sha256: index.target_sha256, provider: index.provider?.name },
    statistics: { procedures: local.length, external: fns.length - local.length },
    overview: samplePseudo,
    sampleName: sample?.name,
    decompDir: outDir,
    // name → per-function pseudocode hash, for detecting changed functions.
    fnHashes: Object.fromEntries(local.map((f) => [f.name, f.sha256])),
  };
}

// Decompile a native binary via REA + Ghidra into <out>/.work/rea-decomp/<name>.
export async function reaInspectNative(target, ctx, name = path.basename(target)) {
  const parent = path.join(ctx.workDir, "rea-decomp");
  const outDir = path.join(parent, name);
  // decompile-all refuses a pre-existing output dir, so clear any stale run.
  fs.mkdirSync(parent, { recursive: true });
  fs.rmSync(outDir, { recursive: true, force: true });
  runReaCommand(["decompile-all", path.resolve(target), "--output", outDir], ctx);
  return parseDecompileDir(outDir, target);
}

// Map REA's JavaScript-application record onto Trinetra's unit shape.
export function parseReaJsRecord(rec) {
  const nr = rec.normalized_result ?? {};
  const nodes = nr.semantic_graph?.nodes ?? [];
  const units = nodes
    .filter((n) => n.kind === "function")
    .map((n) => ({
      name: n.label || n.identity?.role_key || "(anonymous)",
      file: n.identity?.module_path ?? nr.input_path,
      line: n.identity?.source_range?.start?.line ?? 0,
      source: n.label ?? "",
    }));

  return {
    units,
    provenance: {
      sha256: rec.subject?.digest?.sha256 ?? nr.root_artifact_sha256,
      provider: rec.provider?.name,
      evidenceId: rec.evidence_id,
    },
    statistics: nr.statistics ?? {},
    reaFindings: nr.statistics?.findings ?? 0,
  };
}

export async function reaInspectJs(target, ctx) {
  const rec = runReaCommand(
    ["analyze-javascript-application", path.resolve(target), "--detail", "complete"],
    ctx,
  );
  return parseReaJsRecord(rec);
}
