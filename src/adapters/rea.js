// Adapter for the REA reverse-engineering engine (morluto/rea).
//
// Trinetra talks to REA only through this file. When `rea-agents` is installed in
// the project, the INSPECT stage reconstructs the target with REA's semantic
// graph instead of our built-in regex extractor. Everything downstream
// (understand / audit / rebuild) is unchanged.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const REA_BIN = path.join(ROOT, "node_modules", ".bin", "rea");

export function isReaAvailable() {
  return fs.existsSync(REA_BIN);
}

// Load optional config (Ghidra install dir, JDK bin) so native analysis works.
function loadConfig() {
  const file = path.join(ROOT, "trinetra.config.json");
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return {};
  }
}

// Environment for REA: inject the analysis-engine paths when configured.
function reaEnv() {
  const cfg = loadConfig();
  const env = { ...process.env };
  if (cfg.ghidraInstallDir) env.GHIDRA_INSTALL_DIR = cfg.ghidraInstallDir;
  if (cfg.javaBinDir) env.PATH = `${cfg.javaBinDir}:${env.PATH}`;
  return env;
}

// Run a REA command and return the final (non-progress) JSON record.
function runReaCommand(args) {
  const out = execFileSync(REA_BIN, [...args, "--format", "json"], {
    cwd: ROOT,
    env: reaEnv(),
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
  }).toString();
  const records = out.split("\n").filter(Boolean);
  // Drop streaming progress lines; the last record is the result (or an error).
  const last = records.filter((l) => !l.includes('"rea_progress"')).pop();
  const rec = JSON.parse(last);
  if (rec.code && rec.category) {
    throw new Error(`REA ${rec.code}: ${rec.message}`);
  }
  return rec;
}

// Inspect a native program/binary via REA (requires an analysis engine such as
// Ghidra). Returns the same unit shape; raw source is empty for binaries.
export async function reaInspectNative(target) {
  // decompile-all runs Ghidra once and yields BOTH the procedure list and the
  // pseudocode of every function, written to a directory with an index.
  const name = path.basename(target);
  const parent = path.join(ROOT, "reports", ".rea-decomp");
  const outDir = path.join(parent, name);
  // decompile-all creates the output dir itself and refuses a pre-existing one,
  // so we ensure only the parent exists and clear any stale run.
  fs.mkdirSync(parent, { recursive: true });
  fs.rmSync(outDir, { recursive: true, force: true });
  runReaCommand(["decompile-all", target, "--output", outDir]);

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
      /* ignore */
    }
  }

  return {
    units,
    provenance: { sha256: index.target_sha256, provider: index.provider?.name },
    statistics: { procedures: local.length, external: fns.length - local.length },
    overview: samplePseudo,
    sampleName: sample?.name,
    decompDir: path.relative(ROOT, outDir),
    // name → per-function pseudocode hash, for detecting changed functions.
    fnHashes: Object.fromEntries(local.map((f) => [f.name, f.sha256])),
  };
}

// Reconstruct a local JavaScript/Electron application and map REA's semantic
// graph onto Trinetra's unit shape.
export async function reaInspectJs(target) {
  const rec = runReaCommand(["analyze-javascript-application", target, "--detail", "complete"]);
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
