// Adapter for the REA reverse-engineering engine (morluto/rea).
//
// REFORGE talks to REA only through this file. When `rea-agents` is installed in
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
  const file = path.join(ROOT, "reforge.config.json");
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
  const rec = runReaCommand(["inspect", target]);
  const nr = rec.normalized_result ?? {};
  // REA's native overview shape varies by provider; pull functions when present.
  const fns = nr.functions ?? nr.symbols ?? nr.graph?.nodes ?? [];
  const units = fns
    .filter((f) => f && (f.name || f.symbol || f.label))
    .map((f) => ({
      name: f.name || f.symbol || f.label,
      file: target,
      line: 0,
      source: f.address ? `@${f.address}` : "",
    }));
  return {
    units,
    provenance: {
      sha256: rec.subject?.digest?.sha256 ?? nr.root_artifact_sha256,
      provider: rec.provider?.name,
      evidenceId: rec.evidence_id,
    },
    statistics: nr.statistics ?? {},
    reaFindings: 0,
  };
}

// Reconstruct a local JavaScript/Electron application and map REA's semantic
// graph onto REFORGE's unit shape.
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
