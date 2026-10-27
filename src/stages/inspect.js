// Stage 1 — INSPECT.  Take the target apart into "units" we can reason about.
//
// If REA is installed we hand off to it (binaries, native apps, runtime
// behavior). Otherwise we use a built-in source inspector so the pipeline is
// useful on source-code targets today.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { isReaAvailable, reaInspectJs, reaInspectNative } from "../adapters/rea.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

// Ghidra can't import a universal (fat) Mach-O — it needs one architecture.
// If the target is fat, thin it to the host-preferred slice automatically.
function maybeThinFatMacho(target) {
  let archs;
  try {
    archs = execFileSync("lipo", ["-archs", target], { stdio: ["ignore", "pipe", "ignore"] })
      .toString()
      .trim()
      .split(/\s+/);
  } catch {
    return { path: target, thinned: false }; // not fat, or lipo unavailable
  }
  if (archs.length <= 1) return { path: target, thinned: false };

  const arch = ["arm64e", "arm64", "x86_64"].find((a) => archs.includes(a)) || archs[0];
  const dir = path.join(ROOT, "reports", ".thin");
  fs.mkdirSync(dir, { recursive: true });
  const out = path.join(dir, `${path.basename(target)}-${arch}`);
  execFileSync("lipo", ["-thin", arch, target, "-output", out]);
  return { path: out, thinned: true, arch };
}

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"]);
const NATIVE_EXT = new Set([".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".elf", ".apk", ".app"]);

// A single file with no (or a native) extension is treated as a binary target.
function isNativeTarget(target) {
  const stat = fs.statSync(target);
  if (stat.isDirectory()) return false;
  const ext = path.extname(target);
  return NATIVE_EXT.has(ext) || (ext === "" && !stat.isDirectory());
}

function collectSourceFiles(target) {
  const stat = fs.statSync(target);
  if (stat.isFile()) return [target];
  const out = [];
  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name.startsWith(".")) continue;
    const full = path.join(target, entry.name);
    if (entry.isDirectory()) out.push(...collectSourceFiles(full));
    else if (SOURCE_EXT.has(path.extname(entry.name))) out.push(full);
  }
  return out;
}

// Pull named functions / methods out of a source file. Deliberately simple —
// enough to show structure, not a full parser.
function extractUnits(file) {
  const src = fs.readFileSync(file, "utf8");
  const lines = src.split("\n");
  const re =
    /(?:function\s+([A-Za-z0-9_$]+)|(?:const|let|var)\s+([A-Za-z0-9_$]+)\s*=\s*(?:async\s*)?\(|([A-Za-z0-9_$]+)\s*\([^)]*\)\s*\{)/;
  const units = [];
  lines.forEach((line, i) => {
    const m = line.match(re);
    const name = m && (m[1] || m[2] || m[3]);
    if (name && name !== "if" && name !== "for" && name !== "while" && name !== "switch") {
      units.push({ name, file, line: i + 1, source: line.trim() });
    }
  });
  return units;
}

export async function inspect(target) {
  // Native binary path — no source to scan; REA (+ an engine) is required.
  if (isNativeTarget(target)) {
    if (!isReaAvailable()) {
      throw new Error("Native targets need REA installed (`npm install rea-agents`).");
    }
    const thin = maybeThinFatMacho(target);
    if (thin.thinned) console.log(`      (fat binary — thinned to ${thin.arch} slice for Ghidra)`);
    const rea = await reaInspectNative(thin.path);
    return {
      engine: "rea-native",
      files: [target],
      units: rea.units,
      raw: [], // audit's source rules don't apply to binaries
      provenance: rea.provenance,
      statistics: rea.statistics,
      overview: rea.overview,
      sampleName: rea.sampleName,
      decompDir: rea.decompDir,
    };
  }

  // We always read raw source (the AUDIT stage scans it). REA, when present,
  // replaces our crude unit extraction with its real semantic graph.
  const files = collectSourceFiles(target);
  const raw = files.map((f) => ({ file: f, text: fs.readFileSync(f, "utf8") }));

  // REA's JS *application* analyzer is built for packaged apps (ASAR/extracted
  // bundles), not raw dev repos. On a big source tree with node_modules it
  // grinds, so we only hand such targets to REA when they look packaged.
  const stat = fs.statSync(target);
  const hasNodeModules = stat.isDirectory() && fs.existsSync(path.join(target, "node_modules"));
  const looksPackaged = files.length <= 50 && !hasNodeModules;

  if (isReaAvailable() && looksPackaged) {
    try {
      const rea = await reaInspectJs(target);
      return {
        engine: "rea-javascript-application",
        files,
        units: rea.units,
        raw,
        provenance: rea.provenance,
        statistics: rea.statistics,
      };
    } catch (err) {
      console.log(`      (REA unavailable for this target: ${err.message}; using built-in inspector)`);
    }
  } else if (isReaAvailable()) {
    console.log(`      (large/unpackaged source tree — using fast inspector; REA is for packaged apps/binaries)`);
  }

  // Built-in source inspector (fast). Security still runs via Semgrep in AUDIT.
  const units = files.flatMap(extractUnits);
  return { engine: "builtin-source-inspector", files, units, raw };
}
