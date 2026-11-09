// Stage 1 — INSPECT. Take the target apart into "units" plus evidence.
//
// Routing is by content, not file extension:
//   - native executable (ELF / Mach-O / fat / PE, by magic bytes) or a macOS
//     .app bundle (main executable from Contents/Info.plist):
//       Trinetra parses the binary itself (hardening flags, imports, signature);
//       if REA + Ghidra are available it additionally decompiles every function.
//   - packaged Electron archive (.asar): REA's JavaScript reconstructor.
//   - source (directory or file): Trinetra's AST analyzer on every JS file; for
//     small, packaged-looking trees REA's semantic graph is added on top.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { detectFormat } from "../binary/magic.js";
import { analyzeBinary } from "../binary/index.js";
import { parseFat } from "../binary/macho.js";
import { FileSource } from "../binary/source.js";
import { analyzeJs } from "../analysis/js-ast.js";
import { isReaAvailable, reaInspectJs, reaInspectNative, REA_MISSING } from "../adapters/rea.js";
import { sha256File, sha256Files } from "../util/hash.js";

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts"]);
const MAX_SOURCE_BYTES = 5 * 1024 * 1024; // skip giant generated bundles
const SKIP_DIRS = new Set(["node_modules", "dist", "build", "coverage"]);

// ---------------------------------------------------------------------------
// macOS .app bundles

function readPlistText(file) {
  const buf = fs.readFileSync(file);
  if (buf.subarray(0, 6).toString("latin1") !== "bplist") return buf.toString("utf8");
  try {
    // Binary plist: convert with the system tool when present (macOS).
    return execFileSync("plutil", ["-convert", "xml1", "-o", "-", file], {
      stdio: ["ignore", "pipe", "ignore"],
    }).toString();
  } catch {
    return "";
  }
}

export function isAppBundle(dir) {
  try {
    return fs.statSync(dir).isDirectory() && fs.existsSync(path.join(dir, "Contents", "Info.plist"));
  } catch {
    return false;
  }
}

// Resolve a bundle's main executable: CFBundleExecutable, else the only (or
// same-named) file in Contents/MacOS.
export function findBundleExecutable(dir) {
  const macos = path.join(dir, "Contents", "MacOS");
  const plist = readPlistText(path.join(dir, "Contents", "Info.plist"));
  const m = plist.match(/<key>CFBundleExecutable<\/key>\s*<string>([^<]+)<\/string>/);
  const candidates = [];
  if (m) candidates.push(path.join(macos, path.basename(m[1].trim())));
  candidates.push(path.join(macos, path.basename(dir).replace(/\.app$/i, "")));
  for (const c of candidates) if (fs.existsSync(c) && fs.statSync(c).isFile()) return c;
  const files = fs.existsSync(macos)
    ? fs.readdirSync(macos).filter((f) => fs.statSync(path.join(macos, f)).isFile())
    : [];
  if (files.length === 1) return path.join(macos, files[0]);
  throw new Error(`Could not locate the main executable of bundle ${dir}`);
}

// ---------------------------------------------------------------------------
// Fat Mach-O → single slice (Ghidra imports one architecture at a time)

const HOST_PREFERENCE =
  process.arch === "x64" ? ["x86_64", "arm64e", "arm64"] : ["arm64e", "arm64", "x86_64"];

export function thinFatBinary(file, outDir, preference = HOST_PREFERENCE) {
  const src = new FileSource(file);
  try {
    const { archs } = parseFat(src);
    const pick = preference.map((a) => archs.find((x) => x.arch === a)).find(Boolean) ?? archs[0];
    if (!pick) throw new Error("fat binary has no slices");
    fs.mkdirSync(outDir, { recursive: true });
    const out = path.join(outDir, `${path.basename(file)}-${pick.arch}`);
    const fd = fs.openSync(out, "w");
    try {
      for (let off = 0; off < pick.size; off += 8 * 1024 * 1024) {
        fs.writeSync(fd, src.read(pick.offset + off, Math.min(8 * 1024 * 1024, pick.size - off)));
      }
    } finally {
      fs.closeSync(fd);
    }
    return { path: out, arch: pick.arch };
  } finally {
    src.close();
  }
}

// ---------------------------------------------------------------------------
// Native

async function inspectNative(file, ctx, opts, { bundle } = {}) {
  const binary = analyzeBinary(file, { where: ctx.rel(file) });
  const name = path.basename(bundle ?? file);
  const notes = [];
  let rea = null;

  if (!opts.decompile) notes.push("Decompilation skipped (--no-decompile).");
  else if (!opts.useRea) notes.push("Decompilation skipped (--no-rea).");
  else if (!isReaAvailable({ env: ctx.env })) notes.push(`Decompilation unavailable: ${REA_MISSING}`);
  else {
    try {
      let analyzed = file;
      if (binary.format === "fat") {
        const thin = thinFatBinary(file, path.join(ctx.workDir, "thin"));
        analyzed = thin.path;
        notes.push(`Fat binary — decompiled the ${thin.arch} slice.`);
        console.log(`      (fat binary — thinned to ${thin.arch} slice for Ghidra)`);
      }
      rea = await reaInspectNative(analyzed, ctx, name);
    } catch (err) {
      notes.push(`Decompilation failed: ${err.message.split("\n")[0]}`);
      console.log(`      (decompilation unavailable: ${err.message.split("\n")[0]})`);
    }
  }

  // Without decompilation, imported functions are the most useful "units".
  const units = rea?.units ?? binary.imports.map((n) => ({ name: n, file, line: 0, source: "import" }));
  return {
    engine: rea ? "rea-native" : "trinetra-binary",
    kind: "native",
    root: bundle ?? file,
    files: [file],
    units,
    unitKind: rea ? "procedure" : "import",
    raw: [],
    js: [],
    binary,
    provenance: {
      sha256: sha256File(file),
      provider: rea
        ? `Trinetra binary parser + ${rea.provenance.provider ?? "REA"}`
        : "Trinetra binary parser",
    },
    statistics: rea?.statistics ?? { imports: binary.imports.length, libraries: binary.libraries.length },
    overview: rea?.overview,
    sampleName: rea?.sampleName,
    decompDir: rea?.decompDir,
    fnHashes: rea?.fnHashes,
    notes,
  };
}

// ---------------------------------------------------------------------------
// Source

function collectSourceFiles(target) {
  if (fs.statSync(target).isFile()) return [target];
  const out = [];
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith(".") || SKIP_DIRS.has(entry.name)) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.isFile() && SOURCE_EXT.has(path.extname(entry.name))) out.push(full);
    }
  };
  walk(target);
  return out.sort();
}

async function inspectSource(target, ctx, opts) {
  const notes = [];
  const files = collectSourceFiles(target).filter((f) => {
    if (fs.statSync(f).size <= MAX_SOURCE_BYTES) return true;
    notes.push(`Skipped ${ctx.rel(f)} (larger than 5 MB — likely a generated bundle).`);
    return false;
  });
  const raw = files.map((f) => ({ file: f, text: fs.readFileSync(f, "utf8") }));
  const js = raw.map(({ file, text }) => analyzeJs(text, ctx.rel(file)));
  for (const a of js)
    if (!a.parsed) notes.push(`${a.file}: not parseable as JavaScript (${a.error}); regex fallback only.`);

  const astUnits = js.flatMap((a) =>
    a.functions.map((f) => ({ name: f.name, file: a.file, line: f.line, source: f.params.join(", ") })),
  );
  const isDir = fs.statSync(target).isDirectory();
  const base = {
    kind: "source",
    root: target,
    files,
    raw,
    js,
    unitKind: "function",
    provenance: {
      sha256: isDir ? sha256Files(target, files) : sha256File(target),
      provider: "Trinetra AST analyzer",
    },
    notes,
  };

  // REA's application analyzer targets packaged apps, not dev repos with
  // node_modules; on those it grinds, so only use it for small trees.
  const hasNodeModules = isDir && fs.existsSync(path.join(target, "node_modules"));
  const looksPackaged = files.length > 0 && files.length <= 50 && !hasNodeModules;
  if (opts.useRea && looksPackaged && isReaAvailable({ env: ctx.env })) {
    try {
      const rea = await reaInspectJs(target, ctx);
      return {
        ...base,
        engine: "rea-javascript-application",
        units: rea.units,
        provenance: {
          ...base.provenance,
          provider: `Trinetra AST analyzer + ${rea.provenance.provider ?? "REA"}`,
          rea: rea.provenance,
        },
        statistics: rea.statistics,
      };
    } catch (err) {
      notes.push(`REA unavailable for this target: ${err.message.split("\n")[0]}`);
      console.log(
        `      (REA unavailable for this target: ${err.message.split("\n")[0]}; using built-in analysis)`,
      );
    }
  }
  return {
    ...base,
    engine: "trinetra-ast",
    units: astUnits,
    statistics: { files: files.length, functions: astUnits.length },
  };
}

/**
 * @param {string} target
 * @param {object} ctx run context
 * @param {{useRea?:boolean, decompile?:boolean}} [opts]
 */
export async function inspect(target, ctx, opts = {}) {
  const o = { useRea: opts.useRea ?? true, decompile: opts.decompile ?? true };
  const abs = path.resolve(ctx.cwd, target);
  if (!fs.existsSync(abs)) throw new Error(`Target not found: ${target}`);

  if (isAppBundle(abs)) return inspectNative(findBundleExecutable(abs), ctx, o, { bundle: abs });
  if (detectFormat(abs)) return inspectNative(abs, ctx, o);

  if (fs.statSync(abs).isFile() && path.extname(abs) === ".asar") {
    if (!o.useRea) throw new Error("Packed .asar archives need REA; remove --no-rea.");
    if (!isReaAvailable({ env: ctx.env })) throw new Error(REA_MISSING);
    const rea = await reaInspectJs(abs, ctx);
    return {
      engine: "rea-javascript-application",
      kind: "asar",
      root: abs,
      files: [abs],
      units: rea.units,
      unitKind: "function",
      raw: [], // packed archive: reconstruction only, no source scan
      js: [],
      provenance: { sha256: sha256File(abs), provider: rea.provenance.provider, rea: rea.provenance },
      statistics: rea.statistics,
      notes: [],
    };
  }

  return inspectSource(abs, ctx, o);
}
