// Stage 4 — REBUILD (optional). Forge a clean, tested reimplementation of the
// target, test-first (the superpowers discipline).
//
// With Claude configured, each unit is regenerated as a test + implementation
// pair, then the test is actually run to verify it passes (one retry on
// failure). Without credentials, it falls back to scaffolding stub pairs.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { isLlmConfigured, reimplement } from "../adapters/llm.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const MAX_UNITS = 2; // bound cost — rebuild the first couple of units per run

const safe = (s) => String(s || "target").replace(/[^A-Za-z0-9_-]/g, "_");

// What are we rebuilding? Source files for source targets; the decompiled
// pseudocode for native ones.
function unitsToRebuild(name, inspection) {
  if (inspection.raw?.length) {
    return inspection.raw.slice(0, MAX_UNITS).map((r) => ({
      name: safe(path.basename(r.file).replace(/\.[^.]+$/, "")),
      source: r.text,
    }));
  }
  if (inspection.overview) {
    return [{ name: safe(inspection.sampleName || name), source: inspection.overview }];
  }
  return [];
}

function runTest(testFile) {
  try {
    execFileSync(process.execPath, ["--test", testFile], { stdio: "pipe" });
    return { passed: true, output: "" };
  } catch (err) {
    return { passed: false, output: (err.stdout?.toString() || "") + (err.stderr?.toString() || "") };
  }
}

async function rebuildWithLlm(units, outDir) {
  const files = [];
  const verified = [];

  for (const unit of units) {
    const implFile = path.join(outDir, `${unit.name}.js`);
    const testFile = path.join(outDir, `${unit.name}.test.js`);

    let result = await reimplement({ name: unit.name, language: "javascript", source: unit.source });
    fs.writeFileSync(implFile, result.impl);
    fs.writeFileSync(testFile, result.test);
    files.push(implFile, testFile);

    let run = runTest(testFile);
    if (!run.passed) {
      // One test-first retry, feeding the failure back to the model.
      result = await reimplement({
        name: unit.name,
        language: "javascript",
        source: unit.source,
        priorError: run.output.slice(0, 2000),
      });
      fs.writeFileSync(implFile, result.impl);
      fs.writeFileSync(testFile, result.test);
      run = runTest(testFile);
    }
    verified.push({ name: unit.name, passed: run.passed });
  }

  return { outDir, files, verified, mode: "llm" };
}

// Fallback: scaffold a failing test + stub so the test-first loop is ready for
// a human (or a later LLM run) to fill in.
function scaffoldStubs(map, outDir) {
  const files = [];
  for (const b of map.behaviors) {
    const base = safe(b.name);
    const testFile = path.join(outDir, `${base}.test.js`);
    const implFile = path.join(outDir, `${base}.js`);
    if (!fs.existsSync(testFile)) {
      fs.writeFileSync(
        testFile,
        `// TEST FIRST. Describe ${b.name} — "${b.guess}".\n` +
          `import { ${base} } from "./${base}.js";\n\n` +
          `import test from "node:test";\nimport assert from "node:assert/strict";\n\n` +
          `test("${base} exists", () => { assert.equal(typeof ${base}, "function"); });\n`,
      );
      files.push(testFile);
    }
    if (!fs.existsSync(implFile)) {
      fs.writeFileSync(
        implFile,
        `export function ${base}() {\n  // TODO: implement to pass ${base}.test.js\n}\n`,
      );
      files.push(implFile);
    }
  }
  return { outDir, files, verified: [], mode: "scaffold" };
}

export async function rebuild({ name, map, inspection }) {
  const outDir = path.join(ROOT, "src", "rebuilt", safe(name));
  fs.mkdirSync(outDir, { recursive: true });

  if (!isLlmConfigured()) {
    return scaffoldStubs(map, outDir);
  }

  const units = unitsToRebuild(name, inspection);
  if (units.length === 0) return scaffoldStubs(map, outDir);

  try {
    return await rebuildWithLlm(units, outDir);
  } catch (err) {
    console.log(`      (LLM rebuild failed: ${err.message.split("\n")[0]}; scaffolding instead)`);
    return scaffoldStubs(map, outDir);
  }
}
