// Stage 4 — REBUILD (optional, `--rebuild`). Produce a clean, test-first
// reimplementation of the target.
//
// With Claude configured, each unit is sent (as delimited, untrusted data) to
// the model, which returns a test + implementation pair. Those files are
// written to <out>/rebuilt/<name>/ and are NOT executed unless the user also
// passes `--run-generated`. Even then, code that reaches for process, network,
// or environment APIs is refused, and the rest runs only inside the sandbox in
// src/sandbox.js (stripped env, temp-dir-only fs, no child processes, timeout).
// A failing test gets one retry with the failure fed back to the model.
//
// Without credentials, it scaffolds failing-test + stub pairs for a human.

import fs from "node:fs";
import path from "node:path";
import { isLlmConfigured, reimplement as defaultReimplement } from "../adapters/llm.js";
import { safeName } from "../context.js";
import { reviewGeneratedCode, runInSandbox } from "../sandbox.js";

const MAX_UNITS = 2; // bound cost — rebuild the first couple of units per run

const RESERVED = new Set(
  (
    "break case catch class const continue debugger default delete do else enum export extends false " +
    "finally for function if import in instanceof new null return super switch this throw true try typeof " +
    "var void while with yield let static implements interface package private protected public await"
  ).split(" "),
);

// A valid, safe JavaScript identifier / file stem derived from untrusted text.
export function safeIdent(s) {
  let id = String(s || "unit").replace(/[^A-Za-z0-9_]/g, "_");
  if (!id || /^[0-9]/.test(id)) id = `_${id}`;
  if (RESERVED.has(id)) id = `${id}_`;
  return id.slice(0, 80);
}

// Untrusted text placed in a generated `//` comment: one line, printable only.
const commentSafe = (s) =>
  String(s ?? "")
    .replace(/[^\x20-\x7e]/g, " ")
    .slice(0, 200);

// What are we rebuilding? Source files for source targets; the decompiled
// pseudocode for native ones.
function unitsToRebuild(name, inspection) {
  if (inspection.raw?.length) {
    return inspection.raw.slice(0, MAX_UNITS).map((r) => ({
      name: safeIdent(path.basename(r.file).replace(/\.[^.]+$/, "")),
      source: r.text,
    }));
  }
  if (inspection.overview) {
    return [{ name: safeIdent(inspection.sampleName || name), source: inspection.overview }];
  }
  return [];
}

function verify(unit, result, runGenerated, timeoutMs) {
  const concerns = [
    ...reviewGeneratedCode(result.impl, `${unit.name}.js`),
    ...reviewGeneratedCode(result.test, `${unit.name}.test.js`),
  ];
  if (concerns.length) return { status: "blocked", passed: null, reason: concerns.join("; ") };
  if (!runGenerated) return { status: "not-run", passed: null, reason: "pass --run-generated to execute" };
  const run = runInSandbox(
    { [`${unit.name}.js`]: result.impl, [`${unit.name}.test.js`]: result.test },
    `${unit.name}.test.js`,
    { timeoutMs },
  );
  return {
    status: run.passed ? "passed" : run.timedOut ? "timeout" : "failed",
    passed: run.passed,
    output: run.output,
    isolation: run.isolation,
  };
}

async function rebuildWithLlm(units, outDir, { runGenerated, reimplement, timeoutMs }) {
  const files = [];
  const verified = [];

  for (const unit of units) {
    const implFile = path.join(outDir, `${unit.name}.js`);
    const testFile = path.join(outDir, `${unit.name}.test.js`);
    const write = (r) => {
      fs.writeFileSync(implFile, r.impl);
      fs.writeFileSync(testFile, r.test);
    };

    let result = await reimplement({ name: unit.name, language: "javascript", source: unit.source });
    write(result);
    files.push(implFile, testFile);

    let v = verify(unit, result, runGenerated, timeoutMs);
    if (v.status === "failed") {
      result = await reimplement({
        name: unit.name,
        language: "javascript",
        source: unit.source,
        priorError: v.output.slice(0, 2000),
      });
      write(result);
      v = verify(unit, result, runGenerated, timeoutMs);
    }
    const { output: _output, ...summary } = v;
    verified.push({ name: unit.name, ...summary });
  }

  return { outDir, files, verified, mode: "llm", executed: runGenerated };
}

// Fallback: scaffold a failing test + stub so the test-first loop is ready for
// a human (or a later LLM run) to fill in.
function scaffoldStubs(map, outDir) {
  const files = [];
  const seen = new Set();
  for (const b of map.behaviors) {
    const base = safeIdent(b.name);
    if (seen.has(base)) continue;
    seen.add(base);
    const testFile = path.join(outDir, `${base}.test.js`);
    const implFile = path.join(outDir, `${base}.js`);
    if (!fs.existsSync(testFile)) {
      fs.writeFileSync(
        testFile,
        `// TEST FIRST. Pin the behavior of ${commentSafe(b.name)} — ${commentSafe(b.summary ?? b.guess)}.\n` +
          `import test from "node:test";\nimport assert from "node:assert/strict";\n` +
          `import { ${base} } from "./${base}.js";\n\n` +
          `test("${base} exists", () => {\n  assert.equal(typeof ${base}, "function");\n});\n`,
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
  return { outDir, files, verified: [], mode: "scaffold", executed: false };
}

/**
 * @param {{name:string, map:object, inspection:object}} input
 * @param {object} ctx  run context (see context.js)
 * @param {{runGenerated?:boolean, reimplement?:Function, timeoutMs?:number}} [opts]
 */
export async function rebuild({ name, map, inspection }, ctx, opts = {}) {
  const outDir = path.join(ctx.rebuiltDir, safeName(name));
  fs.mkdirSync(outDir, { recursive: true });
  const reimplement = opts.reimplement ?? defaultReimplement;

  if (!opts.reimplement && !isLlmConfigured(ctx.env)) return scaffoldStubs(map, outDir);

  const units = unitsToRebuild(name, inspection);
  if (units.length === 0) return scaffoldStubs(map, outDir);

  console.log(`      sending ${units.length} unit(s) of target source to Claude (as untrusted data)`);
  try {
    return await rebuildWithLlm(units, outDir, {
      runGenerated: Boolean(opts.runGenerated),
      reimplement,
      timeoutMs: opts.timeoutMs,
    });
  } catch (err) {
    console.log(`      (LLM rebuild failed: ${err.message.split("\n")[0]}; scaffolding instead)`);
    return scaffoldStubs(map, outDir);
  }
}
