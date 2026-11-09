// The conductor. `teardown` runs inspect → understand → audit → (rebuild),
// compares the result with the previous run of the same target, and writes
// markdown, HTML, and JSON reports into the output directory. `compare` diffs
// two targets.

import fs from "node:fs";
import path from "node:path";
import { createContext, safeName } from "./context.js";
import { inspect } from "./stages/inspect.js";
import { understand } from "./stages/understand.js";
import { audit } from "./stages/audit.js";
import { rebuild } from "./stages/rebuild.js";
import { diffTeardowns } from "./stages/compare.js";
import { writeReport } from "./report.js";
import { writeHtmlReport } from "./report-html.js";
import { writeCompareReport } from "./report-compare.js";
import { Memory } from "./memory.js";
import { isReaAvailable } from "./adapters/rea.js";

function banner(step, label) {
  console.log(`\n\u001b[36m[${step}]\u001b[0m ${label}`);
}

// Which engines ran, who provides them, and why any were skipped.
export function engineTable(inspection, auditEngines = {}, { opts = {}, ctx, rebuilt } = {}) {
  const rows = [];
  if (inspection.js?.length) {
    const parsed = inspection.js.filter((a) => a.parsed).length;
    rows.push({
      name: "JavaScript AST rules + taint tracking",
      owner: "Trinetra",
      status: `ran on ${parsed}/${inspection.js.length} file(s)${parsed < inspection.js.length ? " (regex fallback for the rest)" : ""}`,
    });
  }
  if (inspection.binary) {
    rows.push({
      name: "Binary format + hardening checks",
      owner: "Trinetra",
      status: `ran (${inspection.binary.format}: ${inspection.binary.archs.join(", ")})`,
    });
  }
  let rea;
  if (inspection.engine.startsWith("rea-")) rea = "used";
  else if (opts.useRea === false) rea = "disabled (--no-rea)";
  else if (!isReaAvailable({ env: ctx?.env })) rea = "not installed";
  else if (inspection.kind === "native" && opts.decompile === false) rea = "disabled (--no-decompile)";
  else rea = (inspection.notes ?? []).find((n) => /REA|Decompil/i.test(n)) ?? "not used for this target";
  rows.push({
    name: "REA (JS reconstruction / Ghidra decompilation)",
    owner: "delegated: rea-agents",
    status: rea,
  });
  if (inspection.decompDir)
    rows.push({ name: "Pseudocode line rules", owner: "Trinetra (over Ghidra output)", status: "ran" });
  rows.push({
    name: "Semgrep community packs",
    owner: "delegated: semgrep",
    status: auditEngines.semgrep ?? "not applicable",
  });
  if (rebuilt)
    rows.push({
      name: "Rebuild code generation",
      owner: rebuilt.mode === "llm" ? "delegated: Claude" : "Trinetra (scaffold)",
      status:
        rebuilt.mode === "llm"
          ? rebuilt.executed
            ? "generated + sandboxed run"
            : "generated, not executed"
          : "scaffolded stubs (no API key)",
    });
  return rows;
}

/**
 * @param {string} target
 * @param {object} [opts] { out, rebuild, runGenerated, useRea, useSemgrep, decompile, ctx, generatedAt }
 */
export async function teardown(target, opts = {}) {
  const ctx = opts.ctx ?? createContext({ out: opts.out });
  const name = path.basename(path.resolve(ctx.cwd, target));
  console.log(`\n\u001b[1mTrinetra\u001b[0m · tearing down "${name}"`);

  banner("1/4 INSPECT", "taking the target apart");
  const inspection = await inspect(target, ctx, { useRea: opts.useRea, decompile: opts.decompile });
  console.log(
    `      found ${inspection.units.length} ${inspection.unitKind ?? "unit"}(s) via ${inspection.engine}`,
  );

  banner("2/4 UNDERSTAND", "mapping imports, exports and capabilities");
  const map = await understand(inspection);
  for (const s of map.summary.slice(0, 3)) console.log(`      ${s}`);

  banner("3/4 AUDIT", "hunting for weaknesses");
  const findings = await audit(inspection, map, target, { useSemgrep: opts.useSemgrep, ctx });
  const engines = [...new Set(findings.flatMap((f) => f.engines))].join(" + ") || "none";
  console.log(`      ${findings.length} finding(s) via ${engines}`);

  let rebuilt = null;
  if (opts.rebuild) {
    banner("4/4 REBUILD", "test-first reimplementation");
    if (opts.runGenerated) {
      console.log(
        "      \u001b[33m⚠ --run-generated: AI-generated code derived from an untrusted target will be executed\u001b[0m\n" +
          "        (sandboxed: stripped env, temp-dir-only filesystem, no child processes, timeout).",
      );
    }
    rebuilt = await rebuild({ name, map, inspection }, ctx, {
      runGenerated: opts.runGenerated,
      reimplement: opts.reimplement,
    });
    if (rebuilt.mode === "llm") {
      const passed = rebuilt.verified.filter((v) => v.status === "passed").length;
      console.log(
        `      generated ${rebuilt.verified.length} unit(s)` +
          (rebuilt.executed
            ? ` · ${passed} passing in the sandbox`
            : " · not executed (pass --run-generated)"),
      );
    } else {
      console.log(
        `      scaffolded ${rebuilt.files.length} file(s) (set ANTHROPIC_API_KEY for a model-generated rebuild)`,
      );
    }
  } else {
    banner("4/4 REBUILD", "skipped (pass --rebuild to enable)");
  }

  // Compare with the previous teardown of this target, then save this run.
  const memory = new Memory(ctx, inspection.root, name);
  const delta = memory.diff({ sha256: inspection.provenance.sha256, findings });
  memory.save({ sha256: inspection.provenance.sha256, findings, engine: inspection.engine });
  if (delta)
    console.log(
      `      since last run: ${delta.new.length} new · ${delta.fixed.length} fixed · ${delta.unchanged} unchanged`,
    );

  const result = {
    name,
    target: ctx.rel(inspection.root),
    inspection,
    map,
    findings,
    engines: engineTable(inspection, findings.engines, { opts, ctx, rebuilt }),
    rebuilt,
    delta,
    generatedAt: opts.generatedAt ?? new Date().toISOString(),
    rel: ctx.rel,
  };
  const reportPath = writeReport(result, ctx.reportsDir);
  const htmlPath = writeHtmlReport(result, ctx.reportsDir);
  const jsonPath = path.join(ctx.reportsDir, `${safeName(name)}.json`);
  fs.writeFileSync(
    jsonPath,
    JSON.stringify(
      {
        name,
        target: result.target,
        generatedAt: result.generatedAt,
        engine: inspection.engine,
        sha256: inspection.provenance.sha256,
        summary: map.summary,
        findings,
        engines: result.engines,
        delta,
      },
      null,
      2,
    ),
  );
  console.log(`\n\u001b[32m✔ done\u001b[0m · report → ${ctx.rel(reportPath)}`);
  console.log(`          html   → ${ctx.rel(htmlPath)}`);
  console.log(`          json   → ${ctx.rel(jsonPath)}\n`);
  return { reportPath, htmlPath, jsonPath, findings, map, inspection, delta, rebuilt };
}

// Diff two targets — "what changed between v1 and v2".
export async function compare(a, b, opts = {}) {
  const ctx = opts.ctx ?? createContext({ out: opts.out });
  const nameA = path.basename(path.resolve(ctx.cwd, a));
  const nameB = path.basename(path.resolve(ctx.cwd, b));
  console.log(`\n\u001b[1mTrinetra\u001b[0m · comparing "${nameA}" → "${nameB}"`);
  const stageOpts = { useRea: opts.useRea, decompile: opts.decompile };

  console.log(`\n\u001b[36m[A]\u001b[0m inspecting ${nameA}`);
  const inspA = await inspect(a, ctx, stageOpts);
  const findA = await audit(inspA, null, a, { useSemgrep: opts.useSemgrep, ctx });

  console.log(`\u001b[36m[B]\u001b[0m inspecting ${nameB}`);
  const inspB = await inspect(b, ctx, stageOpts);
  const findB = await audit(inspB, null, b, { useSemgrep: opts.useSemgrep, ctx });

  const diff = diffTeardowns(
    { name: nameA, inspection: inspA, findings: findA },
    { name: nameB, inspection: inspB, findings: findB },
  );
  const paths = writeCompareReport(diff, ctx.reportsDir, opts.generatedAt);
  console.log(
    `\n\u001b[32m✔ done\u001b[0m · +${diff.procedures.added.length} / -${diff.procedures.removed.length}` +
      `${diff.hashable ? ` / ~${diff.procedures.changed.length}` : ""} units`,
  );
  console.log(`          report → ${ctx.rel(paths.md)}`);
  console.log(`          html   → ${ctx.rel(paths.html)}\n`);
  return { ...diff, paths };
}
