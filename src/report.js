// Markdown teardown report. `renderMarkdown` is pure (deterministic for a given
// input and timestamp); `writeReport` puts it in the run's output directory.

import fs from "node:fs";
import path from "node:path";
import { safeName } from "./context.js";
import {
  countBySeverity,
  HARDENING_COLUMNS,
  hardeningRows,
  mdCode,
  rebuildLines,
  STATUS_ICON,
} from "./report-common.js";

const SEV = { high: "🔴 HIGH", medium: "🟠 MEDIUM", low: "🟡 LOW" };

/**
 * @param {object} r  { name, target, inspection, map, findings, engines, rebuilt, delta, generatedAt, rel }
 */
export function renderMarkdown(r) {
  const { name, inspection, map, findings } = r;
  const rel = r.rel ?? ((p) => p);
  const L = [];
  L.push(`# Trinetra teardown — ${name}`, "");
  L.push(`_Generated ${r.generatedAt} · engine: ${inspection.engine}_`, "");

  // 1. What it is
  L.push(`## 1. What it is`, "");
  if (r.target) L.push(`- Target: ${mdCode(r.target)} (${inspection.kind})`);
  if (inspection.provenance?.sha256)
    L.push(`- Fingerprint (SHA-256): ${mdCode(inspection.provenance.sha256)}`);
  if (inspection.provenance?.provider) L.push(`- Analyzed by: ${inspection.provenance.provider}`);
  if (inspection.kind === "native") {
    const s = inspection.statistics ?? {};
    if (inspection.engine === "rea-native") {
      L.push(`- Procedures with bodies: **${s.procedures}** · external references: **${s.external}**`);
      if (inspection.decompDir) L.push(`- Full pseudocode: ${mdCode(`${rel(inspection.decompDir)}/`)}`);
    } else {
      L.push(`- Imports: **${s.imports}** · linked libraries: **${s.libraries}**`);
    }
  } else {
    L.push(`- Files inspected: **${inspection.files.length}** · units: **${inspection.units.length}**`);
  }
  for (const n of inspection.notes ?? []) L.push(`- _Note:_ ${n}`);
  L.push("");

  const rows = hardeningRows(inspection.binary);
  if (rows.length) {
    L.push(`### Binary hardening`, "");
    L.push(`| ${HARDENING_COLUMNS.map(([, h]) => h).join(" | ")} |`);
    L.push(`| ${HARDENING_COLUMNS.map(() => "---").join(" | ")} |`);
    for (const row of rows) L.push(`| ${HARDENING_COLUMNS.map(([k]) => row[k] || "").join(" | ")} |`);
    L.push("");
  }

  // 2. What it does
  L.push(`## 2. What it does`, "");
  for (const s of map.summary ?? []) L.push(`- ${s}`);
  if (map.summary?.length) L.push("");
  const interesting = (map.behaviors ?? []).filter((b) => b.capabilities?.length || b.exported);
  if (inspection.kind !== "native" && interesting.length) {
    L.push(`| Function | Where | Exported | What it touches |`, `| --- | --- | --- | --- |`);
    for (const b of interesting)
      L.push(
        `| ${mdCode(b.name)} | ${mdCode(b.where)} | ${b.exported ? "yes" : ""} | ${b.summary.replace(/\|/g, "\\|")} |`,
      );
    L.push("");
  }
  if (inspection.engine === "rea-native") {
    if (map.behaviors.length) {
      L.push("Recovered procedures:", "");
      for (const b of map.behaviors) L.push(`- ${mdCode(b.name)}`);
      L.push("");
    }
    // Strip REA's provenance comment header; show the decompiled code itself.
    const code = (inspection.overview || "")
      .split("\n")
      .filter((l) => !l.startsWith("//"))
      .join("\n")
      .trim();
    if (code) {
      L.push(`Sample decompiled function — ${mdCode(inspection.sampleName)}:`, "", "```c");
      L.push(...code.split("\n").slice(0, 45));
      L.push("```", "");
    }
  }

  // 3. Findings
  L.push(`## 3. Security findings`, "");
  const c = countBySeverity(findings);
  if (findings.length === 0) {
    L.push("_No findings from the engines that ran (see Engines below)._", "");
  } else {
    L.push(`**${findings.length}** finding(s): ${c.high} high · ${c.medium} medium · ${c.low} low`, "");
    for (const f of findings) {
      L.push(`### ${SEV[f.severity] ?? f.severity} — ${f.title}`);
      L.push(`- **Where:** ${mdCode(f.where)}${f.function ? ` in ${mdCode(f.function)}` : ""}`);
      L.push(
        `- **Found by:** ${(f.engines ?? [f.engine]).join(" + ")} · **confidence:** ${f.confidence ?? "medium"}`,
      );
      if (f.taint) L.push(`- **Data flow:** ${mdCode(f.taint.source)} → ${f.taint.sink}`);
      L.push(`- **Why it matters:** ${f.why}`);
      L.push(`- **Evidence:** ${mdCode(f.evidence)}`, "");
    }
  }

  // 4. Since last run
  L.push(`## 4. Since last run`, "");
  if (!r.delta) {
    L.push("_First teardown of this target — this run is now the baseline._", "");
  } else {
    const d = r.delta;
    L.push(
      `Compared with the teardown from ${d.previousAt}: content ${d.contentChanged ? "**changed**" : "unchanged"}; ` +
        `**${d.new.length}** new, **${d.fixed.length}** fixed, ${d.unchanged} unchanged finding(s).`,
      "",
    );
    for (const f of d.new) L.push(`- 🆕 ${SEV[f.severity] ?? f.severity} ${f.title} — ${mdCode(f.where)}`);
    for (const f of d.fixed) L.push(`- ✅ fixed: ${f.title} — ${mdCode(f.where)}`);
    if (d.new.length || d.fixed.length) L.push("");
  }

  // 5. Rebuild
  L.push(`## 5. Rebuild`, "");
  const rb = rebuildLines(r.rebuilt, rel);
  if (!rb) L.push("_Not run. Pass `--rebuild` to generate a test-first reimplementation._", "");
  else {
    L.push(rb.headline, "");
    for (const i of rb.items)
      L.push(
        `- ${STATUS_ICON[i.status] ?? ""} ${mdCode(i.name)} — ${i.status}${i.detail ? ` (${i.detail})` : ""}`,
      );
    if (rb.items.length) L.push("");
  }

  // Engines
  if (r.engines?.length) {
    L.push(`## Engines`, "", `| Engine | Provided by | Status |`, `| --- | --- | --- |`);
    for (const e of r.engines) L.push(`| ${e.name} | ${e.owner} | ${e.status} |`);
    L.push("");
  }
  return L.join("\n");
}

export function writeReport(result, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const out = path.join(outDir, `${safeName(result.name)}.md`);
  fs.writeFileSync(out, renderMarkdown(result));
  return out;
}
