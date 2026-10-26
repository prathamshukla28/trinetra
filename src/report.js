// Writes the teardown report (markdown) to reports/.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPORT_DIR = path.join(ROOT, "reports");

const SEV = { high: "🔴 HIGH", medium: "🟠 MEDIUM", low: "🟡 LOW" };

export async function writeReport({ name, inspection, map, findings, rebuilt }) {
  fs.mkdirSync(REPORT_DIR, { recursive: true });
  const out = path.join(REPORT_DIR, `${name}.md`);

  const lines = [];
  lines.push(`# REFORGE teardown — ${name}`, "");
  lines.push(`_Generated ${new Date().toISOString()} · engine: ${inspection.engine}_`, "");

  lines.push(`## 1. What it is`, "");
  lines.push(`- Files inspected: **${inspection.files.length}**`);
  lines.push(`- Units found: **${inspection.units.length}**`);
  if (inspection.provenance?.sha256) {
    lines.push(`- Target fingerprint (SHA-256): \`${inspection.provenance.sha256}\``);
    lines.push(`- Analyzed by: ${inspection.provenance.provider ?? "REA"}`);
  }
  lines.push("");

  lines.push(`## 2. What it does`, "");
  for (const b of map.behaviors) lines.push(`- \`${b.name}\` — ${b.guess} _(${b.where})_`);
  if (map.behaviors.length === 0) lines.push("_No named units extracted._");
  lines.push("");

  lines.push(`## 3. Security findings`, "");
  if (findings.length === 0) {
    lines.push("_No findings from the built-in ruleset._", "");
  } else {
    for (const f of findings) {
      lines.push(`### ${SEV[f.severity]} — ${f.title}`);
      lines.push(`- **Where:** \`${f.where}\``);
      lines.push(`- **Found by:** ${f.engine}`);
      lines.push(`- **Why it matters:** ${f.why}`);
      lines.push(`- **Evidence:** \`${f.evidence}\``, "");
    }
  }

  lines.push(`## 4. Rebuild`, "");
  if (rebuilt) {
    lines.push(`Scaffolded ${rebuilt.files.length} file(s) (test-first) in \`${path.relative(ROOT, rebuilt.outDir)}\`.`, "");
  } else {
    lines.push("_Not run. Pass `--rebuild` to generate a clean, tested reimplementation._", "");
  }

  fs.writeFileSync(out, lines.join("\n"));
  return path.relative(ROOT, out);
}
