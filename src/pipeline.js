// The conductor. Runs the four Trinetra stages in order and ties them together
// with the shared memory store. Each stage maps to one of the project's
// ingredients (see README).

import path from "node:path";
import { inspect } from "./stages/inspect.js";
import { understand } from "./stages/understand.js";
import { audit } from "./stages/audit.js";
import { rebuild } from "./stages/rebuild.js";
import { writeReport } from "./report.js";
import { writeHtmlReport } from "./report-html.js";
import { Memory } from "./memory.js";

function banner(step, label) {
  console.log(`\n\u001b[36m[${step}]\u001b[0m ${label}`);
}

export async function teardown(target, { rebuild: doRebuild = false } = {}) {
  const name = path.basename(target);
  console.log(`\n\u001b[1mTrinetra\u001b[0m · tearing down "${name}"`);

  const memory = new Memory(name);

  // 1. INSPECT  (ingredient: REA — the eyes)
  banner("1/4 INSPECT", "taking the target apart");
  const inspection = await inspect(target);
  memory.remember("inspection", inspection);
  console.log(`      found ${inspection.units.length} unit(s) via ${inspection.engine}`);

  // 2. UNDERSTAND  (ingredient: everything-claude-code — memory)
  banner("2/4 UNDERSTAND", "building a knowledge map");
  const map = await understand(inspection, memory);
  console.log(`      mapped ${map.behaviors.length} behavior(s)`);

  // 3. AUDIT  (ingredient: security skills + mattpocock guardrails)
  banner("3/4 AUDIT", "hunting for weaknesses");
  const findings = await audit(inspection, map, target);
  const engines = [...new Set(findings.flatMap((f) => f.engines))].join(" + ") || "none";
  console.log(`      ${findings.length} finding(s) via ${engines}`);

  // 4. REBUILD  (ingredient: superpowers — test-first discipline) — optional
  let rebuilt = null;
  if (doRebuild) {
    banner("4/4 REBUILD", "forging a clean, tested version");
    rebuilt = await rebuild({ name, map, inspection });
    if (rebuilt.mode === "llm") {
      const passed = rebuilt.verified.filter((v) => v.passed).length;
      console.log(`      rebuilt ${rebuilt.verified.length} unit(s) · ${passed} passing their tests`);
    } else {
      console.log(`      scaffolded ${rebuilt.files.length} file(s) (set ANTHROPIC_API_KEY for a real rebuild)`);
    }
  } else {
    banner("4/4 REBUILD", "skipped (pass --rebuild to enable)");
  }

  const reportPath = await writeReport({ name, inspection, map, findings, rebuilt });
  const htmlPath = writeHtmlReport({ name, inspection, map, findings, rebuilt });
  console.log(`\n\u001b[32m✔ done\u001b[0m · report → ${reportPath}`);
  console.log(`          html   → ${htmlPath}\n`);
  return { reportPath, htmlPath, findings };
}
