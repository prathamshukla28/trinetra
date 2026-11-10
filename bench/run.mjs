#!/usr/bin/env node
// Trinetra accuracy benchmark. Writes bench/results.json and bench/RESULTS.md.
//
//   npm run bench                         fetch the pinned corpus (if needed) and run everything
//   node bench/run.mjs --no-binary        JS corpora only
//   node bench/run.mjs --save-baseline    record raw findings to bench/baseline-findings.json
//
// Output is deterministic: no timestamps, stable ordering. JS numbers depend
// only on the checkout (+ the pinned corpus and package-lock); binary numbers
// depend on the machine's binaries, so the OS build is recorded with them.
// Exit code 1 if labels drifted from their markers or any finding on real code
// is untriaged — the benchmark is only meaningful when every finding is judged.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runJsBench } from "./lib/js.mjs";
import { runBinaryBench } from "./lib/binary.mjs";
import { renderMarkdown } from "./lib/report.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
process.chdir(path.dirname(HERE)); // repo root: corpus paths and node_modules resolve from here
const args = new Set(process.argv.slice(2));
const BASELINE = path.join(HERE, "baseline-findings.json");

const baseline = fs.existsSync(BASELINE) ? JSON.parse(fs.readFileSync(BASELINE, "utf8")) : null;
const js = runJsBench({ baseline: args.has("--save-baseline") ? null : baseline });

if (args.has("--save-baseline")) {
  const out = {
    note: "Raw findings of the rules before the benchmark-driven fixes, re-scored on every run against the current labels and triage.",
    analyzer: process.env.BASELINE_LABEL ?? "working tree",
  };
  for (const c of js.corpora)
    if (!c.skipped) out[c.name] = c.rawFindings.map(({ file, line, rule }) => ({ file, line, rule }));
  out.crashes = Object.fromEntries(
    js.corpora.filter((c) => !c.skipped).map((c) => [c.name, c.crashes.length]),
  );
  fs.writeFileSync(BASELINE, `${JSON.stringify(out, null, 2)}\n`);
  console.log(`baseline written to ${path.relative(process.cwd(), BASELINE)}`);
  process.exit(0);
}

const binary = args.has("--no-binary") ? { skipped: "--no-binary" } : runBinaryBench();

for (const c of js.corpora) delete c.rawFindings;
const results = {
  benchmark: "trinetra-accuracy",
  analyzer: "src/analysis/js-ast.js + src/binary",
  baseline: baseline
    ? { analyzer: baseline.analyzer, crashes: baseline.crashes, binaryBefore: baseline.binaryBefore ?? null }
    : null,
  js,
  binary,
};
fs.writeFileSync(path.join(HERE, "results.json"), `${JSON.stringify(results, null, 2)}\n`);
fs.writeFileSync(path.join(HERE, "RESULTS.md"), renderMarkdown(results));

// Console summary.
const pct = (x) => (x === null ? "  –  " : `${(x * 100).toFixed(1)}%`);
const t = js.overall.total;
console.log(
  `JS overall: TP ${t.tp}  FP ${t.fp}  FN ${t.fn}  precision ${pct(t.precision)}  recall ${pct(t.recall)}  F1 ${pct(t.f1)}`,
);
for (const c of js.corpora) {
  if (c.skipped) console.log(`  ${c.name}: SKIPPED — ${c.skipped}`);
  else
    console.log(
      `  ${c.name.padEnd(9)} files ${String(c.files).padStart(4)}  findings ${String(c.findings).padStart(3)}  P ${pct(c.total.precision)}  R ${pct(c.total.recall)}  crashes ${c.crashes.length}`,
    );
}
if (binary.macho) {
  const worst = Object.entries(binary.macho.perCheck).map(([k, v]) => `${k} ${v.agree}/${v.total}`);
  console.log(`Mach-O (${binary.macho.binaries} binaries): ${worst.join(", ")}`);
}
if (binary.elf) {
  const all = Object.entries(binary.elf.perCheck).map(([k, v]) => `${k} ${v.agree}/${v.total}`);
  console.log(`ELF (${binary.elf.binaries} binaries): ${all.join(", ")}`);
}
console.log("wrote bench/results.json and bench/RESULTS.md");

const problems = [];
const syn = js.corpora.find((c) => c.name === "synthetic");
if (!syn.labelsInSync)
  problems.push("bench/labels/synthetic.json is out of date: run node bench/extract-labels.mjs");
for (const c of js.corpora) {
  if (c.skipped) problems.push(`${c.name} skipped: ${c.skipped}`);
  for (const f of c.untriaged ?? [])
    problems.push(`untriaged ${c.name} finding: ${f.rule} ${f.file}:${f.line}`);
}
for (const p of problems) console.error(`! ${p}`);
if (problems.length) process.exitCode = 1;
