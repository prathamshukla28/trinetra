// Render bench/results.json as bench/RESULTS.md.

const pct = (x) => (x === null || x === undefined ? "–" : `${(x * 100).toFixed(1)}%`);
const num = (x) => (x === null || x === undefined ? "–" : x.toFixed(2));
const esc = (s) => String(s).replace(/\|/g, "\\|").replace(/\n/g, " ");

function ruleTable(rules, perRule, total, { recall = true } = {}) {
  const head = recall
    ? ["| Rule | TP | FP | FN | Precision | Recall | F1 |", "|---|--:|--:|--:|--:|--:|--:|"]
    : ["| Rule | TP | FP | Precision |", "|---|--:|--:|--:|"];
  const row = (name, m) =>
    recall
      ? `| ${name} | ${m.tp} | ${m.fp} | ${m.fn} | ${pct(m.precision)} | ${pct(m.recall)} | ${num(m.f1)} |`
      : `| ${name} | ${m.tp} | ${m.fp} | ${pct(m.precision)} |`;
  return [...head, ...rules.map((r) => row(`\`${r}\``, perRule[r])), row("**all rules**", total)].join("\n");
}

function findingList(items, { reason = true } = {}) {
  if (!items.length) return "_none_\n";
  return `${items
    .map((f) => {
      const why = reason && (f.reason || f.note) ? ` — ${esc(f.reason ?? f.note)}` : "";
      const basis = f.basis && f.basis !== "label" ? ` _(${f.basis})_` : "";
      return `- \`${f.rule}\` ${f.file}:${f.line}${basis}${why}`;
    })
    .join("\n")}\n`;
}

function synthetic(c, rules) {
  const k = c.byKind;
  const kinds = `\`tp\` ${k.tp?.positives ?? 0} vulnerable lines, \`fn-expected\` ${k["fn-expected"]?.positives ?? 0} vulnerable lines in known blind spots, \`tn\` ${k.tn?.negatives ?? 0} must-not-flag lines`;
  return `### Synthetic labelled suite

${c.files} files under \`bench/js/<rule>/{tp,fn-expected,tn}/\`, ${c.labelCount} line labels in
\`bench/labels/synthetic.json\` (${kinds}). \`fn-expected\` cases are real vulnerabilities in
patterns the analyzer is known not to model (inter-procedural flow, aliasing, unmodelled libraries);
they count as false negatives when missed. Any finding not on an \`expect\` line counts as a false positive.
Parsed ${c.parsed}/${c.files}; analyzer crashes: ${c.crashes.length}.

${ruleTable(rules, c.perRule, c.total)}

**False negatives (${c.falseNegatives.length})**

${findingList(c.falseNegatives)}
**False positives (${c.falsePositives.length})**

${findingList(c.falsePositives)}`;
}

function nodegoat(c, rules) {
  if (c.skipped) return `### OWASP NodeGoat\n\nSkipped: ${c.skipped}\n`;
  const cov = c.coverage;
  return `### OWASP NodeGoat (real application with documented vulnerabilities)

Commit \`${c.commit}\`, fetched by \`bench/fetch-corpus.mjs\`. Files selected exactly as
\`trinetra teardown\` would (${c.files} files, ${c.parsed} parsed, ${c.crashes.length} analyzer crashes),
including vendored front-end libraries. Labels and their sources: \`bench/labels/nodegoat.json\`.

${ruleTable(rules, c.perRule, c.total)}

**Coverage of documented issues.** ${cov.documentedIssues} labelled issues; ${cov.inScope} fall under a
Trinetra rule and ${cov.inScopeDetected} of those are detected. ${cov.outOfScope.length} have no
corresponding rule (not counted above): ${cov.outOfScope.map((o) => `${o.issue} (${o.file}:${o.line})`).join(", ")}.

**True positives (${c.truePositives.length})**

${findingList(c.truePositives)}
**False negatives (${c.falseNegatives.length})**

${findingList(c.falseNegatives.map((l) => ({ ...l, reason: l.source })))}
**False positives (${c.falsePositives.length})**

${findingList(c.falsePositives)}`;
}

function packages(c, rules) {
  const rows = c.packages
    .map((p) =>
      p.skipped
        ? `| ${p.name} | ${p.recorded} | not installed | – | – | – | – | – |`
        : `| ${p.name} | ${p.installed}${p.versionMatches ? "" : ` (triaged ${p.recorded})`} | ${p.files} | ${p.lines.toLocaleString("en-US")} | ${p.findings} | ${p.tp} | ${p.fp} |`,
    )
    .join("\n");
  return `### Popular packages (false-positive check)

Every finding on these widely used packages was triaged by hand (\`bench/labels/packages.json\`).
No ground-truth vulnerabilities are known here, so only precision is meaningful. ${c.files} files,
${c.lines.toLocaleString("en-US")} lines, ${c.findings} findings — **${((c.total.fp / c.lines) * 1000).toFixed(2)} false positives per
1,000 lines** — and ${c.crashes.length} analyzer crashes. A finding is TP only if it is a real weakness
under the package's own trust model; a correct sink fed by trusted-by-design input (caller-supplied
schemas, user-configured plugins, protocol-mandated SHA-1) is FP, with the reason recorded.

| Package | Version | Files | Lines | Findings | TP | FP |
|---|---|--:|--:|--:|--:|--:|
${rows}

${ruleTable(rules, c.perRule, c.total, { recall: false })}

**True positives (${c.truePositives.length})**

${findingList(c.truePositives)}
**False positives (${c.falsePositives.length})**

${findingList(c.falsePositives)}`;
}

function beforeAfter(js) {
  if (!js.baselineOverall) return "";
  const rows = [];
  for (const c of js.corpora) {
    if (!c.baseline) continue;
    const b = c.baseline.total;
    const a = c.total;
    rows.push(
      `| ${c.name} | ${b.tp}/${b.fp}/${b.fn} → ${a.tp}/${a.fp}/${a.fn} | ${pct(b.precision)} → ${pct(a.precision)} | ${pct(b.recall)} → ${pct(a.recall)} | ${num(b.f1)} → ${num(a.f1)} |`,
    );
  }
  const b = js.baselineOverall.total;
  const a = js.overall.total;
  rows.push(
    `| **overall** | ${b.tp}/${b.fp}/${b.fn} → ${a.tp}/${a.fp}/${a.fn} | ${pct(b.precision)} → ${pct(a.precision)} | ${pct(b.recall)} → ${pct(a.recall)} | ${num(b.f1)} → ${num(a.f1)} |`,
  );
  const perRule = js.rules
    .filter((r) => JSON.stringify(js.baselineOverall.perRule[r]) !== JSON.stringify(js.overall.perRule[r]))
    .map((r) => {
      const x = js.baselineOverall.perRule[r];
      const y = js.overall.perRule[r];
      return `| \`${r}\` | ${x.tp}/${x.fp}/${x.fn} → ${y.tp}/${y.fp}/${y.fn} | ${pct(x.precision)} → ${pct(y.precision)} | ${pct(x.recall)} → ${pct(y.recall)} | ${num(x.f1)} → ${num(y.f1)} |`;
    });
  return `## Before / after the benchmark-driven fixes

The rules' raw findings before the fixes are stored in \`bench/baseline-findings.json\` and re-scored
on every run with the *same* labels and triage as the current run. Counts are TP/FP/FN.

| Corpus | TP/FP/FN | Precision | Recall | F1 |
|---|---|--:|--:|--:|
${rows.join("\n")}

| Rule (changed only) | TP/FP/FN | Precision | Recall | F1 |
|---|---|--:|--:|--:|
${perRule.join("\n")}

`;
}

function binary(b, before) {
  if (b.skipped) return `## Binary hardening checks\n\nSkipped (${b.skipped}).\n`;
  const out = ["## Binary hardening checks", ""];
  if (before) {
    const m = Object.entries(before.macho)
      .map(([k, [a, t]]) => `${k} ${a}/${t}`)
      .join(", ");
    out.push(
      `Parser bugs this comparison exposed, now fixed: ${before.fixed.map((f) => `(${f})`).join("; ")}. Before the fixes: ${m}. ${before.note}`,
      "",
    );
  }
  out.push(
    "Each field Trinetra's pure-JS parser reports is compared with an independent tool. Agreement is per",
    "slice (one architecture of a binary) except `archs`, which is per file.",
    "",
  );
  if (b.macho) {
    const m = b.macho;
    const oracle = {
      executable: "`otool -hv` filetype EXECUTE",
      pie: "`otool -hv` PIE flag",
      execStack: "`otool -hv` ALLOW_STACK_EXECUTION",
      canary: "`nm -u` has `___stack_chk_fail`/`___stack_chk_guard`",
      imports: "`nm -u` undefined-symbol set (exact match)",
      signed: "`codesign -dvvv` has a CodeDirectory",
      adhoc: "`codesign` CodeDirectory flag 0x2",
      hardenedRuntime: "`codesign` CodeDirectory flag 0x10000 (runtime)",
      platformBinary: "`codesign` `Platform identifier=`",
      archs: "`lipo -archs`",
    };
    out.push(
      `### Mach-O — ${m.binaries} binaries, ${m.slices} slices (${b.platform})`,
      "",
      `Sample: ${Object.entries(m.groups)
        .map(([g, n]) => `${g}: ${n}`)
        .join("; ")}.`,
      `Oracle positives (slices): ${Object.entries(m.positivesInOracle)
        .map(([k, v]) => `${k} ${v}`)
        .join(", ")}.`,
      "",
      "| Check | Oracle | Agree | Total | Agreement |",
      "|---|---|--:|--:|--:|",
      ...Object.entries(m.perCheck).map(
        ([k, v]) => `| ${k} | ${oracle[k] ?? ""} | ${v.agree} | ${v.total} | ${pct(v.rate)} |`,
      ),
      "",
      `Disagreements: ${m.disagreements.length ? "" : "none."}`,
      ...m.disagreements.map(
        (d) =>
          `- ${d.file}${d.arch ? ` [${d.arch}]` : ""}: ${d.check} — ${esc(JSON.stringify(d.truth))} vs ${esc(JSON.stringify(d.trinetra ?? null))}`,
      ),
      `Parser errors: ${m.errors.length ? m.errors.map((e) => `${e.file}: ${e.error}`).join("; ") : "none."}`,
      "",
    );
  }
  if (b.elf) {
    const e = b.elf;
    const oracle = {
      pie: "`file` says “pie executable”",
      static: "`file` says “statically linked”",
      nx: "`llvm-objdump -p` STACK flags lack x",
      relro: "`llvm-objdump -p` RELRO + BIND_NOW/FLAGS",
      canary: "`llvm-objdump -T` has `__stack_chk_fail`",
      imports: "`llvm-objdump -T` *UND* set (exact match)",
      runpath: "`llvm-objdump -p` RPATH/RUNPATH",
    };
    out.push(
      `### ELF — ${e.binaries} binaries (generated fixtures; no ELF binaries exist on this macOS host)`,
      "",
      `Go cross-compiled Linux executables (static and PIE, amd64/arm64/386) plus hand-built variants from`,
      "`test/helpers/binaries.js` (imports, executable stack, RELRO levels, RUNPATH).",
      "",
      "| Check | Oracle | Agree | Total | Agreement |",
      "|---|---|--:|--:|--:|",
      ...Object.entries(e.perCheck).map(
        ([k, v]) => `| ${k} | ${oracle[k] ?? ""} | ${v.agree} | ${v.total} | ${pct(v.rate)} |`,
      ),
      "",
      `Disagreements: ${e.disagreements.length ? "" : "none."}`,
      ...e.disagreements.map(
        (d) =>
          `- ${d.file}: ${d.check} — oracle ${esc(JSON.stringify(d.truth))}, Trinetra ${esc(JSON.stringify(d.trinetra))}${
            d.file.endsWith("et-dyn-no-pie-flag")
              ? " (ET_DYN with PT_INTERP but no DF_1_PIE: Trinetra and checksec call this PIE, as pre-2018 toolchains never set DF_1_PIE; libmagic calls it a shared object. Ambiguous by construction, kept as a disagreement.)"
              : ""
          }`,
      ),
      "",
    );
  }
  if (b.notes?.length) out.push(`Notes: ${b.notes.join("; ")}`, "");
  return out.join("\n");
}

export function renderMarkdown(r) {
  const js = r.js;
  const byName = Object.fromEntries(js.corpora.map((c) => [c.name, c]));
  const corpusCols = js.rules
    .map((rule) => {
      const s = byName.synthetic.perRule[rule];
      const n = byName.nodegoat.skipped ? null : byName.nodegoat.perRule[rule];
      const p = byName.packages.perRule[rule];
      const o = js.overall.perRule[rule];
      return `| \`${rule}\` | ${s.tp}/${s.fp}/${s.fn} | ${n ? `${n.tp}/${n.fp}/${n.fn}` : "–"} | ${p.tp}/${p.fp} | ${pct(o.precision)} | ${pct(o.recall)} | ${num(o.f1)} |`;
    })
    .join("\n");
  const o = js.overall.total;
  const tot = (c) => (c.skipped ? "–" : `${c.total.tp}/${c.total.fp}/${c.total.fn}`);
  return `# Trinetra accuracy benchmark

Generated by \`npm run bench\` (\`bench/run.mjs\`) — do not edit by hand. Output is deterministic:
the JavaScript numbers depend only on this checkout, the pinned NodeGoat commit and
\`package-lock.json\`; the binary numbers depend on the host's binaries (OS build recorded below).

## JavaScript rules — summary

Pooled over all three corpora. Corpus columns are TP/FP/FN (packages: TP/FP — no known
positives there, so they add precision evidence only).

| Rule | Synthetic | NodeGoat | Packages | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
${corpusCols}
| **all rules** | ${tot(byName.synthetic)} | ${tot(byName.nodegoat)} | ${byName.packages.total.tp}/${byName.packages.total.fp} | **${pct(o.precision)}** | **${pct(o.recall)}** | **${num(o.f1)}** |

How to read this honestly:

- **Small corpus.** ${byName.synthetic.labelCount} synthetic labels, ${byName.nodegoat.skipped ? "–" : byName.nodegoat.coverage.documentedIssues} NodeGoat labels, ${byName.packages.findings} triaged findings on ${byName.packages.packages.length} packages. One case moves a rule's score by many points; treat per-rule numbers as indicative.
- **Self-labelled.** The synthetic cases, the NodeGoat labels and the triage were written by the same project that wrote the rules. The synthetic suite deliberately includes known blind spots (\`fn-expected\`) and tricky negatives, but author bias cannot be ruled out. Triage criteria are stated in the label files.
- **Scope.** Intra-function taint only (no inter-procedural or cross-file flow), JavaScript only (TypeScript files fall back to two regex checks and are not benchmarked), Node/browser sinks listed in \`src/analysis/js-ast.js\`. NodeGoat issues without a matching rule (NoSQL injection, open redirect, ReDoS, …) are reported as coverage, not as false negatives.

${beforeAfter(js)}## Per corpus

${synthetic(byName.synthetic, js.rules)}
${nodegoat(byName.nodegoat, js.rules)}
${packages(byName.packages, js.rules)}
${binary(r.binary, r.baseline?.binaryBefore)}`;
}
