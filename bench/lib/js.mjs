// JavaScript benchmark: run Trinetra's AST rules (src/analysis/js-ast.js) over
// three corpora and score every finding against hand-written ground truth.
//
//   synthetic  bench/js/<rule>/{tp,fn-expected,tn}/ — labels in bench/labels/synthetic.json
//   nodegoat   OWASP NodeGoat at a pinned commit    — labels + triage in bench/labels/nodegoat.json
//   packages   popular npm packages in node_modules — triage in bench/labels/packages.json
//
// A finding matches a label when file, line and rule are all equal.

import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { analyzeJs, JS_RULES } from "../../src/analysis/js-ast.js";
import { collectSourceFiles } from "../../src/stages/inspect.js";
import { extractLabels, listCaseFiles, SYNTHETIC_DIR, SYNTHETIC_LABELS } from "../extract-labels.mjs";
import { CORPORA, checkoutHead, corpusPath } from "../fetch-corpus.mjs";

export const RULE_IDS = Object.keys(JS_RULES).sort();
const MAX_SOURCE_BYTES = 5 * 1024 * 1024; // same cut-off as the inspect stage
const PKG_EXT = /\.(js|mjs|cjs|jsx)$/;

const readJson = (f) => JSON.parse(fs.readFileSync(f, "utf8"));
const key = (f) => `${f.file}|${f.line}|${f.rule}`;

// ---------------------------------------------------------------------------
// Metrics

export function metrics({ tp, fp, fn }) {
  const precision = tp + fp ? tp / (tp + fp) : null;
  const recall = tp + fn ? tp / (tp + fn) : null;
  const f1 =
    precision !== null && recall !== null && precision + recall > 0
      ? (2 * precision * recall) / (precision + recall)
      : tp === 0 && fp + fn > 0
        ? 0
        : null;
  return { tp, fp, fn, precision, recall, f1 };
}

export const emptyCounts = () => Object.fromEntries(RULE_IDS.map((r) => [r, { tp: 0, fp: 0, fn: 0 }]));

export function finalize(counts) {
  const perRule = Object.fromEntries(RULE_IDS.map((r) => [r, metrics(counts[r])]));
  const sum = RULE_IDS.reduce(
    (a, r) => ({ tp: a.tp + counts[r].tp, fp: a.fp + counts[r].fp, fn: a.fn + counts[r].fn }),
    { tp: 0, fp: 0, fn: 0 },
  );
  return { perRule, total: metrics(sum) };
}

// ---------------------------------------------------------------------------
// Analysis

function analyzeFiles(root, files) {
  const out = { files: files.length, lines: 0, parsed: 0, parseFailures: [], crashes: [], findings: [] };
  for (const full of files) {
    const rel = path.relative(root, full).split(path.sep).join("/");
    let r;
    const text = fs.readFileSync(full, "utf8");
    out.lines += text.split("\n").length;
    try {
      r = analyzeJs(text, rel);
    } catch (err) {
      out.crashes.push({ file: rel, error: err.message });
      continue;
    }
    if (r.parsed) out.parsed++;
    else out.parseFailures.push(rel);
    for (const f of r.findings) {
      const i = f.where.lastIndexOf(":");
      out.findings.push({
        file: f.where.slice(0, i),
        line: Number(f.where.slice(i + 1)),
        rule: f.rule,
        confidence: f.confidence,
        taint: f.taint?.source ?? null,
        evidence: f.evidence,
      });
    }
  }
  out.findings.sort(
    (a, b) => a.file.localeCompare(b.file) || a.line - b.line || a.rule.localeCompare(b.rule),
  );
  return out;
}

// Score findings against positive labels (expected: true), negative labels
// (expected: false) and post-hoc triage verdicts. `unlabelled` decides what an
// unmatched, untriaged finding is: "fp" (synthetic suite: every true positive
// is labelled up front) or "untriaged" (real code: must be triaged by hand).
function score(findings, labels, triage, { unlabelled }) {
  const counts = emptyCounts();
  const inScope = labels.filter((l) => l.rule in JS_RULES);
  const positives = new Map(inScope.filter((l) => l.expected).map((l) => [key(l), l]));
  const negatives = new Map(inScope.filter((l) => !l.expected).map((l) => [key(l), l]));
  const verdicts = new Map(triage.map((t) => [key(t), t]));
  const matched = new Set();
  const tps = [];
  const fps = [];
  const untriaged = [];
  for (const f of findings) {
    const k = key(f);
    if (positives.has(k)) {
      matched.add(k);
      counts[f.rule].tp++;
      tps.push({ ...f, basis: "label" });
    } else if (verdicts.has(k)) {
      const t = verdicts.get(k);
      if (t.verdict === "TP") {
        counts[f.rule].tp++;
        tps.push({ ...f, basis: "triage", reason: t.reason });
      } else {
        counts[f.rule].fp++;
        fps.push({ ...f, basis: "triage", reason: t.reason });
      }
    } else if (negatives.has(k)) {
      counts[f.rule].fp++;
      fps.push({ ...f, basis: "label", reason: negatives.get(k).note ?? "labelled negative" });
    } else {
      counts[f.rule].fp++;
      if (unlabelled === "untriaged") untriaged.push(f);
      fps.push({ ...f, basis: unlabelled === "untriaged" ? "UNTRIAGED" : "unlabelled" });
    }
  }
  const fns = [];
  for (const [k, l] of positives) {
    if (matched.has(k)) continue;
    counts[l.rule].fn++;
    fns.push(l);
  }
  const staleTriage = triage.filter((t) => !findings.some((f) => key(f) === key(t)));
  return { counts, tps, fps, fns, untriaged, staleTriage };
}

// ---------------------------------------------------------------------------
// Corpora

export function runSynthetic({ baseline } = {}) {
  const labels = readJson(SYNTHETIC_LABELS);
  const drift = JSON.stringify(extractLabels()) !== JSON.stringify(labels);
  const a = analyzeFiles(SYNTHETIC_DIR, listCaseFiles());
  const scoreAll = (findings) => score(findings, labels, [], { unlabelled: "fp" });
  const s = scoreAll(a.findings);
  const byKind = {};
  for (const l of labels) {
    const k = (byKind[l.kind] ??= { labels: 0, positives: 0, negatives: 0 });
    k.labels++;
    if (l.expected) k.positives++;
    else k.negatives++;
  }
  return {
    name: "synthetic",
    title: "Synthetic labelled suite (bench/js)",
    labelsInSync: !drift,
    labelCount: labels.length,
    byKind,
    files: a.files,
    parsed: a.parsed,
    parseFailures: a.parseFailures,
    crashes: a.crashes,
    findings: a.findings.length,
    ...finalize(s.counts),
    falsePositives: s.fps,
    falseNegatives: s.fns,
    rawFindings: a.findings,
    ...(baseline ? { baseline: finalize(scoreAll(baseline).counts) } : {}),
  };
}

export function runNodeGoat({ baseline } = {}) {
  const spec = CORPORA.find((c) => c.name === "NodeGoat");
  const file = readJson(path.resolve("bench/labels/nodegoat.json"));
  const head = checkoutHead(spec);
  if (head !== spec.commit || file.commit !== spec.commit) {
    return {
      name: "nodegoat",
      skipped: `NodeGoat not at ${spec.commit} (found ${head ?? "nothing"}); run: node bench/fetch-corpus.mjs`,
    };
  }
  const root = corpusPath(spec);
  const files = collectSourceFiles(root).filter((f) => fs.statSync(f).size <= MAX_SOURCE_BYTES);
  const a = analyzeFiles(root, files);
  const scoreAll = (findings) => score(findings, file.labels, file.triage, { unlabelled: "untriaged" });
  const s = scoreAll(a.findings);
  const outOfScope = file.labels.filter((l) => !(l.rule in JS_RULES));
  const inScope = file.labels.filter((l) => l.rule in JS_RULES && l.expected);
  const hit = new Set(s.tps.filter((t) => t.basis === "label").map(key));
  return {
    name: "nodegoat",
    title: `OWASP NodeGoat @ ${spec.commit.slice(0, 12)}`,
    commit: spec.commit,
    files: a.files,
    parsed: a.parsed,
    parseFailures: a.parseFailures,
    crashes: a.crashes,
    findings: a.findings.length,
    ...finalize(s.counts),
    coverage: {
      documentedIssues: file.labels.filter((l) => l.expected).length,
      inScope: inScope.length,
      inScopeDetected: inScope.filter((l) => hit.has(key(l))).length,
      outOfScope: outOfScope.map((l) => ({ file: l.file, line: l.line, issue: l.rule })),
    },
    truePositives: s.tps,
    falsePositives: s.fps,
    falseNegatives: s.fns,
    untriaged: s.untriaged,
    staleTriage: s.staleTriage,
    rawFindings: a.findings,
    ...(baseline
      ? { baseline: finalize(scoreAll(baseline).counts), baselineUntriaged: scoreAll(baseline).untriaged }
      : {}),
  };
}

function walkPackage(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((x, y) => x.name.localeCompare(y.name))) {
      if (e.name === "node_modules" || e.name.startsWith(".")) continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && PKG_EXT.test(e.name) && fs.statSync(full).size <= MAX_SOURCE_BYTES)
        out.push(full);
    }
  };
  walk(dir);
  return out;
}

export function runPackages({ baseline } = {}) {
  const file = readJson(path.resolve("bench/labels/packages.json"));
  const require = createRequire(path.resolve("package.json"));
  const counts = emptyCounts();
  const packages = [];
  const allTriage = [];
  const allFindings = [];
  const allTps = [];
  const allFps = [];
  const untriaged = [];
  const staleTriage = [];
  const crashes = [];
  const parseFailures = [];
  let files = 0;
  let lines = 0;
  let findings = 0;
  for (const p of file.packages) {
    const dir = path.resolve("node_modules", p.name);
    let version = null;
    try {
      version = require(path.join(dir, "package.json")).version;
    } catch {
      packages.push({ name: p.name, recorded: p.version, installed: null, skipped: "not installed" });
      continue;
    }
    const a = analyzeFiles(dir, walkPackage(dir));
    const tag = (f) => ({ ...f, file: `${p.name}/${f.file}` });
    const triage = file.triage
      .filter((t) => t.package === p.name)
      .map((t) => ({ ...t, file: `${p.name}/${t.file}` }));
    allTriage.push(...triage);
    allFindings.push(...a.findings.map(tag));
    const s = score(a.findings.map(tag), [], triage, { unlabelled: "untriaged" });
    for (const r of RULE_IDS) {
      counts[r].tp += s.counts[r].tp;
      counts[r].fp += s.counts[r].fp;
    }
    files += a.files;
    lines += a.lines;
    findings += a.findings.length;
    crashes.push(...a.crashes.map(tag));
    parseFailures.push(...a.parseFailures.map((f) => `${p.name}/${f}`));
    allTps.push(...s.tps);
    allFps.push(...s.fps);
    untriaged.push(...s.untriaged);
    staleTriage.push(...s.staleTriage);
    packages.push({
      name: p.name,
      recorded: p.version,
      installed: version,
      versionMatches: version === p.version,
      files: a.files,
      lines: a.lines,
      findings: a.findings.length,
      tp: s.tps.length,
      fp: s.fps.length,
    });
  }
  return {
    name: "packages",
    title: "Popular packages in node_modules (false-positive check)",
    packages,
    files,
    lines,
    findings,
    crashes,
    parseFailures,
    ...finalize(counts),
    truePositives: allTps,
    falsePositives: allFps,
    untriaged,
    staleTriage,
    rawFindings: allFindings,
    ...(baseline ? packagesBaseline(baseline, allTriage) : {}),
  };
}

function packagesBaseline(findings, triage) {
  const s = score(findings, [], triage, { unlabelled: "untriaged" });
  for (const r of RULE_IDS) s.counts[r].fn = 0; // no ground-truth positives in this corpus
  return { baseline: finalize(s.counts), baselineUntriaged: s.untriaged };
}

export function runJsBench({ baseline } = {}) {
  const corpora = [
    runSynthetic({ baseline: baseline?.synthetic }),
    runNodeGoat({ baseline: baseline?.nodegoat }),
    runPackages({ baseline: baseline?.packages }),
  ];
  const counts = emptyCounts();
  for (const c of corpora) {
    if (c.skipped) continue;
    for (const r of RULE_IDS) for (const m of ["tp", "fp", "fn"]) counts[r][m] += c.perRule[r][m];
  }
  const result = { rules: RULE_IDS, corpora, overall: finalize(counts) };
  if (baseline) {
    const b = emptyCounts();
    for (const c of corpora) {
      if (!c.baseline) continue;
      for (const r of RULE_IDS) for (const m of ["tp", "fp", "fn"]) b[r][m] += c.baseline.perRule[r][m];
    }
    result.baselineOverall = finalize(b);
  }
  return result;
}
