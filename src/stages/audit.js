// Stage 3 — AUDIT. Collect findings from every applicable engine and
// *correlate* them so the same issue isn't reported twice:
//   - trinetra-ast     Trinetra's AST + taint rules (always on for JS source)
//   - trinetra-regex   credential/weak-hash line checks for unparseable files
//   - trinetra-binary  Trinetra's binary hardening checks (always on for natives)
//   - ghidra-scan      line rules over REA/Ghidra pseudocode (when decompiled)
//   - semgrep          community packs (delegated; when installed + enabled)

import fs from "node:fs";
import path from "node:path";
import { isSemgrepAvailable, runSemgrep } from "../adapters/semgrep.js";

// Rules for decompiled C pseudocode (Ghidra names externals like `_system`).
// Pseudocode has no stable syntax tree to work with, so these stay line-based.
const NATIVE_RULES = [
  {
    id: "native-command-exec",
    severity: "high",
    re: /\b_?(system|popen|execve?|execl|execvp)\s*\(/,
    title: "Command execution (system / exec / popen)",
    why: "Spawning a shell from a binary is command-injection-prone if any input reaches it.",
  },
  {
    id: "native-unsafe-string",
    severity: "high",
    re: /\b_?(strcpy|strcat|sprintf|gets)\s*\(/,
    title: "Unsafe C string function",
    why: "strcpy/strcat/sprintf/gets are unbounded — the classic buffer-overflow sources.",
  },
  {
    id: "native-embedded-secret",
    severity: "high",
    re: /(?:AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|sk_live_[A-Za-z0-9]{8,}|xox[baprs]-[A-Za-z0-9-]{10,})/,
    title: "Embedded secret / private key",
    why: "A credential baked into the binary can be extracted by anyone with the file.",
  },
  {
    id: "native-format-string",
    severity: "medium",
    re: /\b_?(printf|fprintf|vprintf|syslog)\s*\(\s*[a-z_][A-Za-z0-9_]*\s*[),]/,
    title: "Possible format-string bug",
    why: "A non-literal format argument lets input control the format string (%n writes, info leaks).",
  },
  {
    id: "native-unsafe-memory",
    severity: "low",
    re: /\b_?(memcpy|memmove|alloca)\s*\(/,
    title: "Unbounded memory operation",
    why: "memcpy/memmove/alloca with an attacker-influenced size can overflow.",
  },
  {
    id: "native-bounded-string",
    severity: "low",
    re: /\b_?(strncpy|strncat)\s*\(/,
    title: "Bounded string function (verify termination)",
    why: "strncpy/strncat can leave the destination non-NUL-terminated.",
  },
  {
    id: "native-embedded-url",
    severity: "low",
    re: /https?:\/\/[^\s")]+/,
    title: "Hardcoded URL / endpoint",
    why: "Baked-in endpoints reveal infrastructure and can't be rotated without a rebuild.",
  },
  {
    id: "native-insecure-random",
    severity: "low",
    re: /\b_?(rand|srandom|random)\s*\(/,
    title: "Weak randomness (C rand)",
    why: "C rand() is not cryptographically secure.",
  },
];

// Map a finding to a canonical concept so the same issue from different engines
// collapses into one row.
export function canonical(f) {
  const s = `${f.rule} ${f.title}`.toLowerCase();
  if (/secret|api.?key|password|token/.test(s)) return "hardcoded-secret";
  if (/md5|sha1|weak.?hash/.test(s)) return "weak-hash";
  if (/random/.test(s)) return "insecure-random";
  if (/eval|new function|dynamic code/.test(s)) return "dynamic-code";
  if (/path.?traversal/.test(s)) return "path-traversal";
  if (/sql/.test(s)) return "sql-injection";
  if (/xss|innerhtml/.test(s)) return "dom-xss";
  if (/exec|shell|command|child_process|system|popen/.test(s)) return "command-exec";
  if (/format.?string|printf/.test(s)) return "format-string";
  if (/memcpy|memmove|alloca|unbounded memory/.test(s)) return "unsafe-memory";
  if (/strcpy|strcat|sprintf|gets|strncpy|strncat|overflow|buffer|string function/.test(s))
    return "unsafe-string";
  if (/url|endpoint/.test(s)) return "hardcoded-url";
  return f.rule;
}

// Line-based scan used for decompiled pseudocode only.
export function scanLines(text, file, rules, engine) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    if (line.startsWith("//")) return; // REA's provenance header, not code
    for (const rule of rules) {
      if (rule.re.test(line)) {
        out.push({
          rule: rule.id,
          severity: rule.severity,
          title: rule.title,
          why: rule.why,
          where: `${file}:${i + 1}`,
          evidence: line.trim().slice(0, 160),
          engine,
          confidence: "low",
        });
      }
    }
  });
  return out;
}

function auditNativePseudocode(inspection, rel) {
  if (!inspection.decompDir) return [];
  const fnDir = path.join(path.resolve(inspection.decompDir), "functions");
  if (!fs.existsSync(fnDir)) return [];
  const out = [];
  for (const f of fs.readdirSync(fnDir).sort()) {
    if (!f.endsWith(".c")) continue;
    const full = path.join(fnDir, f);
    out.push(...scanLines(fs.readFileSync(full, "utf8"), rel(full), NATIVE_RULES, "ghidra-scan"));
  }
  return out;
}

const SEV_ORDER = { high: 0, medium: 1, low: 2 };
const CONF_ORDER = { high: 0, medium: 1, low: 2 };

// Collapse findings that describe the same concept at the same location,
// merging the engines that reported them.
export function correlate(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = `${f.where}|${canonical(f)}`;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, { ...f, engines: [f.engine] });
      continue;
    }
    if (!g.engines.includes(f.engine)) g.engines.push(f.engine);
    if (SEV_ORDER[f.severity] < SEV_ORDER[g.severity]) {
      Object.assign(g, { severity: f.severity, title: f.title, why: f.why, evidence: f.evidence });
    }
    // Agreement between engines raises confidence; keep the best evidence of taint.
    if (CONF_ORDER[f.confidence] < CONF_ORDER[g.confidence]) g.confidence = f.confidence;
    if (f.taint && !g.taint) g.taint = f.taint;
  }
  return [...groups.values()]
    .map((g) => (g.engines.length > 1 && g.confidence !== "high" ? { ...g, confidence: "high" } : g))
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.where.localeCompare(b.where, "en"));
}

/**
 * @param {object} inspection
 * @param {object} [_map]
 * @param {string} [target]  original target path (Semgrep scans it)
 * @param {{useSemgrep?:boolean, ctx?:object}} [opts]
 * @returns {Promise<object[]>} findings; `audit.engines` describes what ran
 */
export async function audit(inspection, _map, target, opts = {}) {
  const rel = opts.ctx?.rel ?? ((p) => p);
  const findings = [
    ...(inspection.js ?? []).flatMap((a) => a.findings),
    ...(inspection.binary?.findings ?? []),
    ...auditNativePseudocode(inspection, rel),
  ];
  const engines = { semgrep: "not applicable" };

  // Semgrep is a source scanner — only when we have source (not binaries).
  const hasSource = (inspection.raw?.length ?? 0) > 0;
  const env = opts.ctx?.env ?? process.env;
  if (hasSource && target) {
    if (opts.useSemgrep === false) engines.semgrep = "disabled (--no-semgrep)";
    else if (!isSemgrepAvailable({ env })) engines.semgrep = "not installed";
    else {
      try {
        const sg = runSemgrep(path.resolve(opts.ctx?.cwd ?? process.cwd(), target), {
          env,
          cwd: opts.ctx?.cwd,
        });
        findings.push(...sg.map((f) => ({ ...f, where: rewriteWhere(f.where, rel) })));
        engines.semgrep = `ran (${sg.length} raw finding(s))`;
      } catch (err) {
        engines.semgrep = `failed: ${err.message.split("\n")[0]}`;
        console.log(`      (semgrep skipped: ${err.message.split("\n")[0]})`);
      }
    }
  }

  const out = correlate(findings);
  Object.defineProperty(out, "engines", { value: engines, enumerable: false });
  return out;
}

// Semgrep reports absolute paths when given an absolute target; show them like
// Trinetra's own (relative to the user's cwd) so correlation lines up.
function rewriteWhere(where, rel) {
  const m = where.match(/^(.*):(\d+)$/);
  return m ? `${rel(m[1])}:${m[2]}` : where;
}
