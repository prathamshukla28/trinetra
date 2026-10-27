// Stage 3 — AUDIT.  Scan the target for weaknesses. This is Trinetra's
// security-research output. It runs every applicable engine and then
// *correlates* their findings so the same issue isn't reported twice:
//   - built-in source rules   (fast, offline, always on for source)
//   - semgrep                 (community packs, when installed, for source)
//   - native pseudocode rules (dangerous C calls, for decompiled binaries)

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { isSemgrepAvailable, runSemgrep } from "../adapters/semgrep.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

const SOURCE_RULES = [
  { id: "dynamic-eval", severity: "high", re: /\beval\s*\(|new\s+Function\s*\(/, title: "Dynamic code execution (eval / new Function)", why: "Running strings as code lets attacker-controlled input execute arbitrary logic." },
  { id: "shell-injection", severity: "high", re: /\bexecSync\s*\(|\bexec\s*\(|\bspawn\s*\(/, title: "Shell / command execution", why: "If any part of the command comes from input, this is command injection." },
  { id: "hardcoded-secret", severity: "high", re: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-]{8,}["']/i, title: "Hardcoded secret", why: "Credentials in source leak through the repo, logs, and shipped builds." },
  { id: "weak-hash", severity: "medium", re: /createHash\s*\(\s*["'](md5|sha1)["']/i, title: "Weak hashing algorithm (MD5 / SHA-1)", why: "These are broken for integrity and password use." },
  { id: "insecure-random", severity: "low", re: /Math\.random\s*\(\)/, title: "Insecure randomness (Math.random)", why: "Not cryptographically secure — unsafe for tokens, IDs, or keys." },
];

// Rules for decompiled C pseudocode (Ghidra names externals like `_system`).
const NATIVE_RULES = [
  { id: "native-command-exec", severity: "high", re: /\b_?(system|popen|execve?|execl|execvp)\s*\(/, title: "Command execution (system / exec / popen)", why: "Spawning a shell from a binary is command-injection-prone if any input reaches it." },
  { id: "native-unsafe-string", severity: "high", re: /\b_?(strcpy|strcat|sprintf|gets)\s*\(/, title: "Unsafe C string function", why: "strcpy/strcat/sprintf/gets are unbounded — the classic buffer-overflow sources." },
  { id: "native-insecure-random", severity: "low", re: /\b_?(rand|srandom|random)\s*\(/, title: "Weak randomness (C rand)", why: "C rand() is not cryptographically secure." },
];

// Map a finding to a canonical concept so the same issue from different engines
// collapses into one row.
export function canonical(f) {
  const s = `${f.rule} ${f.title}`.toLowerCase();
  if (/secret|api.?key|password|token/.test(s)) return "hardcoded-secret";
  if (/md5|sha1|weak.?hash/.test(s)) return "weak-hash";
  if (/random/.test(s)) return "insecure-random";
  if (/eval|new function/.test(s)) return "dynamic-code";
  if (/exec|shell|command|child_process|system|popen/.test(s)) return "command-exec";
  if (/strcpy|strcat|sprintf|gets|overflow|buffer/.test(s)) return "unsafe-string";
  return f.rule;
}

function scan(text, file, rules, engine) {
  const out = [];
  text.split("\n").forEach((line, i) => {
    for (const rule of rules) {
      if (rule.re.test(line)) {
        out.push({ rule: rule.id, severity: rule.severity, title: rule.title, why: rule.why, where: `${file}:${i + 1}`, evidence: line.trim().slice(0, 120), engine });
      }
    }
  });
  return out;
}

function auditSource(inspection) {
  return (inspection.raw ?? []).flatMap(({ file, text }) => scan(text, file, SOURCE_RULES, "builtin"));
}

function auditNative(inspection) {
  if (!inspection.decompDir) return [];
  const fnDir = path.join(ROOT, inspection.decompDir, "functions");
  if (!fs.existsSync(fnDir)) return [];
  const out = [];
  for (const f of fs.readdirSync(fnDir)) {
    if (!f.endsWith(".c")) continue;
    const full = path.join(fnDir, f);
    const rel = path.relative(ROOT, full);
    out.push(...scan(fs.readFileSync(full, "utf8"), rel, NATIVE_RULES, "ghidra-scan"));
  }
  return out;
}

const SEV_ORDER = { high: 0, medium: 1, low: 2 };

// Collapse findings that describe the same concept at the same location,
// merging the engines that reported them.
export function correlate(findings) {
  const groups = new Map();
  for (const f of findings) {
    const key = `${f.where}|${canonical(f)}`;
    const g = groups.get(key);
    if (!g) {
      groups.set(key, { ...f, engines: [f.engine] });
    } else {
      if (!g.engines.includes(f.engine)) g.engines.push(f.engine);
      if (SEV_ORDER[f.severity] < SEV_ORDER[g.severity]) {
        Object.assign(g, { severity: f.severity, title: f.title, why: f.why, evidence: f.evidence });
      }
    }
  }
  return [...groups.values()].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
}

export async function audit(inspection, _map, target) {
  let findings = [...auditSource(inspection), ...auditNative(inspection)];

  // Semgrep is a source scanner — only when we have source (not binaries).
  if (isSemgrepAvailable() && target && inspection.raw?.length) {
    try {
      findings = findings.concat(runSemgrep(target).map((f) => ({ ...f, engine: f.engine || "semgrep" })));
    } catch (err) {
      console.log(`      (semgrep skipped: ${err.message.split("\n")[0]})`);
    }
  }

  return correlate(findings);
}
