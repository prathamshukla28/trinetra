// Stage 3 — AUDIT.  Scan the target for weaknesses. This is Trinetra's
// security-research output. Two engines run and their findings are merged:
//   1. built-in  — fast, offline, high-signal regex rules (always on)
//   2. semgrep   — hundreds of community rules + dataflow (when installed)

import { isSemgrepAvailable, runSemgrep } from "../adapters/semgrep.js";

const RULES = [
  {
    id: "dynamic-eval",
    severity: "high",
    re: /\beval\s*\(|new\s+Function\s*\(/,
    title: "Dynamic code execution (eval / new Function)",
    why: "Running strings as code lets attacker-controlled input execute arbitrary logic.",
  },
  {
    id: "shell-injection",
    severity: "high",
    re: /\bexecSync\s*\(|\bexec\s*\(|\bspawn\s*\(/,
    title: "Shell / command execution",
    why: "If any part of the command comes from input, this is command injection.",
  },
  {
    id: "hardcoded-secret",
    severity: "high",
    re: /(?:api[_-]?key|secret|token|password)\s*[:=]\s*["'][A-Za-z0-9_\-]{8,}["']/i,
    title: "Hardcoded secret",
    why: "Credentials in source leak through the repo, logs, and shipped builds.",
  },
  {
    id: "weak-hash",
    severity: "medium",
    re: /createHash\s*\(\s*["'](md5|sha1)["']/i,
    title: "Weak hashing algorithm (MD5 / SHA-1)",
    why: "These are broken for integrity and password use.",
  },
  {
    id: "insecure-random",
    severity: "low",
    re: /Math\.random\s*\(\)/,
    title: "Insecure randomness (Math.random)",
    why: "Not cryptographically secure — unsafe for tokens, IDs, or keys.",
  },
];

function runBuiltin(inspection) {
  const findings = [];
  for (const { file, text } of inspection.raw ?? []) {
    text.split("\n").forEach((line, i) => {
      for (const rule of RULES) {
        if (rule.re.test(line)) {
          findings.push({
            rule: rule.id,
            severity: rule.severity,
            title: rule.title,
            why: rule.why,
            where: `${file}:${i + 1}`,
            evidence: line.trim().slice(0, 120),
            engine: "builtin",
          });
        }
      }
    });
  }
  return findings;
}

export async function audit(inspection, _map, target) {
  let findings = runBuiltin(inspection);

  // Semgrep is a source scanner — only run it when we have source (not binaries).
  if (isSemgrepAvailable() && target && inspection.raw?.length) {
    try {
      findings = findings.concat(runSemgrep(target));
    } catch (err) {
      console.log(`      (semgrep skipped: ${err.message.split("\n")[0]})`);
    }
  }

  // De-duplicate findings that land on the same file:line with the same idea.
  const seen = new Set();
  findings = findings.filter((f) => {
    const key = `${f.where}|${f.rule}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const order = { high: 0, medium: 1, low: 2 };
  return findings.sort((a, b) => order[a.severity] - order[b.severity]);
}
