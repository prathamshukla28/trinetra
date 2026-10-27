// Adapter for Semgrep — Trinetra's heavyweight security scanner.
//
// Runs alongside the built-in ruleset. The built-in rules are fast and always
// available; Semgrep brings hundreds of community rules and real dataflow.

import { execFileSync } from "node:child_process";
import fs from "node:fs";

// Semgrep redacts matched snippets ("requires login") unless logged in. We have
// the file + line, so just read the real line ourselves.
function readLine(file, line) {
  try {
    return fs.readFileSync(file, "utf8").split("\n")[line - 1]?.trim().slice(0, 120) ?? "";
  } catch {
    return "";
  }
}

// A solid default security set. Registry packs are fetched + cached by Semgrep.
const CONFIGS = ["p/security-audit", "p/secrets", "p/javascript", "p/nodejsscan"];

// Never scan vendored dependencies or build output — that's a supply-chain
// concern, not the project's own code, and it floods the report.
const EXCLUDES = [
  "node_modules",
  ".git",
  "site-packages",
  ".venv",
  "venv",
  "dist-info",
  "dist",
  "build",
  "*.pyc",
  "*.min.js",
];

const SEV = { ERROR: "high", WARNING: "medium", INFO: "low" };

function pickEvidence(r) {
  const lines = (r.extra?.lines || "").trim();
  if (lines && !/requires login/i.test(lines)) return lines.slice(0, 120);
  return readLine(r.path, r.start.line);
}

export function isSemgrepAvailable() {
  try {
    execFileSync("semgrep", ["--version"], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

export function runSemgrep(target) {
  const args = [];
  for (const c of CONFIGS) args.push("--config", c);
  for (const e of EXCLUDES) args.push("--exclude", e);
  // --no-git-ignore: Trinetra targets often live in git-ignored folders.
  args.push("--json", "--quiet", "--no-git-ignore", "--metrics=off", target);

  let out;
  try {
    out = execFileSync("semgrep", args, { maxBuffer: 256 * 1024 * 1024 }).toString();
  } catch (err) {
    // Semgrep exits non-zero when findings are present; stdout still holds JSON.
    out = err.stdout?.toString() ?? "";
    if (!out) throw err;
  }

  const parsed = JSON.parse(out);
  return (parsed.results ?? []).map((r) => ({
    rule: r.check_id.split(".").pop(),
    severity: SEV[r.extra?.severity] ?? "low",
    title: r.extra?.metadata?.shortDescription || r.check_id.split(".").pop().replace(/[_-]/g, " "),
    why: (r.extra?.message || "").trim().split("\n")[0] || "Flagged by Semgrep.",
    where: `${r.path}:${r.start.line}`,
    evidence: pickEvidence(r),
    engine: "semgrep",
  }));
}
