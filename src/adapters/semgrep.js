// Adapter for Semgrep — an external source scanner Trinetra delegates to when
// it is installed. Semgrep brings hundreds of community rules; Trinetra's own
// AST rules (src/analysis/js-ast.js) always run regardless.
//
// Execution and output parsing are separate so the parser can be tested
// against recorded Semgrep JSON.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { commandFor, which } from "../util/exec.js";

// Semgrep redacts matched snippets ("requires login") unless logged in. We have
// the file + line, so just read the real line ourselves.
function readLine(file, line) {
  try {
    return fs.readFileSync(file, "utf8").split("\n")[line - 1]?.trim().slice(0, 160) ?? "";
  } catch {
    return "";
  }
}

// A solid default security set. Registry packs are fetched + cached by Semgrep.
export const CONFIGS = ["p/security-audit", "p/secrets", "p/javascript", "p/nodejsscan"];

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
  if (lines && !/requires login/i.test(lines)) return lines.slice(0, 160);
  return readLine(r.path, r.start.line);
}

// $TRINETRA_SEMGREP_BIN overrides discovery (also how tests inject a recorder).
export function resolveSemgrepBin({ env = process.env } = {}) {
  if (env.TRINETRA_SEMGREP_BIN)
    return fs.existsSync(env.TRINETRA_SEMGREP_BIN) ? env.TRINETRA_SEMGREP_BIN : null;
  return which("semgrep", { env });
}

export const isSemgrepAvailable = (opts) => resolveSemgrepBin(opts) !== null;

// Map Semgrep's JSON output to Trinetra findings.
export function parseSemgrepOutput(json) {
  const parsed = typeof json === "string" ? JSON.parse(json) : json;
  return (parsed.results ?? []).map((r) => {
    const rule = r.check_id.split(".").pop();
    return {
      rule,
      severity: SEV[r.extra?.severity] ?? "low",
      title: r.extra?.metadata?.shortDescription || rule.replace(/[_-]/g, " "),
      why: (r.extra?.message || "").trim().split("\n")[0] || "Flagged by Semgrep.",
      where: `${r.path}:${r.start.line}`,
      evidence: pickEvidence(r),
      engine: "semgrep",
      confidence: (r.extra?.metadata?.confidence || "medium").toLowerCase(),
      ...(r.extra?.metadata?.cwe ? { cwe: [].concat(r.extra.metadata.cwe)[0] } : {}),
    };
  });
}

export function runSemgrep(target, { env = process.env, cwd = process.cwd() } = {}) {
  const bin = resolveSemgrepBin({ env });
  if (!bin) throw new Error("semgrep not found on PATH");
  const { command, args: pre } = commandFor(bin);
  const args = [...pre];
  for (const c of CONFIGS) args.push("--config", c);
  for (const e of EXCLUDES) args.push("--exclude", e);
  // --no-git-ignore: Trinetra targets often live in git-ignored folders.
  args.push("--json", "--quiet", "--no-git-ignore", "--metrics=off", target);

  let out;
  try {
    out = execFileSync(command, args, {
      cwd,
      env,
      maxBuffer: 256 * 1024 * 1024,
      timeout: Number(env.TRINETRA_SEMGREP_TIMEOUT_MS) || 20 * 60 * 1000,
      stdio: ["ignore", "pipe", "pipe"],
    }).toString();
  } catch (err) {
    // Semgrep exits non-zero when findings are present; stdout still holds JSON.
    out = err.stdout?.toString() ?? "";
    if (!out) throw err;
  }
  return parseSemgrepOutput(out);
}
