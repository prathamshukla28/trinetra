#!/usr/bin/env node
// Test double for the REA CLI: replays output recorded from rea-agents 6.8.0
// (test/fixtures/rea/). Selected via TRINETRA_REA_BIN.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const fx = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "rea");
const argv = process.argv.slice(2);
const [cmd, target] = argv;
if (process.env.FAKE_REA_LOG) fs.appendFileSync(process.env.FAKE_REA_LOG, `${JSON.stringify(argv)}\n`);

const progress = (phase) => JSON.stringify({ rea_progress: { phase, completed: 0, total: 1, sequence: 1 } });
process.stderr.write(`${progress(cmd)}\n`);

if (cmd === "analyze-javascript-application") {
  const rec = JSON.parse(fs.readFileSync(path.join(fx, "analyze-javascript-application.json"), "utf8"));
  rec.subject.local_path = target;
  rec.normalized_result.input_path = target;
  process.stdout.write(`${progress(cmd)}\n${JSON.stringify(rec)}\n`);
} else if (cmd === "decompile-all") {
  const out = argv[argv.indexOf("--output") + 1];
  if (fs.existsSync(out)) {
    process.stdout.write(`${JSON.stringify({ code: "E_OUTPUT_EXISTS", category: "usage", message: "output exists" })}\n`);
    process.exit(1);
  }
  fs.cpSync(path.join(fx, "decompile"), out, { recursive: true });
  const indexFile = path.join(out, "decompile-index.json");
  const index = JSON.parse(fs.readFileSync(indexFile, "utf8"));
  index.target_sha256 = "f".repeat(64);
  fs.writeFileSync(indexFile, JSON.stringify(index));
  process.stdout.write(`${JSON.stringify({ status: "complete", output: out })}\n`);
} else {
  process.stdout.write(`${JSON.stringify({ code: "E_USAGE", category: "usage", message: `unknown ${cmd}` })}\n`);
  process.exit(2);
}
