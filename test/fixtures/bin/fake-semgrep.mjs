#!/usr/bin/env node
// Test double for Semgrep: replays JSON recorded from semgrep 1.181.0 on the
// sample app, re-rooted at the scanned target. Selected via TRINETRA_SEMGREP_BIN.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const argv = process.argv.slice(2);
if (argv.includes("--version")) {
  console.log("1.181.0");
  process.exit(0);
}
const target = argv.at(-1);
const file = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "semgrep", "sample-cli.json");
const out = fs.readFileSync(file, "utf8").replaceAll("<target>", target.replaceAll("\\", "\\\\"));
process.stdout.write(out);
// Semgrep can exit non-zero with findings; the adapter must still read stdout.
process.exit(1);
