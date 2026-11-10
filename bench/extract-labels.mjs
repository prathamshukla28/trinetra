#!/usr/bin/env node
// Regenerate bench/labels/synthetic.json from the inline markers in bench/js:
//   `// expect: <rule> (note)` — this line is a true vulnerability for <rule>
//   `// ok: <rule> (note)`     — this line must NOT be reported for <rule>
// The labels file is what the benchmark reads; `npm run bench` fails if it has
// drifted from the markers, so edit the case files, then re-run this script.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const SYNTHETIC_DIR = path.join(HERE, "js");
export const SYNTHETIC_LABELS = path.join(HERE, "labels", "synthetic.json");

const MARKER = /\/\/\s*(expect|ok):\s*([a-z-]+)(?:\s*\((.*)\))?\s*$/;

export function listCaseFiles(dir = SYNTHETIC_DIR) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) walk(full);
      else if (/\.(c|m)?jsx?$/.test(e.name)) out.push(full);
    }
  };
  walk(dir);
  return out;
}

export function extractLabels(dir = SYNTHETIC_DIR) {
  const labels = [];
  for (const full of listCaseFiles(dir)) {
    const file = path.relative(dir, full).split(path.sep).join("/");
    const kind = file.split("/")[1]; // tp | fn-expected | tn
    fs.readFileSync(full, "utf8")
      .split("\n")
      .forEach((text, i) => {
        const m = text.match(MARKER);
        if (!m) return;
        labels.push({
          file,
          line: i + 1,
          rule: m[2],
          expected: m[1] === "expect",
          kind,
          ...(m[3] ? { note: m[3] } : {}),
        });
      });
  }
  return labels;
}

export const serializeLabels = (labels) => `${JSON.stringify(labels, null, 2)}\n`;

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const labels = extractLabels();
  fs.writeFileSync(SYNTHETIC_LABELS, serializeLabels(labels));
  console.log(`wrote ${labels.length} labels to ${path.relative(process.cwd(), SYNTHETIC_LABELS)}`);
}
