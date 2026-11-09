// Run-to-run memory: one JSON file per target under <out>/.memory/. Each
// teardown recalls the previous run of the *same target* (identified by its
// resolved path) and reports what changed since: whether the content hash
// moved, and which findings are new, fixed, or still present.
//
// Findings are fingerprinted by (category, file relative to the target,
// normalized evidence) — not line number — so unrelated edits that shift lines
// don't make every finding look new.

import fs from "node:fs";
import path from "node:path";
import { canonical } from "./stages/audit.js";
import { safeName } from "./context.js";
import { sha256Text } from "./util/hash.js";

const FILE_VERSION = 2;

export function targetId(root) {
  return sha256Text(path.resolve(root)).slice(0, 16);
}

// Stable identity for a finding across runs.
export function fingerprint(f, rootLabel = "") {
  const file = f.where.replace(/:\d+$/, "");
  const relFile =
    rootLabel && file.startsWith(rootLabel) ? file.slice(rootLabel.length).replace(/^[\\/]/, "") : file;
  const evidence = String(f.evidence ?? "")
    .replace(/\s+/g, " ")
    .trim();
  return sha256Text(`${canonical(f)}|${relFile}|${evidence}`).slice(0, 20);
}

export class Memory {
  constructor(ctx, root, name = path.basename(root)) {
    this.root = path.resolve(root);
    this.id = targetId(this.root);
    this.file = path.join(ctx.memoryDir, `${safeName(name)}-${this.id}.json`);
    this.rootLabel = ctx.rel(this.root);
    this.data = null;
    try {
      const parsed = JSON.parse(fs.readFileSync(this.file, "utf8"));
      if (parsed.version === FILE_VERSION) this.data = parsed;
    } catch {
      /* first run, or unreadable — start fresh */
    }
  }

  // The previous run's record, or null on the first teardown of this target.
  recall() {
    return this.data?.last ?? null;
  }

  // Compare this run against the recalled one.
  diff({ sha256, findings }) {
    const prev = this.recall();
    if (!prev) return null;
    const now = new Map(findings.map((f) => [fingerprint(f, this.rootLabel), f]));
    const before = new Map(prev.findings.map((f) => [f.id, f]));
    return {
      previousAt: prev.at,
      contentChanged: prev.sha256 !== sha256,
      previousSha256: prev.sha256,
      new: [...now].filter(([id]) => !before.has(id)).map(([, f]) => summarize(f)),
      fixed: [...before].filter(([id]) => !now.has(id)).map(([, f]) => f),
      unchanged: [...now.keys()].filter((id) => before.has(id)).length,
    };
  }

  // Persist this run as the new baseline.
  save({ sha256, findings, engine, at = new Date().toISOString() }) {
    const record = {
      at,
      sha256,
      engine,
      findings: findings.map((f) => ({ id: fingerprint(f, this.rootLabel), ...summarize(f) })),
    };
    const data = {
      version: FILE_VERSION,
      target: this.root,
      firstSeen: this.data?.firstSeen ?? at,
      runs: (this.data?.runs ?? 0) + 1,
      last: record,
    };
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    fs.writeFileSync(this.file, JSON.stringify(data, null, 2));
    this.data = data;
  }
}

const summarize = (f) => ({ rule: f.rule, severity: f.severity, title: f.title, where: f.where });
