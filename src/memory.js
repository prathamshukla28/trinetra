// A tiny persistent memory store — one JSON file per analyzed target.
// Stands in for the memory layer from everything-claude-code: Trinetra remembers
// what it learned about each target across runs.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const MEM_DIR = path.join(ROOT, "reports", ".memory");

export class Memory {
  constructor(targetName) {
    this.targetName = targetName;
    this.file = path.join(MEM_DIR, `${targetName}.json`);
    fs.mkdirSync(MEM_DIR, { recursive: true });
    this.data = fs.existsSync(this.file)
      ? JSON.parse(fs.readFileSync(this.file, "utf8"))
      : { target: targetName, firstSeen: new Date().toISOString(), notes: {} };
  }

  remember(key, value) {
    this.data.notes[key] = value;
    this.data.lastSeen = new Date().toISOString();
    fs.writeFileSync(this.file, JSON.stringify(this.data, null, 2));
  }

  recall(key) {
    return this.data.notes[key];
  }
}
