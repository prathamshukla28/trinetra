// Small helpers for locating and invoking external tools.

import fs from "node:fs";
import path from "node:path";

// Find an executable on PATH (like `which`). Returns an absolute path or null.
export function which(name, { env = process.env } = {}) {
  const exts = process.platform === "win32" ? (env.PATHEXT || ".EXE;.CMD;.BAT").split(";") : [""];
  for (const dir of (env.PATH || "").split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const full = path.join(dir, name + ext);
      try {
        fs.accessSync(full, fs.constants.X_OK);
        if (fs.statSync(full).isFile()) return full;
      } catch {
        /* keep looking */
      }
    }
  }
  return null;
}

// How to invoke a tool: JavaScript entry points run under the current Node
// binary (no reliance on shebangs, exec bits, or .cmd shims); anything else is
// executed directly.
export function commandFor(bin) {
  return /\.(c|m)?js$/.test(bin) ? { command: process.execPath, args: [bin] } : { command: bin, args: [] };
}
