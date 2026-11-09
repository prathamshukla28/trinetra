// Content fingerprints for targets (used for provenance and run-to-run memory).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export function sha256File(file) {
  const h = crypto.createHash("sha256");
  const fd = fs.openSync(file, "r");
  try {
    const buf = Buffer.alloc(1024 * 1024);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally {
    fs.closeSync(fd);
  }
  return h.digest("hex");
}

// Directory fingerprint: hash of (relative path, file hash) pairs, order-independent.
export function sha256Files(root, files) {
  const h = crypto.createHash("sha256");
  const entries = files.map((f) => [path.relative(root, f).split(path.sep).join("/"), sha256File(f)]).sort();
  for (const [rel, digest] of entries) h.update(`${rel}\0${digest}\n`);
  return h.digest("hex");
}

export const sha256Text = (s) => crypto.createHash("sha256").update(s).digest("hex");
