// Identify executable formats by their magic bytes rather than file extension,
// so `Makefile`, shell scripts, and other extensionless text files are never
// mistaken for binaries (and real binaries named `foo.txt` still are).

import fs from "node:fs";

const MACHO_MAGICS = new Set([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe]);

// Classify the first bytes of a file. Returns "elf" | "macho" | "fat" | "pe" | null.
export function detectFormatFromBytes(buf) {
  if (!buf || buf.length < 4) return null;
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return "elf";

  const le = buf.readUInt32LE(0);
  if (MACHO_MAGICS.has(le)) return "macho";

  const be = buf.readUInt32BE(0);
  if (be === 0xcafebabe || be === 0xcafebabf) {
    // 0xCAFEBABE is shared with Java .class files. A fat header's next word is
    // the architecture count (small); a class file's is its version (>= 45).
    if (buf.length < 8) return null;
    const n = buf.readUInt32BE(4);
    return n > 0 && n < 45 ? "fat" : null;
  }

  if (buf[0] === 0x4d && buf[1] === 0x5a && buf.length >= 0x40) {
    const peOff = buf.readUInt32LE(0x3c);
    if (peOff + 4 <= buf.length && buf.readUInt32LE(peOff) === 0x00004550) return "pe";
  }
  return null;
}

// Read just enough of a file to classify it. Directories and unreadable files
// are never binaries.
export function detectFormat(file) {
  let fd;
  try {
    const stat = fs.statSync(file);
    if (!stat.isFile()) return null;
    fd = fs.openSync(file, "r");
    const buf = Buffer.alloc(Math.min(4096, stat.size));
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    return detectFormatFromBytes(buf.subarray(0, n));
  } catch {
    return null;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
  }
}

export const isNativeBinary = (file) => detectFormat(file) !== null;
