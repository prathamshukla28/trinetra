// Random-access byte sources for the binary parsers. Parsers only ever ask for
// (offset, length) windows, so large binaries are never read into memory whole.

import fs from "node:fs";

export class BufferSource {
  constructor(buf) {
    this.buf = buf;
    this.size = buf.length;
  }

  read(offset, length) {
    if (offset < 0 || offset >= this.size) return Buffer.alloc(0);
    return this.buf.subarray(offset, Math.min(this.size, offset + length));
  }

  close() {}
}

export class FileSource {
  constructor(file) {
    this.fd = fs.openSync(file, "r");
    this.size = fs.fstatSync(this.fd).size;
  }

  read(offset, length) {
    if (offset < 0 || offset >= this.size || length <= 0) return Buffer.alloc(0);
    const len = Math.min(length, this.size - offset);
    const buf = Buffer.alloc(len);
    const n = fs.readSync(this.fd, buf, 0, len, offset);
    return buf.subarray(0, n);
  }

  close() {
    fs.closeSync(this.fd);
  }
}

// Read a NUL-terminated string from a buffer (bounded by the buffer's end).
export function cstring(buf, offset, max = 4096) {
  if (offset < 0 || offset >= buf.length) return "";
  let end = offset;
  const limit = Math.min(buf.length, offset + max);
  while (end < limit && buf[end] !== 0) end++;
  return buf.toString("latin1", offset, end);
}

// A source restricted to a window of another source (a slice of a fat binary).
export class SliceSource {
  constructor(parent, base, size) {
    this.parent = parent;
    this.base = base;
    this.size = Math.max(0, Math.min(size, parent.size - base));
  }

  read(offset, length) {
    if (offset < 0 || offset >= this.size) return Buffer.alloc(0);
    return this.parent.read(this.base + offset, Math.min(length, this.size - offset));
  }

  close() {}
}
