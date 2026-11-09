import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { audit } from "../src/stages/audit.js";

test("richer native rules flag the main binary weakness classes", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trinetra-decomp-"));
  const fnDir = path.join(dir, "functions");
  fs.mkdirSync(fnDir, { recursive: true });
  fs.writeFileSync(
    path.join(fnDir, "v.c"),
    [
      "void f(char *s, int n){",
      "  char b[8];",
      '  char *k = "AKIA1234567890ABCDEF";',
      "  _strcpy(b, s);",
      '  _system("ls");',
      "  _printf(s, n);",
      "  _memcpy(b, s, n);",
      '  _connect("http://evil.example.com/beacon");',
      "}",
    ].join("\n"),
  );
  try {
    const findings = await audit({ decompDir: dir }, {});
    const cats = new Set(findings.map((f) => f.rule));
    for (const r of [
      "native-unsafe-string",
      "native-command-exec",
      "native-embedded-secret",
      "native-format-string",
      "native-unsafe-memory",
      "native-embedded-url",
    ]) {
      assert.ok(cats.has(r), `expected ${r}`);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
