import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { audit } from "../src/stages/audit.js";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("richer native rules flag the main binary weakness classes", async () => {
  const dir = path.join(ROOT, "reports", ".test-native-rules");
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
    const findings = await audit({ decompDir: "reports/.test-native-rules" }, {});
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
