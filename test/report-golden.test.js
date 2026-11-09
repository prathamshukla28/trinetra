// Golden-file tests for the report renderers. Regenerate after an intentional
// change with:  UPDATE_GOLDEN=1 npm test   (then review the diff).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { renderMarkdown, writeReport } from "../src/report.js";
import { renderHtml, writeHtmlReport } from "../src/report-html.js";
import { renderCompareHtml, renderCompareMarkdown } from "../src/report-compare.js";
import { analyzeJs } from "../src/analysis/js-ast.js";
import { analyzeBinary } from "../src/binary/index.js";
import { understand } from "../src/stages/understand.js";
import { audit } from "../src/stages/audit.js";
import { diffTeardowns } from "../src/stages/compare.js";
import { engineTable } from "../src/pipeline.js";
import { buildElf } from "./helpers/binaries.js";
import { FIXTURES, ROOT, tempDir } from "./helpers/cli.js";

const GOLDEN = path.join(ROOT, "test", "golden");
const AT = "2026-01-01T00:00:00.000Z";
const rel = (p) => p.replace(/^\/out\//, "");

function golden(name, actual) {
  const file = path.join(GOLDEN, name);
  if (process.env.UPDATE_GOLDEN) {
    fs.mkdirSync(GOLDEN, { recursive: true });
    fs.writeFileSync(file, actual);
  }
  assert.equal(
    actual,
    fs.readFileSync(file, "utf8"),
    `${name} differs from golden (UPDATE_GOLDEN=1 to accept)`,
  );
}

async function sourceResult() {
  const text = fs.readFileSync(path.join(FIXTURES, "js", "sample-cli", "index.js"), "utf8");
  const js = [analyzeJs(text, "sample-cli/index.js")];
  const inspection = {
    engine: "trinetra-ast",
    kind: "source",
    root: "/t/sample-cli",
    files: ["/t/sample-cli/index.js"],
    units: js[0].functions.map((f) => ({ name: f.name, file: "sample-cli/index.js", line: f.line })),
    unitKind: "function",
    raw: [{ file: "/t/sample-cli/index.js", text }],
    js,
    provenance: { sha256: "a".repeat(64), provider: "Trinetra AST analyzer" },
    notes: [],
  };
  const map = await understand(inspection);
  const findings = await audit(inspection, map);
  const rebuilt = { mode: "scaffold", outDir: "/out/rebuilt/sample-cli", files: ["a", "b"], verified: [] };
  return {
    name: "sample-cli",
    target: "sample-cli",
    inspection,
    map,
    findings,
    engines: engineTable(
      inspection,
      { semgrep: "disabled (--no-semgrep)" },
      { opts: { useRea: false }, rebuilt },
    ),
    rebuilt,
    delta: {
      previousAt: "2025-12-31T00:00:00.000Z",
      contentChanged: true,
      new: [findings[0]],
      fixed: [
        {
          rule: "weak-hash",
          title: "Weak hashing algorithm (MD5 / SHA-1)",
          severity: "medium",
          where: "sample-cli/old.js:3",
        },
      ],
      unchanged: 4,
    },
    generatedAt: AT,
    rel,
  };
}

async function nativeResult() {
  const binary = analyzeBinary(
    buildElf({ type: 2, pieFlag: false, relro: false, bindNow: false, imports: ["gets", "puts"] }),
    {
      where: "bin/vuln",
    },
  );
  const inspection = {
    engine: "trinetra-binary",
    kind: "native",
    root: "/t/vuln",
    files: ["/t/vuln"],
    units: binary.imports.map((n) => ({ name: n })),
    unitKind: "import",
    raw: [],
    binary,
    provenance: { sha256: "b".repeat(64), provider: "Trinetra binary parser" },
    statistics: { imports: binary.imports.length, libraries: binary.libraries.length },
    notes: ["Decompilation skipped (--no-decompile)."],
  };
  const map = await understand(inspection);
  const findings = await audit(inspection, map, "bin/vuln");
  const rebuilt = {
    mode: "llm",
    executed: true,
    outDir: "/out/rebuilt/vuln",
    files: [],
    verified: [
      {
        name: "entry",
        status: "passed",
        passed: true,
        isolation: { env: "stripped", fs: "/out/sbx", network: "blocked (sandbox-exec)" },
      },
      { name: "helper", status: "blocked", passed: null, reason: "imports child_process" },
    ],
  };
  return {
    name: "vuln",
    target: "bin/vuln",
    inspection,
    map,
    findings,
    engines: engineTable(inspection, findings.engines, {
      opts: { decompile: false },
      ctx: { env: { TRINETRA_REA_BIN: "/none" } },
      rebuilt,
    }),
    rebuilt,
    delta: null,
    generatedAt: AT,
    rel,
  };
}

test("markdown report — source target", async () =>
  golden("source-report.md", renderMarkdown(await sourceResult())));
test("HTML report — source target", async () =>
  golden("source-report.html", renderHtml(await sourceResult())));
test("markdown report — native target", async () =>
  golden("native-report.md", renderMarkdown(await nativeResult())));
test("HTML report — native target", async () =>
  golden("native-report.html", renderHtml(await nativeResult())));

test("compare reports", () => {
  const diff = diffTeardowns(
    {
      name: "v1",
      inspection: { units: [{ name: "a" }, { name: "b" }] },
      findings: [{ rule: "weak-hash", title: "md5" }],
    },
    { name: "v2", inspection: { units: [{ name: "b" }, { name: "c" }] }, findings: [] },
  );
  golden("compare.md", renderCompareMarkdown(diff, AT));
  golden("compare.html", renderCompareHtml(diff, AT));
});

test("HTML escapes target-controlled text", async () => {
  const r = await sourceResult();
  r.name = `<img src=x onerror=alert(1)>`;
  r.findings = [{ ...r.findings[0], evidence: `</code><script>alert(1)</script>` }];
  const html = renderHtml(r);
  assert.ok(!html.includes("<script>alert(1)"));
  assert.ok(!html.includes("<img src=x"));
  assert.ok(html.includes("&lt;script&gt;"));
});

test("writers put files in the given output directory", async () => {
  const out = tempDir();
  const r = await sourceResult();
  assert.equal(writeReport(r, out), path.join(out, "sample-cli.md"));
  assert.equal(writeHtmlReport(r, out), path.join(out, "sample-cli.html"));
  assert.ok(
    fs.readFileSync(path.join(out, "sample-cli.md"), "utf8").startsWith("# Trinetra teardown — sample-cli"),
  );
});
