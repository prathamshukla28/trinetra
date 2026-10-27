// Renders the teardown report as a self-contained, styled HTML page.
// No external assets — it opens anywhere and prints cleanly.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPORT_DIR = path.join(ROOT, "reports");

const SEV_META = {
  high: { label: "HIGH", color: "#e5484d" },
  medium: { label: "MEDIUM", color: "#f5a623" },
  low: { label: "LOW", color: "#ebd41a" },
};

const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );

function countBySeverity(findings) {
  return findings.reduce((acc, f) => ((acc[f.severity] = (acc[f.severity] || 0) + 1), acc), {
    high: 0,
    medium: 0,
    low: 0,
  });
}

export function writeHtmlReport({ name, inspection, map, findings, rebuilt }) {
  fs.mkdirSync(REPORT_DIR, { recursive: true });
  const out = path.join(REPORT_DIR, `${name}.html`);
  const isNative = inspection.engine === "rea-native";
  const c = countBySeverity(findings);

  const tiles = [
    { label: isNative ? "Procedures" : "Units", value: inspection.units.length },
    { label: "Files", value: inspection.files.length },
    { label: "High", value: c.high, color: SEV_META.high.color },
    { label: "Medium", value: c.medium, color: SEV_META.medium.color },
    { label: "Low", value: c.low, color: SEV_META.low.color },
  ];

  const findingsHtml = findings.length
    ? findings
        .map((f) => {
          const m = SEV_META[f.severity] ?? SEV_META.low;
          return `<div class="finding">
  <div class="finding-head">
    <span class="badge" style="background:${m.color}">${m.label}</span>
    <span class="finding-title">${esc(f.title)}</span>
    <span class="engine">${esc(f.engines.join(" + "))}</span>
  </div>
  <div class="where">${esc(f.where)}</div>
  <p class="why">${esc(f.why)}</p>
  <pre class="evidence"><code>${esc(f.evidence)}</code></pre>
</div>`;
        })
        .join("\n")
    : `<p class="muted">No findings from the configured engines.</p>`;

  let whatItDoes;
  if (isNative) {
    const code = (inspection.overview || "")
      .split("\n")
      .filter((l) => !l.startsWith("//"))
      .join("\n")
      .trim();
    whatItDoes = `
      <ul class="proc-list">${map.behaviors.map((b) => `<li><code>${esc(b.name)}</code></li>`).join("")}</ul>
      ${code ? `<h3>Sample decompiled function — <code>${esc(inspection.sampleName)}</code></h3><pre class="code"><code>${esc(code)}</code></pre>` : ""}`;
  } else {
    whatItDoes = `<ul class="behaviors">${map.behaviors
      .map(
        (b) =>
          `<li><code>${esc(b.name)}</code> — ${esc(b.guess)} <span class="muted">${esc(b.where)}</span></li>`,
      )
      .join("")}</ul>`;
  }

  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Trinetra · ${esc(name)}</title>
<style>
  :root { --bg:#ffffff; --fg:#18181b; --muted:#71717a; --card:#f4f4f5; --border:#e4e4e7; --accent:#7c3aed; --code:#f4f4f5; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0b0b0f; --fg:#e4e4e7; --muted:#a1a1aa; --card:#18181b; --border:#27272a; --accent:#a78bfa; --code:#101014; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:920px; margin:0 auto; padding:40px 20px 80px; }
  .eye { font-size:28px; }
  h1 { font-size:26px; margin:6px 0 2px; letter-spacing:-0.02em; }
  h1 .name { color:var(--accent); }
  .sub { color:var(--muted); margin:0 0 24px; font-size:13px; }
  .meta { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:14px 18px; margin-bottom:24px; font-size:13px; }
  .meta div { margin:3px 0; }
  .meta code { word-break:break-all; }
  .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(110px,1fr)); gap:12px; margin-bottom:32px; }
  .tile { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; text-align:center; }
  .tile .v { font-size:28px; font-weight:700; }
  .tile .l { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:0.05em; }
  h2 { font-size:18px; margin:32px 0 14px; padding-bottom:8px; border-bottom:1px solid var(--border); }
  .finding { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; margin-bottom:14px; }
  .finding-head { display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
  .badge { color:#fff; font-size:11px; font-weight:700; padding:2px 8px; border-radius:999px; }
  .finding-title { font-weight:600; }
  .engine { margin-left:auto; font-size:11px; color:var(--muted); border:1px solid var(--border); border-radius:999px; padding:1px 8px; }
  .where { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; color:var(--muted); margin:6px 0; }
  .why { margin:6px 0; }
  pre { background:var(--code); border:1px solid var(--border); border-radius:8px; padding:12px; overflow:auto; font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace; }
  .evidence { margin:6px 0 0; }
  .behaviors, .proc-list { padding-left:18px; }
  .proc-list { columns:2; }
  .muted { color:var(--muted); }
  footer { margin-top:48px; color:var(--muted); font-size:12px; text-align:center; }
</style>
</head>
<body>
<div class="wrap">
  <div class="eye">🔱</div>
  <h1><span class="name">Trinetra</span> teardown — ${esc(name)}</h1>
  <p class="sub">Generated ${new Date().toISOString()} · engine: ${esc(inspection.engine)}</p>

  <div class="meta">
    ${inspection.provenance?.sha256 ? `<div>🔑 SHA-256: <code>${esc(inspection.provenance.sha256)}</code></div>` : ""}
    ${inspection.provenance?.provider ? `<div>🔬 Analyzed by: ${esc(inspection.provenance.provider)}</div>` : ""}
    ${inspection.decompDir ? `<div>📂 Full pseudocode: <code>${esc(inspection.decompDir)}/</code></div>` : ""}
  </div>

  <div class="tiles">
    ${tiles.map((t) => `<div class="tile"><div class="v" ${t.color ? `style="color:${t.color}"` : ""}>${t.value}</div><div class="l">${t.label}</div></div>`).join("")}
  </div>

  <h2>What it does</h2>
  ${whatItDoes}

  <h2>Security findings</h2>
  ${findingsHtml}

  <h2>Rebuild</h2>
  ${
    rebuilt && rebuilt.mode === "llm"
      ? `<p>Reimplemented <strong>${rebuilt.verified.length}</strong> unit(s), test-first — <strong>${rebuilt.verified.filter((v) => v.passed).length} passing</strong> — in <code>${esc(path.relative(ROOT, rebuilt.outDir))}</code>.</p>
         <ul>${rebuilt.verified.map((v) => `<li>${v.passed ? "✅" : "⚠️"} <code>${esc(v.name)}</code></li>`).join("")}</ul>`
      : rebuilt
        ? `<p class="muted">Scaffolded ${rebuilt.files.length} test-first stub(s) in <code>${esc(path.relative(ROOT, rebuilt.outDir))}</code>. Set <code>ANTHROPIC_API_KEY</code> for a real reimplementation.</p>`
        : `<p class="muted">Not run. Pass <code>--rebuild</code> to generate a clean, tested reimplementation.</p>`
  }

  <footer>Generated by Trinetra — the third eye that sees inside any software.</footer>
</div>
</body>
</html>`;

  fs.writeFileSync(out, html);
  return path.relative(ROOT, out);
}
