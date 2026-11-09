// Self-contained, styled HTML teardown report (no external assets). Every
// value derived from the target is escaped. `renderHtml` is pure.

import fs from "node:fs";
import path from "node:path";
import { safeName } from "./context.js";
import {
  countBySeverity,
  esc,
  HARDENING_COLUMNS,
  hardeningRows,
  rebuildLines,
  STATUS_ICON,
} from "./report-common.js";

const SEV_META = {
  high: { label: "HIGH", color: "#e5484d" },
  medium: { label: "MEDIUM", color: "#f5a623" },
  low: { label: "LOW", color: "#c9a800" },
};

const STYLE = `
  :root { --bg:#ffffff; --fg:#18181b; --muted:#71717a; --card:#f4f4f5; --border:#e4e4e7; --accent:#7c3aed; --code:#f4f4f5; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#0b0b0f; --fg:#e4e4e7; --muted:#a1a1aa; --card:#18181b; --border:#27272a; --accent:#a78bfa; --code:#101014; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
  .wrap { max-width:960px; margin:0 auto; padding:40px 16px 80px; }
  h1 { font-size:26px; margin:6px 0 2px; letter-spacing:-0.02em; }
  h1 .name { color:var(--accent); }
  .sub { color:var(--muted); margin:0 0 24px; font-size:13px; }
  .meta { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:14px 18px; margin-bottom:24px; font-size:13px; }
  .meta div { margin:3px 0; }
  code { word-break:break-all; }
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
  .scroll { overflow-x:auto; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { padding:6px 8px; border-bottom:1px solid var(--border); text-align:left; vertical-align:top; }
  .muted { color:var(--muted); }
  footer { margin-top:48px; color:var(--muted); font-size:12px; text-align:center; }`;

function table(headers, rows) {
  return `<div class="scroll"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join("")}</tr></thead><tbody>${rows
    .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join("")}</tr>`)
    .join("")}</tbody></table></div>`;
}

export function renderHtml(r) {
  const { name, inspection, map, findings } = r;
  const rel = r.rel ?? ((p) => p);
  const isNative = inspection.kind === "native";
  const c = countBySeverity(findings);

  const tiles = [
    {
      label: isNative ? (inspection.unitKind === "procedure" ? "Procedures" : "Imports") : "Units",
      value: inspection.units.length,
    },
    { label: "Files", value: inspection.files.length },
    { label: "High", value: c.high, color: SEV_META.high.color },
    { label: "Medium", value: c.medium, color: SEV_META.medium.color },
    { label: "Low", value: c.low, color: SEV_META.low.color },
  ];

  const meta = [
    r.target ? `<div>Target: <code>${esc(r.target)}</code> (${esc(inspection.kind)})</div>` : "",
    inspection.provenance?.sha256
      ? `<div>SHA-256: <code>${esc(inspection.provenance.sha256)}</code></div>`
      : "",
    inspection.provenance?.provider ? `<div>Analyzed by: ${esc(inspection.provenance.provider)}</div>` : "",
    inspection.decompDir ? `<div>Full pseudocode: <code>${esc(rel(inspection.decompDir))}/</code></div>` : "",
    ...(inspection.notes ?? []).map((n) => `<div class="muted">Note: ${esc(n)}</div>`),
  ].join("\n    ");

  const hRows = hardeningRows(inspection.binary);
  const hardening = hRows.length
    ? `<h2>Binary hardening</h2>${table(
        HARDENING_COLUMNS.map(([, h]) => h),
        hRows.map((row) => HARDENING_COLUMNS.map(([k]) => esc(row[k] || ""))),
      )}`
    : "";

  const summary = (map.summary ?? []).length
    ? `<ul>${map.summary.map((s) => `<li>${esc(s)}</li>`).join("")}</ul>`
    : "";
  let whatItDoes = summary;
  if (!isNative) {
    const interesting = (map.behaviors ?? []).filter((b) => b.capabilities?.length || b.exported);
    if (interesting.length)
      whatItDoes += table(
        ["Function", "Where", "Exported", "What it touches"],
        interesting.map((b) => [
          `<code>${esc(b.name)}</code>`,
          `<code>${esc(b.where)}</code>`,
          b.exported ? "yes" : "",
          esc(b.summary),
        ]),
      );
  } else if (inspection.engine === "rea-native") {
    const code = (inspection.overview || "")
      .split("\n")
      .filter((l) => !l.startsWith("//"))
      .join("\n")
      .trim();
    whatItDoes += `<ul class="proc-list">${map.behaviors.map((b) => `<li><code>${esc(b.name)}</code></li>`).join("")}</ul>
      ${code ? `<h3>Sample decompiled function — <code>${esc(inspection.sampleName)}</code></h3><pre><code>${esc(code)}</code></pre>` : ""}`;
  }

  const findingsHtml = findings.length
    ? findings
        .map((f) => {
          const m = SEV_META[f.severity] ?? SEV_META.low;
          return `<div class="finding">
  <div class="finding-head">
    <span class="badge" style="background:${m.color}">${m.label}</span>
    <span class="finding-title">${esc(f.title)}</span>
    <span class="engine">${esc((f.engines ?? [f.engine]).join(" + "))} · ${esc(f.confidence ?? "medium")} confidence</span>
  </div>
  <div class="where">${esc(f.where)}${f.function ? ` in ${esc(f.function)}` : ""}</div>
  ${f.taint ? `<div class="where">data flow: ${esc(f.taint.source)} → ${esc(f.taint.sink)}</div>` : ""}
  <p class="why">${esc(f.why)}</p>
  <pre class="evidence"><code>${esc(f.evidence)}</code></pre>
</div>`;
        })
        .join("\n")
    : `<p class="muted">No findings from the engines that ran.</p>`;

  let delta;
  if (!r.delta) delta = `<p class="muted">First teardown of this target — this run is now the baseline.</p>`;
  else {
    const d = r.delta;
    delta = `<p>Compared with ${esc(d.previousAt)}: content ${d.contentChanged ? "<strong>changed</strong>" : "unchanged"}; <strong>${d.new.length}</strong> new, <strong>${d.fixed.length}</strong> fixed, ${d.unchanged} unchanged.</p>
  <ul>${d.new.map((f) => `<li>new: ${esc(f.title)} — <code>${esc(f.where)}</code></li>`).join("")}${d.fixed
    .map((f) => `<li>fixed: ${esc(f.title)} — <code>${esc(f.where)}</code></li>`)
    .join("")}</ul>`;
  }

  const rb = rebuildLines(r.rebuilt, rel);
  const rebuild = rb
    ? `<p>${esc(rb.headline)}</p>${rb.items.length ? `<ul>${rb.items.map((i) => `<li>${STATUS_ICON[i.status] ?? ""} <code>${esc(i.name)}</code> — ${esc(i.status)}${i.detail ? ` <span class="muted">(${esc(i.detail)})</span>` : ""}</li>`).join("")}</ul>` : ""}`
    : `<p class="muted">Not run. Pass <code>--rebuild</code> to generate a test-first reimplementation.</p>`;

  const engines = r.engines?.length
    ? `<h2>Engines</h2>${table(
        ["Engine", "Provided by", "Status"],
        r.engines.map((e) => [esc(e.name), esc(e.owner), esc(e.status)]),
      )}`
    : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Trinetra · ${esc(name)}</title>
<style>${STYLE}
</style>
</head>
<body>
<div class="wrap">
  <h1><span class="name">Trinetra</span> teardown — ${esc(name)}</h1>
  <p class="sub">Generated ${esc(r.generatedAt)} · engine: ${esc(inspection.engine)}</p>

  <div class="meta">
    ${meta}
  </div>

  <div class="tiles">
    ${tiles.map((t) => `<div class="tile"><div class="v" ${t.color ? `style="color:${t.color}"` : ""}>${t.value}</div><div class="l">${t.label}</div></div>`).join("")}
  </div>
  ${hardening}

  <h2>What it does</h2>
  ${whatItDoes}

  <h2>Security findings</h2>
  ${findingsHtml}

  <h2>Since last run</h2>
  ${delta}

  <h2>Rebuild</h2>
  ${rebuild}
  ${engines}

  <footer>Generated by Trinetra.</footer>
</div>
</body>
</html>
`;
}

export function writeHtmlReport(result, outDir) {
  fs.mkdirSync(outDir, { recursive: true });
  const out = path.join(outDir, `${safeName(result.name)}.html`);
  fs.writeFileSync(out, renderHtml(result));
  return out;
}
