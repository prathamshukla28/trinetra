// Shared, pure helpers for the markdown and HTML report renderers.

export const SEV_ORDER = ["high", "medium", "low"];

export const esc = (s) =>
  String(s ?? "").replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
  );

// Markdown inline code that can't be broken out of by backticks in the content.
export const mdCode = (s) => {
  const text = String(s ?? "").replace(/\r?\n/g, " ");
  const fence = text.includes("`") ? "``" : "`";
  return `${fence}${fence === "``" ? ` ${text} ` : text}${fence}`;
};

export function countBySeverity(findings) {
  const c = { high: 0, medium: 0, low: 0 };
  for (const f of findings) c[f.severity] = (c[f.severity] || 0) + 1;
  return c;
}

const yesNo = (b) => (b ? "yes" : "no");

function signatureLabel(s) {
  const sig = s.codeSignature;
  if (!sig) return "none";
  if (sig.platformBinary) return "Apple platform binary";
  const parts = [sig.adhoc ? "ad-hoc" : sig.cms ? "signed" : "present"];
  if (sig.hardenedRuntime) parts.push("hardened runtime");
  return parts.join(", ");
}

// One row per architecture slice: the `checksec`-style summary.
export function hardeningRows(binary) {
  if (!binary) return [];
  return binary.slices.map((s) => {
    if (s.error)
      return {
        arch: s.arch,
        type: "unparsed",
        pie: "?",
        canary: "?",
        nx: "?",
        relro: "?",
        signature: s.error,
      };
    const imports = new Set(s.imports ?? []);
    const canary = imports.has("__stack_chk_fail") || imports.has("__stack_chk_guard");
    const fortify = (s.imports ?? []).filter((n) => /^__\w+_chk$/.test(n) && n !== "__stack_chk_fail").length;
    if (s.format === "pe")
      return {
        arch: s.arch,
        type: s.filetype,
        pie: yesNo(s.aslr),
        canary: "n/a",
        nx: yesNo(s.nx),
        relro: "n/a",
        signature: s.signed ? "Authenticode" : "none",
        extra: `CFG: ${yesNo(s.cfg)}`,
      };
    return {
      arch: s.arch,
      type: s.filetype,
      pie: yesNo(s.pie),
      canary: yesNo(canary),
      nx: s.format === "elf" ? yesNo(s.nx) : yesNo(!s.stackExecutable),
      relro: s.format === "elf" ? s.relro : "n/a",
      signature: s.format === "macho" ? signatureLabel(s) : "n/a",
      extra: fortify ? `FORTIFY: ${fortify} _chk import(s)` : "",
    };
  });
}

export const HARDENING_COLUMNS = [
  ["arch", "Arch"],
  ["type", "Type"],
  ["pie", "PIE/ASLR"],
  ["canary", "Stack canary"],
  ["nx", "NX"],
  ["relro", "RELRO"],
  ["signature", "Signature"],
  ["extra", "Notes"],
];

export function rebuildLines(rebuilt, rel) {
  if (!rebuilt) return null;
  const where = rel(rebuilt.outDir);
  if (rebuilt.mode === "scaffold")
    return {
      headline: `Scaffolded ${rebuilt.files.length} test-first stub file(s) in ${where}. Set ANTHROPIC_API_KEY for a model-generated reimplementation.`,
      items: [],
    };
  const counts = {};
  for (const v of rebuilt.verified) counts[v.status] = (counts[v.status] || 0) + 1;
  const tally = Object.entries(counts)
    .map(([k, n]) => `${n} ${k}`)
    .join(", ");
  return {
    headline:
      `Reimplemented ${rebuilt.verified.length} unit(s) test-first in ${where} — ${tally}.` +
      (rebuilt.executed ? "" : " Generated code was written but not executed (pass --run-generated)."),
    items: rebuilt.verified.map((v) => ({
      name: v.name,
      status: v.status,
      detail:
        v.reason ??
        (v.isolation
          ? `sandbox: env ${v.isolation.env}, fs ${rel(v.isolation.fs)}, network ${v.isolation.network}`
          : ""),
    })),
  };
}

export const STATUS_ICON = { passed: "✅", failed: "❌", timeout: "⏱️", blocked: "⛔", "not-run": "⏸️" };
