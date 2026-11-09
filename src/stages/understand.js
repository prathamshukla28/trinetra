// Stage 2 — UNDERSTAND. Turn INSPECT's facts into a map of what the target
// *does*: its dependencies, public surface, entry points, and which functions
// exercise sensitive capabilities (shell, eval, filesystem, network, env, …).
//
// Source targets: built from the AST analyzer's imports/exports/call sites.
// Native targets: built from parsed imports and linked libraries, plus the
// procedure list when REA/Ghidra decompiled the binary.

import { builtinModules } from "node:module";

const BUILTINS = new Set(builtinModules.flatMap((m) => [m, `node:${m}`]));

// Capabilities worth calling out first (attack surface), in order.
const RISK_ORDER = [
  "runs shell commands / processes",
  "evaluates dynamic code",
  "handles HTTP request input",
  "reads command-line arguments",
  "reads environment variables",
  "writes to the filesystem",
  "reads the filesystem",
  "makes network requests",
  "opens raw network sockets",
  "serves HTTP",
  "process execution",
  "network",
  "dynamic loading",
  "privilege / debugging",
  "memory protection changes",
  "filesystem",
  "environment",
];
const rank = (c) => {
  const i = RISK_ORDER.indexOf(c);
  return i < 0 ? RISK_ORDER.length : i;
};

const list = (xs, max = 6) =>
  xs.length > max ? `${xs.slice(0, max).join(", ")}, +${xs.length - max} more` : xs.join(", ");

function describeFunction(fn) {
  const caps = Object.entries(fn.capabilities).sort(([a], [b]) => rank(a) - rank(b));
  if (caps.length === 0) return "no sensitive APIs observed (pure logic / internal calls)";
  return caps.map(([cap, via]) => `${cap} (${via.join(", ")})`).join("; ");
}

function understandSource(inspection) {
  const js = inspection.js ?? [];
  const modules = new Map();
  for (const a of js) for (const i of a.imports) modules.set(i.module, (modules.get(i.module) ?? 0) + 1);
  const builtin = [...modules.keys()].filter((m) => BUILTINS.has(m)).sort();
  const external = [...modules.keys()]
    .filter((m) => !BUILTINS.has(m) && !m.startsWith(".") && !m.startsWith("/"))
    .sort();

  const behaviors = [];
  const capabilities = {};
  for (const a of js) {
    for (const fn of [...a.functions, { ...a.topLevel, name: "(top level)" }]) {
      const isTop = fn.name === "(top level)";
      if (isTop && Object.keys(fn.capabilities).length === 0) continue;
      for (const [cap, via] of Object.entries(fn.capabilities)) {
        (capabilities[cap] ??= []).push(`${fn.name} → ${via.join(", ")}`);
      }
      behaviors.push({
        name: isTop ? `${a.file} (top level)` : fn.name,
        where: `${a.file}:${fn.line}`,
        exported: fn.exported,
        capabilities: Object.keys(fn.capabilities),
        summary: describeFunction(fn),
        // kept for older report consumers
        guess: describeFunction(fn),
      });
    }
  }

  const exports = js.flatMap((a) => a.exports.map((e) => `${e}`));
  const entryPoints = behaviors.filter((b) => b.exported || / handler$/.test(b.name)).map((b) => b.name);
  const unparsed = js.filter((a) => !a.parsed).length;
  const fnCount = js.reduce((n, a) => n + a.functions.length, 0);

  const summary = [];
  summary.push(
    `${inspection.files.length} source file(s), ${fnCount} function(s)` +
      (unparsed ? ` (${unparsed} file(s) could not be parsed as JavaScript)` : "") +
      (inspection.engine === "rea-javascript-application"
        ? `; REA recovered ${inspection.units.length} unit(s)`
        : "") +
      ".",
  );
  if (builtin.length || external.length)
    summary.push(
      `Depends on ${builtin.length ? `Node built-ins ${list(builtin)}` : "no Node built-ins"}` +
        (external.length ? ` and packages ${list(external)}` : "") +
        ".",
    );
  if (exports.length) summary.push(`Public surface: ${list(exports, 10)}.`);
  const ranked = Object.keys(capabilities).sort((a, b) => rank(a) - rank(b));
  if (ranked.length) {
    summary.push(
      `Capabilities: ${ranked.map((c) => `${c} in ${list([...new Set(capabilities[c].map((x) => x.split(" → ")[0]))], 3)}`).join("; ")}.`,
    );
  } else {
    summary.push("No sensitive capabilities (shell, eval, filesystem, network, environment) were observed.");
  }

  return { imports: { builtin, external }, exports, entryPoints, capabilities, behaviors, summary };
}

function understandNative(inspection) {
  const b = inspection.binary;
  const summary = [];
  const fmt = { macho: "Mach-O", fat: "universal Mach-O", elf: "ELF", pe: "PE" }[b.format] ?? b.format;
  const first = b.slices.find((s) => !s.error) ?? {};
  summary.push(`${fmt} ${first.filetype ?? "binary"} (${b.archs.join(", ")}).`);
  if (b.libraries.length) summary.push(`Links ${list(b.libraries.map((l) => l.split("/").pop()))}.`);
  summary.push(`Imports ${b.imports.length} function(s).`);
  const caps = Object.entries(b.capabilities).sort(([a], [c]) => rank(a) - rank(c));
  if (caps.length)
    summary.push(
      `Capabilities from imports: ${caps.map(([c, fns]) => `${c} (${list(fns, 4)})`).join("; ")}.`,
    );
  if (inspection.engine === "rea-native")
    summary.push(
      `Ghidra (via REA) recovered ${inspection.statistics?.procedures ?? inspection.units.length} procedure(s).`,
    );

  const behaviors =
    inspection.unitKind === "procedure"
      ? inspection.units.map((u) => ({
          name: u.name,
          where: u.source,
          exported: false,
          capabilities: [],
          summary: "decompiled procedure",
          guess: "decompiled procedure",
        }))
      : caps.flatMap(([cap, fns]) =>
          fns.map((fn) => ({
            name: fn,
            where: "import",
            exported: false,
            capabilities: [cap],
            summary: cap,
            guess: cap,
          })),
        );

  return {
    imports: { libraries: b.libraries, functions: b.imports },
    exports: [],
    entryPoints: [],
    capabilities: Object.fromEntries(caps),
    behaviors,
    summary,
  };
}

export async function understand(inspection) {
  const base = { engine: inspection.engine, kind: inspection.kind, fileCount: inspection.files.length };
  if (inspection.kind === "native") return { ...base, ...understandNative(inspection) };
  if (inspection.kind === "asar")
    return {
      ...base,
      imports: {},
      exports: [],
      entryPoints: [],
      capabilities: {},
      behaviors: inspection.units.map((u) => ({
        name: u.name,
        where: `${u.file}:${u.line}`,
        exported: false,
        capabilities: [],
        summary: "recovered by REA",
        guess: "recovered by REA",
      })),
      summary: [`Packed archive reconstructed by REA: ${inspection.units.length} function(s).`],
    };
  return { ...base, ...understandSource(inspection) };
}
