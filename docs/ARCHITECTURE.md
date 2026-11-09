# Architecture

Trinetra owns target routing, its own JavaScript and binary analysis, correlation,
run-to-run memory, and reporting. It delegates decompilation and JS-application
reconstruction to REA (→ Ghidra), community rules to Semgrep, and code generation to
Claude — each behind one adapter file.

## The pipeline

```
          ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌──────────┐
 TARGET → │ INSPECT  │ → │ UNDERSTAND│ → │  AUDIT   │ → │ REBUILD  │ → REPORT (md · html · json)
          └──────────┘   └───────────┘   └──────────┘   └──────────┘        ▲
                                                              memory diff ──┘
```

`src/cli.js` parses arguments and builds a run context (`src/context.js`): the
caller's cwd, the output directory, and engine configuration with precedence
**flag > env > ./trinetra.config.json > default**. Nothing is ever written inside
the package directory.

| Stage | File | Responsibility |
| --- | --- | --- |
| Inspect | `src/stages/inspect.js` | Route by content; collect units + evidence. |
| Understand | `src/stages/understand.js` | Imports, exports, entry points, per-function capabilities, summary. |
| Audit | `src/stages/audit.js` | Gather findings from every engine; `correlate()` them. |
| Rebuild | `src/stages/rebuild.js` | Claude-generated test+impl (written; executed only with `--run-generated`, in `src/sandbox.js`) or scaffolded stubs. |
| Compare | `src/stages/compare.js` | Diff two inspections + finding categories. |
| Memory | `src/memory.js` | Recall the previous run of the same target; new / fixed / unchanged. |

## Routing (Inspect)

- **Native** — `src/binary/magic.js` recognises ELF, Mach-O, fat Mach-O, and PE by
  magic bytes (Java `.class` files share `CAFEBABE` and are excluded). `.app`
  directories resolve to `Contents/MacOS/<CFBundleExecutable>`. Trinetra always
  parses the binary itself (`src/binary/`); if REA is available and decompilation
  isn't disabled, fat binaries are thinned in JS and REA's `decompile-all` runs
  Ghidra into `<out>/.work/rea-decomp/<name>/`.
- **`.asar`** — REA's JavaScript application analyzer.
- **Source** — every JS file goes through `src/analysis/js-ast.js`. For small trees
  without `node_modules`, REA's semantic graph supplies the unit list too.

## Own analysis

- `src/analysis/js-ast.js` — acorn parse → binding resolution (imports, requires,
  destructuring) → a walk that keeps a per-function taint map and applies sink rules
  → facts (imports, exports, functions, capabilities) for UNDERSTAND. Unparseable
  files fall back to credential/weak-hash line checks (`trinetra-regex`).
- `src/binary/` — positional readers (`source.js`) so large binaries aren't loaded
  whole; `macho.js` (load commands, symtab + chained-fixups imports, code-signature
  SuperBlob), `elf.js` (program headers, dynamic section, `.dynsym`), `pe.js`
  (DllCharacteristics, import directory, certificate table); `index.js` derives
  hardening findings and capabilities and merges findings across fat slices.

## Adapters

- `src/adapters/rea.js` — resolves the REA CLI from `$TRINETRA_REA_BIN`, then the
  installed `rea-agents` package (via `createRequire`, so hoisted global installs
  work), then `rea` on PATH. JS bins run under the current Node. Parsing
  (`parseReaStdout`, `parseReaJsRecord`, `parseDecompileDir`) is separate from
  execution and tested against recorded output.
- `src/adapters/semgrep.js` — registry packs, vendored dirs excluded;
  `parseSemgrepOutput` is tested against recorded output.
- `src/adapters/llm.js` — Claude via the Anthropic SDK; untrusted content fenced.

## Findings and correlation

Each finding carries `rule`, `severity`, `confidence`, `engine`, `where`
(cwd-relative), `evidence`, and optionally `function` and `taint`. `correlate()`
groups by location + `canonical()` concept; agreement between engines raises
confidence to high.

## Reports

`report.js` / `report-html.js` / `report-compare.js` export pure renderers
(`renderMarkdown`, `renderHtml`, …) that take an explicit timestamp, so they're
covered by golden-file tests in `test/golden/` (`UPDATE_GOLDEN=1 npm test` to
regenerate after an intentional change).

## Extending

- **JS rule** → add metadata to `RULES` and a check in `checkCall`/`walk` in
  `js-ast.js`; extend `canonical()` if it should correlate with other engines.
- **Binary check** → add to `sliceFindings` in `src/binary/index.js`; add a builder
  case in `test/helpers/binaries.js`.
- **Engine** → new adapter in `src/adapters/`, keep parsing separate from execution,
  record a fixture, add a replaying stand-in under `test/fixtures/bin/`.
