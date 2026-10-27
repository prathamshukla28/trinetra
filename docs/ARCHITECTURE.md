# Architecture

Trinetra is a thin **conductor** over established reverse-engineering and security
engines. It owns orchestration, correlation, and reporting; it does not reinvent
analysis.

## The pipeline

```
          ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌──────────┐
 TARGET → │ INSPECT  │ → │ UNDERSTAND│ → │  AUDIT   │ → │ REBUILD  │ → REPORT
          └──────────┘   └───────────┘   └──────────┘   └──────────┘   (md + html)
```

Entry point `src/cli.js` parses the command and calls `src/pipeline.js`, which runs
the stages in order and threads the result into the report writers.

| Stage | File | Responsibility |
| --- | --- | --- |
| Inspect | `src/stages/inspect.js` | Turn a target into units + evidence. Routes by target type (see below). |
| Understand | `src/stages/understand.js` | Summarize units into a behavior map; persist to memory. |
| Audit | `src/stages/audit.js` | Run every applicable engine, then correlate findings. |
| Rebuild | `src/stages/rebuild.js` | Regenerate code test-first (optional, `--rebuild`). |
| Compare | `src/stages/compare.js` | Diff two teardowns. |

## Routing (Inspect)

`inspect()` picks a path by target shape:

- **Native binary** (`.exe`/`.dylib`/extensionless/…) → `reaInspectNative` (Ghidra
  decompile). Universal Mach-O is auto-thinned to the host arch first.
- **Packaged app** (`.asar`) → `reaInspectJs` (REA reconstruction), no source scan.
- **Small source tree / packaged JS** → `reaInspectJs` for a real semantic graph.
- **Large source tree** → fast built-in extractor (REA's app analyzer is for
  packaged apps, not raw dev repos with `node_modules`).

All source paths also read raw file text so the AUDIT stage can scan it.

## Adapters

Every engine is reached through one file in `src/adapters/`, so swapping or
upgrading an engine is a one-file change:

- `rea.js` — REA CLI (JS reconstruction, native decompilation, per-function
  hashes). Reads engine paths from `trinetra.config.json`.
- `semgrep.js` — Semgrep registry packs, scoped to exclude vendored deps.
- `llm.js` — Claude via the Anthropic SDK (`claude-opus-5-5`) for REBUILD.

## Audit & correlation

`audit.js` holds three rule sets — `SOURCE_RULES`, `NATIVE_RULES`, and the Semgrep
packs. Each raw finding carries an `engine`. `correlate()` then collapses findings
that share a location and a `canonical()` concept into one row, merging the engines
that reported it — so builtin + Semgrep naming the same issue become a single
finding with both engines listed.

## Reports

`report.js` (markdown), `report-html.js` (styled, self-contained HTML), and
`report-compare.js` (diff reports) are pure functions of the pipeline result. They
have no engine knowledge — add a field to the pipeline result and render it.

## Extending

- **New security rule** → add to `SOURCE_RULES` or `NATIVE_RULES` in `audit.js`,
  extend `canonical()`, add a test.
- **New engine** → add an adapter in `src/adapters/`, call it from the relevant
  stage, keep the stage's return shape stable.
- **New stage** → add `src/stages/<name>.js` and wire it into `pipeline.js`.
