# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`--rebuild` no longer executes AI-generated code by default.** Generated tests
  run only with the new `--run-generated` flag, after a static review that refuses
  code using `child_process`, network modules, `process.env`, `fetch`, `eval` or
  dynamic `require`, and then only in a sandbox: fresh temp directory, environment
  built from scratch (no `ANTHROPIC_API_KEY` or other inherited variables), Node's
  permission model limited to that directory with no child processes/workers, a
  30 s SIGKILL timeout, and network denial via `sandbox-exec`/`unshare -rn` where
  available. Previously the tests ran with `node --test` and the full parent env.
- Target content sent to Claude is wrapped in `<untrusted_target_source>` delimiters
  (closing tags neutralised) and the system prompt treats it as data; model refusals
  and malformed replies are handled.
- Scaffolded stubs sanitise untrusted names/descriptions (valid identifiers, no
  newline injection into generated comments).
- Hardcoded-secret evidence is redacted in reports.
- `trinetra.config.json` can no longer override the user's `GHIDRA_INSTALL_DIR`;
  precedence is now flag > env > `./trinetra.config.json` > default.

### Added

- Measured-accuracy benchmark (`npm run bench`, `bench/`): per-rule precision, recall
  and F1 on a labelled synthetic suite, OWASP NodeGoat at a pinned commit and a
  hand-triaged false-positive check on 17 popular packages, plus field-by-field
  agreement of the binary parsers with `otool`/`nm`/`codesign`/`lipo` and
  `llvm-objdump`/`file`. Results in `bench/RESULTS.md`.
- JavaScript AST analyzer (`src/analysis/js-ast.js`, acorn) replacing line regexes:
  binding-aware sink matching (RegExp `.exec` and array-arg `spawn` are no longer
  flagged), intra-function taint from `process.argv`/`process.env`/request
  objects/`location`, new rules for dynamic `require`/`import`, DOM XSS, path
  traversal, SQL injection and SSRF, and a per-finding `confidence`.
- Native binary analysis in pure JS (`src/binary/`): ELF, Mach-O, universal Mach-O
  and PE parsing; PIE/ASLR, stack canary, NX, W+X segments, RELRO/BIND_NOW, RPATH,
  code signature / Hardened Runtime / entitlements, DEP/CFG/Authenticode, dangerous
  imports. Works without Ghidra.
- Content-based target routing by magic bytes; `.app` bundles resolve to their
  `CFBundleExecutable`; fat binaries are thinned in JS (no `lipo` dependency).
- UNDERSTAND now reports imports, exports, entry points (including HTTP route
  handlers) and which functions exercise which capabilities.
- Run-to-run memory: each teardown reports new / fixed / unchanged findings
  compared with the previous run of the same target.
- CLI options `--out`, `--config`, `--run-generated`, `--no-rea`, `--no-decompile`,
  `--no-semgrep`, `--fail-on`, `--version`; JSON report alongside Markdown/HTML; an
  Engines table stating what ran and why anything was skipped.
- `trinetra.config.example.json`; `npm run test:coverage`.
- Tests: recorded REA and Semgrep output with replaying stand-ins, CLI and
  integration tests, golden-file report tests, sandbox escape tests, binary parser
  tests on synthesized ELF/Mach-O/fat/PE images.
- Project maturity layer: ESLint + Prettier, `.editorconfig`, `.nvmrc`,
  `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `docs/ARCHITECTURE.md`,
  issue/PR templates, and Dependabot. CI runs lint, format and tests on Node 22/24.

### Fixed

- JS analyzer crashed on a string built by concatenating literals (`"a" + "b"`)
  assigned to a secret-like name, dropping every finding in that file and aborting
  `teardown`; `analyzeJs` now also falls back to line checks instead of throwing on
  any internal error.
- `sql-injection` missed queries assembled in a variable before `query(sql)`.
- Values fixed at authoring time (`const` literals, `__dirname` paths,
  `require.resolve("…")`) were reported as dynamic `eval`/`exec`/`require` input;
  `createHash(ALG)` now resolves a `const` algorithm.
- `innerHTML`/`document.write` of a sanitizer call (`DOMPurify.sanitize`,
  `escapeHtml`) was reported as DOM XSS.
- `hardcoded-secret` flagged bare PEM headers and `AKIA…` runs inside base64 blobs.
- Mach-O: x86_64h slices were named x86_64; weak-definition coalescing entries in
  chained fixups were reported as imports.
- Works when installed from npm: reports, memory, rebuild output, thinned slices and
  decompiler output are written under `./trinetra-out` (or `--out`) in the caller's
  cwd instead of the package directory, and REA is resolved through the module graph
  (then PATH) instead of `<package>/node_modules/.bin/rea`.
- Extensionless text files (Makefiles, shell scripts) are no longer sent to Ghidra.

### Changed

- Default output directory moved from `reports/` to `./trinetra-out/`.
- `acorn` and `acorn-jsx` are now runtime dependencies.

### Removed

- The tracked personal `trinetra.config.json` (now git-ignored).

## [0.1.0] - 2026-10-27

### Added

- **Teardown pipeline**: inspect → understand → audit → rebuild.
- **Inspect**: REA-powered reconstruction for JavaScript/Electron and packaged
  `.asar` apps; Ghidra decompilation for native binaries with automatic thinning
  of universal (fat) Mach-O; a fast built-in inspector for large source trees.
- **Audit**: built-in source rules + Semgrep community packs + native pseudocode
  rules (command exec, unsafe C strings, embedded secrets, format-string bugs,
  unbounded memory ops, hardcoded URLs), correlated across engines.
- **Rebuild**: Claude (`claude-opus-5-5`) regenerates code test-first and verifies
  the tests pass; falls back to scaffolding without an API key.
- **Compare**: diff two targets — added/removed/changed procedures and findings
  by category.
- Markdown and styled HTML reports; `node:test` suite; GitHub Actions CI.

[Unreleased]: https://github.com/prathamshukla28/trinetra/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/prathamshukla28/trinetra/releases/tag/v0.1.0
