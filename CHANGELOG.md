# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Project maturity layer: ESLint + Prettier, `.editorconfig`, `.nvmrc`,
  `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `docs/ARCHITECTURE.md`,
  issue/PR templates, and Dependabot.
- CI now runs lint and format checks and tests across a Node version matrix.

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
