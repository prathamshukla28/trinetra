# Contributing to Trinetra

Thanks for your interest in improving Trinetra! This guide gets you from clone to
pull request.

## Getting started

```bash
git clone https://github.com/prathamshukla28/trinetra.git
cd trinetra
npm install
npm test          # should be all green
npm run demo      # audit the bundled sample
```

Requirements: Node.js ≥ 22. Optional: `semgrep` (community rule packs), a JDK + Ghidra
12.1.x (native decompilation — see the README), `ANTHROPIC_API_KEY` (model-generated
`--rebuild`). The test suite needs none of them.

## Before you open a PR

Run the full local gate — CI runs the same checks:

```bash
npm run format    # prettier check (use `npm run format:fix` to apply)
npm run lint      # eslint
npm test          # node:test suite
```

- Keep changes focused; one concern per PR.
- Add or update a test for any behavior change. New rules, stages, and adapters
  should ship with tests under `test/`.
- Match the surrounding style (the tooling enforces most of it).
- Update `CHANGELOG.md` under an `## [Unreleased]` heading.

## Where things live

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the pipeline and how to add a
new engine, stage, or rule. In short:

- `src/stages/` — the four pipeline stages
- `src/analysis/` — Trinetra's JavaScript AST + taint analyzer
- `src/binary/` — Trinetra's ELF / Mach-O / PE parsers and hardening checks
- `src/adapters/` — how Trinetra talks to each engine (REA, Semgrep, Claude)
- `test/` — `node:test` suites; `test/fixtures/` holds recorded engine output and
  replaying stand-ins; `test/golden/` holds expected reports

## Adding a security rule

JavaScript rules live in `src/analysis/js-ast.js` (`RULES` + the checks in
`checkCall` / `walk`), binary hardening checks in `src/binary/index.js`, and
pseudocode rules in `NATIVE_RULES` in `src/stages/audit.js`. Add a `canonical()`
mapping so your rule correlates with equivalent findings from other engines, and
tests for both a true positive and a near-miss that must *not* be flagged.

If a change alters report output, regenerate the golden files with
`UPDATE_GOLDEN=1 npm test` and review the diff.

## Commit messages

Write a clear subject line in the imperative mood ("Add native format-string rule").
A short body explaining the *why* is welcome for non-trivial changes.

## Code of Conduct

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).
