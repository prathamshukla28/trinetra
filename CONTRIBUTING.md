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

Requirements: Node.js ≥ 22. Optional: `semgrep` (deep source audit), a JDK + Ghidra
12.1.x (native binaries — see the README), `ANTHROPIC_API_KEY` (the real `--rebuild`).

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
- `src/adapters/` — how Trinetra talks to each engine (REA, Semgrep, Claude)
- `test/` — `node:test` suites

## Adding a security rule

Built-in source rules live in `SOURCE_RULES`, native (decompiled) rules in
`NATIVE_RULES`, both in `src/stages/audit.js`. Add a `canonical()` mapping so your
rule correlates with equivalent findings from other engines, and a test.

## Commit messages

Write a clear subject line in the imperative mood ("Add native format-string rule").
A short body explaining the *why* is welcome for non-trivial changes.

## Code of Conduct

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).
