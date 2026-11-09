<div align="center">

# 🔱 Trinetra

### Reverse-engineer, audit, and (optionally) rebuild an app or binary from one command.

[![CI](https://github.com/prathamshukla28/trinetra/actions/workflows/ci.yml/badge.svg)](https://github.com/prathamshukla28/trinetra/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933?style=flat-square&logo=nodedotjs&logoColor=white)](https://nodejs.org)

</div>

---

> ⚠️ **Authorized use only.** Use Trinetra on code you own, open-source projects,
> authorized engagements, or practice/CTF binaries.

## What it is

Trinetra is a CLI that points several analyses at one target and produces a single
correlated report (Markdown, HTML, and JSON). Some of that analysis is Trinetra's
own; some is delegated to established engines when they're installed. The report's
**Engines** table always says which ran and why any were skipped.

| Capability | Who does it |
| --- | --- |
| JavaScript AST rules with intra-function taint tracking (`acorn`) | **Trinetra** |
| Binary parsing + hardening checks for ELF, Mach-O, universal Mach-O, and PE | **Trinetra** (pure JS, no external tools) |
| Content-based target routing (magic bytes, `.app` bundles, `.asar`) | **Trinetra** |
| Capability map: imports, exports, entry points, which functions touch shell / eval / fs / network / env | **Trinetra** |
| Cross-engine correlation, run-to-run memory (new / fixed findings) | **Trinetra** |
| Line rules over decompiled C pseudocode | **Trinetra**, over Ghidra output |
| Native decompilation (every function) | **Delegated** to [REA](https://github.com/morluto/rea) → [Ghidra](https://github.com/NationalSecurityAgency/ghidra) |
| JavaScript/Electron application semantic graph, `.asar` reconstruction | **Delegated** to REA |
| Community security rule packs | **Delegated** to [Semgrep](https://semgrep.dev), if installed |
| Test-first reimplementation (`--rebuild`) | **Delegated** to Claude (`claude-opus-5-5`), if an API key is set; otherwise Trinetra scaffolds stubs |

### What the built-in analysis checks

**JavaScript (AST, not line regex).** Calls are matched by what they resolve to
through `import`/`require`/destructuring — `child_process.exec` — so `regex.exec(s)`
is never mistaken for a shell call. Rules: `eval`/`new Function`/`vm.*` with
non-literal input; `exec`/`execSync` with non-literal, concatenated, or template
commands (and `spawn`/`execFile` only when `shell: true`); `require()`/`import()` of
computed paths; `innerHTML`/`outerHTML`/`document.write`/`insertAdjacentHTML` with
non-literal values; MD5/SHA-1 via `createHash`; hardcoded secrets (known credential
formats anywhere, plus plausible values assigned to secret-named variables — evidence
is redacted); `Math.random()` where the value is evidently a token/key/id. Values from
`process.argv`, `process.env`, `req.query/body/params/headers/cookies`, and
`location.*` are tracked through assignments, destructuring, concatenation,
templates and calls (with `path.basename`, `Number`, `encodeURIComponent` treated as
sanitizers), which raises confidence and enables taint-only rules: path traversal
into `fs.*`/`res.sendFile`, SQL built from request input, and SSRF via
`fetch`/`http(s).get`. Files that don't parse (e.g. TypeScript) get credential and
weak-hash line checks only, labelled `trinetra-regex`.

**Binaries (no Ghidra needed).** PIE/ASLR, stack canary (`__stack_chk_fail` import),
NX / executable stack, W+X segments, RELRO and BIND_NOW (ELF), relative
RPATH/RUNPATH (ELF), code signature, Hardened Runtime and risky entitlements
(Mach-O), DEP/ASLR/CFG and Authenticode presence (PE), every slice of a universal
binary, and imports of `gets`, `strcpy`/`strcat`/`sprintf`, `system`/`popen`, and
`mktemp`/`tmpnam`.

**Known limits.** Taint is intra-function and name-based (no inter-procedural flow,
no alias analysis). Binary checks are header/import level — they don't prove a
dangerous function is reachable. Precision/recall has not yet been measured on a
labeled corpus.

## Demo

```text
$ trinetra teardown targets/sample-cli --no-semgrep

[1/4 INSPECT]     found 4 function(s) via rea-javascript-application
[2/4 UNDERSTAND]  1 source file(s), 4 function(s); REA recovered 4 unit(s).
                  Depends on Node built-ins node:child_process, node:crypto.
[3/4 AUDIT]       5 finding(s) via trinetra-ast
[4/4 REBUILD]     skipped (pass --rebuild to enable)
✔ done · report → trinetra-out/sample-cli.md
```

```text
🔴 HIGH   Shell command built from a non-literal value   index.js:14  in runUserCommand
🔴 HIGH   Dynamic code execution (eval)                  index.js:22  in evalExpression
🔴 HIGH   Hardcoded secret  "sk_l…(redacted)"            index.js:6
🟠 MEDIUM Weak hashing algorithm (md5)                   index.js:9   in login
🟡 LOW    Math.random() for a security-sensitive value   index.js:18  in makeToken
```

A native binary, without Ghidra installed:

```text
$ trinetra teardown /bin/ls --no-decompile
| Arch   | Type       | PIE/ASLR | Stack canary | NX  | RELRO | Signature             |
| x86_64 | executable | yes      | yes          | yes | n/a   | Apple platform binary |
| arm64e | executable | yes      | yes          | yes | n/a   | Apple platform binary |
🟠 MEDIUM Imports unbounded string functions — strcpy [x86_64, arm64e]
```

## Install

```bash
npm install -g @prathamshukla28/trinetra      # or: npx @prathamshukla28/trinetra …
```

From source:

```bash
git clone https://github.com/prathamshukla28/trinetra.git
cd trinetra && npm install
npm run demo
```

**Requirements:** Node.js ≥ 22. Everything else is optional:

- `semgrep` on PATH — adds community rule packs (`pipx install semgrep`).
- JDK 21+ and Ghidra 12.1.x — adds native decompilation via REA. Set
  `GHIDRA_INSTALL_DIR` and `JAVA_HOME`, or copy `trinetra.config.example.json` to
  `./trinetra.config.json` in the directory you run from.
- `ANTHROPIC_API_KEY` — model-generated code for `--rebuild`.

## Usage

```bash
trinetra teardown <target> [options]
trinetra compare  <targetA> <targetB> [options]

  -o, --out <dir>       output directory (default ./trinetra-out)
      --config <file>   config file (default ./trinetra.config.json if present)
      --rebuild         generate a test-first reimplementation (writes files only)
      --run-generated   with --rebuild, execute the generated tests in a sandbox
      --no-rea          Trinetra's own analysis only
      --no-decompile    skip Ghidra for native binaries
      --no-semgrep      skip Semgrep
      --fail-on <sev>   exit 2 if any finding is at least high|medium|low (for CI)
```

Targets are routed by **content**: a source directory or file, a packaged `.asar`,
a native executable (ELF / Mach-O / universal / PE, detected by magic bytes — a
`Makefile` or shell script is never sent to Ghidra), or a macOS `.app` bundle
(resolved to its `CFBundleExecutable`).

Output goes to `./trinetra-out/` relative to **where you run the command**:
`<name>.md`, `<name>.html`, `<name>.json`, `rebuilt/<name>/`, and `.memory/`. Each
teardown is compared with the previous run of the same target, and the report lists
new and fixed findings.

**Configuration precedence:** CLI flag > environment variable (`TRINETRA_OUT`,
`GHIDRA_INSTALL_DIR`, `JAVA_HOME`/`TRINETRA_JAVA_BIN_DIR`, `TRINETRA_REA_BIN`,
`TRINETRA_SEMGREP_BIN`) > `./trinetra.config.json` > defaults.

## `--rebuild` safety model

The rebuild sends target source (untrusted) to Claude and gets code back (also
untrusted — the target could contain prompt-injection text). So:

1. Target content is wrapped in `<untrusted_target_source>` delimiters (closing tags
   inside it are neutralised) and the model is told it is data, not instructions.
2. `--rebuild` alone **writes** the generated files and runs nothing.
3. `--run-generated` executes the generated tests only after a static review refuses
   any code that imports `child_process`/`net`/`http`/`worker_threads`/`vm`, reads
   `process.env`, calls `fetch`, or uses `eval`/dynamic `require`.
4. Survivors run in a child Node process with: a fresh temp directory as cwd/HOME;
   an environment built from scratch (no API keys or inherited variables); Node's
   permission model with fs read/write limited to that directory and no child
   processes, workers, addons or WASI; a 30 s SIGKILL timeout; and network denied via
   `sandbox-exec` (macOS) or `unshare -rn` (Linux) when available. Node 22's
   permission model does not restrict network itself — where no OS mechanism is
   available, the report says `network: not restricted`.

## Development

```bash
npm test                 # node:test suite (unit, golden-file, CLI, integration)
npm run test:coverage    # with Node's built-in coverage
npm run lint && npm run format
```

Integration tests run the real CLI against stand-ins for REA and Semgrep that replay
output recorded from the real engines (`test/fixtures/`), so they need neither
installed. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Roadmap

- [x] Auto-thin universal (fat) Mach-O binaries (now in pure JS)
- [x] Native security rules (pseudocode rules + own binary hardening checks)
- [x] Correlate findings across engines
- [x] `--rebuild` generates and (optionally, sandboxed) verifies code
- [x] `compare` mode — added/removed/changed units + findings by category
- [x] AST-based JavaScript rules with intra-function taint
- [x] Run-to-run memory: new/fixed findings per target
- [ ] Measure precision/recall on a labeled corpus (e.g. Juliet, OWASP Benchmark, CTF binaries)
- [ ] Inter-procedural taint; TypeScript parsing
- [ ] SARIF output

## License

[MIT](LICENSE) © Pratham Shukla · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)
