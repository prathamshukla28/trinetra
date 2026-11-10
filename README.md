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
`fetch`/`http(s).get`. Values fixed at authoring time — literals, `const` bindings to
literals, `__dirname`-relative `path.join`, `require.resolve("…")` — are not treated as
dynamic, and HTML passed through a sanitizer call (`DOMPurify.sanitize`, `escapeHtml`)
is not reported as DOM XSS. Files that don't parse (e.g. TypeScript) get credential and
weak-hash line checks only, labelled `trinetra-regex`.

**Binaries (no Ghidra needed).** PIE/ASLR, stack canary (`__stack_chk_fail` import),
NX / executable stack, W+X segments, RELRO and BIND_NOW (ELF), relative
RPATH/RUNPATH (ELF), code signature, Hardened Runtime and risky entitlements
(Mach-O), DEP/ASLR/CFG and Authenticode presence (PE), every slice of a universal
binary, and imports of `gets`, `strcpy`/`strcat`/`sprintf`, `system`/`popen`, and
`mktemp`/`tmpnam`.

**Known limits.** Taint is intra-function and name-based (no inter-procedural flow,
no alias analysis). Binary checks are header/import level — they don't prove a
dangerous function is reachable. Measured accuracy is below.

## Accuracy

Measured by `npm run bench`, which rebuilds [bench/RESULTS.md](bench/RESULTS.md)
(full per-rule tables, every false positive and false negative with a reason). Three
JavaScript corpora:

| Corpus | Contents | TP | FP | FN | Precision | Recall | F1 |
|---|---|--:|--:|--:|--:|--:|--:|
| Synthetic (`bench/js`) | 30 files, 118 line labels: 40 vulnerable, 26 vulnerable in known blind spots, 52 tricky negatives | 41 | 5 | 25 | 89.1% | 62.1% | 0.73 |
| [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) @ `c5cb68a` | 50 files, as `teardown` selects them; labels cite the tutorial or the code | 10 | 6 | 2 | 62.5% | 83.3% | 0.71 |
| 17 popular npm packages | 191k lines (acorn, ajv, commander, prettier, ws, …); every finding triaged by hand | 0 | 34 | – | 0.0% | – | – |
| **Pooled** | | **51** | **45** | **27** | **53.1%** | **65.4%** | **0.59** |

| Rule (pooled) | TP | FP | FN | Precision | Recall | F1 |
|---|--:|--:|--:|--:|--:|--:|
| `command-injection` | 5 | 3 | 3 | 62.5% | 62.5% | 0.63 |
| `dom-xss` | 4 | 2 | 3 | 66.7% | 57.1% | 0.62 |
| `dynamic-eval` | 8 | 8 | 4 | 50.0% | 66.7% | 0.57 |
| `dynamic-require` | 3 | 11 | 2 | 21.4% | 60.0% | 0.32 |
| `hardcoded-secret` | 14 | 11 | 4 | 56.0% | 77.8% | 0.65 |
| `insecure-random` | 3 | 1 | 2 | 75.0% | 60.0% | 0.67 |
| `path-traversal` | 4 | 1 | 2 | 80.0% | 66.7% | 0.73 |
| `sql-injection` | 4 | 0 | 2 | 100.0% | 66.7% | 0.80 |
| `ssrf` | 3 | 1 | 4 | 75.0% | 42.9% | 0.55 |
| `weak-hash` | 3 | 7 | 1 | 30.0% | 75.0% | 0.43 |

- **On clean real code every finding was noise:** 34 false positives in 191k lines
  (0.18 per 1,000 lines), mostly `dynamic-require` (plugin loaders), `hardcoded-secret`
  (a parser variable named `…Token`) and `weak-hash` (SHA-1 required by git and RFC 6455).
  A finding counts as TP only if it is a real weakness under the code's own trust model.
- **NodeGoat coverage:** 9 of its 22 labelled issues are detected. 11 of the 22 (NoSQL
  injection, open redirect, ReDoS, IDOR, log injection, …) have no Trinetra rule, and the
  `needle`-based SSRF is missed because only `fetch`/`http(s)`/`axios` are modelled.
- **Binaries:** on 177 Mach-O files (320 slices; system, Homebrew, app and generated
  binaries), PIE, canary, imports, signature, ad-hoc, Hardened Runtime, platform-binary,
  executable-stack and arch fields agree 100% with `otool`/`nm`/`codesign`/`lipo`.
  ELF has only 10 generated fixtures (Go cross-builds plus builder variants), checked
  against `llvm-objdump`/`file`: 69/70 fields agree (one PIE case is ambiguous by
  construction). The benchmark exposed two Mach-O parser bugs (x86_64h, weak-bind
  imports), both now fixed.
- **Limits, read before quoting these numbers:** the corpus is small (one case moves a
  rule by many points); the labels, triage and synthetic cases were written by the
  project's author, so self-labelling bias is likely; taint is intra-function only; TypeScript is
  not parsed (regex fallback, not benchmarked); NodeGoat is a teaching app, not a
  random sample of real code; binary numbers are from one macOS 26 host.
- **Fixes the benchmark drove** (before → after, same labels and triage): an analyzer crash
  on `"a" + "b"` secrets, which made `trinetra teardown` of NodeGoat abort outright (and
  dropped `ws`/`minimatch` files); SQL strings built in a variable before `query()`; constants treated as
  dynamic input; sanitized `innerHTML`; PEM headers and base64 blobs reported as keys.
  Pooled precision went from 44.1% to 53.1% and recall from 62.8% to 65.4%. Most of the
  precision gain is on the synthetic suite (78.0% → 89.1%); on NodeGoat it went from 58.8% to 62.5%.

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
npm run bench            # accuracy benchmark → bench/RESULTS.md (fetches the pinned NodeGoat commit)
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
- [x] Measure precision/recall on a labelled corpus ([bench/RESULTS.md](bench/RESULTS.md))
- [ ] Larger, independently labelled corpora (OWASP Benchmark, Juliet, CTF binaries); real ELF binaries
- [ ] Inter-procedural taint; TypeScript parsing
- [ ] SARIF output

## License

[MIT](LICENSE) © Pratham Shukla · [Security policy](SECURITY.md) · [Changelog](CHANGELOG.md)
