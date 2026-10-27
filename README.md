<div align="center">

# 🔱 Trinetra

### The third eye for software — reverse-engineer, audit, and rebuild anything.

Point Trinetra at any app, source tree, or native binary. It **sees inside**,
**audits** it for security weaknesses, and can **rebuild** a clean, tested
version you own — all from one command.

[![CI](https://github.com/prathamshukla28/trinetra/actions/workflows/ci.yml/badge.svg)](https://github.com/prathamshukla28/trinetra/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D22-339933?style=flat-square&logo=nodedotjs&logoColor=white)](https://nodejs.org)
[![Engines](https://img.shields.io/badge/engines-REA%20%C2%B7%20Semgrep%20%C2%B7%20Ghidra-7c3aed?style=flat-square)](#how-it-works)
[![Tests](https://img.shields.io/badge/tests-node%3Atest-informational?style=flat-square)](test/)

</div>

---

> ⚠️ **Authorized use only.** Trinetra tears software apart. Use it on code you
> own, open-source projects, authorized pentest targets, or practice/CTF
> binaries — never on software you are not permitted to analyze.

## Why Trinetra

Plenty of tools *scan* source, and separate tools *decompile* binaries. Almost
nothing does both and then **disciplines the rebuild**. Trinetra wires a
reverse-engineering engine into a test-first builder, so one run gives you two
things:

- **A security report** — what it is, what it does, and where it's weak.
- **A clean reimplementation** *(optional)* — tested code you own.

## Demo

**Auditing a source file:**

```text
$ trinetra teardown ./my-app

Trinetra · tearing down "my-app"
  [1/4 INSPECT]     found 4 unit(s) via rea-javascript-application
  [2/4 UNDERSTAND]  mapped 4 behavior(s)
  [3/4 AUDIT]       8 finding(s) via builtin + semgrep
  [4/4 REBUILD]     skipped (pass --rebuild to enable)
✔ done · report → reports/my-app.md
        html   → reports/my-app.html
```

```text
🔴 HIGH — Hardcoded secret            builtin   sample.js:6
🔴 HIGH — Shell / command execution   builtin   sample.js:14
🔴 HIGH — Dynamic code execution      builtin   sample.js:22
🟠 MEDIUM — Weak hashing (MD5)        semgrep   sample.js:9
```

**Decompiling a native binary (Ghidra):**

```c
// trinetra teardown ./some-binary   →   recovers 11 procedures, decompiles each
undefined8 entry(uint param_1,long param_2)
{
  char *pcVar10;
  pcVar10 = _getenv("POSIXLY_CORRECT");
  if ((pcVar10 == (char *)0x0) && (pcVar10 = _getenv("POSIX_PEDANTIC"), ...)) {
    pcVar10 = *(char **)(param_2 + 8);
    if (((pcVar10 == (char *)0x0) || (*pcVar10 != '-')) || (pcVar10[1] != 'n')) {
      ...
```

Every run also writes a **styled HTML report** you can open in a browser.

## How it works

Trinetra is a thin **conductor** over best-in-class tools — it orchestrates
them, it doesn't reinvent them.

```
          ┌──────────┐   ┌───────────┐   ┌──────────┐   ┌──────────┐
 TARGET → │ INSPECT  │ → │ UNDERSTAND│ → │  AUDIT   │ → │ REBUILD  │ → REPORT
          │ REA /    │   │  memory   │   │ Semgrep  │   │ test-    │   (md + html)
          │ Ghidra   │   │  map      │   │ + rules  │   │ first    │
          └──────────┘   └───────────┘   └──────────┘   └──────────┘
```

| Stage | Engine |
| --- | --- |
| **Inspect** | [REA](https://github.com/morluto/rea) — JS/Electron reconstruction + native decompilation via [Ghidra](https://github.com/NationalSecurityAgency/ghidra) |
| **Understand** | A persistent memory map per target |
| **Audit** | Built-in high-signal rules **+** [Semgrep](https://semgrep.dev) community packs |
| **Rebuild** | Test-first scaffolding (TDD discipline) |

Source trees use a fast inspector + Semgrep; packaged apps and binaries route to
REA/Ghidra automatically.

## Install

```bash
git clone https://github.com/prathamshukla28/trinetra.git
cd trinetra
npm install          # pulls in REA (rea-agents)
```

**Requirements**

- Node.js ≥ 22
- `semgrep` on PATH (optional, for the deep audit): `pipx install semgrep`
- For **native binaries**: a JDK 21+ and Ghidra 12.1.x. Point Trinetra at them in
  `trinetra.config.json`:

  ```json
  { "ghidraInstallDir": "/path/to/ghidra_12.1.x_PUBLIC", "javaBinDir": "/opt/homebrew/opt/openjdk/bin" }
  ```

## Usage

```bash
trinetra teardown <target>              # audit + report
trinetra teardown <target> --rebuild    # also scaffold a clean, tested rebuild

trinetra teardown ./src                 # a source tree
trinetra teardown ./app.asar            # a packaged app
trinetra teardown ./program             # a native binary (needs Ghidra)
```

Reports land in `reports/<name>.md` and `reports/<name>.html`.

## Project layout

```
trinetra/
  src/
    cli.js              command-line entry
    pipeline.js         the conductor (4 stages)
    stages/             inspect · understand · audit · rebuild
    adapters/           rea.js · semgrep.js  (how we talk to the engines)
    memory.js           per-target knowledge store
    report.js           markdown report
    report-html.js      styled HTML report
  test/                 node:test suite
  targets/              things you analyze (git-ignored)
  reports/              generated reports (git-ignored)
```

## Testing

```bash
npm test
```

## Roadmap

- [ ] Auto-thin universal (fat) Mach-O binaries
- [ ] Native security rules (dangerous imports, embedded secrets)
- [ ] Correlate findings across engines
- [ ] Make the REBUILD stage generate working code, not just scaffolding
- [ ] `compare` mode — diff two versions down to the binary

## License

[MIT](LICENSE) © Pratham Shukla

<div align="center">
<sub>Trinetra — the third eye that sees inside any software.</sub>
</div>
