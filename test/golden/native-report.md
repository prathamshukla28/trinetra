# Trinetra teardown — vuln

_Generated 2026-01-01T00:00:00.000Z · engine: trinetra-binary_

## 1. What it is

- Target: `bin/vuln` (native)
- Fingerprint (SHA-256): `bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`
- Analyzed by: Trinetra binary parser
- Imports: **2** · linked libraries: **1**
- _Note:_ Decompilation skipped (--no-decompile).

### Binary hardening

| Arch | Type | PIE/ASLR | Stack canary | NX | RELRO | Signature | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| x86_64 | executable | no | no | yes | none | n/a |  |

## 2. What it does

- ELF executable (x86_64).
- Links libc.so.6.
- Imports 2 function(s).

## 3. Security findings

**4** finding(s): 1 high · 2 medium · 1 low

### 🔴 HIGH — Imports gets()
- **Where:** `bin/vuln`
- **Found by:** trinetra-binary · **confidence:** high
- **Why it matters:** gets() cannot bound its input; any use is a stack buffer overflow waiting for long input.
- **Evidence:** `gets`

### 🟠 MEDIUM — Not position-independent (no ASLR)
- **Where:** `bin/vuln`
- **Found by:** trinetra-binary · **confidence:** high
- **Why it matters:** Fixed load addresses make memory-corruption exploits reliable.
- **Evidence:** `filetype=executable, PIE=false`

### 🟠 MEDIUM — No RELRO
- **Where:** `bin/vuln`
- **Found by:** trinetra-binary · **confidence:** high
- **Why it matters:** The GOT stays writable, so a write primitive can redirect library calls.
- **Evidence:** `no PT_GNU_RELRO`

### 🟡 LOW — No stack canary (__stack_chk_fail not imported)
- **Where:** `bin/vuln`
- **Found by:** trinetra-binary · **confidence:** medium
- **Why it matters:** Built without -fstack-protector (or no function needed one); stack overflows go undetected.
- **Evidence:** `2 imports, none of __stack_chk_fail/__stack_chk_guard`

## 4. Since last run

_First teardown of this target — this run is now the baseline._

## 5. Rebuild

Reimplemented 2 unit(s) test-first in rebuilt/vuln — 1 passed, 1 blocked.

- ✅ `entry` — passed (sandbox: env stripped, fs sbx, network blocked (sandbox-exec))
- ⛔ `helper` — blocked (imports child_process)

## Engines

| Engine | Provided by | Status |
| --- | --- | --- |
| Binary format + hardening checks | Trinetra | ran (elf: x86_64) |
| REA (JS reconstruction / Ghidra decompilation) | delegated: rea-agents | not installed |
| Semgrep community packs | delegated: semgrep | not applicable |
| Rebuild code generation | delegated: Claude | generated + sandboxed run |
