# Trinetra teardown — sample-cli

_Generated 2026-01-01T00:00:00.000Z · engine: trinetra-ast_

## 1. What it is

- Target: `sample-cli` (source)
- Fingerprint (SHA-256): `aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
- Analyzed by: Trinetra AST analyzer
- Files inspected: **1** · units: **4**

## 2. What it does

- 1 source file(s), 4 function(s).
- Depends on Node built-ins node:child_process, node:crypto.
- Public surface: evalExpression, login, makeToken, runUserCommand.
- Capabilities: runs shell commands / processes in runUserCommand; evaluates dynamic code in evalExpression; uses cryptography in login; generates random values in makeToken.

| Function | Where | Exported | What it touches |
| --- | --- | --- | --- |
| `login` | `sample-cli/index.js:8` | yes | uses cryptography (crypto.createHash) |
| `runUserCommand` | `sample-cli/index.js:13` | yes | runs shell commands / processes (child_process.execSync) |
| `makeToken` | `sample-cli/index.js:17` | yes | generates random values (Math.random) |
| `evalExpression` | `sample-cli/index.js:21` | yes | evaluates dynamic code (global.eval) |

## 3. Security findings

**5** finding(s): 3 high · 1 medium · 1 low

### 🔴 HIGH — Shell command built from a non-literal value
- **Where:** `sample-cli/index.js:14` in `runUserCommand`
- **Found by:** trinetra-ast · **confidence:** medium
- **Why it matters:** child_process exec/execSync (or spawn with shell:true) passes the string to /bin/sh — any input in it is command injection.
- **Evidence:** `return execSync(cmd).toString(); // command injection`

### 🔴 HIGH — Dynamic code execution with a non-literal argument
- **Where:** `sample-cli/index.js:22` in `evalExpression`
- **Found by:** trinetra-ast · **confidence:** medium
- **Why it matters:** eval / new Function / vm run strings as code; attacker-influenced input becomes arbitrary code.
- **Evidence:** `return eval(expr); // dynamic eval`

### 🔴 HIGH — Hardcoded secret
- **Where:** `sample-cli/index.js:6` in `(top level)`
- **Found by:** trinetra-ast · **confidence:** high
- **Why it matters:** Credentials in source leak through the repo, logs, and shipped builds. Matches a known credential format.
- **Evidence:** `const API_KEY = "sk_l…(redacted, 24 chars)"; // hardcoded secret (bad)`

### 🟠 MEDIUM — Weak hashing algorithm (MD5 / SHA-1)
- **Where:** `sample-cli/index.js:9` in `login`
- **Found by:** trinetra-ast · **confidence:** high
- **Why it matters:** MD5 and SHA-1 are broken for integrity, signatures, and password storage. Algorithm: md5.
- **Evidence:** `const hash = crypto.createHash("md5").update(password).digest("hex"); // weak hash`

### 🟡 LOW — Math.random() used for a security-sensitive value
- **Where:** `sample-cli/index.js:18` in `makeToken`
- **Found by:** trinetra-ast · **confidence:** medium
- **Why it matters:** Math.random is predictable — unsafe for tokens, IDs, nonces, or keys. Use crypto.randomUUID / randomBytes. Used in `makeToken`.
- **Evidence:** `return Math.floor(Math.random() * 1e9).toString(); // insecure randomness`

## 4. Since last run

Compared with the teardown from 2025-12-31T00:00:00.000Z: content **changed**; **1** new, **1** fixed, 4 unchanged finding(s).

- 🆕 🔴 HIGH Shell command built from a non-literal value — `sample-cli/index.js:14`
- ✅ fixed: Weak hashing algorithm (MD5 / SHA-1) — `sample-cli/old.js:3`

## 5. Rebuild

Scaffolded 2 test-first stub file(s) in rebuilt/sample-cli. Set ANTHROPIC_API_KEY for a model-generated reimplementation.

## Engines

| Engine | Provided by | Status |
| --- | --- | --- |
| JavaScript AST rules + taint tracking | Trinetra | ran on 1/1 file(s) |
| REA (JS reconstruction / Ghidra decompilation) | delegated: rea-agents | disabled (--no-rea) |
| Semgrep community packs | delegated: semgrep | disabled (--no-semgrep) |
| Rebuild code generation | Trinetra (scaffold) | scaffolded stubs (no API key) |
