# Security Policy

Trinetra is a security tool, so we hold its own security to a high bar.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/prathamshukla28/trinetra/security/advisories/new)**.

Include, where possible:

- A description of the issue and its impact
- Steps or a proof-of-concept to reproduce
- Affected version / commit

You can expect an initial response within **72 hours**, and we'll keep you updated
as we investigate and fix.

## Scope

In scope:

- The Trinetra CLI and its pipeline (`src/`)
- How Trinetra invokes its analysis engines (REA, Semgrep, Ghidra)
- The `--rebuild --run-generated` sandbox (`src/sandbox.js`): any way for generated
  code to read the caller's environment or files, spawn processes, or escape its
  temp directory is a vulnerability

Out of scope:

- Vulnerabilities in the upstream engines themselves — report those to their
  respective projects
- Findings produced *by* Trinetra about third-party software

## Responsible use

Trinetra reverse-engineers software. Only run it against software you own, that is
open-source, that you are explicitly authorized to analyze, or that exists for
security practice (CTF). Using it to defeat protections on software you aren't
permitted to analyze may be illegal.

## Handling untrusted targets

Everything Trinetra analyzes is treated as untrusted input. Target text sent to
Claude for `--rebuild` is fenced and labelled as data, and generated code is never
executed unless `--run-generated` is passed — then only after a static review and
inside a sandbox (stripped environment, Node permission model limited to a temp
directory, no child processes or workers, timeout, OS-level network denial where
available). Node 22's permission model does not cover network access; on hosts
without `sandbox-exec`/`unshare` the report states `network: not restricted`.

## Supported versions

Trinetra is pre-1.0; only the latest release on `main` receives security fixes.
