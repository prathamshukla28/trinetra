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

Out of scope:

- Vulnerabilities in the upstream engines themselves — report those to their
  respective projects
- Findings produced *by* Trinetra about third-party software

## Responsible use

Trinetra reverse-engineers software. Only run it against software you own, that is
open-source, that you are explicitly authorized to analyze, or that exists for
security practice (CTF). Using it to defeat protections on software you aren't
permitted to analyze may be illegal.

## Supported versions

Trinetra is pre-1.0; only the latest release on `main` receives security fixes.
