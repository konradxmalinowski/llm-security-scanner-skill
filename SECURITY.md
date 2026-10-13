# Security policy

## Reporting a vulnerability

Do not open a public issue. Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/konradxmalinowski/llm-security-scanner-skill/security/advisories/new).

Please include a description, reproduction steps, and the impact you see. Expect an
acknowledgement within a few days.

## In scope

This package is an adapter that hands an AI agent the ability to run a security scanner,
so the interesting classes are:

- **Authorization bypass** — any way to make `run_scan()` execute against a target the
  gate should refuse, or to reach a third-party provider endpoint.
- **Sanitizer bypass** — target output that survives into an agent's context in a form
  that reads as an instruction: an unneutralized control token, an escape from the fence,
  or a zero-width/encoding trick that defeats the lexical pass.
- **Secret leakage** — any path that puts an unredacted credential into an envelope, a
  log, or an agent's context.
- **Command injection** in the subprocess boundary or the installer.
- **Path traversal** in `install.py` or report-path handling.

## Out of scope

- Vulnerabilities in [`llm-security-scanner`](https://github.com/konradxmalinowski/llm-security-scanner)
  itself — report those on that repository.
- Vulnerabilities in Ollama or in a judge model.
- The scanner finding a vulnerability in *your* application. That is the tool working.
- The attack payloads themselves. They are deliberately adversarial; that is the point.

## Supported versions

The latest minor release receives security fixes.

## Using this tool

It is for testing systems you own or are authorized to test. The authorization gate is a
technical control, not legal advice. Unauthorized security testing is illegal in many
jurisdictions — get written permission.
