# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's private reporting:
**Security → Report a vulnerability** on <https://github.com/blazfxx/erebus/security/advisories/new>.

Include a description, the affected version (`erebus --version`), and — for parser problems — a minimal input file. You can expect an
acknowledgement within a few days. Fixes are released as patch versions and credited in the changelog unless you prefer otherwise.

## What counts

Erebus loads untrusted binaries, so the interesting bugs are in the loaders, analyzer, decompiler and local server:
crashes, hangs, out-of-bounds reads/writes, memory exhaustion on crafted input, or ways a crafted binary could make Erebus run code,
write files, or reach the network. The local web server binds to `127.0.0.1` only.

## Design notes

- Analysis is **static**: Erebus never executes the binary it analyses. (`export --sign` runs `codesign`; `asm` loads Keystone if installed;
  Swift demangling runs `swift-demangle` — all on your own machine, never on the input's behalf.)
- Loaders validate sizes and counts; every loader, the analyzer and the decompiler are mutation-fuzzed (`tests/fuzz.py`).

## Responsible use

Use Erebus on software you own or have permission to analyse, and follow the law and licences that apply to you.

## Supported versions

Only the latest release receives fixes while the project is pre-1.0.
