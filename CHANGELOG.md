# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-10-15

### Changed
- **New icon**: Blobby holding a magnifier over one eye, over a faint listing, on a violet tile.
- **New welcome window**: a dark (or light, following macOS) page with the icon, an Open binary button, a drop area that lights up while you drag a file over the window, and a Recent list with file names and folders (and Clear).
- **New look for the analysis UI** to match the Blobby apps: neutral greys, one accent, Inter, tabs and a floating graph toolbar.

## [0.1.0] — 2026-10-14

First public release.

### Added
- **Loaders**: Mach-O (thin/fat, arm64/arm64e/x86_64, chained fixups, stub/GOT naming), ELF 32/64 (PLT/GOT naming), PE32/PE32+ (imports, exports, x64 `.pdata`).
- **Analysis engine**: recursive-descent disassembly, prologue/gap scanning, jump-table resolution, noreturn inference, functions/basic blocks/CFG, code & data cross-references, string discovery, pointer-table scanning.
- **Database**: single-file SQLite `.erdb` holding bytes, analysis and user edits (names, comments, patches).
- **Decompiler**: arm64 and x86-64 (SysV + Win64) and x86-32; structured pseudo-C with `if`/`while`/`do-while`/`switch`, call-argument recovery, Apple stack varargs, stack-protector stripping.
- **Metadata**: Objective-C class/category methods, Swift symbol demangling (via the Swift toolchain).
- **Patching**: assemble in place (optional Keystone), raw byte patches, revert, re-analyse, export patched binary with ad-hoc signing.
- **Interfaces**: native macOS app (`Erebus.app`), web UI (listing, CFG graph, pseudo-code, hex, call tree, xrefs), CLI/REPL, Python client over a local HTTP API.
- Mutation fuzzing and regression suite (`tests/`).
