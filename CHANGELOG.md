# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [0.3.0] — 2026-10-16

### Added
- **Opens apps**: an `.app`, `.framework` or other bundle opens like a file. Erebus finds the program inside through `Info.plist` (or the bundle's name, or the one file in `Contents/MacOS`). Opening one used to fail with "file too small". A folder with no program in it now says so, and a file that is too small names itself and its size.
- **MCP server** (`mcp/erebus-mcp.mjs`, no dependencies): serves Erebus to [REA](https://github.com/morluto/rea) through the tool profile it expects from an IDA MCP server, so REA runs on Erebus instead of IDA. Tested against REA's own CLI and MCP server.
- **Launcher package** (`scripts/build-package.sh`): the engine, welcome page and MCP server in one `.tar.gz` that the Blobby Launcher downloads and opens in its own window.
- Hold the top of the welcome window to drag it (the page covered the title bar, so it would not move).

### Changed
- CMake finds Capstone without pkg-config, so the engine builds on more machines.

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
