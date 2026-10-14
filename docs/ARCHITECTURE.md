# Architecture

Erebus is a small pipeline. Each stage has one job and one interface, so adding a format, architecture or front end touches one place.

```
 loaders ──► Image ──► analysis engine ──► Database (.erdb) ──► Session ──► CLI · HTTP API · decompiler
```

## 1. Loaders (`src/loaders`)

A loader turns file bytes into an `Image` (`src/core/image.h`): loadable **segments** (address, permissions, file-backed bytes, file offset),
**sections** with a coarse kind (code, stub, c-string, data, pointer, bss), **symbols** (functions, data, import stubs/slots) and
loader-known function starts (`LC_FUNCTION_STARTS`, PE `.pdata`).

- `macho.cpp` — thin & fat, symbol table, stub/GOT names via the indirect symbol table, **chained fixups** (rebases are applied in memory,
  binds name their slot), entry point. `objc.cpp` reads Objective-C metadata and names method implementations.
- `elf.cpp` — program headers for memory, section headers for kinds, `.symtab`/`.dynsym`, PLT and GOT naming from relocations.
- `pe.cpp` — sections, imports (`__imp_*` slots), exports, x64 exception table as authoritative function starts.

`Image::finalize()` sanitises whatever a (possibly hostile) loader produced: absurd segments are dropped and sections are clipped to real,
file-backed memory.

## 2. Processor module (`src/procs`)

`Proc` decodes one instruction (Capstone) and classifies it: control flow (`Jmp/CJmp/Call/Ret/IJmp/...`), direct targets, and **data
references** (arm64 `ADRP+ADD/LDR` pairs, RIP-relative operands). It also recognises switch **jump tables** for arm64 and x86-64.

## 3. Analysis engine (`src/analysis`)

Recursive descent from entry points, symbols and loader hints builds `Func`s with basic blocks and CFG edges. Calls are explored
depth-first so `noreturn` is known before fall-through is followed. Afterwards: string discovery, pointer-table scan, and iterative
prologue/gap scanning for code nothing points at. Everything lands in an `Analysis` (functions, xrefs, names, strings, jump tables).

## 4. Database (`src/core/db.cpp`)

One SQLite file: segments (bytes as blobs), sections, symbols, functions, blocks, edges, jump tables, xrefs, names, strings, comments,
patches. User edits are written through immediately; patches update the stored bytes in place (incremental blob I/O).

## 5. Session & front ends (`src/cli`, `src/ui`)

`Session` loads the database and builds the lookup indexes. On top of it:

- `commands.cpp` — the CLI/REPL commands and the text listing renderer (`render.cpp` is shared with the UI).
- `ui/server.cpp` — a loopback-only JSON API and the embedded single-page UI (`ui/index.html`).
- `app/` — the macOS shell: a `WKWebView` per binary talking to a private `erebus serve` child (which exits automatically when the app dies).
- `tools/erebus.py` — a Python client for the same API.

## 6. Decompiler (`src/decomp`)

1. **Lift** (`lift_arm64.cpp`, `lift_x86.cpp`): instruction → register-level IR statements over expression trees (`ir.h`).
2. **Dataflow** (`analysis.cpp`): per-function stack-pointer tracking and callee-saved-register removal; per-block symbolic simulation that
   decides, for every definition, whether to inline it, give it a temporary, or write it back — using exact memory-hazard and
   register-clobber rules; liveness across blocks; call-arity inference (known libc prototypes, callee summaries, selector parsing for
   `objc_msgSend`); Apple stack varargs; constant propagation.
3. **Structure** (`decompile.cpp`): dominators, post-dominators, natural loops → `if`/`else`, `while`, `do-while`, `switch`, with `goto`
   as the fallback for irreducible flow.
4. **Print**: C-like text with typed-by-use variables (`a1`, `v1`, pointers) and clickable symbol references.

## Testing strategy

Ground truth is `otool`: every instruction Erebus lists must exist in `otool`'s output with the same mnemonic. The decompiler is run
over every function of real system binaries (must never fail), and loaders/analyzer/decompiler are mutation-fuzzed.
