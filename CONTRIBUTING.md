# Contributing to Erebus

Thanks for helping! Bug reports, test cases (especially binaries that analyse or decompile badly), docs and code are all welcome.

## Quick start

```sh
brew install cmake ninja capstone cpp-httplib nlohmann-json     # + `keystone` to test `asm`
cmake -S . -B build -G Ninja && cmake --build build
./tests/run.sh                                                  # regression suite
python3 tests/fuzz.py 300 1                                     # mutation fuzz (optional, a few minutes)
```

`EREBUS_UI_DIR=src/ui ./build/erebus serve <db>` serves `src/ui/index.html` straight from disk, so UI work needs no rebuild.
The macOS app shell is in `app/` (`scripts/build-app.sh` builds it).

## Where things live

| Path | What |
|---|---|
| `src/loaders` | container formats → `Image` (add a format by adding one `load*` function and a sniff in `loader.cpp`) |
| `src/procs` | processor module: decode, control-flow classification, data references, jump tables |
| `src/analysis` | auto-analysis engine |
| `src/decomp` | IR, per-architecture lifters, dataflow (`analysis.cpp`), structuring and C printing (`decompile.cpp`) |
| `src/cli`, `src/ui` | commands, renderer, HTTP API and the single-page UI |
| `tools/` | Python client and examples |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how the stages fit together.

## Pull requests

- Keep changes focused; explain *why* in the description. Link the issue if there is one.
- New behaviour needs a test: a fixture in `tests/`, or an assertion in `tests/run.sh`. Parser changes should survive `tests/fuzz.py`.
- Disassembly changes should keep the `otool` cross-check at 0 mismatches; decompiler changes must keep `decompall` at 0 failures.
- Match the surrounding style (C++20, 4-space indent, `.editorconfig`); no new dependencies without discussion — licensing matters here
  (Erebus is MIT; GPL code must stay out of the linked binary).
- Never commit third-party binaries you don't have the right to redistribute. Describe how to obtain a sample instead.

By contributing you agree that your contribution is licensed under the project's [MIT license](LICENSE).

## Reporting bugs

Use the issue templates. The most useful reports include the binary (or how to get it), the command or UI action, what you expected, and what
happened. For wrong decompiler output, include the disassembly of the function (`erebus <db> disasm <fn>`).
