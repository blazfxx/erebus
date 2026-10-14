#!/bin/bash
# Regression suite: cross-checks against otool and smoke-tests all three loaders.
set -u
cd "$(dirname "$0")/.."
fail=0
mkdir -p tests/bin
[ -f tests/bin/hello_arm64 ] || clang -O1 -o tests/bin/hello_arm64 tests/hello.c
[ -f tests/bin/hello_x64 ] || clang -O1 -arch x86_64 -o tests/bin/hello_x64 tests/hello.c
check() {  # name, python-output
  if echo "$2" | grep -qE "requested arch not in fat|cannot open|no supported slice"; then echo "$1: skipped (not present on this system)"; return; fi
  echo "$2" | head -4
  if echo "$2" | grep -qE "we list that otool doesn't: [1-9]|mnemonic mismatches: [1-9]|Traceback|error:"; then echo "  FAIL: $1"; fail=1; fi
}
for t in tests/bin/hello_arm64:arm64 /bin/ls:arm64e /usr/bin/file:arm64 /usr/bin/curl:arm64e; do
  check "$t" "$(python3 tests/verify_macho.py "${t%%:*}" "${t##*:}")"
done
check hello_x64 "$(python3 tests/verify_macho.py tests/bin/hello_x64 x86_64)"
python3 tests/mkelf.py tests/bin/tiny.elf
out=$(./build/erebus open tests/bin/tiny.elf -o /tmp/er_t.erdb -q && ./build/erebus /tmp/er_t.erdb funcs)
echo "$out" | grep -q "func_b" && echo "elf: ok" || { echo "elf: FAIL"; fail=1; }
# decompiler must survive every function of real binaries
dc() {  # name db-args...
  out=$(./build/erebus open "$1" $2 -o /tmp/er_dc.erdb -q && ./build/erebus /tmp/er_dc.erdb decompall)
  echo "decompall $1: $out"
  echo "$out" | grep -q " 0 failed" || { echo "  FAIL: decompall $1"; fail=1; }
}
dc /bin/ls "--arch arm64e"
dc /usr/bin/curl "--arch arm64"
dc /usr/bin/file "--arch x86_64"
dc tests/bin/hello_x64 "--arch x86_64"
# patching: assemble over fib, export, the patched binary must behave differently
d=$(mktemp -d); cp tests/bin/hello_arm64 $d/h
./build/erebus open $d/h -o $d/h.erdb -q
if ./build/erebus $d/h.erdb asm _fib "mov w0, #99" 2>&1 | grep -q "assembler unavailable"; then
  echo "patch/export: skipped (Keystone not installed)"; rm -rf $d
else
./build/erebus $d/h.erdb asm _fib "mov w0, #99" >/dev/null
./build/erebus $d/h.erdb asm _fib+4 "ret" >/dev/null
./build/erebus $d/h.erdb export $d/h2 --sign >/dev/null
a=$($d/h 5 | head -1); b=$($d/h2 5 | head -1)
[ "$a" = "fib(5) = 5" ] && [ "$b" = "fib(5) = 99" ] && echo "patch/export: ok" || { echo "patch/export: FAIL ($a / $b)"; fail=1; }
fi
# python client
python3 - <<'PY' && echo "python client: ok" || { echo "python client: FAIL"; fail=1; }
import sys; sys.path.insert(0, "tools")
from erebus import Erebus
with Erebus.open("tests/bin/hello_arm64") as e:
    assert e.info()["funcs"] == 9 and "fib" in e.pseudo("_fib") and e.xrefs("_fib")
PY
exit $fail
