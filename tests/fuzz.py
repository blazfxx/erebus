#!/usr/bin/env python3
"""Mutation fuzz: corrupt/truncate real binaries; erebus must never crash or hang."""
import random, subprocess, sys, tempfile, os

er = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "erebus")
seeds = [p for p in ["tests/bin/hello_arm64", "tests/bin/hello_x64", "tests/bin/tiny.elf", "/usr/bin/file"] if os.path.exists(p)]
# extra seeds (e.g. a PE or ELF sample): EREBUS_FUZZ_SEEDS=/path/a.dll:/path/b.so
seeds += [p for p in os.environ.get("EREBUS_FUZZ_SEEDS", "").split(":") if p and os.path.exists(p)]
iters = int(sys.argv[1]) if len(sys.argv) > 1 else 200
rng = random.Random(int(sys.argv[2]) if len(sys.argv) > 2 else 1)
bad = 0
for i in range(iters):
    src = rng.choice(seeds)
    data = bytearray(open(src, "rb").read())
    mode = rng.choice(["flip-header", "flip-any", "truncate", "zero-range"])
    if mode == "flip-header":
        for _ in range(rng.randint(1, 24)):
            data[rng.randrange(min(len(data), 0x400))] = rng.randrange(256)
    elif mode == "flip-any":
        for _ in range(rng.randint(1, 64)):
            data[rng.randrange(len(data))] = rng.randrange(256)
    elif mode == "truncate":
        data = data[: rng.randrange(16, len(data))]
    else:
        a = rng.randrange(len(data)); b = min(len(data), a + rng.randrange(1, 4096))
        data[a:b] = bytes(b - a)
    f = tempfile.mktemp(suffix=".bin"); db = f + ".erdb"
    open(f, "wb").write(data)
    try:
        r = subprocess.run([er, "open", f, "-o", db, "-q"], capture_output=True, timeout=30)
        if r.returncode < 0:
            print(f"CRASH sig {-r.returncode} on open  seed={src} mode={mode} iter={i}"); bad += 1
            os.rename(f, f"/tmp/crash_{i}.bin"); continue
        if r.returncode == 0:
            r2 = subprocess.run([er, db, "decompall"], capture_output=True, timeout=60)
            if r2.returncode < 0:
                print(f"CRASH sig {-r2.returncode} on decompall seed={src} mode={mode} iter={i}"); bad += 1
                os.rename(f, f"/tmp/crash_{i}.bin"); continue
    except subprocess.TimeoutExpired:
        print(f"HANG seed={src} mode={mode} iter={i}"); bad += 1
        os.rename(f, f"/tmp/hang_{i}.bin"); continue
    for p in (f, db):
        try: os.remove(p)
        except OSError: pass
print(f"fuzz done: {iters} cases, {bad} failures")
sys.exit(1 if bad else 0)
