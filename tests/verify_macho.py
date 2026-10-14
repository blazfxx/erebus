#!/usr/bin/env python3
"""Cross-check erebus listing against otool -tv (llvm). Usage: verify_macho.py <binary> [arch]"""
import re, subprocess, sys, os, tempfile

binp = sys.argv[1]
arch = sys.argv[2] if len(sys.argv) > 2 else "arm64"
er = os.path.join(os.path.dirname(__file__), "..", "build", "erebus")
db = tempfile.mktemp(suffix=".erdb")
subprocess.run([er, "open", binp, "-o", db, "--arch", arch, "-q"], check=True)
realarch = arch

def otool(args):
    for a in [arch]:
        r = subprocess.run(["otool", "-arch", a] + args + [binp], capture_output=True, text=True)
        if r.stdout.strip() and "Can't" not in r.stderr:
            return r.stdout
    return subprocess.run(["otool"] + args + [binp], capture_output=True, text=True).stdout
ot = otool(["-tv"]) + otool(["-v", "-s", "__TEXT", "__stubs"]) + otool(["-v", "-s", "__TEXT", "__auth_stubs"])
ref = {}
for ln in ot.splitlines():
    m = re.match(r"^([0-9a-f]{8,16})\s+(\S+)(?:\s+(.*))?$", ln)
    if m:
        ref[int(m.group(1), 16)] = m.group(2)

funcs = subprocess.run([er, db, "funcs"], capture_output=True, text=True).stdout.splitlines()
starts = [int(l.split()[0], 16) for l in funcs if re.match(r"^[0-9a-f]{16}\s", l)]
ours = {}
for s in starts:
    out = subprocess.run([er, db, "disasm", hex(s)], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        m = re.match(r"^  ([0-9a-f]{16})  (\S+)", ln)
        if m: ours[int(m.group(1), 16)] = m.group(2)

bad_addr = [a for a in ours if a not in ref]
mism = [] if arch == 'x86_64' else [(a, ours[a], ref[a]) for a in ours if a in ref and ours[a].split('.')[0] != ref[a].split('.')[0]]
miss = [a for a in ref if a not in ours]
print(f"{binp} [{arch}]: ref insns={len(ref)} ours={len(ours)} funcs={len(starts)}")
print(f"  addresses we list that otool doesn't: {len(bad_addr)}")
print(f"  mnemonic mismatches: {len(mism)}")
print(f"  otool insns we never reached: {len(miss)} ({100*len(miss)/max(1,len(ref)):.1f}%)")
for a, o, r in mism[:8]: print(f"    {a:x}: ours={o} otool={r}")
for a in bad_addr[:5]: print(f"    bad addr {a:x}")
if "-v" in sys.argv:
    for a in sorted(miss)[:40]: print(f"    miss {a:x} {ref[a]}")
os.remove(db)
