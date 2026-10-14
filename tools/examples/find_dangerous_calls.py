#!/usr/bin/env python3
"""Example plugin: list functions that call risky libc routines, with the callsite string args."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from erebus import Erebus

RISKY = ("strcpy", "strcat", "sprintf", "gets", "system", "popen")

with Erebus.open(sys.argv[1], arch=sys.argv[2] if len(sys.argv) > 2 else "") as e:
    for addr, name in e.imports():
        short = name.lstrip("_").replace("_ptr", "")
        if short not in RISKY:
            continue
        print(f"{short}: {len(e.xrefs(addr))} reference(s)")
        for x in e.xrefs(addr):
            fn = e.where(x.addr).get("func")
            print("   ", x.addr, x.name, "in", fn)
