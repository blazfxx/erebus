#!/usr/bin/env python3
"""Erebus scripting client: drive an Erebus database over its local HTTP API (standard library only).

    from erebus import Erebus
    with Erebus.open("/bin/ls", arch="arm64e") as e:          # analyses + starts a private server
        for f in e.funcs("usage"): print(f.addr, f.name)
        print(e.pseudo("start")[:400])

or attach to a running `erebus serve`:   e = Erebus("http://127.0.0.1:8787")
"""
import json, os, re, shutil, subprocess, sys, tempfile, time, urllib.error, urllib.parse, urllib.request
from dataclasses import dataclass
from typing import Iterator, List, Optional

def _find_bin() -> str:
    """$EREBUS_BIN, a dev build next to this file, the app bundle, or `erebus` on PATH."""
    here = os.path.dirname(os.path.abspath(__file__))
    for c in (os.environ.get("EREBUS_BIN"), os.path.join(here, "..", "build", "erebus"),
              "/Applications/Erebus.app/Contents/Resources/bin/erebus", shutil.which("erebus")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return "erebus"


BIN = _find_bin()


class ErebusError(RuntimeError):
    pass


@dataclass
class Func:
    addr: str
    name: str
    size: int
    thunk: bool = False
    noret: bool = False

    @property
    def a(self) -> int:
        return int(self.addr, 16)


@dataclass
class Xref:
    addr: str
    name: str
    kind: str


@dataclass
class Insn:
    addr: str
    bytes: str
    mnem: str
    ops: str
    comment: str
    patched: bool = False

    def __str__(self):
        return f"{self.addr}  {self.mnem} {self.ops}".rstrip() + (f"  ; {self.comment}" if self.comment else "")


class Erebus:
    def __init__(self, url: str, _proc: Optional[subprocess.Popen] = None, _tmp: Optional[str] = None):
        self.url = url.rstrip("/")
        self._proc, self._tmp = _proc, _tmp

    # ---- lifecycle ----------------------------------------------------------------
    @classmethod
    def open(cls, binary: str, arch: str = "", db: Optional[str] = None, extra: Optional[List[str]] = None) -> "Erebus":
        """Analyse `binary` into a database and serve it on a free port (cleaned up on close())."""
        tmp = None
        if db is None:
            tmp = tempfile.mkdtemp(prefix="erebus_")
            db = os.path.join(tmp, "db.erdb")
        cmd = [BIN, "open", binary, "-o", db, "-q"] + (["--arch", arch] if arch else []) + (extra or [])
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            raise ErebusError(r.stderr.strip() or "analysis failed")
        return cls.serve(db, _tmp=tmp)

    @classmethod
    def serve(cls, db: str, _tmp: Optional[str] = None) -> "Erebus":
        p = subprocess.Popen([BIN, "serve", db, "--port", "0", "--no-open"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        line = p.stdout.readline()
        m = re.search(r"(http://[\d.]+:\d+)", line)
        if not m:
            p.kill()
            raise ErebusError("server did not start: " + line)
        return cls(m.group(1), p, _tmp)

    def close(self):
        if self._proc:
            self._proc.terminate()
            self._proc.wait()
            self._proc = None
        if self._tmp:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()

    # ---- transport ------------------------------------------------------------------
    def _get(self, path: str, **q):
        qs = urllib.parse.urlencode({k: v for k, v in q.items() if v is not None})
        return self._req(urllib.request.Request(f"{self.url}{path}?{qs}"))

    def _post(self, path: str, body: dict):
        req = urllib.request.Request(f"{self.url}{path}", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        return self._req(req)

    @staticmethod
    def _req(req):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            try:
                msg = json.load(e).get("error", e.reason)
            except Exception:
                msg = e.reason
            raise ErebusError(msg) from None

    # ---- queries ------------------------------------------------------------------------
    def info(self) -> dict:
        return self._get("/api/info")

    def funcs(self, q: str = "") -> List[Func]:
        r = self._get("/api/funcs", q=q, limit=1000000)
        return [Func(i["a"], i["n"], i["s"], i["t"], i["r"]) for i in r["items"]]

    def names(self, q: str = "") -> List[tuple]:
        return [(i["a"], i["n"]) for i in self._get("/api/list", kind="names", q=q)["items"]]

    def imports(self, q: str = "") -> List[tuple]:
        return [(i["a"], i["n"]) for i in self._get("/api/list", kind="imports", q=q)["items"]]

    def exports(self, q: str = "") -> List[tuple]:
        return [(i["a"], i["n"]) for i in self._get("/api/list", kind="exports", q=q)["items"]]

    def strings(self, q: str = "") -> List[tuple]:
        return [(i["a"], i["n"]) for i in self._get("/api/list", kind="strings", q=q)["items"]]

    def where(self, loc: str) -> dict:
        return self._get("/api/where", a=loc)

    def xrefs(self, loc: str) -> List[Xref]:
        return [Xref(i["a"], i["n"], i["t"]) for i in self._get("/api/xrefs", a=loc)["items"]]

    def callgraph(self, loc: str, depth: int = 2) -> dict:
        return self._get("/api/callgraph", a=loc, d=depth)

    @staticmethod
    def _flat(parts) -> str:
        return "".join(p["t"] for p in parts)

    def _insn(self, i: dict) -> Insn:
        return Insn(i["a"], i["b"], i["m"], self._flat(i["o"]), self._flat(i["c"]), bool(i.get("p")))

    def disasm(self, loc: str) -> List[Insn]:
        """All instructions of the function containing `loc`."""
        f = self._get("/api/func", a=loc)
        return [self._insn(i) for b in f["blocks"] for i in b["insns"]]

    def linear(self, loc: str, n: int = 32) -> List[Insn]:
        return [self._insn(i) for i in self._get("/api/lin", a=loc, n=n)["insns"]]

    def blocks(self, loc: str) -> dict:
        """Basic blocks + edges of the function containing `loc` (raw API shape)."""
        return self._get("/api/func", a=loc)

    def pseudo(self, loc: str) -> str:
        r = self._get("/api/pseudo", a=loc)
        return "\n".join("    " * l["i"] + "".join(p["t"] for p in l["p"]) for l in r["lines"])

    def hex(self, loc: str, n: int = 256) -> bytes:
        return bytes.fromhex(self._get("/api/hex", a=loc, n=n)["hex"])

    def find(self, pattern: str = "", text: str = "") -> List[tuple]:
        """Byte pattern ('48 8b ?? 05') or `text=` search over all segments."""
        r = self._get("/api/find", hex=pattern or None, text=text or None)
        return [(i["a"], i["n"]) for i in r["items"]]

    def iter_calls(self, loc: str) -> Iterator[str]:
        """Names of functions called (directly) from the function containing `loc`."""
        def walk(n):
            for c in n["c"]:
                yield c["n"]
        yield from walk(self.callgraph(loc, 1))

    # ---- edits ------------------------------------------------------------------------------
    def rename(self, loc: str, name: str):
        return self._post("/api/rename", {"a": loc, "name": name})

    def comment(self, loc: str, text: str):
        return self._post("/api/comment", {"a": loc, "text": text})

    def patch(self, loc: str, hexbytes: str):
        return self._post("/api/patch", {"a": loc, "hex": hexbytes})

    def asm(self, loc: str, text: str, force: bool = False):
        return self._post("/api/asm", {"a": loc, "text": text, "force": force})

    def unpatch(self, loc: str):
        return self._post("/api/unpatch", {"a": loc})

    def patches(self) -> List[dict]:
        return self._get("/api/patches")["items"]

    def reanalyze(self) -> dict:
        return self._post("/api/reanalyze", {})

    def export(self, path: str, sign: bool = True):
        return self._post("/api/export", {"path": path, "sign": sign})


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(0)
    with Erebus.open(sys.argv[1], arch=sys.argv[2] if len(sys.argv) > 2 else "") as e:
        i = e.info()
        print(f"{i['file']}: {i['funcs']} functions, {i['insns']} insns")
        print(e.pseudo(i["entry"] or i["segments"][0]["a"]))
