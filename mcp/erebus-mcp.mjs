#!/usr/bin/env node
// Erebus MCP bridge: serves Erebus's analysis to MCP clients using the "database supervisor" tool profile
// that REA (github.com/morluto/rea) expects from an IDA MCP server, so REA runs on Erebus instead of IDA.
//
//   REA_ANALYSIS_PROVIDER=ida  REA_IDA_MCP_CONFIG=<file with {"mode":"headless","command":…,"args":[…]}>
//
// It speaks MCP over stdio (newline-delimited JSON-RPC) and has no dependencies: each opened binary is
// analysed by the `erebus` engine and served from a private local `erebus serve` that this process owns.
// Set EREBUS_BIN to the engine; otherwise ../bin/erebus next to this file, then `erebus` on PATH.
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";

const VERSION = "0.3.1";
const here = dirname(fileURLToPath(import.meta.url));
const ENGINE = [process.env.EREBUS_BIN, join(here, "..", "bin", "erebus"), join(here, "erebus")].find(
  (p) => p && existsSync(p),
) ?? "erebus";

const sessions = new Map(); // id -> { id, input, db, proc, url, base, name }
let scratch;
const scratchDir = () => (scratch ??= mkdtempSync(join(tmpdir(), "erebus-mcp-")));

// ---- engine ---------------------------------------------------------------------------------------------

function run(args) {
  return new Promise((resolve, reject) => {
    const p = spawn(ENGINE, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "", err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", (e) => reject(new Error(`Cannot start the Erebus engine (${ENGINE}): ${e.message}`)));
    p.on("close", (code) => (code === 0 ? resolve(out) : reject(new Error(err.trim() || `erebus exited with ${code}`))));
  });
}

function serve(db) {
  return new Promise((resolve, reject) => {
    const proc = spawn(ENGINE, ["serve", db, "--port", "0", "--no-open", "--watch-pid", String(process.pid)], {
      stdio: ["ignore", "pipe", "ignore"],
    });
    let buf = "";
    const timer = setTimeout(() => { proc.kill(); reject(new Error("The Erebus engine did not start.")); }, 30_000);
    proc.on("error", (e) => { clearTimeout(timer); reject(e); });
    proc.on("exit", () => { clearTimeout(timer); reject(new Error("The Erebus engine stopped.")); });
    proc.stdout.on("data", (d) => {
      buf += d;
      const m = /http:\/\/127\.0\.0\.1:\d+/.exec(buf);
      if (m) { clearTimeout(timer); proc.removeAllListeners("exit"); resolve({ proc, url: m[0] }); }
    });
  });
}

async function api(s, path, params = {}) {
  const u = new URL(path, s.url);
  for (const [k, v] of Object.entries(params)) u.searchParams.set(k, String(v));
  const res = await fetch(u);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) { const e = new Error(body.error ?? `engine answered ${res.status}`); e.status = res.status; throw e; }
  return body;
}

const hex = (a) => `0x${BigInt(a).toString(16)}`;
const flat = (parts) => (parts ?? []).map((p) => p.t).join("");
const fn = (f) => ({ addr: hex(f.a), name: f.n, size: hex(f.s ?? 0) });

function session(id) {
  const s = sessions.get(id) ?? (sessions.size === 1 && !id ? [...sessions.values()][0] : undefined);
  if (!s) throw new Error(id ? `Session not found: ${id}` : "No database is open. Call idb_open first.");
  return s;
}

// ---- tools ----------------------------------------------------------------------------------------------

const tools = {
  async idb_open({ input_path, preferred_session_id }) {
    if (typeof input_path !== "string" || !existsSync(input_path)) return { error: `Input not found: ${input_path}` };
    const id = preferred_session_id || `erebus-${sessions.size + 1}-${Date.now().toString(36)}`;
    if (sessions.has(id)) return { error: `Session already exists: ${id}` };
    const dir = join(scratchDir(), id);
    mkdirSync(dir, { recursive: true });
    const db = join(dir, "analysis.erdb");
    try {
      await run(["open", input_path, "-o", db, "-q"]);
      const { proc, url } = await serve(db);
      const s = { id, input: input_path, db, proc, url, dir };
      const info = await api(s, "/api/info");
      s.base = info.base;
      s.module = basename(input_path);
      sessions.set(id, s);
    } catch (e) {
      rmSync(dir, { recursive: true, force: true });
      return { error: e.message };
    }
    return { success: true, session: { session_id: id, input_path, backend: "worker", owned: true, is_active: true } };
  },

  async idb_list() {
    return {
      sessions: [...sessions.values()].map((s) => ({
        session_id: s.id, input_path: s.input, owned: true, backend: "worker", is_active: true,
      })),
    };
  },

  async idb_close({ database }) {
    const s = sessions.get(database);
    if (!s) return { error: `Session not found: ${database}` };
    sessions.delete(database);
    s.proc.kill();
    rmSync(s.dir, { recursive: true, force: true });
    return { success: true, session_id: s.id, saved: false, owned: true, backend: "worker" };
  },

  async server_health({ database }) {
    const s = session(database);
    return {
      status: "ok", input_path: s.input, idb_path: s.db, imagebase: hex(BigInt(s.base)),
      auto_analysis_ready: true, module: s.module, engine: `erebus ${VERSION}`,
    };
  },

  async list_funcs({ database, queries }) {
    const s = session(database);
    const q = Array.isArray(queries) ? queries[0] ?? {} : queries ?? {};
    const offset = Number(q.offset ?? 0), count = Math.min(Number(q.count ?? 100) || 100, 1000);
    const all = (await api(s, "/api/funcs", { q: q.filter ?? "", limit: 1_000_000 })).items;
    const page = all.slice(offset, offset + count).map(fn);
    return [{ data: page, next_offset: offset + count < all.length ? offset + count : null }];
  },

  async lookup_funcs({ database, queries }) {
    const s = session(database);
    const rows = [];
    for (const query of queries ?? []) {
      try {
        const isAddr = /^(0x)?[0-9a-f]+$/i.test(query) && /^0x/i.test(query);
        if (isAddr) {
          const f = await api(s, "/api/func", { a: query });
          rows.push({ query, fn: { addr: hex(f.a), name: f.n, size: hex(f.size) }, error: null });
        } else {
          const found = (await api(s, "/api/funcs", { q: query, limit: 1_000_000 })).items.find((f) => f.n === query);
          rows.push(found ? { query, fn: fn(found), error: null } : { query, fn: null, error: "Not found" });
        }
      } catch (e) {
        rows.push({ query, fn: null, error: e.status === 404 ? "Not a function" : e.status === 400 ? "Not found" : e.message });
      }
    }
    return rows;
  },

  async find_regex({ database, pattern, offset = 0, limit = 100 }) {
    const s = session(database);
    let re;
    try {
      const flags = /^\(\?s\)/.test(pattern ?? "") ? "s" : "";
      re = new RegExp((pattern ?? "").replace(/^\(\?s\)/, "") || ".*", flags + "u");
    } catch (e) {
      return { matches: [], cursor: { done: true }, error: `Invalid pattern: ${e.message}` };
    }
    const all = (await api(s, "/api/list", { kind: "strings" })).items.filter((x) => re.test(x.n));
    const matches = all.slice(offset, offset + limit).map((x) => ({ addr: x.a, string: x.n }));
    return { matches, cursor: offset + limit < all.length ? { next: offset + limit } : { done: true } };
  },

  async disasm({ database, addr, offset = 0, max_instructions = 100 }) {
    const s = session(database);
    let f;
    try { f = await api(s, "/api/func", { a: addr }); } catch (e) { return { asm: null, error: e.message, cursor: { done: true } }; }
    const lines = [];
    for (const b of f.blocks) for (const i of b.insns) {
      const comment = flat(i.c);
      lines.push({ addr: i.a, instruction: `${i.m} ${flat(i.o)}`.trim(), comments: comment ? [comment] : [] });
    }
    const page = lines.slice(offset, offset + max_instructions);
    return {
      asm: { name: f.n, start_ea: hex(f.a), lines: page },
      cursor: offset + max_instructions < lines.length ? { next: offset + max_instructions } : { done: true },
    };
  },

  async decompile({ database, addr, offset = 0, max_lines = 100 }) {
    const s = session(database);
    let r;
    try { r = await api(s, "/api/pseudo", { a: addr }); } catch (e) { return { code: null, error: e.message, cursor: { done: true } }; }
    const lines = r.lines.map((l) => "    ".repeat(l.i) + flat(l.p));
    const page = lines.slice(offset, offset + max_lines);
    return {
      code: page.join("\n"), line_count: page.length, total_lines: lines.length,
      cursor: offset + max_lines < lines.length ? { next: offset + max_lines } : { done: true },
    };
  },

  async xrefs_to({ database, addrs, limit = 1000 }) {
    const s = session(database);
    const rows = [];
    for (const a of addrs ?? []) {
      try {
        const r = await api(s, "/api/xrefs", { a });
        const xrefs = [];
        for (const x of r.items.slice(0, limit)) {
          let owner = null;
          try { const f = await api(s, "/api/where", { a: x.a }); if (f.func) { const g = (await api(s, "/api/func", { a: f.func })); owner = { addr: hex(g.a), name: g.n, size: hex(g.size) }; } } catch { /* not in a function */ }
          xrefs.push({ addr: x.a, type: x.t, fn: owner });
        }
        rows.push({ xrefs, more: r.items.length > limit });
      } catch (e) { rows.push({ xrefs: null, error: e.message }); }
    }
    return rows;
  },

  async callees({ database, addrs, limit = 500 }) {
    const s = session(database);
    const rows = [];
    for (const a of addrs ?? []) {
      try {
        const g = await api(s, "/api/callgraph", { a, d: 1 });
        const out = [];
        for (const c of g.c.slice(0, limit)) {
          const w = await api(s, "/api/where", { a: c.a });
          out.push({ addr: c.a, name: c.n, type: w.func ? "internal" : "external" });
        }
        rows.push({ callees: out, more: g.c.length > limit });
      } catch (e) { rows.push({ callees: null, error: e.message }); }
    }
    return rows;
  },

  async callgraph({ database, roots }) {
    const s = session(database);
    const rows = [];
    for (const root of roots ?? []) {
      try {
        const g = await api(s, "/api/callgraph", { a: root, d: 1 });
        rows.push({
          root, nodes: [{ addr: g.a, name: g.n }, ...g.c.map((c) => ({ addr: c.a, name: c.n }))],
          edges: g.c.map((c) => ({ from: g.a, to: c.a, type: "call" })),
        });
      } catch (e) { rows.push({ root, nodes: [], edges: [], error: e.message }); }
    }
    return rows;
  },

  async survey_binary({ database }) {
    const s = session(database);
    const info = await api(s, "/api/info");
    const segments = info.segments.map((g) => ({
      name: g.name, start: hex(BigInt(g.a)), end: hex(BigInt(g.a) + BigInt(g.size)), size: hex(g.size), perms: g.perms,
    }));
    return { statistics: { total_segments: segments.length, functions: info.funcs, strings: info.strings }, segments };
  },
};

const schema = (props = {}, required = []) => ({ type: "object", properties: props, required });
const str = { type: "string" }, num = { type: "number" }, db = { type: "string", description: "Session id from idb_open" };
const descriptions = {
  idb_open: ["Analyse a binary with Erebus and open it as a session", schema({ input_path: str, preferred_session_id: str }, ["input_path"])],
  idb_list: ["List open sessions", schema()],
  idb_close: ["Close a session", schema({ database: db, save: { type: "boolean" } }, ["database"])],
  server_health: ["Report the session's input and readiness", schema({ database: db })],
  list_funcs: ["Page through functions", schema({ database: db, queries: { type: "object" } })],
  lookup_funcs: ["Find functions by name or address", schema({ database: db, queries: { type: "array", items: str } }, ["queries"])],
  find_regex: ["Search strings with a regular expression", schema({ database: db, pattern: str, offset: num, limit: num })],
  disasm: ["Disassemble a function", schema({ database: db, addr: str, offset: num, max_instructions: num }, ["addr"])],
  decompile: ["Decompile a function to pseudo-C", schema({ database: db, addr: str, offset: num, max_lines: num }, ["addr"])],
  xrefs_to: ["Cross-references to addresses", schema({ database: db, addrs: { type: "array", items: str }, limit: num }, ["addrs"])],
  callees: ["Functions called by a function", schema({ database: db, addrs: { type: "array", items: str }, limit: num }, ["addrs"])],
  callgraph: ["Call edges of a function", schema({ database: db, roots: { type: "array", items: str }, max_depth: num }, ["roots"])],
  survey_binary: ["Segments and counts", schema({ database: db, detail_level: str })],
};

// ---- MCP over stdio -------------------------------------------------------------------------------------

const send = (m) => process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...m }) + "\n");

async function handle(msg) {
  const { id, method, params } = msg;
  if (id === undefined) return; // notifications need no answer
  try {
    if (method === "initialize") {
      return send({ id, result: {
        protocolVersion: params?.protocolVersion ?? "2024-11-05",
        capabilities: { tools: {} },
        serverInfo: { name: "erebus-mcp", version: VERSION },
      } });
    }
    if (method === "ping") return send({ id, result: {} });
    if (method === "tools/list") {
      return send({ id, result: { tools: Object.entries(descriptions).map(([name, [description, inputSchema]]) => ({ name, description, inputSchema })) } });
    }
    if (method === "tools/call") {
      const tool = tools[params?.name];
      if (!tool) return send({ id, result: { isError: true, content: [{ type: "text", text: `Unknown tool ${params?.name}` }] } });
      try {
        const value = await tool(params.arguments ?? {});
        const text = JSON.stringify(value);
        return send({ id, result: { content: [{ type: "text", text }] } });
      } catch (e) {
        return send({ id, result: { isError: true, content: [{ type: "text", text: e.message }] } });
      }
    }
    send({ id, error: { code: -32601, message: `Method not found: ${method}` } });
  } catch (e) {
    send({ id, error: { code: -32603, message: e.message } });
  }
}

function shutdown() {
  for (const s of sessions.values()) s.proc.kill();
  if (scratch) rmSync(scratch, { recursive: true, force: true });
}
process.on("exit", shutdown);
for (const sig of ["SIGINT", "SIGTERM"]) process.on(sig, () => process.exit(0));
process.stdin.on("end", () => process.exit(0));

const lines = createInterface({ input: process.stdin });
lines.on("line", (line) => {
  if (!line.trim()) return;
  let msg;
  try { msg = JSON.parse(line); } catch { return; }
  void handle(msg);
});
