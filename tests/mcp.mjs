// Drives mcp/erebus-mcp.mjs over stdio the way REA does: open a binary, page functions, decompile, close.
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import assert from "node:assert/strict";

const [elf] = process.argv.slice(2);
const p = spawn(process.execPath, ["mcp/erebus-mcp.mjs"], { stdio: ["pipe", "pipe", "inherit"] });
const pending = new Map();
let n = 0;
createInterface({ input: p.stdout }).on("line", (l) => { const m = JSON.parse(l); pending.get(m.id)?.(m); });
const rpc = (method, params) => new Promise((res) => { const id = ++n; pending.set(id, res); p.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n"); });
const call = async (name, args) => { const r = (await rpc("tools/call", { name, arguments: args })).result; assert.ok(!r.isError, r.content?.[0]?.text); return JSON.parse(r.content[0].text); };

const init = (await rpc("initialize", { protocolVersion: "2025-03-26" })).result;
assert.equal(init.serverInfo.name, "erebus-mcp");
const names = (await rpc("tools/list")).result.tools.map((t) => t.name);
for (const t of ["idb_open", "idb_list", "idb_close", "server_health", "list_funcs", "lookup_funcs", "find_regex", "decompile", "disasm", "callees", "xrefs_to"]) assert.ok(names.includes(t), t);

const opened = await call("idb_open", { input_path: elf, preferred_session_id: "t1" });
assert.equal(opened.session.session_id, "t1");
assert.equal((await call("idb_open", { input_path: "/nonexistent" })).error.startsWith("Input not found"), true);
assert.equal((await call("idb_list", {})).sessions.length, 1);
const health = await call("server_health", { database: "t1" });
assert.equal(health.status, "ok");
const page = (await call("list_funcs", { database: "t1", queries: { offset: 0, count: 100 } }))[0];
const b = page.data.find((f) => f.name === "func_b");
assert.ok(b, "func_b listed");
const look = (await call("lookup_funcs", { database: "t1", queries: ["func_b", "no_such_fn"] }));
assert.equal(look[0].fn.addr, b.addr);
assert.equal(look[1].error, "Not found");
const code = await call("decompile", { database: "t1", addr: b.addr });
assert.match(code.code, /func_b/);
const asm = await call("disasm", { database: "t1", addr: b.addr });
assert.equal(asm.asm.start_ea, b.addr);
assert.ok(asm.asm.lines.length > 3);
assert.equal((await call("xrefs_to", { database: "t1", addrs: [b.addr] }))[0].xrefs.length > 0, true);
assert.equal((await call("idb_close", { database: "nope" })).error, "Session not found: nope");
const closed = await call("idb_close", { database: "t1", save: false });
assert.equal(closed.success, true);
assert.equal((await call("idb_list", {})).sessions.length, 0);
p.stdin.end();
console.log("mcp bridge: ok");
