#include "core/db.h"

#include <sqlite3.h>

#include <cstdio>
#include <cstring>

namespace er {
namespace {

// SQLite integers are signed 64-bit; addresses round-trip through the same bits.
inline sqlite3_int64 S(uint64_t v) { return static_cast<sqlite3_int64>(v); }
inline uint64_t U(sqlite3_int64 v) { return static_cast<uint64_t>(v); }

struct Stmt {
    sqlite3_stmt* s = nullptr;
    Stmt(sqlite3* db, const char* sql) { sqlite3_prepare_v2(db, sql, -1, &s, nullptr); }
    ~Stmt() { if (s) sqlite3_finalize(s); }
    bool ok() const { return s != nullptr; }
    void reset() { sqlite3_reset(s); sqlite3_clear_bindings(s); }
    bool step() { return sqlite3_step(s) == SQLITE_ROW; }
    void run() { sqlite3_step(s); reset(); }
    void i(int idx, uint64_t v) { sqlite3_bind_int64(s, idx, S(v)); }
    void t(int idx, const std::string& v) { sqlite3_bind_text(s, idx, v.c_str(), int(v.size()), SQLITE_TRANSIENT); }
    uint64_t gi(int c) { return U(sqlite3_column_int64(s, c)); }
    std::string gt(int c) {
        const unsigned char* p = sqlite3_column_text(s, c);
        return p ? std::string(reinterpret_cast<const char*>(p), sqlite3_column_bytes(s, c)) : std::string();
    }
};

const char* kSchema = R"SQL(
CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE segments(idx INTEGER PRIMARY KEY, name TEXT, addr INTEGER, size INTEGER, perms INTEGER, data BLOB, fileoff INTEGER, hasfile INTEGER);
CREATE TABLE patches(id INTEGER PRIMARY KEY AUTOINCREMENT, addr INTEGER, orig BLOB, bytes BLOB);
CREATE TABLE sections(idx INTEGER PRIMARY KEY, name TEXT, seg TEXT, addr INTEGER, size INTEGER, kind INTEGER);
CREATE TABLE symbols(idx INTEGER PRIMARY KEY, name TEXT, addr INTEGER, kind INTEGER, exported INTEGER);
CREATE TABLE funcstarts(addr INTEGER);
CREATE TABLE funcs(start INTEGER PRIMARY KEY, end INTEGER, noret INTEGER, thunk INTEGER);
CREATE TABLE blocks(func INTEGER, start INTEGER, end INTEGER);
CREATE TABLE jtables(func INTEGER, insn INTEGER, idxreg TEXT, idx INTEGER, target INTEGER);
CREATE TABLE edges(func INTEGER, src INTEGER, dst INTEGER, kind INTEGER);
CREATE TABLE xrefs(src INTEGER, dst INTEGER, type INTEGER);
CREATE INDEX xrefs_dst ON xrefs(dst);
CREATE INDEX xrefs_src ON xrefs(src);
CREATE TABLE names(addr INTEGER PRIMARY KEY, name TEXT, kind INTEGER);
CREATE TABLE strings(addr INTEGER PRIMARY KEY, length INTEGER, wide INTEGER, text TEXT);
CREATE TABLE comments(addr INTEGER PRIMARY KEY, text TEXT);
)SQL";

}  // namespace

Database::~Database() {
    if (db_) sqlite3_close(db_);
}

bool Database::exec(const char* sql, std::string& err) {
    char* msg = nullptr;
    if (sqlite3_exec(db_, sql, nullptr, nullptr, &msg) != SQLITE_OK) {
        err = msg ? msg : "sqlite error";
        sqlite3_free(msg);
        return false;
    }
    return true;
}

bool Database::create(const std::string& path, const Image& img, const Analysis& an, std::string& err) {
    if (db_) { sqlite3_close(db_); db_ = nullptr; }
    path_ = path;
    std::remove(path.c_str());
    if (sqlite3_open(path.c_str(), &db_) != SQLITE_OK) {
        err = "cannot create " + path;
        return false;
    }
    if (!exec("PRAGMA journal_mode=OFF; PRAGMA synchronous=OFF;", err)) return false;
    if (!exec(kSchema, err)) return false;
    if (!exec("BEGIN", err)) return false;

    {
        Stmt m(db_, "INSERT INTO meta VALUES(?,?)");
        auto put = [&](const char* k, const std::string& v) { m.t(1, k); m.t(2, v); m.run(); };
        put("path", img.path);
        put("format", img.format);
        put("arch", archName(img.arch));
        put("bits", std::to_string(img.bits));
        put("base", std::to_string(img.base));
        put("entry", std::to_string(img.entry));
        put("hasEntry", img.hasEntry ? "1" : "0");
        put("insns", std::to_string(an.insnCount));
        put("codeBytes", std::to_string(an.codeBytes));
        put("coveredBytes", std::to_string(an.coveredBytes));
    }
    {
        Stmt s(db_, "INSERT INTO segments VALUES(?,?,?,?,?,?,?,?)");
        int idx = 0;
        for (const auto& g : img.segments) {
            s.i(1, idx++);
            s.t(2, g.name);
            s.i(3, g.addr);
            s.i(4, g.size);
            s.i(5, g.perms);
            sqlite3_bind_blob(s.s, 6, g.data.data(), int(g.data.size()), SQLITE_TRANSIENT);
            s.i(7, g.fileoff);
            s.i(8, g.hasFile);
            s.run();
        }
    }
    {
        Stmt s(db_, "INSERT INTO sections VALUES(?,?,?,?,?,?)");
        int idx = 0;
        for (const auto& g : img.sections) {
            s.i(1, idx++);
            s.t(2, g.name);
            s.t(3, g.seg);
            s.i(4, g.addr);
            s.i(5, g.size);
            s.i(6, uint8_t(g.kind));
            s.run();
        }
    }
    {
        Stmt s(db_, "INSERT INTO symbols VALUES(?,?,?,?,?)");
        int idx = 0;
        for (const auto& g : img.symbols) {
            s.i(1, idx++);
            s.t(2, g.name);
            s.i(3, g.addr);
            s.i(4, uint8_t(g.kind));
            s.i(5, g.exported);
            s.run();
        }
        Stmt f(db_, "INSERT INTO funcstarts VALUES(?)");
        for (uint64_t a : img.funcStarts) { f.i(1, a); f.run(); }
    }
    {
        Stmt f(db_, "INSERT INTO funcs VALUES(?,?,?,?)");
        Stmt b(db_, "INSERT INTO blocks VALUES(?,?,?)");
        Stmt e(db_, "INSERT INTO edges VALUES(?,?,?,?)");
        Stmt jt(db_, "INSERT INTO jtables VALUES(?,?,?,?,?)");
        for (const auto& [a, fn] : an.funcs) {
            f.i(1, fn.start); f.i(2, fn.end); f.i(3, fn.noret); f.i(4, fn.thunk); f.run();
            for (const auto& bl : fn.blocks) { b.i(1, fn.start); b.i(2, bl.start); b.i(3, bl.end); b.run(); }
            for (const auto& ed : fn.edges) {
                e.i(1, fn.start); e.i(2, ed.src); e.i(3, ed.dst); e.i(4, uint8_t(ed.kind)); e.run();
            }
            for (const auto& [insn, t] : fn.jt)
                for (size_t k = 0; k < t.entries.size(); ++k) {
                    jt.i(1, fn.start); jt.i(2, insn); jt.t(3, t.idxReg); jt.i(4, k); jt.i(5, t.entries[k]); jt.run();
                }
        }
    }
    {
        Stmt x(db_, "INSERT INTO xrefs VALUES(?,?,?)");
        for (const auto& r : an.xrefs) { x.i(1, r.from); x.i(2, r.to); x.i(3, uint8_t(r.type)); x.run(); }
        Stmt n(db_, "INSERT INTO names VALUES(?,?,?)");
        for (const auto& [a, nm] : an.names) { n.i(1, a); n.t(2, nm.name); n.i(3, uint8_t(nm.kind)); n.run(); }
        Stmt st(db_, "INSERT INTO strings VALUES(?,?,?,?)");
        for (const auto& [a, s] : an.strings) { st.i(1, a); st.i(2, s.length); st.i(3, s.wide); st.t(4, s.text); st.run(); }
        Stmt c(db_, "INSERT INTO comments VALUES(?,?)");
        for (const auto& [a, t] : an.comments) { c.i(1, a); c.t(2, t); c.run(); }
    }
    return exec("COMMIT", err);
}

bool Database::open(const std::string& path, std::string& err) {
    path_ = path;
    if (sqlite3_open_v2(path.c_str(), &db_, SQLITE_OPEN_READWRITE, nullptr) != SQLITE_OK) {
        err = "cannot open " + path;
        return false;
    }
    return true;
}

bool Database::load(Image& img, Analysis& an, std::string& err) {
    {
        Stmt m(db_, "SELECT key,value FROM meta");
        if (!m.ok()) { err = "not an erebus database"; return false; }
        while (m.step()) {
            std::string k = m.gt(0), v = m.gt(1);
            if (k == "path") img.path = v;
            else if (k == "format") img.format = v;
            else if (k == "arch") img.arch = archFromName(v);
            else if (k == "bits") img.bits = unsigned(std::stoul(v));
            else if (k == "base") img.base = std::stoull(v);
            else if (k == "entry") img.entry = std::stoull(v);
            else if (k == "hasEntry") img.hasEntry = v == "1";
            else if (k == "insns") an.insnCount = std::stoull(v);
            else if (k == "codeBytes") an.codeBytes = std::stoull(v);
            else if (k == "coveredBytes") an.coveredBytes = std::stoull(v);
        }
    }
    {
        Stmt s(db_, "SELECT name,addr,size,perms,data,fileoff,hasfile FROM segments ORDER BY idx");
        while (s.step()) {
            Segment g;
            g.name = s.gt(0);
            g.addr = s.gi(1);
            g.size = s.gi(2);
            g.perms = uint8_t(s.gi(3));
            const void* p = sqlite3_column_blob(s.s, 4);
            int n = sqlite3_column_bytes(s.s, 4);
            if (p && n > 0) g.data.assign(static_cast<const uint8_t*>(p), static_cast<const uint8_t*>(p) + n);
            g.fileoff = s.gi(5);
            g.hasFile = s.gi(6) != 0;
            img.segments.push_back(std::move(g));
        }
    }
    {
        Stmt s(db_, "SELECT name,seg,addr,size,kind FROM sections ORDER BY idx");
        while (s.step()) {
            Section g;
            g.name = s.gt(0); g.seg = s.gt(1); g.addr = s.gi(2); g.size = s.gi(3);
            g.kind = SecKind(s.gi(4));
            img.sections.push_back(std::move(g));
        }
    }
    {
        Stmt s(db_, "SELECT name,addr,kind,exported FROM symbols ORDER BY idx");
        while (s.step()) {
            Symbol g;
            g.name = s.gt(0); g.addr = s.gi(1); g.kind = SymKind(s.gi(2)); g.exported = s.gi(3);
            img.symbols.push_back(std::move(g));
        }
        Stmt f(db_, "SELECT addr FROM funcstarts");
        while (f.step()) img.funcStarts.push_back(f.gi(0));
    }
    img.finalize();
    {
        Stmt f(db_, "SELECT start,end,noret,thunk FROM funcs ORDER BY start");
        while (f.step()) {
            Func fn;
            fn.start = f.gi(0); fn.end = f.gi(1); fn.noret = f.gi(2); fn.thunk = f.gi(3);
            an.funcs[fn.start] = std::move(fn);
        }
        Stmt b(db_, "SELECT func,start,end FROM blocks ORDER BY func,start");
        while (b.step()) {
            auto it = an.funcs.find(b.gi(0));
            if (it != an.funcs.end()) it->second.blocks.push_back({b.gi(1), b.gi(2)});
        }
        Stmt jt(db_, "SELECT func,insn,idxreg,idx,target FROM jtables ORDER BY func,insn,idx");
        while (jt.step()) {
            auto it = an.funcs.find(jt.gi(0));
            if (it == an.funcs.end()) continue;
            JumpTable& t = it->second.jt[jt.gi(1)];
            t.idxReg = jt.gt(2);
            t.entries.push_back(jt.gi(4));
        }
        Stmt e(db_, "SELECT func,src,dst,kind FROM edges");
        while (e.step()) {
            auto it = an.funcs.find(e.gi(0));
            if (it != an.funcs.end()) it->second.edges.push_back({e.gi(1), e.gi(2), EdgeKind(e.gi(3))});
        }
    }
    {
        Stmt x(db_, "SELECT src,dst,type FROM xrefs ORDER BY src,dst,type");
        while (x.step()) an.xrefs.push_back({x.gi(0), x.gi(1), XType(x.gi(2))});
        Stmt n(db_, "SELECT addr,name,kind FROM names");
        while (n.step()) an.names[n.gi(0)] = {n.gt(1), NameKind(n.gi(2))};
        Stmt st(db_, "SELECT addr,length,wide,text FROM strings");
        while (st.step()) an.strings[st.gi(0)] = {uint32_t(st.gi(1)), uint8_t(st.gi(2)), st.gt(3)};
        Stmt c(db_, "SELECT addr,text FROM comments");
        while (c.step()) an.comments[c.gi(0)] = c.gt(1);
    }
    (void)err;
    return true;
}

bool Database::writeBytes(size_t segIndex, uint64_t off, const uint8_t* data, size_t n, std::string& err) {
    sqlite3_blob* blob = nullptr;
    Stmt q(db_, "SELECT rowid FROM segments WHERE idx=?");
    q.i(1, segIndex);
    if (!q.step()) { err = "segment not in database"; return false; }
    sqlite3_int64 rowid = sqlite3_column_int64(q.s, 0);
    if (sqlite3_blob_open(db_, "main", "segments", "data", rowid, 1, &blob) != SQLITE_OK) { err = "cannot open blob"; return false; }
    int rc = sqlite3_blob_write(blob, data, int(n), int(off));
    sqlite3_blob_close(blob);
    if (rc != SQLITE_OK) { err = "blob write failed"; return false; }
    return true;
}

bool Database::addPatch(Patch& p, std::string& err) {
    Stmt s(db_, "INSERT INTO patches(addr,orig,bytes) VALUES(?,?,?)");
    if (!s.ok()) { err = "db error"; return false; }
    s.i(1, p.addr);
    sqlite3_bind_blob(s.s, 2, p.orig.data(), int(p.orig.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(s.s, 3, p.bytes.data(), int(p.bytes.size()), SQLITE_TRANSIENT);
    s.run();
    p.id = sqlite3_last_insert_rowid(db_);
    return true;
}

bool Database::removePatch(int64_t id, std::string& err) {
    Stmt s(db_, "DELETE FROM patches WHERE id=?");
    if (!s.ok()) { err = "db error"; return false; }
    s.i(1, uint64_t(id));
    s.run();
    return true;
}

bool Database::loadPatches(std::vector<Patch>& out) {
    Stmt s(db_, "SELECT id,addr,orig,bytes FROM patches ORDER BY id");
    if (!s.ok()) return false;
    while (s.step()) {
        Patch p;
        p.id = int64_t(s.gi(0));
        p.addr = s.gi(1);
        const void* o = sqlite3_column_blob(s.s, 2);
        int on = sqlite3_column_bytes(s.s, 2);
        const void* b = sqlite3_column_blob(s.s, 3);
        int bn = sqlite3_column_bytes(s.s, 3);
        if (o && on > 0) p.orig.assign(static_cast<const uint8_t*>(o), static_cast<const uint8_t*>(o) + on);
        if (b && bn > 0) p.bytes.assign(static_cast<const uint8_t*>(b), static_cast<const uint8_t*>(b) + bn);
        out.push_back(std::move(p));
    }
    return true;
}

bool Database::setName(uint64_t addr, const std::string& name, std::string& err) {
    if (name.empty()) {
        Stmt s(db_, "DELETE FROM names WHERE addr=?");
        s.i(1, addr);
        s.run();
        return true;
    }
    Stmt s(db_, "INSERT OR REPLACE INTO names VALUES(?,?,?)");
    if (!s.ok()) { err = "db error"; return false; }
    s.i(1, addr);
    s.t(2, name);
    s.i(3, uint8_t(NameKind::User));
    s.run();
    return true;
}

bool Database::setComment(uint64_t addr, const std::string& text, std::string& err) {
    if (text.empty()) {
        Stmt s(db_, "DELETE FROM comments WHERE addr=?");
        s.i(1, addr);
        s.run();
        return true;
    }
    Stmt s(db_, "INSERT OR REPLACE INTO comments VALUES(?,?)");
    if (!s.ok()) { err = "db error"; return false; }
    s.i(1, addr);
    s.t(2, text);
    s.run();
    return true;
}

}  // namespace er
