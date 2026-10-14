#include "cli/commands.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <functional>
#include <iomanip>
#include <set>
#include <sstream>

#include "cli/render.h"
#include "decomp/decompile.h"
#include "core/util.h"

namespace er {
namespace {

using Args = std::vector<std::string>;

std::string lower(std::string s) {
    for (auto& c : s) c = char(std::tolower((unsigned char)c));
    return s;
}

bool contains(const std::string& hay, const std::string& needle) {
    return lower(hay).find(lower(needle)) != std::string::npos;
}

bool needAddr(Session& s, const Args& a, size_t i, uint64_t& addr, std::ostream& os) {
    if (i >= a.size()) { os << "error: missing location\n"; return false; }
    if (!s.resolve(a[i], addr)) { os << "error: cannot resolve '" << a[i] << "'\n"; return false; }
    return true;
}

void printInsn(Session& s, const Insn& in, std::ostream& os, bool showBytes) {
    RenderedInsn r = renderInsn(s, in);
    os << "  " << hexPlain(in.addr, 16) << "  ";
    if (showBytes) {
        std::string hb = r.bytes.size() > 23 ? r.bytes.substr(0, 23) : r.bytes;
        os << std::left << std::setw(25) << hb << std::right;
    }
    std::string text = r.mnem;
    std::string ops = flatten(r.ops);
    if (!ops.empty()) text += " " + ops;
    os << text;
    std::string comment = flatten(r.comment);
    if (!comment.empty()) {
        size_t pad = text.size() < 40 ? 40 - text.size() : 2;
        os << std::string(pad, ' ') << "; " << comment;
    }
    os << "\n";
}

void printXrefSummary(Session& s, uint64_t addr, std::ostream& os, size_t limit = 8) {
    auto xs = s.xrefsTo(addr);
    if (xs.empty()) return;
    os << "; XREFS:";
    size_t n = 0;
    for (const auto& x : xs) {
        if (n++ >= limit) { os << " ... (+" << (xs.size() - limit) << ")"; break; }
        os << " " << s.symbolic(x.from) << "(" << xtypeName(x.type) << ")";
    }
    os << "\n";
}

void printFunction(Session& s, const Func& f, std::ostream& os, bool showBytes) {
    os << "; ============================================================\n";
    os << "; " << s.label(f.start) << "  [" << hex(f.start) << " - " << hex(f.end) << ")  "
       << (f.end - f.start) << " bytes, " << f.blocks.size() << " blocks";
    if (f.noret) os << ", noreturn";
    if (f.thunk) os << ", thunk";
    os << "\n";
    printXrefSummary(s, f.start, os);
    os << s.label(f.start) << ":\n";
    DecodeCtx ctx;
    for (const Block& b : f.blocks) {
        if (b.start != f.start) {
            auto xs = s.xrefsTo(b.start);
            if (!xs.empty()) {
                os << s.label(b.start) << ":";
                os << "    ; from";
                size_t n = 0;
                for (const auto& x : xs) {
                    if (n++ >= 4) { os << " ..."; break; }
                    os << " " << hex(x.from);
                }
                os << "\n";
            }
        }
        ctx.regs.clear();
        for (uint64_t a = b.start; a < b.end;) {
            Insn in;
            if (!s.proc->decode(s.img, a, in, ctx)) {
                os << "  " << hexPlain(a, 16) << "  <undecodable>\n";
                break;
            }
            printInsn(s, in, os, showBytes);
            a += in.size;
        }
    }
}

void printLinear(Session& s, uint64_t addr, size_t count, std::ostream& os, bool showBytes) {
    DecodeCtx ctx;
    const Func* cur = nullptr;
    for (size_t i = 0; i < count; ++i) {
        const Func* f = s.funcAt(addr);
        if (f != cur) {
            cur = f;
            if (f && f->start == addr) os << s.label(addr) << ":\n";
        } else if (s.hasName(addr) && !(f && f->start == addr)) {
            os << s.label(addr) << ":\n";
        }
        Insn in;
        if (!s.proc->decode(s.img, addr, in, ctx)) {
            os << "  " << hexPlain(addr, 16) << "  <unmapped or undecodable>\n";
            return;
        }
        printInsn(s, in, os, showBytes);
        addr += in.size;
    }
}

// ---- commands -------------------------------------------------------------------------

void cmdInfo(Session& s, std::ostream& os) {
    os << "file     : " << s.img.path << "\n";
    os << "format   : " << s.img.format << " (" << archName(s.img.arch) << ", " << s.img.bits << "-bit)\n";
    os << "base     : " << hex(s.img.base) << "\n";
    if (s.img.hasEntry) os << "entry    : " << hex(s.img.entry) << "  " << s.symbolic(s.img.entry) << "\n";
    size_t blocks = 0;
    for (auto& [a, f] : s.an.funcs) blocks += f.blocks.size();
    os << "segments : " << s.img.segments.size() << "   sections: " << s.img.sections.size() << "\n";
    os << "functions: " << s.an.funcs.size() << "   blocks: " << blocks << "   insns: " << s.an.insnCount << "\n";
    os << "xrefs    : " << s.an.xrefs.size() << "   names: " << s.an.names.size() << "   strings: " << s.an.strings.size() << "\n";
    double pct = s.an.codeBytes ? 100.0 * double(s.an.coveredBytes) / double(s.an.codeBytes) : 0;
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.1f%%", pct);
    os << "code     : " << s.an.coveredBytes << " / " << s.an.codeBytes << " bytes explored (" << buf << ")\n";
}

void cmdSegs(Session& s, std::ostream& os) {
    static const char* kinds[] = {"other", "code", "stub", "cstring", "data", "ptr", "bss"};
    for (const auto& g : s.img.segments) {
        std::string p = std::string(g.perms & P_R ? "r" : "-") + (g.perms & P_W ? "w" : "-") + (g.perms & P_X ? "x" : "-");
        os << hexPlain(g.addr, 16) << "  " << hexPlain(g.addr + g.size, 16) << "  " << p << "  " << g.name << "\n";
        for (const auto& c : s.img.sections) {
            if (c.addr >= g.addr && c.addr < g.addr + g.size)
                os << "    " << hexPlain(c.addr, 16) << "  " << std::setw(10) << std::left << hex(c.size) << std::right
                   << " " << std::setw(8) << std::left << kinds[int(c.kind)] << std::right << " " << c.name << "\n";
        }
    }
}

void cmdFuncs(Session& s, const Args& a, std::ostream& os) {
    std::string filter = a.size() > 1 ? a[1] : "";
    size_t n = 0;
    for (const auto& [addr, f] : s.an.funcs) {
        std::string nm = s.label(addr);
        if (!filter.empty() && !contains(nm, filter)) continue;
        os << hexPlain(addr, 16) << "  " << std::setw(7) << (f.end - addr) << "  " << nm;
        if (f.thunk) os << "  [thunk]";
        if (f.noret) os << "  [noreturn]";
        os << "\n";
        ++n;
    }
    os << n << " functions\n";
}

void cmdNames(Session& s, const Args& a, std::ostream& os, NameKind only, bool filterKind) {
    std::string filter = a.size() > 1 ? a[1] : "";
    size_t n = 0;
    for (const auto& [addr, nm] : s.an.names) {
        if (filterKind && nm.kind != only) continue;
        if (!filter.empty() && !contains(nm.name, filter) && !contains(demangle(nm.name), filter)) continue;
        os << hexPlain(addr, 16) << "  " << demangle(nm.name) << "\n";
        ++n;
    }
    os << n << " names\n";
}

void cmdExports(Session& s, std::ostream& os) {
    size_t n = 0;
    for (const auto& sym : s.img.symbols) {
        if (!sym.exported) continue;
        os << hexPlain(sym.addr, 16) << "  " << demangle(sym.name) << "\n";
        ++n;
    }
    os << n << " exports\n";
}

void cmdStrings(Session& s, const Args& a, std::ostream& os) {
    std::string filter = a.size() > 1 ? a[1] : "";
    size_t n = 0;
    for (const auto& [addr, st] : s.an.strings) {
        if (!filter.empty() && !contains(st.text, filter)) continue;
        os << hexPlain(addr, 16) << "  " << (st.wide ? "L" : " ") << "\"" << escapeText(st.text, 100) << "\"\n";
        ++n;
    }
    os << n << " strings\n";
}

void cmdDisasm(Session& s, const Args& a, std::ostream& os, bool bytes) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    if (a.size() > 2) {
        size_t cnt = std::strtoul(a[2].c_str(), nullptr, 0);
        printLinear(s, addr, cnt ? cnt : 16, os, bytes);
        return;
    }
    const Func* f = s.funcAt(addr);
    if (f) printFunction(s, *f, os, bytes);
    else printLinear(s, addr, 16, os, bytes);
}

void cmdXrefs(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    auto xs = s.xrefsTo(addr);
    if (xs.empty()) { os << "no xrefs to " << s.symbolic(addr) << "\n"; return; }
    os << xs.size() << " xrefs to " << s.symbolic(addr) << "\n";
    for (const auto& x : xs)
        os << "  " << hexPlain(x.from, 16) << "  " << std::setw(7) << std::left << xtypeName(x.type) << std::right
           << "  " << s.symbolic(x.from) << "\n";
}

void cmdHex(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    size_t len = a.size() > 2 ? std::strtoul(a[2].c_str(), nullptr, 0) : 128;
    len = std::min<size_t>(len, 1 << 16);
    std::vector<uint8_t> buf(len);
    size_t got = s.img.readSome(addr, buf.data(), len);
    for (size_t i = 0; i < got; i += 16) {
        os << hexPlain(addr + i, 16) << "  ";
        std::string asc;
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < got) {
                char t[4];
                std::snprintf(t, sizeof t, "%02x ", buf[i + j]);
                os << t;
                asc.push_back(std::isprint(buf[i + j]) ? char(buf[i + j]) : '.');
            } else {
                os << "   ";
            }
            if (j == 7) os << " ";
        }
        os << " |" << asc << "|\n";
    }
    if (!got) os << "unmapped\n";
}

void calleesOf(Session& s, const Func& f, std::vector<uint64_t>& out) {
    std::set<uint64_t> seen;
    for (const Block& b : f.blocks) {
        auto lo = std::lower_bound(s.an.xrefs.begin(), s.an.xrefs.end(), b.start,
                                   [](const Xref& x, uint64_t v) { return x.from < v; });
        for (; lo != s.an.xrefs.end() && lo->from < b.end; ++lo) {
            if (lo->type != XType::Call && lo->type != XType::Tail) continue;
            if (seen.insert(lo->to).second) out.push_back(lo->to);
        }
    }
}

void cmdCallers(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    std::set<uint64_t> seen;
    for (const auto& x : s.xrefsTo(addr)) {
        if (x.type != XType::Call && x.type != XType::Tail) continue;
        const Func* f = s.funcAt(x.from);
        uint64_t st = f ? f->start : x.from;
        if (seen.insert(st).second) os << "  " << hexPlain(st, 16) << "  " << s.label(st) << "\n";
    }
    os << seen.size() << " callers\n";
}

void cmdCallees(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    const Func* f = s.funcAt(addr);
    if (!f) { os << "not in a function\n"; return; }
    std::vector<uint64_t> c;
    calleesOf(s, *f, c);
    for (uint64_t t : c) os << "  " << hexPlain(t, 16) << "  " << s.symbolic(t) << "\n";
    os << c.size() << " callees\n";
}

void cmdCallgraph(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    int depth = a.size() > 2 ? std::atoi(a[2].c_str()) : 3;
    std::set<uint64_t> onPath;
    std::function<void(uint64_t, int)> walk = [&](uint64_t fa, int d) {
        os << std::string(size_t(d) * 2, ' ') << s.symbolic(fa);
        const Func* f = s.funcAt(fa);
        if (!f) { os << "\n"; return; }
        if (d >= depth) { os << " ...\n"; return; }
        if (onPath.count(f->start)) { os << " (recursive)\n"; return; }
        os << "\n";
        onPath.insert(f->start);
        std::vector<uint64_t> c;
        calleesOf(s, *f, c);
        for (uint64_t t : c) walk(t, d + 1);
        onPath.erase(f->start);
    };
    walk(addr, 0);
}

void cmdCfg(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    const Func* f = s.funcAt(addr);
    if (!f) { os << "not in a function\n"; return; }
    os << "digraph \"" << s.label(f->start) << "\" {\n  node [shape=box,fontname=Menlo];\n";
    DecodeCtx ctx;
    for (const Block& b : f->blocks) {
        std::string body;
        ctx.regs.clear();
        for (uint64_t x = b.start; x < b.end;) {
            Insn in;
            if (!s.proc->decode(s.img, x, in, ctx)) break;
            body += hexPlain(in.addr) + "  " + in.mnem + " " + in.ops + "\\l";
            x += in.size;
        }
        for (size_t p = 0; (p = body.find('"', p)) != std::string::npos; p += 2) body.insert(p, "\\");
        os << "  \"" << hexPlain(b.start) << "\" [label=\"" << body << "\"];\n";
    }
    static const char* colors[] = {"black", "blue", "darkgreen", "red"};
    for (const Edge& e : f->edges)
        os << "  \"" << hexPlain(e.src) << "\" -> \"" << hexPlain(e.dst) << "\" [color=" << colors[int(e.kind)] << "];\n";
    os << "}\n";
}

void cmdFind(Session& s, const Args& a, std::ostream& os) {
    if (a.size() < 2) { os << "usage: find <hex bytes with ?? wildcards> | find -s <text>\n"; return; }
    std::vector<int> pat;   // -1 = wildcard
    if (a[1] == "-s") {
        if (a.size() < 3) { os << "usage: find -s <text>\n"; return; }
        for (unsigned char c : a[2]) pat.push_back(c);
    } else {
        for (size_t i = 1; i < a.size(); ++i) {
            if (a[i] == "??" || a[i] == "?") pat.push_back(-1);
            else pat.push_back(int(std::strtoul(a[i].c_str(), nullptr, 16)));
        }
    }
    size_t hits = 0;
    for (const auto& g : s.img.segments) {
        const auto& d = g.data;
        if (d.size() < pat.size()) continue;
        for (size_t i = 0; i + pat.size() <= d.size(); ++i) {
            bool m = true;
            for (size_t k = 0; k < pat.size() && m; ++k)
                if (pat[k] >= 0 && d[i + k] != pat[k]) m = false;
            if (!m) continue;
            os << hexPlain(g.addr + i, 16) << "  " << s.symbolic(g.addr + i) << "\n";
            if (++hits >= 200) { os << "... (truncated at 200 hits)\n"; return; }
        }
    }
    os << hits << " hits\n";
}

void cmdGaps(Session& s, const Args& a, std::ostream& os) {
    size_t minLen = a.size() > 1 ? std::strtoul(a[1].c_str(), nullptr, 0) : 16;
    std::vector<std::pair<uint64_t, uint64_t>> cov;
    for (const auto& [addr, f] : s.an.funcs)
        for (const auto& b : f.blocks) cov.push_back({b.start, b.end});
    std::sort(cov.begin(), cov.end());
    size_t shown = 0, total = 0;
    uint64_t gapBytes = 0;
    for (const auto& sec : s.img.sections) {
        if (sec.kind != SecKind::Code) continue;
        uint64_t cur = sec.addr, end = sec.addr + sec.size;
        auto it = std::lower_bound(cov.begin(), cov.end(), std::make_pair(cur, uint64_t(0)));
        if (it != cov.begin() && std::prev(it)->second > cur) cur = std::min(std::prev(it)->second, end);
        auto report = [&](uint64_t lo, uint64_t hi) {
            if (hi <= lo) return;
            gapBytes += hi - lo;
            ++total;
            if (hi - lo < minLen || shown >= 60) return;
            ++shown;
            uint8_t b[12] = {};
            size_t got = s.img.readSome(lo, b, 12);
            os << hexPlain(lo, 16) << "  " << std::setw(6) << (hi - lo) << "  ";
            for (size_t i = 0; i < got; ++i) { char t[4]; std::snprintf(t, sizeof t, "%02x ", b[i]); os << t; }
            os << "\n";
        };
        for (; it != cov.end() && it->first < end; ++it) {
            if (it->first > cur) report(cur, it->first);
            cur = std::max(cur, it->second);
        }
        report(cur, end);
    }
    os << total << " gaps, " << gapBytes << " unexplored code bytes (showing >= " << minLen << ")\n";
}

void cmdPseudo(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    os << dc::toText(dc::decompile(s, addr));
}

void cmdDecompAll(Session& s, std::ostream& os) {
    size_t ok = 0, fail = 0, lines = 0;
    for (const auto& [addr, f] : s.an.funcs) {
        if (f.thunk) continue;
        auto r = dc::decompile(s, addr);
        if (r.ok) { ++ok; lines += r.lines.size(); }
        else { ++fail; if (fail <= 10) os << "fail " << s.label(addr) << ": " << r.error << "\n"; }
    }
    os << ok << " decompiled (" << lines << " lines), " << fail << " failed\n";
}

static bool parseHex(const Args& a, size_t from, std::vector<uint8_t>& out, std::string& err) {
    for (size_t i = from; i < a.size(); ++i) {
        std::string t = a[i];
        if (t.rfind("0x", 0) == 0) t = t.substr(2);
        if (t.size() % 2) { err = "odd number of hex digits in '" + a[i] + "'"; return false; }
        for (size_t k = 0; k < t.size(); k += 2) {
            if (!std::isxdigit((unsigned char)t[k]) || !std::isxdigit((unsigned char)t[k + 1])) { err = "bad hex '" + a[i] + "'"; return false; }
            out.push_back(uint8_t(std::strtoul(t.substr(k, 2).c_str(), nullptr, 16)));
        }
    }
    if (out.empty()) { err = "no bytes given"; return false; }
    return true;
}

void cmdPatch(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    std::vector<uint8_t> bytes;
    std::string err;
    if (!parseHex(a, 2, bytes, err) || !s.patchBytes(addr, bytes, err)) { os << "error: " << err << "\n"; return; }
    os << "patched " << bytes.size() << " byte(s) at " << hex(addr) << "  (run reanalyze to refresh functions)\n";
}

void cmdAsm(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    bool force = false;
    std::string text;
    for (size_t i = 2; i < a.size(); ++i) {
        if (a[i] == "--force") { force = true; continue; }
        text += (text.empty() ? "" : " ") + a[i];
    }
    std::vector<uint8_t> bytes;
    std::string err;
    if (!s.assembleAt(addr, text, force, bytes, err) || !s.patchBytes(addr, bytes, err)) { os << "error: " << err << "\n"; return; }
    os << "assembled " << bytes.size() << " byte(s) at " << hex(addr) << "\n";
    printLinear(s, addr, 1, os, true);
}

void cmdUnpatch(Session& s, const Args& a, std::ostream& os) {
    uint64_t addr;
    if (!needAddr(s, a, 1, addr, os)) return;
    std::string err;
    if (!s.unpatch(addr, err)) os << "error: " << err << "\n";
    else os << "reverted\n";
}

void cmdPatches(Session& s, std::ostream& os) {
    for (const auto& p : s.patches) {
        os << hexPlain(p.addr, 16) << "  ";
        for (uint8_t b : p.orig) { char t[4]; std::snprintf(t, sizeof t, "%02x", b); os << t; }
        os << " -> ";
        for (uint8_t b : p.bytes) { char t[4]; std::snprintf(t, sizeof t, "%02x", b); os << t; }
        os << "  " << s.symbolic(p.addr) << "\n";
    }
    os << s.patches.size() << " patches\n";
}

void cmdExport(Session& s, const Args& a, std::ostream& os) {
    if (a.size() < 2) { os << "usage: export <out-path> [--sign]\n"; return; }
    bool sign = a.size() > 2 && a[2] == "--sign";
    std::string err;
    if (!s.exportPatched(a[1], sign, err)) os << "error: " << err << "\n";
    else os << "wrote " << a[1] << (sign ? " (ad-hoc signed)" : "") << "\n";
}

void cmdReanalyze(Session& s, std::ostream& os) {
    std::string err;
    if (!s.reanalyze(err)) { os << "error: " << err << "\n"; return; }
    cmdInfo(s, os);
}

void cmdHelp(std::ostream& os) {
    os << "commands:\n"
          "  info                      binary + analysis summary\n"
          "  segs                      segments and sections\n"
          "  funcs [filter]            function list\n"
          "  names [filter]            all names        imports [filter]   import names\n"
          "  exports                   exported symbols\n"
          "  strings [filter]          discovered strings\n"
          "  disasm <loc> [count]      whole function if loc is in one, else linear (-b to show bytes)\n"
          "  xrefs <loc>               references to location\n"
          "  callers <loc> | callees <loc> | callgraph <loc> [depth]\n"
          "  cfg <loc>                 control-flow graph as graphviz dot\n"
          "  hex <loc> [len]           hex dump\n"
          "  pseudo <loc>              decompile function to pseudo-C\n"
          "  patch <loc> <hex...>      write bytes (persisted in the db)\n"
          "  asm <loc> <text> [--force]  assemble an instruction in place (nop-padded)\n"
          "  unpatch <loc> | patches   revert / list patches\n"
          "  export <out> [--sign]     write the patched binary (ad-hoc codesign for Mach-O)\n"
          "  reanalyze                 rerun analysis after patching (keeps names/comments)\n"
          "  gaps [minlen]             unexplored code ranges\n"
          "  find <bytes|-s text>      byte pattern search (?? = wildcard)\n"
          "  rename <loc> <name>       set user name (empty clears)\n"
          "  comment <loc> <text>      set comment (empty clears)\n"
          "  where <loc>               resolve location to name+offset\n"
          "  quit\n"
          "locations: hex address, name, sub_xxxx, name+0xoff\n";
}

}  // namespace

std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool inq = false, have = false;
    for (char c : line) {
        if (c == '"') { inq = !inq; have = true; continue; }
        if (!inq && std::isspace((unsigned char)c)) {
            if (have) { out.push_back(cur); cur.clear(); have = false; }
            continue;
        }
        cur.push_back(c);
        have = true;
    }
    if (have) out.push_back(cur);
    return out;
}

bool runCommand(Session& s, const Args& argsIn, std::ostream& os) {
    if (argsIn.empty()) return true;
    Args a = argsIn;
    bool bytes = false;
    a.erase(std::remove_if(a.begin(), a.end(), [&](const std::string& x) {
                if (x == "-b") { bytes = true; return true; }
                return false;
            }), a.end());
    if (a.empty()) return true;
    const std::string& c = a[0];
    std::string err;

    if (c == "quit" || c == "exit" || c == "q") return false;
    else if (c == "help" || c == "?" || c == "h") cmdHelp(os);
    else if (c == "info") cmdInfo(s, os);
    else if (c == "segs" || c == "segments") cmdSegs(s, os);
    else if (c == "funcs" || c == "functions") cmdFuncs(s, a, os);
    else if (c == "names") cmdNames(s, a, os, NameKind::Symbol, false);
    else if (c == "imports") cmdNames(s, a, os, NameKind::Import, true);
    else if (c == "exports") cmdExports(s, os);
    else if (c == "strings") cmdStrings(s, a, os);
    else if (c == "disasm" || c == "dis" || c == "goto" || c == "g" || c == "u") cmdDisasm(s, a, os, bytes);
    else if (c == "xrefs" || c == "x") cmdXrefs(s, a, os);
    else if (c == "callers") cmdCallers(s, a, os);
    else if (c == "callees") cmdCallees(s, a, os);
    else if (c == "callgraph" || c == "cg") cmdCallgraph(s, a, os);
    else if (c == "cfg") cmdCfg(s, a, os);
    else if (c == "hex" || c == "db") cmdHex(s, a, os);
    else if (c == "find") cmdFind(s, a, os);
    else if (c == "gaps") cmdGaps(s, a, os);
    else if (c == "patch") cmdPatch(s, a, os);
    else if (c == "asm") cmdAsm(s, a, os);
    else if (c == "unpatch") cmdUnpatch(s, a, os);
    else if (c == "patches") cmdPatches(s, os);
    else if (c == "export") cmdExport(s, a, os);
    else if (c == "reanalyze") cmdReanalyze(s, os);
    else if (c == "decompall") cmdDecompAll(s, os);
    else if (c == "pseudo" || c == "decompile" || c == "p") cmdPseudo(s, a, os);
    else if (c == "where") {
        uint64_t addr;
        if (needAddr(s, a, 1, addr, os)) os << hex(addr) << "  " << s.symbolic(addr) << "\n";
    } else if (c == "rename" || c == "n") {
        uint64_t addr;
        if (!needAddr(s, a, 1, addr, os)) return true;
        std::string nm = a.size() > 2 ? a[2] : "";
        if (!s.rename(addr, nm, err)) os << "error: " << err << "\n";
        else os << hex(addr) << " -> " << (nm.empty() ? s.label(addr) : nm) << "\n";
    } else if (c == "comment" || c == ";") {
        uint64_t addr;
        if (!needAddr(s, a, 1, addr, os)) return true;
        std::string text;
        for (size_t i = 2; i < a.size(); ++i) text += (i > 2 ? " " : "") + a[i];
        if (!s.comment(addr, text, err)) os << "error: " << err << "\n";
    } else {
        os << "unknown command '" << c << "' (try: help)\n";
    }
    return true;
}

}  // namespace er
