#include <cstring>
#include "analysis/analyzer.h"

#include <algorithm>
#include <cctype>
#include <deque>
#include <set>
#include <tuple>
#include <unordered_map>
#include <unordered_set>

#include "core/util.h"

namespace er {

const char* xtypeName(XType t) {
    switch (t) {
        case XType::Jump: return "jump";
        case XType::Call: return "call";
        case XType::DRead: return "read";
        case XType::DWrite: return "write";
        case XType::DOffset: return "offset";
        case XType::Tail: return "tail";
    }
    return "?";
}

namespace {

const char* kNoRet[] = {"exit",          "Exit",           "abort",          "stack_chk_fail", "assert_rtn",
                        "assert_fail",   "pthread_exit",   "longjmp",        "siglongjmp",     "cxa_throw",
                        "cxa_rethrow",   "Unwind_Resume",  "chk_fail",       "objc_exception_throw",
                        "err",           "errx",           "verr",           "verrx",          "quick_exit",
                        "ExitProcess",   "abort_message",  "terminate",      "cxa_call_unexpected",
                        "fortify_fail",  "stack_smash_handler"};

bool nameIsNoRet(const std::string& n) {
    size_t i = 0;
    while (i < n.size() && n[i] == '_') ++i;
    std::string s = n.substr(i);
    for (const char* x : kNoRet)
        if (s == x) return true;
    return false;
}

bool validUtf8Printable(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n;) {
        uint8_t c = p[i];
        if (c < 0x80) {
            if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') return false;
            if (c == 0x7f) return false;
            ++i;
        } else {
            int len = (c >= 0xf0) ? 4 : (c >= 0xe0) ? 3 : (c >= 0xc2) ? 2 : 0;
            if (!len || i + len > n) return false;
            for (int k = 1; k < len; ++k)
                if ((p[i + k] & 0xc0) != 0x80) return false;
            i += len;
        }
    }
    return true;
}

bool isAsciiPrintable(uint8_t c) { return (c >= 0x20 && c < 0x7f) || c == '\t' || c == '\n' || c == '\r'; }

class Analyzer {
public:
    Analyzer(const Image& i, Proc& p, Analysis& o, const AnalyzeOptions& op) : img(i), proc(p), out(o), opt(op) {}

    void run() {
        seed();
        drain();
        scanStrings();
        if (opt.ptrScan) {
            scanPointers();
            drain();
        }
        if (opt.gapScan) {
            for (int round = 0; round < 64; ++round) {
                size_t before = out.funcs.size();
                gapScan();
                drain();
                if (out.funcs.size() == before) break;
            }
        }
        stringsFromXrefs();
        finalizeNames();
        stats();
    }

private:
    const Image& img;
    Proc& proc;
    Analysis& out;
    AnalyzeOptions opt;

    std::unordered_map<uint64_t, uint64_t> owner;   // insn address -> owning function start
    std::unordered_set<uint64_t> known, inprog, noret;
    std::deque<uint64_t> queue;
    std::set<std::tuple<uint64_t, uint64_t, uint8_t>> xseen;
    std::unordered_map<uint64_t, std::string> symAt;

    void addXref(uint64_t from, uint64_t to, XType t) {
        if (xseen.emplace(from, to, uint8_t(t)).second) out.xrefs.push_back({from, to, t});
    }

    bool isNoRet(uint64_t a) const { return noret.count(a) != 0; }

    void requestFunc(uint64_t t, int depth) {
        if (!img.isCode(t)) return;
        known.insert(t);
        if (out.funcs.count(t) || inprog.count(t)) return;
        if (depth < 40) analyzeFunction(t, depth + 1);
        else queue.push_back(t);
    }

    void drain() {
        while (!queue.empty()) {
            uint64_t s = queue.front();
            queue.pop_front();
            if (!out.funcs.count(s) && !inprog.count(s)) analyzeFunction(s, 0);
        }
    }

    void seed() {
        for (const auto& s : img.symbols) {
            if (s.kind == SymKind::Func || s.kind == SymKind::ImportFunc) {
                if (img.isCode(s.addr)) {
                    symAt.emplace(s.addr, s.name);
                    known.insert(s.addr);
                    if (nameIsNoRet(s.name)) noret.insert(s.addr);
                }
            }
        }
        for (uint64_t a : img.funcStarts)
            if (img.isCode(a)) known.insert(a);
        if (img.hasEntry && img.isCode(img.entry)) known.insert(img.entry);

        // analyze in address order so output is deterministic
        std::vector<uint64_t> order(known.begin(), known.end());
        std::sort(order.begin(), order.end());
        for (uint64_t a : order) requestFunc(a, 0);
    }

    // ---- function recovery -------------------------------------------------

    void analyzeFunction(uint64_t start, int depth) {
        auto ow = owner.find(start);
        if (ow != owner.end() && ow->second != start) return;   // lives inside another function
        inprog.insert(start);

        std::map<uint64_t, Insn> insns;
        std::set<uint64_t> leaders{start};
        std::set<uint64_t> noFall;
        std::vector<uint64_t> work{start};
        std::map<uint64_t, std::vector<uint64_t>> ijTargets;
        std::map<uint64_t, JumpTable> jtables;
        std::vector<Insn> trail;
        bool hasRet = false, hasIJmp = false, hasNoretCall = false, hasTail = false, hasTrap = false;
        DecodeCtx ctx;

        auto branch = [&](uint64_t from, const Insn& in, bool uncond) {
            uint64_t t = in.target;
            if (!img.isCode(t)) {
                addXref(from, t, XType::Jump);
                return;
            }
            auto o = owner.find(t);
            bool other = (t != start && known.count(t)) || (o != owner.end() && o->second != start);
            if (other) {
                addXref(from, t, XType::Tail);
                if (!known.count(t)) known.insert(t);
                requestFunc(t, depth + 1);
                if (uncond) hasTail = true;
                return;
            }
            addXref(from, t, XType::Jump);
            leaders.insert(t);
            work.push_back(t);
        };

        while (!work.empty()) {
            uint64_t a = work.back();
            work.pop_back();
            ctx.regs.clear();
            trail.clear();
            for (;;) {
                if (insns.count(a)) break;
                auto o = owner.find(a);
                if (o != owner.end() && o->second != start) break;
                if (!img.isCode(a)) break;
                Insn in;
                if (!proc.decode(img, a, in, ctx)) break;
                for (const auto& dr : in.drefs) {
                    XType xt = dr.kind == 'w' ? XType::DWrite : dr.kind == 'r' ? XType::DRead : XType::DOffset;
                    addXref(a, dr.addr, xt);
                }
                uint64_t next = a + in.size;
                insns.emplace(a, in);
                owner[a] = start;
                trail.push_back(in);
                if (trail.size() > 24) trail.erase(trail.begin());
                bool cont = false;
                switch (in.flow) {
                    case Flow::Normal:
                    case Flow::ICall:
                        cont = true;
                        break;
                    case Flow::Call:
                        if (in.hasTarget) {
                            addXref(a, in.target, XType::Call);
                            requestFunc(in.target, depth);
                            if (isNoRet(in.target)) {
                                noFall.insert(a);
                                hasNoretCall = true;
                                break;
                            }
                        }
                        cont = true;
                        break;
                    case Flow::Jmp:
                        if (in.hasTarget) branch(a, in, true);
                        break;
                    case Flow::CJmp:
                        if (in.hasTarget) branch(a, in, false);
                        leaders.insert(next);
                        cont = true;
                        break;
                    case Flow::IJmp: {
                        std::vector<uint64_t> tg;
                        JTInfo ji;
                        if (proc.jumpTable(img, trail, tg, ji)) {
                            jtables[a] = JumpTable{ji.idxReg, ji.ordered};
                            for (uint64_t t : tg) {
                                auto ot = owner.find(t);
                                if (ot != owner.end() && ot->second != start) continue;
                                addXref(a, t, XType::Jump);
                                leaders.insert(t);
                                work.push_back(t);
                            }
                            ijTargets[a] = std::move(tg);
                        } else {
                            hasIJmp = true;
                        }
                        break;
                    }
                    case Flow::Ret: hasRet = true; break;
                    case Flow::Trap: hasTrap = true; break;
                }
                if (!cont) break;
                a = next;
            }
        }

        // leaders after block terminators
        for (const auto& [a, in] : insns) {
            bool term = in.flow == Flow::Jmp || in.flow == Flow::CJmp || in.flow == Flow::Ret ||
                        in.flow == Flow::IJmp || in.flow == Flow::Trap || noFall.count(a);
            if (term) leaders.insert(a + in.size);
        }

        Func fn;
        fn.start = start;
        fn.jt = std::move(jtables);
        uint64_t bstart = 0, prevEnd = 0;
        bool open = false;
        auto close = [&]() {
            if (open) fn.blocks.push_back({bstart, prevEnd});
            open = false;
        };
        for (const auto& [a, in] : insns) {
            if (open && (leaders.count(a) || a != prevEnd)) close();
            if (!open) { bstart = a; open = true; }
            prevEnd = a + in.size;
        }
        close();

        for (const auto& b : fn.blocks) {
            fn.end = std::max(fn.end, b.end);
            // last instruction of the block = largest insn address < b.end
            auto it = insns.lower_bound(b.end);
            if (it == insns.begin()) continue;
            --it;
            const Insn& last = it->second;
            auto hasBlock = [&](uint64_t addr) { return insns.count(addr) && leaders.count(addr); };
            switch (last.flow) {
                case Flow::Jmp:
                    if (last.hasTarget && hasBlock(last.target)) fn.edges.push_back({b.start, last.target, EdgeKind::Jump});
                    break;
                case Flow::IJmp: {
                    auto jt = ijTargets.find(last.addr);
                    if (jt != ijTargets.end())
                        for (uint64_t t : jt->second)
                            if (hasBlock(t)) fn.edges.push_back({b.start, t, EdgeKind::Jump});
                    break;
                }
                case Flow::CJmp:
                    if (last.hasTarget && hasBlock(last.target)) fn.edges.push_back({b.start, last.target, EdgeKind::True});
                    if (hasBlock(b.end)) fn.edges.push_back({b.start, b.end, EdgeKind::False});
                    break;
                case Flow::Normal:
                case Flow::Call:
                case Flow::ICall:
                    if (!noFall.count(last.addr) && hasBlock(b.end)) fn.edges.push_back({b.start, b.end, EdgeKind::Fall});
                    break;
                default: break;
            }
        }
        fn.thunk = fn.blocks.size() == 1 && insns.size() <= 4 &&
                   (insns.rbegin()->second.flow == Flow::IJmp || insns.rbegin()->second.flow == Flow::Jmp);
        if (!hasRet && !hasIJmp && !hasTail && (hasNoretCall || hasTrap) && !fn.thunk) {
            fn.noret = true;
            noret.insert(start);
        }
        out.insnCount += insns.size();
        inprog.erase(start);
        known.insert(start);
        if (!fn.blocks.empty()) out.funcs.emplace(start, std::move(fn));
    }

    // ---- strings -------------------------------------------------------------

    void addString(uint64_t addr, uint32_t len, uint8_t wide, std::string text) {
        if (text.size() > 512) text.resize(512);
        out.strings.emplace(addr, StringEntry{len, wide, std::move(text)});
    }

    void scanStrings() {
        const bool trusted = img.format == "Mach-O";
        for (const auto& sec : img.sections) {
            if (sec.kind != SecKind::CString) continue;
            const Segment* seg = img.segAt(sec.addr);
            if (!seg) continue;
            uint64_t off = sec.addr - seg->addr;
            if (off >= seg->data.size()) continue;
            uint64_t end = std::min<uint64_t>(seg->data.size(), off + sec.size);
            const uint8_t* d = seg->data.data();
            uint64_t i = off;
            while (i < end) {
                uint64_t j = i;
                while (j < end && d[j] != 0) ++j;
                size_t len = j - i;
                bool term = j < end;
                if (term && len >= (trusted ? 2u : 4u)) {
                    bool ok = trusted ? validUtf8Printable(d + i, len)
                                      : std::all_of(d + i, d + j, isAsciiPrintable);
                    if (ok) addString(seg->addr + i, uint32_t(len), 0, std::string((const char*)d + i, len));
                }
                i = j + 1;
            }
            if (img.format == "PE") scanWide(sec, *seg, off, end);
        }
    }

    void scanWide(const Section& sec, const Segment& seg, uint64_t off, uint64_t end) {
        const uint8_t* d = seg.data.data();
        uint64_t i = off;
        while (i + 8 <= end) {
            uint64_t j = i;
            std::string text;
            while (j + 1 < end && d[j + 1] == 0 && isAsciiPrintable(d[j]) && d[j] != 0) {
                text.push_back(char(d[j]));
                j += 2;
            }
            bool term = j + 1 < end && d[j] == 0 && d[j + 1] == 0;
            uint64_t a = seg.addr + i;
            if (term && text.size() >= 4 && !out.strings.count(a)) {
                addString(a, uint32_t(text.size() * 2), 1, text);
                i = j + 2;
            } else {
                i += 2;
            }
        }
        (void)sec;
    }

    void stringsFromXrefs() {
        std::vector<uint64_t> targets;
        for (const auto& x : out.xrefs) {
            if (x.type != XType::DRead && x.type != XType::DOffset) continue;
            if (out.strings.count(x.to) || img.isCode(x.to)) continue;
            const Section* s = img.secAt(x.to);
            if (s && (s->kind == SecKind::CString || s->kind == SecKind::Ptr || s->kind == SecKind::Bss)) continue;
            targets.push_back(x.to);
        }
        std::sort(targets.begin(), targets.end());
        targets.erase(std::unique(targets.begin(), targets.end()), targets.end());
        for (uint64_t t : targets) {
            std::string s;
            if (img.readCString(t, s, 512) && s.size() >= 4 &&
                std::all_of(s.begin(), s.end(), [](char c) { return isAsciiPrintable(uint8_t(c)); })) {
                addString(t, uint32_t(s.size()), 0, s);
                continue;
            }
            if (img.format == "PE") {
                std::string w;
                for (size_t k = 0; k < 512; k += 2) {
                    uint8_t b[2];
                    if (!img.read(t + k, b, 2)) break;
                    if (b[0] == 0 && b[1] == 0) break;
                    if (b[1] != 0 || !isAsciiPrintable(b[0])) { w.clear(); break; }
                    w.push_back(char(b[0]));
                }
                if (w.size() >= 4) addString(t, uint32_t(w.size() * 2), 1, w);
            }
        }
    }

    // ---- data pointer tables ----------------------------------------------------

    void scanPointers() {
        const size_t psz = img.bits == 64 ? 8 : 4;
        std::vector<std::pair<uint64_t, uint64_t>> hits;   // slot, value
        std::vector<uint64_t> newFuncs;
        for (const auto& sec : img.sections) {
            if (sec.kind != SecKind::Data && sec.kind != SecKind::Ptr) continue;
            if (sec.size > (64u << 20)) continue;
            const Segment* seg = img.segAt(sec.addr);
            if (!seg) continue;
            uint64_t off = sec.addr - seg->addr;
            if (off >= seg->data.size()) continue;
            uint64_t end = std::min<uint64_t>(seg->data.size(), off + sec.size);
            const uint8_t* d = seg->data.data();
            for (uint64_t p = (off + psz - 1) / psz * psz; p + psz <= end; p += psz) {
                uint64_t v = 0;
                std::memcpy(&v, d + p, psz);
                if (!v) continue;
                uint64_t slot = seg->addr + p;
                if (known.count(v) || out.strings.count(v)) {
                    hits.push_back({slot, v});
                } else if (img.isCode(v) && v % proc.align() == 0 && proc.looksLikePrologue(img, v)) {
                    hits.push_back({slot, v});
                    newFuncs.push_back(v);
                }
            }
        }
        for (auto [slot, v] : hits) addXref(slot, v, XType::DOffset);
        for (uint64_t f : newFuncs) requestFunc(f, 0);
    }

    // x86 alignment padding: nops, int3, and gcc's lea esi,[esi+0] / mov edi,edi forms
    bool isPadInsn(const Insn& in) const {
        if (in.mnem == "nop" || in.mnem == "int3" || in.mnem == "fnop" || in.mnem == "data16") return true;
        if (in.mnem == "xchg" && (in.ops == "ax, ax" || in.ops == "eax, eax")) return true;
        if (in.mnem == "mov" && (in.ops == "edi, edi" || in.ops == "esi, esi")) return true;
        if (in.mnem == "lea") {
            static const char* regs[] = {"esi", "edi", "rsi", "rdi", "eax", "ebx", "ecx", "edx"};
            for (const char* r : regs) {
                std::string pre = std::string(r) + ", [" + r;
                if (in.ops.rfind(pre, 0) == 0 && in.ops.find("*") == std::string::npos) return true;
            }
        }
        return false;
    }

    // First non-padding address at or after `a` inside [a, end).
    uint64_t skipPadding(uint64_t a, uint64_t end) {
        DecodeCtx ctx;
        while (a < end) {
            Insn in;
            if (!proc.decode(img, a, in, ctx) || !isPadInsn(in)) break;
            a += in.size;
        }
        return a;
    }

    // Something that plausibly opens a function: stack/frame setup or arg load, followed by clean decodes.
    bool plausibleStartX86(uint64_t a) {
        DecodeCtx ctx;
        Insn first;
        if (!proc.decode(img, a, first, ctx)) return false;
        bool ok = first.mnem == "push" || (first.mnem == "sub" && (first.ops.rfind("esp", 0) == 0 || first.ops.rfind("rsp", 0) == 0)) ||
                  (first.mnem == "mov" && (first.ops.find("[esp") != std::string::npos || first.ops.find("[rsp") != std::string::npos)) ||
                  first.mnem == "endbr64" || first.mnem == "endbr32";
        if (!ok) return false;
        uint64_t p = a;
        for (int i = 0; i < 6; ++i) {
            Insn in;
            if (!proc.decode(img, p, in, ctx)) return false;
            if (in.flow == Flow::Trap) return false;
            p += in.size;
            if (in.flow == Flow::Ret || in.flow == Flow::Jmp || in.flow == Flow::IJmp) break;
        }
        return true;
    }

    // A leftover run that decodes cleanly up to a terminator (ret/jmp) — used by the optional sweep.
    bool cleanRun(uint64_t a, uint64_t end) {
        DecodeCtx ctx;
        for (int i = 0; i < 400 && a < end; ++i) {
            Insn in;
            if (!proc.decode(img, a, in, ctx)) return false;
            if (in.flow == Flow::Trap) return false;
            a += in.size;
            if (in.flow == Flow::Ret || in.flow == Flow::Jmp || in.flow == Flow::IJmp) return i >= 1;
        }
        return false;
    }

    // ---- gap scanning -------------------------------------------------------------

    void gapScan() {
        std::vector<std::pair<uint64_t, uint64_t>> cov;
        for (const auto& [a, f] : out.funcs)
            for (const auto& b : f.blocks) cov.push_back({b.start, b.end});
        std::sort(cov.begin(), cov.end());
        std::vector<uint64_t> cands;
        const unsigned al = proc.align();
        for (const auto& sec : img.sections) {
            if (sec.kind != SecKind::Code) continue;
            uint64_t lo = sec.addr, hi = sec.addr + sec.size;
            auto it = std::lower_bound(cov.begin(), cov.end(), std::make_pair(lo, uint64_t(0)));
            if (it != cov.begin()) {
                auto pv = std::prev(it);
                if (pv->second > lo) lo = std::min(pv->second, hi);
            }
            uint64_t cur = lo;
            while (cur < hi) {
                uint64_t gapEnd = hi;
                while (it != cov.end() && it->second <= cur) ++it;
                if (it != cov.end() && it->first < hi) gapEnd = it->first;
                if (it != cov.end() && it->first <= cur) {   // inside covered range
                    cur = std::max(cur, it->second);
                    continue;
                }
                if (al == 1) {
                    uint64_t p0 = skipPadding(cur, gapEnd);
                    if (p0 < gapEnd && !known.count(p0) && (plausibleStartX86(p0) || (opt.sweep && cleanRun(p0, gapEnd))))
                        cands.push_back(p0);
                }
                for (uint64_t a = (cur + al - 1) / al * al; a < gapEnd; a += al) {
                    if (known.count(a)) continue;
                    if (!proc.looksLikePrologue(img, a)) continue;
                    if (al == 1 && a != cur) {
                        uint8_t pb = 0;
                        img.read(a - 1, &pb, 1);
                        if (!(pb == 0xcc || pb == 0x90 || pb == 0x00 || pb == 0xc3) && (a % 16)) continue;
                    }
                    cands.push_back(a);
                }
                cur = gapEnd;
                if (it != cov.end()) cur = std::max(cur, it->second);
            }
        }
        for (uint64_t c : cands) requestFunc(c, 0);
    }

    // ---- names / stats ----------------------------------------------------------------

    static std::string stringName(const std::string& text) {
        std::string n = "a";
        bool up = true;
        for (char c : text) {
            if (n.size() >= 24) break;
            if (std::isalnum((unsigned char)c)) {
                n.push_back(up ? char(std::toupper((unsigned char)c)) : c);
                up = false;
            } else {
                up = true;
            }
        }
        if (n == "a") n = "aStr";
        return n;
    }

    void finalizeNames() {
        for (const auto& s : img.symbols) {
            NameKind k = (s.kind == SymKind::ImportFunc || s.kind == SymKind::ImportPtr) ? NameKind::Import
                                                                                         : NameKind::Symbol;
            auto it = out.names.find(s.addr);
            if (it == out.names.end()) {
                out.names[s.addr] = {s.name, k};
            } else if (it->second.kind == NameKind::Symbol && k == NameKind::Import) {
                it->second = {s.name, k};
            } else if (s.exported && it->second.kind == NameKind::Symbol && s.name.size() < it->second.name.size()) {
                it->second = {s.name, k};
            }
        }
        if (img.hasEntry && !out.names.count(img.entry)) out.names[img.entry] = {"start", NameKind::Symbol};

        std::unordered_set<uint64_t> referenced;
        for (const auto& x : out.xrefs)
            if (out.strings.count(x.to)) referenced.insert(x.to);
        std::unordered_map<std::string, int> used;
        for (const auto& [a, s] : out.strings) {
            if (!referenced.count(a) || out.names.count(a)) continue;
            std::string n = stringName(s.text);
            int c = used[n]++;
            if (c) n += "_" + std::to_string(c);
            out.names[a] = {n, NameKind::String};
        }
    }

    void stats() {
        for (const auto& sec : img.sections)
            if (sec.kind == SecKind::Code || sec.kind == SecKind::Stub) out.codeBytes += sec.size;
        for (const auto& [a, f] : out.funcs)
            for (const auto& b : f.blocks) out.coveredBytes += b.end - b.start;
    }
};

}  // namespace

void analyze(const Image& img, Proc& proc, Analysis& out, const AnalyzeOptions& opt) {
    Analyzer a(img, proc, out, opt);
    a.run();
    std::sort(out.xrefs.begin(), out.xrefs.end(), [](const Xref& x, const Xref& y) {
        return std::tie(x.from, x.to, x.type) < std::tie(y.from, y.to, y.type);
    });
}

}  // namespace er
