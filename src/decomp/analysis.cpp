// Decompiler dataflow: lift -> stack tracking -> per-block symbolic simulation -> liveness -> final blocks.
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <set>

#include "core/util.h"
#include "decomp/dcmodel.h"

namespace er::dc {

// ---------------------------------------------------------------------------------------
// known library prototypes
// ---------------------------------------------------------------------------------------
static const Known kKnown[] = {
    {"printf", 1, true, false, false},   {"fprintf", 2, true, false, false}, {"sprintf", 2, true, false, false},
    {"snprintf", 3, true, false, false}, {"dprintf", 2, true, false, false}, {"vprintf", 2, false, false, false},
    {"scanf", 1, true, false, false},    {"sscanf", 2, true, false, false},  {"fscanf", 2, true, false, false},
    {"puts", 1, false, false, false},    {"putchar", 1, false, false, false}, {"fputs", 2, false, false, false},
    {"fputc", 2, false, false, false},   {"getchar", 0, false, false, false}, {"fgets", 3, false, false, false},
    {"fopen", 2, false, false, false},   {"fclose", 1, false, false, false}, {"fread", 4, false, false, false},
    {"fwrite", 4, false, false, false},  {"fflush", 1, false, false, false}, {"fseek", 3, false, false, false},
    {"ftell", 1, false, false, false},   {"perror", 1, false, true, false},
    {"exit", 1, false, true, true},      {"Exit", 1, false, true, true},     {"abort", 0, false, true, true},
    {"atoi", 1, false, false, false},    {"atol", 1, false, false, false},   {"atof", 1, false, false, false},
    {"strtol", 3, false, false, false},  {"strtoul", 3, false, false, false}, {"strtoll", 3, false, false, false},
    {"strlen", 1, false, false, false},  {"strcmp", 2, false, false, false}, {"strncmp", 3, false, false, false},
    {"strcpy", 2, false, false, false},  {"strncpy", 3, false, false, false}, {"strcat", 2, false, false, false},
    {"strncat", 3, false, false, false}, {"strchr", 2, false, false, false}, {"strrchr", 2, false, false, false},
    {"strstr", 2, false, false, false},  {"strdup", 1, false, false, false}, {"strerror", 1, false, false, false},
    {"memcpy", 3, false, false, false},  {"memmove", 3, false, false, false}, {"memset", 3, false, false, false},
    {"memcmp", 3, false, false, false},  {"memchr", 3, false, false, false},
    {"malloc", 1, false, false, false},  {"calloc", 2, false, false, false}, {"realloc", 2, false, false, false},
    {"free", 1, false, true, false},     {"getenv", 1, false, false, false}, {"setenv", 3, false, false, false},
    {"open", 2, true, false, false},     {"close", 1, false, false, false},  {"read", 3, false, false, false},
    {"write", 3, false, false, false},   {"lseek", 3, false, false, false},  {"unlink", 1, false, false, false},
    {"stat", 2, false, false, false},    {"fstat", 2, false, false, false},  {"access", 2, false, false, false},
    {"mmap", 6, false, false, false},    {"munmap", 2, false, false, false}, {"getpid", 0, false, false, false},
    {"sleep", 1, false, false, false},   {"usleep", 1, false, false, false}, {"time", 1, false, false, false},
    {"rand", 0, false, false, false},    {"srand", 1, false, true, false},   {"qsort", 4, false, true, false},
    {"bsearch", 5, false, false, false}, {"abs", 1, false, false, false},    {"toupper", 1, false, false, false},
    {"tolower", 1, false, false, false}, {"isalpha", 1, false, false, false}, {"isdigit", 1, false, false, false},
    {"isspace", 1, false, false, false}, {"getopt_long", 5, false, false, false}, {"getopt", 3, false, false, false},
    {"stack_chk_fail", 0, false, true, true}, {"assert_rtn", 4, false, true, true}, {"assert_fail", 4, false, true, true},
    {"pthread_create", 4, false, false, false}, {"pthread_join", 2, false, false, false},
    {"pthread_mutex_lock", 1, false, false, false}, {"pthread_mutex_unlock", 1, false, false, false},
    {"signal", 2, false, false, false},  {"fork", 0, false, false, false},   {"execve", 3, false, false, false},
    {"waitpid", 3, false, false, false}, {"socket", 3, false, false, false}, {"connect", 3, false, false, false},
    {"bind", 3, false, false, false},    {"listen", 2, false, false, false}, {"accept", 3, false, false, false},
    {"send", 4, false, false, false},    {"recv", 4, false, false, false},   {"dlopen", 2, false, false, false},
    {"dlsym", 2, false, false, false},   {"opendir", 1, false, false, false}, {"readdir", 1, false, false, false},
    {"closedir", 1, false, false, false}, {"fts_open", 3, false, false, false}, {"fts_read", 1, false, false, false},
    {"fts_close", 1, false, false, false}, {"fts_children", 2, false, false, false},
    {"objc_retain", 1, false, false, false}, {"objc_release", 1, false, true, false},
    {"objc_autorelease", 1, false, false, false}, {"objc_retainAutoreleasedReturnValue", 1, false, false, false},
    {"objc_storeStrong", 2, false, true, false}, {"objc_autoreleaseReturnValue", 1, false, false, false},
    {"objc_msgSend", 2, false, false, false}, {"objc_msgSend_stret", 3, false, false, false},
    {"objc_msgSendSuper2", 2, false, false, false}, {"objc_alloc", 1, false, false, false},
    {"objc_alloc_init", 1, false, false, false}, {"objc_opt_class", 1, false, false, false},
};

std::string stripUnderscores(const std::string& n) {
    size_t i = 0;
    while (i < n.size() && n[i] == '_') ++i;
    std::string s = n.substr(i);
    // strip decorations like $INODE64, @plt, _ptr suffix
    size_t d = s.find('$');
    if (d != std::string::npos) s.resize(d);
    d = s.find('@');
    if (d != std::string::npos) s.resize(d);
    return s;
}

const Known* findKnown(const std::string& symbolName) {
    std::string s = stripUnderscores(symbolName);
    for (const auto& k : kKnown)
        if (s == k.name) return &k;
    return nullptr;
}

namespace {

struct Def {
    int reg = -1, bits = 64;
    ExprP expr;
    bool isCall = false;
    int time = 0, minTime = 0;
    bool hasMem = false;
    std::set<int> leaves;
    int uses = 0;
    std::vector<int> useTimes;
    bool forceMem = false, forceReg = false;
    bool needed = false, liveOutFinal = false;
    bool mat = false;
    int var = -1;     // register id (canonical) or temp id; -1 = expression statement
};

struct Event {
    enum K { DefE, StoreE, RawE } k = DefE;
    int def = -1;
    Stmt st;
    bool dead = false;
};

struct Blk {
    uint64_t addr = 0, end = 0;
    std::vector<Stmt> raw;
    TK tk = TK::None;
    Stmt term;
    int t = -1, f = -1;
    std::vector<int> cases;
    std::vector<std::pair<int64_t, int>> tableCases;   // (table index, block)
    std::string idxReg;
    std::vector<int> succ, pred;
    bool reachable = false;

    std::vector<Def> defs;
    std::vector<Event> events;
    ExprP cond, retv, idx;
    std::map<int, int> finalDef;
    std::set<int> kills;
    std::set<int> liveIn, liveOut;
    std::map<int64_t, int> stackStores;   // stack offset -> event index
    std::vector<std::pair<int, int>> memTimes;   // (time, event index or -1 for call defs) of every memory-effecting event
    bool retDefined = false;
    // stack-tracking state at block entry/exit
    bool spIn = false, fpIn = false, spOut = false, fpOut = false;
    int64_t spInV = 0, fpInV = 0, spOutV = 0, fpOutV = 0;
    bool trackedIn = false;
};

struct Sim {
    std::map<int, int> env;
    std::map<int, int> lastDefTime;
    int lastMemTime = 0;
    int now = 0;
    std::set<int> defSinceCall;
};

bool simpleExpr(const ExprP& e) {
    return e->k == EK::Const || e->k == EK::Reg || e->k == EK::Stack || e->k == EK::Sym || e->k == EK::Str;
}

int countFormat(const std::string& f) {
    int n = 0;
    for (size_t i = 0; i < f.size(); ++i) {
        if (f[i] != '%') continue;
        if (i + 1 < f.size() && f[i + 1] == '%') { ++i; continue; }
        ++n;
        for (++i; i < f.size(); ++i) {
            char c = f[i];
            if (c == '*') ++n;
            if (std::strchr("diouxXeEfFgGaAcspn", c)) break;
        }
    }
    return n;
}

class Builder {
public:
    Builder(Session& s, Lifter& l, uint64_t start) : S(s), L(l), start_(start) {}

    bool run(FuncModel& m, std::string& err) {
        auto fit = S.an.funcs.find(start_);
        if (fit == S.an.funcs.end()) { err = "no function at that address"; return false; }
        F = &fit->second;
        if (!buildBlocks(err)) return false;
        trackStack();
        removeSavedRegs();
        for (auto& b : B) if (b.reachable) simulate(b);
        computeReturn();
        liveness();
        emit(m);
        return true;
    }

private:
    Session& S;
    Lifter& L;
    uint64_t start_;
    const Func* F = nullptr;
    std::vector<Blk> B;
    std::map<uint64_t, int> idxOf;
    std::vector<int> rpo;
    bool returnsValue_ = false;
    int nextTemp_ = 0;
    std::map<int64_t, int> savedSlots_;   // stack offset -> callee-saved register

    // ---- blocks ----------------------------------------------------------------------
    bool isNoRetTarget(uint64_t t) const {
        auto f = S.an.funcs.find(t);
        if (f != S.an.funcs.end() && f->second.noret) return true;
        auto n = S.an.names.find(t);
        if (n != S.an.names.end()) {
            const Known* k = findKnown(n->second.name);
            if (k && k->noret) return true;
        }
        return false;
    }

    bool buildBlocks(std::string& err) {
        B.resize(F->blocks.size());
        for (size_t i = 0; i < F->blocks.size(); ++i) {
            B[i].addr = F->blocks[i].start;
            B[i].end = F->blocks[i].end;
            idxOf[B[i].addr] = int(i);
        }
        auto it0 = idxOf.find(start_);
        if (it0 == idxOf.end()) { err = "entry block missing"; return false; }
        entry_ = it0->second;

        for (auto& b : B) {
            for (uint64_t pc = b.addr; pc < b.end;) {
                uint32_t sz = 0;
                size_t before = b.raw.size();
                if (!L.lift(S.img, pc, b.raw, sz) || !sz) { b.raw.resize(before); break; }
                pc += sz;
            }
            auto blockAt = [&](uint64_t a) { auto it = idxOf.find(a); return it == idxOf.end() ? -1 : it->second; };
            Stmt last;
            bool haveTerm = false;
            if (!b.raw.empty()) {
                last = b.raw.back();
                haveTerm = last.k == SK::Jmp || last.k == SK::Br || last.k == SK::Ret || last.k == SK::Switch;
                if (haveTerm) b.raw.pop_back();
            }
            if (haveTerm) {
                b.term = last;
                switch (last.k) {
                    case SK::Ret: b.tk = TK::Ret; break;
                    case SK::Jmp: {
                        int t = blockAt(last.t);
                        if (t >= 0) { b.tk = TK::Jmp; b.t = t; }
                        else {   // tail call into another function
                            Stmt c; c.k = SK::Call; c.at = last.at; c.val = mkCallE(last.t, nullptr, {});
                            b.raw.push_back(c);
                            b.tk = TK::Ret;
                        }
                        break;
                    }
                    case SK::Br:
                        b.tk = TK::Br; b.t = blockAt(last.t); b.f = blockAt(last.f);
                        if (b.t < 0 && b.f < 0) b.tk = TK::None;
                        break;
                    case SK::Switch: {
                        b.tk = TK::Switch;
                        std::vector<int> cs;
                        auto jt = F->jt.find(last.at);
                        if (jt != F->jt.end()) {
                            b.idxReg = jt->second.idxReg;
                            for (size_t k = 0; k < jt->second.entries.size(); ++k) {
                                int d = jt->second.entries[k] ? blockAt(jt->second.entries[k]) : -1;
                                if (d >= 0) { b.tableCases.push_back({int64_t(k), d}); cs.push_back(d); }
                            }
                        } else
                        for (const Edge& e : F->edges)
                            if (e.src == b.addr) { int d = blockAt(e.dst); if (d >= 0) cs.push_back(d); }
                        if (b.tableCases.empty())
                            std::sort(cs.begin(), cs.end(), [&](int a, int c) { return B[a].addr < B[c].addr; });
                        cs.erase(std::unique(cs.begin(), cs.end()), cs.end());
                        b.cases = cs;
                        if (cs.empty()) b.tk = TK::None;   // unresolved indirect jump
                        break;
                    }
                    default: break;
                }
            } else {
                bool noretCall = !b.raw.empty() && b.raw.back().k == SK::Call && b.raw.back().val &&
                                 b.raw.back().val->directCall && isNoRetTarget(b.raw.back().val->c);
                int n = noretCall ? -1 : blockAt(b.end);
                if (n >= 0) { b.tk = TK::Fall; b.t = n; }
                else b.tk = TK::None;
            }
            switch (b.tk) {
                case TK::Jmp: case TK::Fall: b.succ = {b.t}; break;
                case TK::Br: if (b.t >= 0) b.succ.push_back(b.t); if (b.f >= 0 && b.f != b.t) b.succ.push_back(b.f); break;
                case TK::Switch: b.succ = b.cases; break;
                default: break;
            }
        }
        for (size_t i = 0; i < B.size(); ++i)
            for (int s : B[i].succ) B[s].pred.push_back(int(i));
        // reverse post-order from the entry
        std::vector<char> seen(B.size(), 0);
        std::vector<int> post;
        std::function<void(int)> dfs = [&](int u) {
            seen[u] = 1;
            for (int v : B[u].succ) if (!seen[v]) dfs(v);
            post.push_back(u);
        };
        dfs(entry_);
        rpo.assign(post.rbegin(), post.rend());
        for (int u : rpo) B[u].reachable = true;
        return true;
    }
    int entry_ = 0;

    // ---- stack pointer / frame pointer tracking --------------------------------------------
    ExprP stk(const ExprP& e, const Blk& cur, bool sp, int64_t spv, bool fp, int64_t fpv) {
        const int spr = L.spReg(), fpr = L.fpReg();
        (void)cur;
        return rewrite(e, [&](const ExprP& n) -> ExprP {
            if (n->k == EK::Reg && n->reg == spr && sp) return mkStack(spv);
            if (n->k == EK::Reg && fpr >= 0 && n->reg == fpr && fp) return mkStack(fpv);
            return nullptr;
        });
    }

    void trackStack() {
        const int spr = L.spReg(), fpr = L.fpReg();
        B[entry_].spIn = true; B[entry_].spInV = 0;
        B[entry_].trackedIn = true;
        for (int u : rpo) {
            Blk& b = B[u];
            if (!b.trackedIn) {
                for (int p : b.pred) {
                    if (B[p].trackedIn && (B[p].spOut || B[p].fpOut || true) && B[p].reachable && (u != entry_)) {
                        // predecessor already processed (earlier in RPO)?
                        bool processed = std::find(rpo.begin(), rpo.end(), p) < std::find(rpo.begin(), rpo.end(), u);
                        if (!processed) continue;
                        b.spIn = B[p].spOut; b.spInV = B[p].spOutV;
                        b.fpIn = B[p].fpOut; b.fpInV = B[p].fpOutV;
                        b.trackedIn = true;
                        break;
                    }
                }
            }
            bool sp = b.spIn, fp = b.fpIn;
            int64_t spv = b.spInV, fpv = b.fpInV;
            for (auto& s : b.raw) {
                s.spKnown = sp; s.spOff = spv;
                if (s.val) s.val = stk(s.val, b, sp, spv, fp, fpv);
                if (s.addr) s.addr = stk(s.addr, b, sp, spv, fp, fpv);
                if (s.cond) s.cond = stk(s.cond, b, sp, spv, fp, fpv);
                if (s.index) s.index = stk(s.index, b, sp, spv, fp, fpv);
                if (s.k == SK::Assign && s.dst == spr) {
                    if (s.val && s.val->k == EK::Stack) { sp = true; spv = int64_t(s.val->c); }
                    else sp = false;
                    s.dead = true;
                } else if (s.k == SK::Assign && fpr >= 0 && s.dst == fpr) {
                    if (s.val && s.val->k == EK::Stack) { fp = true; fpv = int64_t(s.val->c); s.dead = true; }
                    else fp = false;
                }
            }
            // terminator operands
            auto fix = [&](ExprP& e) { if (e) e = stk(e, b, sp, spv, fp, fpv); };
            fix(b.term.cond); fix(b.term.index);
            b.spOut = sp; b.spOutV = spv; b.fpOut = fp; b.fpOutV = fpv;
            if (b.tk == TK::Ret || b.tk == TK::None) continue;
        }
    }

    void removeSavedRegs() {
        // stores of untouched callee-saved registers in the entry block = prologue saves
        std::set<int> assigned;
        for (auto& s : B[entry_].raw) {
            if (s.dead) continue;
            if (s.k == SK::Store && s.addr && s.addr->k == EK::Stack && s.val && s.val->k == EK::Reg &&
                L.isCalleeSaved(s.val->reg) && !assigned.count(s.val->reg)) {
                savedSlots_[int64_t(s.addr->c)] = s.val->reg;
                s.dead = true;
                continue;
            }
            if (s.k == SK::Assign) assigned.insert(s.dst);
            if (s.k == SK::Call) break;
        }
        for (auto& b : B)
            for (auto& s : b.raw)
                if (s.k == SK::Assign && !s.dead && s.val && s.val->k == EK::Load && s.val->a && s.val->a->k == EK::Stack) {
                    auto it = savedSlots_.find(int64_t(s.val->a->c));
                    if (it != savedSlots_.end() && it->second == s.dst) s.dead = true;
                }
    }

    // ---- simulation ------------------------------------------------------------------------
    struct CalleeInfo { int nparams = -1; bool variadic = false; bool returns = true; bool known = false; };

    CalleeInfo calleeInfo(uint64_t target) {
        CalleeInfo ci;
        auto n = S.an.names.find(target);
        if (n != S.an.names.end()) {
            if (const Known* k = findKnown(n->second.name)) {
                ci.nparams = k->nparams; ci.variadic = k->variadic; ci.returns = !k->voidRet; ci.known = true;
                return ci;
            }
        }
        auto f = S.an.funcs.find(target);
        if (f != S.an.funcs.end() && !f->second.thunk) {
            FuncSummary sm = summarize(S, L, target);
            ci.nparams = sm.nparams; ci.returns = sm.returnsValue;
        }
        return ci;
    }

    void touch(Blk& b, Sim& st, int id, bool count) {
        Def& D = b.defs[id];
        if (!count) return;
        D.uses++;
        D.useTimes.push_back(st.now);
    }

    void touchAll(Blk& b, Sim& st, const ExprP& e) {
        visit(e, [&](const ExprP& n) { if (n->k == EK::Def) touch(b, st, int(n->c), true); });
    }

    ExprP sub(Blk& b, Sim& st, const ExprP& e, bool count = true) {
        return rewrite(e, [&](const ExprP& n) -> ExprP {
            if (n->k == EK::Reg && n->reg < 64) {
                auto it = st.env.find(n->reg);
                if (it != st.env.end()) { touch(b, st, it->second, count); return mkDef(it->second); }
                return nullptr;
            }
            if (n->k == EK::Flags && !n->a) return resolveCC(b, st, n->size, count);
            return nullptr;
        });
    }

    ExprP condFrom(FlagKind k, int cc, const ExprP& a, const ExprP& b) {
        auto cmp = [&](BinOp op) { return mkBin(op, a, b); };
        auto zero = mkConst(0);
        auto vs0 = [&](const ExprP& v, BinOp op) { return mkBin(op, v, zero); };
        auto raw = [&]() { return mkRaw("cond" + std::to_string(cc)); };
        if (k == FlagKind::Sub) {
            switch (cc) {
                case 1: return cmp(BinOp::Eq);   case 2: return cmp(BinOp::Ne);
                case 3: return cmp(BinOp::UGe);  case 4: return cmp(BinOp::ULt);
                case 9: return cmp(BinOp::UGt);  case 10: return cmp(BinOp::ULe);
                case 11: return cmp(BinOp::SGe); case 12: return cmp(BinOp::SLt);
                case 13: return cmp(BinOp::SGt); case 14: return cmp(BinOp::SLe);
                case 5: return vs0(mkBin(BinOp::Sub, a, b), BinOp::SLt);
                case 6: return vs0(mkBin(BinOp::Sub, a, b), BinOp::SGe);
                default: return raw();
            }
        }
        if (k == FlagKind::Add) {
            ExprP sum = mkBin(BinOp::Add, a, b);
            switch (cc) {
                case 1: return vs0(sum, BinOp::Eq);  case 2: return vs0(sum, BinOp::Ne);
                case 5: case 12: return vs0(sum, BinOp::SLt);
                case 6: case 11: return vs0(sum, BinOp::SGe);
                case 13: return vs0(sum, BinOp::SGt); case 14: return vs0(sum, BinOp::SLe);
                case 3: return mkBin(BinOp::ULt, sum, a);   // carry set
                case 4: return mkBin(BinOp::UGe, sum, a);
                default: return raw();
            }
        }
        if (k == FlagKind::And) {
            ExprP v = mkBin(BinOp::And, a, b);
            switch (cc) {
                case 1: return vs0(v, BinOp::Eq);  case 2: return vs0(v, BinOp::Ne);
                case 5: case 12: return vs0(v, BinOp::SLt);
                case 6: case 11: return vs0(v, BinOp::SGe);
                case 13: return vs0(v, BinOp::SGt); case 14: return vs0(v, BinOp::SLe);
                default: return raw();
            }
        }
        // fcmp
        switch (cc) {
            case 1: return cmp(BinOp::Eq);  case 2: return cmp(BinOp::Ne);
            case 5: case 4: case 12: return cmp(BinOp::SLt);
            case 10: case 14: return cmp(BinOp::SLe);
            case 11: case 3: case 6: return cmp(BinOp::SGe);
            case 13: case 9: return cmp(BinOp::SGt);
            default: return raw();
        }
    }

    ExprP resolveCC(Blk& b, Sim& st, int cc, bool count) {
        auto it = st.env.find(kFlagsReg);
        if (it == st.env.end()) return mkRaw("cond" + std::to_string(cc) + "(flags)");
        Def& fd = b.defs[it->second];
        const ExprP& fe = fd.expr;
        if (!fe || fe->k != EK::Flags || !fe->a) return mkRaw("cond" + std::to_string(cc) + "(flags)");
        // operands must not have been redefined since the flags were set
        bool stale = false;
        auto chk = [&](const ExprP& n) {
            if (n->k == EK::Reg && n->reg < 64 && st.lastDefTime[n->reg] > fd.time) stale = true;
        };
        visit(fe->a, chk); visit(fe->b, chk);
        if (fd.hasMem && st.lastMemTime > fd.minTime) stale = stale || false;
        if (stale) return mkRaw("cond" + std::to_string(cc) + "(flags)");
        if (count) { touchAll(b, st, fe->a); touchAll(b, st, fe->b); }
        return condFrom(fe->fk, cc, fe->a, fe->b);
    }

    int makeDef(Blk& b, Sim& st, int reg, int bits, ExprP e, bool isCall) {
        Def D;
        D.reg = reg; D.bits = bits; D.expr = e; D.isCall = isCall;
        D.time = ++st.now; D.minTime = D.time;
        D.hasMem = isCall;
        visit(e, [&](const ExprP& n) {
            if (n->k == EK::Reg && n->reg < 64) D.leaves.insert(n->reg);
            else if (n->k == EK::Def) {
                const Def& c = b.defs[int(n->c)];
                D.leaves.insert(c.leaves.begin(), c.leaves.end());
                D.minTime = std::min(D.minTime, c.minTime);
                D.hasMem = D.hasMem || c.hasMem;
            } else if (n->k == EK::Load || n->k == EK::Call) D.hasMem = true;
        });
        b.defs.push_back(std::move(D));
        int id = int(b.defs.size()) - 1;
        Event ev; ev.k = Event::DefE; ev.def = id;
        b.events.push_back(ev);
        st.env[reg] = id;
        st.lastDefTime[reg] = b.defs[id].time;
        b.finalDef[reg] = id;
        b.kills.insert(reg);
        st.defSinceCall.insert(reg);
        return id;
    }

    void simulate(Blk& b) {
        Sim st;
        const auto& argRegs = L.argRegs();
        for (auto& s : b.raw) {
            if (s.dead) continue;
            switch (s.k) {
                case SK::Assign: {
                    bool isFlags = s.dst == kFlagsReg;
                    ExprP e = sub(b, st, s.val, !isFlags);
                    makeDef(b, st, s.dst, s.dstBits, e, false);
                    break;
                }
                case SK::Store: {
                    Event ev; ev.k = Event::StoreE; ev.st = s;
                    ev.st.addr = sub(b, st, s.addr);
                    ev.st.val = sub(b, st, s.val);
                    if (mentionsGuard(b, ev.st.val)) ev.dead = true;
                    b.events.push_back(ev);
                    st.lastMemTime = ++st.now;
                    b.memTimes.push_back({st.now, int(b.events.size()) - 1});
                    if (ev.st.addr->k == EK::Stack) b.stackStores[int64_t(ev.st.addr->c)] = int(b.events.size()) - 1;
                    break;
                }
                case SK::Raw: {
                    Event ev; ev.k = Event::RawE; ev.st = s;
                    b.events.push_back(ev);
                    st.lastMemTime = ++st.now;
                    b.memTimes.push_back({st.now, int(b.events.size()) - 1});
                    break;
                }
                case SK::Call: {
                    const ExprP& c = s.val;
                    CalleeInfo ci;
                    if (c->directCall) ci = calleeInfo(c->c);
                    int n = ci.nparams;
                    const bool stackArgs = argRegs.empty();          // x86-32 cdecl: arguments live on the stack
                    const int64_t spAt = s.spKnown ? s.spOff : 0;
                    auto takeStackArg = [&](int64_t slot) -> ExprP {
                        auto it = b.stackStores.find(slot);
                        if (it != b.stackStores.end() && !b.events[size_t(it->second)].dead) {
                            b.events[size_t(it->second)].dead = true;
                            return b.events[size_t(it->second)].st.val;
                        }
                        return mkRaw("/*arg*/");
                    };
                    if (n < 0) {
                        n = 0;
                        if (stackArgs) {
                            while (n < 16) {
                                auto it = b.stackStores.find(spAt + 4 * n);
                                if (it == b.stackStores.end() || b.events[size_t(it->second)].dead) break;
                                ++n;
                            }
                        }
                        else
                        for (size_t i = 0; i < argRegs.size(); ++i)
                            if (st.defSinceCall.count(argRegs[i])) n = int(i) + 1;
                    }
                    std::vector<ExprP> args;
                    if (stackArgs) {
                        for (int i = 0; i < n && i < 16; ++i) args.push_back(takeStackArg(spAt + 4 * i));
                    } else {
                        for (int i = 0; i < n && i < int(argRegs.size()); ++i)
                            args.push_back(sub(b, st, mkReg(argRegs[i], 0)));
                    }
                    if (c->directCall && n >= 2) {
                        auto nm = S.an.names.find(c->c);
                        if (nm != S.an.names.end() && stripUnderscores(nm->second.name).rfind("objc_msgSend", 0) == 0) {
                            std::string sel;
                            if (selectorOf(b, args[1], sel)) {
                                int extra = int(std::count(sel.begin(), sel.end(), ':'));
                                for (int i = 0; i < extra && n + i < int(argRegs.size()); ++i)
                                    args.push_back(sub(b, st, mkReg(argRegs[size_t(n + i)], 0)));
                            }
                        }
                    }
                    if (ci.variadic && n > 0) {
                        std::string fmt;
                        bool haveFmt = constString(b, args[size_t(n) - 1], fmt);
                        int extra = haveFmt ? countFormat(fmt) : 0;
                        bool stackVa = S.img.format == "Mach-O" && S.img.arch == Arch::ARM64;
                        for (int i = 0; i < extra; ++i) {
                            int ai = n + i;
                            if (stackArgs) { args.push_back(takeStackArg(spAt + 4 * ai)); continue; }
                            if (!stackVa && ai < int(argRegs.size())) {
                                args.push_back(sub(b, st, mkReg(argRegs[ai], 0)));
                                continue;
                            }
                            int64_t slot = (s.spKnown ? s.spOff : 0) + 8 * (stackVa ? i : (ai - int(argRegs.size())));
                            auto it = b.stackStores.find(slot);
                            if (it != b.stackStores.end() && !b.events[size_t(it->second)].dead) {
                                b.events[size_t(it->second)].dead = true;
                                args.push_back(b.events[size_t(it->second)].st.val);
                            } else {
                                args.push_back(mkRaw("/*arg*/"));
                            }
                        }
                    }
                    ExprP ind = c->directCall ? nullptr : sub(b, st, c->a);
                    ExprP call = mkCallE(c->c, ind, std::move(args));
                    // the call executes now: result def + caller-saved clobber
                    int retReg = L.retReg();
                    if (ci.returns) {
                        int cid = makeDef(b, st, retReg, 0, call, true);
                        b.memTimes.push_back({b.defs[size_t(cid)].time, -1});
                    } else {
                        Event ev; ev.k = Event::RawE; ev.st.k = SK::Call; ev.st.val = call; ev.st.at = s.at;
                        b.events.push_back(ev);
                        st.lastMemTime = ++st.now;
                        b.memTimes.push_back({st.now, int(b.events.size()) - 1});
                    }
                    st.lastMemTime = st.now;
                    st.defSinceCall.clear();
                    for (int r = 0; r < 32; ++r) {
                        if (r == L.spReg() || r == L.fpReg() || L.isCalleeSaved(r)) continue;
                        if (ci.returns && r == retReg) continue;
                        st.env.erase(r);
                        st.lastDefTime[r] = st.now;
                        b.kills.insert(r);
                    }
                    st.env.erase(kFlagsReg);
                    break;
                }
                default: break;
            }
        }
        // terminator (evaluated after every event)
        st.now++;
        switch (b.tk) {
            case TK::Br:
                if (b.term.cc >= 0) b.cond = resolveCC(b, st, b.term.cc, true);
                else b.cond = sub(b, st, b.term.cond);
                break;
            case TK::Ret: b.retv = sub(b, st, mkReg(L.retReg(), 0)); break;
            case TK::Switch: b.idx = sub(b, st, b.term.index); break;
            default: break;
        }
    }

    std::optional<uint64_t> evalConst(Blk& b, const ExprP& e, int depth = 0) {
        if (!e || depth > 24) return std::nullopt;
        switch (e->k) {
            case EK::Const: case EK::Str: case EK::Sym: return e->c;
            case EK::Def: return evalConst(b, b.defs[int(e->c)].expr, depth + 1);
            case EK::Bin: {
                auto x = evalConst(b, e->a, depth + 1), y = evalConst(b, e->b, depth + 1);
                if (!x || !y) return std::nullopt;
                switch (e->bop) {
                    case BinOp::Add: return *x + *y;
                    case BinOp::Sub: return *x - *y;
                    case BinOp::Or: return *x | *y;
                    case BinOp::And: return *x & *y;
                    case BinOp::Shl: return *y < 64 ? *x << *y : 0;
                    default: return std::nullopt;
                }
            }
            default: return std::nullopt;
        }
    }

    bool constString(Blk& b, const ExprP& e, std::string& out) {
        auto v = evalConst(b, e);
        if (!v) return false;
        auto it = S.an.strings.find(*v);
        if (it != S.an.strings.end()) { out = it->second.text; return true; }
        return S.img.readCString(*v, out, 1024);
    }

    // selector string held by an objc selref slot loaded into the expression (if any)
    bool selectorOf(Blk& b, const ExprP& e, std::string& sel) {
        ExprP x = e;
        for (int i = 0; i < 8 && x && x->k == EK::Def; ++i) x = b.defs[int(x->c)].expr;
        if (!x || x->k != EK::Load) return false;
        auto slot = evalConst(b, x->a);
        if (!slot) return false;
        const Section* sec = S.img.secAt(*slot);
        if (!sec || sec->name.find("__objc_selrefs") == std::string::npos) return false;
        return S.img.readCString(S.img.readPtr(*slot) & 0x0000fffffffffff8ull, sel, 256) && !sel.empty();
    }

    // does the (def-resolved) expression read the stack-protector guard?
    bool mentionsGuard(Blk& b, const ExprP& e, int depth = 0) {
        if (!e || depth > 24) return false;
        if (e->k == EK::Def) return mentionsGuard(b, b.defs[int(e->c)].expr, depth + 1);
        if (e->k == EK::Load || e->k == EK::Const || e->k == EK::Sym) {
            auto v = e->k == EK::Load ? evalConst(b, e->a) : std::optional<uint64_t>(e->c);
            if (v) {
                auto n = S.an.names.find(*v);
                if (n != S.an.names.end() && n->second.name.find("stack_chk_guard") != std::string::npos) return true;
            }
        }
        return mentionsGuard(b, e->a, depth + 1) || mentionsGuard(b, e->b, depth + 1) || mentionsGuard(b, e->cc, depth + 1);
    }

    int idRegByName(const std::string& n) const {
        if (n.empty()) return -1;
        for (int r = 0; r < 32; ++r)
            for (int bits : {64, 32})
                if (L.regName(r, bits) == n) return r;
        return -1;
    }

    // ---- return value / liveness ---------------------------------------------------------------
    void computeReturn() {
        int retReg = L.retReg();
        bool changed = true;
        for (int u : rpo) B[u].retDefined = B[u].finalDef.count(retReg) != 0;
        while (changed) {
            changed = false;
            for (int u : rpo) {
                if (B[u].retDefined) continue;
                for (int p : B[u].pred)
                    if (B[p].reachable && B[p].retDefined) { B[u].retDefined = true; changed = true; break; }
            }
        }
        returnsValue_ = false;
        for (int u : rpo)
            if (B[u].tk == TK::Ret && B[u].retDefined) returnsValue_ = true;
    }

    void closure(Blk& b, int id) {
        Def& D = b.defs[id];
        if (D.needed) return;
        D.needed = true;
        visit(D.expr, [&](const ExprP& n) { if (n->k == EK::Def) closure(b, int(n->c)); });
    }
    void closureExpr(Blk& b, const ExprP& e) {
        visit(e, [&](const ExprP& n) { if (n->k == EK::Def) closure(b, int(n->c)); });
    }

    // Marks needed defs for the given live-out set; returns registers read from block entry.
    std::set<int> computeNeeds(Blk& b, const std::set<int>& liveOut) {
        for (auto& d : b.defs) { d.needed = false; d.liveOutFinal = false; }
        for (size_t i = 0; i < b.defs.size(); ++i)
            if (b.defs[i].isCall) closure(b, int(i));
        for (auto& [r, id] : b.finalDef)
            if (r != kFlagsReg && liveOut.count(r)) { b.defs[size_t(id)].liveOutFinal = true; closure(b, id); }
        std::vector<const ExprP*> roots;
        for (auto& ev : b.events) {
            if (ev.dead) continue;
            if (ev.k == Event::StoreE) { closureExpr(b, ev.st.addr); closureExpr(b, ev.st.val); }
            if (ev.k == Event::RawE && ev.st.val) closureExpr(b, ev.st.val);
        }
        if (b.cond) closureExpr(b, b.cond);
        if (b.idx) closureExpr(b, b.idx);
        if (b.tk == TK::Ret && returnsValue_ && b.retv) closureExpr(b, b.retv);

        std::set<int> reads;
        auto leaf = [&](const ExprP& n) { if (n->k == EK::Reg && n->reg < 64) reads.insert(n->reg); };
        for (auto& d : b.defs) if (d.needed) visit(d.expr, leaf);
        for (auto& ev : b.events) {
            if (ev.dead) continue;
            if (ev.k == Event::StoreE) { visit(ev.st.addr, leaf); visit(ev.st.val, leaf); }
            if (ev.k == Event::RawE && ev.st.val) visit(ev.st.val, leaf);
        }
        if (b.cond) visit(b.cond, leaf);
        if (b.idx) visit(b.idx, leaf);
        if (b.tk == TK::Ret && returnsValue_ && b.retv) visit(b.retv, leaf);
        return reads;
    }

    void liveness() {
        for (bool changed = true; changed;) {
            changed = false;
            for (auto it = rpo.rbegin(); it != rpo.rend(); ++it) {
                Blk& b = B[*it];
                std::set<int> out;
                for (int s : b.succ) out.insert(B[s].liveIn.begin(), B[s].liveIn.end());
                std::set<int> in = computeNeeds(b, out);
                for (int r : out) if (!b.kills.count(r)) in.insert(r);
                if (out != b.liveOut || in != b.liveIn) { b.liveOut = out; b.liveIn = in; changed = true; }
            }
        }
    }

    // ---- final emission ----------------------------------------------------------------------------
    ExprP expand(Blk& b, const ExprP& e) {
        return rewrite(e, [&](const ExprP& n) -> ExprP {
            if (n->k != EK::Def) return nullptr;
            Def& D = b.defs[int(n->c)];
            if (D.mat && D.var >= 0) return mkReg(D.var, D.bits);
            return expand(b, D.expr);
        });
    }

    // Registers written exactly once with a constant (typically adrp bases) are folded into every use.
    void propagateConstants(FuncModel& m) {
        for (int round = 0; round < 4; ++round) {
            std::map<int, int> defs;
            std::map<int, ExprP> value;
            std::set<int> conflict;
            for (auto& fb : m.blocks)
                for (auto& s : fb.out)
                    if (s.k == SK::Assign && s.dst < 64) {
                        defs[s.dst]++;
                        auto it = value.find(s.dst);
                        if (it == value.end()) value[s.dst] = s.val;
                        else if (!exprEq(it->second, s.val)) conflict.insert(s.dst);
                    }
            std::map<int, ExprP> fold;
            for (auto& [r, n] : defs) {
                if (conflict.count(r) || B[entry_].liveIn.count(r)) continue;
                const ExprP& v = value[r];
                if (v && (v->k == EK::Const || v->k == EK::Stack || v->k == EK::Sym || v->k == EK::Str)) fold[r] = v;
            }
            if (fold.empty()) return;
            auto repl = [&](const ExprP& e) {
                return rewrite(e, [&](const ExprP& n) -> ExprP {
                    if (n->k == EK::Reg) { auto it = fold.find(n->reg); if (it != fold.end()) return it->second; }
                    return nullptr;
                });
            };
            for (auto& fb : m.blocks) {
                std::vector<Stmt> keep;
                for (auto& s : fb.out) {
                    if (s.k == SK::Assign && fold.count(s.dst)) continue;
                    if (s.val) s.val = repl(s.val);
                    if (s.addr) s.addr = repl(s.addr);
                    keep.push_back(std::move(s));
                }
                fb.out = std::move(keep);
                if (fb.cond) fb.cond = repl(fb.cond);
                if (fb.retv) fb.retv = repl(fb.retv);
                if (fb.idx) fb.idx = repl(fb.idx);
            }
        }
    }

    void emit(FuncModel& m) {
        m.start = start_;
        m.entry = entry_;
        m.blocks.resize(B.size());
        int retReg = L.retReg();
        // params
        int np = 0;
        const auto& ar = L.argRegs();
        for (size_t i = 0; i < ar.size(); ++i)
            if (B[entry_].liveIn.count(ar[i])) np = int(i) + 1;
        if (ar.empty()) {   // x86-32: parameters are the positive stack slots above the return address
            int64_t maxOff = 0;
            auto scan = [&](const ExprP& e) {
                visit(e, [&](const ExprP& n) {
                    if (n->k == EK::Stack && int64_t(n->c) >= 4 && int64_t(n->c) < 4 + 64) maxOff = std::max<int64_t>(maxOff, int64_t(n->c));
                });
            };
            for (auto& b : B) {
                if (!b.reachable) continue;
                for (auto& ev : b.events) { if (ev.dead) continue; scan(ev.st.addr); scan(ev.st.val); }
                for (auto& d : b.defs) scan(d.expr);
            }
            np = maxOff ? int((maxOff - 4) / 4 + 1) : 0;
            m.stackParams = np;
        }
        m.nparams = np;
        m.returnsValue = returnsValue_;

        for (size_t bi = 0; bi < B.size(); ++bi) {
            Blk& b = B[bi];
            FinalBlock& fb = m.blocks[bi];
            fb.addr = b.addr; fb.tk = b.tk; fb.t = b.t; fb.f = b.f; fb.cases = b.cases;
            fb.succ = b.succ; fb.pred = b.pred; fb.reachable = b.reachable;
            if (!b.reachable) continue;
            computeNeeds(b, b.liveOut);
            // memory hazards: an expression that loads/calls can't be moved across a live store or call
            for (auto& D : b.defs) {
                D.forceMem = false;
                if (!D.hasMem) continue;
                for (int T : D.useTimes) {
                    for (auto& [mt, ei] : b.memTimes) {
                        if (ei >= 0 && b.events[size_t(ei)].dead) continue;
                        if (mt > D.minTime && mt < T) { D.forceMem = true; break; }
                    }
                    if (D.forceMem) break;
                }
            }
            // register-clobber hazards: a leaf register is only overwritten by a final def that is really emitted
            for (size_t di = 0; di < b.defs.size(); ++di) {
                Def& D = b.defs[di];
                D.forceReg = false;
                for (int r : D.leaves) {
                    auto it = b.finalDef.find(r);
                    if (it == b.finalDef.end() || it->second == int(di)) continue;
                    const Def& F = b.defs[size_t(it->second)];
                    if (!F.liveOutFinal) continue;
                    for (int T : D.useTimes)
                        if (F.time > D.minTime && F.time <= T) { D.forceReg = true; break; }
                    if (D.forceReg) break;
                }
            }
            // materialisation decisions
            for (auto& D : b.defs) {
                D.mat = false; D.var = -1;
                if (!D.needed) continue;
                if (D.liveOutFinal) { D.mat = true; D.var = D.reg; continue; }
                if (D.isCall) {
                    if (D.uses == 0) { D.mat = true; D.var = -1; }
                    else if (D.uses > 1 || D.forceMem || D.forceReg) { D.mat = true; D.var = kTempBase + nextTemp_++; }
                    continue;
                }
                ExprP ex = expand(b, D.expr);
                bool simple = simpleExpr(ex);
                // a copy of an already-stable value (constant / materialised variable) can't be invalidated by memory effects
                bool forced = D.forceReg || (D.forceMem && !simple);
                if (forced || (D.uses > 1 && !simple)) { D.mat = true; D.var = kTempBase + nextTemp_++; }
            }
            for (auto& ev : b.events) {
                if (ev.dead) continue;
                if (ev.k == Event::DefE) {
                    Def& D = b.defs[size_t(ev.def)];
                    if (!D.needed || !D.mat) continue;
                    Stmt s; s.at = 0;
                    ExprP val = expand(b, D.expr);
                    if (D.var < 0) { s.k = SK::Call; s.val = val; }
                    else { s.k = SK::Assign; s.dst = D.var; s.dstBits = D.bits; s.val = val; }
                    fb.out.push_back(std::move(s));
                } else if (ev.k == Event::StoreE) {
                    Stmt s = ev.st;
                    s.addr = expand(b, s.addr); s.val = expand(b, s.val);
                    fb.out.push_back(std::move(s));
                } else {
                    Stmt s = ev.st;
                    if (s.val) s.val = expand(b, s.val);
                    fb.out.push_back(std::move(s));
                }
            }
            if (b.cond) fb.cond = expand(b, b.cond);
            if (b.idx) {
                fb.idx = expand(b, b.idx);
                if (!b.tableCases.empty()) {
                    ExprP found;
                    visit(fb.idx, [&](const ExprP& n) {
                        if (found || n->k != EK::Load || !n->a || n->a->k != EK::Bin || n->a->bop != BinOp::Add) return;
                        ExprP x = isConst(n->a->b) ? n->a->a : isConst(n->a->a) ? n->a->b : nullptr;
                        if (!x) x = n->a->a->k == EK::Bin ? n->a->a : n->a->b;
                        if (x->k == EK::Bin && (x->bop == BinOp::Shl || x->bop == BinOp::Mul) && isConst(x->b)) x = x->a;
                        found = x;
                    });
                    if (found) fb.idx = found;
                }
                int64_t bias = 0;
                for (int guard = 0; guard < 6 && fb.idx; ++guard) {
                    const ExprP& x = fb.idx;
                    if (x->k == EK::Cond && x->cc && isConst(x->cc) && x->cc->c == 0) fb.idx = x->b;
                    else if (x->k == EK::Cast && !x->sign) fb.idx = x->a;
                    else if (x->k == EK::Bin && x->bop == BinOp::Add && isConst(x->b)) { bias -= int64_t(x->b->c); fb.idx = x->a; }
                    else break;
                }
                for (auto& [k, blk] : b.tableCases) fb.switchCases.push_back({k + bias, blk});
                std::stable_sort(fb.switchCases.begin(), fb.switchCases.end(),
                                 [](const auto& a, const auto& c) { return a.first < c.first; });
            }
            if (b.tk == TK::Ret && returnsValue_ && b.retv) fb.retv = expand(b, b.retv);
            (void)retReg;
        }
        propagateConstants(m);
        m.nextTemp = nextTemp_;
        // register widths: a register prints as wN only if every access was 32-bit
        auto note = [&](int reg, int bits) {
            if (bits == 0) return;
            auto it = m.reg32.find(reg);
            if (it == m.reg32.end()) m.reg32[reg] = bits == 32;
            else it->second = it->second && bits == 32;
        };
        for (auto& fb : m.blocks) {
            auto scan = [&](const ExprP& e) {
                visit(e, [&](const ExprP& n) { if (n->k == EK::Reg) note(n->reg, n->bits); });
            };
            for (auto& s : fb.out) {
                if (s.k == SK::Assign) note(s.dst, s.dstBits);
                scan(s.val); scan(s.addr);
            }
            scan(fb.cond); scan(fb.retv); scan(fb.idx);
        }
        for (auto& [r, w] : m.reg32) if (r >= kTempBase) w = false;
        // return width
        m.retBits = 64;
        for (auto& b : B)
            if (b.reachable && b.tk == TK::Ret && returnsValue_) {
                auto it = b.finalDef.find(retReg);
                if (it != b.finalDef.end() && b.defs[size_t(it->second)].bits == 32) m.retBits = 32;
            }
    }
};

std::map<std::pair<const Session*, uint64_t>, FuncSummary> g_summaries;
std::set<std::pair<const Session*, uint64_t>> g_inProgress;

}  // namespace

bool buildModel(Session& s, Lifter& L, uint64_t funcStart, FuncModel& m, std::string& err) {
    Builder b(s, L, funcStart);
    return b.run(m, err);
}

void clearSummaryCache() { g_summaries.clear(); }

FuncSummary summarize(Session& s, Lifter& L, uint64_t funcStart) {
    auto key = std::make_pair(static_cast<const Session*>(&s), funcStart);
    auto it = g_summaries.find(key);
    if (it != g_summaries.end()) return it->second;
    if (g_inProgress.count(key)) return FuncSummary{};   // recursion: unknown arity
    g_inProgress.insert(key);
    FuncSummary sm;
    FuncModel m;
    std::string err;
    if (buildModel(s, L, funcStart, m, err)) {
        sm.nparams = m.nparams;
        sm.returnsValue = m.returnsValue;
    }
    auto fit = s.an.funcs.find(funcStart);
    if (fit != s.an.funcs.end()) sm.noret = fit->second.noret;
    g_inProgress.erase(key);
    g_summaries[key] = sm;
    return sm;
}

}  // namespace er::dc
