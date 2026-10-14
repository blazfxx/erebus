// Structuring (CFG -> if/while/switch) and pseudo-C printing.
#include "decomp/decompile.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <set>
#include <sstream>

#include "cli/render.h"
#include "core/util.h"
#include "decomp/dcmodel.h"

namespace er::dc {
namespace {

// ---------------------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------------------
struct Node {
    enum K { Simple, If, While, DoWhile, Switch, Break, Continue, Goto, Label, Return } k = Simple;
    Stmt st;
    ExprP e;                       // If/While/DoWhile condition, Return value, Switch index
    std::vector<Node> a, b;        // If: then / else; loops: body in a
    uint64_t addr = 0;             // Goto / Label
    std::vector<std::pair<std::vector<int64_t>, std::vector<Node>>> cases;
};

bool endsInJump(const std::vector<Node>& v) {
    if (v.empty()) return false;
    const Node& n = v.back();
    if (n.k == Node::Return || n.k == Node::Break || n.k == Node::Continue || n.k == Node::Goto) return true;
    if (n.k == Node::If && !n.b.empty()) return endsInJump(n.a) && endsInJump(n.b);
    return false;
}

// ---------------------------------------------------------------------------------------
// structurer
// ---------------------------------------------------------------------------------------
class Structurer {
public:
    explicit Structurer(const FuncModel& m) : M(m) {}

    std::vector<Node> run() {
        n_ = int(M.blocks.size());
        visited_.assign(size_t(n_), 0);
        computeOrder();
        computeDominators();
        computePostDominators();
        findLoops();
        std::vector<Node> body = region(M.entry, -1);
        // blocks never reached by the structured walk (shouldn't happen for reachable code) are appended with labels
        for (int i = 0; i < n_; ++i)
            if (M.blocks[size_t(i)].reachable && !visited_[size_t(i)]) {
                std::vector<Node> extra = region(i, -1);
                body.insert(body.end(), extra.begin(), extra.end());
            }
        prune(body);
        return body;
    }

private:
    const FuncModel& M;
    int n_ = 0;
    std::vector<char> visited_;
    std::vector<int> rpo_, pos_;
    std::vector<int> idom_, ipdom_;
    std::map<int, std::set<int>> loopBody_;      // header -> body blocks
    struct Ctx { int header, exit; };
    std::vector<Ctx> loops_;
    std::set<uint64_t> gotoTargets_;

    void computeOrder() {
        pos_.assign(size_t(n_), -1);
        std::vector<char> seen(size_t(n_), 0);
        std::vector<int> post;
        std::function<void(int)> dfs = [&](int u) {
            seen[size_t(u)] = 1;
            for (int v : M.blocks[size_t(u)].succ) if (!seen[size_t(v)]) dfs(v);
            post.push_back(u);
        };
        dfs(M.entry);
        rpo_.assign(post.rbegin(), post.rend());
        for (size_t i = 0; i < rpo_.size(); ++i) pos_[size_t(rpo_[i])] = int(i);
    }

    void computeDominators() {
        idom_.assign(size_t(n_), -1);
        idom_[size_t(M.entry)] = M.entry;
        auto intersect = [&](int a, int b) {
            while (a != b) {
                while (pos_[size_t(a)] > pos_[size_t(b)]) a = idom_[size_t(a)];
                while (pos_[size_t(b)] > pos_[size_t(a)]) b = idom_[size_t(b)];
            }
            return a;
        };
        for (bool ch = true; ch;) {
            ch = false;
            for (int u : rpo_) {
                if (u == M.entry) continue;
                int nd = -1;
                for (int p : M.blocks[size_t(u)].pred) {
                    if (pos_[size_t(p)] < 0 || idom_[size_t(p)] < 0) continue;
                    nd = nd < 0 ? p : intersect(p, nd);
                }
                if (nd != idom_[size_t(u)]) { idom_[size_t(u)] = nd; ch = true; }
            }
        }
    }

    bool dominates(int a, int b) const {
        if (pos_[size_t(b)] < 0) return false;
        for (int x = b;;) {
            if (x == a) return true;
            if (x == M.entry || idom_[size_t(x)] < 0) return false;
            x = idom_[size_t(x)];
        }
    }

    void computePostDominators() {
        // reverse graph with a virtual exit node `n_`
        const int E = n_;
        std::vector<std::vector<int>> rsucc(size_t(n_) + 1);   // edges v -> u meaning u -> v in the CFG
        std::vector<std::vector<int>> rpred(size_t(n_) + 1);
        for (int u : rpo_) {
            const auto& s = M.blocks[size_t(u)].succ;
            if (s.empty()) { rsucc[size_t(E)].push_back(u); rpred[size_t(u)].push_back(E); }
            for (int v : s) { rsucc[size_t(v)].push_back(u); rpred[size_t(u)].push_back(v); }
        }
        std::vector<int> post, rpos(size_t(n_) + 1, -1);
        std::vector<char> seen(size_t(n_) + 1, 0);
        std::function<void(int)> dfs = [&](int u) {
            seen[size_t(u)] = 1;
            for (int v : rsucc[size_t(u)]) if (!seen[size_t(v)]) dfs(v);
            post.push_back(u);
        };
        dfs(E);
        std::vector<int> order(post.rbegin(), post.rend());
        for (size_t i = 0; i < order.size(); ++i) rpos[size_t(order[i])] = int(i);
        ipdom_.assign(size_t(n_) + 1, -1);
        ipdom_[size_t(E)] = E;
        auto intersect = [&](int a, int b) {
            while (a != b) {
                while (rpos[size_t(a)] > rpos[size_t(b)]) a = ipdom_[size_t(a)];
                while (rpos[size_t(b)] > rpos[size_t(a)]) b = ipdom_[size_t(b)];
            }
            return a;
        };
        for (bool ch = true; ch;) {
            ch = false;
            for (int u : order) {
                if (u == E) continue;
                int nd = -1;
                for (int p : rpred[size_t(u)]) {
                    if (rpos[size_t(p)] < 0 || ipdom_[size_t(p)] < 0) continue;
                    nd = nd < 0 ? p : intersect(p, nd);
                }
                if (nd != ipdom_[size_t(u)]) { ipdom_[size_t(u)] = nd; ch = true; }
            }
        }
    }

    int ipdom(int b) const {
        int p = ipdom_[size_t(b)];
        return (p < 0 || p == n_) ? -1 : p;
    }

    void findLoops() {
        for (int u : rpo_)
            for (int h : M.blocks[size_t(u)].succ) {
                if (!dominates(h, u)) continue;   // back edge u -> h
                std::set<int>& body = loopBody_[h];
                body.insert(h);
                std::vector<int> work{u};
                while (!work.empty()) {
                    int x = work.back(); work.pop_back();
                    if (body.count(x)) continue;
                    body.insert(x);
                    for (int p : M.blocks[size_t(x)].pred)
                        if (pos_[size_t(p)] >= 0) work.push_back(p);
                }
            }
    }

    bool isHeader(int b) const { return loopBody_.count(b) != 0; }

    int loopExit(int h) const {
        const auto& body = loopBody_.at(h);
        int best = -1;
        for (int u : body)
            for (int v : M.blocks[size_t(u)].succ)
                if (!body.count(v) && (best < 0 || pos_[size_t(v)] < pos_[size_t(best)])) best = v;
        return best;
    }

    // ---- emission ------------------------------------------------------------------------------
    static Node simple(const Stmt& s) { Node n; n.k = Node::Simple; n.st = s; return n; }
    static Node jump(Node::K k, uint64_t addr = 0) { Node n; n.k = k; n.addr = addr; return n; }

    // classify a jump to t from inside the current loop nest
    bool special(int t, std::vector<Node>& out) {
        if (loops_.empty()) return false;
        const Ctx& c = loops_.back();
        if (t == c.header) { out.push_back(jump(Node::Continue)); return true; }
        if (t == c.exit) { out.push_back(jump(Node::Break)); return true; }
        const auto& body = loopBody_[c.header];
        bool outer = false;
        for (size_t i = 0; i + 1 < loops_.size(); ++i)
            if (t == loops_[i].header || t == loops_[i].exit) outer = true;
        if (outer || !body.count(t)) {
            out.push_back(jump(Node::Goto, M.blocks[size_t(t)].addr));
            gotoTargets_.insert(M.blocks[size_t(t)].addr);
            return true;
        }
        return false;
    }

    std::vector<Node> arm(int t, int stop) {
        std::vector<Node> v;
        if (t < 0 || t == stop) return v;
        if (special(t, v)) return v;
        return region(t, stop);
    }

    int clampJoin(int j) const {
        if (j < 0) return -1;
        if (!loops_.empty()) {
            const Ctx& c = loops_.back();
            if (j == c.exit || j == c.header || !loopBody_.at(c.header).count(j)) return -1;
        }
        return j;
    }

    std::vector<Node> region(int b, int stop, bool loopTop = false) {
        std::vector<Node> out;
        for (;;) {
            if (b < 0 || b == stop) break;
            if (visited_[size_t(b)]) {
                out.push_back(jump(Node::Goto, M.blocks[size_t(b)].addr));
                gotoTargets_.insert(M.blocks[size_t(b)].addr);
                break;
            }
            if (isHeader(b) && !(loopTop && !loops_.empty() && loops_.back().header == b)) {
                int X = loopExit(b);
                loops_.push_back({b, X});
                Node w; w.k = Node::While;
                w.a = region(b, -1, true);
                loops_.pop_back();
                out.push_back(std::move(w));
                b = X;
                loopTop = false;
                continue;
            }
            loopTop = false;
            visited_[size_t(b)] = 1;
            const FinalBlock& fb = M.blocks[size_t(b)];
            Node lab; lab.k = Node::Label; lab.addr = fb.addr;
            out.push_back(lab);
            for (const Stmt& s : fb.out) out.push_back(simple(s));
            switch (fb.tk) {
                case TK::Ret: { Node r; r.k = Node::Return; r.e = fb.retv; out.push_back(r); return out; }
                case TK::None: return out;
                case TK::Fall:
                case TK::Jmp: {
                    int nx = fb.t;
                    if (nx == stop) return out;
                    if (special(nx, out)) return out;
                    b = nx;
                    continue;
                }
                case TK::Br: {
                    int J = clampJoin(ipdom(b));
                    // a join that is the stop block of an enclosing region is fine; otherwise it must be reachable from both arms
                    Node iff; iff.k = Node::If; iff.e = fb.cond;
                    iff.a = arm(fb.t, J);
                    iff.b = arm(fb.f, J);
                    out.push_back(std::move(iff));
                    if (J < 0) return out;
                    b = J;
                    continue;
                }
                case TK::Switch: {
                    int J = clampJoin(ipdom(b));
                    Node sw; sw.k = Node::Switch; sw.e = fb.idx;
                    if (!fb.switchCases.empty()) {
                        std::vector<int> order;
                        std::map<int, std::vector<int64_t>> vals;
                        for (const auto& [v, blk] : fb.switchCases) {
                            if (!vals.count(blk)) order.push_back(blk);
                            vals[blk].push_back(v);
                        }
                        for (int c : order) {
                            std::vector<Node> body = arm(c, J);
                            if (!endsInJump(body)) body.push_back(jump(Node::Break));
                            sw.cases.push_back({vals[c], std::move(body)});
                        }
                    } else {
                        int64_t i = 0;
                        for (int c : fb.cases) {
                            std::vector<Node> body = arm(c, J);
                            if (!endsInJump(body)) body.push_back(jump(Node::Break));
                            sw.cases.push_back({{i++}, std::move(body)});
                        }
                    }
                    out.push_back(std::move(sw));
                    if (J < 0) return out;
                    b = J;
                    continue;
                }
            }
        }
        return out;
    }

    // ---- cleanup -----------------------------------------------------------------------------------
    void collectGotos(const std::vector<Node>& v, std::set<uint64_t>& s) {
        for (const auto& n : v) {
            if (n.k == Node::Goto) s.insert(n.addr);
            collectGotos(n.a, s); collectGotos(n.b, s);
            for (const auto& c : n.cases) collectGotos(c.second, s);
        }
    }

    void prune(std::vector<Node>& v) {
        simplify(v);
        std::set<uint64_t> used;
        collectGotos(v, used);
        dropLabels(v, used);
    }

    void dropLabels(std::vector<Node>& v, const std::set<uint64_t>& used) {
        v.erase(std::remove_if(v.begin(), v.end(), [&](const Node& n) { return n.k == Node::Label && !used.count(n.addr); }), v.end());
        for (auto& n : v) {
            dropLabels(n.a, used); dropLabels(n.b, used);
            for (auto& c : n.cases) dropLabels(c.second, used);
        }
    }

    static bool isStackChkFail(const Node& n) {
        if (n.k != Node::Simple || n.st.k != SK::Call || !n.st.val) return false;
        const Expr& c = *n.st.val;
        return c.k == EK::Call && c.directCall && stackChkTargets().count(c.c);
    }
    static std::set<uint64_t>& stackChkTargets() { static std::set<uint64_t> s; return s; }

public:
    void setStackChk(const std::set<uint64_t>& t) { stackChkTargets() = t; }

private:
    void simplify(std::vector<Node>& v) {
        for (auto& n : v) {
            simplify(n.a); simplify(n.b);
            for (auto& c : n.cases) simplify(c.second);
        }
        // stack-protector: `if (c) { __stack_chk_fail(); }` disappears
        for (size_t i = 0; i < v.size(); ++i) {
            Node& n = v[i];
            if (n.k != Node::If) continue;
            auto onlyChk = [&](const std::vector<Node>& arm) {
                size_t calls = 0;
                for (const auto& x : arm) { if (x.k == Node::Label) continue; if (isStackChkFail(x)) ++calls; else return false; }
                return calls > 0;
            };
            if (onlyChk(n.a) || onlyChk(n.b)) {
                std::vector<Node> keep = onlyChk(n.a) ? std::move(n.b) : std::move(n.a);
                v.erase(v.begin() + long(i));
                v.insert(v.begin() + long(i), keep.begin(), keep.end());
                --i;
            }
        }
        for (size_t i = 0; i < v.size(); ++i) {
            Node& n = v[i];
            if (n.k == Node::If) {
                if (n.a.empty() && !n.b.empty()) { n.e = mkUn(UnOp::LNot, n.e); std::swap(n.a, n.b); }
                // if (c) { ...; jump } else { B }  ->  if (c) { ...; jump } B
                if (!n.b.empty() && endsInJump(n.a)) {
                    std::vector<Node> rest = std::move(n.b);
                    n.b.clear();
                    v.insert(v.begin() + long(i) + 1, rest.begin(), rest.end());
                }
            }
            if (n.k == Node::While) loopForms(n);
        }
        // drop gotos that jump to the label immediately after
        for (size_t i = 0; i + 1 < v.size(); ++i)
            if (v[i].k == Node::Goto && v[i + 1].k == Node::Label && v[i + 1].addr == v[i].addr) { v.erase(v.begin() + long(i)); --i; }
        // trailing `continue` in a loop body is implicit
    }

    static bool containsContinue(const std::vector<Node>& v) {
        for (const auto& n : v) {
            if (n.k == Node::Continue) return true;
            if (n.k == Node::While || n.k == Node::DoWhile) continue;   // inner loops own their continues
            if (containsContinue(n.a) || containsContinue(n.b)) return true;
            for (const auto& c : n.cases) if (containsContinue(c.second)) return true;
        }
        return false;
    }

    void loopForms(Node& w) {
        std::vector<Node>& body = w.a;
        // strip leading labels for pattern matching purposes
        size_t first = 0;
        while (first < body.size() && body[first].k == Node::Label) ++first;
        // while (c) : body starts with `if (c) break;`
        if (first < body.size() && body[first].k == Node::If && body[first].b.empty() && body[first].a.size() == 1 &&
            body[first].a[0].k == Node::Break) {
            w.e = mkUn(UnOp::LNot, body[first].e);
            body.erase(body.begin() + long(first));
            return;
        }
        // while (c): body starts with `if (c) { ... } else break` already flattened above into if+rest
        // do { } while (c): body ends with `if (c) continue; else break;`  (after flatten: if (c) {continue;} break;)
        if (body.size() >= 2 && body.back().k == Node::Break) {
            Node& prev = body[body.size() - 2];
            if (prev.k == Node::If && prev.b.empty() && prev.a.size() == 1 && prev.a[0].k == Node::Continue) {
                ExprP c = prev.e;
                std::vector<Node> nb(body.begin(), body.end() - 2);
                if (!containsContinue(nb)) {
                    w.k = Node::DoWhile;
                    w.e = c;
                    w.a = std::move(nb);
                    return;
                }
            }
        }
        // drop a trailing continue
        while (!body.empty() && body.back().k == Node::Continue) body.pop_back();
    }
};

// ---------------------------------------------------------------------------------------
// printer
// ---------------------------------------------------------------------------------------
struct SlotInfo {
    int size = 0;
    bool direct = false;
    bool addrTaken = false;
    bool sign = false;
};

class Printer {
public:
    Printer(Session& s, Lifter& l, const FuncModel& m) : S(s), L(l), M(m) {}

    std::vector<CLine> print(std::vector<Node>& body) {
        scanSlots(body);
        assignNames(body);
        paramRegs_.clear();
        for (int i = 0; i < M.nparams && i < int(L.argRegs().size()); ++i) paramRegs_.insert(L.argRegs()[size_t(i)]);
        std::set<int> regs;
        collectRegs(body, regs);
        header();
        decls(regs);
        nodes(body, 1);
        line(0).parts.push_back(part("}"));
        return lines_;
    }

private:
    Session& S;
    Lifter& L;
    const FuncModel& M;
    std::vector<CLine> lines_;
    std::map<int64_t, SlotInfo> slots_;
    std::map<int64_t, int64_t> extent_;
    std::set<int> paramRegs_;
    std::map<int, std::string> names_;
    std::set<int> ptr_;

    static CPart part(const std::string& t, Cls c = Cls::Plain) { CPart p; p.text = t; p.cls = c; return p; }
    static CPart ref(const std::string& t, uint64_t a, Cls c = Cls::Name) { CPart p; p.text = t; p.cls = c; p.ref = true; p.addr = a; return p; }
    CLine& line(int indent) { lines_.emplace_back(); lines_.back().indent = indent; return lines_.back(); }

    // -- naming ------------------------------------------------------------------------------------
    std::string dispName(uint64_t addr) const {
        std::string n = S.label(addr);
        if (S.img.format == "Mach-O" && n.size() > 1 && n[0] == '_') n = n.substr(1);
        return n;
    }

    std::string regVar(int reg) const {
        auto n = names_.find(reg);
        if (n != names_.end()) return n->second;
        if (reg >= kTempBase) return "v" + std::to_string(reg - kTempBase + 1);
        auto it = M.reg32.find(reg);
        bool w = it != M.reg32.end() && it->second;
        return L.regName(reg, w ? 32 : 64);
    }

    const char* varType(int reg) const {
        if (ptr_.count(reg)) return "void *";
        auto it = M.reg32.find(reg);
        return it != M.reg32.end() && it->second ? "int" : "int64_t";
    }

    // ---- variable naming and pointer inference ------------------------------------------------
    void markPtrBase(const ExprP& a) {
        if (!a) return;
        if (a->k == EK::Reg) { ptr_.insert(a->reg); return; }
        if (a->k == EK::Bin && a->bop == BinOp::Add) { markPtrBase(a->a); markPtrBase(a->b); return; }
        if (a->k == EK::Cast) markPtrBase(a->a);
    }

    static bool returnsPointer(const std::string& n) {
        static const char* names[] = {"malloc", "calloc", "realloc", "strdup", "strchr", "strrchr", "strstr", "fopen",
                                      "getenv", "strerror", "memcpy", "memset", "memmove", "strcpy", "strncpy", "strcat",
                                      "fgets", "opendir", "readdir", "dlopen", "dlsym", "mmap", "fts_open", "fts_read",
                                      "fts_children", "objc_retain", "objc_msgSend", "objc_alloc", "objc_alloc_init",
                                      "objc_autorelease", "objc_retainAutoreleasedReturnValue", "objc_opt_class"};
        std::string s = stripUnderscores(n);
        for (const char* x : names) if (s == x) return true;
        return false;
    }

    void inferExpr(const ExprP& e) {
        visit(e, [&](const ExprP& n) { if (n->k == EK::Load) markPtrBase(n->a); });
    }

    void inferNodes(const std::vector<Node>& v) {
        for (const auto& n : v) {
            if (n.k == Node::Simple) {
                const Stmt& st = n.st;
                if (st.k == SK::Store) markPtrBase(st.addr);
                inferExpr(st.val); inferExpr(st.addr);
                if (st.k == SK::Assign && st.val) {
                    const Expr& x = *st.val;
                    std::function<bool(const ExprP&)> isAddr = [&](const ExprP& e) -> bool {
                        if (!e) return false;
                        if (e->k == EK::Stack || e->k == EK::Str) return true;
                        if (e->k == EK::Const) return e->c >= 0x1000 && S.an.strings.count(e->c);
                        if (e->k == EK::Cond) return isAddr(e->b) && isAddr(e->cc);
                        return false;
                    };
                    bool strAddr = isAddr(st.val);
                    if (strAddr) ptr_.insert(st.dst);
                    if (x.k == EK::Call && x.directCall && returnsPointer(S.label(x.c))) ptr_.insert(st.dst);
                }
            }
            inferExpr(n.e);
            inferNodes(n.a); inferNodes(n.b);
            for (const auto& c : n.cases) inferNodes(c.second);
        }
    }

    void nameExpr(const ExprP& e, int& next) {
        visit(e, [&](const ExprP& n) { if (n->k == EK::Reg) nameReg(n->reg, next); });
    }
    void nameReg(int reg, int& next) {
        if (reg == kFlagsReg || names_.count(reg)) return;
        names_[reg] = "v" + std::to_string(next++);
    }
    void nameNodes(const std::vector<Node>& v, int& next) {
        for (const auto& n : v) {
            if (n.k == Node::Simple) {
                if (n.st.k == SK::Assign) nameReg(n.st.dst, next);
                nameExpr(n.st.addr, next);
                nameExpr(n.st.val, next);
            }
            nameExpr(n.e, next);
            nameNodes(n.a, next); nameNodes(n.b, next);
            for (const auto& c : n.cases) nameNodes(c.second, next);
        }
    }

    void assignNames(const std::vector<Node>& body) {
        names_.clear(); ptr_.clear();
        inferNodes(body);
        bool objc = S.label(M.start).size() > 2 && (S.label(M.start)[0] == '-' || S.label(M.start)[0] == '+') &&
                    S.label(M.start)[1] == '[';
        for (int i = 0; i < M.nparams && i < int(L.argRegs().size()); ++i) {
            int r = L.argRegs()[size_t(i)];
            if (objc && i == 0) names_[r] = "self";
            else if (objc && i == 1) names_[r] = "_cmd";
            else names_[r] = "a" + std::to_string(i + 1);
        }
        int next = 1;
        nameNodes(body, next);
    }

    std::string slotName(int64_t off) const {
        if (M.stackParams > 0 && off >= 4 && off < 4 + 4 * M.stackParams && (off - 4) % 4 == 0)
            return "a" + std::to_string((off - 4) / 4 + 1);
        char b[40];
        if (off < 0) std::snprintf(b, sizeof b, "var_%llx", (unsigned long long)(-off));
        else std::snprintf(b, sizeof b, "arg_%llx", (unsigned long long)off);
        return b;
    }

    static const char* intType(int size, bool sign) {
        switch (size) {
            case 1: return sign ? "int8_t" : "uint8_t";
            case 2: return sign ? "int16_t" : "uint16_t";
            case 4: return sign ? "int32_t" : "uint32_t";
            default: return sign ? "int64_t" : "uint64_t";
        }
    }

    // -- stack slot scan ----------------------------------------------------------------------------
    void scanExpr(const ExprP& e, bool memAddr, int size = 0, bool sign = false) {
        if (!e) return;
        if (e->k == EK::Stack) {
            SlotInfo& s = slots_[int64_t(e->c)];
            if (memAddr) { s.direct = true; s.size = std::max(s.size, size); s.sign = s.sign || sign; }
            else s.addrTaken = true;
            return;
        }
        if (e->k == EK::Load) { scanExpr(e->a, true, e->size, e->sign); return; }
        scanExpr(e->a, false); scanExpr(e->b, false); scanExpr(e->cc, false);
        for (const auto& x : e->args) scanExpr(x, false);
    }
    void scanNodes(const std::vector<Node>& v) {
        for (const auto& n : v) {
            if (n.k == Node::Simple) {
                if (n.st.k == SK::Store) { scanExpr(n.st.addr, true, n.st.size, false); scanExpr(n.st.val, false); }
                else scanExpr(n.st.val, false);
            }
            scanExpr(n.e, false);
            scanNodes(n.a); scanNodes(n.b);
            for (const auto& c : n.cases) scanNodes(c.second);
        }
    }
    void scanSlots(const std::vector<Node>& body) {
        scanNodes(body);
        std::vector<int64_t> offs;
        for (auto& [o, s] : slots_) offs.push_back(o);
        for (size_t i = 0; i < offs.size(); ++i) {
            int64_t next = i + 1 < offs.size() ? offs[i + 1] : (offs[i] < 0 ? 0 : offs[i] + 64);
            extent_[offs[i]] = std::min<int64_t>(next - offs[i], 4096);
        }
    }
    bool isArraySlot(int64_t off) const {
        const SlotInfo& s = slots_.at(off);
        if (!s.addrTaken) return false;
        int64_t ex = extent_.at(off);
        return ex > 8 || !s.direct;
    }

    void collectRegsExpr(const ExprP& e, std::set<int>& regs) {
        visit(e, [&](const ExprP& n) { if (n->k == EK::Reg && n->reg < 64 + kTempBase) regs.insert(n->reg); });
    }
    void collectRegs(const std::vector<Node>& v, std::set<int>& regs) {
        for (const auto& n : v) {
            if (n.k == Node::Simple && n.st.k == SK::Assign) regs.insert(n.st.dst);
            if (n.k == Node::Simple) { collectRegsExpr(n.st.val, regs); collectRegsExpr(n.st.addr, regs); }
            collectRegsExpr(n.e, regs);
            collectRegs(n.a, regs); collectRegs(n.b, regs);
            for (const auto& c : n.cases) collectRegs(c.second, regs);
        }
    }

    // -- expressions --------------------------------------------------------------------------------
    static int bitsOf(const ExprP& e) {
        switch (e->k) {
            case EK::Reg: return e->bits;
            case EK::Cast: return e->bits;
            case EK::Load: return e->size * 8;
            case EK::Bin: return std::max(bitsOf(e->a), bitsOf(e->b));
            case EK::Un: return bitsOf(e->a);
            default: return 64;
        }
    }

    static int prec(const ExprP& e) {
        if (e->k == EK::Bin) {
            switch (e->bop) {
                case BinOp::LOr: return 1; case BinOp::LAnd: return 2; case BinOp::Or: return 3;
                case BinOp::Xor: return 4; case BinOp::And: return 5;
                case BinOp::Eq: case BinOp::Ne: return 6;
                case BinOp::SLt: case BinOp::SLe: case BinOp::SGt: case BinOp::SGe:
                case BinOp::ULt: case BinOp::ULe: case BinOp::UGt: case BinOp::UGe: return 7;
                case BinOp::Shl: case BinOp::LShr: case BinOp::AShr: return 8;
                case BinOp::Add: case BinOp::Sub: return 9;
                case BinOp::Ror: return 12;
                default: return 10;
            }
        }
        if (e->k == EK::Cond) return 0;
        if (e->k == EK::Un || e->k == EK::Cast) return 11;
        return 13;
    }

    static std::string num(uint64_t v) {
        int64_t sv = int64_t(v);
        char b[40];
        if (sv < 0 && sv > -0x10000) { std::snprintf(b, sizeof b, "-%lld", (long long)(-sv)); return b; }
        if (v < 10) { std::snprintf(b, sizeof b, "%llu", (unsigned long long)v); return b; }
        std::snprintf(b, sizeof b, "0x%llx", (unsigned long long)v);
        return b;
    }

    void addParts(std::vector<CPart>& out, const std::vector<CPart>& in) { out.insert(out.end(), in.begin(), in.end()); }

    std::vector<CPart> E(const ExprP& e, int minPrec = 0) {
        std::vector<CPart> r;
        int p = prec(e);
        bool paren = p < minPrec;
        if (paren) r.push_back(part("("));
        switch (e->k) {
            case EK::Const: {
                uint64_t c = e->c;
                if (c >= 0x1000 && S.img.isMapped(c)) {
                    auto st = S.an.strings.find(c);
                    if (st != S.an.strings.end()) { r.push_back(ref((st->second.wide ? "L\"" : "\"") + escapeText(st->second.text, 80) + "\"", c, Cls::String)); break; }
                    if (S.an.names.count(c) || S.an.funcs.count(c)) { r.push_back(ref(dispName(c), c)); break; }
                    r.push_back(ref(num(c), c, Cls::Number));
                    break;
                }
                r.push_back(part(num(c), Cls::Number));
                break;
            }
            case EK::Str: case EK::Sym: r.push_back(ref(dispName(e->c), e->c)); break;
            case EK::Reg: r.push_back(part(regVar(e->reg), Cls::Var)); break;
            case EK::Stack: {
                int64_t off = int64_t(e->c);
                auto it = slots_.find(off);
                bool arr = it != slots_.end() && isArraySlot(off);
                if (!arr) r.push_back(part("&"));
                r.push_back(part(slotName(off), Cls::Var));
                break;
            }
            case EK::Un: {
                const char* op = e->uop == UnOp::Neg ? "-" : e->uop == UnOp::Not ? "~" : "!";
                r.push_back(part(op));
                addParts(r, E(e->a, 11));
                break;
            }
            case EK::Cast: {
                std::string t = intType(e->bits / 8, e->sign);
                r.push_back(part("(", Cls::Plain)); r.push_back(part(t, Cls::Type)); r.push_back(part(")"));
                addParts(r, E(e->a, 11));
                break;
            }
            case EK::Load: {
                if (e->a->k == EK::Stack && slots_.count(int64_t(e->a->c)) && !isArraySlot(int64_t(e->a->c))) {
                    r.push_back(part(slotName(int64_t(e->a->c)), Cls::Var));
                    break;
                }
                if (e->a->k == EK::Const && S.img.isMapped(e->a->c) && !S.img.isCode(e->a->c)) {
                    r.push_back(ref(dispName(e->a->c), e->a->c));
                    break;
                }
                r.push_back(part("*(")); r.push_back(part(intType(e->size, e->sign), Cls::Type)); r.push_back(part(" *)"));
                addParts(r, E(e->a, 11));
                break;
            }
            case EK::Cond: {
                addParts(r, E(e->a, 1));
                r.push_back(part(" ? "));
                addParts(r, E(e->b, 1));
                r.push_back(part(" : "));
                addParts(r, E(e->cc, 0));
                break;
            }
            case EK::Call: {
                // objc_msgSend(obj, selref, a, b) -> [obj sel:a part:b]
                if (e->directCall && e->args.size() >= 2 && stripUnderscores(S.label(e->c)).rfind("objc_msgSend", 0) == 0) {
                    const ExprP& sa = e->args[1];
                    if (sa->k == EK::Load && sa->a->k == EK::Const) {
                        auto nm = S.an.names.find(sa->a->c);
                        if (nm != S.an.names.end() && nm->second.name.rfind("selref_", 0) == 0) {
                            std::string sel = nm->second.name.substr(7);
                            r.push_back(part("["));
                            addParts(r, E(e->args[0], 11));
                            size_t ai = 2, pos = 0;
                            if (sel.find(':') == std::string::npos) {
                                r.push_back(part(" ")); r.push_back(part(sel, Cls::Name));
                            }
                            while ((pos = sel.find(':')) != std::string::npos) {
                                r.push_back(part(" ")); r.push_back(part(sel.substr(0, pos + 1), Cls::Name));
                                sel = sel.substr(pos + 1);
                                if (ai < e->args.size()) addParts(r, E(e->args[ai++], 1));
                            }
                            r.push_back(part("]"));
                            break;
                        }
                    }
                }
                if (e->directCall) r.push_back(ref(dispName(e->c), e->c));
                else if (e->a && e->a->k == EK::Raw) r.push_back(part(e->a->text, Cls::Name));
                else { r.push_back(part("(*")); addParts(r, E(e->a, 11)); r.push_back(part(")")); }
                r.push_back(part("("));
                for (size_t i = 0; i < e->args.size(); ++i) {
                    if (i) r.push_back(part(", "));
                    addParts(r, E(e->args[i], 1));
                }
                r.push_back(part(")"));
                break;
            }
            case EK::Flags: r.push_back(part("flags")); break;
            case EK::Raw: r.push_back(part(e->text, Cls::Comment)); break;
            case EK::Def: r.push_back(part("?def")); break;
            case EK::Bin: {
                if (e->bop == BinOp::Ror) {
                    r.push_back(part("__ror(")); addParts(r, E(e->a, 1)); r.push_back(part(", ")); addParts(r, E(e->b, 1)); r.push_back(part(")"));
                    break;
                }
                const char* op = "?";
                bool uns = false;
                switch (e->bop) {
                    case BinOp::Add: op = "+"; break; case BinOp::Sub: op = "-"; break; case BinOp::Mul: op = "*"; break;
                    case BinOp::SDiv: op = "/"; break; case BinOp::UDiv: op = "/"; uns = true; break;
                    case BinOp::SRem: op = "%"; break; case BinOp::URem: op = "%"; uns = true; break;
                    case BinOp::And: op = "&"; break; case BinOp::Or: op = "|"; break; case BinOp::Xor: op = "^"; break;
                    case BinOp::Shl: op = "<<"; break; case BinOp::LShr: op = ">>"; uns = true; break; case BinOp::AShr: op = ">>"; break;
                    case BinOp::Eq: op = "=="; break; case BinOp::Ne: op = "!="; break;
                    case BinOp::SLt: op = "<"; break; case BinOp::SLe: op = "<="; break; case BinOp::SGt: op = ">"; break; case BinOp::SGe: op = ">="; break;
                    case BinOp::ULt: op = "<"; uns = true; break; case BinOp::ULe: op = "<="; uns = true; break;
                    case BinOp::UGt: op = ">"; uns = true; break; case BinOp::UGe: op = ">="; uns = true; break;
                    case BinOp::LAnd: op = "&&"; break; case BinOp::LOr: op = "||"; break;
                    default: break;
                }
                // x + (-c) prints as x - c
                if (e->bop == BinOp::Add && e->b->k == EK::Const && int64_t(e->b->c) < 0 && int64_t(e->b->c) > -0x100000) {
                    addParts(r, E(e->a, 9));
                    r.push_back(part(" - "));
                    r.push_back(part(num(uint64_t(-int64_t(e->b->c))), Cls::Number));
                    break;
                }
                auto operand = [&](const ExprP& x, int mp) {
                    if (uns && x->k != EK::Const) {
                        r.push_back(part("(")); r.push_back(part(bitsOf(e->a) <= 32 ? "uint32_t" : "uint64_t", Cls::Type)); r.push_back(part(")"));
                        addParts(r, E(x, 11));
                    } else addParts(r, E(x, mp));
                };
                operand(e->a, p);
                r.push_back(part(std::string(" ") + op + " "));
                if (uns && (e->bop == BinOp::LShr)) addParts(r, E(e->b, p + 1));
                else operand(e->b, p + 1);
                break;
            }
        }
        if (paren) r.push_back(part(")"));
        return r;
    }

    // -- statements ----------------------------------------------------------------------------------
    std::vector<CPart> stmtParts(const Stmt& s) {
        std::vector<CPart> r;
        switch (s.k) {
            case SK::Assign:
                r.push_back(part(regVar(s.dst), Cls::Var)); r.push_back(part(" = ")); addParts(r, E(s.val, 0)); r.push_back(part(";"));
                break;
            case SK::Store: {
                if (s.addr->k == EK::Stack && slots_.count(int64_t(s.addr->c)) && !isArraySlot(int64_t(s.addr->c))) {
                    r.push_back(part(slotName(int64_t(s.addr->c)), Cls::Var));
                } else if (s.addr->k == EK::Const && S.img.isMapped(s.addr->c) && !S.img.isCode(s.addr->c)) {
                    r.push_back(ref(dispName(s.addr->c), s.addr->c));
                } else {
                    r.push_back(part("*(")); r.push_back(part(intType(s.size, false), Cls::Type)); r.push_back(part(" *)"));
                    addParts(r, E(s.addr, 11));
                }
                r.push_back(part(" = ")); addParts(r, E(s.val, 0)); r.push_back(part(";"));
                break;
            }
            case SK::Call: addParts(r, E(s.val, 0)); r.push_back(part(";")); break;
            case SK::Raw: {
                if (s.val) { addParts(r, E(s.val, 0)); r.push_back(part(";")); }
                else if (s.text == "__builtin_trap()") r.push_back(part("__builtin_trap();", Cls::Name));
                else r.push_back(part("/* " + s.text + " */", Cls::Comment));
                break;
            }
            default: break;
        }
        return r;
    }

    void header() {
        CLine& l = line(0);
        std::string rt = !M.returnsValue ? "void" : (M.retBits == 32 ? "int" : "int64_t");
        l.parts.push_back(part(rt, Cls::Type));
        l.parts.push_back(part(" "));
        l.parts.push_back(ref(dispName(M.start), M.start));
        l.parts.push_back(part("("));
        for (int i = 0; i < M.nparams && i < int(L.argRegs().size()) && M.stackParams == 0; ++i) {
            int r = L.argRegs()[size_t(i)];
            auto it = M.reg32.find(r);
            bool w = it != M.reg32.end() && it->second;
            if (i) l.parts.push_back(part(", "));
            (void)w;
            std::string ty = varType(r);
            l.parts.push_back(part(ty, Cls::Type));
            if (ty.back() != '*') l.parts.push_back(part(" "));
            l.parts.push_back(part(regVar(r), Cls::Var));
        }
        if (M.stackParams > 0) {
            for (int i = 0; i < M.stackParams; ++i) {
                if (i) l.parts.push_back(part(", "));
                l.parts.push_back(part("int", Cls::Type)); l.parts.push_back(part(" "));
                l.parts.push_back(part("a" + std::to_string(i + 1), Cls::Var));
            }
        } else if (M.nparams == 0) l.parts.push_back(part("void", Cls::Type));
        l.parts.push_back(part(")"));
        line(0).parts.push_back(part("{"));
    }

    void decls(const std::set<int>& regs) {
        std::vector<int> vars;
        for (int r : regs) {
            if (r == kFlagsReg || paramRegs_.count(r)) continue;
            vars.push_back(r);
        }
        std::sort(vars.begin(), vars.end(), [&](int x, int y) {
            auto nx = names_.find(x), ny = names_.find(y);
            int ax = nx == names_.end() ? 1 << 20 : std::atoi(nx->second.c_str() + 1);
            int ay = ny == names_.end() ? 1 << 20 : std::atoi(ny->second.c_str() + 1);
            return ax != ay ? ax < ay : x < y;
        });
        for (const char* ty : {"int", "int64_t", "void *"}) {
            std::vector<int> v;
            for (int r : vars) if (std::strcmp(varType(r), ty) == 0) v.push_back(r);
            if (v.empty()) continue;
            CLine& l = line(1);
            l.parts.push_back(part(ty, Cls::Type));
            if (ty[std::strlen(ty) - 1] != '*') l.parts.push_back(part(" "));
            for (size_t i = 0; i < v.size(); ++i) {
                if (i) l.parts.push_back(part(", "));
                if (ty[std::strlen(ty) - 1] == '*' && i) l.parts.push_back(part("*"));
                l.parts.push_back(part(regVar(v[i]), Cls::Var));
            }
            l.parts.push_back(part(";"));
        }
        bool any = false;
        for (auto& [off, s] : slots_) {
            if (M.stackParams > 0 && off >= 4 && off < 4 + 4 * M.stackParams) continue;
            CLine& l = line(1);
            any = true;
            if (isArraySlot(off)) {
                l.parts.push_back(part("char", Cls::Type)); l.parts.push_back(part(" "));
                l.parts.push_back(part(slotName(off), Cls::Var));
                l.parts.push_back(part("[" + std::to_string(extent_[off]) + "];"));
            } else {
                l.parts.push_back(part(intType(s.size ? s.size : 8, s.sign), Cls::Type)); l.parts.push_back(part(" "));
                l.parts.push_back(part(slotName(off), Cls::Var)); l.parts.push_back(part(";"));
            }
            if (off >= 0) l.parts.push_back(part("  // stack argument", Cls::Comment));
        }
        if (!regs.empty() || any) line(1);   // blank separator
    }

    void kw(CLine& l, const std::string& s) { l.parts.push_back(part(s, Cls::Keyword)); }

    void nodes(const std::vector<Node>& v, int ind) {
        for (size_t i = 0; i < v.size(); ++i) node(v[i], ind, i + 1 < v.size() ? &v[i + 1] : nullptr);
    }

    void block(const std::vector<Node>& v, int ind) {
        nodes(v, ind);
    }

    void node(const Node& n, int ind, const Node*) {
        switch (n.k) {
            case Node::Simple: {
                auto p = stmtParts(n.st);
                if (p.empty()) return;
                CLine& l = line(ind);
                addParts(l.parts, p);
                break;
            }
            case Node::Label: {
                CLine& l = line(std::max(0, ind - 1));
                l.parts.push_back(part("L_" + hexPlain(n.addr) + ":", Cls::Name));
                break;
            }
            case Node::Goto: { CLine& l = line(ind); kw(l, "goto"); l.parts.push_back(part(" L_" + hexPlain(n.addr) + ";", Cls::Name)); break; }
            case Node::Break: { CLine& l = line(ind); kw(l, "break"); l.parts.push_back(part(";")); break; }
            case Node::Continue: { CLine& l = line(ind); kw(l, "continue"); l.parts.push_back(part(";")); break; }
            case Node::Return: {
                CLine& l = line(ind);
                kw(l, "return");
                if (n.e) { l.parts.push_back(part(" ")); addParts(l.parts, E(n.e, 0)); }
                l.parts.push_back(part(";"));
                break;
            }
            case Node::If: {
                { CLine& l = line(ind); kw(l, "if"); l.parts.push_back(part(" (")); addParts(l.parts, E(n.e, 0)); l.parts.push_back(part(") {")); }
                block(n.a, ind + 1);
                if (!n.b.empty()) {
                    if (n.b.size() == 1 && n.b[0].k == Node::If) {
                        // else if chain
                        { CLine& l = line(ind); l.parts.push_back(part("} ")); kw(l, "else"); l.parts.push_back(part(" ")); kw(l, "if"); l.parts.push_back(part(" (")); addParts(l.parts, E(n.b[0].e, 0)); l.parts.push_back(part(") {")); }
                        elseChain(n.b[0], ind);
                        return;
                    }
                    { CLine& l = line(ind); l.parts.push_back(part("} ")); kw(l, "else"); l.parts.push_back(part(" {")); }
                    block(n.b, ind + 1);
                }
                line(ind).parts.push_back(part("}"));
                break;
            }
            case Node::While: {
                { CLine& l = line(ind); kw(l, "while"); l.parts.push_back(part(" (")); if (n.e) addParts(l.parts, E(n.e, 0)); else l.parts.push_back(part("1", Cls::Number)); l.parts.push_back(part(") {")); }
                block(n.a, ind + 1);
                line(ind).parts.push_back(part("}"));
                break;
            }
            case Node::DoWhile: {
                { CLine& l = line(ind); kw(l, "do"); l.parts.push_back(part(" {")); }
                block(n.a, ind + 1);
                { CLine& l = line(ind); l.parts.push_back(part("} ")); kw(l, "while"); l.parts.push_back(part(" (")); addParts(l.parts, E(n.e, 0)); l.parts.push_back(part(");")); }
                break;
            }
            case Node::Switch: {
                { CLine& l = line(ind); kw(l, "switch"); l.parts.push_back(part(" (")); if (n.e) addParts(l.parts, E(n.e, 0)); l.parts.push_back(part(") {")); }
                for (const auto& c : n.cases) {
                    for (int64_t v : c.first) {
                        CLine& l = line(ind);
                        kw(l, "case"); l.parts.push_back(part(" "));
                        char nb[40];
                        if (v >= 0 && v < 10) std::snprintf(nb, sizeof nb, "%lld", (long long)v);
                        else if (v < 0) std::snprintf(nb, sizeof nb, "-%lld", (long long)-v);
                        else std::snprintf(nb, sizeof nb, "0x%llx", (unsigned long long)v);
                        l.parts.push_back(part(nb, Cls::Number));
                        l.parts.push_back(part(":"));
                        if (v >= 0x20 && v < 0x7f) {
                            std::string ch = std::string("  /* '") + char(v) + "' */";
                            l.parts.push_back(part(ch, Cls::Comment));
                        }
                    }
                    block(c.second, ind + 1);
                }
                line(ind).parts.push_back(part("}"));
                break;
            }
        }
    }

    void elseChain(const Node& n, int ind) {
        block(n.a, ind + 1);
        if (!n.b.empty()) {
            if (n.b.size() == 1 && n.b[0].k == Node::If) {
                { CLine& l = line(ind); l.parts.push_back(part("} ")); kw(l, "else"); l.parts.push_back(part(" ")); kw(l, "if"); l.parts.push_back(part(" (")); addParts(l.parts, E(n.b[0].e, 0)); l.parts.push_back(part(") {")); }
                elseChain(n.b[0], ind);
                return;
            }
            { CLine& l = line(ind); l.parts.push_back(part("} ")); kw(l, "else"); l.parts.push_back(part(" {")); }
            block(n.b, ind + 1);
        }
        line(ind).parts.push_back(part("}"));
    }
};

}  // namespace

DecompResult decompile(Session& s, uint64_t funcStart) {
    DecompResult res;
    auto L = Lifter::create(s.img.arch, s.img.bits, s.img.format == "PE");
    if (!L) { res.error = "decompiler does not support this architecture yet"; return res; }
    const Func* f = s.funcAt(funcStart);
    if (!f) { res.error = "not inside a function"; return res; }
    FuncModel m;
    std::string err;
    if (!buildModel(s, *L, f->start, m, err)) { res.error = err; return res; }

    Structurer st(m);
    std::set<uint64_t> chk;
    for (const auto& [a, n] : s.an.names)
        if (n.name.find("stack_chk_fail") != std::string::npos) chk.insert(a);
    st.setStackChk(chk);
    std::vector<Node> body = st.run();

    Printer p(s, *L, m);
    res.lines = p.print(body);
    res.ok = true;
    return res;
}

std::string toText(const DecompResult& r) {
    std::string out;
    if (!r.ok) return "// " + r.error + "\n";
    for (const auto& l : r.lines) {
        out += std::string(size_t(l.indent) * 4, ' ');
        for (const auto& p : l.parts) out += p.text;
        out += "\n";
    }
    return out;
}

}  // namespace er::dc
