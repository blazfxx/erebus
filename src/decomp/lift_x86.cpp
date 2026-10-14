// x86 / x86-64 -> IR. Register ids: rax0 rcx1 rdx2 rbx3 rsp4 rbp5 rsi6 rdi7 r8..r15 = 8..15, flags = 32.
#include <capstone/capstone.h>

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <map>

#include "decomp/lifter.h"

namespace er::dc {
namespace {

struct RI {
    int id = -1;
    int bits = 64;
    bool high = false;    // ah/ch/dh/bh
    bool gpr = false;
    bool rip = false;
};

const std::map<std::string, RI>& regTable() {
    static std::map<std::string, RI> t;
    if (!t.empty()) return t;
    const char* r64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
    const char* r32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    const char* r16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di"};
    const char* r8[] = {"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil"};
    for (int i = 0; i < 8; ++i) {
        t[r64[i]] = {i, 64, false, true, false};
        t[r32[i]] = {i, 32, false, true, false};
        t[r16[i]] = {i, 16, false, true, false};
        t[r8[i]] = {i, 8, false, true, false};
    }
    t["ah"] = {0, 8, true, true, false}; t["ch"] = {1, 8, true, true, false};
    t["dh"] = {2, 8, true, true, false}; t["bh"] = {3, 8, true, true, false};
    for (int i = 8; i < 16; ++i) {
        std::string n = "r" + std::to_string(i);
        t[n] = {i, 64, false, true, false};
        t[n + "d"] = {i, 32, false, true, false};
        t[n + "w"] = {i, 16, false, true, false};
        t[n + "b"] = {i, 8, false, true, false};
    }
    t["rip"] = {-1, 64, false, false, true};
    t["eip"] = {-1, 32, false, false, true};
    return t;
}

class X86Lifter : public Lifter {
public:
    X86Lifter(unsigned bits, bool win) : bits_(bits) {
        cs_mode m = bits == 64 ? CS_MODE_64 : CS_MODE_32;
        if (cs_open(CS_ARCH_X86, m, &h_) == CS_ERR_OK) {
            cs_option(h_, CS_OPT_DETAIL, CS_OPT_ON);
            insn_ = cs_malloc(h_);
        }
        if (bits == 64) {
            if (win) args_ = {1, 2, 8, 9};
            else args_ = {7, 6, 2, 1, 8, 9};
            saved_ = win ? std::vector<int>{3, 5, 6, 7, 12, 13, 14, 15} : std::vector<int>{3, 5, 12, 13, 14, 15};
        } else {
            saved_ = {3, 5, 6, 7};
        }
    }
    ~X86Lifter() override {
        if (insn_) cs_free(insn_, 1);
        if (h_) cs_close(&h_);
    }

    std::string regName(int id, int bits) const override {
        static const char* n64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"};
        static const char* n32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
        if (id == kFlagsReg) return "flags";
        bool w32 = bits == 32 || bits_ == 32;
        if (id < 8) return w32 ? n32[id] : n64[id];
        return "r" + std::to_string(id) + (w32 && bits_ == 64 ? "d" : "");
    }
    int spReg() const override { return 4; }
    int fpReg() const override { return 5; }
    int retReg() const override { return 0; }
    const std::vector<int>& argRegs() const override { return args_; }
    const std::vector<int>& calleeSaved() const override { return saved_; }

    bool lift(const Image& img, uint64_t addr, std::vector<Stmt>& out, uint32_t& size) override {
        if (!h_) return false;
        uint8_t buf[16];
        size_t got = img.readSome(addr, buf, sizeof buf);
        if (!got) return false;
        const uint8_t* p = buf;
        size_t sz = got;
        uint64_t a = addr;
        if (!cs_disasm_iter(h_, &p, &sz, &a, insn_)) return false;
        size = insn_->size;
        at_ = addr;
        out_ = &out;
        doLift();
        return true;
    }

private:
    unsigned bits_;
    csh h_ = 0;
    cs_insn* insn_ = nullptr;
    uint64_t at_ = 0;
    std::vector<Stmt>* out_ = nullptr;
    std::vector<int> args_, saved_;

    int ptr() const { return int(bits_ / 8); }

    RI regInfo(x86_reg r) const {
        const auto& t = regTable();
        auto it = t.find(cs_reg_name(h_, r));
        if (it != t.end()) return it->second;
        return RI{};   // xmm/segment/etc.
    }

    // ---- statement helpers --------------------------------------------------------------
    void push(Stmt s) { s.at = at_; out_->push_back(std::move(s)); }
    void assignRaw(int dst, int bits, ExprP v) {
        Stmt s; s.k = SK::Assign; s.dst = dst; s.dstBits = bits; s.val = std::move(v);
        push(std::move(s));
    }
    void store(ExprP addr, ExprP v, int size) {
        Stmt s; s.k = SK::Store; s.addr = std::move(addr); s.val = std::move(v); s.size = size;
        push(std::move(s));
    }
    void rawStmt() {
        Stmt s; s.k = SK::Raw;
        s.text = std::string(insn_->mnemonic) + (insn_->op_str[0] ? " " : "") + insn_->op_str;
        push(std::move(s));
    }
    void setFlags(FlagKind k, ExprP a, ExprP b) { assignRaw(kFlagsReg, 64, mkFlags(k, std::move(a), std::move(b))); }
    ExprP ccExpr(int cc) const {
        Expr e;
        e.k = EK::Flags;
        e.size = cc;
        return std::make_shared<const Expr>(std::move(e));
    }

    static uint64_t maskOf(int bits) { return bits >= 64 ? ~0ull : ((1ull << bits) - 1); }

    ExprP regExpr(const RI& ri) const {
        if (ri.rip) return mkConst(at_ + insn_->size);
        if (ri.high) return mkCast(mkBin(BinOp::LShr, mkReg(ri.id, 64), mkConst(8)), 8, false);
        return mkReg(ri.id, ri.bits);
    }

    // write a register with x86 partial-register semantics
    void writeReg(const RI& ri, ExprP v) {
        if (ri.id < 0) return;
        if (ri.bits >= 32 || (bits_ == 32 && ri.bits >= 32)) { assignRaw(ri.id, ri.bits, std::move(v)); return; }
        if (ri.high) {
            ExprP old = mkReg(ri.id, 64);
            ExprP merged = mkBin(BinOp::Or, mkBin(BinOp::And, old, mkConst(~0xff00ull)),
                                 mkBin(BinOp::Shl, mkBin(BinOp::And, v, mkConst(0xff)), mkConst(8)));
            assignRaw(ri.id, 64, merged);
            return;
        }
        uint64_t m = maskOf(ri.bits);
        ExprP old = mkReg(ri.id, 64);
        ExprP merged = mkBin(BinOp::Or, mkBin(BinOp::And, old, mkConst(~m)), mkBin(BinOp::And, v, mkConst(m)));
        assignRaw(ri.id, 64, merged);
    }

    ExprP memAddr(const cs_x86_op& o) const {
        const x86_op_mem& m = o.mem;
        ExprP a;
        RI b = m.base != X86_REG_INVALID ? regInfo(m.base) : RI{};
        if (m.base != X86_REG_INVALID && b.rip) {
            return mkConst(at_ + insn_->size + uint64_t(int64_t(m.disp)));
        }
        if (m.base != X86_REG_INVALID && b.gpr) a = mkReg(b.id, 64);
        if (m.index != X86_REG_INVALID) {
            RI ix = regInfo(m.index);
            if (ix.gpr) {
                ExprP e = mkReg(ix.id, 64);
                if (m.scale > 1) e = mkBin(BinOp::Mul, e, mkConst(uint64_t(m.scale)));
                a = a ? mkBin(BinOp::Add, a, e) : e;
            }
        }
        if (m.disp || !a) {
            ExprP d = mkConst(uint64_t(int64_t(m.disp)));
            a = a ? mkBin(BinOp::Add, a, d) : d;
        }
        if (m.segment == X86_REG_FS || m.segment == X86_REG_GS) {
            ExprP seg = mkRaw(m.segment == X86_REG_FS ? "__fs_base" : "__gs_base");
            a = mkBin(BinOp::Add, seg, a);
        }
        return a;
    }

    ExprP readOp(const cs_x86_op& o, int sizeBytes = 0) const {
        switch (o.type) {
            case X86_OP_REG: return regExpr(regInfo(o.reg));
            case X86_OP_IMM: return mkConst(uint64_t(o.imm));
            case X86_OP_MEM: return mkLoad(memAddr(o), sizeBytes ? sizeBytes : o.size, false);
            default: return mkRaw("?");
        }
    }
    void writeOp(const cs_x86_op& o, ExprP v) {
        if (o.type == X86_OP_REG) {
            RI ri = regInfo(o.reg);
            if (!ri.gpr) { rawStmt(); return; }
            writeReg(ri, std::move(v));
        } else if (o.type == X86_OP_MEM) {
            store(memAddr(o), std::move(v), o.size);
        }
    }
    int opBits(const cs_x86_op& o) const { return o.size * 8; }

    static int ccOf(const std::string& m, size_t skip) {
        std::string c = m.substr(skip);
        if (c == "e" || c == "z") return 1;
        if (c == "ne" || c == "nz") return 2;
        if (c == "ae" || c == "nb" || c == "nc") return 3;
        if (c == "b" || c == "nae" || c == "c") return 4;
        if (c == "s") return 5;
        if (c == "ns") return 6;
        if (c == "o") return 7;
        if (c == "no") return 8;
        if (c == "a" || c == "nbe") return 9;
        if (c == "be" || c == "na") return 10;
        if (c == "ge" || c == "nl") return 11;
        if (c == "l" || c == "nge") return 12;
        if (c == "g" || c == "nle") return 13;
        if (c == "le" || c == "ng") return 14;
        return 0;   // parity and friends: unresolved
    }

    static bool startsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

    // ---- main ------------------------------------------------------------------------------
    void doLift() {
        const cs_x86& d = insn_->detail->x86;
        std::string m = insn_->mnemonic;
        const cs_x86_op* o = d.operands;
        const int n = d.op_count;
        const uint64_t next = at_ + insn_->size;
        const int psz = ptr();
        // strip prefixes shown in the mnemonic text (e.g. "rep movsb" is a single mnemonic in capstone ops)
        bool hasRep = d.prefix[0] == X86_PREFIX_REP || d.prefix[0] == X86_PREFIX_REPNE;

        auto sp = [&]() { return mkReg(4, 64); };

        // control flow
        if (m == "jmp") {
            if (n == 1 && o[0].type == X86_OP_IMM) { Stmt s; s.k = SK::Jmp; s.t = uint64_t(o[0].imm); push(s); }
            else { Stmt s; s.k = SK::Switch; s.index = readOp(o[0], psz); push(s); }
            return;
        }
        if (m[0] == 'j' && m != "jmp") {
            int cc = ccOf(m, 1);
            if (n == 1 && o[0].type == X86_OP_IMM) {
                if (m == "jrcxz" || m == "jecxz" || m == "jcxz") {
                    Stmt s; s.k = SK::Br; s.cond = mkBin(BinOp::Eq, mkReg(1, m == "jrcxz" ? 64 : 32), mkConst(0));
                    s.t = uint64_t(o[0].imm); s.f = next; push(s);
                    return;
                }
                Stmt s; s.k = SK::Br; s.cc = cc; s.t = uint64_t(o[0].imm); s.f = next; push(s);
                return;
            }
        }
        if (m == "call") {
            Stmt s; s.k = SK::Call;
            if (n == 1 && o[0].type == X86_OP_IMM) s.val = mkCallE(uint64_t(o[0].imm), nullptr, {});
            else s.val = mkCallE(0, readOp(o[0], psz), {});
            push(s);
            return;
        }
        if (startsWith(m, "ret") || m == "iret" || m == "iretq") { Stmt s; s.k = SK::Ret; push(s); return; }
        if (m == "ud2" || m == "hlt" || m == "int3") { Stmt s; s.k = SK::Raw; s.text = "__builtin_trap()"; push(s); return; }
        if (m == "nop" || startsWith(m, "nop") || startsWith(m, "endbr") || m == "pause" || m == "fnop" ||
            m == "data16" || startsWith(m, "prefetch") || m == "lfence" || m == "mfence" || m == "sfence" || m == "cld" || m == "std")
            return;

        // stack
        if (m == "push") {
            ExprP v = readOp(o[0], psz);
            assignRaw(4, 64, mkBin(BinOp::Sub, sp(), mkConst(uint64_t(psz))));
            store(sp(), v, psz);
            return;
        }
        if (m == "pop") {
            ExprP v = mkLoad(sp(), psz, false);
            writeOp(o[0], v);
            assignRaw(4, 64, mkBin(BinOp::Add, sp(), mkConst(uint64_t(psz))));
            return;
        }
        if (m == "leave") {
            assignRaw(4, 64, mkReg(5, 64));
            assignRaw(5, 64, mkLoad(sp(), psz, false));
            assignRaw(4, 64, mkBin(BinOp::Add, sp(), mkConst(uint64_t(psz))));
            return;
        }

        // data movement
        if ((m == "mov" || m == "movabs") && n == 2) { writeOp(o[0], readOp(o[1], opBits(o[0]) / 8)); return; }
        if (m == "lea" && n == 2) { writeOp(o[0], memAddr(o[1])); return; }
        if ((m == "movzx" || m == "movzx") && n == 2) {
            int sb = o[1].size * 8;
            writeOp(o[0], mkCast(readOp(o[1]), sb, false));
            return;
        }
        if ((m == "movsx" || m == "movsxd") && n == 2) {
            int sb = o[1].size * 8;
            writeOp(o[0], mkCast(readOp(o[1]), sb, true));
            return;
        }
        if (m == "cdqe") { assignRaw(0, 64, mkCast(mkReg(0, 32), 32, true)); return; }
        if (m == "cwde") { assignRaw(0, 32, mkCast(mkReg(0, 16), 16, true)); return; }
        if (m == "cbw") { writeReg(RI{0, 16, false, true, false}, mkCast(mkReg(0, 8), 8, true)); return; }
        if (m == "cdq") { assignRaw(2, 32, mkBin(BinOp::AShr, mkCast(mkReg(0, 32), 32, true), mkConst(31))); return; }
        if (m == "cqo") { assignRaw(2, 64, mkBin(BinOp::AShr, mkReg(0, 64), mkConst(63))); return; }
        if (m == "xchg" && n == 2 && o[0].type == X86_OP_REG && o[1].type == X86_OP_REG) {
            ExprP a = readOp(o[0]), b = readOp(o[1]);
            writeOp(o[0], b);
            writeOp(o[1], a);   // note: second write reads a (captured before the first write)
            return;
        }
        if (startsWith(m, "cmov") && n == 2) {
            int cc = ccOf(m, 4);
            writeOp(o[0], mkCond(ccExpr(cc), readOp(o[1], opBits(o[0]) / 8), readOp(o[0])));
            return;
        }
        if (startsWith(m, "set") && n == 1) {
            int cc = ccOf(m, 3);
            writeOp(o[0], mkCond(ccExpr(cc), mkConst(1), mkConst(0)));
            return;
        }

        // arithmetic / logic
        if (n == 2 && (m == "add" || m == "sub" || m == "and" || m == "or" || m == "xor")) {
            // xor r, r -> zero idiom
            if (m == "xor" && o[0].type == X86_OP_REG && o[1].type == X86_OP_REG && o[0].reg == o[1].reg) {
                writeOp(o[0], mkConst(0));
                setFlags(FlagKind::And, mkConst(0), mkConst(0));
                return;
            }
            ExprP a = readOp(o[0]), b = readOp(o[1], opBits(o[0]) / 8);
            BinOp op = m == "add" ? BinOp::Add : m == "sub" ? BinOp::Sub : m == "and" ? BinOp::And : m == "or" ? BinOp::Or : BinOp::Xor;
            ExprP r = mkBin(op, a, b);
            writeOp(o[0], r);
            if (m == "add") setFlags(FlagKind::Add, a, b);
            else if (m == "sub") setFlags(FlagKind::Sub, a, b);
            else setFlags(FlagKind::And, r, r);
            return;
        }
        if (n == 2 && (m == "cmp" || m == "test")) {
            ExprP a = readOp(o[0]), b = readOp(o[1], opBits(o[0]) / 8);
            setFlags(m == "cmp" ? FlagKind::Sub : FlagKind::And, a, b);
            return;
        }
        if (n == 1 && (m == "inc" || m == "dec")) {
            ExprP a = readOp(o[0]);
            writeOp(o[0], mkBin(m == "inc" ? BinOp::Add : BinOp::Sub, a, mkConst(1)));
            setFlags(m == "inc" ? FlagKind::Add : FlagKind::Sub, a, mkConst(1));
            return;
        }
        if (n == 1 && m == "neg") {
            ExprP a = readOp(o[0]);
            writeOp(o[0], mkUn(UnOp::Neg, a));
            setFlags(FlagKind::Sub, mkConst(0), a);
            return;
        }
        if (n == 1 && m == "not") { writeOp(o[0], mkUn(UnOp::Not, readOp(o[0]))); return; }
        if ((m == "shl" || m == "sal" || m == "shr" || m == "sar" || m == "rol" || m == "ror") && n >= 1) {
            ExprP a = readOp(o[0]);
            ExprP cnt = n >= 2 ? readOp(o[1]) : mkConst(1);
            BinOp op = (m == "shl" || m == "sal") ? BinOp::Shl : m == "shr" ? BinOp::LShr : m == "sar" ? BinOp::AShr : BinOp::Ror;
            if (m == "rol") { rawStmt(); return; }
            ExprP r = mkBin(op, a, cnt);
            writeOp(o[0], r);
            setFlags(FlagKind::And, r, r);
            return;
        }
        if (m == "imul") {
            if (n == 2) {
                ExprP r = mkBin(BinOp::Mul, readOp(o[0]), readOp(o[1], opBits(o[0]) / 8));
                writeOp(o[0], r);
                return;
            }
            if (n == 3) {
                ExprP r = mkBin(BinOp::Mul, readOp(o[1]), readOp(o[2], opBits(o[0]) / 8));
                writeOp(o[0], r);
                return;
            }
        }
        if ((m == "mul" || m == "imul" || m == "div" || m == "idiv") && n == 1) {
            int bw = opBits(o[0]);
            if (bw >= 32) {
                int ab = bw;
                ExprP src = readOp(o[0]);
                ExprP rax = mkReg(0, ab);
                if (m == "div" || m == "idiv") {
                    bool sg = m == "idiv";
                    assignRaw(2, ab, mkBin(sg ? BinOp::SRem : BinOp::URem, rax, src));
                    assignRaw(0, ab, mkBin(sg ? BinOp::SDiv : BinOp::UDiv, rax, src));
                } else {
                    assignRaw(2, ab, mkCallE(0, mkRaw(m == "mul" ? "__mulhi_u" : "__mulhi_s"), {rax, src}));
                    assignRaw(0, ab, mkBin(BinOp::Mul, rax, src));
                }
                return;
            }
        }
        if ((m == "adc" || m == "sbb") && n == 2) { rawAssignFirst(); return; }
        if (m == "bswap" && n == 1) { writeOp(o[0], mkCallE(0, mkRaw("__builtin_bswap"), {readOp(o[0])})); return; }
        if (hasRep || startsWith(m, "movs") || startsWith(m, "stos") || startsWith(m, "cmps") || startsWith(m, "scas") || startsWith(m, "lods")) {
            if (n == 0 || o[0].type == X86_OP_MEM) { rawStmt(); return; }
        }
        if (m == "syscall" || m == "sysenter" || m == "cpuid" || m == "rdtsc") { rawStmt(); return; }

        rawAssignFirst();
    }

    // unhandled instruction: if it writes a GPR, keep dataflow honest with an opaque assignment
    void rawAssignFirst() {
        const cs_x86& d = insn_->detail->x86;
        if (d.op_count >= 1 && d.operands[0].type == X86_OP_REG && (d.operands[0].access & CS_AC_WRITE)) {
            RI ri = regInfo(d.operands[0].reg);
            if (ri.gpr) {
                std::string t = std::string(insn_->mnemonic) + " " + insn_->op_str;
                writeReg(ri, mkRaw("/* " + t + " */"));
                return;
            }
        }
        rawStmt();
    }
};

}  // namespace

std::unique_ptr<Lifter> makeX86Lifter(unsigned bits, bool win) { return std::make_unique<X86Lifter>(bits, win); }

}  // namespace er::dc
