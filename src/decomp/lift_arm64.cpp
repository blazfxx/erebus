// arm64 -> IR. Register ids: x0..x30 = 0..30, sp = 31, flags = 32.
#include <capstone/capstone.h>

#include <cctype>
#include <cstdlib>
#include <cstring>

#include "decomp/lifter.h"

namespace er::dc {
namespace {

class Arm64Lifter : public Lifter {
public:
    Arm64Lifter() {
        if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &h_) == CS_ERR_OK) {
            cs_option(h_, CS_OPT_DETAIL, CS_OPT_ON);
            insn_ = cs_malloc(h_);
        }
        for (int i = 0; i < 8; ++i) args_.push_back(i);
        for (int i = 19; i <= 30; ++i) saved_.push_back(i);
    }
    ~Arm64Lifter() override {
        if (insn_) cs_free(insn_, 1);
        if (h_) cs_close(&h_);
    }

    std::string regName(int id, int bits) const override {
        if (id == 31) return "sp";
        if (id == kFlagsReg) return "flags";
        return std::string(bits == 32 ? "w" : "x") + std::to_string(id);
    }
    int spReg() const override { return 31; }
    int fpReg() const override { return 29; }
    int retReg() const override { return 0; }
    const std::vector<int>& argRegs() const override { return args_; }
    const std::vector<int>& calleeSaved() const override { return saved_; }

    bool lift(const Image& img, uint64_t addr, std::vector<Stmt>& out, uint32_t& size) override {
        if (!h_) return false;
        uint8_t buf[4];
        if (img.readSome(addr, buf, 4) < 4) return false;
        const uint8_t* p = buf;
        size_t sz = 4;
        uint64_t a = addr;
        if (!cs_disasm_iter(h_, &p, &sz, &a, insn_)) return false;
        size = insn_->size;
        at_ = addr;
        out_ = &out;
        doLift();
        return true;
    }

private:
    csh h_ = 0;
    cs_insn* insn_ = nullptr;
    uint64_t at_ = 0;
    std::vector<Stmt>* out_ = nullptr;
    std::vector<int> args_, saved_;

    // ---- helpers ------------------------------------------------------------------
    struct RI { int id = -1; int bits = 64; bool zero = false; bool fp = false; };

    RI regInfo(arm64_reg r) const {
        RI ri;
        std::string n = cs_reg_name(h_, r);
        if (n == "xzr") { ri.zero = true; return ri; }
        if (n == "wzr") { ri.zero = true; ri.bits = 32; return ri; }
        if (n == "sp") { ri.id = 31; return ri; }
        if (n == "wsp") { ri.id = 31; ri.bits = 32; return ri; }
        if (n == "fp") { ri.id = 29; return ri; }
        if (n == "lr") { ri.id = 30; return ri; }
        if ((n[0] == 'x' || n[0] == 'w') && n.size() > 1 && std::isdigit((unsigned char)n[1])) {
            ri.id = std::atoi(n.c_str() + 1);
            ri.bits = n[0] == 'w' ? 32 : 64;
            return ri;
        }
        ri.fp = true;   // s/d/q/v/b/h simd-fp registers
        return ri;
    }

    ExprP readReg(arm64_reg r) const {
        RI ri = regInfo(r);
        if (ri.zero) return mkConst(0, ri.bits);
        if (ri.fp) return mkRaw(cs_reg_name(h_, r));
        return mkReg(ri.id, ri.bits);
    }

    ExprP applyShiftExt(ExprP e, const cs_arm64_op& o) const {
        switch (o.ext) {
            case ARM64_EXT_UXTB: e = mkCast(e, 8, false); break;
            case ARM64_EXT_UXTH: e = mkCast(e, 16, false); break;
            case ARM64_EXT_UXTW: e = mkCast(e, 32, false); break;
            case ARM64_EXT_SXTB: e = mkCast(e, 8, true); break;
            case ARM64_EXT_SXTH: e = mkCast(e, 16, true); break;
            case ARM64_EXT_SXTW: e = mkCast(e, 32, true); break;
            default: break;
        }
        if (o.shift.value) {
            uint64_t v = o.shift.value;
            switch (o.shift.type) {
                case ARM64_SFT_LSL: case ARM64_SFT_MSL: e = mkBin(BinOp::Shl, e, mkConst(v)); break;
                case ARM64_SFT_LSR: e = mkBin(BinOp::LShr, e, mkConst(v)); break;
                case ARM64_SFT_ASR: e = mkBin(BinOp::AShr, e, mkConst(v)); break;
                case ARM64_SFT_ROR: e = mkBin(BinOp::Ror, e, mkConst(v)); break;
                default: break;
            }
        }
        return e;
    }

    ExprP opVal(const cs_arm64_op& o) const {
        if (o.type == ARM64_OP_REG) return applyShiftExt(readReg(o.reg), o);
        if (o.type == ARM64_OP_IMM) {
            ExprP c = mkConst(uint64_t(o.imm));
            return o.shift.value ? applyShiftExt(c, o) : c;
        }
        return mkRaw("?");
    }

    ExprP memAddr(const cs_arm64_op& o) const {
        ExprP a = readReg(o.mem.base);
        if (o.mem.index != ARM64_REG_INVALID) {
            ExprP ix = readReg(o.mem.index);
            cs_arm64_op tmp = o;
            ix = applyShiftExt(ix, tmp);
            a = mkBin(BinOp::Add, a, ix);
        }
        if (o.mem.disp) a = mkBin(BinOp::Add, a, mkConst(uint64_t(int64_t(o.mem.disp))));
        return a;
    }

    void push(Stmt s) { s.at = at_; out_->push_back(std::move(s)); }

    void assign(int dst, int bits, ExprP v) {
        Stmt s; s.k = SK::Assign; s.dst = dst; s.dstBits = bits; s.val = std::move(v);
        push(std::move(s));
    }
    void assignOp(const cs_arm64_op& d, ExprP v) {
        RI ri = regInfo(d.reg);
        if (ri.zero) return;
        if (ri.fp) { raw(); return; }
        assign(ri.id, ri.bits, std::move(v));
    }
    void setFlags(FlagKind k, ExprP a, ExprP b) { assign(kFlagsReg, 64, mkFlags(k, std::move(a), std::move(b))); }
    void store(ExprP addr, ExprP v, int size) {
        Stmt s; s.k = SK::Store; s.addr = std::move(addr); s.val = std::move(v); s.size = size;
        push(std::move(s));
    }
    void raw() {
        Stmt s; s.k = SK::Raw;
        s.text = std::string(insn_->mnemonic) + (insn_->op_str[0] ? " " : "") + insn_->op_str;
        push(std::move(s));
    }
    ExprP ccExpr(int cc) const {
        Expr e;   // Flags with null operands = "condition cc over the current flags"
        e.k = EK::Flags;
        e.size = cc;
        return std::make_shared<const Expr>(std::move(e));
    }

    static bool startsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }

    // ---- main -------------------------------------------------------------------------
    void doLift() {
        const cs_arm64& d = insn_->detail->arm64;
        const std::string m = insn_->mnemonic;
        const cs_arm64_op* o = d.operands;
        const int n = d.op_count;
        auto isReg = [&](int i) { return i < n && o[i].type == ARM64_OP_REG; };
        auto val = [&](int i) { return opVal(o[i]); };
        const uint64_t next = at_ + insn_->size;

        // -- control flow --
        if (m == "b") { Stmt s; s.k = SK::Jmp; s.t = uint64_t(o[0].imm); push(s); return; }
        if (startsWith(m, "b.") || startsWith(m, "bc.")) {
            Stmt s; s.k = SK::Br; s.cc = d.cc; s.t = uint64_t(o[n - 1].imm); s.f = next; push(s); return;
        }
        if (m == "cbz" || m == "cbnz") {
            Stmt s; s.k = SK::Br;
            s.cond = mkBin(m == "cbz" ? BinOp::Eq : BinOp::Ne, val(0), mkConst(0));
            s.t = uint64_t(o[1].imm); s.f = next; push(s); return;
        }
        if (m == "tbz" || m == "tbnz") {
            Stmt s; s.k = SK::Br;
            ExprP bit = mkBin(BinOp::And, val(0), mkConst(1ull << (o[1].imm & 63)));
            s.cond = mkBin(m == "tbz" ? BinOp::Eq : BinOp::Ne, bit, mkConst(0));
            s.t = uint64_t(o[2].imm); s.f = next; push(s); return;
        }
        if (m == "bl") { Stmt s; s.k = SK::Call; s.val = mkCallE(uint64_t(o[0].imm), nullptr, {}); push(s); return; }
        if (startsWith(m, "blr")) { Stmt s; s.k = SK::Call; s.val = mkCallE(0, readReg(o[0].reg), {}); push(s); return; }
        if (m == "br" || startsWith(m, "bra")) {
            Stmt s; s.k = SK::Switch; s.index = readReg(o[0].reg); push(s); return;
        }
        if (startsWith(m, "ret") || startsWith(m, "eret")) { Stmt s; s.k = SK::Ret; push(s); return; }
        if (m == "nop" || m == "hint" || startsWith(m, "bti") || startsWith(m, "pac") || startsWith(m, "aut") ||
            m == "isb" || m == "dsb" || m == "dmb" || startsWith(m, "xpac") || m == "yield")
            return;
        if (m == "brk" || m == "udf" || m == "hlt") { Stmt s; s.k = SK::Raw; s.text = "__builtin_trap()"; push(s); return; }

        // -- address generation --
        if (m == "adrp" || m == "adr") { assignOp(o[0], mkConst(uint64_t(o[1].imm))); return; }

        // -- moves --
        if (m == "mov" && n == 2) { assignOp(o[0], val(1)); return; }
        if (m == "movz") { assignOp(o[0], mkConst(uint64_t(o[1].imm) << (o[1].shift.value))); return; }
        if (m == "movn") { RI ri = regInfo(o[0].reg); uint64_t v = ~(uint64_t(o[1].imm) << o[1].shift.value);
                           if (ri.bits == 32) v &= 0xffffffffull; assignOp(o[0], mkConst(v)); return; }
        if (m == "movk") {
            uint64_t sh = o[1].shift.value, mask = 0xffffull << sh;
            ExprP cur = readReg(o[0].reg);
            assignOp(o[0], mkBin(BinOp::Or, mkBin(BinOp::And, cur, mkConst(~mask)), mkConst(uint64_t(o[1].imm) << sh)));
            return;
        }
        if (m == "mvn" && n >= 2) { assignOp(o[0], mkUn(UnOp::Not, val(1))); return; }
        if ((m == "neg" || m == "negs") && n >= 2) {
            assignOp(o[0], mkBin(BinOp::Sub, mkConst(0), val(1)));
            if (m == "negs") setFlags(FlagKind::Sub, mkConst(0), val(1));
            return;
        }

        // -- arithmetic / logic --
        auto bin3 = [&](BinOp op, bool flags, FlagKind fk) {
            ExprP a = val(1), b = val(2);
            if (flags) setFlags(fk, a, b);
            assignOp(o[0], mkBin(op, a, b));
        };
        if (n == 3 && isReg(0) && (m == "add" || m == "sub" || m == "and" || m == "orr" || m == "eor" ||
                                    m == "adds" || m == "subs" || m == "ands")) {
            BinOp op = (m[0] == 'a' && m[1] == 'd') ? BinOp::Add : (m[0] == 's') ? BinOp::Sub :
                       (m[0] == 'a') ? BinOp::And : (m[0] == 'o') ? BinOp::Or : BinOp::Xor;
            bool fl = m.back() == 's' && m != "adds" ? true : m == "adds";
            if (m == "adds") fl = true;
            FlagKind fk = op == BinOp::Add ? FlagKind::Add : op == BinOp::Sub ? FlagKind::Sub : FlagKind::And;
            RI rd = regInfo(o[0].reg);
            if (rd.zero && fl) { setFlags(fk, val(1), val(2)); return; }   // cmp/cmn/tst expanded forms
            bin3(op, fl, fk);
            return;
        }
        if ((m == "cmp" || m == "cmn" || m == "tst") && n >= 2) {
            setFlags(m == "cmp" ? FlagKind::Sub : m == "cmn" ? FlagKind::Add : FlagKind::And, val(0), val(1));
            return;
        }
        if (n == 3 && (m == "bic" || m == "bics")) {
            ExprP a = val(1), b = mkUn(UnOp::Not, val(2));
            if (m == "bics") setFlags(FlagKind::And, a, b);
            assignOp(o[0], mkBin(BinOp::And, a, b)); return;
        }
        if (n == 3 && m == "orn") { assignOp(o[0], mkBin(BinOp::Or, val(1), mkUn(UnOp::Not, val(2)))); return; }
        if (n == 3 && m == "eon") { assignOp(o[0], mkUn(UnOp::Not, mkBin(BinOp::Xor, val(1), val(2)))); return; }
        if (n == 3 && (m == "lsl" || m == "lsr" || m == "asr" || m == "ror")) {
            BinOp op = m == "lsl" ? BinOp::Shl : m == "lsr" ? BinOp::LShr : m == "asr" ? BinOp::AShr : BinOp::Ror;
            assignOp(o[0], mkBin(op, val(1), val(2))); return;
        }
        if (n == 3 && (m == "lslv" || m == "lsrv" || m == "asrv" || m == "rorv")) {
            BinOp op = m == "lslv" ? BinOp::Shl : m == "lsrv" ? BinOp::LShr : m == "asrv" ? BinOp::AShr : BinOp::Ror;
            assignOp(o[0], mkBin(op, val(1), val(2))); return;
        }
        if (n == 3 && m == "mul") { assignOp(o[0], mkBin(BinOp::Mul, val(1), val(2))); return; }
        if (n == 3 && m == "mneg") { assignOp(o[0], mkUn(UnOp::Neg, mkBin(BinOp::Mul, val(1), val(2)))); return; }
        if (n == 4 && m == "madd") { assignOp(o[0], mkBin(BinOp::Add, val(3), mkBin(BinOp::Mul, val(1), val(2)))); return; }
        if (n == 4 && m == "msub") { assignOp(o[0], mkBin(BinOp::Sub, val(3), mkBin(BinOp::Mul, val(1), val(2)))); return; }
        if (n == 3 && (m == "smull" || m == "umull")) {
            bool sg = m[0] == 's';
            assignOp(o[0], mkBin(BinOp::Mul, mkCast(val(1), 32, sg), mkCast(val(2), 32, sg))); return;
        }
        if (n == 4 && (m == "smaddl" || m == "umaddl")) {
            bool sg = m[0] == 's';
            assignOp(o[0], mkBin(BinOp::Add, val(3), mkBin(BinOp::Mul, mkCast(val(1), 32, sg), mkCast(val(2), 32, sg)))); return;
        }
        if (n == 3 && m == "sdiv") { assignOp(o[0], mkBin(BinOp::SDiv, val(1), val(2))); return; }
        if (n == 3 && m == "udiv") { assignOp(o[0], mkBin(BinOp::UDiv, val(1), val(2))); return; }
        if (n == 3 && (m == "smulh" || m == "umulh")) {
            assignOp(o[0], mkCallE(0, mkRaw(m == "smulh" ? "__mulhi_s" : "__mulhi_u"), {val(1), val(2)})); return;
        }

        // -- extends / bitfields --
        if (n == 2 && m == "sxtw") { assignOp(o[0], mkCast(val(1), 32, true)); return; }
        if (n == 2 && m == "sxth") { assignOp(o[0], mkCast(val(1), 16, true)); return; }
        if (n == 2 && m == "sxtb") { assignOp(o[0], mkCast(val(1), 8, true)); return; }
        if (n == 2 && m == "uxtw") { assignOp(o[0], mkCast(val(1), 32, false)); return; }
        if (n == 2 && m == "uxth") { assignOp(o[0], mkCast(val(1), 16, false)); return; }
        if (n == 2 && m == "uxtb") { assignOp(o[0], mkCast(val(1), 8, false)); return; }
        if (n == 4 && (m == "ubfx" || m == "sbfx")) {
            uint64_t lsb = uint64_t(o[2].imm), w = uint64_t(o[3].imm);
            ExprP sh = mkBin(BinOp::LShr, val(1), mkConst(lsb));
            if (m == "ubfx") assignOp(o[0], mkBin(BinOp::And, sh, mkConst(w >= 64 ? ~0ull : (1ull << w) - 1)));
            else assignOp(o[0], mkCast(sh, int(w), true));
            return;
        }
        if (n == 4 && m == "ubfiz") {
            uint64_t lsb = uint64_t(o[2].imm), w = uint64_t(o[3].imm);
            assignOp(o[0], mkBin(BinOp::Shl, mkBin(BinOp::And, val(1), mkConst((1ull << w) - 1)), mkConst(lsb))); return;
        }
        if (n == 4 && m == "sbfiz") {
            uint64_t lsb = uint64_t(o[2].imm), w = uint64_t(o[3].imm);
            assignOp(o[0], mkBin(BinOp::Shl, mkCast(val(1), int(w), true), mkConst(lsb))); return;
        }
        if (n == 4 && m == "bfi") {
            uint64_t lsb = uint64_t(o[2].imm), w = uint64_t(o[3].imm), mask = ((1ull << w) - 1) << lsb;
            ExprP ins = mkBin(BinOp::Shl, mkBin(BinOp::And, val(1), mkConst((1ull << w) - 1)), mkConst(lsb));
            assignOp(o[0], mkBin(BinOp::Or, mkBin(BinOp::And, readReg(o[0].reg), mkConst(~mask)), ins)); return;
        }
        if (n == 4 && m == "bfxil") {
            uint64_t lsb = uint64_t(o[2].imm), w = uint64_t(o[3].imm), mask = (1ull << w) - 1;
            ExprP ex = mkBin(BinOp::And, mkBin(BinOp::LShr, val(1), mkConst(lsb)), mkConst(mask));
            assignOp(o[0], mkBin(BinOp::Or, mkBin(BinOp::And, readReg(o[0].reg), mkConst(~mask)), ex)); return;
        }
        if (n == 2 && m == "rev") { assignOp(o[0], mkCallE(0, mkRaw("__builtin_bswap"), {val(1)})); return; }
        if (n == 2 && m == "clz") { assignOp(o[0], mkCallE(0, mkRaw("__builtin_clz"), {val(1)})); return; }
        if (n == 2 && m == "rbit") { assignOp(o[0], mkCallE(0, mkRaw("__builtin_bitreverse"), {val(1)})); return; }

        // -- conditional select / set --
        if (m == "csel" && n == 3) { assignOp(o[0], mkCond(ccExpr(d.cc), val(1), val(2))); return; }
        if (m == "csinc" && n == 3) { assignOp(o[0], mkCond(ccExpr(d.cc), val(1), mkBin(BinOp::Add, val(2), mkConst(1)))); return; }
        if (m == "csinv" && n == 3) { assignOp(o[0], mkCond(ccExpr(d.cc), val(1), mkUn(UnOp::Not, val(2)))); return; }
        if (m == "csneg" && n == 3) { assignOp(o[0], mkCond(ccExpr(d.cc), val(1), mkUn(UnOp::Neg, val(2)))); return; }
        if (m == "cset" && n == 1) { assignOp(o[0], mkCond(ccExpr(d.cc), mkConst(1), mkConst(0))); return; }
        if (m == "csetm" && n == 1) { assignOp(o[0], mkCond(ccExpr(d.cc), mkConst(~0ull), mkConst(0))); return; }
        if (m == "cinc" && n == 2) { assignOp(o[0], mkCond(ccExpr(d.cc), mkBin(BinOp::Add, val(1), mkConst(1)), val(1))); return; }
        if (m == "cinv" && n == 2) { assignOp(o[0], mkCond(ccExpr(d.cc), mkUn(UnOp::Not, val(1)), val(1))); return; }
        if (m == "cneg" && n == 2) { assignOp(o[0], mkCond(ccExpr(d.cc), mkUn(UnOp::Neg, val(1)), val(1))); return; }

        // -- memory --
        if (liftMemory(m, d, n)) return;

        // everything else (fp/simd/atomics/system): keep visible but opaque
        raw();
    }

    bool liftMemory(const std::string& m, const cs_arm64& d, int n) {
        const cs_arm64_op* o = d.operands;
        bool isLoad = startsWith(m, "ldr") || startsWith(m, "ldur") || startsWith(m, "ldp") || startsWith(m, "ldnp") ||
                      startsWith(m, "ldtr") || startsWith(m, "ldxr") || startsWith(m, "ldar") || startsWith(m, "ldapr");
        bool isStore = startsWith(m, "str") || startsWith(m, "stur") || startsWith(m, "stp") || startsWith(m, "stnp") ||
                       startsWith(m, "sttr") || startsWith(m, "stlr");
        if (!isLoad && !isStore) return false;
        if (startsWith(m, "ldxr") || startsWith(m, "ldar") || startsWith(m, "ldapr") || startsWith(m, "stlr") ||
            startsWith(m, "ldtr") || startsWith(m, "sttr"))
            return false;   // exclusives / acquire-release: leave opaque

        bool pair = m[2] == 'p' || m[3] == 'p' || startsWith(m, "ldnp") || startsWith(m, "stnp");
        int memIdx = -1;
        for (int i = 0; i < n; ++i) if (o[i].type == ARM64_OP_MEM) { memIdx = i; break; }
        if (memIdx < 0 && !(startsWith(m, "ldr") && n == 2 && o[1].type == ARM64_OP_IMM)) return false;

        // element size / signedness
        auto rinfo0 = regInfo(o[0].reg);
        if (rinfo0.fp) return false;           // simd/fp loads and stores stay opaque
        int size = rinfo0.bits == 32 ? 4 : 8;
        bool sign = false;
        std::string suf = m;
        if (suf == "ldrb" || suf == "ldurb" || suf == "strb" || suf == "sturb") size = 1;
        else if (suf == "ldrh" || suf == "ldurh" || suf == "strh" || suf == "spurh" || suf == "sturh") size = 2;
        else if (suf == "ldrsb" || suf == "ldursb") { size = 1; sign = true; }
        else if (suf == "ldrsh" || suf == "ldursh") { size = 2; sign = true; }
        else if (suf == "ldrsw" || suf == "ldursw" || suf == "ldpsw") { size = 4; sign = true; }

        // literal load
        if (memIdx < 0) {
            assignOp(o[0], mkLoad(mkConst(uint64_t(o[1].imm)), size, sign));
            return true;
        }
        const cs_arm64_op& mo = o[memIdx];
        RI base = regInfo(mo.mem.base);
        ExprP addr = memAddr(mo);
        bool post = d.post_index;
        int64_t postImm = 0;
        if (post) for (int i = memIdx + 1; i < n; ++i) if (o[i].type == ARM64_OP_IMM) postImm = o[i].imm;

        auto emitAccess = [&](const cs_arm64_op& r, ExprP a) {
            if (isLoad) assignOp(r, mkLoad(a, size, sign));
            else store(a, opVal(r), size);
        };
        emitAccess(o[0], addr);
        if (pair) emitAccess(o[1], mkBin(BinOp::Add, addr, mkConst(size)));
        if (d.writeback && !base.zero && base.id >= 0) {
            ExprP nb = post ? mkBin(BinOp::Add, readReg(mo.mem.base), mkConst(uint64_t(postImm)))
                            : mkBin(BinOp::Add, readReg(mo.mem.base), mkConst(uint64_t(int64_t(mo.mem.disp))));
            // pre-index: address already includes the update; post-index: base advanced after the access
            assign(base.id, 64, nb);
        }
        return true;
    }
};

}  // namespace

std::unique_ptr<Lifter> makeArm64Lifter() { return std::make_unique<Arm64Lifter>(); }

}  // namespace er::dc
