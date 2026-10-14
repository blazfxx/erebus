#include "decomp/ir.h"

#include <algorithm>

namespace er::dc {

namespace {
ExprP make(Expr&& e) { return std::make_shared<const Expr>(std::move(e)); }
}

ExprP mkConst(uint64_t v, int bits) {
    Expr e; e.k = EK::Const; e.c = v; e.bits = bits;
    return make(std::move(e));
}
ExprP mkReg(int reg, int bits) {
    Expr e; e.k = EK::Reg; e.reg = reg; e.bits = bits;
    return make(std::move(e));
}
ExprP mkStack(int64_t off) {
    Expr e; e.k = EK::Stack; e.c = uint64_t(off);
    return make(std::move(e));
}
ExprP mkSym(uint64_t addr) {
    Expr e; e.k = EK::Sym; e.c = addr;
    return make(std::move(e));
}
ExprP mkStr(uint64_t addr) {
    Expr e; e.k = EK::Str; e.c = addr;
    return make(std::move(e));
}
ExprP mkUn(UnOp op, ExprP a) {
    if (a->k == EK::Const) {
        if (op == UnOp::Neg) return mkConst(uint64_t(-int64_t(a->c)), a->bits);
        if (op == UnOp::Not) return mkConst(~a->c, a->bits);
        if (op == UnOp::LNot) return mkConst(a->c == 0, a->bits);
    }
    if (op == UnOp::LNot && a->k == EK::Un && a->uop == UnOp::LNot) return a->a;
    if (op == UnOp::LNot && a->k == EK::Bin) {   // !(a < b) -> a >= b, etc.
        BinOp inv;
        bool ok = true;
        switch (a->bop) {
            case BinOp::Eq: inv = BinOp::Ne; break;
            case BinOp::Ne: inv = BinOp::Eq; break;
            case BinOp::SLt: inv = BinOp::SGe; break;
            case BinOp::SLe: inv = BinOp::SGt; break;
            case BinOp::SGt: inv = BinOp::SLe; break;
            case BinOp::SGe: inv = BinOp::SLt; break;
            case BinOp::ULt: inv = BinOp::UGe; break;
            case BinOp::ULe: inv = BinOp::UGt; break;
            case BinOp::UGt: inv = BinOp::ULe; break;
            case BinOp::UGe: inv = BinOp::ULt; break;
            default: ok = false; inv = BinOp::Eq;
        }
        if (ok) return mkBin(inv, a->a, a->b);
    }
    Expr e; e.k = EK::Un; e.uop = op; e.a = std::move(a);
    return make(std::move(e));
}

bool isConst(const ExprP& e) { return e && e->k == EK::Const; }

ExprP mkBin(BinOp op, ExprP a, ExprP b) {
    if (isConst(a) && isConst(b)) {
        uint64_t x = a->c, y = b->c;
        int bits = std::max(a->bits, b->bits);
        switch (op) {
            case BinOp::Add: return mkConst(x + y, bits);
            case BinOp::Sub: return mkConst(x - y, bits);
            case BinOp::Mul: return mkConst(x * y, bits);
            case BinOp::And: return mkConst(x & y, bits);
            case BinOp::Or: return mkConst(x | y, bits);
            case BinOp::Xor: return mkConst(x ^ y, bits);
            case BinOp::Shl: return mkConst(y < 64 ? x << y : 0, bits);
            case BinOp::LShr: return mkConst(y < 64 ? x >> y : 0, bits);
            default: break;
        }
    }
    if ((op == BinOp::And || op == BinOp::Or) && exprEq(a, b)) return a;
    // (x & signbit) == 0  ->  x >= 0 ; != 0 -> x < 0
    if ((op == BinOp::Eq || op == BinOp::Ne) && isConst(b) && b->c == 0 && a->k == EK::Bin && a->bop == BinOp::And &&
        isConst(a->b) && (a->b->c == 0x8000000000000000ull || a->b->c == 0x80000000ull))
        return mkBin(op == BinOp::Eq ? BinOp::SGe : BinOp::SLt, a->a, mkConst(0));
    // canonicalise constants to the right for commutative ops
    if ((op == BinOp::Add || op == BinOp::Mul || op == BinOp::And || op == BinOp::Or || op == BinOp::Xor) &&
        isConst(a) && !isConst(b))
        std::swap(a, b);
    if (isConst(b)) {
        uint64_t y = b->c;
        if ((op == BinOp::Add || op == BinOp::Sub || op == BinOp::Or || op == BinOp::Xor || op == BinOp::Shl ||
             op == BinOp::LShr || op == BinOp::AShr) && y == 0)
            return a;
        if ((op == BinOp::Mul || op == BinOp::SDiv || op == BinOp::UDiv) && y == 1) return a;
        if (op == BinOp::Mul && y == 0) return b;
        if (op == BinOp::And && y == 0) return b;
        // (x + c1) + c2 / (x - c1) + c2 folding
        if ((op == BinOp::Add || op == BinOp::Sub) && a->k == EK::Bin && (a->bop == BinOp::Add || a->bop == BinOp::Sub) &&
            isConst(a->b)) {
            int64_t c1 = a->bop == BinOp::Add ? int64_t(a->b->c) : -int64_t(a->b->c);
            int64_t c2 = op == BinOp::Add ? int64_t(y) : -int64_t(y);
            int64_t t = c1 + c2;
            if (t == 0) return a->a;
            return mkBin(BinOp::Add, a->a, mkConst(uint64_t(t), b->bits));
        }
        // stack slot +/- const stays a stack slot
        if ((op == BinOp::Add || op == BinOp::Sub) && a->k == EK::Stack) {
            int64_t d = op == BinOp::Add ? int64_t(y) : -int64_t(y);
            return mkStack(int64_t(a->c) + d);
        }
        // normalise x - c  ->  x + (-c)
        if (op == BinOp::Sub) return mkBin(BinOp::Add, a, mkConst(uint64_t(-int64_t(y)), b->bits));
    }
    Expr e; e.k = EK::Bin; e.bop = op; e.a = std::move(a); e.b = std::move(b);
    return make(std::move(e));
}

ExprP mkLoad(ExprP addr, int size, bool sign) {
    Expr e; e.k = EK::Load; e.size = size; e.sign = sign; e.a = std::move(addr);
    return make(std::move(e));
}
ExprP mkCast(ExprP a, int bits, bool sign) {
    if (a->k == EK::Const && bits < 64) {
        uint64_t m = (1ull << bits) - 1, v = a->c & m;
        if (sign && (v >> (bits - 1))) v |= ~m;
        return mkConst(v, 64);
    }
    Expr e; e.k = EK::Cast; e.bits = bits; e.sign = sign; e.a = std::move(a);
    return make(std::move(e));
}
ExprP mkCond(ExprP c, ExprP t, ExprP f) {
    Expr e; e.k = EK::Cond; e.a = std::move(c); e.b = std::move(t); e.cc = std::move(f);
    return make(std::move(e));
}
ExprP mkFlags(FlagKind k, ExprP a, ExprP b) {
    Expr e; e.k = EK::Flags; e.fk = k; e.a = std::move(a); e.b = std::move(b);
    return make(std::move(e));
}
ExprP mkRaw(const std::string& text) {
    Expr e; e.k = EK::Raw; e.text = text;
    return make(std::move(e));
}
ExprP mkDef(int id) {
    Expr e; e.k = EK::Def; e.c = uint64_t(id);
    return make(std::move(e));
}
ExprP mkCallE(uint64_t target, ExprP indirect, std::vector<ExprP> args) {
    Expr e; e.k = EK::Call; e.c = target; e.a = std::move(indirect); e.args = std::move(args);
    e.directCall = e.a == nullptr;
    return make(std::move(e));
}

bool exprEq(const ExprP& a, const ExprP& b) {
    if (a == b) return true;
    if (!a || !b || a->k != b->k) return false;
    switch (a->k) {
        case EK::Const: case EK::Stack: case EK::Sym: case EK::Str: return a->c == b->c;
        case EK::Reg: return a->reg == b->reg && a->bits == b->bits;
        case EK::Un: return a->uop == b->uop && exprEq(a->a, b->a);
        case EK::Bin: return a->bop == b->bop && exprEq(a->a, b->a) && exprEq(a->b, b->b);
        case EK::Load: return a->size == b->size && a->sign == b->sign && exprEq(a->a, b->a);
        case EK::Cast: return a->bits == b->bits && a->sign == b->sign && exprEq(a->a, b->a);
        case EK::Cond: return exprEq(a->a, b->a) && exprEq(a->b, b->b) && exprEq(a->cc, b->cc);
        case EK::Flags: return a->fk == b->fk && exprEq(a->a, b->a) && exprEq(a->b, b->b);
        case EK::Raw: return a->text == b->text;
        case EK::Def: return a->c == b->c;
        case EK::Call: {
            if (a->c != b->c || a->args.size() != b->args.size() || !exprEq(a->a, b->a)) return false;
            for (size_t i = 0; i < a->args.size(); ++i)
                if (!exprEq(a->args[i], b->args[i])) return false;
            return true;
        }
    }
    return false;
}

ExprP rewrite(const ExprP& e, const std::function<ExprP(const ExprP&)>& f) {
    if (!e) return e;
    if (ExprP r = f(e)) return r;
    switch (e->k) {
        case EK::Un: { auto a = rewrite(e->a, f); return a == e->a ? e : mkUn(e->uop, a); }
        case EK::Bin: {
            auto a = rewrite(e->a, f), b = rewrite(e->b, f);
            return (a == e->a && b == e->b) ? e : mkBin(e->bop, a, b);
        }
        case EK::Load: { auto a = rewrite(e->a, f); return a == e->a ? e : mkLoad(a, e->size, e->sign); }
        case EK::Cast: { auto a = rewrite(e->a, f); return a == e->a ? e : mkCast(a, e->bits, e->sign); }
        case EK::Cond: {
            auto a = rewrite(e->a, f), b = rewrite(e->b, f), c = rewrite(e->cc, f);
            return (a == e->a && b == e->b && c == e->cc) ? e : mkCond(a, b, c);
        }
        case EK::Flags: {
            auto a = rewrite(e->a, f), b = rewrite(e->b, f);
            return (a == e->a && b == e->b) ? e : mkFlags(e->fk, a, b);
        }
        case EK::Call: {
            bool changed = false;
            std::vector<ExprP> args;
            for (const auto& x : e->args) { auto n = rewrite(x, f); changed |= n != x; args.push_back(n); }
            auto ind = rewrite(e->a, f);
            changed |= ind != e->a;
            return changed ? mkCallE(e->c, ind, std::move(args)) : e;
        }
        default: return e;
    }
}

void visit(const ExprP& e, const std::function<void(const ExprP&)>& f) {
    if (!e) return;
    f(e);
    visit(e->a, f);
    visit(e->b, f);
    visit(e->cc, f);
    for (const auto& x : e->args) visit(x, f);
}

}  // namespace er::dc
