// Decompiler IR: register-level three-address statements over expression trees.
#pragma once
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace er::dc {

struct Expr;
using ExprP = std::shared_ptr<const Expr>;

enum class EK : uint8_t {
    Const,    // c
    Reg,      // reg, bits
    Stack,    // address of stack slot: c = signed offset from entry sp (as uint64 two's complement)
    Sym,      // c = address (named global / function), name filled by the decompiler
    Str,      // c = address of a string literal
    Un,       // uop, a
    Bin,      // bop, a, b
    Load,     // size (bytes), sign, a = address
    Cast,     // bits, sign, a
    Cond,     // a ? b : cc
    Call,     // target (c if direct, else a), args
    Flags,    // a, b, fk : result of a comparison-setting instruction
    Raw,      // text (unliftable instruction placeholder)
    Def       // c = definition id inside a block (simulation placeholder)
};

enum class BinOp : uint8_t {
    Add, Sub, Mul, SDiv, UDiv, SRem, URem, And, Or, Xor, Shl, LShr, AShr, Ror,
    Eq, Ne, SLt, SLe, SGt, SGe, ULt, ULe, UGt, UGe, LAnd, LOr
};
enum class UnOp : uint8_t { Neg, Not, LNot };
enum class FlagKind : uint8_t { Sub, Add, And, Fcmp };

struct Expr {
    EK k = EK::Const;
    uint64_t c = 0;
    int reg = -1;
    int bits = 64;
    int size = 0;
    bool sign = false;
    BinOp bop = BinOp::Add;
    UnOp uop = UnOp::Neg;
    FlagKind fk = FlagKind::Sub;
    ExprP a, b, cc;
    std::vector<ExprP> args;
    std::string text;
    bool directCall = false;
};

// --- constructors -------------------------------------------------------------
ExprP mkConst(uint64_t v, int bits = 64);
ExprP mkReg(int reg, int bits);
ExprP mkStack(int64_t off);
ExprP mkSym(uint64_t addr);
ExprP mkStr(uint64_t addr);
ExprP mkUn(UnOp op, ExprP a);
ExprP mkBin(BinOp op, ExprP a, ExprP b);   // folds constants / identities
ExprP mkLoad(ExprP addr, int size, bool sign);
ExprP mkCast(ExprP a, int bits, bool sign);
ExprP mkCond(ExprP c, ExprP t, ExprP f);
ExprP mkFlags(FlagKind k, ExprP a, ExprP b);
ExprP mkRaw(const std::string& text);
ExprP mkDef(int id);
ExprP mkCallE(uint64_t target, ExprP indirect, std::vector<ExprP> args);

bool isConst(const ExprP& e);
bool exprEq(const ExprP& a, const ExprP& b);
// Pre-order rewrite: if f(node) returns non-null it replaces the node (children untouched),
// otherwise children are rewritten and the node rebuilt (only if something changed).
ExprP rewrite(const ExprP& e, const std::function<ExprP(const ExprP&)>& f);
// Visit every node (pre-order).
void visit(const ExprP& e, const std::function<void(const ExprP&)>& f);

// --- statements ---------------------------------------------------------------------
enum class SK : uint8_t { Assign, Store, Call, Ret, Br, Jmp, Switch, Raw };

struct Stmt {
    SK k = SK::Raw;
    uint64_t at = 0;          // address of originating instruction
    int dst = -1;             // Assign/Call: destination register (-1 none)
    int dstBits = 64;
    ExprP val;                // Assign value / Store value / Ret value / Call expression
    ExprP addr;               // Store address
    int size = 0;             // Store size
    ExprP cond;               // Br condition (null = unresolved)
    int cc = -1;              // Br: condition code to be resolved against flags (lifter-defined)
    uint64_t t = 0, f = 0;    // Br targets; Jmp target in t
    std::string text;         // Raw
    std::vector<uint64_t> targets;   // Switch targets
    ExprP index;              // Switch index
    int64_t spOff = 0;        // stack pointer offset (from entry sp) at this statement, when known
    bool spKnown = false;
    bool dead = false;        // removed by a cleanup pass
};

enum class CC : int { EQ = 1, NE, HS, LO, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL };

}  // namespace er::dc
