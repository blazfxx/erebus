// Internal: the analysed function model handed from the dataflow stage to the structurer/printer.
#pragma once
#include <map>
#include <string>
#include <vector>

#include "cli/session.h"
#include "decomp/ir.h"
#include "decomp/lifter.h"

namespace er::dc {

enum class TK : uint8_t { Fall, Jmp, Br, Ret, Switch, None };

struct FinalBlock {
    uint64_t addr = 0;
    std::vector<Stmt> out;        // Assign / Store / Call / Raw, expressions fully expanded
    TK tk = TK::None;
    ExprP cond;                   // Br
    ExprP retv;                   // Ret (null = void)
    ExprP idx;                    // Switch
    int t = -1, f = -1;           // Br successors; Jmp/Fall use t
    std::vector<int> cases;       // Switch successor blocks
    std::vector<std::pair<int64_t, int>> switchCases;   // (case value, block) in ascending value order (jump tables)
    std::vector<int> succ, pred;
    bool reachable = false;
};

struct FuncModel {
    uint64_t start = 0;
    std::vector<FinalBlock> blocks;
    int entry = 0;
    int nparams = 0;
    int stackParams = 0;          // x86-32: parameters passed on the stack (slots 4, 8, ...)
    bool returnsValue = false;
    int retBits = 64;
    std::map<int, bool> reg32;    // register id -> every access was 32-bit
    int nextTemp = 0;             // temps are register ids >= kTempBase
};

constexpr int kTempBase = 1000;

struct FuncSummary {
    int nparams = -1;             // -1 unknown / in progress
    bool returnsValue = true;
    bool noret = false;
    bool variadic = false;
};

// Runs lifting, stack tracking, symbolic simulation, liveness. Returns false if the function can't be modelled.
bool buildModel(Session& s, Lifter& L, uint64_t funcStart, FuncModel& m, std::string& err);

FuncSummary summarize(Session& s, Lifter& L, uint64_t funcStart);
void clearSummaryCache();

// Known library prototypes (name without leading underscores).
struct Known { const char* name; int nparams; bool variadic; bool voidRet; bool noret; };
const Known* findKnown(const std::string& symbolName);
std::string stripUnderscores(const std::string& n);

}  // namespace er::dc
