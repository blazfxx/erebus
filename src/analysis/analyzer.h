// Auto-analysis: recursive-descent disassembly, function/basic-block recovery,
// cross references, string discovery, pointer-table scanning, naming.
#pragma once
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "core/image.h"
#include "procs/proc.h"

namespace er {

enum class XType : uint8_t { Jump = 0, Call = 1, DRead = 2, DWrite = 3, DOffset = 4, Tail = 5 };
const char* xtypeName(XType t);

enum class EdgeKind : uint8_t { Fall = 0, Jump = 1, True = 2, False = 3 };

enum class NameKind : uint8_t { Symbol = 0, Import = 1, User = 2, String = 3 };

struct Xref {
    uint64_t from = 0, to = 0;
    XType type = XType::Jump;
};

struct Block {
    uint64_t start = 0, end = 0;
};

struct Edge {
    uint64_t src = 0, dst = 0;   // block start addresses
    EdgeKind kind = EdgeKind::Fall;
};

struct JumpTable {
    std::string idxReg;
    std::vector<uint64_t> entries;   // ordered by table index; 0 = invalid
};

struct Func {
    uint64_t start = 0, end = 0;
    std::map<uint64_t, JumpTable> jt;   // keyed by the indirect jump's address
    std::vector<Block> blocks;
    std::vector<Edge> edges;
    bool noret = false;
    bool thunk = false;
};

struct NameEntry {
    std::string name;
    NameKind kind = NameKind::Symbol;
};

struct StringEntry {
    uint32_t length = 0;     // bytes in memory (excluding terminator)
    uint8_t wide = 0;        // 0 = byte string, 1 = UTF-16LE
    std::string text;        // decoded as UTF-8 (printable approximation)
};

struct Analysis {
    std::map<uint64_t, Func> funcs;
    std::vector<Xref> xrefs;
    std::map<uint64_t, NameEntry> names;
    std::map<uint64_t, StringEntry> strings;
    std::map<uint64_t, std::string> comments;

    // statistics
    uint64_t insnCount = 0;
    uint64_t codeBytes = 0;
    uint64_t coveredBytes = 0;
};

struct AnalyzeOptions {
    bool verbose = false;
    bool gapScan = true;      // prologue sweep over uncovered code
    bool ptrScan = true;      // function/string pointers inside data sections
    bool sweep = false;       // also turn any cleanly-decoding leftover run into a function (EH landing pads)
};

void analyze(const Image& img, Proc& proc, Analysis& out, const AnalyzeOptions& opt);

}  // namespace er
