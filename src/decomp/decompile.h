// Decompiler front door: function -> pseudo-C lines (with clickable name references).
#pragma once
#include <string>
#include <vector>

#include "cli/session.h"

namespace er::dc {

enum class Cls : uint8_t { Plain, Keyword, Type, Number, String, Name, Comment, Var };

struct CPart {
    std::string text;
    Cls cls = Cls::Plain;
    bool ref = false;
    uint64_t addr = 0;   // valid when ref
};

struct CLine {
    int indent = 0;
    std::vector<CPart> parts;
};

struct DecompResult {
    bool ok = false;
    std::string error;
    std::vector<CLine> lines;
};

DecompResult decompile(Session& s, uint64_t funcStart);
std::string toText(const DecompResult& r);

}  // namespace er::dc
