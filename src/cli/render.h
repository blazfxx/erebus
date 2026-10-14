// Presentation of a decoded instruction: operand symbolization + annotations.
// Shared by the text CLI and the web UI.
#pragma once
#include <string>
#include <vector>

#include "cli/session.h"

namespace er {

struct TextPart {
    std::string text;
    bool isRef = false;
    uint64_t addr = 0;   // valid when isRef
};

struct RenderedInsn {
    uint64_t addr = 0;
    uint32_t size = 0;
    std::string bytes;                // "48 89 e5"
    std::string mnem;
    std::vector<TextPart> ops;        // operand text, branch targets resolved to clickable names
    std::vector<TextPart> comment;    // data refs / strings / user comment
};

RenderedInsn renderInsn(Session& s, const Insn& in);

std::string escapeText(const std::string& s, size_t max = 64);
std::string flatten(const std::vector<TextPart>& parts);

}  // namespace er
