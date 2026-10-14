// Assembler wrapper (Keystone) used by the patching workflow.
#pragma once
#include <cstdint>
#include <string>
#include <vector>

#include "core/image.h"

namespace er {

// True when a Keystone library could be loaded at runtime.
bool assemblerAvailable();

// Assembles `text` (one or more instructions, ';'-separated) as if placed at `addr`.
bool assembleText(Arch arch, unsigned bits, uint64_t addr, const std::string& text, std::vector<uint8_t>& out,
                  std::string& err);

}  // namespace er
