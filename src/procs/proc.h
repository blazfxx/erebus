// Processor module interface. Decodes one instruction and classifies control flow and
// data references. First implementation wraps Capstone for arm64 and x86/x86_64.
#pragma once
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/image.h"

namespace er {

enum class Flow : uint8_t { Normal, Jmp, CJmp, Call, Ret, IJmp, ICall, Trap };

struct DataRef {
    uint64_t addr = 0;
    char kind = 'o';   // 'r' read, 'w' write, 'o' address taken / offset
};

struct Insn {
    uint64_t addr = 0;
    uint32_t size = 0;
    std::string mnem;
    std::string ops;
    Flow flow = Flow::Normal;
    bool hasTarget = false;
    uint64_t target = 0;
    std::vector<DataRef> drefs;
};

// Per-basic-block decode state (e.g. ADRP page tracking). Reset at every block entry.
struct DecodeCtx {
    std::unordered_map<unsigned, uint64_t> regs;
};

struct JTInfo {
    std::vector<uint64_t> ordered;   // table entry i -> target (0 where invalid), index order
    std::string idxReg;              // register holding the table index (e.g. "x16", "rax")
};

class Proc {
public:
    virtual ~Proc() = default;
    virtual Arch arch() const = 0;
    virtual unsigned align() const = 0;   // instruction alignment (4 for arm64, 1 for x86)
    virtual bool decode(const Image& img, uint64_t addr, Insn& out, DecodeCtx& ctx) = 0;
    // Cheap check for "a function plausibly starts here" used by gap scanning.
    virtual bool looksLikePrologue(const Image& img, uint64_t addr) = 0;

    // Try to resolve the indirect jump that ends `trail` (recent instructions of the current
    // linear run, oldest first) into its switch-table targets.
    virtual bool jumpTable(const Image& img, const std::vector<Insn>& trail, std::vector<uint64_t>& targets, JTInfo& info) {
        return false;
    }

    static std::unique_ptr<Proc> create(Arch a, unsigned bits);
};

}  // namespace er
