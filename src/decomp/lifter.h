// Lifter: machine instruction -> decompiler IR statements. One implementation per architecture.
#pragma once
#include <memory>
#include <string>
#include <vector>

#include "core/image.h"
#include "decomp/ir.h"

namespace er::dc {

constexpr int kFlagsReg = 32;

class Lifter {
public:
    virtual ~Lifter() = default;
    // Lifts the instruction at addr. Returns false if undecodable. `size` is the instruction length.
    virtual bool lift(const Image& img, uint64_t addr, std::vector<Stmt>& out, uint32_t& size) = 0;

    virtual std::string regName(int id, int bits) const = 0;
    virtual int spReg() const = 0;
    virtual int fpReg() const = 0;                     // frame pointer register id (-1 if none)
    virtual int retReg() const = 0;
    virtual const std::vector<int>& argRegs() const = 0;
    virtual const std::vector<int>& calleeSaved() const = 0;
    virtual bool isCalleeSaved(int r) const;

    static std::unique_ptr<Lifter> create(Arch a, unsigned bits, bool win64 = false);
};

}  // namespace er::dc
