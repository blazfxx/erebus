#include "decomp/lifter.h"

#include <algorithm>

namespace er::dc {

bool Lifter::isCalleeSaved(int r) const {
    const auto& v = calleeSaved();
    return std::find(v.begin(), v.end(), r) != v.end();
}

std::unique_ptr<Lifter> makeArm64Lifter();
std::unique_ptr<Lifter> makeX86Lifter(unsigned bits, bool win);

std::unique_ptr<Lifter> Lifter::create(Arch a, unsigned bits, bool win64) {
    if (a == Arch::ARM64) return makeArm64Lifter();
    if (a == Arch::X86_64 || a == Arch::X86) return makeX86Lifter(bits, win64);
    return nullptr;
}

}  // namespace er::dc
