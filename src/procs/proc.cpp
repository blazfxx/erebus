#include "procs/proc.h"

#include <capstone/capstone.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>

namespace er {
namespace {

bool startsWith(const std::string& s, const char* p) { return s.rfind(p, 0) == 0; }


std::string trim(std::string s) {
    size_t a = s.find_first_not_of(" \t");
    size_t b = s.find_last_not_of(" \t");
    return a == std::string::npos ? "" : s.substr(a, b - a + 1);
}

std::vector<std::string> splitTop(const std::string& s) {   // split on commas outside [] brackets
    std::vector<std::string> out;
    std::string cur;
    int depth = 0;
    for (char c : s) {
        if (c == '[') ++depth;
        if (c == ']') --depth;
        if (c == ',' && depth == 0) { out.push_back(trim(cur)); cur.clear(); }
        else cur.push_back(c);
    }
    if (!trim(cur).empty()) out.push_back(trim(cur));
    return out;
}

int a64Reg(const std::string& t) {   // x8 / w8 -> 8, anything else -> -1
    if (t.size() < 2 || (t[0] != 'x' && t[0] != 'w') || !std::isdigit((unsigned char)t[1])) return -1;
    return std::atoi(t.c_str() + 1);
}

int shiftOf(const std::string& t) {   // "lsl #2" / "sxtw #2" -> 2, otherwise 0
    size_t p = t.find('#');
    return p == std::string::npos ? 0 : std::atoi(t.c_str() + p + 1);
}

int64_t immOf(const std::string& t) {
    size_t p = t.find('#');
    const char* s = t.c_str() + (p == std::string::npos ? 0 : p + 1);
    return std::strtoll(s, nullptr, 0);
}

// returns (base, idx, shift) of "[x8, x9, lsl #2]"
bool memOperand(const std::string& t, int& base, int& idx, int& shift) {
    size_t a = t.find('['), b = t.find(']');
    if (a == std::string::npos || b == std::string::npos) return false;
    auto parts = splitTop(t.substr(a + 1, b - a - 1));
    if (parts.size() < 2) return false;
    base = a64Reg(parts[0]);
    idx = a64Reg(parts[1]);
    shift = parts.size() > 2 ? shiftOf(parts[2]) : 0;
    return base >= 0 && idx >= 0;
}

uint64_t lastDref(const Insn& i, char kind = 'o') {
    for (auto it = i.drefs.rbegin(); it != i.drefs.rend(); ++it)
        if (it->kind == kind) return it->addr;
    return 0;
}

class CsProc : public Proc {
public:
    CsProc(Arch a, unsigned bits) : arch_(a), bits_(bits) {
        cs_arch ca = (a == Arch::ARM64) ? CS_ARCH_ARM64 : CS_ARCH_X86;
        cs_mode cm = (a == Arch::ARM64) ? CS_MODE_ARM : (bits == 64 ? CS_MODE_64 : CS_MODE_32);
        if (cs_open(ca, cm, &h_) != CS_ERR_OK) h_ = 0;
        if (h_) {
            cs_option(h_, CS_OPT_DETAIL, CS_OPT_ON);
            insn_ = cs_malloc(h_);
        }
    }
    ~CsProc() override {
        if (insn_) cs_free(insn_, 1);
        if (h_) cs_close(&h_);
    }

    Arch arch() const override { return arch_; }
    unsigned align() const override { return arch_ == Arch::ARM64 ? 4 : 1; }

    bool decode(const Image& img, uint64_t addr, Insn& out, DecodeCtx& ctx) override {
        if (!h_) return false;
        uint8_t buf[16];
        size_t got = img.readSome(addr, buf, sizeof buf);
        if (!got) return false;
        const uint8_t* p = buf;
        size_t sz = got;
        uint64_t a = addr;
        if (!cs_disasm_iter(h_, &p, &sz, &a, insn_)) return false;

        out = Insn{};
        out.addr = addr;
        out.size = insn_->size;
        out.mnem = insn_->mnemonic;
        out.ops = insn_->op_str;
        if (arch_ == Arch::ARM64) classifyArm64(img, ctx, out);
        else classifyX86(img, ctx, out);
        return true;
    }

    bool looksLikePrologue(const Image& img, uint64_t addr) override {
        uint8_t b[8];
        if (img.readSome(addr, b, 8) < 8) return false;
        if (arch_ == Arch::ARM64) {
            uint32_t w;
            std::memcpy(&w, b, 4);
            if (w == 0xd503237f) return true;                       // pacibsp
            if ((w & 0xffc003e0) == 0xa98003e0 && ((w >> 10) & 0x1f) == 30 && (w & 0x1f) == 29) return true;  // stp x29,x30,[sp,#-n]!
            if ((w & 0xffc003ff) == 0xd10003ff) {                   // sub sp,sp,#n ; then stp x29,x30
                uint32_t w2;
                if (img.read(addr + 4, &w2, 4) && (w2 & 0xffc07fff) == 0xa9007bfd) return true;
            }
            return false;
        }
        if (b[0] == 0xf3 && b[1] == 0x0f && b[2] == 0x1e && (b[3] == 0xfa || b[3] == 0xfb)) return true;  // endbr
        if (b[0] == 0x55 && ((b[1] == 0x48 && b[2] == 0x89 && b[3] == 0xe5) || (b[1] == 0x89 && b[2] == 0xe5))) return true;
        if (b[0] == 0x48 && b[1] == 0x83 && b[2] == 0xec) return true;              // sub rsp, imm8
        if (b[0] == 0x48 && b[1] == 0x89 && b[2] == 0x5c && b[3] == 0x24) return true;  // mov [rsp+x], rbx (MSVC)
        if (b[0] == 0x40 && b[1] == 0x53 && b[2] == 0x48 && b[3] == 0x83) return true;  // push rbx; sub rsp
        return false;
    }


    bool jumpTable(const Image& img, const std::vector<Insn>& trail, std::vector<uint64_t>& targets, JTInfo& info) override {
        if (trail.size() < 3) return false;
        return arch_ == Arch::ARM64 ? jtArm64(img, trail, targets, info) : jtX86(img, trail, targets, info);
    }

private:
    // index of the most recent instruction before `from` whose first operand is register `reg` and mnemonic matches
    template <class Pred>
    int findBack(const std::vector<Insn>& t, int from, Pred p) const {
        for (int i = from; i >= 0 && i >= from - 14; --i)
            if (p(t[i])) return i;
        return -1;
    }

    bool jtArm64(const Image& img, const std::vector<Insn>& t, std::vector<uint64_t>& out, JTInfo& info) {
        const Insn& br = t.back();
        if (br.mnem != "br") return false;
        int T = a64Reg(trim(br.ops));
        if (T < 0) return false;
        int n = int(t.size()) - 2;

        int iAdd = findBack(t, n, [&](const Insn& i) {
            return i.mnem == "add" && a64Reg(splitTop(i.ops)[0]) == T;
        });
        if (iAdd < 0) return false;
        auto ap = splitTop(t[iAdd].ops);
        if (ap.size() < 3) return false;
        int A = a64Reg(ap[1]), B = a64Reg(ap[2]);
        int addShift = ap.size() > 3 ? shiftOf(ap[3]) : 0;
        if (A < 0 || B < 0) return false;

        int iLd = findBack(t, iAdd - 1, [&](const Insn& i) {
            return (i.mnem == "ldrsw" || i.mnem == "ldr" || i.mnem == "ldrb" || i.mnem == "ldrh" ||
                    i.mnem == "ldrsb" || i.mnem == "ldrsh") && !splitTop(i.ops).empty() &&
                   a64Reg(splitTop(i.ops)[0]) == B && i.ops.find('[') != std::string::npos;
        });
        if (iLd < 0) return false;
        auto lp = splitTop(t[iLd].ops);
        int base, idx, mshift;
        if (lp.size() < 2 || !memOperand(lp[1], base, idx, mshift)) return false;
        const std::string& lm = t[iLd].mnem;
        int stride = lm == "ldrsw" ? 4 : lm == "ldrb" || lm == "ldrsb" ? 1 : lm == "ldrh" || lm == "ldrsh" ? 2 : 4;
        bool sign = lm == "ldrsw" || lm == "ldrsb" || lm == "ldrsh";

        uint64_t tableBase = 0, anchor = 0;
        int iBase = findBack(t, iLd - 1, [&](const Insn& i) {
            auto p = splitTop(i.ops);
            return (i.mnem == "add" || i.mnem == "adr") && !p.empty() && a64Reg(p[0]) == base && lastDref(i);
        });
        if (iBase < 0) return false;
        tableBase = lastDref(t[iBase]);
        {
            // latest writer of A before the final add decides the anchor (adr, or the table-base add itself)
            int iA = findBack(t, iAdd - 1, [&](const Insn& i) {
                auto p = splitTop(i.ops);
                return !p.empty() && a64Reg(p[0]) == A && i.mnem != "cmp" && i.mnem != "str";
            });
            if (iA < 0) return false;
            if (t[iA].mnem == "adr" && lastDref(t[iA])) anchor = lastDref(t[iA]);
            else if (iA == iBase) anchor = tableBase;
            else return false;
        }

        // bounds: cmp wN, #K ; b.hi/b.hs default
        size_t count = 0;
        for (int i = int(t.size()) - 2; i >= 1 && i >= int(t.size()) - 16; --i) {
            if ((t[i].mnem == "b.hi" || t[i].mnem == "b.hs" || t[i].mnem == "b.ls" || t[i].mnem == "b.lo") &&
                t[i - 1].mnem == "cmp") {
                auto cp = splitTop(t[i - 1].ops);
                if (cp.size() == 2 && cp[1][0] == '#') {
                    int64_t k = immOf(cp[1]);
                    count = size_t(t[i].mnem == "b.hi" || t[i].mnem == "b.ls" ? k + 1 : k);
                    break;
                }
            }
        }
        size_t limit = count ? std::min<size_t>(count, 4096) : 256;
        for (size_t k = 0; k < limit; ++k) {
            uint64_t raw = 0;
            if (!img.read(tableBase + k * stride, &raw, stride)) break;
            int64_t v = int64_t(raw);
            if (sign) {
                int bits = stride * 8;
                v = (int64_t(raw << (64 - bits))) >> (64 - bits);
            }
            uint64_t tgt = anchor + uint64_t(v << addShift);
            if (!img.isCode(tgt) || tgt % 4) {
                if (count) { info.ordered.push_back(0); continue; }
                break;
            }
            info.ordered.push_back(tgt);
            out.push_back(tgt);
        }
        info.idxReg = "x" + std::to_string(idx);
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return !out.empty();
    }

    bool jtX86(const Image& img, const std::vector<Insn>& t, std::vector<uint64_t>& out, JTInfo& info) {
        const Insn& jmp = t.back();
        if (jmp.mnem != "jmp") return false;
        std::string op = trim(jmp.ops);
        const size_t psz = bits_ == 64 ? 8 : 4;

        // count from cmp/ja
        size_t count = 0;
        for (int i = int(t.size()) - 2; i >= 1 && i >= int(t.size()) - 14; --i) {
            if ((t[i].mnem == "ja" || t[i].mnem == "jae" || t[i].mnem == "jb" || t[i].mnem == "jbe") &&
                t[i - 1].mnem == "cmp") {
                auto cp = splitTop(t[i - 1].ops);
                if (cp.size() == 2 && (std::isdigit((unsigned char)cp[1][0]))) {
                    int64_t k = std::strtoll(cp[1].c_str(), nullptr, 0);
                    count = size_t(t[i].mnem == "ja" || t[i].mnem == "jbe" ? k + 1 : k);
                    break;
                }
            }
        }
        size_t limit = count ? std::min<size_t>(count, 4096) : 256;

        // jmp qword ptr [reg*8 + abs]
        size_t star = op.find("*");
        if (op.find('[') != std::string::npos && star != std::string::npos) {
            size_t plus = op.find("+ 0x", star);
            if (plus == std::string::npos) return false;
            uint64_t table = std::strtoull(op.c_str() + plus + 2, nullptr, 16);
            for (size_t k = 0; k < limit; ++k) {
                uint64_t v = 0;
                if (!img.read(table + k * psz, &v, psz)) break;
                if (!img.isCode(v)) { if (count) { info.ordered.push_back(0); continue; } break; }
                info.ordered.push_back(v);
                out.push_back(v);
            }
            {
                size_t lb = op.find('[');
                size_t sp = op.find('*', lb);
                if (lb != std::string::npos && sp != std::string::npos) info.idxReg = trim(op.substr(lb + 1, sp - lb - 1));
            }
        } else {
            // jmp rax ; add rax, rcx ; movsxd rax, dword ptr [rcx + rax*4] ; lea rcx, [rip + ...]
            if (op.empty() || !std::isalpha((unsigned char)op[0])) return false;
            int n = int(t.size()) - 2;
            int iAdd = findBack(t, n, [&](const Insn& i) {
                auto p = splitTop(i.ops);
                return i.mnem == "add" && p.size() == 2 && p[0] == op;
            });
            if (iAdd < 0) return false;
            std::string other = splitTop(t[iAdd].ops)[1];
            int iLd = findBack(t, iAdd - 1, [&](const Insn& i) {
                auto p = splitTop(i.ops);
                return i.mnem == "movsxd" && p.size() == 2 && p[0] == op && p[1].find("dword ptr") != std::string::npos;
            });
            if (iLd < 0) return false;
            int iLea = findBack(t, iLd - 1, [&](const Insn& i) {
                auto p = splitTop(i.ops);
                return i.mnem == "lea" && p.size() == 2 && p[0] == other && lastDref(i);
            });
            if (iLea < 0) return false;
            uint64_t table = lastDref(t[iLea]);
            for (size_t k = 0; k < limit; ++k) {
                int32_t v;
                if (!img.read(table + k * 4, &v, 4)) break;
                uint64_t tgt = table + uint64_t(int64_t(v));
                if (!img.isCode(tgt)) { if (count) { info.ordered.push_back(0); continue; } break; }
                info.ordered.push_back(tgt);
                out.push_back(tgt);
            }
            {
                auto lp = splitTop(t[iLd].ops);
                size_t lb = lp[1].find('['), sp = lp[1].find('*');
                size_t plus = lp[1].find('+', lb);
                if (lb != std::string::npos && sp != std::string::npos && plus != std::string::npos && plus < sp)
                    info.idxReg = trim(lp[1].substr(plus + 1, sp - plus - 1));
            }
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return !out.empty();
    }

    void classifyArm64(const Image& img, DecodeCtx& ctx, Insn& out) {
        const cs_arm64& d = insn_->detail->arm64;
        const std::string& m = out.mnem;
        auto lastImm = [&](uint64_t& t) {
            for (int i = d.op_count - 1; i >= 0; --i)
                if (d.operands[i].type == ARM64_OP_IMM) { t = uint64_t(d.operands[i].imm); return true; }
            return false;
        };
        uint64_t t = 0;
        if (m == "b") {
            if (lastImm(t)) { out.flow = Flow::Jmp; out.hasTarget = true; out.target = t; }
        } else if (startsWith(m, "b.") || startsWith(m, "bc.") || m == "cbz" || m == "cbnz" || m == "tbz" || m == "tbnz") {
            if (lastImm(t)) { out.flow = Flow::CJmp; out.hasTarget = true; out.target = t; }
        } else if (m == "bl") {
            if (lastImm(t)) { out.flow = Flow::Call; out.hasTarget = true; out.target = t; }
        } else if (startsWith(m, "blr")) {
            out.flow = Flow::ICall;
        } else if (m == "br" || startsWith(m, "bra") ) {
            out.flow = Flow::IJmp;
        } else if (startsWith(m, "ret") || startsWith(m, "eret") || m == "drps") {
            out.flow = Flow::Ret;
        } else if (m == "brk" || m == "udf" || m == "hlt") {
            out.flow = Flow::Trap;
        }

        // address materialisation: adrp/adr/add pairs and base+disp memory operands
        unsigned id = insn_->id;
        if (id == ARM64_INS_ADRP || id == ARM64_INS_ADR) {
            if (d.op_count == 2 && d.operands[0].type == ARM64_OP_REG && d.operands[1].type == ARM64_OP_IMM) {
                uint64_t page = uint64_t(d.operands[1].imm);
                ctx.regs[d.operands[0].reg] = page;
                if (id == ARM64_INS_ADR && img.isMapped(page)) out.drefs.push_back({page, 'o'});
            }
            return;
        }
        if (id == ARM64_INS_ADD && d.op_count == 3 && d.operands[0].type == ARM64_OP_REG &&
            d.operands[1].type == ARM64_OP_REG && d.operands[2].type == ARM64_OP_IMM) {
            auto it = ctx.regs.find(d.operands[1].reg);
            if (it != ctx.regs.end()) {
                uint64_t a = it->second + uint64_t(d.operands[2].imm);
                ctx.regs[d.operands[0].reg] = a;
                if (img.isMapped(a)) out.drefs.push_back({a, 'o'});
                return;
            }
        }
        for (int i = 0; i < d.op_count; ++i) {
            const cs_arm64_op& op = d.operands[i];
            if (op.type == ARM64_OP_MEM && op.mem.base != ARM64_REG_INVALID && op.mem.index == ARM64_REG_INVALID) {
                auto it = ctx.regs.find(op.mem.base);
                if (it != ctx.regs.end()) {
                    uint64_t a = it->second + uint64_t(int64_t(op.mem.disp));
                    if (img.isMapped(a)) {
                        bool store = startsWith(m, "st");
                        out.drefs.push_back({a, store ? 'w' : 'r'});
                    }
                }
            } else if (op.type == ARM64_OP_IMM && (id == ARM64_INS_LDR || id == ARM64_INS_LDRSW) && i == 1) {
                uint64_t a = uint64_t(op.imm);   // ldr literal
                if (img.isMapped(a)) out.drefs.push_back({a, 'r'});
            }
        }
        // any other write to a tracked register invalidates it
        if (d.op_count > 0 && d.operands[0].type == ARM64_OP_REG && !startsWith(m, "st") && !startsWith(m, "cmp") &&
            !startsWith(m, "tst") && !startsWith(m, "cmn") && out.flow == Flow::Normal)
            ctx.regs.erase(d.operands[0].reg);
        if (out.flow == Flow::Call || out.flow == Flow::ICall) {
            // caller-saved registers die across calls
            ctx.regs.clear();
        }
    }

    void classifyX86(const Image& img, DecodeCtx&, Insn& out) {
        const cs_x86& d = insn_->detail->x86;
        const std::string& m = out.mnem;
        bool jump = false, call = false, ret = false;
        for (int i = 0; i < insn_->detail->groups_count; ++i) {
            uint8_t g = insn_->detail->groups[i];
            if (g == CS_GRP_JUMP) jump = true;
            else if (g == CS_GRP_CALL) call = true;
            else if (g == CS_GRP_RET || g == CS_GRP_IRET) ret = true;
        }
        bool direct = d.op_count == 1 && d.operands[0].type == X86_OP_IMM;
        if (jump) {
            if (direct) {
                out.hasTarget = true;
                out.target = uint64_t(d.operands[0].imm);
                out.flow = (m == "jmp") ? Flow::Jmp : Flow::CJmp;
            } else {
                out.flow = (m == "jmp" || m == "ljmp") ? Flow::IJmp : Flow::CJmp;
            }
        } else if (call) {
            if (direct) { out.hasTarget = true; out.target = uint64_t(d.operands[0].imm); out.flow = Flow::Call; }
            else out.flow = Flow::ICall;
        } else if (ret) {
            out.flow = Flow::Ret;
        } else if (m == "hlt" || m == "ud2" || m == "int3" || m == "ud1" || m == "ud0") {
            out.flow = Flow::Trap;
        } else if (m == "add" && out.ops == "byte ptr [rax], al") {
            out.flow = Flow::Trap;   // 00 00: zero padding, not code
        }

        bool isLea = m == "lea";
        for (int i = 0; i < d.op_count; ++i) {
            const cs_x86_op& op = d.operands[i];
            if (op.type == X86_OP_MEM) {
                uint64_t a = 0;
                bool ok = false;
                if (op.mem.base == X86_REG_RIP) {
                    a = out.addr + out.size + uint64_t(int64_t(op.mem.disp));
                    ok = true;
                } else if (op.mem.base == X86_REG_INVALID && op.mem.index == X86_REG_INVALID && op.mem.disp > 0 &&
                           op.mem.segment == X86_REG_INVALID) {
                    a = uint64_t(op.mem.disp);
                    ok = bits_ == 32;
                }
                if (ok && img.isMapped(a)) {
                    char kind = 'r';
                    if (isLea) kind = 'o';
                    else if (op.access & CS_AC_WRITE) kind = 'w';
                    out.drefs.push_back({a, kind});
                }
            } else if (op.type == X86_OP_IMM && bits_ == 32 && out.flow == Flow::Normal) {
                uint64_t a = uint64_t(uint32_t(op.imm));
                if (img.isMapped(a) && !img.isCode(out.addr) == false && a >= 0x1000) out.drefs.push_back({a, 'o'});
            }
        }
    }

    Arch arch_;
    unsigned bits_;
    csh h_ = 0;
    cs_insn* insn_ = nullptr;
};

}  // namespace

std::unique_ptr<Proc> Proc::create(Arch a, unsigned bits) {
    if (a != Arch::ARM64 && a != Arch::X86_64 && a != Arch::X86) return nullptr;
    return std::make_unique<CsProc>(a, bits);
}

}  // namespace er
