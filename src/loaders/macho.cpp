// Mach-O loader: thin and fat, 64-bit. Handles segments/sections, symbol table,
// stub + pointer-slot naming through the indirect symbol table, LC_FUNCTION_STARTS,
// LC_MAIN, and chained fixups (rebases are applied in place, binds name the slot).
#include <algorithm>
#include <map>

#include "loaders/loader.h"

namespace er {
namespace {

constexpr uint32_t CPU_ARM64 = 0x0100000c;
constexpr uint32_t CPU_X86_64 = 0x01000007;

constexpr uint32_t LC_SEGMENT_64 = 0x19;
constexpr uint32_t LC_SYMTAB = 0x2;
constexpr uint32_t LC_DYSYMTAB = 0xb;
constexpr uint32_t LC_FUNCTION_STARTS = 0x26;
constexpr uint32_t LC_MAIN = 0x80000028;
constexpr uint32_t LC_DYLD_CHAINED_FIXUPS = 0x80000034;

SecKind sectionKind(uint32_t flags) {
    uint32_t type = flags & 0xff;
    if (type == 0x1 || type == 0xc || type == 0x12) return SecKind::Bss;
    if (type == 0x8) return SecKind::Stub;
    if (flags & (0x80000000u | 0x400u)) return SecKind::Code;
    if (type == 0x2) return SecKind::CString;
    if (type == 0x6 || type == 0x7 || type == 0x9 || type == 0xa || type == 0x16) return SecKind::Ptr;
    return SecKind::Data;
}

struct RawSection {
    std::string name, seg;
    uint64_t addr = 0, size = 0;
    uint32_t flags = 0, reserved1 = 0, reserved2 = 0;
};

uint64_t uleb(const Reader& f, size_t& p, size_t end) {
    uint64_t v = 0;
    int shift = 0;
    while (p < end) {
        uint8_t b = f.u8(p++);
        v |= uint64_t(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
        if (shift > 63) break;
    }
    return v;
}

// Resolves a rebase target that may be a vmaddr or a runtime offset from the image base.
uint64_t resolveRebase(const Image& img, uint64_t t) {
    if (t >= img.base && img.isMapped(t)) return t;
    return img.base + t;
}

void applyChainedFixups(Image& img, const Reader& f, size_t off, size_t size) {
    if (size < 28) return;
    uint32_t startsOff = f.u32(off + 4), importsOff = f.u32(off + 8), symsOff = f.u32(off + 12);
    uint32_t importsCount = std::min<uint32_t>(f.u32(off + 16), uint32_t(size / 4)), importsFmt = f.u32(off + 20);

    std::vector<std::string> imports;
    imports.reserve(importsCount);
    for (uint32_t i = 0; i < importsCount; ++i) {
        uint32_t nameOff = 0;
        if (importsFmt == 1 || importsFmt == 2) {
            size_t stride = importsFmt == 1 ? 4 : 8;
            nameOff = f.u32(off + importsOff + stride * i) >> 9;
        } else if (importsFmt == 3) {
            nameOff = uint32_t(f.u64(off + importsOff + 16ull * i) >> 32);
        } else {
            return;
        }
        imports.push_back(f.cstr(off + symsOff + nameOff));
    }

    size_t si0 = off + startsOff;
    uint32_t segCount = std::min<uint32_t>(f.u32(si0), 256);
    for (uint32_t s = 0; s < segCount; ++s) {
        uint32_t segInfoOff = f.u32(si0 + 4 + 4ull * s);
        if (!segInfoOff) continue;
        size_t si = si0 + segInfoOff;
        uint32_t pageSize = f.u16(si + 4);
        uint16_t fmt = f.u16(si + 6);
        uint64_t segOffset = f.u64(si + 8);
        uint16_t pageCount = f.u16(si + 20);
        if (!pageSize) continue;
        bool arm64e = fmt == 1 || fmt == 9 || fmt == 12;
        bool p64 = fmt == 2 || fmt == 6;
        if (!arm64e && !p64) continue;
        size_t stride = arm64e ? 8 : 4;

        for (uint16_t pg = 0; pg < pageCount; ++pg) {
            uint16_t ps = f.u16(si + 22 + 2ull * pg);
            if (ps == 0xFFFF || (ps & 0x8000)) continue;
            uint64_t addr = img.base + segOffset + uint64_t(pg) * pageSize + ps;
            for (uint32_t guard = 0; guard <= pageSize / stride + 1; ++guard) {
                uint64_t v = 0;
                if (!img.read(addr, &v, 8)) break;
                uint64_t next = 0, newv = 0;
                bool bind = false;
                uint32_t ordinal = 0;
                if (p64) {
                    bind = v >> 63;
                    next = (v >> 51) & 0xfff;
                    if (bind) {
                        ordinal = uint32_t(v & 0xffffff);
                    } else {
                        uint64_t t = v & 0xfffffffffull;
                        newv = (fmt == 6) ? img.base + t : t;
                    }
                } else {
                    bool auth = v >> 63;
                    bind = (v >> 62) & 1;
                    next = (v >> 51) & 0x7ff;
                    if (bind) {
                        ordinal = uint32_t(v & (fmt == 12 ? 0xffffff : 0xffff));
                    } else if (auth) {
                        newv = img.base + (v & 0xffffffffull);
                    } else {
                        newv = resolveRebase(img, v & 0x7ffffffffffull);
                    }
                }
                if (bind) {
                    if (ordinal < imports.size()) {
                        Symbol sym;
                        sym.name = imports[ordinal] + "_ptr";
                        sym.addr = addr;
                        sym.kind = SymKind::ImportPtr;
                        img.symbols.push_back(sym);
                    }
                    newv = 0;
                }
                img.write(addr, &newv, 8);
                if (!next) break;
                addr += next * stride;
            }
        }
    }
}

}  // namespace

bool loadMachO(const std::vector<uint8_t>& file, const LoadOptions& opt, Image& img, std::string& err) {
    Reader f{file.data(), file.size()};
    size_t so = 0, ss = file.size();

    uint32_t magic = f.u32(0);
    if (magic == 0xbebafeca || magic == 0xbfbafeca) {
        bool wide = magic == 0xbfbafeca;
        auto be32 = [](uint32_t v) { return __builtin_bswap32(v); };
        auto be64 = [](uint64_t v) { return __builtin_bswap64(v); };
        uint32_t n = be32(f.u32(4));
        struct Cand { uint32_t cpu, sub; uint64_t off, size; };
        std::vector<Cand> cands;
        size_t p = 8;
        for (uint32_t i = 0; i < n && i < 32; ++i) {
            Cand c{};
            c.cpu = be32(f.u32(p));
            c.sub = be32(f.u32(p + 4)) & 0xff;
            if (wide) {
                c.off = be64(f.u64(p + 8));
                c.size = be64(f.u64(p + 16));
                p += 32;
            } else {
                c.off = be32(f.u32(p + 8));
                c.size = be32(f.u32(p + 12));
                p += 20;
            }
            cands.push_back(c);
        }
        uint32_t want = 0;
        Arch pref = archFromName(opt.arch);
        bool wantE = opt.arch == "arm64e";
        if (pref == Arch::ARM64) want = CPU_ARM64;
        else if (pref == Arch::X86_64) want = CPU_X86_64;
        const Cand* pick = nullptr;
        if (want) {
            // exact subtype first (arm64 vs arm64e), then any slice of that cputype
            for (auto& c : cands)
                if (c.cpu == want && (want != CPU_ARM64 || (c.sub == 2) == wantE)) { pick = &c; break; }
            if (!pick) for (auto& c : cands) if (c.cpu == want) { pick = &c; break; }
            if (!pick) { err = "requested arch not in fat binary"; return false; }
        } else {
            for (auto& c : cands) if (c.cpu == CPU_ARM64 && c.sub != 2) { pick = &c; break; }
            if (!pick) for (auto& c : cands) if (c.cpu == CPU_ARM64) { pick = &c; break; }
            if (!pick) for (auto& c : cands) if (c.cpu == CPU_X86_64) { pick = &c; break; }
        }
        if (!pick) { err = "no supported slice (need arm64 or x86_64)"; return false; }
        so = pick->off;
        ss = pick->size;
        magic = f.u32(so);
    }
    if (magic != 0xfeedfacf) { err = "only 64-bit Mach-O is supported"; return false; }

    uint32_t cpu = f.u32(so + 4);
    if (cpu == CPU_ARM64) img.arch = Arch::ARM64;
    else if (cpu == CPU_X86_64) img.arch = Arch::X86_64;
    else { err = "unsupported cputype"; return false; }
    img.format = "Mach-O";
    img.bits = 64;

    uint32_t ncmds = std::min<uint32_t>(f.u32(so + 16), 4096);
    size_t p = so + 32;

    std::vector<RawSection> raw;
    uint64_t textBase = 0;
    bool haveText = false;
    uint32_t symoff = 0, nsyms = 0, stroff = 0, strsize = 0;
    uint32_t indOff = 0, nInd = 0;
    uint32_t fsOff = 0, fsSize = 0;
    uint32_t cfOff = 0, cfSize = 0;
    uint64_t entryOff = 0;
    bool haveMain = false;

    for (uint32_t i = 0; i < ncmds; ++i) {
        uint32_t cmd = f.u32(p), sz = f.u32(p + 4);
        if (sz < 8 || p + sz > so + ss) break;
        switch (cmd) {
            case LC_SEGMENT_64: {
                std::string name = f.fixedStr(p + 8, 16);
                uint64_t vmaddr = f.u64(p + 24), vmsize = f.u64(p + 32);
                uint64_t fileoff = f.u64(p + 40), filesize = f.u64(p + 48);
                uint32_t initprot = f.u32(p + 60), nsects = f.u32(p + 64);
                nsects = std::min<uint32_t>(nsects, sz > 72 ? (sz - 72) / 80 : 0);
                if (name == "__TEXT" && !haveText) { textBase = vmaddr; haveText = true; }
                if (initprot != 0 && vmsize != 0 && vmsize <= (1ull << 32) && vmaddr + vmsize > vmaddr) {
                    Segment seg;
                    seg.name = name;
                    seg.addr = vmaddr;
                    seg.size = vmsize;
                    if (initprot & 1) seg.perms |= P_R;
                    if (initprot & 2) seg.perms |= P_W;
                    if (initprot & 4) seg.perms |= P_X;
                    if (filesize) { seg.data = f.slice(so + fileoff, std::min(filesize, vmsize)); seg.fileoff = so + fileoff; seg.hasFile = true; }
                    img.segments.push_back(std::move(seg));
                }
                size_t sp = p + 72;
                for (uint32_t s = 0; s < nsects; ++s, sp += 80) {
                    RawSection rs;
                    rs.name = f.fixedStr(sp, 16);
                    rs.seg = f.fixedStr(sp + 16, 16);
                    rs.addr = f.u64(sp + 32);
                    rs.size = f.u64(sp + 40);
                    rs.flags = f.u32(sp + 64);
                    rs.reserved1 = f.u32(sp + 68);
                    rs.reserved2 = f.u32(sp + 72);
                    raw.push_back(rs);
                }
                break;
            }
            case LC_SYMTAB:
                symoff = f.u32(p + 8); nsyms = f.u32(p + 12);
                stroff = f.u32(p + 16); strsize = f.u32(p + 20);
                break;
            case LC_DYSYMTAB:
                indOff = f.u32(p + 56); nInd = f.u32(p + 60);
                break;
            case LC_FUNCTION_STARTS:
                fsOff = f.u32(p + 8); fsSize = f.u32(p + 12);
                break;
            case LC_DYLD_CHAINED_FIXUPS:
                cfOff = f.u32(p + 8); cfSize = f.u32(p + 12);
                break;
            case LC_MAIN:
                entryOff = f.u64(p + 8);
                haveMain = true;
                break;
        }
        p += sz;
    }
    if (img.segments.empty()) { err = "no loadable segments"; return false; }
    img.base = textBase;
    if (haveMain && haveText) { img.entry = textBase + entryOff; img.hasEntry = true; }

    for (auto& rs : raw) {
        Section s;
        s.name = rs.seg + "," + rs.name;
        s.seg = rs.seg;
        s.addr = rs.addr;
        s.size = rs.size;
        s.kind = sectionKind(rs.flags);
        img.sections.push_back(s);
    }
    img.finalize();   // sections sorted so Image::isCode works while loading

    // symbol table
    if (symoff >= ss) nsyms = 0;
    nsyms = std::min<uint32_t>(nsyms, uint32_t((ss - std::min<size_t>(symoff, ss)) / 16));
    std::vector<std::string> symNames(nsyms);
    for (uint32_t i = 0; i < nsyms; ++i) {
        size_t e = so + symoff + 16ull * i;
        uint32_t strx = f.u32(e);
        uint8_t type = f.u8(e + 4);
        uint64_t value = f.u64(e + 8);
        if (strx >= strsize) continue;
        std::string name = f.cstr(so + stroff + strx);
        symNames[i] = name;
        if (type & 0xe0) continue;          // N_STAB
        if (name.empty()) continue;
        if ((type & 0x0e) == 0x0e) {        // N_SECT
            if (name.rfind("ltmp", 0) == 0 || name.rfind("l_", 0) == 0) continue;
            Symbol s;
            s.name = name;
            s.addr = value;
            s.kind = img.isCode(value) ? SymKind::Func : SymKind::Data;
            s.exported = type & 1;
            img.symbols.push_back(s);
        }
    }

    // stubs + lazy/non-lazy pointers via the indirect symbol table
    for (auto& rs : raw) {
        uint32_t type = rs.flags & 0xff;
        bool isStub = type == 0x8, isPtr = type == 0x6 || type == 0x7;
        if (!isStub && !isPtr) continue;
        uint32_t elem = isStub ? rs.reserved2 : 8;
        if (!elem) continue;
        uint64_t count = rs.size / elem;
        for (uint64_t k = 0; k < count; ++k) {
            uint64_t idx = rs.reserved1 + k;
            if (idx >= nInd) break;
            uint32_t symIdx = f.u32(so + indOff + 4 * idx);
            if (symIdx & 0xC0000000u) continue;   // local / abs
            if (symIdx >= nsyms || symNames[symIdx].empty()) continue;
            Symbol s;
            s.addr = rs.addr + k * elem;
            if (isStub) { s.name = symNames[symIdx]; s.kind = SymKind::ImportFunc; }
            else { s.name = symNames[symIdx] + "_ptr"; s.kind = SymKind::ImportPtr; }
            img.symbols.push_back(s);
        }
    }

    if (cfSize) applyChainedFixups(img, f, so + cfOff, cfSize);
    parseObjC(img);

    // function starts: ULEB deltas from the Mach header
    if (fsSize && haveText) {
        size_t q = so + fsOff, end = q + fsSize;
        uint64_t addr = textBase;
        while (q < end) {
            uint64_t d = uleb(f, q, end);
            if (!d) break;
            addr += d;
            img.funcStarts.push_back(addr);
        }
    }
    return true;
}

}  // namespace er
