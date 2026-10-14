// PE/COFF loader (PE32 and PE32+). Sections as segments, import slots named __imp_*,
// exports, and x64 .pdata function starts.
#include <algorithm>

#include "loaders/loader.h"

namespace er {
namespace {

struct PeSec {
    std::string name;
    uint32_t vsize = 0, va = 0, rawSize = 0, rawPtr = 0, chars = 0;
};

}  // namespace

bool loadPE(const std::vector<uint8_t>& file, const LoadOptions&, Image& img, std::string& err) {
    Reader f{file.data(), file.size()};
    uint32_t pe = f.u32(0x3c);
    if (f.u32(pe) != 0x00004550) { err = "bad PE signature"; return false; }
    uint16_t machine = f.u16(pe + 4), nsec = f.u16(pe + 6), optSize = f.u16(pe + 20);
    size_t opt = pe + 24;
    uint16_t magic = f.u16(opt);
    bool pe64 = magic == 0x20b;
    if (!pe64 && magic != 0x10b) { err = "bad optional header"; return false; }
    switch (machine) {
        case 0x8664: img.arch = Arch::X86_64; break;
        case 0x14c: img.arch = Arch::X86; break;
        case 0xaa64: img.arch = Arch::ARM64; break;
        default: err = "unsupported PE machine"; return false;
    }
    img.format = "PE";
    img.bits = pe64 ? 64 : 32;

    uint32_t entryRva = f.u32(opt + 16);
    uint64_t imageBase = pe64 ? f.u64(opt + 24) : f.u32(opt + 28);
    size_t ddBase = pe64 ? opt + 112 : opt + 96;
    uint32_t nDirs = f.u32(pe64 ? opt + 108 : opt + 92);
    auto dir = [&](unsigned i, uint32_t& rva, uint32_t& size) {
        rva = size = 0;
        if (i >= nDirs) return;
        rva = f.u32(ddBase + 8ull * i);
        size = f.u32(ddBase + 8ull * i + 4);
    };
    img.base = imageBase;
    img.entry = imageBase + entryRva;
    img.hasEntry = entryRva != 0;

    nsec = std::min<uint16_t>(nsec, 96);
    std::vector<PeSec> secs;
    size_t sp = opt + optSize;
    for (uint16_t i = 0; i < nsec; ++i, sp += 40) {
        PeSec s;
        s.name = f.fixedStr(sp, 8);
        s.vsize = f.u32(sp + 8);
        s.va = f.u32(sp + 12);
        s.rawSize = f.u32(sp + 16);
        s.rawPtr = f.u32(sp + 20);
        s.chars = f.u32(sp + 36);
        secs.push_back(s);

        uint64_t size = s.vsize ? s.vsize : s.rawSize;
        if (size > (1ull << 31)) continue;
        Segment g;
        g.name = s.name;
        g.addr = imageBase + s.va;
        g.size = size;
        if (s.chars & 0x40000000) g.perms |= P_R;
        if (s.chars & 0x80000000) g.perms |= P_W;
        if (s.chars & 0x20000000) g.perms |= P_X;
        if (s.rawPtr && s.rawSize) { g.data = f.slice(s.rawPtr, std::min<uint64_t>(s.rawSize, size)); g.fileoff = s.rawPtr; g.hasFile = true; }
        img.segments.push_back(std::move(g));

        Section sec;
        sec.name = s.name;
        sec.seg = s.name;
        sec.addr = imageBase + s.va;
        sec.size = size;
        if (s.chars & 0x20000000) sec.kind = SecKind::Code;
        else if (s.chars & 0x80) sec.kind = SecKind::Bss;
        else if (s.name == ".rdata" || s.name == ".rodata") sec.kind = SecKind::CString;
        else if (s.name == ".idata") sec.kind = SecKind::Ptr;
        else sec.kind = SecKind::Data;
        img.sections.push_back(sec);
    }
    if (img.segments.empty()) { err = "no sections"; return false; }
    img.finalize();

    auto rvaToOff = [&](uint32_t rva, size_t& off) {
        for (auto& s : secs) {
            uint32_t span = std::max(s.vsize, s.rawSize);
            if (rva >= s.va && rva - s.va < span) {
                off = s.rawPtr + (rva - s.va);
                return true;
            }
        }
        return false;
    };

    // imports
    uint32_t impRva, impSize;
    dir(1, impRva, impSize);
    size_t io;
    if (impRva && rvaToOff(impRva, io)) {
        for (int guard = 0; guard < 4096; ++guard, io += 20) {
            uint32_t oft = f.u32(io), nameRva = f.u32(io + 12), ft = f.u32(io + 16);
            if (!nameRva && !ft) break;
            size_t thunk;
            if (!rvaToOff(oft ? oft : ft, thunk)) break;
            size_t psz = pe64 ? 8 : 4;
            for (size_t k = 0; k < 65536; ++k) {
                uint64_t ent = pe64 ? f.u64(thunk + k * psz) : f.u32(thunk + k * psz);
                if (!ent) break;
                std::string nm;
                if (ent >> (pe64 ? 63 : 31)) {
                    nm = "ord" + std::to_string(ent & 0xffff);
                } else {
                    size_t no;
                    if (!rvaToOff(uint32_t(ent), no)) continue;
                    nm = f.cstr(no + 2);
                }
                Symbol s;
                s.name = "__imp_" + nm;
                s.addr = imageBase + ft + k * psz;
                s.kind = SymKind::ImportPtr;
                img.symbols.push_back(s);
            }
        }
    }

    // exports
    uint32_t expRva, expSize;
    dir(0, expRva, expSize);
    size_t eo;
    if (expRva && rvaToOff(expRva, eo)) {
        uint32_t nFuncs = f.u32(eo + 20), nNames = f.u32(eo + 24);
        uint32_t funcsRva = f.u32(eo + 28), namesRva = f.u32(eo + 32), ordsRva = f.u32(eo + 36);
        size_t fo, no, oo;
        if (rvaToOff(funcsRva, fo) && rvaToOff(namesRva, no) && rvaToOff(ordsRva, oo)) {
            for (uint32_t i = 0; i < nNames && i < 65536; ++i) {
                uint32_t nrva = f.u32(no + 4ull * i);
                uint16_t ord = f.u16(oo + 2ull * i);
                if (ord >= nFuncs) continue;
                uint32_t frva = f.u32(fo + 4ull * ord);
                size_t nameOff;
                if (!rvaToOff(nrva, nameOff)) continue;
                Symbol s;
                s.name = f.cstr(nameOff);
                s.addr = imageBase + frva;
                s.kind = SymKind::Func;
                s.exported = true;
                img.symbols.push_back(s);
            }
        }
    }

    // x64 exception directory: RUNTIME_FUNCTION table = authoritative function starts
    uint32_t excRva, excSize;
    dir(3, excRva, excSize);
    size_t xo;
    if (pe64 && excRva && rvaToOff(excRva, xo)) {
        for (uint32_t i = 0; i + 12 <= excSize; i += 12) {
            uint32_t begin = f.u32(xo + i);
            if (!begin) break;
            img.funcStarts.push_back(imageBase + begin);
        }
    }
    return true;
}

}  // namespace er
