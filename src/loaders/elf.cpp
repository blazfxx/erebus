// ELF loader (32/64-bit little-endian). Segments from PT_LOAD, sections for kinds,
// .symtab/.dynsym symbols, PLT stub + GOT slot naming from relocations (64-bit).
#include <algorithm>
#include <map>

#include "loaders/loader.h"

namespace er {
namespace {

struct Shdr {
    uint32_t name = 0, type = 0;
    uint64_t flags = 0, addr = 0, off = 0, size = 0;
    uint32_t link = 0, info = 0;
    uint64_t entsize = 0;
};

SecKind elfKind(const Shdr& s, const std::string& name) {
    if (s.type == 8) return SecKind::Bss;
    if (name.rfind(".plt", 0) == 0) return SecKind::Stub;
    if (s.flags & 4) return SecKind::Code;
    if (name == ".got" || name == ".got.plt" || s.type == 14 || s.type == 15 || s.type == 16) return SecKind::Ptr;
    if (name.rfind(".rodata", 0) == 0 || name.rfind(".cstring", 0) == 0) return SecKind::CString;
    return SecKind::Data;
}

}  // namespace

bool loadELF(const std::vector<uint8_t>& file, const LoadOptions&, Image& img, std::string& err) {
    Reader f{file.data(), file.size()};
    bool is64 = f.u8(4) == 2;
    if (f.u8(5) != 1) { err = "big-endian ELF not supported"; return false; }
    uint16_t machine = f.u16(18);
    switch (machine) {
        case 62: img.arch = Arch::X86_64; break;
        case 183: img.arch = Arch::ARM64; break;
        case 3: img.arch = Arch::X86; break;
        default: err = "unsupported ELF machine " + std::to_string(machine); return false;
    }
    img.format = "ELF";
    img.bits = is64 ? 64 : 32;

    uint64_t entry, phoff, shoff;
    uint16_t phentsize, phnum, shentsize, shnum, shstrndx;
    if (is64) {
        entry = f.u64(24); phoff = f.u64(32); shoff = f.u64(40);
        phentsize = f.u16(54); phnum = f.u16(56); shentsize = f.u16(58); shnum = f.u16(60); shstrndx = f.u16(62);
    } else {
        entry = f.u32(24); phoff = f.u32(28); shoff = f.u32(32);
        phentsize = f.u16(42); phnum = f.u16(44); shentsize = f.u16(46); shnum = f.u16(48); shstrndx = f.u16(50);
    }
    img.entry = entry;
    img.hasEntry = entry != 0;

    phnum = std::min<uint16_t>(phnum, 256);
    shnum = std::min<uint16_t>(shnum, 4096);
    uint64_t lowest = ~0ull;
    for (uint16_t i = 0; i < phnum; ++i) {
        size_t p = phoff + size_t(i) * phentsize;
        uint32_t type = f.u32(p);
        if (type != 1) continue;  // PT_LOAD
        uint32_t flags;
        uint64_t off, vaddr, filesz, memsz;
        if (is64) {
            flags = f.u32(p + 4); off = f.u64(p + 8); vaddr = f.u64(p + 16);
            filesz = f.u64(p + 32); memsz = f.u64(p + 40);
        } else {
            off = f.u32(p + 4); vaddr = f.u32(p + 8); filesz = f.u32(p + 16);
            memsz = f.u32(p + 20); flags = f.u32(p + 24);
        }
        if (memsz > (1ull << 32) || vaddr + memsz < vaddr) continue;
        Segment s;
        s.name = "LOAD" + std::to_string(img.segments.size());
        s.addr = vaddr;
        s.size = memsz;
        if (flags & 4) s.perms |= P_R;
        if (flags & 2) s.perms |= P_W;
        if (flags & 1) s.perms |= P_X;
        s.data = f.slice(off, std::min(filesz, memsz));
        s.fileoff = off; s.hasFile = true;
        img.segments.push_back(std::move(s));
        lowest = std::min(lowest, vaddr);
    }
    if (img.segments.empty()) { err = "no PT_LOAD segments"; return false; }
    img.base = lowest;

    // section headers
    std::vector<Shdr> sh(shnum);
    for (uint16_t i = 0; i < shnum && shoff; ++i) {
        size_t p = shoff + size_t(i) * shentsize;
        Shdr& s = sh[i];
        s.name = f.u32(p);
        s.type = f.u32(p + 4);
        if (is64) {
            s.flags = f.u64(p + 8); s.addr = f.u64(p + 16); s.off = f.u64(p + 24); s.size = f.u64(p + 32);
            s.link = f.u32(p + 40); s.info = f.u32(p + 44); s.entsize = f.u64(p + 56);
        } else {
            s.flags = f.u32(p + 8); s.addr = f.u32(p + 12); s.off = f.u32(p + 16); s.size = f.u32(p + 20);
            s.link = f.u32(p + 24); s.info = f.u32(p + 28); s.entsize = f.u32(p + 36);
        }
    }
    auto secName = [&](const Shdr& s) {
        if (shstrndx >= sh.size()) return std::string();
        return f.cstr(sh[shstrndx].off + s.name);
    };
    std::vector<std::string> names(shnum);
    for (uint16_t i = 0; i < shnum; ++i) {
        names[i] = secName(sh[i]);
        if (!(sh[i].flags & 2) || !sh[i].addr) continue;  // SHF_ALLOC
        Section s;
        s.name = names[i];
        s.addr = sh[i].addr;
        s.size = sh[i].size;
        s.kind = elfKind(sh[i], names[i]);
        const Segment* g = img.segAt(s.addr);
        if (g) s.seg = g->name;
        img.sections.push_back(s);
    }
    img.finalize();

    // symbols
    std::vector<std::string> dynNames;
    for (uint16_t i = 0; i < shnum; ++i) {
        if (sh[i].type != 2 && sh[i].type != 11) continue;  // SYMTAB / DYNSYM
        if (sh[i].link >= sh.size()) continue;
        const Shdr& strt = sh[sh[i].link];
        size_t esz = is64 ? 24 : 16;
        size_t count = std::min<size_t>(sh[i].size / esz, file.size() / esz);
        bool dyn = sh[i].type == 11;
        if (dyn) dynNames.assign(count, "");
        for (size_t k = 0; k < count; ++k) {
            size_t p = sh[i].off + k * esz;
            uint32_t nm = f.u32(p);
            uint8_t info;
            uint16_t shndx;
            uint64_t value;
            if (is64) { info = f.u8(p + 4); shndx = f.u16(p + 6); value = f.u64(p + 8); }
            else { value = f.u32(p + 4); info = f.u8(p + 12); shndx = f.u16(p + 14); }
            std::string name = f.cstr(strt.off + nm);
            if (dyn) dynNames[k] = name;
            uint8_t type = info & 0xf;
            if (name.empty() || shndx == 0 || shndx >= 0xff00) continue;
            if (type != 0 && type != 1 && type != 2) continue;
            Symbol s;
            s.name = name;
            s.addr = value;
            s.kind = (type == 2 || img.isCode(value)) ? SymKind::Func : SymKind::Data;
            s.exported = (info >> 4) != 0;
            img.symbols.push_back(s);
        }
    }

    // PLT stubs / GOT slots from relocations (64-bit only)
    if (is64 && !dynNames.empty()) {
        const Shdr* plt = nullptr; const Shdr* pltsec = nullptr;
        for (uint16_t i = 0; i < shnum; ++i) {
            if (names[i] == ".plt") plt = &sh[i];
            if (names[i] == ".plt.sec") pltsec = &sh[i];
        }
        for (uint16_t i = 0; i < shnum; ++i) {
            if (sh[i].type != 4) continue;  // SHT_RELA
            bool isPltRel = names[i] == ".rela.plt";
            size_t count = std::min<size_t>(sh[i].size / 24, file.size() / 24);
            for (size_t k = 0; k < count; ++k) {
                size_t p = sh[i].off + k * 24;
                uint64_t roff = f.u64(p), info = f.u64(p + 8);
                uint32_t symi = uint32_t(info >> 32), rtype = uint32_t(info);
                if (symi == 0 || symi >= dynNames.size() || dynNames[symi].empty()) continue;
                bool slot = (machine == 62) ? (rtype == 6 || rtype == 7 || rtype == 1)
                                            : (rtype == 1025 || rtype == 1026);
                if (slot && (rtype == 6 || rtype == 7 || rtype == 1025 || rtype == 1026)) {
                    Symbol s;
                    s.name = dynNames[symi] + "_ptr";
                    s.addr = roff;
                    s.kind = SymKind::ImportPtr;
                    img.symbols.push_back(s);
                }
                if (isPltRel) {
                    uint64_t stub = 0;
                    if (machine == 62) {
                        if (pltsec) stub = pltsec->addr + 16 * k;
                        else if (plt) stub = plt->addr + 16 * (k + 1);
                    } else if (plt) {
                        stub = plt->addr + 32 + 16 * k;
                    }
                    if (stub) {
                        Symbol s;
                        s.name = dynNames[symi];
                        s.addr = stub;
                        s.kind = SymKind::ImportFunc;
                        img.symbols.push_back(s);
                    }
                }
            }
        }
    }
    return true;
}

}  // namespace er
