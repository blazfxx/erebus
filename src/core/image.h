// Erebus core: loaded program image model (what a loader produces).
#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace er {

enum class Arch : uint8_t { Unknown, X86, X86_64, ARM64, ARM };

const char* archName(Arch a);
Arch archFromName(const std::string& s);

enum Perm : uint8_t { P_R = 1, P_W = 2, P_X = 4 };

enum class SecKind : uint8_t { Other, Code, Stub, CString, Data, Ptr, Bss };

struct Segment {
    std::string name;
    uint64_t addr = 0;
    uint64_t size = 0;            // size in memory
    uint8_t perms = 0;
    std::vector<uint8_t> data;    // file-backed bytes; may be shorter than size (rest is zero)
    uint64_t fileoff = 0;         // offset of data[0] inside the original file (absolute, includes fat slice offset)
    bool hasFile = false;
};

// A byte patch applied on top of the loaded image.
struct Patch {
    int64_t id = 0;
    uint64_t addr = 0;
    std::vector<uint8_t> orig, bytes;
};

struct Section {
    std::string name;
    std::string seg;
    uint64_t addr = 0;
    uint64_t size = 0;
    SecKind kind = SecKind::Other;
};

enum class SymKind : uint8_t { Func, Data, ImportFunc, ImportPtr };

struct Symbol {
    std::string name;
    uint64_t addr = 0;
    SymKind kind = SymKind::Func;
    bool exported = false;
};

struct Image {
    std::string path;
    std::string format;           // "Mach-O", "ELF", "PE"
    Arch arch = Arch::Unknown;
    unsigned bits = 64;
    uint64_t base = 0;
    uint64_t entry = 0;
    bool hasEntry = false;

    std::vector<Segment> segments;
    std::vector<Section> sections;   // sorted by address after finalize()
    std::vector<Symbol> symbols;
    std::vector<uint64_t> funcStarts; // loader-known function starts (unwind info, LC_FUNCTION_STARTS, ...)

    void finalize();                 // sort sections, dedupe

    const Segment* segAt(uint64_t va) const;
    Segment* segAtMut(uint64_t va);
    const Section* secAt(uint64_t va) const;

    bool isMapped(uint64_t va) const { return segAt(va) != nullptr; }
    bool isCode(uint64_t va) const;
    bool isCStringSec(uint64_t va) const;

    // Reads up to n bytes starting at va (zero-fills bss). Returns bytes produced
    // (stops at the first unmapped address).
    size_t readSome(uint64_t va, void* out, size_t n) const;
    bool read(uint64_t va, void* out, size_t n) const { return readSome(va, out, n) == n; }
    uint64_t readPtr(uint64_t va) const;       // pointer-sized little-endian read, 0 if unmapped
    bool write(uint64_t va, const void* in, size_t n);  // only into file-backed bytes

    // NUL-terminated string at va; returns false if unmapped or unterminated within max.
    bool readCString(uint64_t va, std::string& out, size_t max = 4096) const;
};

}  // namespace er
