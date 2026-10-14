// Loader registry: file bytes -> Image. One function per container format.
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "core/image.h"

namespace er {

struct LoadOptions {
    std::string arch;   // preferred slice for fat Mach-O ("arm64", "x86_64"); empty = auto
};

// Bounds-checked little-endian reader over a byte buffer.
struct Reader {
    const uint8_t* d = nullptr;
    size_t n = 0;

    template <class T> bool get(size_t off, T& v) const {
        if (off > n || n - off < sizeof(T)) return false;
        std::memcpy(&v, d + off, sizeof(T));
        return true;
    }
    uint8_t u8(size_t o) const { uint8_t v = 0; get(o, v); return v; }
    uint16_t u16(size_t o) const { uint16_t v = 0; get(o, v); return v; }
    uint32_t u32(size_t o) const { uint32_t v = 0; get(o, v); return v; }
    uint64_t u64(size_t o) const { uint64_t v = 0; get(o, v); return v; }
    std::string fixedStr(size_t o, size_t len) const {
        std::string s;
        for (size_t i = 0; i < len && o + i < n && d[o + i]; ++i) s.push_back(char(d[o + i]));
        return s;
    }
    std::string cstr(size_t o, size_t max = 1024) const {
        std::string s;
        for (size_t i = 0; i < max && o + i < n && d[o + i]; ++i) s.push_back(char(d[o + i]));
        return s;
    }
    std::vector<uint8_t> slice(size_t off, size_t len) const {
        if (off > n) return {};
        len = std::min(len, n - off);
        return std::vector<uint8_t>(d + off, d + off + len);
    }
};

bool loadMachO(const std::vector<uint8_t>& file, const LoadOptions& opt, Image& img, std::string& err);
bool loadELF(const std::vector<uint8_t>& file, const LoadOptions& opt, Image& img, std::string& err);
bool loadPE(const std::vector<uint8_t>& file, const LoadOptions& opt, Image& img, std::string& err);

// Objective-C metadata -> method symbols (called by the Mach-O loader).
void parseObjC(Image& img);

// Sniffs the container and dispatches. Returns null and sets err on failure.
std::unique_ptr<Image> loadFile(const std::string& path, const LoadOptions& opt, std::string& err);

}  // namespace er
