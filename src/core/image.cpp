#include "core/image.h"

#include <algorithm>
#include <cstring>

namespace er {

const char* archName(Arch a) {
    switch (a) {
        case Arch::X86: return "x86";
        case Arch::X86_64: return "x86_64";
        case Arch::ARM64: return "arm64";
        case Arch::ARM: return "arm";
        default: return "unknown";
    }
}

Arch archFromName(const std::string& s) {
    if (s == "x86") return Arch::X86;
    if (s == "x86_64" || s == "x64" || s == "amd64") return Arch::X86_64;
    if (s == "arm64" || s == "aarch64" || s == "arm64e") return Arch::ARM64;
    if (s == "arm") return Arch::ARM;
    return Arch::Unknown;
}

void Image::finalize() {
    // sanitize: drop absurd segments, clip sections to real (and, for code, file-backed) memory
    segments.erase(std::remove_if(segments.begin(), segments.end(), [](const Segment& s) {
                       return s.size == 0 || s.size > (1ull << 32) || s.addr + s.size < s.addr;
                   }), segments.end());
    for (auto& sec : sections) {
        const Segment* g = nullptr;
        for (const auto& s : segments)
            if (sec.addr >= s.addr && sec.addr - s.addr < s.size) { g = &s; break; }
        if (!g) { sec.size = 0; continue; }
        sec.size = std::min<uint64_t>(sec.size, g->addr + g->size - sec.addr);
        if (sec.kind == SecKind::Code || sec.kind == SecKind::Stub) {
            uint64_t backedEnd = g->addr + g->data.size();
            sec.size = sec.addr >= backedEnd ? 0 : std::min<uint64_t>(sec.size, backedEnd - sec.addr);
        }
    }
    sections.erase(std::remove_if(sections.begin(), sections.end(), [](const Section& s) { return s.size == 0; }), sections.end());
    std::sort(segments.begin(), segments.end(),
              [](const Segment& a, const Segment& b) { return a.addr < b.addr; });
    std::stable_sort(sections.begin(), sections.end(),
                     [](const Section& a, const Section& b) { return a.addr < b.addr; });
    std::sort(funcStarts.begin(), funcStarts.end());
    funcStarts.erase(std::unique(funcStarts.begin(), funcStarts.end()), funcStarts.end());
}

const Segment* Image::segAt(uint64_t va) const {
    for (const auto& s : segments)
        if (va >= s.addr && va - s.addr < s.size) return &s;
    return nullptr;
}

Segment* Image::segAtMut(uint64_t va) {
    return const_cast<Segment*>(static_cast<const Image*>(this)->segAt(va));
}

const Section* Image::secAt(uint64_t va) const {
    auto it = std::upper_bound(sections.begin(), sections.end(), va,
                               [](uint64_t v, const Section& s) { return v < s.addr; });
    // sections may nest/overlap in odd binaries; walk back a few
    for (int i = 0; i < 4 && it != sections.begin(); ++i) {
        --it;
        if (va >= it->addr && va - it->addr < it->size) return &*it;
    }
    return nullptr;
}

bool Image::isCode(uint64_t va) const {
    const Section* s = secAt(va);
    if (s) return s->kind == SecKind::Code || s->kind == SecKind::Stub;
    // stripped / sectionless images: fall back to segment permissions
    const Segment* g = segAt(va);
    return g && (g->perms & P_X) && sections.empty();
}

bool Image::isCStringSec(uint64_t va) const {
    const Section* s = secAt(va);
    return s && s->kind == SecKind::CString;
}

size_t Image::readSome(uint64_t va, void* out, size_t n) const {
    auto* o = static_cast<uint8_t*>(out);
    size_t got = 0;
    while (got < n) {
        const Segment* s = segAt(va + got);
        if (!s) break;
        uint64_t off = va + got - s->addr;
        size_t take = static_cast<size_t>(std::min<uint64_t>(n - got, s->size - off));
        size_t backed = 0;
        if (off < s->data.size())
            backed = static_cast<size_t>(std::min<uint64_t>(take, s->data.size() - off));
        if (backed) std::memcpy(o + got, &s->data[off], backed);
        if (take > backed) std::memset(o + got + backed, 0, take - backed);
        got += take;
    }
    return got;
}

uint64_t Image::readPtr(uint64_t va) const {
    uint64_t v = 0;
    size_t n = bits == 64 ? 8 : 4;
    if (!read(va, &v, n)) return 0;
    return v;
}

bool Image::write(uint64_t va, const void* in, size_t n) {
    Segment* s = segAtMut(va);
    if (!s) return false;
    uint64_t off = va - s->addr;
    if (off + n > s->data.size()) return false;
    std::memcpy(&s->data[off], in, n);
    return true;
}

bool Image::readCString(uint64_t va, std::string& out, size_t max) const {
    out.clear();
    for (size_t i = 0; i < max; ++i) {
        uint8_t c;
        if (!read(va + i, &c, 1)) return false;
        if (c == 0) return true;
        out.push_back(static_cast<char>(c));
    }
    return false;
}

}  // namespace er
