#pragma once
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cxxabi.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace er {

inline std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

inline std::string hexPlain(uint64_t v, int width = 0) {
    char b[24];
    std::snprintf(b, sizeof b, "%0*llx", width, static_cast<unsigned long long>(v));
    return b;
}

// Swift demangling goes through the toolchain's swift-demangle once per database load.
inline std::unordered_map<std::string, std::string>& swiftCache() {
    static std::unordered_map<std::string, std::string> c;
    return c;
}
void primeSwiftNames(const std::vector<std::string>& mangled);   // core/swiftdemangle.cpp

// Itanium C++ demangle (handles Mach-O's extra leading underscore). Returns input if not mangled.
inline std::string demangle(const std::string& n) {
    if (!swiftCache().empty()) {
        auto it = swiftCache().find(n);
        if (it != swiftCache().end()) return it->second;
    }
    const char* s = n.c_str();
    if (n.rfind("__Z", 0) == 0) s = s + 1;
    else if (n.rfind("_Z", 0) != 0) return n;
    int st = 0;
    char* d = abi::__cxa_demangle(s, nullptr, nullptr, &st);
    if (st != 0 || !d) return n;
    std::string r = d;
    std::free(d);
    return r;
}

}  // namespace er
