// Assembler bridge. Keystone is GPL-2.0, so it is NOT linked: it is loaded at runtime (dlopen) when the
// user has it installed (`brew install keystone`). Without it, `asm` reports how to enable it and
// raw `patch` keeps working.
#include "core/asm.h"

#include <dlfcn.h>

#include <cstdlib>

namespace er {
namespace {

// minimal slice of the Keystone C API (constants copied from keystone.h, stable since 0.9)
constexpr int KS_ARCH_ARM64 = 2;
constexpr int KS_ARCH_X86 = 4;
constexpr int KS_MODE_LITTLE_ENDIAN = 0;
constexpr int KS_MODE_32 = 1 << 2;
constexpr int KS_MODE_64 = 1 << 3;

struct Ks {
    void* lib = nullptr;
    int (*open)(int, int, void**) = nullptr;
    int (*asmFn)(void*, const char*, uint64_t, unsigned char**, size_t*, size_t*) = nullptr;
    void (*free)(unsigned char*) = nullptr;
    int (*close)(void*) = nullptr;
    int (*err)(void*) = nullptr;
    const char* (*strerror)(int) = nullptr;
    bool ok() const { return lib && open && asmFn && free && close && err && strerror; }
};

Ks& loadKs() {
    static Ks k;
    static bool tried = false;
    if (tried) return k;
    tried = true;
    const char* env = std::getenv("EREBUS_KEYSTONE");
    const char* paths[] = {env, "libkeystone.dylib", "libkeystone.0.dylib", "/opt/homebrew/lib/libkeystone.dylib",
                           "/usr/local/lib/libkeystone.dylib", "libkeystone.so", "libkeystone.so.0"};
    for (const char* p : paths) {
        if (!p) continue;
        k.lib = dlopen(p, RTLD_LAZY | RTLD_LOCAL);
        if (k.lib) break;
    }
    if (!k.lib) return k;
    k.open = reinterpret_cast<decltype(k.open)>(dlsym(k.lib, "ks_open"));
    k.asmFn = reinterpret_cast<decltype(k.asmFn)>(dlsym(k.lib, "ks_asm"));
    k.free = reinterpret_cast<decltype(k.free)>(dlsym(k.lib, "ks_free"));
    k.close = reinterpret_cast<decltype(k.close)>(dlsym(k.lib, "ks_close"));
    k.err = reinterpret_cast<decltype(k.err)>(dlsym(k.lib, "ks_errno"));
    k.strerror = reinterpret_cast<decltype(k.strerror)>(dlsym(k.lib, "ks_strerror"));
    return k;
}

}  // namespace

bool assemblerAvailable() { return loadKs().ok(); }

bool assembleText(Arch arch, unsigned bits, uint64_t addr, const std::string& text, std::vector<uint8_t>& out,
                  std::string& err) {
    (void)bits;
    int ka, km;
    switch (arch) {
        case Arch::ARM64: ka = KS_ARCH_ARM64; km = KS_MODE_LITTLE_ENDIAN; break;
        case Arch::X86_64: ka = KS_ARCH_X86; km = KS_MODE_64; break;
        case Arch::X86: ka = KS_ARCH_X86; km = KS_MODE_32; break;
        default: err = "no assembler for this architecture"; return false;
    }
    Ks& k = loadKs();
    if (!k.ok()) {
        err = "assembler unavailable: install Keystone (brew install keystone) or use `patch` with raw bytes";
        return false;
    }
    void* ks = nullptr;
    if (k.open(ka, km, &ks) != 0) { err = "cannot start assembler"; return false; }
    unsigned char* enc = nullptr;
    size_t size = 0, count = 0;
    int rc = k.asmFn(ks, text.c_str(), addr, &enc, &size, &count);
    bool ok = rc == 0 && enc && size > 0;
    if (ok) out.assign(enc, enc + size);
    else err = std::string("assembler: ") + k.strerror(k.err(ks));
    if (enc) k.free(enc);
    k.close(ks);
    return ok;
}

}  // namespace er
