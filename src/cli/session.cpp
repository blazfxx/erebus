#include "cli/session.h"

#include <algorithm>
#include <cctype>

#include <fstream>
#include <iterator>

#include "core/asm.h"
#include "core/util.h"
#include "decomp/dcmodel.h"

namespace er {

bool Session::analyzeFile(const std::string& path, const std::string& dbPath, const LoadOptions& lo,
                          const AnalyzeOptions& ao, std::string& err) {
    auto loaded = loadFile(path, lo, err);
    if (!loaded) return false;
    img = std::move(*loaded);
    analyzeOpts = ao;
    proc = Proc::create(img.arch, img.bits);
    if (!proc) {
        err = std::string("no processor module for ") + archName(img.arch);
        return false;
    }
    an = Analysis{};
    analyze(img, *proc, an, ao);
    if (!db.create(dbPath, img, an, err)) return false;
    buildIndexes();
    return true;
}

bool Session::openDb(const std::string& dbPath, std::string& err) {
    if (!db.open(dbPath, err)) return false;
    if (!db.load(img, an, err)) return false;
    proc = Proc::create(img.arch, img.bits);
    if (!proc) {
        err = "no processor module for this architecture";
        return false;
    }
    db.loadPatches(patches);
    buildIndexes();
    return true;
}

void Session::buildIndexes() {
    if (swiftCache().empty()) {
        std::vector<std::string> sw;
        for (const auto& [a, n] : an.names) {
            const std::string& x = n.name;
            if (x.rfind("$s", 0) == 0 || x.rfind("_$s", 0) == 0 || x.rfind("__$s", 0) == 0 || x.rfind("$S", 0) == 0 || x.rfind("_$S", 0) == 0)
                sw.push_back(x);
        }
        primeSwiftNames(sw);
    }
    byName_.clear();
    for (const auto& [a, n] : an.names) {
        byName_.emplace(n.name, a);
        std::string d = demangle(n.name);
        if (d != n.name) byName_.emplace(d, a);
    }
    byDst_ = an.xrefs;
    std::sort(byDst_.begin(), byDst_.end(), [](const Xref& x, const Xref& y) {
        return x.to != y.to ? x.to < y.to : x.from < y.from;
    });
}

std::string Session::label(uint64_t addr) const {
    auto it = an.names.find(addr);
    if (it != an.names.end()) return demangle(it->second.name);
    if (an.funcs.count(addr)) return "sub_" + hexPlain(addr);
    if (funcAt(addr)) return "loc_" + hexPlain(addr);
    if (img.isCode(addr)) return "loc_" + hexPlain(addr);
    return "data_" + hexPlain(addr);
}

std::string Session::symbolic(uint64_t addr) const {
    if (an.names.count(addr) || an.funcs.count(addr)) return label(addr);
    if (const Func* f = funcAt(addr)) {
        auto n = an.names.find(f->start);
        std::string base = n != an.names.end() ? demangle(n->second.name) : "sub_" + hexPlain(f->start);
        return base + "+" + hex(addr - f->start);
    }
    // nearest preceding name within the same section
    auto it = an.names.upper_bound(addr);
    if (it != an.names.begin()) {
        --it;
        const Section* a = img.secAt(addr);
        const Section* b = img.secAt(it->first);
        if (a && a == b && addr - it->first < 0x1000) return demangle(it->second.name) + "+" + hex(addr - it->first);
    }
    return hex(addr);
}

std::string Session::branchLabel(uint64_t addr) const {
    if (an.names.count(addr) || an.funcs.count(addr)) return label(addr);
    if (const Func* f = funcAt(addr))
        for (const auto& b : f->blocks)
            if (b.start == addr) return "loc_" + hexPlain(addr);
    return symbolic(addr);
}

bool Session::resolve(const std::string& expr, uint64_t& addr) const {
    if (expr.empty()) return false;
    std::string e = expr;
    uint64_t off = 0;
    bool plus = false;
    size_t p = e.rfind('+');
    if (p != std::string::npos && p > 0) {
        char* endp = nullptr;
        unsigned long long v = std::strtoull(e.c_str() + p + 1, &endp, 0);
        if (endp && *endp == 0) {
            off = v;
            e = e.substr(0, p);
            plus = true;
        }
    }
    (void)plus;
    auto it = byName_.find(e);
    if (it != byName_.end()) { addr = it->second + off; return true; }
    if (e.rfind("sub_", 0) == 0 || e.rfind("loc_", 0) == 0 || e.rfind("data_", 0) == 0) {
        char* endp = nullptr;
        unsigned long long v = std::strtoull(e.c_str() + e.find('_') + 1, &endp, 16);
        if (endp && *endp == 0) { addr = v + off; return true; }
    }
    // addresses are hex, with or without 0x
    const char* s = e.c_str();
    if (e.rfind("0x", 0) == 0 || e.rfind("0X", 0) == 0) s += 2;
    if (!*s || !std::all_of(s, s + std::strlen(s), [](char c) { return std::isxdigit((unsigned char)c); }))
        return false;
    addr = std::strtoull(s, nullptr, 16) + off;
    return true;
}

const Func* Session::funcAt(uint64_t addr) const {
    auto it = an.funcs.upper_bound(addr);
    if (it == an.funcs.begin()) return nullptr;
    --it;
    const Func& f = it->second;
    for (const auto& b : f.blocks)
        if (addr >= b.start && addr < b.end) return &f;
    return nullptr;
}

std::vector<Xref> Session::xrefsTo(uint64_t addr) const {
    std::vector<Xref> r;
    auto lo = std::lower_bound(byDst_.begin(), byDst_.end(), addr,
                               [](const Xref& x, uint64_t v) { return x.to < v; });
    for (; lo != byDst_.end() && lo->to == addr; ++lo) r.push_back(*lo);
    return r;
}

std::vector<Xref> Session::xrefsFrom(uint64_t addr) const {
    std::vector<Xref> r;
    auto lo = std::lower_bound(an.xrefs.begin(), an.xrefs.end(), addr,
                               [](const Xref& x, uint64_t v) { return x.from < v; });
    for (; lo != an.xrefs.end() && lo->from == addr; ++lo) r.push_back(*lo);
    return r;
}

bool Session::isPatched(uint64_t addr, uint32_t size) const {
    for (const auto& p : patches)
        if (addr < p.addr + p.bytes.size() && p.addr < addr + size) return true;
    return false;
}

bool Session::patchBytes(uint64_t addr, const std::vector<uint8_t>& bytes, std::string& err) {
    if (bytes.empty()) { err = "nothing to write"; return false; }
    const Segment* seg = img.segAt(addr);
    if (!seg || !seg->hasFile) { err = "address is not file-backed"; return false; }
    uint64_t off = addr - seg->addr;
    if (off + bytes.size() > seg->data.size()) { err = "patch runs past the end of the segment's file data"; return false; }
    Patch p;
    p.addr = addr;
    p.orig.assign(seg->data.begin() + long(off), seg->data.begin() + long(off + bytes.size()));
    p.bytes = bytes;
    size_t segIdx = size_t(seg - img.segments.data());
    if (!db.writeBytes(segIdx, off, bytes.data(), bytes.size(), err)) return false;
    img.write(addr, bytes.data(), bytes.size());
    if (!db.addPatch(p, err)) return false;
    patches.push_back(std::move(p));
    return true;
}

bool Session::unpatch(uint64_t addr, std::string& err) {
    bool any = false;
    for (size_t i = patches.size(); i-- > 0;) {
        Patch& p = patches[i];
        if (addr < p.addr || addr >= p.addr + p.bytes.size()) continue;
        const Segment* seg = img.segAt(p.addr);
        if (!seg) continue;
        size_t segIdx = size_t(seg - img.segments.data());
        if (!db.writeBytes(segIdx, p.addr - seg->addr, p.orig.data(), p.orig.size(), err)) return false;
        img.write(p.addr, p.orig.data(), p.orig.size());
        db.removePatch(p.id, err);
        patches.erase(patches.begin() + long(i));
        any = true;
    }
    if (!any) err = "no patch at that address";
    return any;
}

bool Session::assembleAt(uint64_t addr, const std::string& text, bool force, std::vector<uint8_t>& out, std::string& err) {
    if (!assembleText(img.arch, img.bits, addr, text, out, err)) return false;
    Insn in;
    DecodeCtx ctx;
    if (!proc->decode(img, addr, in, ctx)) return true;   // nothing to replace: raw write
    if (out.size() > in.size && !force) {
        err = "assembled code is " + std::to_string(out.size()) + " bytes but the instruction at this address is " +
              std::to_string(in.size) + " (use force to overwrite following instructions)";
        return false;
    }
    // pad the remainder with nops so the following instruction stays aligned
    while (out.size() < in.size) {
        if (img.arch == Arch::ARM64) {
            static const uint8_t nop[4] = {0x1f, 0x20, 0x03, 0xd5};
            for (int k = 0; k < 4 && out.size() < in.size; ++k) out.push_back(nop[k]);
        } else {
            out.push_back(0x90);
        }
    }
    return true;
}

static std::string shellQuote(const std::string& s) {
    std::string o = "'";
    for (char c : s) o += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return o + "'";
}

bool Session::exportPatched(const std::string& outPath, bool sign, std::string& err) {
    std::ifstream in(img.path, std::ios::binary);
    if (!in) { err = "original file not found: " + img.path; return false; }
    std::vector<char> file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    for (const auto& p : patches) {
        const Segment* seg = img.segAt(p.addr);
        if (!seg || !seg->hasFile) { err = "patch not file-backed"; return false; }
        uint64_t foff = seg->fileoff + (p.addr - seg->addr);
        if (foff + p.bytes.size() > file.size()) { err = "original file is smaller than expected (changed on disk?)"; return false; }
        std::copy(p.bytes.begin(), p.bytes.end(), file.begin() + long(foff));
    }
    std::ofstream out(outPath, std::ios::binary | std::ios::trunc);
    if (!out) { err = "cannot write " + outPath; return false; }
    out.write(file.data(), long(file.size()));
    out.close();
    std::string cmd = "chmod +x " + shellQuote(outPath) + " >/dev/null 2>&1";
    if (std::system(cmd.c_str()) != 0) {}
    if (sign && img.format == "Mach-O") {
        cmd = "codesign --force -s - " + shellQuote(outPath) + " >/dev/null 2>&1";
        if (std::system(cmd.c_str()) != 0) { err = "written, but codesign failed"; return false; }
    }
    return true;
}

bool Session::reanalyze(std::string& err) {
    if (!proc) { err = "no processor module"; return false; }
    std::map<uint64_t, NameEntry> userNames;
    for (const auto& [a, n] : an.names) if (n.kind == NameKind::User) userNames[a] = n;
    auto comments = an.comments;
    Analysis fresh;
    analyze(img, *proc, fresh, analyzeOpts);
    for (auto& [a, n] : userNames) fresh.names[a] = n;
    fresh.comments = comments;
    std::string path = db.path();
    auto saved = patches;
    if (!db.create(path, img, fresh, err)) return false;
    for (auto& p : saved) db.addPatch(p, err);
    patches = saved;
    an = std::move(fresh);
    dc::clearSummaryCache();
    buildIndexes();
    return true;
}

bool Session::rename(uint64_t addr, const std::string& name, std::string& err) {
    if (!db.setName(addr, name, err)) return false;
    auto it = an.names.find(addr);
    if (it != an.names.end()) {
        for (auto b = byName_.begin(); b != byName_.end();)
            b = (b->second == addr) ? byName_.erase(b) : std::next(b);
        an.names.erase(it);
    }
    if (!name.empty()) {
        an.names[addr] = {name, NameKind::User};
        byName_[name] = addr;
    }
    return true;
}

bool Session::comment(uint64_t addr, const std::string& text, std::string& err) {
    if (!db.setComment(addr, text, err)) return false;
    if (text.empty()) an.comments.erase(addr);
    else an.comments[addr] = text;
    return true;
}

}  // namespace er
