// Objective-C 2.0 metadata (Mach-O 64-bit): class / category method lists become named functions
// (`-[Class selector]`, `+[Class selector]`), selector reference slots become named data.
#include <algorithm>
#include <cstring>
#include <map>
#include <set>

#include "loaders/loader.h"

namespace er {
namespace {

constexpr uint64_t kPtrMask = 0x0000fffffffffff8ull;   // strip pointer-auth / tag bits and flag bits

struct ObjC {
    Image& img;
    std::vector<Symbol> out;
    std::set<uint64_t> seenImp;
    std::map<uint64_t, std::string> importAt;   // bound slot address -> import symbol (without "_ptr")

    uint64_t rdp(uint64_t a) const { return img.readPtr(a); }
    int32_t ri32(uint64_t a) const { int32_t v = 0; img.read(a, &v, 4); return v; }
    uint32_t ru32(uint64_t a) const { uint32_t v = 0; img.read(a, &v, 4); return v; }
    std::string str(uint64_t a, size_t max = 512) const {
        std::string s;
        if (!a || !img.isMapped(a)) return s;
        img.readCString(a, s, max);
        for (char& c : s) if (static_cast<unsigned char>(c) < 0x20) c = '?';
        return s;
    }

    bool isSelrefSlot(uint64_t a) const {
        const Section* s = img.secAt(a);
        return s && s->name.find("__objc_selrefs") != std::string::npos;
    }

    std::string classNameOf(uint64_t cls) const {
        if (!cls) return "";
        uint64_t ro = rdp(cls + 32) & kPtrMask;
        if (!ro || !img.isMapped(ro)) return "";
        return str(rdp(ro + 24));
    }

    void methodList(uint64_t list, char sign, const std::string& cls, const std::string& cat) {
        list &= kPtrMask;
        if (!list || !img.isMapped(list)) return;
        uint32_t ef = ru32(list), count = ru32(list + 4);
        bool small = ef & 0x80000000u;
        uint32_t entsize = ef & 0xfffc;
        if (!entsize) entsize = small ? 12 : 24;
        if (count > 200000) return;
        for (uint32_t i = 0; i < count; ++i) {
            uint64_t e = list + 8 + uint64_t(i) * entsize;
            std::string sel;
            uint64_t imp;
            if (small) {
                uint64_t nameRef = e + uint64_t(int64_t(ri32(e)));
                sel = isSelrefSlot(nameRef) ? str(rdp(nameRef)) : str(nameRef);
                imp = (e + 8) + uint64_t(int64_t(ri32(e + 8)));
            } else {
                sel = str(rdp(e));
                imp = rdp(e + 16) & kPtrMask;
            }
            if (sel.empty() || !imp || !img.isCode(imp) || !seenImp.insert(imp).second) continue;
            Symbol s;
            s.name = std::string(1, sign) + "[" + cls + (cat.empty() ? "" : "(" + cat + ")") + " " + sel + "]";
            s.addr = imp;
            s.kind = SymKind::Func;
            out.push_back(std::move(s));
        }
    }

    void classRec(uint64_t cls) {
        cls &= kPtrMask;
        if (!cls || !img.isMapped(cls)) return;
        std::string name = classNameOf(cls);
        if (name.empty()) return;
        uint64_t ro = rdp(cls + 32) & kPtrMask;
        if (ro && img.isMapped(ro)) methodList(rdp(ro + 32), '-', name, "");
        uint64_t meta = rdp(cls) & kPtrMask;
        if (meta && img.isMapped(meta)) {
            uint64_t mro = rdp(meta + 32) & kPtrMask;
            if (mro && img.isMapped(mro)) methodList(rdp(mro + 32), '+', name, "");
        }
    }

    void categoryRec(uint64_t cat) {
        cat &= kPtrMask;
        if (!cat || !img.isMapped(cat)) return;
        std::string catName = str(rdp(cat));
        std::string cls = classNameOf(rdp(cat + 8) & kPtrMask);
        if (cls.empty()) {
            auto it = importAt.find(cat + 8);
            if (it != importAt.end()) {
                cls = it->second;
                const std::string pre = "_OBJC_CLASS_$_";
                if (cls.rfind(pre, 0) == 0) cls = cls.substr(pre.size());
            }
        }
        if (cls.empty()) cls = "?";
        methodList(rdp(cat + 16), '-', cls, catName);
        methodList(rdp(cat + 24), '+', cls, catName);
    }
};

}  // namespace

void parseObjC(Image& img) {
    ObjC o{img, {}, {}, {}};
    for (const auto& s : img.symbols)
        if (s.kind == SymKind::ImportPtr && s.name.size() > 4 && s.name.compare(s.name.size() - 4, 4, "_ptr") == 0)
            o.importAt[s.addr] = s.name.substr(0, s.name.size() - 4);

    const size_t psz = 8;
    for (const auto& sec : img.sections) {
        bool classes = sec.name.find("__objc_classlist") != std::string::npos;
        bool cats = sec.name.find("__objc_catlist") != std::string::npos;
        if (!classes && !cats) continue;
        uint64_t n = std::min<uint64_t>(sec.size / psz, 100000);
        for (uint64_t i = 0; i < n; ++i) {
            uint64_t p = o.rdp(sec.addr + i * psz);
            if (classes) o.classRec(p);
            else o.categoryRec(p);
        }
    }
    // selector reference slots: name them after the selector they hold
    for (const auto& sec : img.sections) {
        if (sec.name.find("__objc_selrefs") == std::string::npos) continue;
        uint64_t n = std::min<uint64_t>(sec.size / psz, 200000);
        for (uint64_t i = 0; i < n; ++i) {
            uint64_t slot = sec.addr + i * psz;
            std::string sel = o.str(o.rdp(slot) & kPtrMask, 128);
            if (sel.empty()) continue;
            Symbol s;
            s.name = "selref_" + sel;
            s.addr = slot;
            s.kind = SymKind::Data;
            o.out.push_back(std::move(s));
        }
    }
    // ObjC names win over anonymous/auto ones: put them first
    img.symbols.insert(img.symbols.begin(), o.out.begin(), o.out.end());
}

}  // namespace er
