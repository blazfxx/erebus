#include "cli/render.h"

#include <cctype>
#include <cstdio>

#include "core/util.h"

namespace er {

std::string escapeText(const std::string& s, size_t max) {
    std::string o;
    for (unsigned char c : s) {
        if (o.size() >= max) { o += "..."; break; }
        if (c == '\n') o += "\\n";
        else if (c == '\r') o += "\\r";
        else if (c == '\t') o += "\\t";
        else if (c == '"') o += "\\\"";
        else if (c < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\x%02x", c); o += b; }
        else o.push_back(char(c));
    }
    return o;
}

std::string flatten(const std::vector<TextPart>& parts) {
    std::string r;
    for (const auto& p : parts) r += p.text;
    return r;
}

namespace {

// Locate the hex literal for `addr` in an operand string. Returns npos if absent.
size_t findLiteral(const std::string& ops, uint64_t addr, size_t& len) {
    std::string lit = hex(addr);
    size_t p = 0;
    while ((p = ops.find(lit, p)) != std::string::npos) {
        size_t e = p + lit.size();
        if (e >= ops.size() || !std::isxdigit((unsigned char)ops[e])) {
            len = lit.size();
            return p;
        }
        p = e;
    }
    return std::string::npos;
}

}  // namespace

RenderedInsn renderInsn(Session& s, const Insn& in) {
    RenderedInsn r;
    r.addr = in.addr;
    r.size = in.size;
    r.mnem = in.mnem;

    uint8_t b[16] = {};
    size_t got = s.img.readSome(in.addr, b, std::min<uint32_t>(in.size, 16));
    for (size_t i = 0; i < got; ++i) {
        char t[4];
        std::snprintf(t, sizeof t, i ? " %02x" : "%02x", b[i]);
        r.bytes += t;
    }

    bool replaced = false;
    std::string ops = in.ops;
    for (const Xref& x : s.xrefsFrom(in.addr)) {
        bool isStr = s.an.strings.count(x.to) != 0;
        bool branch = x.type == XType::Call || x.type == XType::Jump || x.type == XType::Tail;
        if (!isStr && branch && !replaced) {
            size_t len = 0;
            size_t p = findLiteral(ops, x.to, len);
            if (p != std::string::npos) {
                if (p) r.ops.push_back({ops.substr(0, p), false, 0});
                r.ops.push_back({s.branchLabel(x.to), true, x.to});
                if (p + len < ops.size()) r.ops.push_back({ops.substr(p + len), false, 0});
                replaced = true;
                continue;
            }
        }
        if (!r.comment.empty()) r.comment.push_back({", ", false, 0});
        auto st = s.an.strings.find(x.to);
        if (st != s.an.strings.end())
            r.comment.push_back({(st->second.wide ? "L\"" : "\"") + escapeText(st->second.text) + "\"", true, x.to});
        else
            r.comment.push_back({s.symbolic(x.to), true, x.to});
    }
    if (!replaced && !ops.empty()) r.ops.push_back({ops, false, 0});

    auto uc = s.an.comments.find(in.addr);
    if (uc != s.an.comments.end()) {
        if (!r.comment.empty()) r.comment.push_back({" | ", false, 0});
        r.comment.push_back({uc->second, false, 0});
    }
    return r;
}

}  // namespace er
