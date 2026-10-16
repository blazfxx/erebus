#include "ui/server.h"

#include <httplib.h>

#include <signal.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <fstream>
#include <functional>
#include <iostream>
#include <mutex>
#include <set>
#include <sstream>

#include <nlohmann/json.hpp>

#include "cli/render.h"
#include "core/util.h"
#include "decomp/decompile.h"

extern const char* const kIndexHtml;

namespace er {
namespace {

using json = nlohmann::json;

std::string hx(uint64_t v) { return hex(v); }

bool lowerContains(const std::string& hay, const std::string& needle) {
    if (needle.empty()) return true;
    auto it = std::search(hay.begin(), hay.end(), needle.begin(), needle.end(), [](char a, char b) {
        return std::tolower((unsigned char)a) == std::tolower((unsigned char)b);
    });
    return it != hay.end();
}

json partsJson(const std::vector<TextPart>& parts) {
    json a = json::array();
    for (const auto& p : parts) {
        json j = {{"t", p.text}};
        if (p.isRef) j["a"] = hx(p.addr);
        a.push_back(std::move(j));
    }
    return a;
}

json insnJson(Session& s, const Insn& in) {
    RenderedInsn r = renderInsn(s, in);
    json j = {{"a", hx(r.addr)}, {"z", r.size}, {"b", r.bytes}, {"m", r.mnem},
              {"o", partsJson(r.ops)}, {"c", partsJson(r.comment)}};
    if (s.isPatched(r.addr, r.size)) j["p"] = true;
    return j;
}

void calleesOf(Session& s, const Func& f, std::vector<uint64_t>& out) {
    std::set<uint64_t> seen;
    for (const Block& b : f.blocks) {
        auto lo = std::lower_bound(s.an.xrefs.begin(), s.an.xrefs.end(), b.start,
                                   [](const Xref& x, uint64_t v) { return x.from < v; });
        for (; lo != s.an.xrefs.end() && lo->from < b.end; ++lo) {
            if (lo->type != XType::Call && lo->type != XType::Tail) continue;
            if (seen.insert(lo->to).second) out.push_back(lo->to);
        }
    }
}

std::string readFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

}  // namespace

int serveUi(Session& s, const std::string& host, int port, bool openBrowser, int watchPid) {
    httplib::Server svr;
    std::mutex mu;   // Capstone handle + session mutation are single-threaded

    // Binaries contain arbitrary bytes; never let invalid UTF-8 make the encoder throw (-> HTTP 500).
    auto dumpJson = [](const json& j) { return j.dump(-1, ' ', false, json::error_handler_t::replace); };
    auto reply = [dumpJson](httplib::Response& res, const json& j) { res.set_content(dumpJson(j), "application/json"); };
    auto fail = [dumpJson](httplib::Response& res, int code, const std::string& msg) {
        res.status = code;
        res.set_content(dumpJson(json{{"error", msg}}), "application/json");
    };
    auto addrParam = [&](const httplib::Request& req, const char* key, uint64_t& a) {
        if (!req.has_param(key)) return false;
        return s.resolve(req.get_param_value(key), a);
    };

    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        const char* dir = std::getenv("EREBUS_UI_DIR");   // dev: edit index.html without rebuilding
        if (dir) res.set_content(readFile(std::string(dir) + "/index.html"), "text/html; charset=utf-8");
        else res.set_content(kIndexHtml, "text/html; charset=utf-8");
    });

    svr.Get("/api/info", [&](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        size_t blocks = 0;
        for (auto& [a, f] : s.an.funcs) blocks += f.blocks.size();
        json segs = json::array();
        for (const auto& sg : s.img.segments)
            segs.push_back({{"name", sg.name}, {"a", hx(sg.addr)}, {"size", sg.size}, {"perms", sg.perms}});
        reply(res, {{"file", s.img.path}, {"format", s.img.format}, {"arch", archName(s.img.arch)},
                    {"bits", s.img.bits}, {"base", hx(s.img.base)},
                    {"entry", s.img.hasEntry ? hx(s.img.entry) : ""},
                    {"entryName", s.img.hasEntry ? s.symbolic(s.img.entry) : ""},
                    {"funcs", s.an.funcs.size()}, {"blocks", blocks}, {"insns", s.an.insnCount},
                    {"xrefs", s.an.xrefs.size()}, {"names", s.an.names.size()},
                    {"strings", s.an.strings.size()}, {"codeBytes", s.an.codeBytes},
                    {"covered", s.an.coveredBytes}, {"segments", segs}});
    });

    svr.Get("/api/funcs", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        std::string q = req.get_param_value("q");
        size_t limit = req.has_param("limit") ? std::strtoul(req.get_param_value("limit").c_str(), nullptr, 10) : 5000;
        json out = json::array();
        size_t total = 0;
        for (const auto& [a, f] : s.an.funcs) {
            std::string nm = s.label(a);
            if (!lowerContains(nm, q)) continue;
            ++total;
            if (out.size() < limit)
                out.push_back({{"a", hx(a)}, {"n", nm}, {"s", f.end - a}, {"t", f.thunk}, {"r", f.noret}});
        }
        reply(res, {{"total", total}, {"items", out}});
    });

    svr.Get("/api/list", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        std::string kind = req.get_param_value("kind"), q = req.get_param_value("q");
        size_t limit = 5000;
        json out = json::array();
        size_t total = 0;
        auto push = [&](uint64_t a, const std::string& label, const std::string& extra) {
            if (!lowerContains(label, q)) return;
            ++total;
            if (out.size() < limit) out.push_back({{"a", hx(a)}, {"n", label}, {"x", extra}});
        };
        if (kind == "names" || kind == "imports") {
            for (const auto& [a, n] : s.an.names) {
                if (kind == "imports" && n.kind != NameKind::Import) continue;
                if (kind == "names" && n.kind == NameKind::String) continue;
                push(a, demangle(n.name), "");
            }
        } else if (kind == "exports") {
            for (const auto& sym : s.img.symbols)
                if (sym.exported) push(sym.addr, demangle(sym.name), "");
        } else if (kind == "strings") {
            for (const auto& [a, st] : s.an.strings) push(a, st.text, st.wide ? "utf16" : "");
        }
        reply(res, {{"total", total}, {"items", out}});
    });

    svr.Get("/api/func", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        uint64_t a;
        if (!addrParam(req, "a", a)) return fail(res, 400, "cannot resolve location");
        const Func* f = s.funcAt(a);
        if (!f) return fail(res, 404, "not inside a function");
        json blocks = json::array();
        DecodeCtx ctx;
        for (const Block& b : f->blocks) {
            json insns = json::array();
            ctx.regs.clear();
            for (uint64_t x = b.start; x < b.end;) {
                Insn in;
                if (!s.proc->decode(s.img, x, in, ctx)) break;
                insns.push_back(insnJson(s, in));
                x += in.size;
            }
            json from = json::array();
            for (const auto& xr : s.xrefsTo(b.start))
                if (from.size() < 6) from.push_back(hx(xr.from));
            bool named = s.hasName(b.start) || b.start == f->start;
            blocks.push_back({{"a", hx(b.start)}, {"end", hx(b.end)},
                              {"label", (named || !from.empty()) ? s.label(b.start) : ""},
                              {"from", from}, {"insns", insns}});
        }
        json edges = json::array();
        for (const Edge& e : f->edges) edges.push_back({{"s", hx(e.src)}, {"d", hx(e.dst)}, {"k", int(e.kind)}});
        json xr = json::array();
        for (const auto& x : s.xrefsTo(f->start))
            xr.push_back({{"a", hx(x.from)}, {"n", s.symbolic(x.from)}, {"t", xtypeName(x.type)}});
        reply(res, {{"a", hx(f->start)}, {"end", hx(f->end)}, {"n", s.label(f->start)}, {"size", f->end - f->start},
                    {"noret", f->noret}, {"thunk", f->thunk}, {"blocks", blocks}, {"edges", edges}, {"xrefs", xr}});
    });

    svr.Get("/api/pseudo", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        uint64_t a;
        if (!addrParam(req, "a", a)) return fail(res, 400, "cannot resolve location");
        dc::DecompResult r = dc::decompile(s, a);
        if (!r.ok) return fail(res, 422, r.error);
        static const char* cls = "pkdnsrcv";   // plain keyword type(d) number string name comment var
        json lines = json::array();
        for (const auto& l : r.lines) {
            json parts = json::array();
            for (const auto& p : l.parts) {
                json j = {{"t", p.text}, {"c", std::string(1, cls[int(p.cls) == 0 ? 0 : int(p.cls)])}};
                if (p.ref) j["a"] = hx(p.addr);
                parts.push_back(std::move(j));
            }
            lines.push_back({{"i", l.indent}, {"p", parts}});
        }
        const Func* f = s.funcAt(a);
        reply(res, {{"a", f ? hx(f->start) : hx(a)}, {"lines", lines}});
    });

    svr.Get("/api/lin", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        uint64_t a;
        if (!addrParam(req, "a", a)) return fail(res, 400, "cannot resolve location");
        size_t n = req.has_param("n") ? std::min<size_t>(std::strtoul(req.get_param_value("n").c_str(), nullptr, 10), 2000) : 64;
        json insns = json::array();
        DecodeCtx ctx;
        for (size_t i = 0; i < n; ++i) {
            Insn in;
            if (!s.proc->decode(s.img, a, in, ctx)) break;
            json j = insnJson(s, in);
            if (s.hasName(a) || s.an.funcs.count(a)) j["label"] = s.label(a);
            insns.push_back(std::move(j));
            a += in.size;
        }
        reply(res, {{"insns", insns}, {"next", hx(a)}});
    });

    svr.Get("/api/xrefs", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        uint64_t a;
        if (!addrParam(req, "a", a)) return fail(res, 400, "cannot resolve location");
        json l = json::array();
        for (const auto& x : s.xrefsTo(a))
            l.push_back({{"a", hx(x.from)}, {"n", s.symbolic(x.from)}, {"t", xtypeName(x.type)}});
        reply(res, {{"a", hx(a)}, {"n", s.symbolic(a)}, {"items", l}});
    });

    svr.Get("/api/hex", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        uint64_t a;
        if (!addrParam(req, "a", a)) return fail(res, 400, "cannot resolve location");
        size_t n = req.has_param("n") ? std::min<size_t>(std::strtoul(req.get_param_value("n").c_str(), nullptr, 10), 8192) : 512;
        std::vector<uint8_t> buf(n);
        size_t got = s.img.readSome(a, buf.data(), n);
        std::string h;
        for (size_t i = 0; i < got; ++i) {
            char t[4];
            std::snprintf(t, sizeof t, "%02x", buf[i]);
            h += t;
        }
        reply(res, {{"a", hx(a)}, {"n", s.symbolic(a)}, {"hex", h}});
    });

    svr.Get("/api/where", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        uint64_t a;
        if (!addrParam(req, "a", a)) return fail(res, 404, "cannot resolve location");
        const Func* f = s.funcAt(a);
        reply(res, {{"a", hx(a)}, {"n", s.symbolic(a)}, {"func", f ? hx(f->start) : ""},
                    {"code", s.img.isCode(a)}, {"mapped", s.img.isMapped(a)}});
    });

    svr.Get("/api/callgraph", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        uint64_t a;
        if (!addrParam(req, "a", a)) return fail(res, 400, "cannot resolve location");
        int depth = req.has_param("d") ? std::min(6, std::atoi(req.get_param_value("d").c_str())) : 2;
        std::set<uint64_t> path;
        std::function<json(uint64_t, int)> walk = [&](uint64_t fa, int d) -> json {
            json node = {{"a", hx(fa)}, {"n", s.symbolic(fa)}, {"c", json::array()}};
            const Func* f = s.funcAt(fa);
            if (!f || d >= depth || path.count(f->start)) return node;
            path.insert(f->start);
            std::vector<uint64_t> c;
            calleesOf(s, *f, c);
            for (uint64_t t : c) node["c"].push_back(walk(t, d + 1));
            path.erase(f->start);
            return node;
        };
        reply(res, walk(a, 0));
    });

    auto parseHexString = [](const std::string& in, std::vector<uint8_t>& out) {
        std::string t;
        for (char c : in) if (std::isxdigit((unsigned char)c)) t.push_back(c);
        if (t.empty() || t.size() % 2) return false;
        for (size_t i = 0; i < t.size(); i += 2) out.push_back(uint8_t(std::strtoul(t.substr(i, 2).c_str(), nullptr, 16)));
        return true;
    };

    svr.Post("/api/patch", [&, parseHexString](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        json b = json::parse(req.body, nullptr, false);
        uint64_t a;
        if (b.is_discarded() || !b.contains("a") || !s.resolve(b["a"].get<std::string>(), a)) return fail(res, 400, "bad location");
        std::vector<uint8_t> bytes;
        if (!parseHexString(b.value("hex", ""), bytes)) return fail(res, 400, "bad hex bytes");
        std::string err;
        if (!s.patchBytes(a, bytes, err)) return fail(res, 422, err);
        reply(res, {{"ok", true}, {"n", bytes.size()}});
    });

    svr.Post("/api/asm", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        json b = json::parse(req.body, nullptr, false);
        uint64_t a;
        if (b.is_discarded() || !b.contains("a") || !s.resolve(b["a"].get<std::string>(), a)) return fail(res, 400, "bad location");
        std::vector<uint8_t> bytes;
        std::string err;
        if (!s.assembleAt(a, b.value("text", ""), b.value("force", false), bytes, err)) return fail(res, 422, err);
        if (b.value("dry", false)) {
            std::string h;
            for (uint8_t x : bytes) { char t[4]; std::snprintf(t, sizeof t, "%02x", x); h += t; }
            return reply(res, {{"ok", true}, {"hex", h}});
        }
        if (!s.patchBytes(a, bytes, err)) return fail(res, 422, err);
        reply(res, {{"ok", true}, {"n", bytes.size()}});
    });

    svr.Post("/api/unpatch", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        json b = json::parse(req.body, nullptr, false);
        uint64_t a;
        if (b.is_discarded() || !b.contains("a") || !s.resolve(b["a"].get<std::string>(), a)) return fail(res, 400, "bad location");
        std::string err;
        if (!s.unpatch(a, err)) return fail(res, 422, err);
        reply(res, {{"ok", true}});
    });

    svr.Get("/api/patches", [&](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        json l = json::array();
        for (const auto& p : s.patches) {
            auto hx2 = [](const std::vector<uint8_t>& v) { std::string h; for (uint8_t x : v) { char t[4]; std::snprintf(t, sizeof t, "%02x", x); h += t; } return h; };
            l.push_back({{"a", hx(p.addr)}, {"n", s.symbolic(p.addr)}, {"orig", hx2(p.orig)}, {"new", hx2(p.bytes)}});
        }
        reply(res, {{"items", l}});
    });

    svr.Post("/api/reanalyze", [&](const httplib::Request&, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        std::string err;
        if (!s.reanalyze(err)) return fail(res, 500, err);
        reply(res, {{"ok", true}, {"funcs", s.an.funcs.size()}});
    });

    svr.Post("/api/export", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        json b = json::parse(req.body, nullptr, false);
        if (b.is_discarded() || !b.contains("path")) return fail(res, 400, "bad request");
        std::string err;
        if (!s.exportPatched(b["path"].get<std::string>(), b.value("sign", false), err)) return fail(res, 422, err);
        reply(res, {{"ok", true}});
    });

    svr.Get("/api/find", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        std::vector<int> pat;
        if (req.has_param("text")) { for (unsigned char c : req.get_param_value("text")) pat.push_back(c); }
        else {
            std::stringstream ss(req.get_param_value("hex"));
            std::string tok;
            while (ss >> tok) pat.push_back(tok == "??" || tok == "?" ? -1 : int(std::strtoul(tok.c_str(), nullptr, 16)));
        }
        if (pat.empty()) return fail(res, 400, "empty pattern");
        json out = json::array();
        for (const auto& sg : s.img.segments) {
            const auto& d = sg.data;
            for (size_t i = 0; i + pat.size() <= d.size() && out.size() < 500; ++i) {
                bool m = true;
                for (size_t k = 0; k < pat.size() && m; ++k) if (pat[k] >= 0 && d[i + k] != pat[k]) m = false;
                if (m) out.push_back({{"a", hx(sg.addr + i)}, {"n", s.symbolic(sg.addr + i)}});
            }
        }
        reply(res, {{"items", out}});
    });

    svr.Post("/api/rename", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        json b = json::parse(req.body, nullptr, false);
        if (b.is_discarded() || !b.contains("a")) return fail(res, 400, "bad request");
        uint64_t a;
        if (!s.resolve(b["a"].get<std::string>(), a)) return fail(res, 400, "cannot resolve location");
        std::string name = b.value("name", ""), err;
        if (!s.rename(a, name, err)) return fail(res, 500, err);
        reply(res, {{"ok", true}, {"n", s.label(a)}});
    });

    svr.Post("/api/comment", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> g(mu);
        json b = json::parse(req.body, nullptr, false);
        if (b.is_discarded() || !b.contains("a")) return fail(res, 400, "bad request");
        uint64_t a;
        if (!s.resolve(b["a"].get<std::string>(), a)) return fail(res, 400, "cannot resolve location");
        std::string err;
        if (!s.comment(a, b.value("text", ""), err)) return fail(res, 500, err);
        reply(res, {{"ok", true}});
    });

    int bound = port;
    if (port == 0) bound = svr.bind_to_any_port(host);
    else if (!svr.bind_to_port(host, port)) {
        std::cerr << "error: cannot bind " << host << ":" << port << "\n";
        return 1;
    }
    std::string url = "http://" + host + ":" + std::to_string(bound) + "/";
    std::cout << "erebus ui: " << url << "   (ctrl-c to stop)\n" << std::flush;
    if (openBrowser) {
        std::string cmd = "open '" + url + "' >/dev/null 2>&1";
        if (std::system(cmd.c_str()) != 0) {}
    }
    if (watchPid > 0) {
        std::thread([&svr, watchPid]() {
            for (;;) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                if (kill(watchPid, 0) != 0 && errno == ESRCH) { svr.stop(); return; }
            }
        }).detach();
    }
    svr.listen_after_bind();
    return 0;
}

}  // namespace er
