#include "loaders/loader.h"

#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>

namespace fs = std::filesystem;

namespace er {

namespace {

// The value of <key>CFBundleExecutable</key><string>…</string> in an XML Info.plist ("" if absent or binary).
std::string plistExecutable(const fs::path& plist) {
    std::ifstream in(plist, std::ios::binary);
    if (!in) return "";
    std::stringstream ss;
    ss << in.rdbuf();
    std::string t = ss.str();
    size_t k = t.find("<key>CFBundleExecutable</key>");
    if (k == std::string::npos) return "";
    size_t a = t.find("<string>", k);
    size_t b = a == std::string::npos ? a : t.find("</string>", a);
    if (a == std::string::npos || b == std::string::npos) return "";
    return t.substr(a + 8, b - a - 8);
}

bool isRegular(const fs::path& p) {
    std::error_code ec;
    return fs::is_regular_file(p, ec);
}

// Picks the program inside a folder that macOS treats as one thing (.app, .framework, .xpc, .appex, plugin bundles).
// Finder and Terminal show these as single files, so people expect to open them like one.
std::string resolveBundle(const std::string& path, std::string& err) {
    std::error_code ec;
    if (!fs::is_directory(path, ec)) return path;
    fs::path root(path);
    while (!root.empty() && root.filename().empty()) root = root.parent_path();   // trailing slash
    const std::string stem = root.stem().string();

    std::vector<fs::path> dirs;
    for (const char* sub : {"Contents/MacOS", "MacOS", "Versions/Current", "."}) dirs.push_back(sub[0] == '.' ? root : root / sub);
    std::vector<fs::path> plists = {root / "Contents/Info.plist", root / "Info.plist", root / "Versions/Current/Resources/Info.plist"};

    std::string named;
    for (auto& pl : plists) {
        named = plistExecutable(pl);
        if (!named.empty()) break;
    }
    for (auto& d : dirs) {
        if (!named.empty() && isRegular(d / named)) return (d / named).string();
    }
    for (auto& d : dirs) {
        if (isRegular(d / stem)) return (d / stem).string();
    }
    // Binary plist or unusual layout: the only (or largest) file in the executable folder.
    for (const char* sub : {"Contents/MacOS", "MacOS"}) {
        fs::path d = root / sub;
        if (!fs::is_directory(d, ec)) continue;
        fs::path best;
        uintmax_t bestSize = 0;
        for (auto& e : fs::directory_iterator(d, ec)) {
            if (!e.is_regular_file(ec)) continue;
            uintmax_t sz = e.file_size(ec);
            if (sz >= bestSize) { best = e.path(); bestSize = sz; }
        }
        if (!best.empty()) return best.string();
    }
    err = path + " is a folder, and no program was found inside it. Open the file inside (an .app keeps its program in Contents/MacOS).";
    return "";
}

}  // namespace

std::unique_ptr<Image> loadFile(const std::string& given, const LoadOptions& opt, std::string& err) {
    std::string path = resolveBundle(given, err);
    if (path.empty()) return nullptr;
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + path;
        return nullptr;
    }
    std::vector<uint8_t> file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (file.size() < 16) {
        err = path + " is too small to be a program (" + std::to_string(file.size()) + " bytes)";
        return nullptr;
    }
    auto img = std::make_unique<Image>();
    img->path = path;

    Reader r{file.data(), file.size()};
    uint32_t m = r.u32(0);
    bool ok = false;
    if (m == 0xfeedfacf || m == 0xfeedface || m == 0xbebafeca || m == 0xbfbafeca)
        ok = loadMachO(file, opt, *img, err);
    else if (m == 0x464c457f)
        ok = loadELF(file, opt, *img, err);
    else if ((m & 0xffff) == 0x5a4d)
        ok = loadPE(file, opt, *img, err);
    else
        err = "unrecognized file format";
    if (!ok) return nullptr;
    img->finalize();
    return img;
}

}  // namespace er
