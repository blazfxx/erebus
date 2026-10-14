#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <set>
#include <unistd.h>

#include "core/util.h"

namespace er {

static std::string shellQ(const std::string& s) {
    std::string o = "'";
    for (char c : s) o += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return o + "'";
}

void primeSwiftNames(const std::vector<std::string>& mangled) {
    if (mangled.empty()) return;
    // locate the tool (Xcode / Command Line Tools)
    std::string tool;
    if (FILE* p = popen("xcrun -f swift-demangle 2>/dev/null", "r")) {
        char buf[1024];
        if (fgets(buf, sizeof buf, p)) tool = buf;
        pclose(p);
    }
    while (!tool.empty() && (tool.back() == '\n' || tool.back() == '\r')) tool.pop_back();
    if (tool.empty()) return;

    std::set<std::string> uniq(mangled.begin(), mangled.end());
    std::vector<std::string> names(uniq.begin(), uniq.end());
    char tmpl[] = "/tmp/erebus_swXXXXXX";
    int fd = mkstemp(tmpl);
    if (fd < 0) return;
    close(fd);
    std::string in = tmpl, out = in + ".out";
    {
        std::ofstream f(in);
        for (auto& n : names) f << n << "\n";
    }
    std::string cmd = shellQ(tool) + " --simplified < " + shellQ(in) + " > " + shellQ(out) + " 2>/dev/null";
    if (std::system(cmd.c_str()) == 0) {
        std::ifstream r(out);
        std::string line;
        size_t i = 0;
        while (std::getline(r, line) && i < names.size()) {
            if (!line.empty() && line != names[i]) swiftCache()[names[i]] = line;
            ++i;
        }
    }
    std::remove(in.c_str());
    std::remove(out.c_str());
}

}  // namespace er
