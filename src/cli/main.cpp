// erebus: command-line front end.
//   erebus open <binary> [-o out.erdb] [--arch arm64|x86_64] [--no-gap] [--no-ptr]
//   erebus shell <db>
//   erebus <db> <command...>
#include <chrono>
#include <cstdio>
#include <iostream>

#include "cli/commands.h"
#include "cli/session.h"
#include "ui/server.h"

#ifndef EREBUS_VERSION
#define EREBUS_VERSION "dev"
#endif

using namespace er;

static void usage() {
    std::cerr << "erebus - disassembler / analysis database\n"
                 "  erebus open <binary> [-o out.erdb] [--arch arm64|x86_64] [--no-gap] [--no-ptr] [--sweep] [-q]\n"
                 "  erebus shell <db>\n"
                 "  erebus serve <db> [--port 8787] [--no-open] [--watch-pid N]   web UI\n"
                 "  erebus <db> <command...>       (try: erebus <db> help)\n";
}

static int shell(Session& s) {
    std::cout << "erebus shell - " << s.img.path << "  (help for commands)\n";
    std::string line;
    while (true) {
        std::cout << "erebus> " << std::flush;
        if (!std::getline(std::cin, line)) break;
        if (!runCommand(s, tokenize(line), std::cout)) break;
    }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 1; }
    std::string cmd = argv[1];
    if (cmd == "--version" || cmd == "-v" || cmd == "version") {
        std::cout << "erebus " << EREBUS_VERSION << "\n";
        return 0;
    }

    if (cmd == "open") {
        if (argc < 3) { usage(); return 1; }
        std::string in = argv[2], out;
        LoadOptions lo;
        AnalyzeOptions ao;
        bool quiet = false;
        for (int i = 3; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "-o" && i + 1 < argc) out = argv[++i];
            else if (a == "--arch" && i + 1 < argc) lo.arch = argv[++i];
            else if (a == "--no-gap") ao.gapScan = false;
            else if (a == "--no-ptr") ao.ptrScan = false;
            else if (a == "--sweep") ao.sweep = true;
            else if (a == "-q") quiet = true;
        }
        if (out.empty()) out = in + ".erdb";
        Session s;
        std::string err;
        auto t0 = std::chrono::steady_clock::now();
        if (!s.analyzeFile(in, out, lo, ao, err)) {
            std::cerr << "error: " << err << "\n";
            return 1;
        }
        double sec = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
        if (!quiet) {
            runCommand(s, {"info"}, std::cout);
            std::printf("database : %s  (%.2fs)\n", out.c_str(), sec);
        }
        return 0;
    }

    std::string dbPath = (cmd == "shell" || cmd == "serve") ? (argc > 2 ? argv[2] : "") : cmd;
    if (dbPath.empty()) { usage(); return 1; }
    Session s;
    std::string err;
    if (!s.openDb(dbPath, err)) {
        std::cerr << "error: " << err << "\n";
        return 1;
    }
    if (cmd == "shell") return shell(s);
    if (cmd == "serve") {
        int port = 8787;
        bool open = true;
        int watch = 0;
        for (int i = 3; i < argc; ++i) {
            std::string a = argv[i];
            if (a == "--port" && i + 1 < argc) port = std::atoi(argv[++i]);
            else if (a == "--no-open") open = false;
            else if (a == "--watch-pid" && i + 1 < argc) watch = std::atoi(argv[++i]);
        }
        return serveUi(s, "127.0.0.1", port, open, watch);
    }
    if (argc < 3) { usage(); return 1; }
    std::vector<std::string> args;
    for (int i = 2; i < argc; ++i) args.push_back(argv[i]);
    runCommand(s, args, std::cout);
    return 0;
}
