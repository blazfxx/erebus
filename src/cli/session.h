// Session: an opened database plus the in-memory indexes the CLI queries need.
#pragma once
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis/analyzer.h"
#include "core/db.h"
#include "core/image.h"
#include "loaders/loader.h"
#include "procs/proc.h"

namespace er {

class Session {
public:
    Image img;
    Analysis an;
    Database db;
    std::unique_ptr<Proc> proc;

    // Load + analyze a binary and write the database.
    bool analyzeFile(const std::string& path, const std::string& dbPath, const LoadOptions& lo,
                     const AnalyzeOptions& ao, std::string& err);
    // Open an existing database.
    bool openDb(const std::string& dbPath, std::string& err);

    // Names -------------------------------------------------------------
    bool hasName(uint64_t addr) const { return an.names.count(addr) != 0; }
    std::string label(uint64_t addr) const;       // defined name or auto name (sub_/loc_/data_), demangled
    std::string symbolic(uint64_t addr) const;    // label or label+0xoff, or raw hex
    std::string branchLabel(uint64_t addr) const; // like symbolic(), but intra-function targets read loc_xxxx
    bool resolve(const std::string& expr, uint64_t& addr) const;  // hex / name / name+off

    // Structure --------------------------------------------------------------
    const Func* funcAt(uint64_t addr) const;      // function whose range contains addr
    std::vector<Xref> xrefsTo(uint64_t addr) const;
    std::vector<Xref> xrefsFrom(uint64_t addr) const;

    // Patching ---------------------------------------------------------------------
    std::vector<Patch> patches;
    AnalyzeOptions analyzeOpts;                     // used by reanalyze()
    bool patchBytes(uint64_t addr, const std::vector<uint8_t>& bytes, std::string& err);
    bool unpatch(uint64_t addr, std::string& err);  // reverts every patch overlapping addr
    bool assembleAt(uint64_t addr, const std::string& text, bool force, std::vector<uint8_t>& out, std::string& err);
    bool exportPatched(const std::string& outPath, bool sign, std::string& err);
    bool isPatched(uint64_t addr, uint32_t size) const;
    bool reanalyze(std::string& err);               // rerun auto-analysis on the (patched) image, keeping user edits

    // Edits ----------------------------------------------------------------------
    bool rename(uint64_t addr, const std::string& name, std::string& err);
    bool comment(uint64_t addr, const std::string& text, std::string& err);

private:
    void buildIndexes();
    std::unordered_map<std::string, uint64_t> byName_;
    std::vector<Xref> byDst_;   // sorted by (to, from)
};

}  // namespace er
