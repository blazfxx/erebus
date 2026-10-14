// Erebus database (.erdb): a SQLite file holding the image bytes, analysis results and user edits.
#pragma once
#include <string>
#include <vector>

#include "analysis/analyzer.h"
#include "core/image.h"

struct sqlite3;

namespace er {

class Database {
public:
    Database() = default;
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    bool create(const std::string& path, const Image& img, const Analysis& an, std::string& err);
    bool open(const std::string& path, std::string& err);
    bool load(Image& img, Analysis& an, std::string& err);

    // user edits (persisted immediately)
    bool setName(uint64_t addr, const std::string& name, std::string& err);
    bool setComment(uint64_t addr, const std::string& text, std::string& err);

    // patches
    bool writeBytes(size_t segIndex, uint64_t off, const uint8_t* data, size_t n, std::string& err);
    bool addPatch(Patch& p, std::string& err);
    bool removePatch(int64_t id, std::string& err);
    bool loadPatches(std::vector<Patch>& out);
    const std::string& path() const { return path_; }

private:
    sqlite3* db_ = nullptr;
    std::string path_;
    bool exec(const char* sql, std::string& err);
};

}  // namespace er
