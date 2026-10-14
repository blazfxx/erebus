#include "loaders/loader.h"

#include <fstream>
#include <iterator>

namespace er {

std::unique_ptr<Image> loadFile(const std::string& path, const LoadOptions& opt, std::string& err) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "cannot open " + path;
        return nullptr;
    }
    std::vector<uint8_t> file((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    if (file.size() < 16) {
        err = "file too small";
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
