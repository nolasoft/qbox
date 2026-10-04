#include "payload.hpp"
#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
namespace qbox {
// Linux supports concatenated compressed/uncompressed newc archives. This
// Windows-compatible boot injection avoids requiring QEMU's POSIX-only 9P
// backend.
static void padding(std::ostream &out, unsigned alignment) {
  auto offset = static_cast<uint64_t>(out.tellp());
  for (unsigned n = 0; n < (alignment - offset % alignment) % alignment; ++n)
    out.put('\0');
}
static void entry(std::ostream &out, const std::string &name, uint32_t inode,
                  const std::filesystem::path &source = {}) {
  uint64_t size = source.empty() ? 0 : std::filesystem::file_size(source);
  if (size > 0xffffffffu)
    throw std::runtime_error("payload exceeds newc file-size limit");
  uint32_t mode = name == "TRAILER!!!" ? 0 : 0100644;
  std::array<uint32_t, 13> fields{inode,
                                  mode,
                                  0,
                                  0,
                                  1,
                                  0,
                                  static_cast<uint32_t>(size),
                                  0,
                                  0,
                                  0,
                                  0,
                                  static_cast<uint32_t>(name.size() + 1),
                                  0};
  std::ostringstream h;
  h << "070701" << std::hex << std::setfill('0');
  for (uint32_t field : fields)
    h << std::setw(8) << field;
  out << h.str() << name;
  out.put('\0');
  padding(out, 4);
  if (!source.empty()) {
    std::ifstream file(source, std::ios::binary);
    if (!file)
      throw std::runtime_error("cannot read payload");
    out << file.rdbuf();
    if (file.bad())
      throw std::runtime_error("payload read failed");
  }
  padding(out, 4);
}
void embed_payload(const std::filesystem::path &base,
                   const std::filesystem::path &payload,
                   const std::filesystem::path &destination) {
  std::ifstream input(base, std::ios::binary);
  std::ofstream out(destination, std::ios::binary);
  if (!input || !out)
    throw std::runtime_error("cannot stage per-run initramfs");
  out << input.rdbuf();
  if (input.bad())
    throw std::runtime_error("initramfs read failed");
  padding(out, 4);
  uint32_t inode = 1;
  for (const auto *name :
       {"program", "hosts", "token", "agent", "workspace", "excludes", "audit"})
    if (std::filesystem::is_regular_file(payload / name))
      entry(out, std::string("payload/") + name, inode++, payload / name);
  entry(out, "payload/embedded", inode++);
  entry(out, "TRAILER!!!", inode);
  padding(out, 512);
  if (!out)
    throw std::runtime_error("per-run initramfs write failed");
}
} // namespace qbox
