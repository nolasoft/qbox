#include "protocol.hpp"
#include "workspace.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace qbox;
namespace fs = std::filesystem;
static void check(bool v, const char *message) {
  if (!v)
    throw std::runtime_error(message);
}
static void write(const fs::path &path, const std::string &text) {
  std::ofstream f(path, std::ios::binary);
  f << text;
  if (!f)
    throw std::runtime_error("test write failed");
}
static std::string read(const fs::path &p) {
  std::ifstream f(p, std::ios::binary);
  return {std::istreambuf_iterator<char>(f), {}};
}
struct Entry {
  uint8_t kind;
  uint32_t mode;
  std::string data;
};
using Tree = std::map<std::string, Entry>;
static Tree tree(const fs::path &file) {
  std::ifstream f(file, std::ios::binary);
  f.seekg(8);
  Tree result;
  while (true) {
    uint8_t h[17];
    f.read(reinterpret_cast<char *>(h), 17);
    if (!f)
      throw std::runtime_error("archive read");
    if (!h[0])
      break;
    uint32_t len = get_u32(h + 5), size = get_u32(h + 13);
    std::string path(len, '\0'), data(size, '\0');
    f.read(path.data(), len);
    f.read(data.data(), size);
    result.emplace(path, Entry{h[0], get_u32(h + 1), std::move(data)});
  }
  return result;
}
static void archive(const fs::path &file, const Tree &entries) {
  std::ofstream f(file, std::ios::binary);
  f.write("QBWS0001", 8);
  for (const auto &[name, e] : entries) {
    std::vector<uint8_t> h{e.kind};
    put_u32(h, e.mode);
    put_u32(h, static_cast<uint32_t>(name.size()));
    put_u32(h, 0);
    put_u32(h, static_cast<uint32_t>(e.data.size()));
    f.write(reinterpret_cast<const char *>(h.data()), h.size());
    f.write(name.data(), name.size());
    f.write(e.data.data(), e.data.size());
  }
  uint8_t end[17]{};
  f.write(reinterpret_cast<char *>(end), 17);
}
template <class F> static void rejects(F f) {
  bool rejected = false;
  try {
    f();
  } catch (const std::exception &) {
    rejected = true;
  }
  check(rejected, "expected safe rejection");
}
int main() {
  try {
    Network net;
    TempDirectory temp;
    Config c;
    c.workspace = temp.path / "project";
    fs::create_directory(c.workspace);
    fs::create_directory(c.workspace / ".git");
    write(c.workspace / ".git" / "config", "host metadata");
    write(c.workspace / "keep", "keep");
    write(c.workspace / "change", "old");
    write(c.workspace / "remove", "remove");
    fs::create_directory(c.workspace / "dir");
    write(c.workspace / "dir" / "file", "nested");
    Workspace workspace(c, temp.path / "cache");
    auto input = temp.path / "input", output = temp.path / "output";
    workspace.snapshot(input);
    auto entries = tree(input);
    check(!entries.count(".git"), "git metadata excluded");
    entries["change"].data = "agent edit";
    entries.erase("remove");
    entries["new"] = {2, 0644, std::string("binary\0data", 11)};
    write(c.workspace / "keep", "concurrent untouched edit");
    archive(output, entries);
    workspace.apply(output);
    check(read(c.workspace / "change") == "agent edit", "file update");
    check(!fs::exists(c.workspace / "remove"), "file deletion");
    check(read(c.workspace / "new") == std::string("binary\0data", 11),
          "binary creation");
    check(read(c.workspace / "keep") == "concurrent untouched edit",
          "preserve independent host edit");
    check(read(c.workspace / ".git" / "config") == "host metadata",
          "metadata preserved");
    Workspace conflicting(c, temp.path / "conflict-cache");
    conflicting.snapshot(input);
    auto conflict = tree(input);
    conflict["change"].data = "second agent edit";
    conflict["new2"] = {2, 0644, "new file"};
    write(c.workspace / "change", "concurrent same-file edit");
    archive(output, conflict);
    rejects([&] { conflicting.apply(output); });
    check(read(c.workspace / "change") == "concurrent same-file edit" &&
              !fs::exists(c.workspace / "new2"),
          "conflict preflight must not partially apply");
    Workspace secure(c, temp.path / "secure-cache");
    secure.snapshot(input);
    for (const auto &name :
         {"../escape", "/absolute", "dir/../escape", "dir\\escape",
          "dir//escape", "CON", ".git/config", ".GIT/config", "bad?name"}) {
      auto unsafe = tree(input);
      unsafe[name] = {2, 0644, "unsafe"};
      archive(output, unsafe);
      rejects([&] { secure.apply(output); });
    }
    auto unsafe = tree(input);
    unsafe["link"] = {3, 0777, "../outside"};
    archive(output, unsafe);
    rejects([&] { secure.apply(output); });
    unsafe = tree(input);
    unsafe["alias"] = {3, 0777, "."};
    unsafe["chained"] = {3, 0777, "alias/.."};
    archive(output, unsafe);
    rejects([&] { secure.apply(output); });
#ifndef _WIN32
    fs::create_symlink("../outside", c.workspace / "bad-link");
    Workspace invalid(c, temp.path / "invalid-cache");
    rejects([&] { invalid.snapshot(input); });
    fs::remove(c.workspace / "bad-link");
    Workspace redirected(c, temp.path / "redirect-cache");
    redirected.snapshot(input);
    auto redirect = tree(input);
    redirect["dir/file"].data = "changed";
    fs::rename(c.workspace / "dir", temp.path / "saved-dir");
    fs::create_directory(temp.path / "outside");
    fs::create_symlink(temp.path / "outside", c.workspace / "dir");
    archive(output, redirect);
    rejects([&] { redirected.apply(output); });
    check(!fs::exists(temp.path / "outside" / "file"),
          "symlink ancestor must not be followed");
#endif
    std::cout << "workspace creation/update/deletion, binary data, conflict "
                 "and traversal checks passed\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
