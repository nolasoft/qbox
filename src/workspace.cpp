#include "workspace.hpp"
#include "protocol.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <stdexcept>
namespace qbox {
namespace fs = std::filesystem;
using Tree = std::map<std::string, WorkspaceEntry>;
static void fail(const std::string &message) {
  throw std::runtime_error("workspace: " + message);
}
static bool excluded(const std::string &path,
                     const std::vector<std::string> &names) {
  auto top = path.substr(0, path.find('/'));
  // Protect excluded directories on case-insensitive host filesystems too.
  auto fold = [](std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                     return c >= 'A' && c <= 'Z' ? char(c + 'a' - 'A') : char(c);
                   });
    return value;
  };
  top = fold(top);
  return std::any_of(names.begin(), names.end(),
                     [&](const auto &name) { return fold(name) == top; });
}
static void valid_path(const std::string &path) {
  if (path.empty() || path.size() > 4096 || path[0] == '/' ||
      path.find('\0') != std::string::npos ||
      path.find_first_of("\\:<>\"|?*") != std::string::npos ||
      std::any_of(path.begin(), path.end(),
                  [](unsigned char c) { return c < 32; }))
    fail("unsafe path");
  size_t pos = 0;
  while (pos < path.size()) {
    auto end = path.find('/', pos);
    if (end == std::string::npos)
      end = path.size();
    auto part = path.substr(pos, end - pos);
    if (part.empty() || part == "." || part == ".." || part.back() == '.' ||
        part.back() == ' ')
      fail("unsafe path component");
    std::string name = part.substr(0, part.find('.'));
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
      return static_cast<char>(std::toupper(c));
    });
    if (name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" ||
        (name.size() == 4 &&
         (name.rfind("COM", 0) == 0 || name.rfind("LPT", 0) == 0) &&
         name[3] >= '1' && name[3] <= '9'))
      fail("reserved path component");
    pos = end + 1;
  }
  if (path.back() == '/')
    fail("trailing slash");
}
static void valid_link(const std::string &path, const std::string &target) {
  if (target.empty() || target.find('\0') != std::string::npos ||
      target.find_first_of("\\:\r\n") != std::string::npos || target[0] == '/')
    fail("symlink must stay inside the workspace");
  for (const auto &component : fs::u8path(target))
    if (component == "..")
      fail("parent traversal in symlink target is unsupported");
  auto resolved = (fs::u8path(path).parent_path() / fs::u8path(target))
                      .lexically_normal()
                      .generic_u8string();
  if (resolved == ".." || resolved.rfind("../", 0) == 0)
    fail("symlink escapes workspace");
  if (resolved != "." && !resolved.empty())
    valid_path(resolved);
}
static bool same_file(const fs::path &a, const fs::path &b) {
  if (fs::file_size(a) != fs::file_size(b))
    return false;
  std::ifstream x(a, std::ios::binary), y(b, std::ios::binary);
  if (!x || !y)
    fail("cannot compare file");
  char p[65536], q[65536];
  while (x) {
    x.read(p, sizeof(p));
    y.read(q, sizeof(q));
    auto n = x.gcount();
    if (n != y.gcount() || !std::equal(p, p + n, q))
      return false;
  }
  if (x.bad() || y.bad())
    fail("file read failed");
  return true;
}
static bool equal(const WorkspaceEntry &a, const WorkspaceEntry &b) {
  return a.kind == b.kind && a.mode == b.mode &&
         (a.kind == 2   ? same_file(a.content, b.content)
          : a.kind == 3 ? a.target == b.target
                        : true);
}
static WorkspaceEntry current(const fs::path &path) {
  auto status = fs::symlink_status(path);
  WorkspaceEntry e;
  e.mode = static_cast<uint32_t>(status.permissions()) & 0777;
  if (fs::is_symlink(status)) {
    e.kind = 3;
    e.mode = 0777;
    e.target = fs::read_symlink(path).generic_u8string();
  } else if (fs::is_directory(status))
    e.kind = 1;
  else if (fs::is_regular_file(status)) {
    e.kind = 2;
    e.content = path;
  } else if (status.type() != fs::file_type::not_found)
    fail("special files cannot be synchronized");
  return e;
}
static void ancestors(const fs::path &root, const std::string &name) {
  auto path = root;
  auto relative = fs::u8path(name);
  for (auto it = relative.begin(); it != relative.end(); ++it) {
    auto next = it;
    ++next;
    if (next == relative.end())
      break;
    path /= *it;
    auto s = fs::symlink_status(path);
    if (fs::is_symlink(s) ||
        (!fs::is_directory(s) && s.type() != fs::file_type::not_found))
      fail("host ancestor is not a directory: " + path.u8string());
  }
}
static void bytes(std::istream &in, void *p, size_t n) {
  if (n && !in.read(static_cast<char *>(p), n))
    fail("truncated archive");
}
static uint64_t u64(const uint8_t *p) {
  return (uint64_t(get_u32(p)) << 32) | get_u32(p + 4);
}
static void record(std::ostream &out, const std::string &path,
                   const WorkspaceEntry &e) {
  uint64_t size = e.kind == 2   ? fs::file_size(e.content)
                  : e.kind == 3 ? e.target.size()
                                : 0;
  std::vector<uint8_t> h{e.kind};
  put_u32(h, e.mode);
  put_u32(h, static_cast<uint32_t>(path.size()));
  put_u32(h, static_cast<uint32_t>(size >> 32));
  put_u32(h, static_cast<uint32_t>(size));
  out.write(reinterpret_cast<const char *>(h.data()), h.size());
  out.write(path.data(), path.size());
  if (e.kind == 2 && size) {
    std::ifstream file(e.content, std::ios::binary);
    if (!file)
      fail("cannot read snapshot");
    out << file.rdbuf();
    if (file.bad())
      fail("snapshot read failed");
  }
  if (e.kind == 3)
    out.write(e.target.data(), e.target.size());
  if (!out)
    fail("archive write failed");
}
static Tree unpack(const fs::path &archive, const fs::path &cache,
                   uint64_t limit, const std::vector<std::string> &excludes) {
  if (fs::file_size(archive) > limit)
    fail("export exceeds workspace limit");
  std::ifstream in(archive, std::ios::binary);
  char magic[8];
  bytes(in, magic, 8);
  if (std::string(magic, 8) != "QBWS0001")
    fail("invalid archive magic");
  Tree result;
  std::set<std::string> names;
  size_t count = 0;
  while (true) {
    uint8_t h[17];
    bytes(in, h, 17);
    uint8_t kind = h[0];
    uint32_t mode = get_u32(h + 1), len = get_u32(h + 5);
    uint64_t size = u64(h + 9);
    if (!kind) {
      if (mode || len || size || in.peek() != std::char_traits<char>::eof())
        fail("invalid archive terminator");
      break;
    }
    if (kind > 3 || !len || len > 4096 || size > limit || ++count > 100000 ||
        (kind == 1 && size) || (kind == 3 && size > 4096))
      fail("invalid archive entry");
    std::string path(len, '\0');
    bytes(in, path.data(), len);
    valid_path(path);
    if (excluded(path, excludes))
      fail("export contains protected path: " + path);
    std::string key = path;
#ifdef _WIN32
    auto wide = fs::u8path(path).native();
    int n = LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, wide.data(),
                          static_cast<int>(wide.size()), nullptr, 0, nullptr,
                          nullptr, 0);
    std::wstring folded(n, L'\0');
    LCMapStringEx(LOCALE_NAME_INVARIANT, LCMAP_LOWERCASE, wide.data(),
                  static_cast<int>(wide.size()), folded.data(), n, nullptr,
                  nullptr, 0);
    key = fs::path(folded).u8string();
#endif
    if (!names.insert(key).second)
      fail("duplicate archive path");
    WorkspaceEntry e{kind, mode & 0777, {}, {}};
    if (kind == 2) {
      e.content = cache / std::to_string(count);
      std::ofstream f(e.content, std::ios::binary);
      if (!f)
        fail("cannot stage export");
      char b[65536];
      for (uint64_t left = size; left;) {
        auto n = static_cast<size_t>(std::min(left, uint64_t(sizeof(b))));
        bytes(in, b, n);
        f.write(b, n);
        left -= n;
      }
      if (!f)
        fail("export staging failed");
    } else if (kind == 3) {
      e.mode = 0777;
      e.target.resize(static_cast<size_t>(size));
      bytes(in, e.target.data(), e.target.size());
      valid_link(path, e.target);
    }
    result.emplace(path, std::move(e));
  }
  for (const auto &[name, e] : result) {
    auto parent = fs::u8path(name).parent_path().generic_u8string();
    while (!parent.empty()) {
      auto it = result.find(parent);
      if (it == result.end() || it->second.kind != 1)
        fail("archive parent is not a directory");
      parent = fs::u8path(parent).parent_path().generic_u8string();
    }
  }
  return result;
}
Workspace::Workspace(const Config &c, const fs::path &directory)
    : root(c.workspace), cache(directory), limit(c.workspace_limit),
      excludes(c.excludes) {
  fs::create_directories(cache / "original");
  fs::create_directories(cache / "returned");
}
void Workspace::snapshot(const fs::path &archive) {
  uint64_t size = 25;
  size_t count = 0;
  for (fs::recursive_directory_iterator it(root), end; it != end; ++it) {
    auto name = it->path().lexically_relative(root).generic_u8string();
    if (excluded(name, excludes)) {
      if (it->is_directory())
        it.disable_recursion_pending();
      continue;
    }
    valid_path(name);
    if (++count > 100000)
      fail("too many files");
    auto e = current(it->path());
    if (e.kind == 3)
      valid_link(name, e.target);
    size += 17 + name.size() +
            (e.kind == 2   ? fs::file_size(e.content)
             : e.kind == 3 ? e.target.size()
                           : 0);
    if (size > limit)
      fail("snapshot exceeds --workspace-limit; use --exclude for large "
           "generated directories");
    if (e.kind == 2) {
      auto saved = cache / "original" / std::to_string(count);
      fs::copy_file(e.content, saved);
      if (!fs::is_regular_file(fs::symlink_status(e.content)))
        fail("file changed type during snapshot");
      e.content = saved;
    }
    baseline.emplace(name, std::move(e));
  }
  std::ofstream out(archive, std::ios::binary);
  out.write("QBWS0001", 8);
  for (const auto &[name, e] : baseline)
    record(out, name, e);
  record(out, "", {});
  out.close();
  if (!out || fs::file_size(archive) > limit)
    fail("snapshot write failed or exceeded limit");
}
void Workspace::apply(const fs::path &archive) {
  Tree returned = unpack(archive, cache / "returned", limit, excludes);
  std::set<std::string> changes;
  for (const auto &[name, e] : baseline) {
    auto it = returned.find(name);
    if (it == returned.end() || !equal(e, it->second))
      changes.insert(name);
  }
  for (const auto &[name, e] : returned)
    if (!baseline.count(name))
      changes.insert(name);
  // Preflight the entire change set before the first write. Unchanged agent
  // files leave concurrent host edits untouched; changed files require the
  // launch baseline.
  for (const auto &name : changes) {
    ancestors(root, name);
    auto now = current(root / fs::u8path(name));
    auto old = baseline.find(name);
    auto updated = returned.find(name);
    if (old == baseline.end()) {
      if (now.kind &&
          (updated == returned.end() || !equal(now, updated->second)))
        fail("new file conflicts with host: " + name);
    } else if (!equal(now, old->second))
      fail("host file changed while agent ran: " + name);
    if (now.kind == 1 &&
        (updated == returned.end() || updated->second.kind != 1)) {
      for (fs::recursive_directory_iterator it(root / fs::u8path(name)), end;
           it != end; ++it) {
        auto child = it->path().lexically_relative(root).generic_u8string();
        if (!baseline.count(child) || !changes.count(child))
          fail("directory contains concurrent or preserved host files: " +
               name);
      }
    }
  }
  std::vector<std::string> deepest(changes.begin(), changes.end());
  std::sort(deepest.begin(), deepest.end(),
            [](const auto &a, const auto &b) { return a.size() > b.size(); });
  for (const auto &name : deepest) {
    auto old = baseline.find(name), next = returned.find(name);
    if (old != baseline.end() &&
        (next == returned.end() || old->second.kind != next->second.kind)) {
      ancestors(root, name);
      if (!equal(current(root / fs::u8path(name)), old->second))
        fail("host changed during writeback: " + name);
      if (!fs::remove(root / fs::u8path(name)))
        fail("cannot remove " + name);
    }
  }
  for (const auto &[name, e] : returned)
    if (changes.count(name) && e.kind == 1) {
      ancestors(root, name);
      fs::create_directories(root / fs::u8path(name));
    }
  for (const auto &[name, e] : returned)
    if (changes.count(name) && e.kind != 1) {
      ancestors(root, name);
      auto destination = root / fs::u8path(name);
      auto old = baseline.find(name);
      auto now = current(destination);
      if (old != baseline.end() && old->second.kind == e.kind) {
        if (!equal(now, old->second) && !equal(now, e))
          fail("host changed during writeback: " + name);
      } else if (now.kind && !equal(now, e))
        fail("host changed during writeback: " + name);
      auto staged = destination.parent_path() /
                    fs::u8path(".qbox-write-" + random_token().substr(0, 24));
      try {
        if (e.kind == 2) {
          fs::copy_file(e.content, staged);
          fs::permissions(staged, static_cast<fs::perms>(e.mode));
        } else
          fs::create_symlink(fs::u8path(e.target), staged);
#ifdef _WIN32
        if (!MoveFileExW(staged.c_str(), destination.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
          fail("atomic replacement failed: " + name);
#else
        fs::rename(staged, destination);
#endif
      } catch (...) {
        std::error_code error;
        fs::remove(staged, error);
        throw;
      }
    }
  for (const auto &name : deepest) {
    auto next = returned.find(name);
    if (next != returned.end() && next->second.kind == 1)
      fs::permissions(root / fs::u8path(name),
                      static_cast<fs::perms>(next->second.mode));
  }
}
} // namespace qbox
