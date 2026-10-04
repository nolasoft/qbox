#pragma once
#include "config.hpp"
#include <map>
namespace qbox {
struct WorkspaceEntry {
  uint8_t kind = 0;
  uint32_t mode = 0;
  std::filesystem::path content;
  std::string target;
};
class Workspace {
  std::filesystem::path root, cache;
  uint64_t limit;
  std::vector<std::string> excludes;
  std::map<std::string, WorkspaceEntry> baseline;

public:
  Workspace(const Config &config, const std::filesystem::path &cache_directory);
  void snapshot(const std::filesystem::path &archive);
  void apply(const std::filesystem::path &archive);
};
} // namespace qbox
