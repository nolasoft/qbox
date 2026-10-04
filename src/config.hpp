#pragma once
#include "platform.hpp"
#include <array>
namespace qbox {
constexpr uint32_t max_frame = 1024 * 1024;
constexpr size_t max_allows = 32;
struct Allow {
  std::string host;
  uint16_t port;
  std::string guest_ip;
  bool literal = false;
};
struct Config {
  unsigned memory = 256, timeout = 300, connect_timeout = 30;
  uint64_t output_limit = 64 * 1024 * 1024;
  std::string arch, accel, qemu;
  std::string payload_mode;
  bool agent = false, tty = false;
  uint64_t workspace_limit = 512 * 1024 * 1024;
  std::filesystem::path workspace, audit_log;
  std::vector<std::string> excludes = {".git", ".qbox-results", ".DS_Store"};
  std::vector<std::string> environment;
  std::filesystem::path kernel, initrd, connector, program;
  std::vector<std::string> args;
  std::vector<Allow> allows;
};
std::string native_arch();
Allow parse_allow(const std::string &s);
bool public_address(const sockaddr *address);
Config parse_cli(int argc, char **argv);
void validate_elf(const std::filesystem::path &path, const std::string &arch);
std::string qemu_escape(const std::string &value);
std::vector<std::string> qemu_command(const Config &c,
                                      const std::filesystem::path &payload,
                                      const std::string &endpoint);
std::string hosts_file(const Config &c);
const char *usage();
} // namespace qbox
