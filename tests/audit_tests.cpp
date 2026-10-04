#include "audit.hpp"
#include <cassert>
#include <fstream>
#include <iostream>
using namespace qbox;
int main() {
  TempDirectory directory;
  Config c;
  c.arch = "aarch64";
  c.audit_log = directory.path / "audit.jsonl";
  bool capacity = false;
  {
    AuditLog log(c);
    std::vector<uint8_t> event(336);
    event[8] = 2;
    event[12] = event[16] = 7;
    std::fill(event.begin() + 60, event.begin() + 315, 'x');
    try {
      for (unsigned i = 0; i < 300000; i++)
        log.event(event.data(), event.size());
    } catch (const std::exception &e) {
      capacity =
          std::string(e.what()).find("capacity exhausted") != std::string::npos;
    }
  }
  assert(capacity);
  assert(std::filesystem::file_size(c.audit_log) <= 64ull * 1024 * 1024);
  std::ifstream file(c.audit_log, std::ios::binary);
  file.seekg(-128, std::ios::end);
  std::string tail(std::istreambuf_iterator<char>(file), {});
  assert(tail.find("\"complete\":false") != std::string::npos);
  bool exclusive = false;
  try {
    AuditLog duplicate(c);
  } catch (...) {
    exclusive = true;
  }
  assert(exclusive);
  std::cout << "audit capacity, incomplete completion and exclusive creation "
               "passed\n";
}
