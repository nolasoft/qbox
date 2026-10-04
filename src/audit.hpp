#pragma once
#include "config.hpp"
namespace qbox {
class AuditLog {
#ifdef _WIN32
  HANDLE file = INVALID_HANDLE_VALUE;
#else
  int file = -1;
#endif
  uint64_t bytes = 0, events = 0;
  bool finished = false, failed = false;
  void line(const std::string &s, bool final = false);

public:
  explicit AuditLog(const Config &c);
  ~AuditLog();
  void event(const uint8_t *data, size_t size);
  void done(const uint8_t *data, size_t size);
  bool complete() const { return finished && !failed; }
  AuditLog(const AuditLog &) = delete;
};
} // namespace qbox
