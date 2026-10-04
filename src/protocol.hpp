#pragma once
#include "config.hpp"
namespace qbox {
enum Type : uint8_t {
  Exec = 1,
  Stdin = 2,
  Stdout = 3,
  Stderr = 4,
  Exit = 5,
  Signal = 6,
  Ready = 7,
  ExecAgent = 8,
  WorkspaceData = 9,
  WorkspaceDone = 10,
  Resize = 11,
  AuditEvent = 12,
  AuditDone = 13,
  AuditReady = 14
};
struct Frame {
  uint8_t type;
  std::vector<uint8_t> payload;
};
void put_u32(std::vector<uint8_t> &out, uint32_t n);
uint32_t get_u32(const uint8_t *p);
std::vector<uint8_t>
encode_exec(const std::vector<std::string> &args,
            const std::vector<std::string> &extra_environment = {},
            bool agent = false);
void send_frame(socket_t socket, uint8_t type,
                const std::vector<uint8_t> &payload);
Frame receive_frame(socket_t socket, int timeout_ms = 10000);
} // namespace qbox
