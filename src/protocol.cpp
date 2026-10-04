#include "protocol.hpp"
#include <stdexcept>
namespace qbox {
void put_u32(std::vector<uint8_t> &o, uint32_t n) {
  o.push_back(n >> 24);
  o.push_back(n >> 16);
  o.push_back(n >> 8);
  o.push_back(n);
}
uint32_t get_u32(const uint8_t *p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
         (uint32_t(p[2]) << 8) | p[3];
}
std::vector<uint8_t>
encode_exec(const std::vector<std::string> &args,
            const std::vector<std::string> &extra_environment, bool agent) {
  if (args.empty() || args.size() > 256)
    throw std::runtime_error("EXEC requires 1..256 arguments");
  std::vector<uint8_t> out;
  put_u32(out, static_cast<uint32_t>(args.size()));
  for (const auto &s : args) {
    if (s.find('\0') != std::string::npos || s.size() > max_frame)
      throw std::runtime_error("invalid argument");
    put_u32(out, static_cast<uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
  }
  // An intentionally fixed, minimal environment; never forward host secrets.
  std::vector<std::string> env = {
      "PATH=/", "HOME=/run", "LANG=C",
      "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"};
  if (agent)
    env = {"PATH=/usr/local/bin:/usr/bin:/bin",
           "HOME=/home/agent",
           "TMPDIR=/tmp",
           "LANG=C.UTF-8",
           "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
           "TERM=xterm-256color"};
  env.insert(env.end(), extra_environment.begin(), extra_environment.end());
  put_u32(out, static_cast<uint32_t>(env.size()));
  for (const auto &s : env) {
    put_u32(out, static_cast<uint32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
  }
  if (out.size() > max_frame)
    throw std::runtime_error("EXEC exceeds frame limit");
  return out;
}
void send_frame(socket_t s, uint8_t type, const std::vector<uint8_t> &p) {
  if (p.size() > max_frame)
    throw std::runtime_error("frame too large");
  std::vector<uint8_t> h{type};
  put_u32(h, static_cast<uint32_t>(p.size()));
  send_all(s, h.data(), h.size());
  if (!p.empty())
    send_all(s, p.data(), p.size());
}
Frame receive_frame(socket_t s, int ms) {
  uint8_t h[5];
  read_all(s, h, 5, ms);
  uint32_t n = get_u32(h + 1);
  if (n > max_frame)
    throw std::runtime_error("guest frame exceeds limit");
  Frame f{h[0], std::vector<uint8_t>(n)};
  if (n)
    read_all(s, f.payload.data(), n, ms);
  return f;
}
} // namespace qbox
