#include "audit.hpp"
#include "protocol.hpp"
#include <sstream>
#include <stdexcept>
#ifdef _WIN32
#include <sddl.h>
#else
#include <fcntl.h>
#endif
namespace qbox {
static constexpr uint64_t limit = 64ull * 1024 * 1024;
static uint32_t le32(const uint8_t *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) |
         (uint32_t(p[3]) << 24);
}
static uint64_t le64(const uint8_t *p) {
  return le32(p) | (uint64_t(le32(p + 4)) << 32);
}
static uint64_t be64(const uint8_t *p) {
  return (uint64_t(get_u32(p)) << 32) | get_u32(p + 4);
}
static std::string quote(const uint8_t *p, size_t n) {
  std::string s = "\"";
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < n && p[i]; i++) {
    unsigned char c = p[i];
    if (c == '"' || c == '\\') {
      s += '\\';
      s += char(c);
    } else if (c < 32 || c >= 127) {
      s += "\\u00";
      s += hex[c >> 4];
      s += hex[c & 15];
    } else
      s += char(c);
  }
  return s + '"';
}
AuditLog::AuditLog(const Config &c) {
#ifdef _WIN32
  // Protected DACL: only this token's user may access the audit file.
  HANDLE token = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    throw std::runtime_error("cannot identify audit log owner");
  DWORD length = 0;
  GetTokenInformation(token, TokenUser, nullptr, 0, &length);
  std::vector<uint8_t> info(length);
  bool valid =
      GetTokenInformation(token, TokenUser, info.data(), length, &length);
  CloseHandle(token);
  LPWSTR sid = nullptr;
  if (!valid ||
      !ConvertSidToStringSidW(
          reinterpret_cast<TOKEN_USER *>(info.data())->User.Sid, &sid))
    throw std::runtime_error("cannot identify audit log owner");
  std::wstring sddl = L"D:P(A;;GA;;;" + std::wstring(sid) + L")";
  LocalFree(sid);
  PSECURITY_DESCRIPTOR descriptor = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
          sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
    throw std::runtime_error("cannot protect audit log");
  SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
  file = CreateFileW(c.audit_log.c_str(), GENERIC_WRITE, 0, &attributes,
                     CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
  LocalFree(descriptor);
  if (file == INVALID_HANDLE_VALUE)
#else
  file = open(c.audit_log.c_str(),
              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
  if (file < 0)
#endif
    throw std::runtime_error("cannot create new private audit log");
  try {
    line("{\"version\":1,\"event\":\"session\",\"arch\":\"" + c.arch +
         "\",\"metadata_only\":true}");
  } catch (...) {
#ifdef _WIN32
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
#else
    close(file);
    file = -1;
#endif
    throw;
  }
}
void AuditLog::line(const std::string &s, bool final) {
  std::string data = s + '\n';
  // Leave room for an incomplete completion record after hitting the cap.
  if (data.size() > limit - (final ? 0 : 1024) - bytes) {
    failed = true;
    throw std::runtime_error("audit log capacity exhausted");
  }
  size_t pos = 0;
  while (pos < data.size()) {
#ifdef _WIN32
    DWORD n = 0;
    if (!WriteFile(file, data.data() + pos, DWORD(data.size() - pos), &n,
                   nullptr) ||
        !n)
#else
    ssize_t n = write(file, data.data() + pos, data.size() - pos);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0)
#endif
    {
      failed = true;
      throw std::runtime_error("cannot write audit log");
    }
    pos += size_t(n);
    bytes += uint64_t(n);
  }
}
void AuditLog::event(const uint8_t *p, size_t size) {
  if (finished || size != 336 || le32(p + 8) < 1 || le32(p + 8) > 5 ||
      le32(p + 40) > 1 || le32(p + 332) || p[59] || p[315])
    throw std::runtime_error("invalid audit event");
  static const char *names[] = {
      "", "fork", "exec", "exit", "connect_attempt", "connect_result"};
  uint32_t type = le32(p + 8), family = le32(p + 28), port = le32(p + 32);
  if (type >= 4 && ((family != 2 && family != 10) || port > 65535))
    throw std::runtime_error("invalid audit connection event");
  std::ostringstream out;
  out << "{\"event\":\"" << names[type] << "\",\"guest_ns\":" << le64(p)
      << ",\"tid\":" << le32(p + 12) << ",\"pid\":" << le32(p + 16)
      << ",\"parent_tid\":" << le32(p + 20) << ",\"uid\":" << le32(p + 24)
      << ",\"comm\":" << quote(p + 44, 16);
  if (type == 2)
    out << ",\"executable\":" << quote(p + 60, 256)
        << ",\"truncated\":" << (le32(p + 40) ? "true" : "false");
  if (type == 3 || type == 5)
    out << ",\"result\":" << int32_t(le32(p + 36));
  if (type >= 4) {
    char address[INET6_ADDRSTRLEN];
    if (!inet_ntop(family == 2 ? AF_INET : AF_INET6, p + 316, address,
                   sizeof(address)))
      throw std::runtime_error("invalid audit address");
    out << ",\"family\":" << (family == 2 ? 4 : 6) << ",\"address\":\""
        << address << "\",\"port\":" << port;
  }
  out << '}';
  line(out.str());
  events++;
}
void AuditLog::done(const uint8_t *p, size_t size) {
  if (finished || size != 20 || get_u32(p) > 1)
    throw std::runtime_error("invalid audit completion");
  uint64_t count = be64(p + 4), lost = be64(p + 12);
  bool complete = !failed && !get_u32(p) && !lost && count == events;
  line("{\"event\":\"completion\",\"complete\":" +
           std::string(complete ? "true" : "false") +
           ",\"events\":" + std::to_string(events) + ",\"guest_events\":" +
           std::to_string(count) + ",\"lost\":" + std::to_string(lost) + "}",
       true);
#ifdef _WIN32
  if (!FlushFileBuffers(file))
#else
  if (fsync(file))
#endif
  {
    failed = true;
    throw std::runtime_error("cannot flush audit log");
  }
  finished = true;
  failed = !complete;
}
AuditLog::~AuditLog() {
  if (!finished) {
    try {
      line("{\"event\":\"completion\",\"complete\":false,\"events\":" +
               std::to_string(events) + "}",
           true);
    } catch (...) {
    }
  }
#ifdef _WIN32
  if (file != INVALID_HANDLE_VALUE)
    CloseHandle(file);
#else
  if (file >= 0)
    close(file);
#endif
}
} // namespace qbox
