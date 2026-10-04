#include "config.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <set>
#include <stdexcept>
namespace qbox {
static unsigned number(const std::string &s, unsigned low, unsigned high,
                       const char *what) {
  if (s.empty() || s.size() > 10 ||
      !std::all_of(s.begin(), s.end(),
                   [](unsigned char c) { return c >= '0' && c <= '9'; }))
    throw std::runtime_error(std::string("invalid ") + what);
  auto n = std::stoull(s);
  if (n < low || n > high)
    throw std::runtime_error(std::string("out of range ") + what);
  return static_cast<unsigned>(n);
}
std::string native_arch() {
#if defined(__aarch64__) || defined(_M_ARM64)
  return "aarch64";
#else
  return "x86_64";
#endif
}
bool public_address(const sockaddr *s) {
  if (s->sa_family == AF_INET) {
    uint32_t a =
        ntohl(reinterpret_cast<const sockaddr_in *>(s)->sin_addr.s_addr);
    auto match = [a](uint32_t n, unsigned bits) {
      return (a >> (32 - bits)) == (n >> (32 - bits));
    };
    return !(match(0x00000000, 8) || match(0x0a000000, 8) ||
             match(0x64400000, 10) || match(0x7f000000, 8) ||
             match(0xa9fe0000, 16) || match(0xac100000, 12) ||
             match(0xc0000000, 24) || match(0xc0000200, 24) ||
             match(0xc0586300, 24) || match(0xc0a80000, 16) ||
             match(0xc6120000, 15) || match(0xc6336400, 24) ||
             match(0xcb007100, 24) || a >= 0xe0000000);
  }
  if (s->sa_family == AF_INET6) {
    const auto *a =
        reinterpret_cast<const sockaddr_in6 *>(s)->sin6_addr.s6_addr;
    // Accept global unicast only; exclude transition, documentation, and
    // special-use allocations.
    if ((a[0] & 0xe0) != 0x20)
      return false;
    if (a[0] == 0x20 && a[1] == 0x01 &&
        (a[2] < 2 || (a[2] == 0x0d && a[3] == 0xb8)))
      return false;
    if (a[0] == 0x20 && a[1] == 0x02)
      return false;
    if (a[0] == 0x3f && a[1] == 0xff && (a[2] & 0xf0) == 0)
      return false;
    return reinterpret_cast<const sockaddr_in6 *>(s)->sin6_scope_id == 0;
  }
  return false;
}
Allow parse_allow(const std::string &s) {
  std::string host, port;
  bool bracketed = !s.empty() && s.front() == '[';
  if (bracketed) {
    auto end = s.find(']');
    if (end == std::string::npos || end + 1 >= s.size() || s[end + 1] != ':')
      throw std::runtime_error("expected [IPv6]:port");
    host = s.substr(1, end - 1);
    port = s.substr(end + 2);
  } else {
    auto colon = s.find(':');
    if (colon == std::string::npos || colon != s.rfind(':'))
      throw std::runtime_error("expected hostname:port (bracket IPv6)");
    host = s.substr(0, colon);
    port = s.substr(colon + 1);
  }
  Allow out{host, static_cast<uint16_t>(number(port, 1, 65535, "port")), "",
            false};
  sockaddr_in v4{};
  v4.sin_family = AF_INET;
  sockaddr_in6 v6{};
  v6.sin6_family = AF_INET6;
  const sockaddr *addr = nullptr;
  if (inet_pton(AF_INET, host.c_str(), &v4.sin_addr) == 1)
    addr = reinterpret_cast<sockaddr *>(&v4);
  else if (inet_pton(AF_INET6, host.c_str(), &v6.sin6_addr) == 1)
    addr = reinterpret_cast<sockaddr *>(&v6);
  if (addr) {
    if (bracketed && addr->sa_family != AF_INET6)
      throw std::runtime_error("brackets are only valid for IPv6 literals");
    if (!public_address(addr))
      throw std::runtime_error("--allow IP must be public");
    out.literal = true;
    char normalized[INET6_ADDRSTRLEN];
    inet_ntop(addr->sa_family,
              addr->sa_family == AF_INET
                  ? static_cast<const void *>(&v4.sin_addr)
                  : static_cast<const void *>(&v6.sin6_addr),
              normalized, sizeof(normalized));
    out.host = normalized;
    return out;
  }
  if (bracketed)
    throw std::runtime_error("invalid bracketed IPv6 address");
  if (host.empty() || host.size() > 253)
    throw std::runtime_error("invalid hostname");
  std::transform(host.begin(), host.end(), host.begin(), [](unsigned char c) {
    return static_cast<char>(std::tolower(c));
  });
  if (host.back() == '.')
    host.pop_back();
  size_t start = 0;
  while (start < host.size()) {
    size_t end = host.find('.', start);
    if (end == std::string::npos)
      end = host.size();
    size_t len = end - start;
    if (!len || len > 63 || host[start] == '-' || host[end - 1] == '-')
      throw std::runtime_error("invalid DNS label");
    for (size_t i = start; i < end; i++)
      if (!((host[i] >= 'a' && host[i] <= 'z') ||
            (host[i] >= '0' && host[i] <= '9') || host[i] == '-'))
        throw std::runtime_error("only ASCII DNS names are supported");
    start = end + 1;
  }
  if (host.empty() || host.back() == '.' ||
      std::all_of(host.begin(), host.end(),
                  [](char c) { return (c >= '0' && c <= '9') || c == '.'; }))
    throw std::runtime_error("invalid hostname or IP");
  out.host = host;
  return out;
}
const char *usage() {
  return "Usage: qbox run [options] -- ELF [args...]\n"
         "       qbox agent --workspace DIR [--tty] [--env NAME] [options] -- "
         "guest-command [args...]\n"
         "  [--memory MB] [--allow host:port] [--timeout SEC]\n"
         "  [--output-limit BYTES] [--kernel PATH] [--initrd PATH] [--qemu "
         "PATH]\n"
         "  [--connector PATH] [--arch x86_64|aarch64] [--accel auto|tcg]\n"
         "  [--payload-mode 9p|initrd]\n"
         "Agent options: [--workspace-limit BYTES] [--exclude TOP_LEVEL_NAME]\n"
         "  [--audit-log PATH] records process and connection metadata\n"
         "  --env NAME explicitly forwards a host variable; edits write back\n"
         "  automatically after the guest command exits.\n";
}
Config parse_cli(int argc, char **argv) {
  if (argc < 2 ||
      (std::string(argv[1]) != "run" && std::string(argv[1]) != "agent"))
    throw std::runtime_error(usage());
  Config c;
  c.agent = std::string(argv[1]) == "agent";
  if (c.agent) {
    c.memory = 4096;
    c.timeout = 3600;
    c.connect_timeout = 120;
  }
  c.arch = native_arch();
  c.accel = "auto";
#ifdef _WIN32
  c.payload_mode = "initrd";
#else
  c.payload_mode = "9p";
#endif
  auto dir = executable_directory();
#ifdef _WIN32
  c.connector = dir / "qbox-connector.exe";
#else
  c.connector = dir / "qbox-connector";
#endif
  bool separator = false;
  for (int i = 2; i < argc; i++) {
    std::string flag = argv[i];
    if (flag == "--tty") {
      c.tty = true;
      continue;
    }
    if (flag == "--") {
      separator = true;
      for (++i; i < argc; i++)
        c.args.emplace_back(argv[i]);
      break;
    }
    if (i + 1 >= argc)
      throw std::runtime_error("missing value for " + flag);
    std::string value = argv[++i];
    if (flag == "--memory")
      c.memory = number(value, 32, 65536, "memory MB");
    else if (flag == "--timeout")
      c.timeout = number(value, 1, 86400, "timeout seconds");
    else if (flag == "--output-limit")
      c.output_limit = number(value, 1, 0xffffffffu, "output limit");
    else if (flag == "--allow") {
      if (c.allows.size() == max_allows)
        throw std::runtime_error("at most 32 capabilities");
      c.allows.push_back(parse_allow(value));
    } else if (flag == "--kernel")
      c.kernel = std::filesystem::u8path(value);
    else if (flag == "--initrd")
      c.initrd = std::filesystem::u8path(value);
    else if (flag == "--connector")
      c.connector = std::filesystem::u8path(value);
    else if (flag == "--qemu")
      c.qemu = value;
    else if (flag == "--arch")
      c.arch = value;
    else if (flag == "--accel")
      c.accel = value;
    else if (flag == "--payload-mode")
      c.payload_mode = value;
    else if (flag == "--workspace")
      c.workspace = std::filesystem::u8path(value);
    else if (flag == "--audit-log") {
      if (value.empty())
        throw std::runtime_error("--audit-log requires a path");
      c.audit_log = std::filesystem::u8path(value);
    } else if (flag == "--workspace-limit")
      c.workspace_limit =
          number(value, 1024, 0xffffffffu, "workspace byte limit");
    else if (flag == "--exclude") {
      if (value.empty() || value == "." || value == ".." ||
          value.size() > 255 || c.excludes.size() >= 128 ||
          value.find_first_of("/\\:\r\n") != std::string::npos)
        throw std::runtime_error("--exclude requires a top-level name");
      c.excludes.push_back(value);
    } else if (flag == "--env") {
      if (value.empty() ||
          !std::all_of(value.begin(), value.end(),
                       [](unsigned char ch) {
                         return (ch >= 'A' && ch <= 'Z') ||
                                (ch >= 'a' && ch <= 'z') ||
                                (ch >= '0' && ch <= '9') || ch == '_';
                       }) ||
          (value[0] >= '0' && value[0] <= '9'))
        throw std::runtime_error("--env requires an environment variable name");
      if (value == "HOME" || value == "PATH" || value == "TMPDIR")
        throw std::runtime_error(
            "HOME, PATH and TMPDIR are managed by the guest");
      const char *env = std::getenv(value.c_str());
      if (!env)
        throw std::runtime_error("requested environment variable is not set: " +
                                 value);
      if (c.environment.size() >= 64)
        throw std::runtime_error("at most 64 forwarded variables");
      c.environment.push_back(value + "=" + env);
    } else
      throw std::runtime_error("unknown option: " + flag);
  }
  if (!separator || c.args.empty())
    throw std::runtime_error("expected -- ELF [args...]");
  if (c.agent) {
    if (c.workspace.empty() || !std::filesystem::is_directory(c.workspace))
      throw std::runtime_error(
          "agent requires --workspace with an existing directory");
    c.workspace = std::filesystem::canonical(c.workspace);
  } else if (c.tty || !c.workspace.empty() || !c.environment.empty() ||
             !c.audit_log.empty())
    throw std::runtime_error(
        "--tty, --workspace, --env and --audit-log require agent mode");
  if (!c.audit_log.empty()) {
    auto parent = std::filesystem::canonical(
        std::filesystem::absolute(c.audit_log).parent_path());
    c.audit_log = parent / c.audit_log.filename();
    auto relative = c.audit_log.lexically_relative(c.workspace);
    if (relative.empty() || *relative.begin() != "..")
      throw std::runtime_error("audit log must be outside the workspace");
    if (std::filesystem::symlink_status(c.audit_log).type() !=
        std::filesystem::file_type::not_found)
      throw std::runtime_error("audit log destination already exists");
  }
  if (c.arch != "x86_64" && c.arch != "aarch64")
    throw std::runtime_error("unsupported guest architecture");
  if (c.kernel.empty())
    c.kernel = dir / "../share/qbox" / c.arch / "vmlinuz";
  if (c.initrd.empty())
    c.initrd = dir / "../share/qbox" / c.arch / "initramfs.img";
  if (c.accel != "auto" && c.accel != "tcg")
    throw std::runtime_error("accelerator must be auto or tcg");
  if (c.payload_mode != "9p" && c.payload_mode != "initrd")
    throw std::runtime_error("payload mode must be 9p or initrd");
#ifdef _WIN32
  if (c.payload_mode == "9p")
    throw std::runtime_error("QEMU Windows does not provide a local 9P "
                             "backend; use initrd payloads");
#endif
  if (c.arch != native_arch() && c.accel != "tcg")
    throw std::runtime_error(
        "cross-architecture execution requires --accel tcg");
  if (c.qemu.empty())
    c.qemu = "qemu-system-" + c.arch;
  if (!c.agent)
    c.program =
        std::filesystem::absolute(std::filesystem::u8path(c.args.front()));
  std::set<std::pair<std::string, unsigned>> seen;
  std::vector<std::string> hosts;
  for (auto &a : c.allows) {
    if (!seen.emplace(a.host, a.port).second)
      throw std::runtime_error("duplicate capability");
    auto it = std::find(hosts.begin(), hosts.end(), a.host);
    if (it == hosts.end()) {
      hosts.push_back(a.host);
      it = hosts.end() - 1;
    }
    a.guest_ip = "10.0.2." + std::to_string(100 + (it - hosts.begin()));
  }
  return c;
}
void validate_elf(const std::filesystem::path &path, const std::string &arch) {
  if (!std::filesystem::is_regular_file(path))
    throw std::runtime_error("program is not a regular file");
  std::ifstream in(path, std::ios::binary);
  std::array<unsigned char, 64> h{};
  in.read(reinterpret_cast<char *>(h.data()), h.size());
  if (in.gcount() != 64 || h[0] != 0x7f || h[1] != 'E' || h[2] != 'L' ||
      h[3] != 'F' || h[4] != 2 || h[5] != 1 || h[6] != 1 ||
      (h[7] != 0 && h[7] != 3))
    throw std::runtime_error("expected a 64-bit little-endian Linux ELF");
  unsigned machine = h[18] | (h[19] << 8);
  if (machine != (arch == "aarch64" ? 183u : 62u))
    throw std::runtime_error("ELF architecture does not match guest " + arch);
  unsigned type = h[16] | (h[17] << 8);
  if (type != 2 && type != 3)
    throw std::runtime_error("ELF is not executable");
}
std::string qemu_escape(const std::string &s) {
  std::string out;
  for (char ch : s) {
    out += ch;
    if (ch == ',')
      out += ch;
  }
  return out;
}
static std::string command_quote(const std::string &s) {
  // QEMU's command chardev uses GLib argv parsing, not a shell. Double-quoted
  // tokens with escaped quotes/backslashes work on POSIX and Windows GLib.
  std::string out = "\"";
  for (char c : s) {
    if (c == '\\' || c == '\"' || c == '$' || c == '`')
      out += '\\';
    out += c;
  }
  return out + '\"';
}
std::vector<std::string> qemu_command(const Config &c,
                                      const std::filesystem::path &payload,
                                      const std::string &endpoint) {
  std::string accel = c.accel;
  if (accel == "auto") {
#ifdef __APPLE__
    accel = "hvf";
#elif defined(_WIN32)
    accel = "whpx";
#else
    accel = "kvm";
#endif
  }
  std::vector<std::string> a = {
      c.qemu,
      "-machine",
      c.arch == "aarch64" ? "virt,accel=" + accel : "q35,accel=" + accel,
      "-cpu",
      accel == "whpx" ? "qemu64" : (c.accel == "tcg" ? "max" : "host"),
      "-m",
      std::to_string(c.memory),
      "-smp",
      "1",
      "-nodefaults",
      "-no-user-config",
      "-display",
      "none",
      "-monitor",
      "none",
      "-serial",
      "none",
      "-no-reboot",
      "-kernel",
      std::filesystem::absolute(c.kernel).u8string(),
      "-initrd",
      std::filesystem::absolute(c.initrd).u8string(),
      "-append",
      "rdinit=/init panic=-1 quiet ipv6.disable=1",
      "-device",
      "virtio-serial-pci",
      "-chardev",
      "socket,id=runner," + endpoint + ",server=off",
      "-device",
      "virtserialport,chardev=runner,name=qbox.runner"};
  if (c.payload_mode != "initrd")
    a.insert(a.end(),
             {"-fsdev",
              "local,id=payload,path=" + qemu_escape(payload.u8string()) +
                  ",security_model=none,readonly=on",
              "-device", "virtio-9p-pci,fsdev=payload,mount_tag=payload"});
  std::string net = "user,id=n0,restrict=on,ipv6=off";
  for (const auto &cap : c.allows)
    net +=
        ",guestfwd=tcp:" + cap.guest_ip + ":" + std::to_string(cap.port) +
        "-cmd:" +
        qemu_escape(
            command_quote(std::filesystem::absolute(c.connector).u8string()) +
            " " + command_quote(cap.host) + " " + std::to_string(cap.port) +
            " --lease " +
            command_quote((payload.parent_path() / "alive").u8string()));
  a.insert(a.end(), {"-netdev", net, "-device", "virtio-net-pci,netdev=n0"});
  return a;
}
std::string hosts_file(const Config &c) {
  bool mapped_localhost =
      std::any_of(c.allows.begin(), c.allows.end(),
                  [](const Allow &a) { return a.host == "localhost"; });
  std::string out = mapped_localhost ? "" : "127.0.0.1 localhost\n";
  std::set<std::string> done;
  for (const auto &a : c.allows)
    if (done.insert(a.host).second)
      out += a.guest_ip + " " + a.host + "\n";
  return out;
}
} // namespace qbox
