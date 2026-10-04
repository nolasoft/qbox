#include "connect_policy.hpp"
#include "payload.hpp"
#include "protocol.hpp"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdexcept>
using namespace qbox;
static void check(bool b, const char *s) {
  if (!b)
    throw std::runtime_error(s);
}
template <class F> static void rejects(F f) {
  bool rejected = false;
  try {
    f();
  } catch (const std::exception &) {
    rejected = true;
  }
  check(rejected, "expected rejection");
}
static bool address(const std::string &ip) {
  sockaddr_in a{};
  a.sin_family = AF_INET;
  if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) == 1)
    return public_address(reinterpret_cast<sockaddr *>(&a));
  sockaddr_in6 b{};
  b.sin6_family = AF_INET6;
  check(inet_pton(AF_INET6, ip.c_str(), &b.sin6_addr) == 1, "parse test IP");
  return public_address(reinterpret_cast<sockaddr *>(&b));
}
int main() {
  try {
    Network n;
    for (auto s : {"",
                   "example.com",
                   "*:443",
                   ":443",
                   "a:0",
                   "a:65536",
                   "a:-1",
                   "a:443/x",
                   "https://a:443",
                   "u@a:443",
                   "a..b:443",
                   "-a:443",
                   "a-:443",
                   "a:4:3",
                   "a b:443",
                   "a$:443",
                   "a\":443",
                   "a.:443x",
                   "999.1.2.3:80",
                   "127.0.0.1:80",
                   "[::1]:80",
                   "[example.com]:443",
                   "[8.8.8.8]:80"})
      rejects([&] { parse_allow(s); });
    auto a = parse_allow("API.Example.COM.:443");
    check(a.host == "api.example.com" && a.port == 443, "normalization");
    check(parse_allow("[2606:4700:4700::1111]:443").literal, "IPv6 literal");
    for (auto ip : {"0.0.0.0",
                    "10.1.2.3",
                    "100.64.0.1",
                    "100.127.255.255",
                    "127.2.3.4",
                    "169.254.169.254",
                    "172.16.1.1",
                    "172.31.1.1",
                    "192.0.0.1",
                    "192.0.2.1",
                    "192.168.1.1",
                    "192.88.99.1",
                    "198.18.0.1",
                    "198.51.100.1",
                    "203.0.113.1",
                    "224.0.0.1",
                    "255.255.255.255",
                    "::",
                    "::1",
                    "::ffff:8.8.8.8",
                    "fc00::1",
                    "fe80::1",
                    "ff02::1",
                    "2001:db8::1",
                    "2001::1",
                    "2002:0808:0808::1",
                    "3fff::1"})
      check(!address(ip), ip);
    for (auto ip : {"1.1.1.1", "8.8.8.8", "100.128.0.1", "172.32.0.1",
                    "192.1.1.1", "2606:4700:4700::1111"})
      check(address(ip), ip);
    // Private answer is skipped; first public connect fails; second succeeds.
    sockaddr_in ips[3]{};
    addrinfo ai[3]{};
    const char *names[] = {"127.0.0.1", "8.8.8.8", "1.1.1.1"};
    for (int i = 0; i < 3; i++) {
      ips[i].sin_family = AF_INET;
      ips[i].sin_port = htons(443);
      inet_pton(AF_INET, names[i], &ips[i].sin_addr);
      ai[i].ai_family = AF_INET;
      ai[i].ai_addr = reinterpret_cast<sockaddr *>(&ips[i]);
      ai[i].ai_addrlen = sizeof(ips[i]);
      ai[i].ai_next = i < 2 ? &ai[i + 1] : nullptr;
    }
    int calls = 0;
    socket_t s = connect_validated(ai, [&](const addrinfo &candidate) {
      check(candidate.ai_addr == reinterpret_cast<sockaddr *>(&ips[calls + 1]),
            "exact validated address");
      calls++;
      return calls == 1 ? invalid_socket : socket_t(42);
    });
    check(s == 42 && calls == 2, "multi-answer fallback");
    ai[0].ai_next = nullptr;
    bool private_called = false;
    rejects([&] {
      connect_validated(ai, [&](const addrinfo &) {
        private_called = true;
        return socket_t(0);
      });
    });
    check(!private_called, "private answers must never reach connect");
    auto cli = [](std::vector<std::string> values) {
      std::vector<char *> argv;
      for (auto &v : values)
        argv.push_back(v.data());
      return parse_cli(static_cast<int>(argv.size()), argv.data());
    };
    auto parsed = cli({"qbox", "run", "--allow", "API.example.com:443",
                       "--allow", "api.example.com:80", "--allow",
                       "auth.example.com:443", "--", "program", "arg"});
    check(parsed.allows[0].guest_ip == parsed.allows[1].guest_ip &&
              parsed.allows[2].guest_ip == "10.0.2.101",
          "host mapping across ports");
    rejects([&] {
      cli({"qbox", "run", "--allow", "A:443", "--allow", "a:443", "--",
           "program"});
    });
    auto cross = cli({"qbox", "run", "--arch",
                      native_arch() == "aarch64" ? "x86_64" : "aarch64",
                      "--accel", "tcg", "--", "program"});
    check(cross.kernel.u8string().find(cross.arch) != std::string::npos,
          "default guest artifact architecture");
    rejects([&] {
      std::vector<std::string> flags = {"qbox", "run"};
      for (unsigned i = 0; i < 33; i++)
        flags.insert(flags.end(),
                     {"--allow", "a" + std::to_string(i) + ".example:80"});
      flags.insert(flags.end(), {"--", "program"});
      cli(flags);
    });
    Config c;
    c.arch = "aarch64";
    c.accel = "tcg";
    c.qemu = "qemu";
    c.kernel = "kernel";
    c.initrd = "initrd";
    c.connector = "/tmp/path with spaces/connector";
    auto cap = parse_allow("api.example.com:443");
    cap.guest_ip = "10.0.2.100";
    c.allows = {cap};
    auto cmd = qemu_command(c, "/tmp/a,b/payload", "path=/tmp/runner.sock");
    auto it = std::find(cmd.begin(), cmd.end(), "-netdev");
    check(it != cmd.end(), "network present");
    check((it + 1)->find("restrict=on,ipv6=off") != std::string::npos,
          "restricted networking");
    check((it + 1)->find("guestfwd=tcp:10.0.2.100:443-cmd:") !=
              std::string::npos,
          "bound guestfwd");
    check(std::find(cmd.begin(), cmd.end(),
                    "local,id=payload,path=/tmp/a,,b/"
                    "payload,security_model=none,readonly=on") != cmd.end(),
          "QEMU comma escaping");
    c.allows.clear();
    cmd = qemu_command(c, "payload", "host=127.0.0.1,port=1234");
    it = std::find(cmd.begin(), cmd.end(), "-netdev");
    check((it + 1)->find("guestfwd") == std::string::npos, "default deny");
    c.payload_mode = "initrd";
    cmd = qemu_command(c, "payload", "host=127.0.0.1,port=1234");
    check(std::find(cmd.begin(), cmd.end(), "-fsdev") == cmd.end(),
          "initrd payload must not expose a host filesystem");
    TempDirectory temp;
    std::filesystem::create_directory(temp.path / "payload");
    for (const auto *name : {"program", "hosts", "token"}) {
      std::ofstream f(temp.path / "payload" / name, std::ios::binary);
      f << name;
    }
    {
      std::ofstream f(temp.path / "base", std::ios::binary);
      f << "base";
    }
    embed_payload(temp.path / "base", temp.path / "payload",
                  temp.path / "image");
    std::ifstream image(temp.path / "image", std::ios::binary);
    std::string bytes{std::istreambuf_iterator<char>(image), {}};
    size_t pos = 4;
    unsigned count = 0;
    while (pos < bytes.size() && bytes.compare(pos, 6, "070701") == 0) {
      unsigned size = std::stoul(bytes.substr(pos + 54, 8), nullptr, 16),
               namesize = std::stoul(bytes.substr(pos + 94, 8), nullptr, 16);
      std::string name = bytes.substr(pos + 110, namesize - 1);
      pos = (pos + 110 + namesize + 3) & ~size_t(3);
      if (name == "TRAILER!!!")
        break;
      check(name.rfind("payload/", 0) == 0,
            "newc paths must be relative payload files");
      if (name != "payload/embedded")
        check(bytes.substr(pos, size) == name.substr(8),
              "newc payload contents");
      pos = (pos + size + 3) & ~size_t(3);
      ++count;
    }
    check(count == 4, "all initrd payload entries written");
    check(windows_quote("a b\\") == "\"a b\\\\\"",
          "Windows trailing slash quoting");
    auto exec = encode_exec({"program", "a b", ""});
    check(get_u32(exec.data()) == 3, "argument encoding");
    rejects([] { encode_exec({std::string(max_frame, 'a')}); });
    std::cout << "core checks passed\n";
    return 0;
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
