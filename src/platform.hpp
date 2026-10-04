#pragma once
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>
#ifdef _WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
using socket_t = SOCKET;
constexpr socket_t invalid_socket = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
using socket_t = int;
constexpr socket_t invalid_socket = -1;
#endif
namespace qbox {
struct Network {
  Network();
  ~Network();
};
void close_socket(socket_t s);
void nonblocking(socket_t s);
bool would_block();
bool ready(socket_t s, bool write, int milliseconds);
void send_all(socket_t s, const void *data, size_t size,
              int timeout_ms = 10000);
void read_all(socket_t s, void *data, size_t size, int timeout_ms = 10000);
std::string random_token();
std::filesystem::path executable_directory();
void binary_stdio();
struct TempDirectory {
  std::filesystem::path path;
  bool preserve = false;
  TempDirectory();
  ~TempDirectory();
  TempDirectory(const TempDirectory &) = delete;
};
struct Listener {
  socket_t fd = invalid_socket;
  std::string endpoint;
  explicit Listener(const std::filesystem::path &directory);
  ~Listener();
  socket_t accept_one(int timeout_ms);
};
struct Process {
#ifdef _WIN32
  HANDLE handle = nullptr, job = nullptr;
#else
  int pid = -1;
#endif
  explicit Process(const std::vector<std::string> &argv,
                   const std::filesystem::path &log);
  ~Process();
  bool running();
  void stop();
  Process(const Process &) = delete;
};
std::string windows_quote(const std::string &value);
} // namespace qbox
