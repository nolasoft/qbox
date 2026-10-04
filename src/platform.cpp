#include "platform.hpp"
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <thread>
#ifdef _WIN32
#include <bcrypt.h>
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
extern char **environ;
#endif
namespace qbox {
Network::Network() {
#ifdef _WIN32
  WSADATA w;
  if (WSAStartup(MAKEWORD(2, 2), &w))
    throw std::runtime_error("Winsock startup failed");
#else
  signal(SIGPIPE, SIG_IGN);
#endif
}
Network::~Network() {
#ifdef _WIN32
  WSACleanup();
#endif
}
void close_socket(socket_t s) {
  if (s == invalid_socket)
    return;
#ifdef _WIN32
  closesocket(s);
#else
  close(s);
#endif
}
void nonblocking(socket_t s) {
#ifdef _WIN32
  u_long one = 1;
  if (ioctlsocket(s, FIONBIO, &one))
    throw std::runtime_error("ioctlsocket failed");
  SetHandleInformation(reinterpret_cast<HANDLE>(s), HANDLE_FLAG_INHERIT, 0);
#else
  if (fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK) < 0 ||
      fcntl(s, F_SETFD, FD_CLOEXEC) < 0)
    throw std::runtime_error("fcntl failed");
#endif
}
bool would_block() {
#ifdef _WIN32
  int e = WSAGetLastError();
  return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEINTR;
#else
  return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS ||
         errno == EINTR;
#endif
}
bool ready(socket_t s, bool write, int ms) {
  fd_set f;
  FD_ZERO(&f);
  FD_SET(s, &f);
  timeval tv{ms / 1000, (ms % 1000) * 1000};
  int n = select(static_cast<int>(s) + 1, write ? nullptr : &f,
                 write ? &f : nullptr, nullptr, &tv);
  if (n < 0 && would_block())
    return false;
  if (n < 0)
    throw std::runtime_error("select failed");
  return n > 0;
}
static int remaining(std::chrono::steady_clock::time_point deadline) {
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                deadline - std::chrono::steady_clock::now())
                .count();
  if (ms <= 0)
    throw std::runtime_error("I/O timeout");
  return static_cast<int>(ms);
}
void send_all(socket_t s, const void *data, size_t len, int ms) {
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  const char *p = static_cast<const char *>(data);
  while (len) {
    if (!ready(s, true, remaining(deadline)))
      throw std::runtime_error("send timeout");
    int n = send(s, p, static_cast<int>(std::min(len, size_t(65536))), 0);
    if (n < 0 && would_block())
      continue;
    if (n <= 0)
      throw std::runtime_error("control connection closed during send");
    p += n;
    len -= n;
  }
}
void read_all(socket_t s, void *data, size_t len, int ms) {
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
  char *p = static_cast<char *>(data);
  while (len) {
    if (!ready(s, false, remaining(deadline)))
      throw std::runtime_error("read timeout");
    int n = recv(s, p, static_cast<int>(std::min(len, size_t(65536))), 0);
    if (n < 0 && would_block())
      continue;
    if (n <= 0)
      throw std::runtime_error("control connection closed during read");
    p += n;
    len -= n;
  }
}
std::string random_token() {
  unsigned char bytes[32];
#ifdef _WIN32
  if (BCryptGenRandom(nullptr, bytes, sizeof(bytes),
                      BCRYPT_USE_SYSTEM_PREFERRED_RNG))
    throw std::runtime_error("system RNG failed");
#else
  int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    throw std::runtime_error("system RNG unavailable");
  size_t pos = 0;
  while (pos < sizeof(bytes)) {
    ssize_t n = read(fd, bytes + pos, sizeof(bytes) - pos);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0) {
      close(fd);
      throw std::runtime_error("system RNG failed");
    }
    pos += n;
  }
  close(fd);
#endif
  const char *hex = "0123456789abcdef";
  std::string out;
  for (auto b : bytes) {
    out += hex[b >> 4];
    out += hex[b & 15];
  }
  return out;
}
std::filesystem::path executable_directory() {
#ifdef _WIN32
  wchar_t p[32768];
  DWORD n = GetModuleFileNameW(nullptr, p, 32768);
  if (!n || n == 32768)
    throw std::runtime_error("executable path unavailable");
  return std::filesystem::path(p).parent_path();
#elif defined(__APPLE__)
  uint32_t n = 0;
  _NSGetExecutablePath(nullptr, &n);
  std::vector<char> p(n);
  if (_NSGetExecutablePath(p.data(), &n))
    throw std::runtime_error("executable path unavailable");
  return std::filesystem::canonical(p.data()).parent_path();
#else
  return std::filesystem::canonical("/proc/self/exe").parent_path();
#endif
}
void binary_stdio() {
#ifdef _WIN32
  _setmode(_fileno(stdin), _O_BINARY);
  _setmode(_fileno(stdout), _O_BINARY);
  _setmode(_fileno(stderr), _O_BINARY);
#endif
}
TempDirectory::TempDirectory() {
  for (unsigned i = 0; i < 10; i++) {
    path = std::filesystem::temp_directory_path() /
           ("qbox-" + random_token().substr(0, 24));
#ifdef _WIN32
    // Windows user temp inherits the user's ACL; private random names plus
    // the authenticated channel prevent an unrelated local client taking over.
    if (CreateDirectoryW(path.c_str(), nullptr))
      return;
#else
    if (mkdir(path.c_str(), 0700) == 0)
      return;
#endif
  }
  throw std::runtime_error("cannot create private temporary directory");
}
TempDirectory::~TempDirectory() {
  if (preserve)
    return;
  std::error_code e;
  std::filesystem::remove_all(path, e);
}
Listener::Listener(const std::filesystem::path &directory) {
#ifdef _WIN32
  (void)directory;
  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd == invalid_socket)
    throw std::runtime_error("socket failed");
  BOOL exclusive = TRUE;
  setsockopt(fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE,
             reinterpret_cast<const char *>(&exclusive), sizeof(exclusive));
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a))) {
    close_socket(fd);
    throw std::runtime_error("bind failed");
  }
  int n = sizeof(a);
  getsockname(fd, reinterpret_cast<sockaddr *>(&a), &n);
  endpoint = "host=127.0.0.1,port=" + std::to_string(ntohs(a.sin_port));
#else
  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    throw std::runtime_error("socket failed");
  sockaddr_un a{};
  a.sun_family = AF_UNIX;
  std::string p = (directory / "runner.sock").string();
  if (p.size() >= sizeof(a.sun_path)) {
    close_socket(fd);
    throw std::runtime_error(
        "temporary socket path too long; use a shorter TMPDIR");
  }
  std::memcpy(a.sun_path, p.c_str(), p.size() + 1);
  if (bind(fd, reinterpret_cast<sockaddr *>(&a), sizeof(a)) < 0) {
    int e = errno;
    close_socket(fd);
    throw std::runtime_error("bind failed: " + std::string(strerror(e)));
  }
  endpoint = "path=";
  for (char c : p) {
    endpoint += c;
    if (c == ',')
      endpoint += c;
  }
#endif
  if (listen(fd, 4)) {
    close_socket(fd);
    throw std::runtime_error("listen failed");
  }
  nonblocking(fd);
}
Listener::~Listener() { close_socket(fd); }
socket_t Listener::accept_one(int ms) {
  if (!ready(fd, false, ms))
    return invalid_socket;
  socket_t s = accept(fd, nullptr, nullptr);
  if (s != invalid_socket)
    nonblocking(s);
  return s;
}
std::string windows_quote(const std::string &s) {
  std::string out = "\"";
  size_t slash = 0;
  for (char c : s) {
    if (c == '\\') {
      slash++;
      continue;
    }
    if (c == '\"')
      out.append(slash * 2 + 1, '\\');
    else
      out.append(slash, '\\');
    slash = 0;
    out += c;
  }
  out.append(slash * 2, '\\');
  return out + '\"';
}
#ifdef _WIN32
static std::wstring wide(const std::string &s) {
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                              static_cast<int>(s.size()), nullptr, 0);
  if (!n)
    throw std::runtime_error("invalid UTF-8 path");
  std::wstring out(n, L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                      out.data(), n);
  return out;
}
#endif
Process::Process(const std::vector<std::string> &args,
                 const std::filesystem::path &log) {
#ifdef _WIN32
  std::string command;
  for (const auto &a : args) {
    if (!command.empty())
      command += ' ';
    command += windows_quote(a);
  }
  auto cmd = wide(command);
  SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
  HANDLE f = CreateFileW(log.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  HANDLE nul =
      CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                  OPEN_EXISTING, 0, nullptr);
  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdOutput = f;
  si.hStdError = f;
  si.hStdInput = nul;
  PROCESS_INFORMATION pi{};
  job = CreateJobObjectW(nullptr, nullptr);
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!job || !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                       &limits, sizeof(limits))) {
    CloseHandle(f);
    CloseHandle(nul);
    if (job)
      CloseHandle(job);
    job = nullptr;
    throw std::runtime_error("cannot create QEMU process job");
  }
  BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                           CREATE_SUSPENDED | CREATE_NO_WINDOW, nullptr,
                           nullptr, &si, &pi);
  CloseHandle(f);
  CloseHandle(nul);
  if (!ok) {
    CloseHandle(job);
    job = nullptr;
    throw std::runtime_error("cannot launch QEMU; check --qemu and PATH");
  }
  handle = pi.hProcess;
  if (!AssignProcessToJobObject(job, handle)) {
    TerminateProcess(handle, 125);
    CloseHandle(pi.hThread);
    CloseHandle(handle);
    CloseHandle(job);
    handle = job = nullptr;
    throw std::runtime_error("cannot assign QEMU to cleanup job");
  }
  ResumeThread(pi.hThread);
  CloseHandle(pi.hThread);
#else
  std::vector<char *> av;
  for (const auto &a : args)
    av.push_back(const_cast<char *>(a.c_str()));
  av.push_back(nullptr);
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null",
                                   O_RDONLY, 0);
  posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, log.c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC, 0600);
  posix_spawn_file_actions_adddup2(&actions, STDOUT_FILENO, STDERR_FILENO);
  posix_spawnattr_t attr;
  posix_spawnattr_init(&attr);
  posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETPGROUP);
  posix_spawnattr_setpgroup(&attr, 0);
  int r = posix_spawnp(&pid, av[0], &actions, &attr, av.data(), environ);
  posix_spawnattr_destroy(&attr);
  posix_spawn_file_actions_destroy(&actions);
  if (r) {
    pid = -1;
    throw std::runtime_error("cannot launch QEMU: " + std::string(strerror(r)));
  }
#endif
}
Process::~Process() { stop(); }
bool Process::running() {
#ifdef _WIN32
  return handle && WaitForSingleObject(handle, 0) == WAIT_TIMEOUT;
#else
  if (pid < 0)
    return false;
  int status;
  pid_t r = waitpid(pid, &status, WNOHANG);
  if (r == pid)
    return false;
  return r == 0;
#endif
}
void Process::stop() {
#ifdef _WIN32
  if (job) {
    TerminateJobObject(job, 125);
    CloseHandle(job);
    job = nullptr;
  }
  if (handle) {
    WaitForSingleObject(handle, 2000);
    CloseHandle(handle);
    handle = nullptr;
  }
#else
  if (pid < 0)
    return;
  kill(-pid, SIGTERM);
  for (int i = 0; i < 20; i++) {
    if (!running())
      break;
    std::this_thread::sleep_for(std::chrono::milliseconds(25));
  }
  kill(-pid, SIGKILL);
  int status;
  while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
  }
  pid = -1;
#endif
}
} // namespace qbox
