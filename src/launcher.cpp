#include "audit.hpp"
#include "payload.hpp"
#include "protocol.hpp"
#include "terminal.hpp"
#include "workspace.hpp"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <deque>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#else
#include <io.h>
#endif
using namespace qbox;
static volatile sig_atomic_t interrupted = 0;
static void on_signal(int s) { interrupted = s; }
#ifdef _WIN32
static BOOL WINAPI on_control(DWORD s) {
  if (s == CTRL_C_EVENT || s == CTRL_BREAK_EVENT || s == CTRL_CLOSE_EVENT) {
    interrupted = SIGINT;
    return TRUE;
  }
  return FALSE;
}
#endif
static void write_file(const std::filesystem::path &p, const std::string &s) {
  std::ofstream f(p, std::ios::binary);
  if (!f.write(s.data(), s.size()))
    throw std::runtime_error("cannot write payload configuration");
}
struct SocketOwner {
  socket_t fd = invalid_socket;
  ~SocketOwner() { close_socket(fd); }
};
class Input {
  std::mutex mutex;
  std::condition_variable cv;
  std::deque<std::vector<uint8_t>> queue;
  std::atomic<bool> stop{false};
  std::thread thread;

public:
  Input(bool tty = false)
      : thread([this, tty] {
          while (!stop) {
#ifndef _WIN32
            pollfd f{STDIN_FILENO, POLLIN, 0};
            int r = poll(&f, 1, 100);
            if (r < 0 && errno == EINTR)
              continue;
            if (r <= 0)
              continue;
#else
            HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
            DWORD type = GetFileType(h);
            if (type == FILE_TYPE_PIPE) {
              DWORD available = 0;
              if (PeekNamedPipe(h, nullptr, 0, nullptr, &available, nullptr) &&
                  !available) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
              }
            }
#endif
            std::vector<uint8_t> b(16384);
#ifdef _WIN32
            int n = _read(0, b.data(), static_cast<unsigned>(b.size()));
#else
            ssize_t n = read(0, b.data(), b.size());
            if (n < 0 && errno == EINTR)
              continue;
#endif
            if (n < 0)
              n = 0;
            if (tty && n > 0) {
              auto escape = std::find(b.begin(), b.begin() + n, uint8_t(29));
              if (escape != b.begin() + n) {
                n = escape - b.begin();
                interrupted = SIGTERM;
              }
            }
            b.resize(static_cast<size_t>(n));
            std::unique_lock<std::mutex> lock(mutex);
            cv.wait(lock, [this] { return stop || queue.size() < 4; });
            if (stop)
              return;
            queue.push_back(std::move(b));
            if (!n)
              return;
          }
        }) {
  }
  bool take(std::vector<uint8_t> &b) {
    std::lock_guard<std::mutex> lock(mutex);
    if (queue.empty())
      return false;
    b = std::move(queue.front());
    queue.pop_front();
    cv.notify_all();
    return true;
  }
  ~Input() {
    stop = true;
    cv.notify_all();
#ifdef _WIN32
    CancelSynchronousIo(thread.native_handle());
#endif
    thread.join();
  }
};
static std::vector<uint8_t> wire(uint8_t type, const std::vector<uint8_t> &p) {
  std::vector<uint8_t> b{type};
  put_u32(b, static_cast<uint32_t>(p.size()));
  b.insert(b.end(), p.begin(), p.end());
  return b;
}
static void output(int fd, const std::vector<uint8_t> &b, size_t start,
                   size_t n, std::chrono::steady_clock::time_point deadline) {
  while (n) {
    if (interrupted)
      return;
    if (std::chrono::steady_clock::now() > deadline)
      throw std::runtime_error("wall-clock timeout forwarding output");
#ifdef _WIN32
    // Only enter a synchronous pipe write when capacity is expected; Windows
    // also needs cancellation for blocked output (see watchdog below).
    int r = _write(fd, b.data() + start,
                   static_cast<unsigned>(std::min(n, size_t(4096))));
#else
    pollfd p{fd, POLLOUT, 0};
    if (poll(&p, 1, 100) <= 0)
      continue;
    ssize_t r = write(fd, b.data() + start, std::min(n, size_t(4096)));
    if (r < 0 && (errno == EINTR || errno == EAGAIN))
      continue;
#endif
    if (r <= 0)
      throw std::runtime_error("host output closed");
    start += r;
    n -= r;
  }
}
static int qbox_main(int argc, char **argv) {
  if (argc == 2 &&
      (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
    std::cout << usage();
    return 0;
  }
  std::filesystem::path log;
  std::string diagnostics;
  try {
    Network network;
    binary_stdio();
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
#ifdef _WIN32
    SetConsoleCtrlHandler(on_control, TRUE);
#endif
    Config c = parse_cli(argc, argv);
    if (!c.agent)
      validate_elf(c.program, c.arch);
    for (const auto &p : {c.kernel, c.initrd})
      if (!std::filesystem::is_regular_file(p))
        throw std::runtime_error(
            "missing guest artifact: " + p.u8string() +
            "; see guest/README.md or supply --kernel/--initrd");
    if (!c.allows.empty() && !std::filesystem::is_regular_file(c.connector))
      throw std::runtime_error("missing qbox-connector");
    std::unique_ptr<AuditLog> audit;
    if (!c.audit_log.empty())
      audit = std::make_unique<AuditLog>(c);
    auto exec = encode_exec(c.args, c.environment, c.agent);
    TempDirectory temp;
    auto payload = temp.path / "payload";
    std::filesystem::create_directory(payload);
    std::unique_ptr<Workspace> workspace;
    if (c.agent) {
      workspace = std::make_unique<Workspace>(c, temp.path / "workspace-cache");
      workspace->snapshot(payload / "workspace");
      write_file(payload / "agent", std::to_string(c.workspace_limit));
      std::string excluded;
      for (const auto &name : c.excludes)
        excluded += name + "\n";
      write_file(payload / "excludes", excluded);
    } else {
      std::filesystem::copy_file(c.program, payload / "program");
      validate_elf(payload / "program", c.arch);
    }
#ifndef _WIN32
    if (!c.agent)
      std::filesystem::permissions(payload / "program",
                                   std::filesystem::perms::owner_read);
#endif
    if (audit)
      write_file(payload / "audit", "1");
    std::string token = random_token();
    write_file(payload / "hosts", hosts_file(c));
    write_file(payload / "token", token);
    write_file(temp.path / "alive", token);
    struct Lease {
      std::filesystem::path file;
      bool connectors;
      ~Lease() {
        std::error_code e;
        std::filesystem::remove(file, e);
        if (connectors)
          std::this_thread::sleep_for(std::chrono::milliseconds(200));
      }
    } lease{temp.path / "alive", !c.allows.empty()};
    if (c.payload_mode == "initrd") {
      auto staged = temp.path / "initramfs.img";
      embed_payload(c.initrd, payload, staged);
      c.initrd = staged;
    }
    Listener listener(temp.path);
    log = temp.path / "qemu.log";
    auto process = std::make_unique<Process>(
        qemu_command(c, payload, listener.endpoint), log);
    bool can_fallback = c.accel == "auto";
    // Preserve a bounded diagnostic tail before temporary files are removed.
    struct LogTail {
      std::filesystem::path p;
      std::string &out;
      ~LogTail() {
        std::ifstream f(p, std::ios::binary);
        if (f) {
          f.seekg(0, std::ios::end);
          std::streamoff n = f.tellg();
          f.seekg(n > 8192 ? n - 8192 : 0);
          out.assign(std::istreambuf_iterator<char>(f), {});
        }
      }
    } tail{log, diagnostics};
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(c.timeout);
    SocketOwner control;
    auto boot_deadline =
        std::min(deadline, std::chrono::steady_clock::now() +
                               std::chrono::seconds(c.connect_timeout));
    while (control.fd == invalid_socket) {
      if (interrupted)
        return interrupted == SIGINT ? 130 : 143;
      if (!process->running()) {
        if (!can_fallback)
          throw std::runtime_error("QEMU exited before connecting");
        process.reset();
        c.accel = "tcg";
        can_fallback = false;
        process = std::make_unique<Process>(
            qemu_command(c, payload, listener.endpoint), log);
        continue;
      }
      if (std::chrono::steady_clock::now() > boot_deadline)
        throw std::runtime_error("QEMU connection timed out");
      control.fd = listener.accept_one(100);
    }
    // Authentication is checked before any argv or stdin is delivered.
    std::vector<uint8_t> hello(69);
    size_t hello_pos = 0;
    while (hello_pos < hello.size()) {
      if (interrupted)
        throw std::runtime_error("runner startup interrupted");
      if (std::chrono::steady_clock::now() > boot_deadline)
        throw std::runtime_error("runner startup timed out");
      if (!process->running())
        throw std::runtime_error("QEMU exited during runner startup");
      if (!ready(control.fd, false, 100))
        continue;
      int n =
          recv(control.fd, reinterpret_cast<char *>(hello.data() + hello_pos),
               static_cast<int>(hello.size() - hello_pos), 0);
      if (n < 0 && would_block())
        continue;
      if (n <= 0)
        throw std::runtime_error("runner closed during authentication");
      hello_pos += n;
      if (hello_pos >= 5 &&
          (hello[0] != Ready || get_u32(hello.data() + 1) != 64))
        throw std::runtime_error("runner authentication failed");
    }
    if (std::string(hello.begin() + 5, hello.end()) != token)
      throw std::runtime_error("runner authentication failed");
    if (audit) {
      auto startup_read = [&](std::vector<uint8_t> &bytes) {
        size_t pos = 0;
        while (pos < bytes.size()) {
          if (interrupted)
            throw std::runtime_error("audit startup interrupted");
          if (std::chrono::steady_clock::now() > boot_deadline)
            throw std::runtime_error("audit startup timed out");
          if (!process->running())
            throw std::runtime_error("QEMU exited during audit startup");
          if (!ready(control.fd, false, 100))
            continue;
          int n = recv(control.fd, reinterpret_cast<char *>(bytes.data() + pos),
                       static_cast<int>(bytes.size() - pos), 0);
          if (n < 0 && would_block())
            continue;
          if (n <= 0)
            throw std::runtime_error("runner closed during audit startup");
          pos += n;
        }
      };
      std::vector<uint8_t> header(5);
      startup_read(header);
      uint32_t size = get_u32(header.data() + 1);
      if (header[0] != AuditReady || size < 4 || size > 8196)
        throw std::runtime_error("invalid guest audit readiness");
      Frame confirmation{AuditReady, std::vector<uint8_t>(size)};
      startup_read(confirmation.payload);
      if (confirmation.type != AuditReady || confirmation.payload.size() < 4 ||
          confirmation.payload.size() > 8196)
        throw std::runtime_error("invalid guest audit readiness");
      if (get_u32(confirmation.payload.data()))
        throw std::runtime_error("guest audit collector unavailable: " +
                                 std::string(confirmation.payload.begin() + 4,
                                             confirmation.payload.end()));
      if (confirmation.payload.size() != 4)
        throw std::runtime_error("invalid guest audit readiness");
    }
    Terminal terminal(c.tty);
    auto dimensions = terminal.size();
    if (c.agent) {
      std::vector<uint8_t> header;
      put_u32(header, c.tty ? 1 : 0);
      put_u32(header, dimensions.first);
      put_u32(header, dimensions.second);
      header.insert(header.end(), exec.begin(), exec.end());
      if (header.size() > max_frame)
        throw std::runtime_error("agent request exceeds frame limit");
      exec = std::move(header);
    }
    if (c.tty)
      std::cerr << "qbox: Ctrl-] stops the session and writes back its "
                   "workspace.\r\n";
    Input input(c.tty);
    std::vector<uint8_t> rx, tx = wire(c.agent ? ExecAgent : Exec, exec);
    std::ofstream returned;
    auto returned_path = temp.path / "workspace-result.qbws";
    if (c.agent)
      returned.open(returned_path, std::ios::binary);
    uint64_t returned_size = 0;
    bool workspace_done = false, audit_failed = false, audit_done = false;
    size_t tx_pos = 0;
    uint64_t total = 0;
    bool stdin_done = false, signal_sent = false, cancelling = false;
    auto grace = deadline;
#ifndef _WIN32
    struct OutputFlags {
      int a = fcntl(1, F_GETFL), b = fcntl(2, F_GETFL);
      OutputFlags() {
        fcntl(1, F_SETFL, a | O_NONBLOCK);
        fcntl(2, F_SETFL, b | O_NONBLOCK);
      }
      ~OutputFlags() {
        fcntl(1, F_SETFL, a);
        fcntl(2, F_SETFL, b);
      }
    } flags;
#else
    std::atomic<bool> finished{false};
    HANDLE main_thread =
        OpenThread(THREAD_TERMINATE, FALSE, GetCurrentThreadId());
    struct Watch {
      std::atomic<bool> &done;
      std::thread t;
      ~Watch() {
        done = true;
        t.join();
      }
    } watcher{finished, std::thread([&] {
                while (!finished) {
                  if (interrupted ||
                      std::chrono::steady_clock::now() > deadline) {
                    CancelSynchronousIo(main_thread);
                    break;
                  }
                  std::this_thread::sleep_for(std::chrono::milliseconds(50));
                }
                CloseHandle(main_thread);
              })};
#endif
    while (true) {
      auto now = std::chrono::steady_clock::now();
      if (now > deadline)
        throw std::runtime_error("wall-clock timeout");
      if ((interrupted || audit_failed) && !cancelling) {
        cancelling = true;
        grace = now + std::chrono::seconds(c.agent ? 30 : 2);
      }
      if ((interrupted || audit_failed) && !signal_sent && tx.empty()) {
        std::vector<uint8_t> p;
        put_u32(p, interrupted == SIGINT ? 2 : 15);
        tx = wire(Signal, p);
        signal_sent = true;
      }
      if (cancelling && now > grace)
        return audit_failed ? 125 : (interrupted == SIGINT ? 130 : 143);
      if (c.tty && tx.empty() && !signal_sent) {
        auto next = terminal.size();
        if (next != dimensions) {
          dimensions = next;
          std::vector<uint8_t> size;
          put_u32(size, next.first);
          put_u32(size, next.second);
          tx = wire(Resize, size);
        }
      }
      if (tx.empty() && !stdin_done && !signal_sent) {
        std::vector<uint8_t> p;
        if (input.take(p)) {
          stdin_done = p.empty();
          tx = wire(Stdin, p);
          tx_pos = 0;
        }
      }
      if (!tx.empty() && ready(control.fd, true, 0)) {
        int n =
            send(control.fd, reinterpret_cast<const char *>(tx.data() + tx_pos),
                 static_cast<int>(tx.size() - tx_pos), 0);
        if (n < 0 && !would_block())
          throw std::runtime_error("runner send failed");
        if (n > 0) {
          tx_pos += n;
          if (tx_pos == tx.size()) {
            tx.clear();
            tx_pos = 0;
          }
        }
      }
      if (ready(control.fd, false, 20)) {
        uint8_t b[65536];
        int n = recv(control.fd, reinterpret_cast<char *>(b), sizeof(b), 0);
        if (n == 0)
          throw std::runtime_error("guest/control channel crashed");
        if (n < 0 && !would_block())
          throw std::runtime_error("runner receive failed");
        if (n > 0)
          rx.insert(rx.end(), b, b + n);
      }
      size_t consumed = 0;
      while (rx.size() - consumed >= 5) {
        uint8_t type = rx[consumed];
        uint32_t len = get_u32(rx.data() + consumed + 1);
        if (len > max_frame)
          throw std::runtime_error("guest frame exceeds limit");
        if (rx.size() - consumed < 5 + len)
          break;
        size_t begin = consumed + 5;
        if (type == Stdout || type == Stderr) {
          if (len > c.output_limit - total)
            throw std::runtime_error("output limit exceeded");
          total += len;
          output(type == Stdout ? 1 : 2, rx, begin, len, deadline);
        } else if ((type == AuditEvent || type == AuditDone) && audit &&
                   !audit_done) {
          try {
            if (type == AuditEvent) {
              if (!audit_failed)
                audit->event(rx.data() + begin, len);
            } else {
              audit_done = true;
              audit->done(rx.data() + begin, len);
              if (!audit->complete()) {
                if (!audit_failed)
                  std::cerr << "qbox: guest audit incomplete; see "
                            << c.audit_log.u8string() << '\n';
                audit_failed = true;
              }
            }
          } catch (const std::exception &e) {
            if (!audit_failed)
              std::cerr << "qbox: " << e.what() << '\n';
            audit_failed = true;
          }
        } else if (type == WorkspaceData && c.agent && !workspace_done) {
          if (len > c.workspace_limit - returned_size)
            throw std::runtime_error("workspace export exceeds limit");
          returned.write(reinterpret_cast<const char *>(rx.data() + begin),
                         len);
          if (!returned)
            throw std::runtime_error("cannot stage workspace export");
          returned_size += len;
        } else if (type == WorkspaceDone && c.agent && !workspace_done) {
          if (len != 4 || get_u32(rx.data() + begin))
            throw std::runtime_error("guest workspace export failed");
          workspace_done = true;
          returned.close();
          if (!returned)
            throw std::runtime_error("cannot complete workspace export");
        } else if (type == Exit) {
          if (len != 8)
            throw std::runtime_error("invalid EXIT frame");
          uint32_t kind = get_u32(rx.data() + begin),
                   value = get_u32(rx.data() + begin + 4);
          if (kind > 1 || value > (kind ? 64u : 255u))
            throw std::runtime_error("invalid guest exit status");
          if (c.agent) {
            if (!workspace_done)
              throw std::runtime_error("guest exited before workspace export");
            try {
              workspace->apply(returned_path);
            } catch (const std::exception &e) {
              temp.preserve = true;
              throw std::runtime_error(std::string(e.what()) +
                                       "; returned workspace retained at " +
                                       returned_path.u8string());
            }
          }
          if (audit && (audit_failed || !audit_done || !audit->complete())) {
            if (!audit_failed)
              std::cerr << "qbox: guest exited without a complete audit; see "
                        << c.audit_log.u8string() << '\n';
            return 125;
          }
          return kind ? 128 + static_cast<int>(value) : static_cast<int>(value);
        } else
          throw std::runtime_error("unexpected runner frame");
        consumed += 5 + len;
      }
      if (consumed)
        rx.erase(rx.begin(),
                 rx.begin() + static_cast<std::ptrdiff_t>(consumed));
      if (!process->running())
        throw std::runtime_error("QEMU exited without guest EXIT");
    }
  } catch (const std::exception &e) {
    std::cerr << "qbox: " << e.what() << '\n';
    if (!diagnostics.empty())
      std::cerr << "QEMU diagnostics:\n" << diagnostics;
    return interrupted ? (interrupted == SIGINT ? 130 : 143) : 125;
  }
}
#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
  std::vector<std::string> utf8;
  std::vector<char *> arguments;
  for (int i = 0; i < argc; ++i) {
    int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1,
                                    nullptr, 0, nullptr, nullptr);
    if (!count)
      return 125;
    std::string arg(count, '\0');
    WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, arg.data(), count, nullptr,
                        nullptr);
    arg.pop_back();
    utf8.push_back(std::move(arg));
  }
  for (auto &arg : utf8)
    arguments.push_back(arg.data());
  return qbox_main(argc, arguments.data());
}
#else
int main(int argc, char **argv) { return qbox_main(argc, argv); }
#endif
