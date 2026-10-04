#include "connect_policy.hpp"
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <memory>
#include <thread>
#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#else
#include <io.h>
#endif
using namespace qbox;
using Clock = std::chrono::steady_clock;
static int64_t tick() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             Clock::now().time_since_epoch())
      .count();
}
struct Answers {
  addrinfo *value = nullptr;
  ~Answers() {
    if (value)
      freeaddrinfo(value);
  }
};
static int connector_main(int argc, char **argv) {
  try {
    Network net;
    binary_stdio();
    if (argc != 3 && !(argc == 5 && std::string(argv[3]) == "--lease"))
      throw std::runtime_error(
          "usage: qbox-connector HOST PORT [--lease PATH]");
    std::atomic<bool> finished{false};
    struct LeaseWatch {
      std::atomic<bool> &done;
      std::thread thread;
      ~LeaseWatch() {
        done = true;
        if (thread.joinable())
          thread.join();
      }
    } lease{finished, {}};
    if (argc == 5) {
      auto path = std::filesystem::u8path(argv[4]);
      if (!std::filesystem::is_regular_file(path))
        return 0;
      lease.thread = std::thread([path, &finished] {
        while (!finished) {
          std::error_code error;
          if (!std::filesystem::is_regular_file(path, error))
            std::_Exit(0);
          std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
      });
    }
    std::string host = argv[1];
    Allow cap = parse_allow(
        (host.find(':') == std::string::npos ? host : "[" + host + "]") + ":" +
        argv[2]);
    auto answers = std::make_shared<Answers>();
    auto promise = std::make_shared<std::promise<int>>();
    auto result = promise->get_future();
    std::thread([answers, promise, cap] {
      addrinfo hints{};
      hints.ai_socktype = SOCK_STREAM;
      hints.ai_family = AF_UNSPEC;
      hints.ai_protocol = IPPROTO_TCP;
      hints.ai_flags = AI_NUMERICSERV;
      promise->set_value(getaddrinfo(cap.host.c_str(),
                                     std::to_string(cap.port).c_str(), &hints,
                                     &answers->value));
    }).detach();
    if (result.wait_for(std::chrono::seconds(10)) != std::future_status::ready)
      throw std::runtime_error("DNS timeout");
    if (result.get() != 0)
      throw std::runtime_error("DNS resolution failed");
    auto deadline = Clock::now() + std::chrono::seconds(10);
    socket_t s = connect_validated(answers->value, [&](const addrinfo &a) {
      if (Clock::now() >= deadline)
        return invalid_socket;
      socket_t candidate = socket(a.ai_family, SOCK_STREAM, IPPROTO_TCP);
      if (candidate == invalid_socket)
        return invalid_socket;
      nonblocking(candidate);
      int r = connect(candidate, a.ai_addr, static_cast<int>(a.ai_addrlen));
      if (r < 0 && !would_block()) {
        close_socket(candidate);
        return invalid_socket;
      }
      int ms = static_cast<int>(std::min<int64_t>(
          3000, std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - Clock::now())
                    .count()));
      if (r < 0 && (ms <= 0 || !ready(candidate, true, ms))) {
        close_socket(candidate);
        return invalid_socket;
      }
      int error = 0;
#ifdef _WIN32
      int len = sizeof(error);
#else
      socklen_t len=sizeof(error);
#endif
      if (getsockopt(candidate, SOL_SOCKET, SO_ERROR,
                     reinterpret_cast<char *>(&error), &len) ||
          error) {
        close_socket(candidate);
        return invalid_socket;
      }
      return candidate;
    });
    std::atomic<bool> done{false};
    std::atomic<int64_t> activity{tick()};
    auto upstream = std::thread([&] {
      try {
        while (!done) {
#ifndef _WIN32
          pollfd p{0, POLLIN, 0};
          if (poll(&p, 1, 100) <= 0)
            continue;
#else
          HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
          DWORD available = 0;
          if (GetFileType(h) == FILE_TYPE_PIPE &&
              PeekNamedPipe(h, nullptr, 0, nullptr, &available, nullptr) &&
              !available) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
          }
#endif
          char buf[16384];
#ifdef _WIN32
          int n = _read(0, buf, sizeof(buf));
#else
          ssize_t n = read(0, buf, sizeof(buf));
          if (n < 0 && errno == EINTR)
            continue;
#endif
          if (n <= 0)
            break;
          send_all(s, buf, static_cast<size_t>(n), 10000);
          activity = tick();
        }
      } catch (...) {
      }
      done = true;
    });
    auto downstream = std::thread([&] {
      try {
        while (!done) {
          if (!ready(s, false, 100))
            continue;
          char buf[16384];
          int n = recv(s, buf, sizeof(buf), 0);
          if (n < 0 && would_block())
            continue;
          if (n <= 0)
            break;
          int pos = 0;
          while (pos < n && !done) {
#ifndef _WIN32
            pollfd p{1, POLLOUT, 0};
            if (poll(&p, 1, 100) <= 0)
              continue;
            ssize_t w = write(1, buf + pos, std::min(n - pos, 4096));
            if (w < 0 && (errno == EINTR || errno == EAGAIN))
              continue;
#else
            int w = _write(1, buf + pos,
                           static_cast<unsigned>(std::min(n - pos, 4096)));
#endif
            if (w <= 0)
              throw std::runtime_error("output closed");
            pos += static_cast<int>(w);
            activity = tick();
          }
        }
      } catch (...) {
      }
      done = true;
    });
    while (!done) {
      if (tick() - activity > 120000)
        done = true;
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
#ifdef _WIN32
    shutdown(s, SD_BOTH);
    CancelSynchronousIo(upstream.native_handle());
    CancelSynchronousIo(downstream.native_handle());
#else
    shutdown(s, SHUT_RDWR);
#endif
    upstream.join();
    downstream.join();
    close_socket(s);
    return 0;
  } catch (const std::exception &e) {
    std::cerr << "qbox-connector: " << e.what() << '\n';
    return 1;
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
      return 1;
    std::string arg(count, '\0');
    WideCharToMultiByte(CP_UTF8, 0, argv[i], -1, arg.data(), count, nullptr,
                        nullptr);
    arg.pop_back();
    utf8.push_back(std::move(arg));
  }
  for (auto &arg : utf8)
    arguments.push_back(arg.data());
  return connector_main(argc, arguments.data());
}
#else
int main(int argc, char **argv) { return connector_main(argc, argv); }
#endif
