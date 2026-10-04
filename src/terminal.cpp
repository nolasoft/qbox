#include "terminal.hpp"
#include <stdexcept>
#ifndef _WIN32
#include <sys/ioctl.h>
#endif
namespace qbox {
Terminal::Terminal(bool enabled) {
  if (!enabled)
    return;
#ifdef _WIN32
  auto in = GetStdHandle(STD_INPUT_HANDLE),
       out = GetStdHandle(STD_OUTPUT_HANDLE);
  if (!GetConsoleMode(in, &input_mode) || !GetConsoleMode(out, &output_mode))
    throw std::runtime_error("--tty requires an interactive host console");
  if (!SetConsoleMode(in,
                      (input_mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT |
                                      ENABLE_PROCESSED_INPUT)) |
                          ENABLE_VIRTUAL_TERMINAL_INPUT) ||
      !SetConsoleMode(out, output_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
    SetConsoleMode(in, input_mode);
    throw std::runtime_error("virtual terminal mode unavailable");
  }
#else
  if (!isatty(0) || !isatty(1) || tcgetattr(0, &saved))
    throw std::runtime_error("--tty requires an interactive host terminal");
  auto mode = saved;
  cfmakeraw(&mode);
  if (tcsetattr(0, TCSANOW, &mode))
    throw std::runtime_error("cannot set terminal raw mode");
#endif
  active = true;
}
Terminal::~Terminal() {
  if (!active)
    return;
#ifdef _WIN32
  SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), input_mode);
  SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), output_mode);
#else
  tcsetattr(0, TCSANOW, &saved);
#endif
}
std::pair<unsigned, unsigned> Terminal::size() const {
  unsigned rows = 24, columns = 80;
  if (!active)
    return {rows, columns};
#ifdef _WIN32
  CONSOLE_SCREEN_BUFFER_INFO info;
  if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
    rows = static_cast<unsigned>(info.srWindow.Bottom - info.srWindow.Top + 1);
    columns =
        static_cast<unsigned>(info.srWindow.Right - info.srWindow.Left + 1);
  }
#else
  winsize s{};
  if (!ioctl(0, TIOCGWINSZ, &s) && s.ws_row && s.ws_col) {
    rows = s.ws_row;
    columns = s.ws_col;
  }
#endif
  return {std::min(rows, 1000u), std::min(columns, 1000u)};
}
} // namespace qbox
