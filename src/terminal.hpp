#pragma once
#include "platform.hpp"
#ifndef _WIN32
#include <termios.h>
#endif
namespace qbox {
class Terminal {
  bool active = false;
#ifdef _WIN32
  DWORD input_mode = 0, output_mode = 0;
#else
  termios saved{};
#endif
public:
  explicit Terminal(bool enabled);
  ~Terminal();
  std::pair<unsigned, unsigned> size() const;
};
} // namespace qbox
