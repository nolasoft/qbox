#pragma once
#include "config.hpp"
#include <functional>
#include <stdexcept>
namespace qbox {
// Shared policy seam for deterministic DNS/rebinding tests. The callback
// receives exactly the sockaddr returned by the one resolution pass and
// validated here.
inline socket_t
connect_validated(const addrinfo *answers,
                  const std::function<socket_t(const addrinfo &)> &connect) {
  for (auto *a = answers; a; a = a->ai_next) {
    if (!a->ai_addr || (a->ai_family != AF_INET && a->ai_family != AF_INET6) ||
        a->ai_addrlen < (a->ai_family == AF_INET ? sizeof(sockaddr_in)
                                                 : sizeof(sockaddr_in6)) ||
        a->ai_addr->sa_family != a->ai_family || !public_address(a->ai_addr))
      continue;
    socket_t s = connect(*a);
    if (s != invalid_socket)
      return s;
  }
  throw std::runtime_error("no permitted public address connected");
}
} // namespace qbox
