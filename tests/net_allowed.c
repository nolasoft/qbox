#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  struct addrinfo hints = {0}, *answers = NULL;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_INET;
  if (getaddrinfo(argv[1], argv[2], &hints, &answers)) {
    fprintf(stderr, "resolution failed\n");
    return 1;
  }
  int success = 0;
  for (struct addrinfo *a = answers; a; a = a->ai_next) {
    int s = socket(a->ai_family, SOCK_STREAM, 0);
    if (s < 0)
      continue;
    fcntl(s, F_SETFL, O_NONBLOCK);
    int r = connect(s, a->ai_addr, a->ai_addrlen);
    struct pollfd p = {s, POLLOUT, 0};
    if (r == 0 || (errno == EINPROGRESS && poll(&p, 1, 5000) > 0)) {
      int error = 0;
      socklen_t len = sizeof(error);
      if (!getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) && !error) {
#ifdef QBOX_TCP_ONLY
        success = 1;
        close(s);
        break;
#endif
        // A guestfwd handshake alone does not prove the host connector
        // succeeded. Require an HTTP response byte through the
        // destination-bound stream.
        char req[1024];
        int n = snprintf(req, sizeof(req), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n",
                         argv[1]);
        if (send(s, req, (size_t)n, 0) == n) {
          p.events = POLLIN;
          if (poll(&p, 1, 10000) > 0) {
            char b[64];
            ssize_t count = recv(s, b, sizeof(b), 0);
            if (count >= 5 && !memcmp(b, "HTTP/", 5)) {
              success = 1;
              puts("connected");
            }
          }
        }
      }
    }
    close(s);
    if (success)
      break;
  }
  freeaddrinfo(answers);
  return success ? 0 : 1;
}
