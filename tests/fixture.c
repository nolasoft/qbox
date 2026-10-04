#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int write_all(int fd, const char *p, size_t n) {
  while (n) {
    ssize_t w = write(fd, p, n);
    if (w <= 0)
      return 1;
    p += w;
    n -= (size_t)w;
  }
  return 0;
}
int main(int argc, char **argv) {
  if (argc < 2)
    return 2;
  if (!strcmp(argv[1], "exit"))
    return argc > 2 ? atoi(argv[2]) : 42;
  if (!strcmp(argv[1], "crash")) {
    raise(SIGSEGV);
    return 1;
  }
  if (!strcmp(argv[1], "sleep")) {
    sleep(60);
    return 0;
  }
  if (!strcmp(argv[1], "echo")) {
    char b[16384];
    ssize_t n;
    while ((n = read(0, b, sizeof(b))) > 0)
      if (write_all(1, b, (size_t)n))
        return 1;
    return n < 0;
  }
  if (!strcmp(argv[1], "large")) {
    char b[16384];
    memset(b, 'x', sizeof(b));
    for (int i = 0; i < 512; i++) {
      if (write_all(1, b, sizeof(b)) || write_all(2, b, sizeof(b)))
        return 1;
    }
    return 0;
  }
  return 2;
}
