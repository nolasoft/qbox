#define _POSIX_C_SOURCE 200809L
#include "audit.h"
#include "audit_event.h"
#include <errno.h>
#ifdef QBOX_WITH_AUDIT
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
static char diagnostic[8192];
static size_t diagnostic_size;
static int log_error(enum libbpf_print_level level, const char *format,
                     va_list args) {
  if (level == LIBBPF_DEBUG || diagnostic_size >= sizeof(diagnostic) - 1)
    return 0;
  int n = vsnprintf(diagnostic + diagnostic_size,
                    sizeof(diagnostic) - diagnostic_size, format, args);
  if (n > 0)
    diagnostic_size += (size_t)n < sizeof(diagnostic) - diagnostic_size
                           ? (size_t)n
                           : sizeof(diagnostic) - diagnostic_size - 1;
  return 0;
}
const char *qbox_audit_error(void) {
  return diagnostic_size ? diagnostic
                         : "audit setup failed (kernel tracing/BTF or BPF "
                           "object unavailable)";
}
static struct bpf_object *object;
static struct bpf_link *links[5];
static struct ring_buffer *ring;
static int tracked, losses;
static uint64_t count, dropped, kernel_dropped;
static struct qbox_audit_event initial;
static int initial_pending;
static int (*sender)(const void *, size_t, void *);
static void *sender_context;
static int sample(void *ctx, void *data, size_t size) {
  (void)ctx;
  if (size != sizeof(struct qbox_audit_event) ||
      sender(data, size, sender_context)) {
    dropped++;
    return -1;
  }
  count++;
  return 0;
}
int qbox_audit_start(void) {
  libbpf_set_print(log_error);
  if (mount("tracefs", "/sys/kernel/tracing", "tracefs",
            MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0700") &&
      errno != EBUSY)
    return -1;
  struct rlimit limit = {RLIM_INFINITY, RLIM_INFINITY};
  if (setrlimit(RLIMIT_MEMLOCK, &limit))
    return -1;
  FILE *sysctl = fopen("/proc/sys/kernel/unprivileged_bpf_disabled", "w");
  if (!sysctl)
    return -1;
  int failed = fprintf(sysctl, "1\n") < 0;
  if (fclose(sysctl))
    failed = 1;
  if (failed)
    return -1;
  object = bpf_object__open_file("/etc/qbox/audit.bpf.o", NULL);
  if (!object || libbpf_get_error(object)) {
    object = NULL;
    return -1;
  }
  if (bpf_object__load(object))
    return -1;
  tracked = bpf_object__find_map_fd_by_name(object, "tracked");
  losses = bpf_object__find_map_fd_by_name(object, "lost");
  int fd = bpf_object__find_map_fd_by_name(object, "events");
  if (tracked < 0 || losses < 0 || fd < 0)
    return -1;
  ring = ring_buffer__new(fd, sample, NULL, NULL);
  if (!ring || libbpf_get_error(ring)) {
    ring = NULL;
    return -1;
  }
  struct bpf_program *program;
  unsigned n = 0;
  bpf_object__for_each_program(program, object) {
    if (n >= 5)
      return -1;
    links[n] = bpf_program__attach(program);
    if (!links[n] || libbpf_get_error(links[n])) {
      links[n] = NULL;
      return -1;
    }
    n++;
  }
  return n == 5 ? 0 : -1;
}
int qbox_audit_seed(pid_t pid) {
  unsigned int p = (unsigned int)pid;
  if (bpf_map_update_elem(tracked, &p, &p, BPF_ANY))
    return -1;
  struct timespec now;
  clock_gettime(CLOCK_MONOTONIC, &now);
  memset(&initial, 0, sizeof(initial));
  initial.time = (uint64_t)now.tv_sec * 1000000000 + now.tv_nsec;
  initial.type = 1;
  initial.tid = p;
  initial.pid = p;
  initial.parent = 1;
  initial_pending = 1;
  return 0;
}
int qbox_audit_drain(int (*send)(const void *, size_t, void *), void *ctx) {
  sender = send;
  sender_context = ctx;
  if (initial_pending) {
    initial_pending = 0;
    if (sample(NULL, &initial, sizeof(initial)))
      return -1;
  }
  int result = ring_buffer__consume_n(ring, 32);
  unsigned int zero = 0;
  if (bpf_map_lookup_elem(losses, &zero, &kernel_dropped))
    return -1;
  return result < 0 || dropped || kernel_dropped ? -1 : result;
}
uint64_t qbox_audit_count(void) { return count; }
uint64_t qbox_audit_lost(void) { return dropped + kernel_dropped; }
void qbox_audit_stop(void) {
  for (unsigned i = 0; i < 5; i++) {
    bpf_link__destroy(links[i]);
    links[i] = NULL;
  }
}
void qbox_audit_close(void) {
  qbox_audit_stop();
  ring_buffer__free(ring);
  ring = NULL;
  bpf_object__close(object);
  object = NULL;
}
#else
const char *qbox_audit_error(void) {
  return "image was built without --with-audit";
}
int qbox_audit_start(void) {
  errno = ENOTSUP;
  return -1;
}
int qbox_audit_seed(pid_t pid) {
  (void)pid;
  errno = ENOTSUP;
  return -1;
}
int qbox_audit_drain(int (*send)(const void *, size_t, void *), void *ctx) {
  (void)send;
  (void)ctx;
  return -1;
}
uint64_t qbox_audit_count(void) { return 0; }
uint64_t qbox_audit_lost(void) { return 0; }
void qbox_audit_stop(void) {}
void qbox_audit_close(void) {}
#endif
