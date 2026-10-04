#define _GNU_SOURCE
#include "audit.h"
#include "rootfs.h"
#include "workspace.h"
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <arpa/inet.h>
#include <dirent.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/sysmacros.h>
#endif
#define MAX_FRAME (1024u * 1024u)
#define BUFFER_CAP (2u * MAX_FRAME + 65536u)
enum {
  EXEC = 1,
  INPUT = 2,
  OUTPUT = 3,
  ERROR_OUTPUT = 4,
  EXIT = 5,
  SIGNAL_CHILD = 6,
  READY = 7,
  EXEC_AGENT = 8,
  WORKSPACE_DATA = 9,
  WORKSPACE_DONE = 10,
  RESIZE = 11,
  AUDIT_EVENT = 12,
  AUDIT_DONE = 13,
  AUDIT_READY = 14
};
static int agent_mode = 0, audit_mode = 0;
static uint64_t workspace_limit = 512u * 1024u * 1024u;
static const char *workspace_root = "/workspace";
static const char *workspace_excludes = "/run/qbox/excludes";
static void kill_agent_processes(void) {
#ifdef __linux__
  // Only the disposable VM's PID 1 may use this. kill(-1) excludes PID 1
  // and also stops detached children whose /proc ownership was changed by
  // disabling dumpability. Native protocol tests must never kill host jobs.
  if (getpid() == 1)
    kill(-1, SIGKILL);
#endif
}
struct buffer {
  unsigned char *p;
  size_t n, pos;
};
static uint32_t u32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}
static void be32(unsigned char *p, uint32_t n) {
  p[0] = n >> 24;
  p[1] = n >> 16;
  p[2] = n >> 8;
  p[3] = n;
}
static void compact(struct buffer *b) {
  if (b->pos) {
    memmove(b->p, b->p + b->pos, b->n - b->pos);
    b->n -= b->pos;
    b->pos = 0;
  }
}
static int append(struct buffer *b, const void *p, size_t n) {
  compact(b);
  if (n > BUFFER_CAP - b->n)
    return -1;
  memcpy(b->p + b->n, p, n);
  b->n += n;
  return 0;
}
static int frame(struct buffer *b, unsigned char type, const void *p,
                 uint32_t n) {
  unsigned char h[5];
  h[0] = type;
  be32(h + 1, n);
  return append(b, h, 5) || append(b, p, n) ? -1 : 0;
}
static int audit_send(const void *data, size_t n, void *ctx) {
  return frame(ctx, AUDIT_EVENT, data, (uint32_t)n);
}
static uint64_t monotonic_seconds(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return (uint64_t)t.tv_sec;
}
static void be64(unsigned char *p, uint64_t n) {
  be32(p, (uint32_t)(n >> 32));
  be32(p + 4, (uint32_t)n);
}
static int make_buffer(struct buffer *b) {
  b->p = malloc(BUFFER_CAP);
  b->n = b->pos = 0;
  return b->p ? 0 : -1;
}
static int nb(int fd) {
  return fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
}
static int flush(int fd, struct buffer *b) {
  if (b->pos == b->n)
    return 0;
  ssize_t n = write(fd, b->p + b->pos, b->n - b->pos);
  if (n > 0) {
    b->pos += (size_t)n;
    return 0;
  }
  return n < 0 && (errno == EAGAIN || errno == EINTR) ? 0 : -1;
}
static int strings(const unsigned char *p, size_t n, size_t *pos, char ***out,
                   int environment) {
  if (n - *pos < 4)
    return -1;
  uint32_t count = u32(p + *pos);
  *pos += 4;
  if (count > 256 || (!environment && !count))
    return -1;
  char **v = calloc(count + 1, sizeof(char *));
  if (!v)
    return -1;
  *out = v;
  for (uint32_t i = 0; i < count; i++) {
    if (n - *pos < 4)
      return -1;
    uint32_t len = u32(p + *pos);
    *pos += 4;
    if (len > n - *pos || memchr(p + *pos, 0, len))
      return -1;
    v[i] = malloc(len + 1);
    if (!v[i])
      return -1;
    memcpy(v[i], p + *pos, len);
    v[i][len] = 0;
    *pos += len;
    if (environment && (!strchr(v[i], '=') || v[i][0] == '='))
      return -1;
  }
  return 0;
}
static void free_strings(char **v) {
  if (v) {
    for (size_t i = 0; v[i]; i++)
      free(v[i]);
    free(v);
  }
}
#ifdef __linux__
static int copy(const char *from, const char *to, mode_t mode) {
  int in = open(from, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (in < 0)
    return -1;
  int out = open(to, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (out < 0) {
    close(in);
    return -1;
  }
  char b[16384];
  ssize_t n;
  int result = 0;
  while ((n = read(in, b, sizeof(b))) > 0) {
    ssize_t pos = 0;
    while (pos < n) {
      ssize_t w = write(out, b + pos, (size_t)(n - pos));
      if (w < 0 && errno == EINTR)
        continue;
      if (w <= 0) {
        result = -1;
        goto end;
      }
      pos += w;
    }
  }
  if (n < 0)
    result = -1;
end:
  close(in);
  close(out);
  return result;
}
static int interface(const char *name) {
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0)
    return -1;
  struct ifreq r;
  memset(&r, 0, sizeof(r));
  snprintf(r.ifr_name, sizeof(r.ifr_name), "%s", name);
  struct sockaddr_in *a = (struct sockaddr_in *)&r.ifr_addr;
  a->sin_family = AF_INET;
  inet_pton(AF_INET, "10.0.2.15", &a->sin_addr);
  if (ioctl(s, SIOCSIFADDR, &r) < 0)
    goto fail;
  inet_pton(AF_INET, "255.255.255.0", &a->sin_addr);
  if (ioctl(s, SIOCSIFNETMASK, &r) < 0)
    goto fail;
  if (ioctl(s, SIOCGIFFLAGS, &r) < 0)
    goto fail;
  r.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (ioctl(s, SIOCSIFFLAGS, &r) < 0)
    goto fail;
  struct rtentry route;
  memset(&route, 0, sizeof(route));
  ((struct sockaddr_in *)&route.rt_dst)->sin_family = AF_INET;
  ((struct sockaddr_in *)&route.rt_genmask)->sin_family = AF_INET;
  a = (struct sockaddr_in *)&route.rt_gateway;
  a->sin_family = AF_INET;
  inet_pton(AF_INET, "10.0.2.2", &a->sin_addr);
  route.rt_flags = RTF_UP | RTF_GATEWAY;
  route.rt_dev = (char *)name;
  if (ioctl(s, SIOCADDRT, &route) < 0)
    goto fail;
  close(s);
  return 0;
fail:
  close(s);
  return -1;
}
static int load_boot_modules(void) {
  FILE *list = fopen("/etc/qbox/modules", "r");
  if (!list)
    return errno == ENOENT ? 0 : -1;
  char path[4097];
  while (fgets(path, sizeof(path), list)) {
    path[strcspn(path, "\r\n")] = 0;
    if (strncmp(path, "/lib/modules/", 13) || strstr(path, "..")) {
      fclose(list);
      return -1;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
      fclose(list);
      return -1;
    }
    int result = (int)syscall(SYS_finit_module, fd, "", 0);
    int error = errno;
    close(fd);
    if (result && error != EEXIST) {
      fclose(list);
      errno = error;
      return -1;
    }
  }
  int result = ferror(list) ? -1 : 0;
  fclose(list);
  return result;
}
static int guest_init(char token[65]) {
  umask(077);
  if (qbox_tmpfs_root())
    return -1;
  if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) ||
      mount("sysfs", "/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) ||
      mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID, NULL) ||
      mount("tmpfs", "/run", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") ||
      mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC,
            "mode=1777"))
    return -1;
  if (load_boot_modules())
    return -1;
  // Early initramfs boot may have no /dev/console when the kernel starts PID 1.
  // Reserve stdio before opening pipes/control so dup2 cannot alias their
  // sources.
  int null = open("/dev/null", O_RDWR | O_CLOEXEC);
  if (null < 0)
    return -1;
  for (int target = 0; target < 3; target++) {
    if (dup2(null, target) < 0) {
      if (null > 2)
        close(null);
      return -1;
    }
  }
  if (null > 2)
    close(null);
  if (mkdir("/run/qbox", 0755))
    return -1;
  chmod("/run/qbox", 0755);
  int embedded = access("/payload/embedded", F_OK) == 0;
  if (!embedded && mount("payload", "/payload", "9p",
                         MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
                         "trans=virtio,version=9p2000.L,cache=none"))
    return -1;
  agent_mode = access("/payload/agent", F_OK) == 0;
  audit_mode = agent_mode && access("/payload/audit", F_OK) == 0;
  if ((!agent_mode && copy("/payload/program", "/run/qbox/program", 0555)) ||
      copy("/payload/hosts", "/etc/hosts", 0644) ||
      copy("/payload/token", "/run/qbox/token", 0600))
    return -1;
  if (agent_mode &&
      (copy("/payload/agent", "/run/qbox/agent", 0600) ||
       copy("/payload/workspace", "/run/qbox/workspace.input", 0600) ||
       copy("/payload/excludes", workspace_excludes, 0600)))
    return -1;
  if (!agent_mode)
    chmod("/run/qbox/program", 0555);
  chmod("/etc/hosts", 0644);
  if (!embedded && umount("/payload"))
    return -1;
  if (embedded) {
    if ((!agent_mode && unlink("/payload/program")) ||
        unlink("/payload/hosts") || unlink("/payload/token") ||
        unlink("/payload/embedded"))
      return -1;
    if (audit_mode && unlink("/payload/audit"))
      return -1;
    if (agent_mode &&
        (unlink("/payload/agent") || unlink("/payload/workspace") ||
         unlink("/payload/excludes")))
      return -1;
  }
  if (agent_mode) {
    FILE *config = fopen("/run/qbox/agent", "r");
    unsigned long long limit;
    if (!config)
      return -1;
    int valid = fscanf(config, "%llu", &limit) == 1;
    fclose(config);
    unlink("/run/qbox/agent");
    if (!valid || limit < 1024 || limit > 0xffffffffu)
      return -1;
    workspace_limit = (uint64_t)limit;
    if (mount("tmpfs", "/workspace", "tmpfs", MS_NOSUID | MS_NODEV,
              "mode=0700") ||
        chown("/workspace", 65534, 65534) ||
        mount("tmpfs", "/home", "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755") ||
        mkdir("/home/agent", 0700) || chown("/home/agent", 65534, 65534))
      return -1;
    if (qbox_workspace_import("/run/qbox/workspace.input", workspace_root,
                              65534, 65534, workspace_limit))
      return -1;
    unlink("/run/qbox/workspace.input");
    if (mkdir("/dev/pts", 0755) && errno != EEXIST)
      return -1;
    if (mount("devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC,
              "mode=0620,ptmxmode=0666"))
      return -1;
  }
  int t = open("/run/qbox/token", O_RDONLY | O_CLOEXEC);
  if (t < 0)
    return -1;
  ssize_t n = read(t, token, 65);
  close(t);
  unlink("/run/qbox/token");
  if (n != 64)
    return -1;
  token[64] = 0;
  if (interface("eth0"))
    return -1;
  // Agents may use guest-local HTTP services for their UI or tools. This
  // loopback interface is entirely inside the VM and exposes no host ports.
  int loopback = socket(AF_INET, SOCK_DGRAM, 0);
  if (loopback < 0)
    return -1;
  struct ifreq lo;
  memset(&lo, 0, sizeof(lo));
  snprintf(lo.ifr_name, sizeof(lo.ifr_name), "lo");
  if (ioctl(loopback, SIOCGIFFLAGS, &lo) < 0) {
    close(loopback);
    return -1;
  }
  lo.ifr_flags |= IFF_UP | IFF_RUNNING;
  if (ioctl(loopback, SIOCSIFFLAGS, &lo) < 0) {
    close(loopback);
    return -1;
  }
  close(loopback);
  // devtmpfs supplies device nodes but not udev's /dev/virtio-ports symlink.
  for (int attempt = 0; attempt < 300; attempt++) {
    DIR *d = opendir("/sys/class/virtio-ports");
    struct dirent *e;
    if (d) {
      while ((e = readdir(d))) {
        if (e->d_name[0] == '.')
          continue;
        char path[512], name[64];
        snprintf(path, sizeof(path), "/sys/class/virtio-ports/%s/name",
                 e->d_name);
        int f = open(path, O_RDONLY | O_CLOEXEC);
        if (f < 0)
          continue;
        n = read(f, name, sizeof(name) - 1);
        close(f);
        if (n < 0)
          continue;
        name[n] = 0;
        if (!strcmp(name, "qbox.runner\n") || !strcmp(name, "qbox.runner")) {
          snprintf(path, sizeof(path), "/dev/%s", e->d_name);
          chmod(path, 0600);
          f = open(path, O_RDWR | O_CLOEXEC);
          if (f >= 0) {
            closedir(d);
            return f;
          }
        }
      }
      closedir(d);
    }
    usleep(100000);
  }
  return -1;
}
#endif
static pid_t launch(const char *program, char **argv, char **env, int *input,
                    int *output, int *error, int isolated, int tty,
                    unsigned rows, unsigned columns) {
  int master = -1;
  char slave_path[256];
  if (tty) {
    master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master < 0)
      return -1;
    if (fcntl(master, F_SETFD, FD_CLOEXEC) < 0) {
      close(master);
      return -1;
    }
    if (grantpt(master) || unlockpt(master)) {
      close(master);
      return -1;
    }
    char *name = ptsname(master);
    if (!name || strlen(name) >= sizeof(slave_path)) {
      close(master);
      return -1;
    }
    strcpy(slave_path, name);
  }
  int in[2], out[2], err[2];
  if (pipe(in)) {
    if (master >= 0)
      close(master);
    return -1;
  }
  if (pipe(out)) {
    close(in[0]);
    close(in[1]);
    if (master >= 0)
      close(master);
    return -1;
  }
  if (pipe(err)) {
    close(in[0]);
    close(in[1]);
    close(out[0]);
    close(out[1]);
    if (master >= 0)
      close(master);
    return -1;
  }
  int barrier[2] = {-1, -1};
  if (audit_mode && pipe(barrier)) {
    close(in[0]);
    close(in[1]);
    close(out[0]);
    close(out[1]);
    close(err[0]);
    close(err[1]);
    if (master >= 0)
      close(master);
    return -1;
  }
  pid_t child = fork();
  if (child == 0) {
    if (audit_mode) {
      close(barrier[1]);
      char go;
      ssize_t n;
      do {
        n = read(barrier[0], &go, 1);
      } while (n < 0 && errno == EINTR);
      close(barrier[0]);
      if (n != 1)
        _exit(125);
    }
    if (tty) {
      if (setsid() < 0)
        _exit(126);
      int slave = open(slave_path, O_RDWR);
      if (slave < 0 || ioctl(slave, TIOCSCTTY, 0) < 0)
        _exit(126);
      struct winsize size = {0};
      size.ws_row = (unsigned short)rows;
      size.ws_col = (unsigned short)columns;
      if (ioctl(slave, TIOCSWINSZ, &size))
        _exit(126);
      dup2(slave, 0);
      dup2(slave, 1);
      dup2(slave, 2);
    } else {
      setpgid(0, 0);
      dup2(in[0], 0);
      dup2(out[1], 1);
      dup2(err[1], 2);
    }
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit) == 0) {
      unsigned long count =
          limit.rlim_max == RLIM_INFINITY ? 65536 : limit.rlim_max;
      for (unsigned long f = 3; f < count; f++)
        close((int)f);
    }
    signal(SIGPIPE, SIG_DFL);
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    sigset_t mask;
    sigemptyset(&mask);
    sigprocmask(SIG_SETMASK, &mask, NULL);
#ifdef __linux__
    if (isolated) {
      struct rlimit processes = {agent_mode ? 512 : 64, agent_mode ? 512 : 64};
      setrlimit(RLIMIT_NPROC, &processes);
      struct rlimit core = {0, 0};
      setrlimit(RLIMIT_CORE, &core);
      if (setgroups(0, NULL) || setgid(65534) || setuid(65534) ||
          prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        _exit(126);
      if (chdir(agent_mode ? workspace_root : "/run"))
        _exit(126);
    }
#else
    (void)isolated;
#endif
    if (!isolated && agent_mode && chdir(workspace_root))
      _exit(126);
    if (agent_mode && !strchr(program, '/')) {
      const char *dirs[] = {"/usr/local/bin/", "/usr/bin/", "/bin/"};
      char path[4097];
      for (unsigned i = 0; i < 3; i++) {
        if (snprintf(path, sizeof(path), "%s%s", dirs[i], program) <
            (int)sizeof(path))
          execve(path, argv, env);
      }
    }
    execve(program, argv, env);
    dprintf(
        2,
        "runnerd: execve: %s (use a static Linux ELF or include its runtime)\n",
        strerror(errno));
    _exit(127);
  }
  if (audit_mode) {
    close(barrier[0]);
    if (child > 0 && !qbox_audit_seed(child)) {
      if (write(barrier[1], "1", 1) != 1) {
        kill(child, SIGKILL);
        child = -1;
      }
    } else if (child > 0) {
      kill(child, SIGKILL);
      child = -1;
    }
    close(barrier[1]);
  }
  close(in[0]);
  close(out[1]);
  close(err[1]);
  if (child < 0) {
    if (master >= 0)
      close(master);
    close(in[1]);
    close(out[0]);
    close(err[0]);
    return -1;
  }
  if (tty) {
    close(in[1]);
    close(out[0]);
    close(err[0]);
    *input = dup(master);
    *output = master;
    *error = -1;
    if (*input < 0) {
      kill(child, SIGKILL);
      close(master);
      return -1;
    }
    nb(*input);
    nb(*output);
    return child;
  }
  setpgid(child, child);
  *input = in[1];
  *output = out[0];
  *error = err[0];
  nb(*input);
  nb(*output);
  nb(*error);
  return child;
}
int main(int argc, char **argv) {
  int fd = -1, isolated = 0;
  const char *program = "/run/qbox/program";
  char token[65] = "test";
  signal(SIGPIPE, SIG_IGN);
#ifdef __linux__
  if (getpid() == 1) {
    isolated = 1;
    fd = guest_init(token);
  }
#endif
  if (!isolated && argc == 4 && !strcmp(argv[1], "--test")) {
    fd = atoi(argv[2]);
    program = argv[3];
  }
  if (!isolated && argc == 5 && !strcmp(argv[1], "--test-agent")) {
    fd = atoi(argv[2]);
    program = argv[3];
    workspace_root = argv[4];
    agent_mode = 1;
  }
  if (fd < 0) {
#ifdef __linux__
    if (isolated) {
      int error = errno;
      mkdir("/dev", 0755);
      mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1));
      int console = open("/dev/console", O_WRONLY | O_NOCTTY);
      if (console >= 0) {
        dprintf(console, "runnerd: initialization failed: %s\n",
                strerror(error));
        close(console);
      }
      errno = error;
    }
#endif
    fprintf(stderr, "runnerd: initialization failed: %s\n", strerror(errno));
    return 125;
  }
  if (nb(fd) < 0)
    return 125;
  struct buffer rx = {0}, tx = {0}, pending = {0};
  if (make_buffer(&rx) || make_buffer(&tx) || make_buffer(&pending))
    return 125;
  if (frame(&tx, READY, token, (uint32_t)strlen(token)))
    return 125;
  if (audit_mode) {
    unsigned char ready[8196];
    int failed = qbox_audit_start() != 0;
    be32(ready, (uint32_t)failed);
    size_t ready_size = 4;
    if (failed) {
      const char *reason = qbox_audit_error();
      size_t n = strlen(reason);
      if (n > sizeof(ready) - 4)
        n = sizeof(ready) - 4;
      memcpy(ready + 4, reason, n);
      ready_size += n;
    }
    if (frame(&tx, AUDIT_READY, ready, (uint32_t)ready_size))
      return 125;
    if (failed) {
      while (tx.pos < tx.n) {
        struct pollfd writable = {fd, POLLOUT, 0};
        if (poll(&writable, 1, 100) > 0 && flush(fd, &tx))
          break;
      }
      qbox_audit_close();
      close(fd);
      if (isolated)
        while (1)
          pause();
      return 125;
    }
  }
  int audit_failed = 0, audit_stopped = 0, audit_done = 0;
  uint64_t audit_grace = 0;
  pid_t child = -1;
  int input = -1, output = -1, error = -1, stdin_eof = 0, exited = 0,
      status = 0, exit_queued = 0, result = 125;
  int tty = 0, exported = 0, exportfd = -1, export_status = 0;
  char export_path[8192];
  snprintf(export_path, sizeof(export_path), "%s",
           isolated ? "/run/qbox/workspace.output" : "");
  if (!isolated && agent_mode)
    snprintf(export_path, sizeof(export_path), "%s.export", workspace_root);
  while (1) {
    int audit_activity = 0;
    if (audit_mode && !audit_done && tx.n - tx.pos < MAX_FRAME - 32768) {
      int drained = qbox_audit_drain(audit_send, &tx);
      audit_activity = drained == 32;
      if (drained < 0 && !audit_failed) {
        audit_failed = 1;
        audit_grace = monotonic_seconds() + 30;
        if (child > 0 && kill(-child, SIGTERM) && errno == ESRCH)
          kill(child, SIGTERM);
        qbox_audit_stop();
        audit_stopped = 1;
      }
      if (audit_stopped && (drained <= 0 || audit_failed)) {
        unsigned char done[20];
        be32(done, (uint32_t)audit_failed);
        be64(done + 4, qbox_audit_count());
        be64(done + 12, qbox_audit_lost());
        if (frame(&tx, AUDIT_DONE, done, sizeof(done)))
          break;
        audit_done = 1;
      }
    }
    if (audit_failed && !exited && child > 0 &&
        monotonic_seconds() >= audit_grace) {
      kill(-child, SIGKILL);
      kill(child, SIGKILL);
      if (isolated)
        kill_agent_processes();
    }
    struct pollfd p[4] = {
        {fd,
         (short)((rx.n < MAX_FRAME + 5 && pending.n - pending.pos < MAX_FRAME
                      ? POLLIN
                      : 0) |
                 (tx.n > tx.pos ? POLLOUT : 0)),
         0},
        {input, (short)(pending.n > pending.pos ? POLLOUT : 0), 0},
        {output, (short)(tx.n - tx.pos < MAX_FRAME ? POLLIN : 0), 0},
        {error, (short)(tx.n - tx.pos < MAX_FRAME ? POLLIN : 0), 0}};
    int r = poll(p, 4, audit_activity ? 0 : 50);
    if (r < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    if (p[0].revents & POLLOUT) {
      if (flush(fd, &tx))
        break;
    }
    if (exit_queued && tx.pos == tx.n) {
      result = 0;
      break;
    }
    if (p[0].revents & (POLLIN | POLLHUP)) {
      unsigned char b[16384];
      ssize_t n = read(fd, b, sizeof(b));
      if (n == 0)
        break;
      if (n < 0 && errno != EAGAIN && errno != EINTR)
        break;
      if (n > 0 && append(&rx, b, (size_t)n))
        break;
    }
    compact(&rx);
    size_t used = 0;
    int bad = 0;
    while (rx.n - used >= 5) {
      uint8_t type = rx.p[used];
      uint32_t n = u32(rx.p + used + 1);
      if (n > MAX_FRAME) {
        bad = 1;
        break;
      }
      if (rx.n - used < 5 + n)
        break;
      unsigned char *body = rx.p + used + 5;
      if ((type == EXEC || type == EXEC_AGENT) && child < 0) {
        size_t pos = 0;
        unsigned rows = 24, columns = 80;
        if (type == EXEC_AGENT) {
          if (!agent_mode || n < 12 || u32(body) > 1 || !u32(body + 4) ||
              u32(body + 4) > 1000 || !u32(body + 8) || u32(body + 8) > 1000) {
            bad = 1;
            break;
          }
          tty = (int)u32(body);
          rows = u32(body + 4);
          columns = u32(body + 8);
          pos = 12;
        } else if (agent_mode) {
          bad = 1;
          break;
        }
        char **args = NULL, **env = NULL;
        int valid = !strings(body, n, &pos, &args, 0) &&
                    !strings(body, n, &pos, &env, 1) && pos == n;
        if (valid && !audit_failed)
          child = launch(agent_mode ? args[0] : program, args, env, &input,
                         &output, &error, isolated, tty, rows, columns);
        free_strings(args);
        free_strings(env);
        if (!valid || child < 0) {
          if (valid)
            dprintf(2, "runnerd: launch failed: %s\n", strerror(errno));
          bad = 1;
          break;
        }
      } else if (type == INPUT && child > 0 && !stdin_eof) {
        if (!n && tty) {
          unsigned char eof = 4;
          if (input >= 0 && append(&pending, &eof, 1)) {
            bad = 1;
            break;
          }
          stdin_eof = 1;
        } else if (!n)
          stdin_eof = 1;
        else if (input >= 0 && append(&pending, body, n)) {
          bad = 1;
          break;
        }
      } else if (type == SIGNAL_CHILD && child > 0 && n == 4) {
        uint32_t sig = u32(body);
        if (sig != 2 && sig != 15 && sig != 9) {
          bad = 1;
          break;
        }
        if (kill(-child, (int)sig) && errno == ESRCH)
          kill(child, (int)sig);
      } else if (type == RESIZE && child > 0 && tty && n == 8) {
        uint32_t rows = u32(body), columns = u32(body + 4);
        if (!rows || rows > 1000 || !columns || columns > 1000) {
          bad = 1;
          break;
        }
        struct winsize size = {0};
        size.ws_row = (unsigned short)rows;
        size.ws_col = (unsigned short)columns;
        if (output >= 0)
          ioctl(output, TIOCSWINSZ, &size);
      } else {
        bad = 1;
        break;
      }
      used += 5 + n;
    }
    rx.pos = used;
    compact(&rx);
    if (bad)
      break;
    if (input >= 0 && (p[1].revents & (POLLOUT | POLLERR | POLLHUP))) {
      if (flush(input, &pending)) {
        close(input);
        input = -1;
        pending.n = pending.pos = 0;
      }
    }
    if (input >= 0 && stdin_eof && pending.n == pending.pos) {
      close(input);
      input = -1;
    }
    int *fds[2] = {&output, &error};
    for (int i = 0; i < 2; i++)
      if (*fds[i] >= 0 && (p[i + 2].revents & (POLLIN | POLLHUP | POLLERR))) {
        unsigned char b[16384];
        ssize_t n = read(*fds[i], b, sizeof(b));
        if (n > 0) {
          if (frame(&tx, i ? ERROR_OUTPUT : OUTPUT, b, (uint32_t)n)) {
            bad = 1;
            break;
          }
        } else if (n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR)) {
          close(*fds[i]);
          *fds[i] = -1;
        }
      }
    if (bad)
      break;
    if (child > 0 && !exited) {
      pid_t w;
      int state;
      while ((w = waitpid(-1, &state, WNOHANG)) > 0) {
        if (w == child) {
          status = state;
          exited = 1;
          kill(-child, SIGKILL);
          if (isolated && agent_mode)
            kill_agent_processes();
        }
      }
    }
    if (exited && output < 0 && error < 0 && agent_mode && !exported) {
      if (isolated)
        while (waitpid(-1, NULL, 0) > 0) {
        }
      if (audit_mode && !audit_stopped) {
        qbox_audit_stop();
        audit_stopped = 1;
      }
      export_status = qbox_workspace_export(export_path, workspace_root,
                                            workspace_excludes, workspace_limit)
                          ? 1
                          : 0;
      if (!export_status) {
        exportfd = open(export_path, O_RDONLY | O_CLOEXEC);
        if (exportfd < 0)
          export_status = 1;
      }
      exported = 1;
    }
    if (exportfd >= 0 && tx.n - tx.pos < MAX_FRAME) {
      unsigned char b[16384];
      ssize_t count = read(exportfd, b, sizeof(b));
      if (count > 0) {
        if (frame(&tx, WORKSPACE_DATA, b, (uint32_t)count))
          break;
      } else {
        if (count < 0)
          export_status = 1;
        close(exportfd);
        exportfd = -1;
        unlink(export_path);
      }
    }
    if (exited && output < 0 && error < 0 && exportfd < 0 && !exit_queued &&
        (!audit_mode || audit_done)) {
      if (agent_mode) {
        unsigned char done[4];
        be32(done, (uint32_t)export_status);
        if (frame(&tx, WORKSPACE_DONE, done, 4))
          break;
      }
      unsigned char body[8];
      be32(body, WIFSIGNALED(status) ? 1 : 0);
      be32(body + 4, WIFSIGNALED(status) ? (uint32_t)WTERMSIG(status)
                                         : (uint32_t)WEXITSTATUS(status));
      if (frame(&tx, EXIT, body, 8))
        break;
      exit_queued = 1;
    }
  }
  if (child > 0) {
    kill(-child, SIGKILL);
    if (isolated && agent_mode)
      kill_agent_processes();
    while (waitpid(-1, NULL, 0) > 0) {
    }
  }
  if (input >= 0)
    close(input);
  if (output >= 0)
    close(output);
  if (error >= 0)
    close(error);
  close(fd);
  if (exportfd >= 0)
    close(exportfd);
  if (agent_mode)
    unlink(export_path);
  if (audit_mode)
    qbox_audit_close();
  free(rx.p);
  free(tx.p);
  free(pending.p);
  // PID 1 must stay alive until the host tears down QEMU, avoiding a kernel
  // panic racing the final virtio-serial write.
  if (isolated)
    while (1)
      pause();
  return result;
}
