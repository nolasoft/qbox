#define _GNU_SOURCE
#include "rootfs.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/mount.h>
static int copy_tree(const char *source, const char *destination, int top) {
  DIR *dir = opendir(source);
  if (!dir) return -1;
  struct dirent *entry;
  int result = 0;
  while ((entry = readdir(dir))) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
        (top && !strcmp(entry->d_name, "qbox-root"))) continue;
    char from[4097], to[4097];
    if (snprintf(from, sizeof(from), "%s%s%s", source, !strcmp(source, "/") ? "" : "/", entry->d_name) >= (int)sizeof(from) ||
        snprintf(to, sizeof(to), "%s/%s", destination, entry->d_name) >= (int)sizeof(to)) {
      result = -1; break;
    }
    struct stat s;
    if (lstat(from, &s)) { result = -1; break; }
    if (S_ISDIR(s.st_mode)) {
      if (mkdir(to, 0700) || copy_tree(from, to, 0) || chmod(to, s.st_mode & 0777)) {
        result = -1; break;
      }
    } else if (S_ISREG(s.st_mode)) {
      int in = open(from, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      int out = open(to, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
      if (in < 0 || out < 0) {
        if (in >= 0) close(in);
        if (out >= 0) close(out);
        result = -1; break;
      }
      char buffer[65536];
      ssize_t n;
      while ((n = read(in, buffer, sizeof(buffer))) > 0) {
        for (ssize_t pos = 0; pos < n;) {
          ssize_t written = write(out, buffer + pos, (size_t)(n - pos));
          if (written < 0 && errno == EINTR) continue;
          if (written <= 0) { result = -1; break; }
          pos += written;
        }
        if (result) break;
      }
      if (n < 0 || fchmod(out, s.st_mode & 0777)) result = -1;
      close(in); close(out);
      if (result) break;
    } else if (S_ISLNK(s.st_mode)) {
      char target[4097];
      ssize_t n = readlink(from, target, sizeof(target) - 1);
      if (n < 0 || n == (ssize_t)sizeof(target) - 1) { result = -1; break; }
      target[n] = 0;
      if (symlink(target, to)) { result = -1; break; }
    } else if (!strncmp(from, "/dev/", 5) &&
               (S_ISCHR(s.st_mode) || S_ISBLK(s.st_mode))) {
      // The kernel's built-in initramfs may supply /dev/console. The new
      // root gets its device nodes from devtmpfs after this transition.
    } else { errno = EINVAL; result = -1; break; }
    // The original initramfs has no mounted children yet. Release each source
    // after its copy succeeds, keeping RAM usage close to the image size.
    if ((S_ISDIR(s.st_mode) ? rmdir(from) : unlink(from))) { result = -1; break; }
  }
  closedir(dir);
  return result;
}
#endif
int qbox_tmpfs_root(void) {
#ifdef __linux__
  if (getpid() != 1 || access("/etc/qbox/tmpfs-root", F_OK)) return 0;
  if (mkdir("/qbox-root", 0755) ||
      mount("tmpfs", "/qbox-root", "tmpfs", MS_NOSUID, "mode=0755") ||
      copy_tree("/", "/qbox-root", 1) || chdir("/qbox-root") ||
      mount(".", "/", NULL, MS_MOVE, NULL) || chroot(".") || chdir("/"))
    return -1;
#endif
  return 0;
}
