#define _GNU_SOURCE
#include "workspace.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>
static uint32_t u32(const unsigned char *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
static void be32(unsigned char *p, uint32_t n) {
  p[0] = n >> 24;
  p[1] = n >> 16;
  p[2] = n >> 8;
  p[3] = n;
}
static int exact(FILE *in, void *p, size_t n) {
  return fread(p, 1, n, in) == n ? 0 : -1;
}
static int safe_path(const char *p) {
  if (!*p || *p == '/' || strlen(p) > 4096 || strpbrk(p, "\\:<>\"|?*"))
    return 0;
  for (const unsigned char *s = (const unsigned char *)p; *s; s++)
    if (*s < 32) return 0;
  const char *start = p;
  for (const char *s = p;; s++)
    if (*s == '/' || !*s) {
      size_t n = (size_t)(s - start);
      if (!n || (n == 1 && *start == '.') ||
          (n == 2 && !memcmp(start, "..", 2)))
        return 0;
      if (!*s)
        break;
      start = s + 1;
    }
  return 1;
}
static int safe_link(const char *path, const char *target) {
  if (!*target || *target == '/' || strpbrk(target, "\\:\r\n"))
    return 0;
  (void)path;
  const char *start = target;
  for (const char *p = target;; p++)
    if (*p == '/' || !*p) {
      size_t n = (size_t)(p - start);
      if (n == 2 && !memcmp(start, "..", 2)) {
        // Even lexically contained '..' can escape through another symlink.
        return 0;
      }
      if (!*p)
        break;
      start = p + 1;
    }
  return 1;
}
// Resolve every parent with openat/O_NOFOLLOW, never through an archive
// symlink.
static int parent_fd(int root, const char *path, char name[4097]) {
  char copy[4097];
  snprintf(copy, sizeof(copy), "%s", path);
  char *part = copy, *slash;
  int fd = dup(root);
  if (fd < 0)
    return -1;
  while ((slash = strchr(part, '/'))) {
    *slash = 0;
    int next =
        openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(fd);
    if (next < 0)
      return -1;
    fd = next;
    part = slash + 1;
  }
  snprintf(name, 4097, "%s", part);
  return fd;
}
int qbox_workspace_import(const char *archive, const char *root, uid_t uid,
                          gid_t gid, uint64_t limit) {
  struct stat st;
  if (stat(archive, &st) || (uint64_t)st.st_size > limit)
    return -1;
  FILE *in = fopen(archive, "rb");
  int rootfd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (!in || rootfd < 0) {
    if (in)
      fclose(in);
    if (rootfd >= 0)
      close(rootfd);
    return -1;
  }
  char magic[8];
  int result = -1;
  char **directories = NULL;
  mode_t *modes = NULL;
  size_t dircount = 0, count = 0;
  if (exact(in, magic, 8) || memcmp(magic, "QBWS0001", 8))
    goto done;
  for (;;) {
    unsigned char h[17];
    if (exact(in, h, sizeof(h)))
      goto done;
    unsigned kind = h[0];
    uint32_t mode = u32(h + 1) & 0777, len = u32(h + 5);
    uint64_t size = (uint64_t)u32(h + 9) << 32 | u32(h + 13);
    if (!kind) {
      if (len || size || u32(h + 1) || fgetc(in) != EOF)
        goto done;
      break;
    }
    if (kind > 3 || !len || len > 4096 || size > limit || ++count > 100000 ||
        (kind == 1 && size) || (kind == 3 && size > 4096))
      goto done;
    char path[4097], name[4097];
    if (exact(in, path, len) || memchr(path, 0, len))
      goto done;
    path[len] = 0;
    if (!safe_path(path))
      goto done;
    int parent = parent_fd(rootfd, path, name);
    if (parent < 0)
      goto done;
    int bad = 0;
    if (kind == 1) {
      if (mkdirat(parent, name, 0700))
        bad = 1;
      else {
        char **newdirs = realloc(directories, (dircount + 1) * sizeof(char *));
        if (!newdirs)
          bad = 1;
        else {
          directories = newdirs;
          mode_t *newmodes = realloc(modes, (dircount + 1) * sizeof(mode_t));
          if (!newmodes)
            bad = 1;
          else {
            modes = newmodes;
            directories[dircount] = strdup(path);
            if (!directories[dircount])
              bad = 1;
            else
              modes[dircount++] = mode;
          }
        }
      }
    } else if (kind == 2) {
      int f =
          openat(parent, name,
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
      if (f < 0)
        bad = 1;
      else {
        char b[16384];
        for (uint64_t left = size; left && !bad;) {
          size_t n = left > sizeof(b) ? sizeof(b) : (size_t)left;
          if (exact(in, b, n)) {
            bad = 1;
            break;
          }
          size_t pos = 0;
          while (pos < n) {
            ssize_t w = write(f, b + pos, n - pos);
            if (w < 0 && errno == EINTR)
              continue;
            if (w <= 0) {
              bad = 1;
              break;
            }
            pos += (size_t)w;
          }
          left -= n;
        }
        if (fchown(f, uid, gid) || fchmod(f, (mode_t)mode))
          bad = 1;
        close(f);
      }
    } else {
      char target[4097];
      if (exact(in, target, (size_t)size) || memchr(target, 0, (size_t)size))
        bad = 1;
      else {
        target[size] = 0;
        if (!safe_link(path, target) || symlinkat(target, parent, name))
          bad = 1;
      }
    }
    if (!bad && fchownat(parent, name, uid, gid, AT_SYMLINK_NOFOLLOW))
      bad = 1;
    close(parent);
    if (bad)
      goto done;
  }
  for (size_t i = dircount; i > 0; i--) {
    char name[4097];
    int parent = parent_fd(rootfd, directories[i - 1], name);
    if (parent < 0)
      goto done;
    int f =
        openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    close(parent);
    if (f < 0)
      goto done;
    int bad = fchmod(f, modes[i - 1]);
    close(f);
    if (bad)
      goto done;
  }
  result = 0;
done:
  for (size_t i = 0; i < dircount; i++)
    free(directories[i]);
  free(directories);
  free(modes);
  fclose(in);
  close(rootfd);
  return result;
}
struct export_state {
  FILE *out;
  uint64_t size, limit;
  unsigned count;
  char **excluded;
  size_t exclude_count;
};
static int emit(struct export_state *s, const void *p, size_t n) {
  if (n > s->limit - s->size)
    return -1;
  if (fwrite(p, 1, n, s->out) != n)
    return -1;
  s->size += n;
  return 0;
}
static int walk(struct export_state *s, int fd, const char *prefix) {
  DIR *dir = fdopendir(dup(fd));
  if (!dir)
    return -1;
  struct dirent *entry;
  int result = 0;
  while ((entry = readdir(dir))) {
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;
    int skip = 0;
    if (!*prefix)
      for (size_t i = 0; i < s->exclude_count; i++)
        if (!strcasecmp(entry->d_name, s->excluded[i]))
          skip = 1;
    if (skip)
      continue;
    char path[4097];
    int n = snprintf(path, sizeof(path), "%s%s%s", prefix, *prefix ? "/" : "",
                     entry->d_name);
    if (n < 0 || n >= 4097 || !safe_path(path) || ++s->count > 100000) {
      result = -1;
      break;
    }
    struct stat st;
    if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
      result = -1;
      break;
    }
    unsigned kind = S_ISDIR(st.st_mode)   ? 1
                    : S_ISREG(st.st_mode) ? 2
                    : S_ISLNK(st.st_mode) ? 3
                                          : 0;
    if (!kind) {
      result = -1;
      break;
    }
    uint64_t size = kind == 2 ? (uint64_t)st.st_size : 0;
    char target[4097];
    if (kind == 3) {
      ssize_t len = readlinkat(fd, entry->d_name, target, 4096);
      if (len <= 0 || len >= 4096) {
        result = -1;
        break;
      }
      target[len] = 0;
      if (!safe_link(path, target)) {
        result = -1;
        break;
      }
      size = (uint64_t)len;
    }
    unsigned char h[17];
    h[0] = (unsigned char)kind;
    be32(h + 1, kind == 3 ? 0777 : st.st_mode & 0777);
    be32(h + 5, (uint32_t)n);
    be32(h + 9, (uint32_t)(size >> 32));
    be32(h + 13, (uint32_t)size);
    if (emit(s, h, 17) || emit(s, path, (size_t)n)) {
      result = -1;
      break;
    }
    if (kind == 1) {
      int child = openat(fd, entry->d_name,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      if (child < 0) {
        result = -1;
        break;
      }
      result = walk(s, child, path);
      close(child);
      if (result)
        break;
    } else if (kind == 2) {
      int f = openat(fd, entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
      if (f < 0) {
        result = -1;
        break;
      }
      char b[16384];
      for (uint64_t left = size; left;) {
        size_t count = left > sizeof(b) ? sizeof(b) : (size_t)left;
        ssize_t got = read(f, b, count);
        if (got < 0 && errno == EINTR)
          continue;
        if (got <= 0 || emit(s, b, (size_t)got)) {
          result = -1;
          break;
        }
        left -= (uint64_t)got;
      }
      close(f);
      if (result)
        break;
    } else if (emit(s, target, (size_t)size)) {
      result = -1;
      break;
    }
  }
  closedir(dir);
  return result;
}
int qbox_workspace_export(const char *archive, const char *root,
                          const char *excludes, uint64_t limit) {
  FILE *out = fopen(archive, "wb");
  if (!out)
    return -1;
  struct export_state state = {out, 0, limit, 0, NULL, 0};
  int result = -1;
  int fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0)
    goto done;
  const char *defaults[] = {".git", ".qbox-results", ".DS_Store"};
  state.excluded = calloc(3, sizeof(char *));
  if (!state.excluded)
    goto done;
  for (size_t i = 0; i < 3; i++) {
    state.excluded[i] = strdup(defaults[i]);
    if (!state.excluded[i])
      goto done;
    state.exclude_count++;
  }
  FILE *names = excludes ? fopen(excludes, "r") : NULL;
  if (names) {
    char name[4097];
    while (fgets(name, sizeof(name), names)) {
      name[strcspn(name, "\r\n")] = 0;
      char **p =
          realloc(state.excluded, (state.exclude_count + 1) * sizeof(char *));
      if (!p) {
        fclose(names);
        goto done;
      }
      state.excluded = p;
      p[state.exclude_count] = strdup(name);
      if (!p[state.exclude_count]) {
        fclose(names);
        goto done;
      }
      state.exclude_count++;
    }
    fclose(names);
  }
  unsigned char end[17] = {0};
  if (!emit(&state, "QBWS0001", 8) && !walk(&state, fd, "") &&
      !emit(&state, end, 17))
    result = 0;
done:
  if (fd >= 0)
    close(fd);
  for (size_t i = 0; i < state.exclude_count; i++)
    free(state.excluded[i]);
  free(state.excluded);
  if (fclose(out))
    result = -1;
  return result;
}
