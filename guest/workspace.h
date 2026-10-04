#ifndef QBOX_WORKSPACE_H
#define QBOX_WORKSPACE_H
#include <stdint.h>
#include <sys/types.h>
int qbox_workspace_import(const char *archive, const char *root, uid_t uid,
                          gid_t gid, uint64_t limit);
int qbox_workspace_export(const char *archive, const char *root,
                          const char *excludes, uint64_t limit);
#endif
