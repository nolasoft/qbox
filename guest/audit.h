#ifndef QBOX_AUDIT_H
#define QBOX_AUDIT_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
const char *qbox_audit_error(void);
int qbox_audit_start(void);
int qbox_audit_seed(pid_t pid);
int qbox_audit_drain(int (*send)(const void *, size_t, void *), void *context);
uint64_t qbox_audit_count(void);
uint64_t qbox_audit_lost(void);
void qbox_audit_stop(void);
void qbox_audit_close(void);
#endif
