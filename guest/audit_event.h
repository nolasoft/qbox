#ifndef QBOX_AUDIT_EVENT_H
#define QBOX_AUDIT_EVENT_H
/* Little-endian, fixed layout shared by BPF, PID 1 and the host decoder. */
struct qbox_audit_event {
  unsigned long long time;
  unsigned int type, tid, pid, parent, uid, family, port;
  int result;
  unsigned int truncated;
  char comm[16], path[256];
  unsigned char address[16];
  unsigned int reserved;
};
_Static_assert(sizeof(struct qbox_audit_event) == 336,
               "audit wire layout changed");
#endif
