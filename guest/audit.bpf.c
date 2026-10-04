/* SPDX-License-Identifier: MIT OR GPL-2.0-only */
/* Copyright (c) 2026 vertigo and QBox contributors */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "audit_event.h"
/* Only the accessed fields need declarations: CO-RE relocates against BTF. */
struct task_struct {
  int pid, tgid, exit_code;
} __attribute__((preserve_access_index));
struct linux_binprm {
  const char *filename;
} __attribute__((preserve_access_index));
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32768);
  __type(key, unsigned int);
  __type(value, unsigned int);
} tracked SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 32768);
  __type(key, unsigned int);
  __type(value, struct qbox_audit_event);
} connecting SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, unsigned int);
  __type(value, unsigned long long);
} lost SEC(".maps");
static __always_inline void loss(void) {
  unsigned int zero = 0;
  unsigned long long *n = bpf_map_lookup_elem(&lost, &zero);
  if (n)
    __sync_fetch_and_add(n, 1);
}
static __always_inline void emit(struct qbox_audit_event *e) {
  if (bpf_ringbuf_output(&events, e, sizeof(*e), 0))
    loss();
}
static __always_inline void init(struct qbox_audit_event *e,
                                 unsigned int type) {
  unsigned long long ids = bpf_get_current_pid_tgid();
  e->time = bpf_ktime_get_ns();
  e->type = type;
  e->tid = ids;
  e->pid = ids >> 32;
  e->uid = bpf_get_current_uid_gid();
  bpf_get_current_comm(e->comm, sizeof(e->comm));
}
SEC("raw_tp/sched_process_fork")
int on_fork(struct bpf_raw_tracepoint_args *ctx) {
  struct task_struct *parent = (void *)ctx->args[0],
                     *child = (void *)ctx->args[1];
  unsigned int p = BPF_CORE_READ(parent, pid), c = BPF_CORE_READ(child, pid);
  unsigned int *root = bpf_map_lookup_elem(&tracked, &p);
  if (!root)
    return 0;
  unsigned int value = *root;
  if (bpf_map_update_elem(&tracked, &c, &value, BPF_ANY))
    loss();
  struct qbox_audit_event e = {};
  init(&e, 1);
  e.parent = p;
  e.tid = c;
  e.pid = BPF_CORE_READ(child, tgid);
  emit(&e);
  return 0;
}
SEC("raw_tp/sched_process_exec")
int on_exec(struct bpf_raw_tracepoint_args *ctx) {
  unsigned int old = ctx->args[1], tid = bpf_get_current_pid_tgid();
  unsigned int *root = bpf_map_lookup_elem(&tracked, &old);
  if (!root)
    root = bpf_map_lookup_elem(&tracked, &tid);
  if (!root)
    return 0;
  unsigned int value = *root;
  if (old != tid) {
    bpf_map_delete_elem(&tracked, &old);
    if (bpf_map_update_elem(&tracked, &tid, &value, BPF_ANY))
      loss();
  }
  struct qbox_audit_event e = {};
  init(&e, 2);
  struct linux_binprm *bprm = (void *)ctx->args[2];
  const char *filename = BPF_CORE_READ(bprm, filename);
  long n = bpf_probe_read_kernel_str(e.path, sizeof(e.path), filename);
  if (n < 0)
    loss();
  e.truncated = n == sizeof(e.path);
  emit(&e);
  return 0;
}
SEC("raw_tp/sched_process_exit")
int on_exit(struct bpf_raw_tracepoint_args *ctx) {
  unsigned int tid = bpf_get_current_pid_tgid();
  if (!bpf_map_lookup_elem(&tracked, &tid))
    return 0;
  struct qbox_audit_event e = {};
  init(&e, 3);
  struct task_struct *task = (void *)ctx->args[0];
  e.result = BPF_CORE_READ(task, exit_code);
  emit(&e);
  bpf_map_delete_elem(&tracked, &tid);
  bpf_map_delete_elem(&connecting, &tid);
  return 0;
}
struct enter {
  unsigned long long common;
  long id;
  unsigned long args[6];
};
struct leave {
  unsigned long long common;
  long id, result;
};
SEC("tp/syscalls/sys_enter_connect")
int on_connect(struct enter *ctx) {
  unsigned int tid = bpf_get_current_pid_tgid();
  if (!bpf_map_lookup_elem(&tracked, &tid))
    return 0;
  unsigned char addr[28] = {};
  unsigned int len = ctx->args[2];
  if (len < 2)
    return 0;
  if (bpf_probe_read_user(addr, len < sizeof(addr) ? len : sizeof(addr),
                          (void *)ctx->args[1]))
    return 0;
  unsigned short family = addr[0] | ((unsigned short)addr[1] << 8);
  if ((family != 2 && family != 10) || len < (family == 2 ? 16 : 28))
    return 0;
  struct qbox_audit_event e = {};
  init(&e, 4);
  e.family = family;
  e.port = ((unsigned int)addr[2] << 8) | addr[3];
  if (family == 2)
    __builtin_memcpy(e.address, addr + 4, 4);
  else
    __builtin_memcpy(e.address, addr + 8, 16);
  if (bpf_map_update_elem(&connecting, &tid, &e, BPF_ANY))
    loss();
  emit(&e);
  return 0;
}
SEC("tp/syscalls/sys_exit_connect")
int on_connect_exit(struct leave *ctx) {
  unsigned int tid = bpf_get_current_pid_tgid();
  struct qbox_audit_event *e = bpf_map_lookup_elem(&connecting, &tid);
  if (!e)
    return 0;
  e->type = 5;
  e->time = bpf_ktime_get_ns();
  e->result = ctx->result;
  emit(e);
  bpf_map_delete_elem(&connecting, &tid);
  return 0;
}
char LICENSE[] SEC("license") = "Dual MIT/GPL";
