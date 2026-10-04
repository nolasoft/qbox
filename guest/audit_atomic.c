/* Alpine's GCC-built libbpf uses this outlined atomic helper. Zig's Linux
 * compiler runtime does not currently provide its _sync variant. Compile
 * this file with -mno-outline-atomics so it uses inline LL/SC instructions. */
#ifdef __aarch64__
unsigned int __aarch64_ldadd4_sync(unsigned int value,
                                   volatile unsigned int *ptr) {
  return __atomic_fetch_add(ptr, value, __ATOMIC_SEQ_CST);
}
#endif
