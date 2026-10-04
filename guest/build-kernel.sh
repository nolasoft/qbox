#!/bin/sh
set -eu
qbox_arch=${1:?usage: build-kernel.sh x86_64\|aarch64 linux-source-directory output-directory [--with-audit]}
qbox_source=${2:?provide a verified Linux source checkout}
qbox_out=${3:?provide an output directory}
case "$qbox_arch" in x86_64) qbox_linux_arch=x86; qbox_image=arch/x86/boot/bzImage;; aarch64) qbox_linux_arch=arm64; qbox_image=arch/arm64/boot/Image;; *) exit 1;; esac
mkdir -p "$qbox_out"
qbox_out=$(CDPATH= cd -- "$qbox_out" && pwd)
make -C "$qbox_source" O="$qbox_out/kernel-build" ARCH="$qbox_linux_arch" defconfig
qbox_config="$qbox_out/kernel-build/.config"
for qbox_option in BLK_DEV_INITRD RD_GZIP DEVTMPFS DEVTMPFS_MOUNT TMPFS PROC_FS SYSFS BINFMT_ELF BINFMT_SCRIPT UNIX98_PTYS TTY SECCOMP SECCOMP_FILTER SECURITY SECURITY_LANDLOCK NAMESPACES USER_NS PID_NS IPC_NS UTS_NS NET_NS NET INET PACKET UNIX PCI VIRTIO VIRTIO_PCI VIRTIO_NET VIRTIO_CONSOLE NET_9P NET_9P_VIRTIO 9P_FS; do
  "$qbox_source/scripts/config" --file "$qbox_config" --enable "$qbox_option"
done
"$qbox_source/scripts/config" --file "$qbox_config" --disable MODULES --disable IPV6
if [ "${4:-}" = --with-audit ]; then
  for qbox_option in BPF BPF_SYSCALL BPF_JIT BPF_UNPRIV_DEFAULT_OFF BPF_EVENTS PERF_EVENTS TRACEPOINTS FTRACE FTRACE_SYSCALLS DEBUG_INFO DEBUG_INFO_DWARF5 DEBUG_INFO_BTF; do
    "$qbox_source/scripts/config" --file "$qbox_config" --enable "$qbox_option"
  done
  "$qbox_source/scripts/config" --file "$qbox_config" --disable DEBUG_INFO_NONE --disable DEBUG_INFO_REDUCED --disable BPF_LSM
elif [ -n "${4:-}" ]; then
  echo 'unknown option' >&2; exit 1
fi
make -C "$qbox_source" O="$qbox_out/kernel-build" ARCH="$qbox_linux_arch" olddefconfig
make -C "$qbox_source" O="$qbox_out/kernel-build" ARCH="$qbox_linux_arch" -j "${JOBS:-4}"
cp "$qbox_out/kernel-build/$qbox_image" "$qbox_out/vmlinuz"

cp "$qbox_config" "$qbox_out/kernel.config"
