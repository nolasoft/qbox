#!/bin/sh
set -eu
# Run with a Linux-targeting static C toolchain (native Linux or cross compiler).
# CC may be a compiler command such as 'zig cc -target aarch64-linux-musl'.
qbox_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
qbox_arch=${1:?usage: build-guest.sh x86_64\|aarch64 [output-directory]}
case "$qbox_arch" in x86_64|aarch64) ;; *) echo 'unsupported architecture' >&2; exit 1;; esac
qbox_out=${2:-"$qbox_script_dir/../assets/$qbox_arch"}
mkdir -p "$qbox_out"
${CC:-cc} ${CFLAGS:-} -std=c11 -Os -static -Wall -Wextra "$qbox_script_dir/runnerd.c" "$qbox_script_dir/workspace.c" "$qbox_script_dir/rootfs.c" "$qbox_script_dir/audit.c" -o "$qbox_out/runnerd"
"$qbox_script_dir/build-initramfs.sh" --runner "$qbox_out/runnerd" --arch "$qbox_arch" --output "$qbox_out/initramfs.img"
for qbox_fixture in hello net_allowed net_denied fixture; do
  ${CC:-cc} ${CFLAGS:-} -std=c11 -Os -static "$qbox_script_dir/../tests/$qbox_fixture.c" -o "$qbox_out/$qbox_fixture"
done
