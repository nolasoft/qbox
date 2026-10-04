#!/bin/sh
set -eu
qbox_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec python3 "$qbox_script_dir/make_initramfs.py" "$@"
