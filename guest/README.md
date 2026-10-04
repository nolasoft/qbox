# Building the disposable Linux guest

Build on Linux with a native static C toolchain, or use a Linux cross compiler.
No root privileges are needed for guest image creation or ordinary QBox launch.
Building a kernel needs Linux build tools: make, compiler, binutils, flex, bison,
bc, and the development dependencies requested by the selected kernel release.

```sh
# Native Linux x86_64:
guest/build-guest.sh x86_64 assets/x86_64

# Cross compiler (also usable on macOS if installed):
CC=aarch64-linux-musl-gcc guest/build-guest.sh aarch64 assets/aarch64

# Alternative compiler command:
CC='zig cc -target aarch64-linux-musl' guest/build-guest.sh aarch64 assets/aarch64
```

`build-guest.sh` creates static runnerd, initramfs, and integration fixtures. It
rejects a host Mach-O runner or a dynamic Linux runner. The initramfs is a
deterministic gzip-compressed newc archive generated with Python; no BusyBox,
shell, cpio utility, persistent disk, or package manager is included.

Obtain and verify a Linux source release independently. Then run:

```sh
guest/build-kernel.sh x86_64 /path/to/linux-source assets/x86_64
# For an arm64 cross build, export CROSS_COMPILE=aarch64-linux-gnu-
guest/build-kernel.sh aarch64 /path/to/linux-source assets/aarch64
```

The script enables built-in initramfs/gzip, devtmpfs, tmpfs, proc/sysfs, ELF, IPv4,
PCI and virtio PCI/network/console/9P. Kernel modules and IPv6 are disabled. Its
defconfig-based kernel is a starting point; hardening/minimization is future work.
The arm64 kernel must support the QEMU `virt` machine and the x86_64 kernel `q35`.
Record the kernel release, source checksum and final `.config` used for deployment.

To include HTTPS trust or dynamic program runtimes:

```sh
guest/build-initramfs.sh --runner assets/aarch64/runnerd --arch aarch64 \
  --output assets/aarch64/initramfs.img --ca-bundle /path/to/ca-certificates.crt \
  --runtime /path/to/minimal-linux-runtime-tree
```

The optional runtime tree must contain only `lib`, `lib64`, and `usr` with guest
architecture libraries and loaders. It is trusted build input. The supervisor
itself always remains static. Kernel and guest artifacts are ignored by Git.

For coding agents, use `--rootfs /path/to/prepared-linux-rootfs` instead of
`--runtime`. The builder includes `bin`, `sbin`, `lib`, `lib64`, `usr`, `etc`,
`opt`, and `var`; it excludes account home directories and preserves QBox's
hosts/NSS/resolver configuration. Install agent executables in `/usr/local/bin`
or `/usr/bin`, with their architecture-compatible libraries and dependencies.
Build from a clean, trusted userspace tree without credentials. System files
are packaged without write permission; `/workspace`, `/home/agent`, and `/tmp`
are writable temporary storage. See [agent setup](../docs/agents.md).

Alternatively, after building the static runner, assemble a prepared image:

```sh
python3 guest/prepare-agent-image.py --arch aarch64
# For an x86 guest, first build assets/x86_64/runnerd, then use --arch x86_64.
```

This requires Python and curl, works without Docker/root, and writes only local
`build/agent-image` and `assets/<arch>` directories. Versions of Codex, Claude
Code, and OpenCode are explicit script defaults and can be overridden by `--codex-version`,
`--claude-version`, and `--opencode-version`. Alpine package indexes are cached; use a fresh `--cache`
directory to resolve new package versions. The assembler is tailored to these
tools, does not run APK maintainer scripts, and is not a general package manager.

For C/C++ projects, add `--with-build-tools` to include Alpine `build-base`,
CMake, and Ninja. Add other guest dependencies with repeatable `--package NAME`
options, for example `--package pkgconf --package openssl-dev`. Both flags work
with `--with-audit`; resolved versions appear in `agents-manifest.json`.
Host tools are not shared with the VM. See
[guest project tools](../docs/agents.md#guest-project-tools) for image/runtime
constraints and [copy/paste](../docs/agents.md#copy-and-paste) for terminal behavior.

The Alpine virtual kernel includes some required drivers as modules. The
assembler extracts only QBox's selected modules and their dependencies, verifies
APK control/data checksums against the HTTPS-downloaded index, decompresses them,
and writes `/etc/qbox/modules` in dependency order. Guest PID 1 loads that trusted
list before using the devices; ordinary agent processes cannot load modules.
Provider binaries are checked against published SHA256 release digests. The
indexes are trusted via HTTPS; independent Alpine signing-key verification is
not implemented. `agents-manifest.json` records source URLs, resolved versions,
and SHA256 hashes of every downloaded input. Kernel config is saved alongside it.

Prepared images contain `/etc/qbox/tmpfs-root`. PID 1 copies the initial root
onto tmpfs, frees the old files, and moves that mount to `/` before mounting
proc/sys/dev. This allows tools such as bubblewrap to pivot their own roots and
create unprivileged user namespaces. IPv6 is disabled through the kernel command
line even when the distribution kernel has IPv6 compiled in. Custom kernels
with all required drivers built in need no module list.

## Building with eBPF auditing

The prepared Alpine kernel already has BPF syscalls, tracepoints and BTF. Add a
static PID 1 collector and its CO-RE object with:

```sh
python3 guest/prepare-agent-image.py --arch aarch64 --with-audit \
  --cc 'zig cc -target aarch64-linux-musl' \
  --bpf-clang /opt/homebrew/opt/llvm/bin/clang
# Native Linux: use --cc cc with a musl toolchain and --bpf-clang clang.
# x86 guest: --arch x86_64 --cc 'zig cc -target x86_64-linux-musl'.
```

Clang must include the `bpfel` target. `llvm-objcopy` is found next to Clang, or
can be selected with `--llvm-objcopy`. The assembler downloads verified Alpine
musl/Linux headers and static libbpf, libelf, zlib and zstd build packages into
separate staging. They are not added to the guest runtime. It isolates libelf's
private CRC symbol before static linking, and supplies the GCC atomic helper
needed by Alpine's aarch64 library when using Zig. The manifest records build
package versions and hashes, the compiler commands, source hashes, and runner/BPF object hashes. `--with-audit` builds its
own runner and cannot be combined with `--runner`.

For a custom kernel, use:

```sh
guest/build-kernel.sh aarch64 /path/to/linux-source assets/aarch64 --with-audit
```

This enables BPF syscalls/JIT, tracing, perf events, DWARF/BTF and disabled-by-
default unprivileged BPF. BTF generation requires a compatible `pahole` in the
Linux kernel build environment. BPF LSM enforcement is not enabled. Include
`/etc/qbox/audit.bpf.o` from the prepared rootfs when assembling a custom agent
image. The minimal `initramfs.img` intentionally omits the object and refuses
an audit request; use `agents.img` for audited agent sessions.

Run the real audit checks with:

```sh
python3 tests/audit_integration.py --qbox build/qbox --assets assets/aarch64
python3 tests/agent_integration.py --qbox build/qbox --assets assets/aarch64 --audit --agent-ui
python3 tests/audit_integration.py --qbox build/qbox --assets assets/aarch64 \
  --payload-mode initrd --network-host example.com
```

OpenCode is included as the official musl release, pinned by `--opencode-version`
(default `v1.18.34`). The aarch64 image uses the arm64 build; x86_64 uses the
baseline x64 build for CPU compatibility. Its published GitHub SHA256 digest is
verified and recorded alongside the selected version in the image manifest.
The binary is installed under `/opt/opencode` with a launcher in
`/usr/local/bin`; see [OpenCode usage](../docs/agents.md#opencode).
