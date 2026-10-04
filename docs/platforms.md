# Platform and QEMU validation

QEMU command-line targets: 8.2.x and 11.1.2 (locally tested on Apple Silicon
macOS). Other releases require revalidation.
The prepared Alpine image currently resolves kernel 6.12.111-r0 from Alpine 3.22.
The build does not silently download or pin an executable. QEMU's current
[invocation documentation](https://www.qemu.org/docs/master/system/invocation.html)
was checked for restricted user networking, guestfwd, socket chardev, and 9P.
The [libslirp spawning implementation](https://gitlab.freedesktop.org/slirp/libslirp/-/blob/master/src/misc.c)
parses command arguments with `g_shell_parse_argv` and spawns with GLib. QBox
quotes the connector path as a GLib token, validates the destination, and doubles
commas for the outer QEMU option parser. No command shell is invoked by QBox.

| Host | Guest | Default accelerator | Control socket |
|---|---|---|---|
| macOS Apple Silicon | aarch64 | HVF | private Unix socket |
| macOS Intel | x86_64 | HVF | private Unix socket |
| Windows x86_64 | x86_64 | WHPX | authenticated loopback TCP |
| Linux (development) | native | KVM | private Unix socket |

Use `--accel tcg` to force emulation. Automatic selection tries the platform
accelerator, then retries with TCG if QEMU exits before opening the control channel.
The WHPX profile uses `qemu64`, since QEMU's x86 `host` CPU requires KVM or HVF.
Windows payload injection uses a concatenated newc archive in a per-run initramfs;
the [QEMU build configuration](https://github.com/qemu/qemu/blob/master/fsdev/meson.build)
does not provide its local 9P backend on Windows. Linux supports
[concatenated initramfs archives](https://docs.kernel.org/driver-api/early-userspace/buffer-format.html).
On Windows,
enabling Windows Hypervisor Platform is a one-time host setup requirement; normal
launch is unprivileged. QEMU processes and their descendants are assigned to a
kill-on-close Windows Job Object. POSIX QEMU is spawned in its own process group.
Connectors watch a private per-run lease file, which the launcher removes during
cleanup; this also terminates helpers waiting in DNS/connect work. On macOS a trusted user
temp directory is created mode 0700; Windows relies on the user temp directory's
inherited ACL and per-run random names. Shared/public Windows temp directories
are not an appropriate deployment configuration.

On 2026-10-04, the real QEMU integration suite passed on Apple Silicon macOS with
QEMU 11.1.2 and the Alpine virtual kernel. It covers binary I/O, exit status,
output, crashes, timeout/cancellation, VM cleanup, allowed public networking,
wrong-port/other-host denial, and private-DNS rejection. The real agent-image
suite verifies Codex CLI 0.160.0, Claude Code 2.1.285, and OpenCode 1.18.34
startup, project writeback,
ephemeral home/isolation, nested bubblewrap namespaces, HTTPS trust, and host/guest
PTY input and resize. The agents' interactive startup screens also open and
terminate cleanly. Automatic acceleration and both 9P/initrd payload paths
are exercised. These tests do not perform authenticated model inference; no
provider API-key variables were available in the session.
The minimal suite also passes with TCG and initrd payload injection.

A checksum-verified local Zig 0.15.2 compiler builds the static aarch64 and
x86_64 Linux runners, initramfs images and fixtures. All Windows backend
translation units have been cross-compiled, and
both Windows executables linked successfully, without executing them on Windows.
Build and test commands are documented in the README and guest instructions.
The repository does not include GitHub Actions workflows.

Release qualification still requires real Windows WHPX execution, authenticated
provider tasks, connector path quoting tests (spaces, Unicode, commas), repeated
cleanup checks during DNS/connect operations, and the P0 acceptance matrix.

Optional eBPF auditing has been exercised in real aarch64/HVF and x86_64/TCG
VMs with the prepared Alpine kernel. Checks cover namespace descendants,
permitted/denied connects, blocked agent BPF access, private metadata logs,
log-write failure, and graceful workspace export. The aarch64 tests also force
ring-buffer loss through host backpressure. Both 9P and initrd payloads and
interactive agent setup/PTY sessions have audit coverage. Windows audit output
cross-compiles and links; its runtime ACL behavior remains unverified on Windows.
The custom kernel build profile is provided but has not been built here.

OpenCode is packaged from checksum-verified musl releases for aarch64 and
baseline x86_64. Its disposable-home temporary directory permits native OpenTUI
library extraction while `/tmp` remains mounted with execution disabled.
Guest-local loopback is enabled for agent services without exposing host ports.
The headless OpenCode test passes on aarch64/HVF and x86_64/TCG with audit
logging; aarch64 also covers initrd payloads. It exercises a streamed tool call
and host writeback against a fake provider inside the guest; this does not validate authenticated
execution against a real model provider.
