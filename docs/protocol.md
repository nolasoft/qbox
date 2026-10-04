# Runner protocol, version 1

Transport: virtio-serial named `qbox.runner`, connected to a private Unix socket
on POSIX or a loopback TCP listener on Windows. QEMU is the host socket client.
Each frame is `type:u8`, `length:u32be`, then exactly `length` bytes. Maximum
payload is 1,048,576 bytes. All data is binary; no Unicode decoding occurs.

| Type | Name | Payload |
|---|---|---|
| 1 | EXEC | argv vector followed by environment vector |
| 2 | STDIN | raw bytes; zero length closes stdin after pending bytes drain |
| 3 | STDOUT | raw bytes |
| 4 | STDERR | raw bytes |
| 5 | EXIT | kind:u32be (0 exit, 1 signal), value:u32be |
| 6 | SIGNAL | Linux signal:u32be; only 2, 15, 9 accepted |
| 7 | READY | 64 ASCII hex bytes of the per-run authentication token |
| 8 | EXEC_AGENT | flags:u32be (0 pipes, 1 PTY), rows:u32be, columns:u32be, then EXEC vectors |
| 9 | WORKSPACE_DATA | next bytes of the returned workspace archive |
| 10 | WORKSPACE_DONE | status:u32be (0 complete, 1 export failed) |
| 11 | RESIZE | rows:u32be, columns:u32be; PTY only, 1–1000 each |
| 12 | AUDIT_EVENT | fixed 336-byte little-endian metadata record |
| 13 | AUDIT_DONE | failed:u32be, sent_events:u64be, lost_events:u64be |
| 14 | AUDIT_READY | failed:u32be; optional bounded startup diagnostic on failure |

Each EXEC vector is `count:u32be`, then repeated `length:u32be, bytes[length]`.
There are at most 256 elements per vector, embedded NULs are rejected, argv is
nonempty, and environment entries must contain `=` after a nonempty name.
The launcher supplies PATH, HOME, LANG and SSL_CERT_FILE, without host secrets.
Arguments preserve whitespace and empty elements.

READY is sent after guest boot initialization and 9P unmount. The token is copied
from the protected payload and removed from guest storage before executing the
child. The host verifies it before transmitting EXEC. The child cannot open the
root-owned virtio-serial device or inherit runner control/pipe descriptors.
The runner accepts one EXEC and one stdin EOF per run. Invalid frames close the
channel and kill the child process group. Child stdout/stderr are drained before
EXIT; descendants in the child's process group are killed when the child exits.
PID 1 stays alive after EXIT until the host destroys QEMU.

Agent execution requires an agent boot payload; EXEC and EXEC_AGENT cannot be
substituted between modes. Agent defaults include HOME=/home/agent,
TMPDIR=/tmp and TERM=xterm-256color; explicitly selected environment variables
are appended. After child exit, guest PID 1 kills/reaps remaining processes
before exporting the workspace. WORKSPACE_DATA and WORKSPACE_DONE precede EXIT;
the host validates/applies the complete export before returning the guest code.
PTY output uses STDOUT only. Empty STDIN sends EOT before closing its input
descriptor in PTY mode; RESIZE changes the guest terminal dimensions.

Workspace archives start with `QBWS0001`. Each record is kind:u8 (1 directory,
2 regular file, 3 symlink), mode:u32be, path_length:u32be, content_length:u64be,
then path and content bytes. Directories have no content; symlinks contain their
relative targets. A 17-byte zero record terminates the archive with no trailing
data. Parents precede their children. Paths are workspace-relative, cannot
traverse symlink parents, and are validated independently on both sides.

## Opt-in audit extension

An agent payload containing `audit` requests auditing. After authenticated READY,
the host waits for AUDIT_READY before sending EXEC_AGENT. Success has exactly
four zero bytes; failure has status 1 and up to 8,192 diagnostic bytes. An image
without audit support refuses the request. Sessions without the marker emit no
audit frames and retain the existing handshake.

AUDIT_EVENT matches `guest/audit_event.h`: timestamp:u64le (guest monotonic ns),
then type, TID, TGID, parent TID, initial-namespace UID, Linux address family,
port, signed result, and truncation flag (each 32 bits little-endian); followed
by NUL-terminated comm[16], executable[256], address[16], reserved:u32le (zero).
Types are 1 fork, 2 successful exec, 3 exit, 4 IP connect attempt, 5 connect
result. Addresses are network byte order; family is 2 or 10. Process exit
results are raw Linux wait status; connect results are syscall return values.
Fork comm/UID describe the creating task; the root launch record has UID 0
because it is created before the privilege drop. Paths are the successful exec
filename, not resolved canonical paths. Truncation applies to the exec filename.

The collector drains bounded batches independently of terminal data. After all
agent descendants are killed and reaped, PID 1 detaches probes, drains remaining
events and sends AUDIT_DONE before EXIT. Detected loss stops the agent with
SIGTERM, then SIGKILL after 30 seconds if needed, and marks the audit incomplete.
The host also requests graceful termination on invalid events or log-write
failure, consumes the workspace export, and returns infrastructure status 125.
Logs are encoded and validated by the host; audit bytes never enter stdout or
stderr. Older runners that ignore the marker fail the readiness check before
receiving the command or its environment.
