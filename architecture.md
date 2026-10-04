# QBox architecture

QBox runs one command and its children in a disposable Linux VM. The host
launcher owns the VM's lifetime, terminal connection, network capabilities,
and workspace synchronization. Agents such as Claude Code, Codex, and OpenCode are ordinary
Linux programs inside that VM.

The diagrams use Mermaid and render in GitHub and other Mermaid-enabled Markdown
viewers. They describe the current implementation.

## Components and boundaries

```mermaid
flowchart TB
    user["User terminal or automation"]
    remote["Public provider APIs and other allowed services"]

    subgraph host["Host: macOS, Windows, or Linux"]
        project["Host project"]
        launcher["qbox launcher"]
        temp["Private per-run directory<br/>snapshot, payload, token, lease, logs"]
        connector["qbox-connector<br/>DNS and public-address validation"]

        subgraph qemu["QEMU host process"]
            channel["Virtio-serial backend"]
            network["Restricted user-mode networking<br/>explicit TCP guestfwd entries"]

            subgraph vm["Disposable Linux guest"]
                runner["/init: runnerd<br/>root supervisor, PID 1"]
                agent["Agent or program and its children<br/>UID/GID 65534"]
                files["Temporary workspace and home<br/>/workspace and /home/agent"]
                tools["Installed Linux agents, tools, libraries"]
                local["Guest-local services<br/>loopback inside the VM"]
                runner -->|"pipes or PTY"| agent
                agent -->|"read and edit"| files
                tools -->|"execute"| agent
                agent <-->|"local IPC or HTTP"| local
            end

            channel <-->|"framed control and data"| runner
            agent -->|"outbound TCP traffic"| network
        end

        project -->|"snapshot"| launcher
        launcher -->|"validated writeback"| project
        launcher -->|"stage and clean up"| temp
        launcher -->|"launch and terminate"| qemu
        launcher <-->|"private local connection"| channel
        temp -->|"boot payload"| runner
        network -->|"spawn helper for allowed endpoint"| connector
    end

    user <-->|"arguments, stdin, output, exit status"| launcher
    connector <-->|"validated public TCP connection"| remote
```

The guest receives a copy of the project. Its edits reach the host through the
launcher’s writeback code. Boot-time 9P is read-only and unmounted before the
command runs; the alternative initrd payload is consumed and deleted.

The host launcher runs with ordinary user privileges. QEMU and the guest kernel
provide the VM boundary. Inside the guest, the root supervisor keeps the control
device and authentication token away from the unprivileged command. The agent
may use its own Linux sandbox, such as Codex's bubblewrap, within this boundary.

## Optional trusted guest audit

```mermaid
flowchart LR
    flag["--audit-log PATH"] --> launcher["Host launcher"]
    launcher -->|"audit boot marker"| runner["runnerd / PID 1"]
    runner -->|"attach before agent launch"| bpf["CO-RE BPF programs<br/>fork, exec, exit, IP connect"]
    agent["Agent descendants<br/>including nested namespaces"] -->|"kernel events"| bpf
    bpf --> ring["Bounded ring buffer"]
    ring --> collector["Collector inside PID 1"]
    collector -->|"audit frames"| launcher
    launcher -->|"validated metadata"| log["Private host JSONL<br/>outside workspace"]
    failure["Event loss or log failure"] -->|"SIGTERM, export grace, status 125"| runner
```

Auditing is explicitly requested per session. The audited image contains a
static libbpf collector and `/etc/qbox/audit.bpf.o`; the kernel supplies BTF and
tracing support. Audit readiness is checked after token authentication and
before command/environment delivery. A launch barrier registers the initial
agent before execution; fork tracing follows its descendants by initial guest
namespace task IDs, independent of their current UID or namespace.

The collector lives inside PID 1 and survives `kill(-1)` cleanup. It detaches
and drains after descendants are reaped, then sends completion metadata before
EXIT. The host writes a bounded, private JSONL log and still applies workspace
exports after an audit failure. Arguments, environment and payload bytes are
omitted. QEMU and the host connector enforce network policy; these probes only
observe process lifecycle and IP connection attempts. No BPF privileges are
given to agents.

## Preparing the images

```mermaid
flowchart LR
    sources["Guest C sources"] --> compiler["Static Linux compiler<br/>native or cross compiler"]
    compiler --> runner["runnerd"]

    alpine["Alpine HTTPS repositories<br/>package indexes, userspace, virtual kernel"]
    providers["Official provider releases<br/>Codex package, Claude and OpenCode binaries"]
    alpine --> prepare["prepare-agent-image.py"]
    providers --> prepare
    prepare --> root["Prepared Linux root tree<br/>tools, libraries, CA bundle, selected modules"]
    prepare --> kernel["vmlinuz and kernel.config"]
    prepare --> manifest["agents-manifest.json<br/>versions, URLs, hashes"]

    root --> builder["make_initramfs.py"]
    runner --> builder
    builder --> full["agents.img<br/>supervisor and agent userspace"]
    root --> subset["Boot subset<br/>selected modules and root-transition marker"]
    subset --> smallbuilder["make_initramfs.py<br/>separate minimal-image build"]
    runner --> smallbuilder
    smallbuilder --> minimal["initramfs.img<br/>supervisor and required boot modules"]
```

The assembler checks APK control/data checksums against the downloaded index
and provider binaries against published SHA256 digests. Index trust comes from
HTTPS; independent Alpine signing-key verification is not implemented. Downloads
and generated artifacts stay in ignored `build/` and `assets/` directories.

The image determines which project tools agents can use. Host-installed tools
are not exposed inside the VM. `--with-build-tools` adds C/C++ compilers, headers,
Make, CMake, and Ninja; repeatable `--package NAME` options include additional
Alpine dependencies before the root tree is packed.

The prepared image uses a tmpfs root so bubblewrap can pivot roots and create
user namespaces. PID 1 copies the initial filesystem, releases its old files,
and moves the new mount to `/`. It then mounts proc/sys/dev and loads the trusted
module list needed by the distribution kernel. Custom kernels with built-in
drivers can omit the module list. The root transition remains necessary for
image tools that need to pivot roots or create unprivileged user namespaces.

Codex is packaged under `/opt/codex`, including its server and helpers. Claude
Code, the Codex link, and the OpenCode launcher are available through `/usr/local/bin`.
OpenCode uses a pinned musl binary under `/opt/opencode`; its launcher disables
updates and model-catalog downloads by default, and directs native-library
extraction to a temporary directory in the disposable home. Guest loopback is enabled for
local agent services, with no host port exposure. Guest account
homes and credentials are created at runtime rather than packaged in the image.

## Boot and execution

```mermaid
sequenceDiagram
    actor User
    participant L as Host launcher
    participant P as Host project
    participant Q as QEMU
    participant R as Guest runnerd, PID 1
    participant A as Guest command

    User->>L: qbox agent --workspace DIR -- command args
    L->>P: Snapshot included files and save baseline
    L->>L: Stage payload, random token, hosts map, lease
    L->>Q: Launch kernel, image, devices, restricted network
    Q->>R: Boot /init
    R->>R: Prepare root, devices, network, workspace and home
    R->>R: Unmount or delete payload, then read and unlink token
    R->>L: READY(token) through virtio-serial
    L->>L: Verify token before transmitting execution request
    L->>R: EXEC_AGENT(argv, selected environment, terminal settings)
    R->>A: Execute as UID/GID 65534 in /workspace

    loop While command runs
        L->>R: STDIN, SIGNAL, or RESIZE
        R->>A: Relay input and controls
        A->>R: Output
        R->>L: STDOUT and STDERR frames
        L->>User: Output
    end

    A->>R: Exit or signal
    R->>R: Stop remaining guest processes and drain output
    R->>L: WORKSPACE_DATA, WORKSPACE_DONE, EXIT
    L->>L: Validate archive and preflight host conflicts
    L->>P: Apply changes when preflight succeeds
    L->>Q: Destroy VM
    L->>L: Remove lease and temporary state
    L->>User: Guest status, or launcher failure 125
```

`qbox run` follows the same lifecycle but stages a host-supplied Linux ELF,
sends `EXEC`, and skips workspace snapshot/export. `qbox agent` executes an
installed guest command and sends `EXEC_AGENT`. Agent mode defaults to 4 GiB RAM
and a one-hour timeout; ordinary run mode defaults to 256 MiB and five minutes.

The control connection is a private Unix socket on POSIX or authenticated
loopback TCP on Windows. QEMU connects to the host listener and bridges it to
`qbox.runner` virtio-serial. Frames are binary with a one-byte type, four-byte
length, and a maximum 1 MiB payload. Token verification identifies the expected
runner; the local transport is not an encrypted protocol.

## Headless and interactive I/O

```mermaid
flowchart LR
    subgraph headless["Headless job"]
        input["Host stdin"] --> stdinframe["STDIN frames"] --> pipein["Guest stdin pipe"]
        pipeout["Guest stdout pipe"] --> stdoutframe["STDOUT frames"] --> stdout["Host stdout"]
        pipeerr["Guest stderr pipe"] --> stderrframe["STDERR frames"] --> stderr["Host stderr"]
    end

    subgraph interactive["Interactive session: --tty"]
        terminal["Host terminal in raw mode"] <-->|"STDIN and STDOUT frames"| pty["Guest controlling PTY"]
        terminal -->|"RESIZE frames"| size["Guest PTY dimensions"]
        pty <-->|"stdin, stdout, stderr"| cli["Agent CLI"]
    end
```

Headless output streams stay separate and preserve binary data. A PTY combines
stdout/stderr and lets the agent use terminal controls. Ctrl-C is forwarded to
the guest terminal in interactive mode; Ctrl-] asks QBox to terminate the session
with SIGTERM and allows up to 30 seconds for shutdown/export. Terminal settings
are restored when the launcher exits.

Only variables named by `--env NAME` are forwarded alongside the guest's fixed
environment. Credentials travel in the execution frame, not QEMU arguments.
The private guest home disappears when the VM is destroyed.

## Outbound network capabilities

For example, `--allow api.openai.com:443` creates a synthetic address such as
`10.0.2.100` and a forwarding entry for that address and port.

```mermaid
flowchart TD
    request["Agent connects to hostname and port"]
    hosts["Guest /etc/hosts<br/>hostname maps to synthetic IPv4"]
    match{"Matches an explicit<br/>guestfwd address and port?"}
    deny["No authorized forwarding path"]
    helper["Host qbox-connector<br/>fixed destination hostname and port"]
    dns["Resolve hostname once for this connection"]
    policy{"Resolved sockaddr is public<br/>and allowed by address policy?"}
    reject["Reject address"]
    connect["Connect to that exact validated sockaddr<br/>try another validated answer on failure"]
    relay["Relay TCP bytes<br/>TLS stays between guest and remote service"]

    request --> hosts --> match
    match -->|"No"| deny
    match -->|"Yes"| helper --> dns --> policy
    policy -->|"No"| reject
    policy -->|"Yes"| connect --> relay
```

QEMU uses `restrict=on`; the guest cannot widen the host's forwarding rules.
The connector resolves afresh for each connection, rejects private/loopback/
link-local and other special addresses, and connects to the exact sockaddr it
checked. It does not resolve the name again between validation and connection.
Allowed hostnames do not authorize redirects to other names or different ports.

There is no general guest DNS service or inbound forwarding. IPv6 is disabled
in the guest, while the connector can reach validated public IPv6 endpoints.
Numeric destinations must use their assigned synthetic IPv4 address. Helpers
watch a per-run lease file and stop when the launcher removes it during cleanup.

## Workspace writeback

```mermaid
flowchart TD
    snapshot["Host project snapshot<br/>included paths and original contents"]
    guest["Guest /workspace<br/>private writable copy"]
    result["Complete returned archive<br/>after command exit"]
    validate["Validate size, entries, paths, symlinks<br/>and excluded-directory protection"]
    diff["Compare returned tree with launch baseline"]
    changed{"Agent changed this path?"}
    preserve["Leave current host path untouched"]
    conflict{"Current host path still matches baseline<br/>or an identical new result?"}
    retained["Reject writeback before applying changes<br/>retain archive and baseline; return 125"]
    apply["After all paths pass preflight:<br/>remove deleted entries, create directories,<br/>stage and replace changed files"]

    snapshot --> guest --> result --> validate --> diff --> changed
    snapshot -.->|"baseline"| diff
    changed -->|"No"| preserve
    changed -->|"Yes"| conflict
    conflict -->|"No"| retained
    conflict -->|"Yes, for the entire change set"| apply
```

`.git`, `.qbox-results`, and `.DS_Store` are excluded by default; `--exclude`
adds top-level names. Snapshot and export each default to a 512 MiB limit.
Archives support directories, regular files, and contained relative symlinks;
symlink targets containing `..` are rejected. Host and guest validate archives
independently. The host also checks that writeback does not follow symlink parents.

Writeback happens after complete export, including nonzero command exits.
Concurrent host edits to untouched paths survive. Conflicting edits prevent
preflight from succeeding and leave recoverable private temporary state.
Replacement is atomic per file, not across the project; concurrent changes or
I/O failures during application can leave some edits applied. A VM crash or
forced termination before export can lose guest edits.

## Platforms and implementation map

| Concern | Implementation |
|---|---|
| CLI parsing, resource limits, capability mapping, QEMU arguments | [src/config.cpp](src/config.cpp) |
| VM lifecycle, authentication, frame relay, writeback orchestration | [src/launcher.cpp](src/launcher.cpp) |
| Processes, private directories, sockets, OS cleanup | [src/platform.cpp](src/platform.cpp) |
| TCP connector and public-address connection policy | [src/connector.cpp](src/connector.cpp), [src/connect_policy.hpp](src/connect_policy.hpp) |
| Frame format and execution environment | [src/protocol.cpp](src/protocol.cpp), [docs/protocol.md](docs/protocol.md) |
| Host snapshot, archive validation, conflict checks, file replacement | [src/workspace.cpp](src/workspace.cpp) |
| Host terminal handling and initrd payload injection | [src/terminal.cpp](src/terminal.cpp), [src/payload.cpp](src/payload.cpp) |
| Trusted eBPF collector and probes | [guest/audit.c](guest/audit.c), [guest/audit.bpf.c](guest/audit.bpf.c) |
| Host audit validation and JSONL output | [src/audit.cpp](src/audit.cpp) |
| Guest boot, process supervision, pipes/PTY, export relay | [guest/runnerd.c](guest/runnerd.c) |
| Guest archive import/export and root transition | [guest/workspace.c](guest/workspace.c), [guest/rootfs.c](guest/rootfs.c) |
| Kernel/userspace preparation and deterministic image packing | [guest/prepare-agent-image.py](guest/prepare-agent-image.py), [guest/make_initramfs.py](guest/make_initramfs.py) |

macOS uses HVF, Windows uses WHPX, and Linux uses KVM in automatic mode, with a
TCG retry if the first QEMU process exits before connecting. POSIX supports the
read-only 9P boot payload; Windows uses initrd injection because its QEMU build
lacks the local 9P backend. POSIX cleanup uses a process group; Windows uses a
kill-on-close Job Object. Both paths remove the connector lease.

QBox remains an MVP. QEMU, the kernel, device implementations, trusted images,
and the host connector are part of its trusted computing base. Real macOS VM
tests cover CLI startup, interactive setup screens, PTYs, network policy, nested
sandboxing, and writeback. Authenticated model inference and real Windows
execution remain separate validation steps. See [platform validation](docs/platforms.md)
for details and [agent setup](docs/agents.md) for commands.
