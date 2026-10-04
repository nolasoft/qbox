# Coding agents in QBox

Agent mode runs a command installed in the Linux guest, with `/workspace` as its
working directory. It supports headless jobs and interactive PTY sessions. Each
session gets a disposable home directory; when the command exits, QBox returns
the workspace and automatically applies its changes to the host project.

## Prepare an agent image

The included assembler supplies an Alpine userspace with Codex, Claude Code, OpenCode,
Bash, Git, ripgrep, curl, Node/npm, Python, bubblewrap, process utilities, and CA certificates:

```sh
# Requires an existing static assets/aarch64/runnerd; see guest/README.md.
python3 guest/prepare-agent-image.py --arch aarch64
```

It also obtains a compatible kernel and builds the minimal image. Artifacts
stay in `assets/aarch64` and are ignored by Git. The generated provenance manifest
records exact package/agent versions and input hashes. Add project compilers or
dependencies using the [guest tooling options](#guest-project-tools), or prepare
a customized rootfs.

Codex is installed as its complete standalone package under `/opt/codex`, with
a `/usr/local/bin/codex` link. Its background server and bundled helpers are
included; copying only the `codex` executable is insufficient for this release's
interactive mode.

For a custom image:

Build `runnerd` and a kernel as described in [guest/README.md](../guest/README.md).
Prepare a clean Linux userspace tree for the chosen architecture. It needs the
agent CLI, its dynamic loader/libraries, a CA certificate bundle, Bash, Git,
ripgrep, and whichever project tools the agent will invoke. Include Node,
Python, compilers, package managers, or MCP dependencies as required by your
project. QBox does not install or download these tools at session startup.

Install agents into `/usr/local/bin` or `/usr/bin`, including the files their
launchers reference. User-specific installations under `/root` or `/home` are
excluded from images. Use the providers' supported Linux installation procedures
inside your image-building environment:
[Claude Code setup](https://code.claude.com/docs/en/setup) and
[Codex CLI](https://developers.openai.com/codex/cli).

```sh
guest/build-initramfs.sh --runner assets/aarch64/runnerd --arch aarch64 \
  --rootfs /path/to/prepared-linux-rootfs \
  --ca-bundle /path/to/ca-certificates.crt \
  --output assets/aarch64/agents.img
```

Choose `x86_64` for an x86 guest. Agent mode defaults to 4096 MiB memory,
a one-hour timeout, and a two-minute boot deadline. Increase `--memory` for
large images or projects: the unpacked image, workspace, and agent processes
share guest RAM. The image is trusted build input; avoid packaging secrets or
unneeded services. QBox replaces the normal init system with its own runner.

## Guest project tools

Host dependencies build and run QBox; guest dependencies build and run your
project. Installing CMake or a compiler on macOS/Windows does not install it in
the Linux VM. The default agent image includes the agent CLIs and basic tools,
but C/C++ build tools must be explicitly added when preparing the image:

```sh
python3 guest/prepare-agent-image.py --arch aarch64 --with-build-tools
# Include more Alpine packages and their dependencies:
python3 guest/prepare-agent-image.py --arch aarch64 --with-build-tools \
  --package pkgconf --package openssl-dev
```

`--with-build-tools` adds Alpine `build-base`, `cmake`, and `ninja`: GCC/G++,
Make, binutils, Linux/musl development headers, CMake, and Ninja. Repeat
`--package NAME` for other available Alpine packages. These flags also work
with `--with-audit`. Rebuild before launching the next session; already running
VMs continue using their original image. The provenance manifest records all
resolved package versions. Additional packages follow the assembler's existing
rules: maintainer scripts are skipped, so packages needing service setup or
post-install actions may require a custom rootfs.

The guest is Linux with musl, regardless of your host OS. Provide compatible
libraries, language runtimes, test tools, and Linux dependencies for the
project. Avoid copying host `node_modules`, virtual environments, or compiled
binaries into the guest. System directories are read-only and the agent is
unprivileged, so prepare system packages in the image rather than attempting
`sudo` or `apk add` during a session. Workspace-level dependency downloads need
explicit registry/network capabilities. Larger images share the session's RAM
with project builds; increase `--memory` when needed.

## Optional eBPF audit

Build an auditable image using the instructions in
[guest/README.md](../guest/README.md#building-with-ebpf-auditing), then choose a
new log path outside the host project:

```sh
build/qbox agent --workspace "$PWD" \
  --kernel assets/aarch64/vmlinuz --initrd assets/aarch64/agents.img \
  --audit-log /tmp/qbox-session.jsonl -- bash -c 'git status; echo done'
```

`--audit-log` works with headless and PTY sessions. It creates a private JSONL
file (0600 on POSIX, an owner-only DACL on Windows), refuses existing files,
and requires an existing parent directory. Each log starts with a versioned
session record and ends with a completion record. A complete audit preserves
the command's exit status. Missing or false `complete` means the audit is
incomplete; failed auditing returns 125 even if the command exits successfully.
A write failure can leave a truncated final line.

Metadata includes process creation, successful exec filenames, process exits,
and IPv4/IPv6 `connect()` attempts/results from the agent and its descendants,
including nested namespaces. Arguments, environment values, file contents and
network payloads are omitted. Executable paths and process names can still
contain sensitive metadata. Filenames are bounded and marked if truncated;
non-ASCII bytes are escaped individually to preserve byte values in JSON.

The log limit is 64 MiB, including completion metadata. Startup failures prevent
command launch. Detected event loss, capacity exhaustion, collector failure or
host log-write failure requests shutdown with the existing 30-second export
grace period. Returned workspace edits still pass the normal conflict checks.
Forced teardown may lose edits. Partial audit logs remain at the requested path.

Auditing observes IP `connect()` calls; it does not cover file accesses,
unconnected UDP sends, every packet, or failed exec attempts. A successful guest
connect does not prove that the host connector permitted or completed an
upstream connection. The existing QEMU/connector policy remains authoritative.
Only PID 1 can operate the monitor; agents receive no BPF capabilities or file
descriptors, and unprivileged BPF loading is locked off for audited sessions.

## Headless jobs

Explicitly forward credentials by variable name. Values are sent through the
authenticated runner channel rather than placed in QEMU arguments. Set the
variables in your shell beforehand; these examples do not store them in images.

```sh
build/qbox agent --workspace "$PWD" \
  --kernel assets/aarch64/vmlinuz --initrd assets/aarch64/agents.img \
  --env CODEX_API_KEY --allow api.openai.com:443 \
  -- codex exec --skip-git-repo-check --sandbox workspace-write \
  "Implement the requested change and run the relevant tests"

build/qbox agent --workspace "$PWD" \
  --kernel assets/aarch64/vmlinuz --initrd assets/aarch64/agents.img \
  --env ANTHROPIC_API_KEY --allow api.anthropic.com:443 \
  -- claude -p "Implement the requested change and run the relevant tests" \
  --allowedTools "Read,Edit,Write,Bash"
```

Agent permissions still apply inside the VM. Configure them for the tools your
job needs. See [Codex noninteractive mode](https://developers.openai.com/codex/noninteractive)
and [Claude headless mode](https://code.claude.com/docs/en/headless).
`CODEX_API_KEY` is intended for Codex noninteractive execution. The host `.git`
directory is excluded, so Codex exec uses `--skip-git-repo-check`. Git history
and host Git configuration are unavailable; an agent may initialize a temporary
guest repository, whose `.git` directory is also excluded from writeback.

## Interactive sessions

```sh
build/qbox agent --workspace "$PWD" --tty \
  --kernel assets/aarch64/vmlinuz --initrd assets/aarch64/agents.img \
  --env ANTHROPIC_API_KEY --allow api.anthropic.com:443 -- claude
```

`--tty` requires a host terminal and gives the guest a controlling PTY. Terminal
dimensions propagate on resize; stdout and stderr share the PTY stream. Ctrl-C
goes to the guest terminal. Ctrl-] requests session termination with SIGTERM and
allows up to 30 seconds for shutdown/export. Exit the agent normally to retain
edits reliably. Without `--tty`, stdout and stderr remain separate byte streams.

Interactive Codex can log in inside the disposable guest using its supported
login flow, or through explicit credentials appropriate to that flow. Account
login needs additional auth destinations beyond the model API. Consult
[Codex authentication](https://developers.openai.com/codex/auth) and
[Claude network configuration](https://code.claude.com/docs/en/network-config).
Login state and agent home-directory history disappear when the VM closes.
QBox does not import host account credentials or expose a browser callback port.

### Copy and paste

Use your **host terminal's** Paste command to insert text into the guest:
Cmd+V on macOS, usually Ctrl+Shift+V on Linux, or the configured Windows
Terminal paste shortcut. QBox relays terminal text and bracketed-paste escape
sequences. OpenCode's Ctrl+V shortcut can try to read the guest's own clipboard,
which has no connection to your desktop clipboard. Image clipboard contents
and host file paths are not automatically imported into the guest.

For copying, select text using the host terminal's selection mode and use its
Copy command. When OpenCode captures mouse input, use your terminal's modifier
to override mouse reporting (commonly Option on macOS terminals or Shift on
Linux/Windows terminals), or its selection menu. OpenCode's own “Copied” toast
does not confirm that your host clipboard changed: guest-local clipboard tools
cannot access your desktop, and OSC 52 clipboard writes depend on support and
settings in the host terminal. QBox relays those sequences but does not operate
a host clipboard broker or read the host clipboard. See
[OpenCode clipboard troubleshooting](https://opencode.ai/docs/troubleshooting/#copypaste-not-working-on-linux).

In Apple Terminal, use terminal selection followed by Cmd+C, and Cmd+V to
paste. Option-drag selects a rectangular block independently of the agent's
selection; see [Apple's terminal shortcuts](https://support.apple.com/guide/terminal/trmlshtcts/mac).
OpenCode's OSC 52 copy sequence is not supported by Apple Terminal, so its
“Copied” notification can leave the Mac clipboard unchanged. For the agent's
own copy action, use an OSC 52-capable terminal such as iTerm2 or Ghostty with
clipboard writes permitted; see [iTerm2 clipboard support](https://iterm2.com/documentation-escape-codes.html)
and [Ghostty OSC 52 support](https://ghostty.org/docs/vt/osc/52).

## OpenCode

Prepared images include OpenCode for both guest architectures. Pin another
release using `guest/prepare-agent-image.py --opencode-version vVERSION`.
Headless jobs use `opencode run`; interactive sessions use `opencode` with
QBox's `--tty`. See the [OpenCode CLI documentation](https://opencode.ai/docs/cli/).

```sh
build/qbox agent --workspace "$PWD" \
  --kernel assets/aarch64/vmlinuz --initrd assets/aarch64/agents.img \
  --env ANTHROPIC_API_KEY --allow api.anthropic.com:443 \
  -- opencode run --model anthropic/claude-sonnet-4-5 \
  "Implement the requested change and run the relevant tests"

build/qbox agent --workspace "$PWD" --tty \
  --kernel assets/aarch64/vmlinuz --initrd assets/aarch64/agents.img \
  --env ANTHROPIC_API_KEY --allow api.anthropic.com:443 \
  -- opencode --model anthropic/claude-sonnet-4-5
```

Choose the provider/model and explicitly forwarded credential variables your
provider requires. Project `opencode.json` configuration travels with the
workspace. Credentials and history stored under the guest home are disposable;
QBox does not import host OpenCode accounts. OpenCode permissions apply alongside
QBox's VM boundary and network capabilities. Optional plugins, MCP services,
and language servers can require additional installed tools and allowed hosts.
See [providers](https://opencode.ai/docs/providers/) and
[configuration](https://opencode.ai/docs/config/).

The image launcher defaults `OPENCODE_DISABLE_AUTOUPDATE=1` and
`OPENCODE_DISABLE_MODELS_FETCH=1`, using the pinned release and bundled model
catalog without startup downloads. Explicitly forward either variable with
value `0` to enable that behavior, and authorize its required destinations.
These defaults are defined in the
[pinned OpenCode runtime flags](https://github.com/anomalyco/opencode/blob/v1.18.34/packages/core/src/flag/flag.ts).
OpenCode extracts native UI libraries into a private temporary directory under
its disposable home because QBox mounts `/tmp` with execution disabled.
Guest-local loopback supports agent services; it provides no access to host
loopback or incoming host connections. `--audit-log PATH` and automatic workspace
writeback work with OpenCode through the same agent protocol.

## Network and workspace behavior

Outbound networking starts denied. Repeat `--allow hostname:port` for provider,
package-registry, Git, MCP, or other destinations the job actually needs. The
examples authorize only the model API; login, updates, telemetry, dependencies,
and optional features may need more capabilities. Each redirect or secondary
hostname needs its own entry. Localhost and private-network MCP servers are
blocked by the connector's public-address policy. No inbound server exposure
or general DNS service is provided. Disable unwanted agent auto-updates in your
prepared image using the provider's documented settings.

The guest receives a copied workspace, never a writable host filesystem mount.
`.git`, `.qbox-results`, and `.DS_Store` are excluded by default. Add
`--exclude node_modules --exclude .venv` to omit host-specific dependencies,
then provide Linux dependencies in the image or install them inside the guest
with the necessary network capabilities. Exclusions match top-level names.
`--workspace-limit BYTES` limits each snapshot/export, defaulting to 512 MiB.
When the target is this QBox repository, add `--exclude build --exclude assets`
to omit downloaded toolchains and VM images from the workspace snapshot.
Both sides allow at most 100,000 entries. Only directories, regular files, and
relative symlinks that stay inside the workspace are supported.
Symlink targets containing `..` are rejected, including lexically contained
targets, because chained symlinks can turn those into escapes. Ownership,
timestamps, ACLs, extended attributes, and hard-link identity are not preserved.
Paths must also be compatible with Windows filename rules.

Writeback happens after a complete export, including when the agent exits with
a nonzero code or a handled signal. QBox checks the full change set against the
launch snapshot before writing. It preserves host edits to files the agent left
untouched. If both sides changed a file, it returns 125, retains the returned
archive and snapshot in a private temporary directory, and prints their path
for recovery. Excluded files are protected from returned changes.

Files are replaced individually using adjacent staging files. Writeback is not
a transaction across the whole project: an I/O failure or concurrent host
mutation during application can leave some changes applied. Avoid editing the
same project while a session writes back. Forced timeout, output-cap termination,
VM crash, or connection failure before a complete export can lose guest edits.
Unchanged generated dependencies are returned unless excluded; special files or
escaping symlinks make export/writeback fail.

Host and native runner tests exercise dispatch, PTYs, workspace parsing,
automatic writeback, and conflict recovery. Real VM checks also exercise the
prepared image and installed agent CLI startup. Authenticated agent tasks
still need provider credentials or login and a live prompt test.

The opt-in real agent-image suite checks installed CLI versions, UID/workspace
isolation, automatic writeback after nonzero exit, ephemeral home state,
bubblewrap namespaces, network policy, optional HTTPS trust, PTY input/resize,
multiline UTF-8 bracketed paste, and OSC 52 output relay:

```sh
python3 tests/agent_integration.py --qbox build/qbox --assets assets/aarch64 \
  --arch aarch64 --network-host example.com --agent-ui
# Repeat with --payload-mode initrd to exercise embedded-payload injection.
```

`--agent-ui` additionally verifies Codex, Claude Code, and OpenCode interactive startup screens on
POSIX hosts. These tests do not read host account credentials or make model inference calls.
For images prepared with `--with-build-tools`, add `--build-tools` to compile,
run, and write back a CMake C/C++ project using Ninja. Clipboard relay checks
verify bytes crossing the PTY; they do not verify that a graphical terminal
actually changes the desktop clipboard.
An authenticated agent prompt needs explicit credentials or a user login inside
the guest. CLI startup and environment validation are recorded separately from
authenticated provider execution in [platform validation](platforms.md).

The OpenCode headless integration test uses a fake OpenAI-compatible provider
entirely inside the guest. It exercises a streamed Bash tool call, the tool
result, an audit log, and automatic host writeback without real credentials:

```sh
python3 tests/opencode_integration.py --qbox build/qbox --assets assets/aarch64 --audit
# Repeat with --payload-mode initrd, or --arch x86_64 --accel tcg.
```
