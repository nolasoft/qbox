"""Real QEMU agent-image checks. No account credentials or inference calls."""
import argparse
import json
import os
from pathlib import Path
import select
import struct
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--qbox', type=Path, required=True)
p.add_argument('--assets', type=Path, required=True)
p.add_argument('--arch', choices=['aarch64', 'x86_64'], default='aarch64')
p.add_argument('--accel', choices=['auto', 'tcg'], default='auto')
p.add_argument('--payload-mode', choices=['9p', 'initrd'], default='9p')
p.add_argument('--network-host', help='Optional HTTPS endpoint for TLS/network check')
p.add_argument('--audit', action='store_true', help='Require complete eBPF logs for every session')
p.add_argument('--agent-ui', action='store_true', help='Also check all interactive agent startup screens (POSIX host)')
p.add_argument('--build-tools', action='store_true', help='Compile and run a CMake C/C++ project in the guest')
a = p.parse_args()
slow_guest = a.arch == 'x86_64' and a.accel == 'tcg'
vm_timeout = 180 if slow_guest else 90
for name in ('vmlinuz', 'agents.img'):
    if not (a.assets / name).is_file():
        p.error('missing ' + str(a.assets / name))

with tempfile.TemporaryDirectory(prefix='qbox-agent-it-', dir='/tmp' if os.name != 'nt' else None) as directory:
    root = Path(directory)
    project = root / 'project'
    project.mkdir()
    (project / '.git').mkdir()
    (project / '.git/config').write_text('host metadata')
    (project / 'original').write_text('before')
    (project / 'delete').write_text('remove me')
    base = [str(a.qbox.resolve()), 'agent', '--workspace', str(project),
            '--arch', a.arch, '--accel', a.accel, '--payload-mode', a.payload_mode,
            '--kernel', str((a.assets / 'vmlinuz').resolve()),
            '--initrd', str((a.assets / 'agents.img').resolve()), '--timeout', str(vm_timeout)]
    env = dict(os.environ, TMPDIR=directory, TMP=directory, TEMP=directory,
               QBOX_AGENT_SENTINEL='explicit test value')
    audit_number = 0
    def audit_options():
        global audit_number
        if not a.audit: return [], None
        audit_number += 1
        path = root / ('audit-' + str(audit_number) + '.jsonl')
        return ['--audit-log', str(path)], path
    def check_audit(path):
        if path is not None:
            records = [json.loads(line) for line in path.read_text().splitlines()]
            assert records[-1]['complete'], records[-1]
    def run(command, expected=0, options=()):
        audit_args, audit_path = audit_options()
        result = subprocess.run(base + list(options) + audit_args + ['--', *command],
                                input=b'', capture_output=True, env=env, timeout=vm_timeout+10)
        assert result.returncode == expected, (command, result.returncode, result.stderr)
        check_audit(audit_path)
        assert not list(root.glob('qbox-*')), 'temporary VM state leaked'
        return result

    r = run(['bash', '-c', 'set -eu; codex --version; claude --version; opencode --version; git --version; '
             'rg --version | head -1; node --version; npm --version; python3 --version'])
    assert (a.assets / 'agents-manifest.json').is_file()
    manifest = json.loads((a.assets / 'agents-manifest.json').read_text())
    assert manifest['opencode'].removeprefix('v').encode() in r.stdout
    assert b'codex-cli ' in r.stdout and b'(Claude Code)' in r.stdout, r.stdout
    print(r.stdout.decode(), end='', flush=True)
    if a.build_tools:
        sample = project / 'build-tools-check'
        sample.mkdir()
        (sample / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.20)
project(qbox_toolchain_check LANGUAGES C CXX)
add_executable(toolchain-check main.cpp helper.c)
''')
        (sample / 'helper.c').write_text('int answer(void) { return 42; }\n')
        (sample / 'main.cpp').write_text('''#include <iostream>
extern "C" int answer(void);
int main() { std::cout << "guest-build-ok:" << answer() << '\\n'; }
''')
        r = run(['bash', '-c', 'set -eu; cmake --version; c++ --version; make --version; '
                 'cmake -S build-tools-check -B build-tools-check/out -G Ninja; '
                 'cmake --build build-tools-check/out; build-tools-check/out/toolchain-check'])
        assert b'guest-build-ok:42\n' in r.stdout, r.stdout
        assert (sample / 'out/toolchain-check').is_file(), 'compiled binary was not written back'
        print('guest CMake, C/C++, Ninja build and executable writeback verified', flush=True)
    code = """import os
from pathlib import Path
assert os.getcwd() == '/workspace'
assert os.getuid() == 65534
assert os.environ['HOME'] == '/home/agent'
assert os.environ['QBOX_AGENT_SENTINEL'] == 'explicit test value'
assert not Path('.git').exists()
assert not Path('/payload/workspace').exists()
assert not Path('/run/qbox/token').exists()
Path('original').write_text('after')
Path('binary').write_bytes(bytes(range(256)))
Path('delete').unlink()
Path('relative-link').symlink_to('binary')
Path('/home/agent/private-state').write_text('ephemeral')
raise SystemExit(42)
"""
    run(['python3', '-c', code], expected=42, options=['--env', 'QBOX_AGENT_SENTINEL'])
    assert (project / 'original').read_text() == 'after'
    assert (project / 'binary').read_bytes() == bytes(range(256))
    assert not (project / 'delete').exists()
    assert os.readlink(project / 'relative-link') == 'binary'
    assert (project / '.git/config').read_text() == 'host metadata'
    run(['python3', '-c', "from pathlib import Path;assert not Path('/home/agent/private-state').exists()"])
    # Nested Linux namespaces needed by Codex's bubblewrap sandbox.
    r = run(['bwrap', '--unshare-user', '--ro-bind', '/', '/', '--dev', '/dev',
             '--proc', '/proc', '--', 'bash', '-c', 'echo nested-sandbox-ok'])
    assert r.stdout == b'nested-sandbox-ok\n', r.stdout
    r = run(['curl', '--silent', '--connect-timeout', '2', '--max-time', '3',
             'http://1.1.1.1'], expected=7)
    if a.network_host:
        r = run(['curl', '--fail', '--silent', '--show-error', '--max-time', '20',
                 'https://' + a.network_host], options=['--allow', a.network_host + ':443'])
        assert r.stdout, 'empty HTTPS response'
    if os.name != 'nt':
        import fcntl
        import pty
        import termios
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 31, 97, 0, 0))
        paste_bytes = b'\x1b[200~' + ('pasted text: café λ\nsecond line\tend\n' * 1400).encode() + b'\x1b[201~'
        command = """import os,sys,tty
assert all(os.isatty(n) for n in range(3))
assert os.get_terminal_size().columns==97
print('terminal-ready',flush=True)
assert sys.stdin.readline()=='terminal input\\n'
assert os.get_terminal_size().columns==73
tty.setraw(0)
print('paste-ready',flush=True)
expected = b'\\x1b[200~' + ('pasted text: café λ\\nsecond line\\tend\\n' * 1400).encode() + b'\\x1b[201~'
received = b''
while len(received) < len(expected):
    received += os.read(0, min(8192, len(expected)-len(received)))
assert received == expected
sys.stdout.write('\\x1b]52;c;cWJveC1jbGlwYm9hcmQtdGVzdA==\\x07')
sys.stdout.flush()
open('pty-result','w').write('terminal writeback')
print('terminal-finished',flush=True)
"""
        audit_args, audit_path = audit_options()
        proc = subprocess.Popen(base + audit_args + ['--tty', '--', 'python3', '-c', command],
                                stdin=slave, stdout=slave, stderr=slave, env=env)
        os.close(slave)
        output = b''
        sent = False
        paste_sent = False
        deadline = time.monotonic() + vm_timeout+10
        try:
            while proc.poll() is None:
                assert time.monotonic() < deadline, 'PTY test timed out'
                if select.select([master], [], [], 0.1)[0]:
                    try:
                        data = os.read(master, 65536)
                    except OSError:
                        break
                    if not data:
                        break
                    output += data
                if not sent and b'terminal-ready' in output:
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 23, 73, 0, 0))
                    time.sleep(0.3)
                    os.write(master, b'terminal input\n')
                    sent = True
                if not paste_sent and b'paste-ready' in output:
                    remaining = memoryview(paste_bytes)
                    while remaining:
                        count = os.write(master, remaining[:4096])
                        remaining = remaining[count:]
                    paste_sent = True
            assert proc.wait(timeout=10) == 0, output
            check_audit(audit_path)
            assert sent and b'terminal-finished' in output, output
            assert paste_sent and b'\x1b]52;c;cWJveC1jbGlwYm9hcmQtdGVzdA==\x07' in output
            assert (project / 'pty-result').read_text() == 'terminal writeback'
            print('multiline UTF-8 bracketed paste and OSC 52 output relay verified', flush=True)
        finally:
            os.close(master)
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=35)
        if a.agent_ui:
            for agent in ('codex', 'claude', 'opencode'):
                master, slave = pty.openpty()
                fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 35, 120, 0, 0))
                audit_args, audit_path = audit_options()
                proc = subprocess.Popen(base + audit_args + ['--tty', '--', agent],
                                        stdin=slave, stdout=slave, stderr=slave, env=env)
                os.close(slave)
                output = b''
                deadline = time.monotonic() + (120 if slow_guest else 30)
                ui_ready = False
                try:
                    while time.monotonic() < deadline and proc.poll() is None:
                        if select.select([master], [], [], 0.2)[0]:
                            try:
                                chunk = os.read(master, 65536)
                            except OSError:
                                break
                            output += chunk
                            # Answer terminal cursor queries as a real terminal
                            # would; the test PTY has no terminal emulator.
                            if b'\x1b[6n' in chunk:
                                os.write(master, b'\x1b[1;1R')
                            screen = output.lower()
                            if agent.encode() in screen and any(text in screen for text in
                                    (b'welcome', b'sign in', b'log in', b'get started', b'choose', b'ask anything', b'connect provider')):
                                ui_ready = True
                                break
                    assert ui_ready, (agent, output[-4000:])
                    os.write(master, b'\x1d')
                    assert proc.wait(timeout=35) in (0, 1, 130, 143), (agent, proc.returncode)
                    check_audit(audit_path)
                    print(agent + ' interactive setup screen verified', flush=True)
                finally:
                    os.close(master)
                    if proc.poll() is None:
                        proc.terminate()
                    proc.wait(timeout=35)
    assert not list(root.glob('qbox-*')), 'temporary VM state leaked'
print('real agent-image versions, isolation, writeback, nested sandbox, network and PTY checks passed')
