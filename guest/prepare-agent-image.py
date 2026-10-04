#!/usr/bin/env python3
"""Assemble Alpine kernel/userspace and provider CLIs without Docker or root.

Downloads are HTTPS only. Provider binaries are checked against their published
SHA256 digests; every input is recorded in the output provenance manifest.
Alpine package scripts are not executed. This is an image assembler for the
explicit packages below, not a general apk replacement.
"""
import argparse
import base64
import gzip
import hashlib
import json
import io
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import shlex
import struct
import subprocess
import tarfile
import zlib


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arch', choices=['aarch64', 'x86_64'], default='aarch64')
    parser.add_argument('--alpine', default='3.22')
    parser.add_argument('--codex-version', default='rust-v0.160.0')
    parser.add_argument('--claude-version', default='2.1.285')
    parser.add_argument('--opencode-version', default='v1.18.34')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cache', type=Path, default=Path('build/agent-image'))
    parser.add_argument('--runner', type=Path)
    parser.add_argument('--with-build-tools', action='store_true',
                        help='include Alpine build-base (C/C++ compiler, Make, headers), CMake and Ninja')
    parser.add_argument('--package', action='append', default=[], metavar='NAME',
                        help='include an additional Alpine package and its dependencies; repeat as needed')
    parser.add_argument('--with-audit', action='store_true', help='build a static trusted eBPF collector')
    parser.add_argument('--cc', default=os.environ.get('CC', 'cc'), help='Linux musl C compiler command')
    parser.add_argument('--bpf-clang', default=os.environ.get('BPF_CLANG', 'clang'), help='Clang with the BPF target')
    parser.add_argument('--llvm-objcopy', help='llvm-objcopy for isolating libelf static symbols')
    args = parser.parse_args()
    if args.with_audit and args.runner:
        parser.error('--with-audit builds its runner; do not also supply --runner')
    args.output = args.output or Path('assets') / args.arch
    for value in (args.alpine, args.codex_version, args.claude_version, args.opencode_version):
        if not re.fullmatch(r'[A-Za-z0-9._-]+', value):
            parser.error('invalid release identifier')
    for name in args.package:
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9+_.-]*', name):
            parser.error('--package requires an Alpine package name')
    args.output.mkdir(parents=True, exist_ok=True)
    downloads = args.cache / 'downloads'
    downloads.mkdir(parents=True, exist_ok=True)
    root = args.cache / ('rootfs-' + args.arch)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    provenance = []

    def fetch(url, name, digest=None):
        path = downloads / name
        if not path.exists():
            staged = path.with_suffix(path.suffix + '.part')
            print('Downloading ' + name, flush=True)
            subprocess.run(['curl', '--proto', '=https', '--proto-redir', '=https',
                            '-fsSL', '--retry', '2', '--connect-timeout', '20',
                            '--max-time', '600', url, '-o', str(staged)], check=True)
            staged.replace(path)
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest and actual != digest.removeprefix('sha256:'):
            raise ValueError('checksum mismatch: ' + name)
        provenance.append({'url': url, 'sha256': actual, 'file': name,
                           'published_sha256_verified': bool(digest)})
        return path

    packages, providers = {}, {}
    for repo in ('main', 'community'):
        index = fetch(f'https://dl-cdn.alpinelinux.org/alpine/v{args.alpine}/{repo}/{args.arch}/APKINDEX.tar.gz',
                      f'alpine-{args.alpine}-{repo}-{args.arch}-index.tar.gz')
        with tarfile.open(index) as tar:
            content = tar.extractfile('APKINDEX').read().decode()
        for block in content.split('\n\n'):
            record = dict(line.split(':', 1) for line in block.splitlines() if ':' in line)
            if 'P' not in record:
                continue
            record['repo'] = repo
            packages[record['P']] = record
            for provided in record.get('p', '').split():
                providers.setdefault(re.split('[<>=~]', provided)[0], record['P'])

    selected = set()
    def verify_apk(path, record):
        # APK v2's index checksum covers the compressed control member. The
        # control .PKGINFO binds the compressed data member through SHA256.
        remaining = path.read_bytes()
        members = []
        while remaining:
            decoder = zlib.decompressobj(31)
            raw = decoder.decompress(remaining)
            if not decoder.eof:
                raise ValueError('truncated APK: ' + path.name)
            length = len(remaining) - len(decoder.unused_data)
            members.append((remaining[:length], raw))
            remaining = decoder.unused_data
        if len(members) != 3 or not record['C'].startswith('Q1'):
            raise ValueError('unsupported APK format: ' + path.name)
        if hashlib.sha1(members[1][0]).digest() != base64.b64decode(record['C'][2:]):
            raise ValueError('APK index checksum mismatch: ' + path.name)
        with tarfile.open(fileobj=io.BytesIO(members[1][1]), mode='r:', ignore_zeros=True) as control:
            text = control.extractfile('.PKGINFO').read().decode()
        digest = next(line.split(' = ', 1)[1] for line in text.splitlines() if line.startswith('datahash = '))
        if hashlib.sha256(members[2][0]).hexdigest() != digest:
            raise ValueError('APK data checksum mismatch: ' + path.name)
        provenance[-1]['apk_index_and_data_verified'] = True

    def require(dependency):
        if dependency.startswith('!'):
            return
        name = re.split('[<>=~]', dependency)[0]
        name = name if name in packages else providers.get(name)
        if not name:
            raise ValueError('unresolved dependency: ' + dependency)
        if name in selected:
            return
        selected.add(name)
        for child in packages[name].get('D', '').split():
            require(child)

    for name in ('musl', 'busybox', 'bash', 'git', 'ripgrep', 'libstdc++',
                 'ca-certificates-bundle', 'curl', 'nodejs', 'npm', 'python3',
                 'bubblewrap', 'procps-ng'):
        require(name)
    if args.with_build_tools:
        for name in ('build-base', 'cmake', 'ninja'):
            require(name)
    for name in args.package:
        require(name)

    def safe_destination(name):
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe archive entry: ' + name)
        target = root.joinpath(*relative.parts)
        for parent in target.parents:
            if parent == root:
                break
            if parent.is_symlink():
                raise ValueError('symlink parent in archive: ' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def extract_package(path, prefix=''):
        # APK v2 has concatenated gzip/tar members. Metadata and maintainer
        # scripts are intentionally omitted. Do not use extractall: archive
        # symlinks must never redirect host writes.
        with tarfile.open(path, 'r:gz', ignore_zeros=True) as tar:
            for member in tar:
                name = member.name.removeprefix('./')
                if not name or name.startswith('.'):
                    continue
                destination = safe_destination(prefix + '/' + name if prefix else name)
                if member.isdir():
                    destination.mkdir(exist_ok=True)
                elif member.isfile():
                    if destination.is_symlink():
                        destination.unlink()
                    with tar.extractfile(member) as source, destination.open('wb') as output:
                        shutil.copyfileobj(source, output)
                    destination.chmod(member.mode & 0o777)
                elif member.issym():
                    if destination.is_symlink() or destination.is_file():
                        destination.unlink()
                    destination.symlink_to(member.linkname)
                elif member.islnk():
                    source = safe_destination(prefix + '/' + member.linkname if prefix else member.linkname)
                    if source.is_symlink() or not source.is_file():
                        raise ValueError('unsafe hardlink: ' + name)
                    if destination.is_symlink():
                        destination.unlink()
                    shutil.copyfile(source, destination)
                    destination.chmod(member.mode & 0o777)
                else:
                    raise ValueError('special archive entry: ' + name)

    for name in sorted(selected):
        p = packages[name]
        filename = f"{name}-{p['V']}.apk"
        path = fetch(f"https://dl-cdn.alpinelinux.org/alpine/v{args.alpine}/{p['repo']}/{args.arch}/{filename}",
                     args.arch + '-' + filename)
        verify_apk(path, p)
        extract_package(path)

    # busybox applet links are normally created by a package post-install
    # script; provide the standard commands needed by agent subprocesses.
    (root / 'bin').mkdir(exist_ok=True)
    for name in ('sh', 'ash', 'cat', 'chmod', 'cp', 'date', 'dd', 'echo', 'false',
                 'grep', 'head', 'id', 'ln', 'ls', 'mkdir', 'mv', 'pwd', 'rm',
                 'rmdir', 'sed', 'sleep', 'sort', 'tail', 'tar', 'tee', 'test',
                 'touch', 'tr', 'true', 'uname', 'wc', 'whoami', 'awk', 'env',
                 'find', 'xargs', 'printf', 'readlink', 'realpath', 'stat', 'cut',
                 'gzip', 'gunzip', 'printenv'):
        path = root / 'bin' / name
        if not path.exists() and not path.is_symlink():
            path.symlink_to('busybox')
    if not (root / 'usr/bin/env').exists():
        (root / 'usr/bin/env').symlink_to('../../bin/busybox')

    kernel = packages['linux-virt']
    filename = f"linux-virt-{kernel['V']}.apk"
    apk = fetch(f"https://dl-cdn.alpinelinux.org/alpine/v{args.alpine}/{kernel['repo']}/{args.arch}/{filename}",
                args.arch + '-' + filename)
    verify_apk(apk, kernel)
    with tarfile.open(apk, 'r:gz', ignore_zeros=True) as tar:
        image = tar.extractfile('boot/vmlinuz-virt').read()
        if args.arch == 'aarch64' and image[4:8] == b'zimg':
            # Linux EFI zboot header contains payload offset/size at 8/12.
            offset, size = struct.unpack_from('<II', image, 8)
            if image[24:29] != b'gzip\0' or offset + size > len(image):
                raise ValueError('unsupported EFI zboot kernel')
            image = gzip.decompress(image[offset:offset + size])
        if args.arch == 'aarch64' and image[56:60] != b'ARM\x64':
            raise ValueError('invalid arm64 Linux Image')
        (args.output / 'vmlinuz').write_bytes(image)
        config = next(m for m in tar.getmembers() if m.name.startswith('boot/config-'))
        (args.output / 'kernel.config').write_bytes(tar.extractfile(config).read())
        depname = next(n for n in tar.getnames() if n.endswith('/modules.dep'))
        modulebase = depname.rsplit('/', 1)[0]
        dependencies = dict(line.split(':', 1) for line in tar.extractfile(depname).read().decode().splitlines())
        ordered, seen = [], set()
        def module(path):
            if path in seen:
                return
            seen.add(path)
            for child in dependencies[path].split():
                module(child)
            ordered.append(path)
        for suffix in ('/9p.ko.gz', '/9pnet_virtio.ko.gz', '/virtio_net.ko.gz'):
            module(next(path for path in dependencies if path.endswith(suffix)))
        paths = []
        for path in ordered:
            destination = safe_destination(modulebase + '/' + path.removesuffix('.gz'))
            destination.write_bytes(gzip.decompress(tar.extractfile(modulebase + '/' + path).read()))
            paths.append('/' + destination.relative_to(root).as_posix())
        (root / 'etc/qbox').mkdir(parents=True, exist_ok=True)
        (root / 'etc/qbox/modules').write_text('\n'.join(paths) + '\n')
        (root / 'etc/qbox/tmpfs-root').touch()

    metadata = fetch(f'https://api.github.com/repos/openai/codex/releases/tags/{args.codex_version}',
                     args.codex_version + '.json')
    release = json.loads(metadata.read_text())
    assetname = f'codex-package-{args.arch}-unknown-linux-musl.tar.gz'
    asset = next(a for a in release['assets'] if a['name'] == assetname)
    if not asset.get('digest', '').startswith('sha256:'):
        raise ValueError('Codex release has no SHA256 digest')
    binary = fetch(asset['browser_download_url'], args.codex_version + '-' + assetname, asset['digest'])
    (root / 'usr/local/bin').mkdir(parents=True, exist_ok=True)
    extract_package(binary, 'opt/codex')
    (root / 'usr/local/bin/codex').symlink_to('/opt/codex/bin/codex')
    base = 'https://downloads.claude.ai/claude-code-releases'
    manifest = fetch(f'{base}/{args.claude_version}/manifest.json',
                     f'claude-{args.claude_version}-manifest.json')
    platform = 'linux-' + ('arm64' if args.arch == 'aarch64' else 'x64') + '-musl'
    digest = json.loads(manifest.read_text())['platforms'][platform]['checksum']
    binary = fetch(f'{base}/{args.claude_version}/{platform}/claude',
                   f'claude-{args.claude_version}-{platform}', digest)
    shutil.copyfile(binary, root / 'usr/local/bin/claude')
    (root / 'usr/local/bin/claude').chmod(0o755)

    metadata = fetch(f'https://api.github.com/repos/anomalyco/opencode/releases/tags/{args.opencode_version}',
                     'opencode-' + args.opencode_version + '.json')
    release = json.loads(metadata.read_text())
    # The baseline x64 build also works on CPUs without AVX2 and under TCG.
    platform = 'arm64' if args.arch == 'aarch64' else 'x64-baseline'
    assetname = f'opencode-linux-{platform}-musl.tar.gz'
    asset = next(a for a in release['assets'] if a['name'] == assetname)
    if not asset.get('digest', '').startswith('sha256:'):
        raise ValueError('OpenCode release has no SHA256 digest')
    binary = fetch(asset['browser_download_url'],
                   args.opencode_version + '-' + assetname, asset['digest'])
    extract_package(binary, 'opt/opencode')
    executable = root / 'opt/opencode/opencode'
    if executable.is_symlink() or not executable.is_file():
        raise ValueError('OpenCode release lacks its executable')
    executable.chmod(0o755)
    # OpenCode ships its model catalog. Avoid startup fetches and updates in
    # disposable, default-deny guests; explicit forwarded values override these.
    launcher = root / 'usr/local/bin/opencode'
    launcher.write_text('#!/bin/sh\n'
        ': "${OPENCODE_DISABLE_AUTOUPDATE:=1}"\n'
        ': "${OPENCODE_DISABLE_MODELS_FETCH:=1}"\n'
        'export OPENCODE_DISABLE_AUTOUPDATE OPENCODE_DISABLE_MODELS_FETCH\n'
        'TMPDIR="${XDG_CACHE_HOME:-$HOME/.cache}/opencode/tmp"\n'
        'mkdir -p "$TMPDIR" || exit 125\n'
        'export TMPDIR\n'
        'exec /opt/opencode/opencode "$@"\n')
    launcher.chmod(0o755)

    audit_packages = {}
    runner = args.runner or args.output / 'runnerd'
    if args.with_audit:
        config = (args.output / 'kernel.config').read_text()
        required = ('BPF', 'BPF_SYSCALL', 'BPF_EVENTS', 'DEBUG_INFO_BTF', 'FTRACE_SYSCALLS')
        if any('CONFIG_' + name + '=y' not in config.splitlines() for name in required):
            raise ValueError('prepared kernel lacks audit tracing/BTF support')
        runtime_root = root
        root = args.cache / ('audit-deps-' + args.arch)
        if root.exists():
            shutil.rmtree(root)
        root.mkdir()
        for name in ('musl-dev', 'linux-headers', 'libbpf-dev', 'elfutils-dev',
                     'zlib-dev', 'zlib-static', 'zstd-dev', 'zstd-static'):
            p = packages[name]
            filename = f"{name}-{p['V']}.apk"
            path = fetch(f"https://dl-cdn.alpinelinux.org/alpine/v{args.alpine}/{p['repo']}/{args.arch}/{filename}",
                         args.arch + '-' + filename)
            verify_apk(path, p)
            extract_package(path)
            audit_packages[name] = p['V']
        source = Path(__file__).resolve().parent
        obj = runtime_root / 'etc/qbox/audit.bpf.o'
        subprocess.run([args.bpf_clang, '-target', 'bpfel', '-O2', '-g', '-Wall', '-Werror',
                        '-I' + str(root / 'usr/include'), '-I' + str(source),
                        '-c', str(source / 'audit.bpf.c'), '-o', str(obj)], check=True)
        obj.chmod(0o600)
        # Alpine libelf's private crc32 has the same exported name as zlib's
        # public function. Rename both definition and references in the build
        # copy; accepting duplicate definitions would select the wrong ABI.
        objcopy = args.llvm_objcopy or str(Path(args.bpf_clang).with_name('llvm-objcopy'))
        subprocess.run([objcopy, '--redefine-sym', 'crc32=qbox_elf_crc32',
                        str(root / 'usr/lib/libelf.a'), str(root / 'usr/lib/libelf-qbox.a')], check=True)
        subprocess.run(shlex.split(args.cc) + ['-std=c11', '-Os', '-static', '-Wall', '-Wextra',
                        *(['-mno-outline-atomics'] if args.arch == 'aarch64' else []),
                        '-DQBOX_WITH_AUDIT', '-isystem', str(root / 'usr/include'),
                        *[str(source / name) for name in ('runnerd.c', 'workspace.c', 'rootfs.c', 'audit.c', 'audit_atomic.c')],
                        *[str(root / 'usr/lib' / name) for name in ('libbpf.a', 'libelf-qbox.a', 'libz.a', 'libzstd.a')],
                        '-o', str(runner)], check=True)
        root = runtime_root

    provenance_path = args.output / 'agents-manifest.json'
    provenance_path.write_text(json.dumps({'arch': args.arch, 'alpine': args.alpine,
        'kernel': kernel['V'], 'codex': args.codex_version, 'claude': args.claude_version,
        'opencode': args.opencode_version,
        'packages': {name: packages[name]['V'] for name in sorted(selected)},
        'runner_sha256': hashlib.sha256(runner.read_bytes()).hexdigest(),
        'audit': args.with_audit, 'audit_build_packages': audit_packages,
        'audit_tools': {'cc': args.cc, 'bpf_clang': args.bpf_clang, 'llvm_objcopy': objcopy} if args.with_audit else None,
        'audit_sources_sha256': {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
            for name in ('runnerd.c', 'audit.c', 'audit.h', 'audit.bpf.c', 'audit_event.h', 'audit_atomic.c')} if args.with_audit else None,
        'audit_object_sha256': hashlib.sha256((root / 'etc/qbox/audit.bpf.o').read_bytes()).hexdigest() if args.with_audit else None,
        'inputs': provenance}, indent=2) + '\n')
    script = Path(__file__).resolve().parent / 'build-initramfs.sh'
    subprocess.run([str(script), '--runner', str(runner), '--arch', args.arch,
                    '--rootfs', str(root), '--ca-bundle', str(root / 'etc/ssl/certs/ca-certificates.crt'),
                    '--output', str(args.output / 'agents.img')], check=True)
    boot = args.cache / ('boot-' + args.arch)
    if boot.exists():
        shutil.rmtree(boot)
    (boot / 'etc/qbox').mkdir(parents=True)
    shutil.copytree(root / 'lib/modules', boot / 'lib/modules')
    shutil.copyfile(root / 'etc/qbox/modules', boot / 'etc/qbox/modules')
    (boot / 'etc/qbox/tmpfs-root').touch()
    subprocess.run([str(script), '--runner', str(runner), '--arch', args.arch,
                    '--rootfs', str(boot), '--output', str(args.output / 'initramfs.img')], check=True)
    print(f'Prepared {args.output / "agents.img"}; provenance: {provenance_path}', flush=True)


if __name__ == '__main__':
    main()
