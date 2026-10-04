"""Build a deterministic newc initramfs without root, cpio, or a guest shell."""
import argparse
import gzip
from pathlib import Path
import stat
import struct

parser = argparse.ArgumentParser()
parser.add_argument('--runner', type=Path, required=True)
parser.add_argument('--arch', choices=['x86_64','aarch64'], required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--ca-bundle', type=Path)
parser.add_argument('--runtime', type=Path, help='Optional root tree containing Linux libraries/loader')
parser.add_argument('--rootfs',type=Path,help='Trusted Linux agent userspace tree (binaries, libraries, tools and system config)')
args = parser.parse_args()
data = args.runner.read_bytes()
machine = 183 if args.arch == 'aarch64' else 62
if data[:7] != b'\x7fELF\x02\x01\x01' or len(data)<64 or struct.unpack_from('<H',data,18)[0] != machine:
    parser.error('runner must be a Linux ELF matching --arch')
phoff = struct.unpack_from('<Q',data,32)[0]
phsize,phnum = struct.unpack_from('<HH',data,54)
if phsize<56 or phoff+phsize*phnum>len(data):
    parser.error('invalid ELF program headers')
if any(struct.unpack_from('<I',data,phoff+i*phsize)[0]==3 for i in range(phnum)):
    parser.error('runner must be statically linked (PT_INTERP present)')
entries = {}
def directory(name):
    if name not in entries:
        parent = str(Path(name).parent)
        if parent not in ('.',''):
            directory(parent)
        entries[name] = (stat.S_IFDIR|0o755,b'')
def entry(name,mode,contents):
    if name in entries:
        raise ValueError(f'duplicate initramfs entry: {name}')
    parent=str(Path(name).parent)
    if parent not in ('.',''):
        directory(parent)
    entries[name]=(mode,contents)
for name in ('proc','sys','dev','run','tmp','payload','etc','etc/ssl/certs','home','workspace'):
    directory(name)
entry('init',stat.S_IFREG|0o755,data)
entry('etc/hosts',stat.S_IFREG|0o644,b'127.0.0.1 localhost\n')
entry('etc/nsswitch.conf',stat.S_IFREG|0o644,b'hosts: files\n')
entry('etc/resolv.conf',stat.S_IFREG|0o644,b'')
if args.ca_bundle:
    entry('etc/ssl/certs/ca-certificates.crt',stat.S_IFREG|0o644,args.ca_bundle.read_bytes())
if args.runtime and args.rootfs:
    parser.error('choose --runtime or --rootfs')
source=args.rootfs or args.runtime
if source:
    permitted=('bin','sbin','lib','lib64','usr','etc','opt','var') if args.rootfs else ('lib','lib64','usr')
    for p in sorted(source.rglob('*')):
        name=p.relative_to(source).as_posix()
        if name.split('/')[0] not in permitted:
            if args.rootfs: continue
            parser.error('runtime tree may contain only lib, lib64, and usr')
        # Host input is a trusted, prepared Linux image, not the host filesystem.
        # Keep QBox's boot configuration and do not package accounts' home data.
        if name in entries and not p.is_dir(): continue
        if p.is_symlink():
            entry(name,stat.S_IFLNK|0o777,str(p.readlink()).encode())
        elif p.is_dir():
            directory(name)
        elif p.is_file():
            entry(name,stat.S_IFREG|(p.stat().st_mode&0o555),p.read_bytes())
        else:
            parser.error(f'special file in userspace tree: {name}')
archive=bytearray()
for inode,(name,(mode,contents)) in enumerate(list(sorted(entries.items()))+[('TRAILER!!!',(0,b''))],1):
    encoded=name.encode()+b'\0'
    fields=(inode,mode,0,0,2 if stat.S_ISDIR(mode) else 1,0,len(contents),0,0,0,0,len(encoded),0)
    archive+=b'070701'+''.join(f'{n:08x}' for n in fields).encode()+encoded
    archive+=b'\0'*(-len(archive)%4)
    archive+=contents
    archive+=b'\0'*(-len(archive)%4)
archive+=b'\0'*(-len(archive)%512)
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_bytes(gzip.compress(bytes(archive),mtime=0))
print(f'Wrote {args.output} ({len(archive)} bytes uncompressed)')
