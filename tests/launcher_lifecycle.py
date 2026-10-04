"""Launcher tests with a fake QEMU peer. These are not VM isolation tests."""
import os
import shutil
from pathlib import Path
import struct
import signal
import subprocess
import sys
import tempfile
import time

QBOX, CONNECTOR = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='qbox-tests-') as directory:
    root = Path(directory)
    elf = root / 'program'
    header = bytearray(64)
    header[:7] = b'\x7fELF\x02\x01\x01'
    header[16:20] = struct.pack('<HH', 2, 183 if os.uname().machine == 'arm64' else 62)
    elf.write_bytes(header)
    (root/'kernel').touch()
    (root/'initrd').write_bytes(b'base')
    fake = root/'fake-qemu'
    fake.write_text('''#!/usr/bin/env python3
import os,socket,struct,sys,time
from pathlib import Path
args=sys.argv[1:]
mode=os.environ.get('MODE','echo')
if mode=='fallback' and 'accel=tcg' not in args[args.index('-machine')+1]: sys.exit(1)
if '-fsdev' in args:
 fs=args[args.index('-fsdev')+1]
 payload=Path(fs.split('path=',1)[1].split(',security_model=',1)[0].replace(',,',','))
else:
 payload=Path(args[args.index('-initrd')+1]).parent/'payload'
Path(os.environ['RECORD']).write_text(str(payload.parent))
channel=args[args.index('-chardev')+1]
s=socket.socket(socket.AF_UNIX)
s.connect(channel.split('path=',1)[1].split(',server=',1)[0].replace(',,',','))
def frame(k,b=b''):
 return bytes([k])+struct.pack('!I',len(b))+b
def exact(n):
 b=b''
 while len(b)<n:
  p=s.recv(n-len(b))
  if not p: raise EOFError()
  b+=p
 return b
def recv():
 h=exact(5)
 return h[0],exact(struct.unpack('!I',h[1:])[0])
token=(payload/'token').read_bytes()
if mode=='silent': time.sleep(60)
s.sendall(frame(7,b'wrong' if mode=='auth' else token))
if mode=='auth': time.sleep(5)
k,b=recv()
if mode.startswith('agent'):
 assert k==8 and b[:12]==struct.pack('!III',0,24,80)
 assert b'QBOX_TEST_KEY=test-secret' in b
 assert b'QBOX_UNFORWARDED_SECRET=' not in b
 assert not any('test-secret' in arg for arg in args)
 archive=(payload/'workspace').read_bytes()
 assert b'host original' in archive and b'git secret' not in archive
 archive=archive.replace(b'host original',b'agent changed')
 if mode=='agent-conflict': Path(os.environ['HOST_FILE']).write_text('host concurrent edit')
 s.sendall(frame(9,archive)+frame(10,struct.pack('!I',0))+frame(5,struct.pack('!II',0,42)))
 time.sleep(5)
 sys.exit(0)
assert k==1
if mode=='crash': sys.exit(1)
if mode=='hang': time.sleep(60)
if mode=='large': s.sendall(frame(3,b'x'*100000))
status=(0,42)
while True:
 k,b=recv()
 if k==2:
  if not b:
   if mode=='signal': continue
   break
  s.sendall(frame(3,b))
 elif k==6:
  status=(1,struct.unpack('!I',b)[0])
  break
s.sendall(frame(4,b'stderr\\n'))
s.sendall(frame(5,struct.pack('!II',*status)))
time.sleep(5)
''')
    fake.chmod(0o700)
    record = root/'record'
    base = [QBOX, 'run', '--kernel', str(root/'kernel'), '--initrd', str(root/'initrd'), '--qemu', str(fake), '--connector', CONNECTOR]
    data = bytes(range(256))*2048
    for mode, extra, expected in [('echo',[],42),('echo',['--payload-mode','initrd'],42),('fallback',[],42),('auth',[],125),('crash',[],125),('silent',['--timeout','1'],125),('hang',['--timeout','1'],125),('large',['--output-limit','1000'],125)]:
        env = dict(os.environ, MODE=mode, RECORD=str(record))
        result = subprocess.run(base+extra+['--',str(elf),'space argument'],input=data,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,timeout=15)
        assert result.returncode == expected, (mode,result.returncode,result.stderr)
        if mode in ('echo','fallback'):
            assert result.stdout == data
            assert result.stderr == b'stderr\n'
        assert not Path(record.read_text()).exists(), 'temporary directory leaked'
    result=subprocess.run(base+['--allow','bad:0','--',str(elf)],capture_output=True)
    assert result.returncode==125
    record.unlink()
    env=dict(os.environ,MODE='signal',RECORD=str(record))
    proc=subprocess.Popen(base+['--',str(elf)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    deadline=time.monotonic()+5
    while not record.exists():
        assert time.monotonic()<deadline
        time.sleep(0.05)
    time.sleep(0.2)
    proc.send_signal(signal.SIGINT)
    proc.communicate(timeout=5)
    assert proc.returncode==130,proc.returncode
    assert not Path(record.read_text()).exists()
    project=root/'project'
    project.mkdir()
    (project/'.git').mkdir()
    (project/'.git'/'private').write_text('git secret')
    original=project/'original'
    for mode in ('agent','agent-conflict'):
        original.write_text('host original')
        env=dict(os.environ,MODE=mode,RECORD=str(record),HOST_FILE=str(original),QBOX_TEST_KEY='test-secret',QBOX_UNFORWARDED_SECRET='not forwarded')
        command=[QBOX,'agent','--workspace',str(project),'--env','QBOX_TEST_KEY','--kernel',str(root/'kernel'),'--initrd',str(root/'initrd'),'--qemu',str(fake),'--','codex','exec','--skip-git-repo-check','test prompt']
        result=subprocess.run(command,input=b'',capture_output=True,env=env,timeout=15)
        staged=Path(record.read_text())
        if mode=='agent':
            assert result.returncode==42,result.stderr
            assert original.read_text()=='agent changed'
            assert not staged.exists()
        else:
            assert result.returncode==125,result.stderr
            assert original.read_text()=='host concurrent edit'
            assert b'host file changed' in result.stderr,result.stderr
            assert (staged/'workspace-result.qbws').is_file()
            shutil.rmtree(staged)
        assert (project/'.git'/'private').read_text()=='git secret'
print('launcher authentication, binary stdio, exit status, accelerator fallback, timeout, crash and cleanup checks passed')
