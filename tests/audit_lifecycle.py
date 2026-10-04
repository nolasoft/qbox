"""Audit protocol, private logs and graceful writeback with a fake VM peer."""
import json
import os
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import time

qbox = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='qbox-audit-', dir='/tmp') as directory:
    root = Path(directory)
    project = root / 'project'
    project.mkdir()
    (project / 'file').write_text('before')
    for name in ('kernel', 'initrd'):
        (root / name).write_bytes(b'base')
    fake = root / 'qemu'
    fake.write_text('''#!/usr/bin/env python3
import os,socket,struct,sys,time
from pathlib import Path
a=sys.argv[1:]
if '-fsdev' in a:
 payload=Path(a[a.index('-fsdev')+1].split('path=',1)[1].split(',security_model=',1)[0])
else: payload=Path(a[a.index('-initrd')+1]).parent/'payload'
assert (payload/'audit').read_text()=='1'
s=socket.socket(socket.AF_UNIX)
s.connect(a[a.index('-chardev')+1].split('path=',1)[1].split(',server=',1)[0])
def frame(k,b=b''): return bytes([k])+struct.pack('!I',len(b))+b
def exact(n):
 b=b''
 while len(b)<n:
  p=s.recv(n-len(b))
  if not p: raise EOFError()
  b+=p
 return b
def recv():
 h=exact(5); return h[0],exact(struct.unpack('!I',h[1:])[0])
mode=os.environ['AUDIT_MODE']
s.sendall(frame(7,(payload/'token').read_bytes()))
if mode!='old': s.sendall(frame(14,struct.pack('!I',mode=='startup')))
if mode in ('startup','old'):
 try:
  recv(); Path(os.environ['EXEC_MARKER']).touch()
 except EOFError: pass
 time.sleep(3); sys.exit()
k,b=recv(); assert k==8
assert b'argv-secret' in b
n=50 if mode=='disk' else 1
e=bytearray(336)
struct.pack_into('<QIIIIIIIiI',e,0,123,2,7,7,1,65534,0,0,0,0)
e[44:47]=b'sh\\0'
p=b'/bin/a"\\n\\\\z' if mode!='disk' else b'/' + b'x'*250
e[60:60+len(p)]=p
s.sendall((frame(12,e)*n) if mode!='malformed' else frame(12,b'x'))
if mode in ('disk','malformed'):
 while True:
  k,b=recv()
  if k==6:
   assert struct.unpack('!I',b)[0]==15
   Path(os.environ['SIGNAL_MARKER']).touch(); break
archive=(payload/'workspace').read_bytes().replace(b'before',b'after!')
s.sendall(frame(9,archive)+frame(10,struct.pack('!I',0)))
if mode!='missing':
 s.sendall(frame(13,struct.pack('!IQQ',mode=='lost',n,1 if mode=='lost' else 0)))
s.sendall(frame(5,struct.pack('!II',0,42)))
time.sleep(3)
''')
    fake.chmod(0o700)
    base = [qbox, 'agent', '--workspace', str(project), '--kernel', str(root/'kernel'),
            '--initrd', str(root/'initrd'), '--qemu', str(fake)]
    marker = root/'exec-marker'
    signalled = root/'signal-marker'
    for mode in ('ok', 'startup', 'old', 'lost', 'missing', 'malformed', 'disk'):
        for transport in ('9p', 'initrd') if mode in ('ok','disk') else ('9p',):
            (project/'file').write_text('before')
            audit = root / (mode + '-' + transport + '.jsonl')
            env = dict(os.environ, AUDIT_MODE=mode, EXEC_MARKER=str(marker), SIGNAL_MARKER=str(signalled))
            def disk_limit():
                signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
                resource.setrlimit(resource.RLIMIT_FSIZE, (4096,4096))
            options = ['--timeout','1'] if mode=='old' else []
            result = subprocess.run(base + options + ['--payload-mode', transport, '--audit-log', str(audit),
                                    '--', 'sh', '-c', 'argv-secret'], input=b'', capture_output=True,
                                    env=env, timeout=15, preexec_fn=disk_limit if mode=='disk' else None)
            assert result.returncode == (42 if mode=='ok' else 125), (mode, result.stderr)
            assert stat.S_IMODE(audit.stat().st_mode) == 0o600
            data = audit.read_bytes()
            assert b'argv-secret' not in data
            if mode!='disk':
                records = [json.loads(line) for line in data.splitlines()]
                assert records[0]['metadata_only']
                assert records[-1]['complete'] == (mode=='ok'), records[-1]
                if mode=='ok': assert records[1]['executable']=='/bin/a"\n\\z'
            if mode in ('startup','old'):
                assert not marker.exists()
                assert (project/'file').read_text()=='before'
            else: assert (project/'file').read_text()=='after!'
            if mode in ('disk','malformed'):
                assert signalled.exists()
                signalled.unlink()
    interrupted_log = root/'interrupted.jsonl'
    proc = subprocess.Popen(base + ['--audit-log',str(interrupted_log),'--','true'],
            stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
            env=dict(os.environ,AUDIT_MODE='old',EXEC_MARKER=str(marker),SIGNAL_MARKER=str(signalled)))
    try:
        deadline = time.monotonic()+5
        while not interrupted_log.exists():
            assert time.monotonic()<deadline
            time.sleep(0.01)
        time.sleep(0.3)
        proc.send_signal(signal.SIGINT)
        proc.communicate(timeout=3)
        assert proc.returncode==130,proc.returncode
        assert not marker.exists()
        assert not json.loads(interrupted_log.read_text().splitlines()[-1])['complete']
    finally:
        if proc.poll() is None: proc.kill();proc.wait()
    for path in ('',project/'audit.jsonl', root/'missing-parent/audit.jsonl', root/'ok-9p.jsonl'):
        result = subprocess.run(base + ['--audit-log', str(path), '--', 'true'], capture_output=True)
        assert result.returncode==125
    result = subprocess.run([qbox,'run','--audit-log',str(root/'run.jsonl'),'--','anything'],capture_output=True)
    assert result.returncode==125
print('audit startup, metadata, transports, loss, malformed frames, write failure and writeback passed')
