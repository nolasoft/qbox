"""Opt-in real-QEMU suite. Requires guest artifacts and compiled Linux fixtures."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

p=argparse.ArgumentParser()
p.add_argument('--qbox',type=Path,required=True)
p.add_argument('--assets',type=Path,required=True)
p.add_argument('--arch',choices=['x86_64','aarch64'],required=True)
p.add_argument('--qemu')
p.add_argument('--accel',choices=['auto','tcg'],default='tcg')
p.add_argument('--payload-mode',choices=['9p','initrd'])
p.add_argument('--network-host',help='Public HTTP server hostname, enabling network tests')
p.add_argument('--network-port',type=int,default=80)
a=p.parse_args()
base=[str(a.qbox.resolve()),'run','--arch',a.arch,'--accel',a.accel,'--kernel',str(a.assets/'vmlinuz'),'--initrd',str(a.assets/'initramfs.img')]
if a.qemu: base+=['--qemu',a.qemu]
if a.payload_mode: base+=['--payload-mode',a.payload_mode]
for name in ['vmlinuz','initramfs.img','hello','fixture','net_allowed','net_denied']:
    if not (a.assets/name).is_file(): p.error(f'missing artifact: {a.assets/name}')
with tempfile.TemporaryDirectory(prefix='qbox-it-',dir=None if os.name=='nt' else '/tmp') as directory:
    env=dict(os.environ,TMPDIR=directory,TMP=directory,TEMP=directory)
    def run(program,*args,options=(),data=b'',expected=0):
        r=subprocess.run(base+list(options)+['--',str(a.assets/program),*args],input=data,capture_output=True,timeout=45,env=env)
        assert r.returncode==expected,(program,args,r.returncode,r.stderr)
        assert not list(Path(directory).glob('qbox-*')),'temporary state leaked'
        return r
    for _ in range(3): assert run('hello').stdout==b'hello from qbox\n'
    run('fixture','exit','42',expected=42)
    binary=bytes(range(256))*16384
    assert run('fixture','echo',data=binary).stdout==binary
    r=run('fixture','large')
    assert r.stdout==b'x'*(8*1024*1024) and r.stderr==b'x'*(8*1024*1024)
    run('fixture','crash',expected=128+signal.SIGSEGV)
    run('fixture','sleep',options=['--timeout','3'],expected=125)
    # Default-deny numeric public destination; no guest DNS involved.
    run('net_denied','1.1.1.1','80')
    if a.network_host:
        allow=['--allow',f'{a.network_host}:{a.network_port}']
        run('net_allowed',a.network_host,str(a.network_port),options=allow)
        run('net_denied',a.network_host,str(a.network_port+1),options=allow)
        run('net_denied','8.8.8.8','80',options=allow)
        # Special-address DNS answer must never reach a host service. A numeric
        # private IP is rejected by CLI; localhost exercises connector DNS policy.
        run('net_allowed','localhost','80',options=['--allow','localhost:80'],expected=1)
    else:
        print('Network capability cases omitted: supply --network-host to run them')
    has_console=True
    if os.name=='nt':
        import ctypes
        has_console=bool(ctypes.windll.kernel32.GetConsoleWindow())
    if has_console:
        flags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name=='nt' else 0
        proc=subprocess.Popen(base+['--',str(a.assets/'fixture'),'sleep'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env,creationflags=flags)
        time.sleep(2)
        proc.send_signal(signal.CTRL_BREAK_EVENT if os.name=='nt' else signal.SIGINT)
        proc.communicate(timeout=10)
        assert proc.returncode==130
        assert not list(Path(directory).glob('qbox-*'))
    else:
        print('Console cancellation omitted: Windows host has no attached console')
    if os.name!='nt':
        # Disable startup fallback for deliberate QEMU termination. With auto,
        # killing the first VM before it connects correctly triggers a retry.
        proc=subprocess.Popen(base+['--accel','tcg','--',str(a.assets/'fixture'),'sleep'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try:
            deadline=time.monotonic()+5
            while True:
                children=subprocess.run(['pgrep','-P',str(proc.pid)],capture_output=True,text=True).stdout.split()
                if children: break
                assert time.monotonic()<deadline,'QEMU did not start'
                time.sleep(0.05)
            os.kill(int(children[0]),signal.SIGKILL)
            proc.communicate(timeout=10)
            assert proc.returncode==125,'VM crash must be reported as launcher failure'
            assert not list(Path(directory).glob('qbox-*'))
        finally:
            if proc.poll() is None: proc.kill()
            proc.wait()
print('real QEMU integration checks passed')
