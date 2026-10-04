"""Real-VM eBPF checks, including namespace descendants and secret exclusion."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--qbox', type=Path, required=True)
p.add_argument('--assets', type=Path, required=True)
p.add_argument('--arch', choices=('aarch64','x86_64'), default='aarch64')
p.add_argument('--payload-mode', choices=('9p','initrd'), default='9p')
p.add_argument('--accel', choices=('auto','tcg'), default='auto')
p.add_argument('--network-host', help='Optional permitted TLS endpoint')
a = p.parse_args()
with tempfile.TemporaryDirectory(prefix='qbox-audit-it-', dir='/tmp') as directory:
    root = Path(directory)
    project = root / 'project'
    project.mkdir()
    base = [str(a.qbox.resolve()), 'agent', '--workspace', str(project), '--arch', a.arch,
            '--payload-mode', a.payload_mode, '--accel', a.accel,
            '--kernel', str((a.assets/'vmlinuz').resolve()), '--timeout', '90']
    log = root/'audit.jsonl'
    code = '''import ctypes,errno,os,socket,subprocess,struct
from pathlib import Path
assert Path('/proc/sys/kernel/unprivileged_bpf_disabled').read_text().strip()=='1'
libc=ctypes.CDLL(None,use_errno=True)
attr=ctypes.create_string_buffer(128)
struct.pack_into('IIIII',attr,0,2,4,4,1,0)
r=libc.syscall(280 if os.uname().machine=='aarch64' else 321,0,ctypes.byref(attr),128)
assert r==-1 and ctypes.get_errno()==errno.EPERM
assert not os.access('/etc/qbox/audit.bpf.o',os.R_OK)
assert not os.access('/sys/kernel/tracing',os.R_OK)
subprocess.run(['bwrap','--unshare-user','--unshare-pid','--ro-bind','/','/',
               '--dev','/dev','--proc','/proc','--','sh','-c','echo nested'],check=True)
for addr in ('1.1.1.1','127.0.0.1'):
 s=socket.socket();s.settimeout(2)
 try: s.connect((addr,80))
 except OSError: pass
 s.close()
subprocess.Popen(['sleep','10'])
Path('changed').write_text('audited writeback')
raise SystemExit(42)
'''
    env = dict(os.environ, QBOX_AUDIT_SECRET='environment-secret', TMPDIR=directory)
    result = subprocess.run(base + ['--initrd', str((a.assets/'agents.img').resolve()),
            '--audit-log',str(log),'--env','QBOX_AUDIT_SECRET','--','python3','-c',code,'argument-secret'],
            input=b'',capture_output=True,env=env,timeout=100)
    assert result.returncode==42,(result.returncode,result.stderr,result.stdout)
    assert (project/'changed').read_text()=='audited writeback'
    text = log.read_text()
    assert 'argument-secret' not in text and 'environment-secret' not in text
    records = [json.loads(line) for line in text.splitlines()]
    assert records[-1]['complete'], records[-1]
    events = records[1:-1]
    assert records[-1]['events']==len(events)
    kinds = {r['event'] for r in events}
    assert {'fork','exec','exit','connect_attempt','connect_result'} <= kinds,kinds
    assert any(r.get('executable')=='/bin/sh' for r in events),events
    attempts = [r for r in events if r['event']=='connect_attempt']
    assert {'1.1.1.1','127.0.0.1'} <= {r['address'] for r in attempts},attempts
    assert any(r['event']=='connect_result' and r['result']<0 for r in events)
    assert any(r.get('comm')=='sleep' and r['event']=='exit' for r in events),events
    if a.network_host:
        tls_log = root/'tls.jsonl'
        result = subprocess.run(base + ['--initrd',str((a.assets/'agents.img').resolve()),
                '--audit-log',str(tls_log),'--allow',a.network_host+':443','--','curl',
                '--fail','--silent','--show-error','--max-time','20','https://'+a.network_host],
                input=b'',capture_output=True,env=env,timeout=100)
        assert result.returncode==0 and result.stdout,result.stderr
        records = [json.loads(line) for line in tls_log.read_text().splitlines()]
        assert records[-1]['complete']
        assert any(r.get('port')==443 for r in records)
    if os.name != 'nt' and a.payload_mode == '9p':
        import resource
        import signal
        def limited_log():
            signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
            resource.setrlimit(resource.RLIMIT_FSIZE, (4096,4096))
        failure_code = """import signal,socket
from pathlib import Path
Path('before-audit-failure').write_text('before')
def stopped(sig,frame):
 Path('after-audit-failure').write_text('graceful export')
 raise SystemExit(0)
signal.signal(signal.SIGTERM,stopped)
while True:
 s=socket.socket();s.setblocking(False)
 try: s.connect(('127.0.0.1',1))
 except OSError: pass
 s.close()
"""
        result = subprocess.run(base + ['--initrd',str((a.assets/'agents.img').resolve()),
                '--audit-log',str(root/'write-failure.jsonl'),'--','python3','-c',failure_code],
                input=b'',capture_output=True,env=env,timeout=100,preexec_fn=limited_log)
        assert result.returncode==125,result.stderr
        assert (project/'before-audit-failure').exists(),result.stderr
        assert (project/'before-audit-failure').read_text()=='before'
        assert (project/'after-audit-failure').read_text()=='graceful export'
    if os.name != 'nt' and a.arch == 'aarch64' and a.payload_mode == '9p':
        # Stop only the host reader. Guest production then fills both bounded
        # transport and ring buffers, giving a real kernel loss scenario.
        overflow_log = root/'overflow.jsonl'
        flood = failure_code.replace('before-audit-failure','before-overflow').replace('after-audit-failure','after-overflow')
        proc = subprocess.Popen(base + ['--initrd',str((a.assets/'agents.img').resolve()),
                '--audit-log',str(overflow_log),'--','python3','-c',flood],
                stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
        try:
            deadline = time.monotonic()+60
            while not overflow_log.exists() or 'connect_attempt' not in overflow_log.read_text():
                assert proc.poll() is None,proc.communicate()
                assert time.monotonic()<deadline,'no connect audit event'
                time.sleep(0.05)
            proc.send_signal(signal.SIGSTOP)
            time.sleep(8)
            proc.send_signal(signal.SIGCONT)
            stdout,stderr = proc.communicate(timeout=40)
            assert proc.returncode==125,(proc.returncode,stderr)
            assert (project/'after-overflow').read_text()=='graceful export'
            completion = json.loads(overflow_log.read_text().splitlines()[-1])
            assert not completion['complete'] and completion['lost']>0,completion
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGCONT)
                proc.kill()
                proc.wait()
    missing_log = root/'unavailable.jsonl'
    result = subprocess.run(base + ['--initrd',str((a.assets/'initramfs.img').resolve()),
            '--audit-log',str(missing_log),'--','true'],input=b'',capture_output=True,env=env,timeout=100)
    assert result.returncode==125,result.stderr
    assert b'audit collector unavailable' in result.stderr,result.stderr
    assert not json.loads(missing_log.read_text().splitlines()[-1])['complete']
print('real VM audit lifecycle, namespaces, connects, BPF isolation, fault shutdown and writeback passed')
