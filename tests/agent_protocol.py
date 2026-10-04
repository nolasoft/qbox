"""Real agent runner tests for guest command dispatch, cwd, export and a PTY."""
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile

runner=sys.argv[1]
def strings(items):
    return struct.pack('!I',len(items))+b''.join(struct.pack('!I',len(s))+s for s in items)
def exact(s,n):
    data=b''
    while len(data)<n:
        b=s.recv(n-len(data))
        if not b: raise EOFError()
        data+=b
    return data
def receive(s):
    h=exact(s,5)
    return h[0],exact(s,struct.unpack('!I',h[1:])[0])
def send(s,kind,data=b''):
    s.sendall(bytes([kind])+struct.pack('!I',len(data))+data)
def run(code,tty=False,interactive=False):
    with tempfile.TemporaryDirectory() as root:
        workspace=Path(root)/'project'
        workspace.mkdir()
        (workspace/'original').write_text('before')
        a,b=socket.socketpair()
        a.settimeout(15)
        p=subprocess.Popen([runner,'--test-agent',str(b.fileno()),sys.executable,str(workspace)],pass_fds=(b.fileno(),))
        b.close()
        try:
            assert receive(a)==(7,b'test')
            req=struct.pack('!III',int(tty),33,101)+strings([sys.executable.encode(),b'-c',code.encode()])+strings([b'LANG=C'])
            send(a,8,req)
            if not tty:send(a,2)
            output=b''
            archive=b''
            done=False
            responded=False
            while True:
                kind,data=receive(a)
                if kind in (3,4):
                    output+=data
                    if interactive and not responded and b'ready' in output:
                        send(a,11,struct.pack('!II',17,63))
                        send(a,2,b'terminal input\n')
                        responded=True
                elif kind==9:archive+=data
                elif kind==10:
                    assert data==struct.pack('!I',0)
                    done=True
                elif kind==5:
                    assert done and struct.unpack('!II',data)==(0,0)
                    break
                else:raise AssertionError(kind)
            assert archive.startswith(b'QBWS0001')
            assert p.wait(timeout=5)==0
            return output,archive
        finally:
            a.close()
            if p.poll() is None:p.kill()
            p.wait()

out,archive=run("import os;assert os.path.basename(os.getcwd())=='project';open('original','w').write('after');open('created','wb').write(bytes(range(256)));os.mkdir('.git');open('.git/secret','w').write('must not export');print('headless ok')")
assert out==b'headless ok\n'
assert b'after' in archive and bytes(range(256)) in archive and b'must not export' not in archive
out,archive=run("import os;assert all(os.isatty(i) for i in range(3));assert os.get_terminal_size().columns==101;assert os.get_terminal_size().lines==33;print('tty ok')",tty=True)
assert out==b'tty ok\r\n',out
out,archive=run("import os,sys;print('ready',flush=True);assert sys.stdin.readline()=='terminal input\\n';assert os.get_terminal_size().columns==63;assert os.get_terminal_size().lines==17;print('input and resize ok')",tty=True,interactive=True)
assert b'input and resize ok\r\n' in out,out
print('agent dispatch, working directory, binary workspace export, protected paths and PTY checks passed')
