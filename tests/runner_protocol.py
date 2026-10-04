"""Exercise the real runner over a socketpair; no QEMU mock in this suite."""
import os
import signal
import socket
import struct
import subprocess
import sys
import threading

RUNNER = sys.argv[1]
def frame(kind, data=b''):
    return bytes([kind]) + struct.pack('!I', len(data)) + data
def read_exact(s, n):
    out = b''
    while len(out) < n:
        b = s.recv(n - len(out))
        if not b:
            raise EOFError('runner closed')
        out += b
    return out
def recv(s):
    h = read_exact(s, 5)
    return h[0], read_exact(s, struct.unpack('!I', h[1:])[0])
def strings(items):
    return struct.pack('!I', len(items)) + b''.join(struct.pack('!I', len(i)) + i for i in items)
def run(code, data=b'', expected=0, sig=None):
    a, b = socket.socketpair()
    a.settimeout(15)
    p = subprocess.Popen([RUNNER, '--test', str(b.fileno()), sys.executable], pass_fds=(b.fileno(),))
    b.close()
    try:
        assert recv(a) == (7, b'test')
        req = strings([sys.executable.encode(), b'-c', code.encode()]) + strings([b'LANG=C'])
        # Deliberately fragmented request/header tests incremental framing.
        request = frame(1, req)
        for byte in request:
            a.sendall(bytes([byte]))
        def send_input():
            for pos in range(0, len(data), 16384):
                a.sendall(frame(2, data[pos:pos+16384]))
            a.sendall(frame(2))
            if sig:
                a.sendall(frame(6, struct.pack('!I', sig)))
        writer = threading.Thread(target=send_input)
        writer.start()
        out, err = b'', b''
        while True:
            kind, body = recv(a)
            if kind == 3:
                out += body
            elif kind == 4:
                err += body
            elif kind == 5:
                status_kind, value = struct.unpack('!II', body)
                assert (status_kind, value) == ((1, sig) if sig else (0, expected)), (status_kind, value)
                break
            else:
                raise AssertionError(kind)
        writer.join(5)
        assert not writer.is_alive()
        assert p.wait(timeout=5) == 0
        return out, err
    finally:
        a.close()
        if p.poll() is None:
            p.kill()
        p.wait()

assert run("import os;os.write(1,b'hello\\n');os.write(2,b'error\\n')") == (b'hello\n', b'error\n')
run('raise SystemExit(42)', expected=42)
data = bytes(range(256)) * 32768
assert run('import os\nwhile True:\n b=os.read(0,16384)\n if not b: break\n os.write(1,b)', data)[0] == data
assert len(run("import os;os.write(1,b'x'*4000000);os.write(2,b'y'*4000000)")[0]) == 4000000
run('import time;time.sleep(60)', sig=signal.SIGTERM)
# Oversized frame and malformed EXEC both fail closed.
for request in (bytes([1])+struct.pack('!I',1048577), frame(1, struct.pack('!I',257))):
    a,b=socket.socketpair()
    a.settimeout(5)
    p=subprocess.Popen([RUNNER,'--test',str(b.fileno()),sys.executable],pass_fds=(b.fileno(),))
    b.close()
    assert recv(a)==(7,b'test')
    a.sendall(request)
    assert p.wait(timeout=5)==125
    a.close()
print('runner framing, binary echo, exit, signal, backpressure and malformed-frame checks passed')
