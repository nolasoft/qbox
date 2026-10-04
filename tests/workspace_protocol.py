"""Exercise the actual guest archive importer/exporter without a VM."""
from pathlib import Path
import os
import struct
import subprocess
import sys
import tempfile

fixture=sys.argv[1]
def record(kind,path,data=b'',mode=0o644):
    path=path.encode()
    return struct.pack('!BIIQ',kind,mode,len(path),len(data))+path+data
def archive(records):return b'QBWS0001'+b''.join(records)+bytes(17)
with tempfile.TemporaryDirectory() as directory:
    root=Path(directory)
    source=root/'input'
    def check(data,expected):
        source.write_bytes(data)
        with tempfile.TemporaryDirectory(dir=root) as target:
            result=subprocess.run([fixture,'import',str(source),target])
            assert result.returncode==expected,data
            if not expected:
                assert (Path(target)/'dir'/'binary').read_bytes()==bytes(range(256))
                assert os.readlink(Path(target)/'link')=='dir/binary'
                returned=root/'returned'
                assert subprocess.run([fixture,'export',str(returned),target]).returncode==0
                assert bytes(range(256)) in returned.read_bytes()
    valid=[record(1,'dir',mode=0o755),record(2,'dir/binary',bytes(range(256))),record(3,'link',b'dir/binary',0o777)]
    check(archive(valid),0)
    for path in ('../outside','/absolute','dir/../../outside','a\\b','a//b'):
        check(archive([record(2,path,b'evil')]),1)
    check(archive([record(3,'link',b'../outside',0o777)]),1)
    check(archive([record(3,'alias',b'.',0o777),record(3,'chained',b'alias/..',0o777)]),1)
    check(archive([record(3,'link',b'dir',0o777),record(2,'link/child',b'evil')]),1)
    check(archive([record(2,'duplicate'),record(2,'duplicate')]),1)
    check(archive(valid)+b'trailing',1)
    check(archive(valid)[:-1],1)
    check(b'wrong magic',1)
    assert not (root/'outside').exists()
print('guest workspace roundtrip, binary contents, relative symlinks, traversal and malformed archive checks passed')
