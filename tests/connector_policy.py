"""Policy checks against the actual helper; no external service needed."""
from pathlib import Path
import subprocess
import sys
import tempfile

connector=sys.argv[1]
for host,port in [('localhost','443'),('127.0.0.1','80'),('10.0.0.1','80'),('::1','80'),('example.com','0'),('bad/host','80')]:
    r=subprocess.run([connector,host,port],stdin=subprocess.DEVNULL,capture_output=True,timeout=15)
    assert r.returncode==1,(host,r.returncode,r.stdout,r.stderr)
    assert r.stdout==b'', 'connector diagnostics must not be written to stdout'
with tempfile.TemporaryDirectory() as directory:
    # A connector starting after teardown must not perform DNS or socket work.
    missing=Path(directory)/'alive'
    r=subprocess.run([connector,'1.1.1.1','80','--lease',str(missing)],capture_output=True,timeout=2)
    assert r.returncode==0
print('actual connector private DNS/literal denial and expired-lease checks passed')
