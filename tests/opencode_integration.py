"""Real OpenCode headless tool execution against a guest-local fake provider.

No host credentials, external network capabilities, or real model calls.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--qbox', type=Path, required=True)
p.add_argument('--assets', type=Path, required=True)
p.add_argument('--arch', choices=('aarch64','x86_64'), default='aarch64')
p.add_argument('--accel', choices=('auto','tcg'), default='auto')
p.add_argument('--payload-mode', choices=('9p','initrd'), default='9p')
p.add_argument('--audit', action='store_true')
a = p.parse_args()
job_timeout = 150 if a.arch == 'x86_64' and a.accel == 'tcg' else 45
# This fixture runs *inside* the VM: loopback never reaches a host server.
fixture = r'''import json,subprocess,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
requests=[]
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_POST(self):
  request=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
  requests.append(request)
  assert self.path=='/v1/chat/completions',self.path
  tools=request.get('tools',[])
  called=any(m.get('role')=='tool' for m in request['messages'])
  use_tool=any(t['function']['name']=='bash' for t in tools) and not called
  message={'role':'assistant','content':'QBox test complete'}
  reason='stop'
  if use_tool:
   message={'role':'assistant','content':None,'tool_calls':[{'index':0,'id':'call_qbox','type':'function','function':{
    'name':'bash','arguments':json.dumps({'command':'printf qbox-opencode-ok > opencode-result','description':'Write integration result'})}}]}
   reason='tool_calls'
  if request.get('stream'):
   payload='data: '+json.dumps({'id':'chatcmpl-qbox','object':'chat.completion.chunk','created':1,'model':'test',
    'choices':[{'index':0,'delta':message,'finish_reason':None}]})+'\n\n'
   payload+='data: '+json.dumps({'id':'chatcmpl-qbox','object':'chat.completion.chunk','created':1,'model':'test',
    'choices':[{'index':0,'delta':{},'finish_reason':reason}]})+'\n\ndata: [DONE]\n\n'
   kind='text/event-stream'
  else:
   payload=json.dumps({'id':'chatcmpl-qbox','object':'chat.completion','created':1,'model':'test',
    'choices':[{'index':0,'message':message,'finish_reason':reason}],
    'usage':{'prompt_tokens':1,'completion_tokens':1,'total_tokens':2}})
   kind='application/json'
  body=payload.encode();self.send_response(200);self.send_header('Content-Type',kind)
  self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
config={'model':'qbox-test/test','autoupdate':False,'share':'disabled','permission':{'bash':'allow'},
 'provider':{'qbox-test':{'npm':'@ai-sdk/openai-compatible','name':'QBox test','options':{
 'baseURL':'http://127.0.0.1:'+str(server.server_port)+'/v1','apiKey':'test-only'},
 'models':{'test':{'name':'Test','limit':{'context':32000,'output':2048}}}}}}
Path('opencode.json').write_text(json.dumps(config))
result=subprocess.run(['opencode','run','--pure','--model','qbox-test/test','--format','json',
 'Write opencode-result using the bash tool'],capture_output=True,timeout=JOB_TIMEOUT)
print(result.stdout.decode(),end='');print(result.stderr.decode(),end='')
assert result.returncode==0,(result.returncode,result.stderr)
assert requests,'OpenCode did not call the local provider'
assert Path('opencode-result').read_text()=='qbox-opencode-ok',result.stdout
assert any(m.get('role')=='tool' for r in requests for m in r['messages']),'tool result not returned to provider'
server.shutdown()
'''
with tempfile.TemporaryDirectory(prefix='qbox-opencode-', dir='/tmp') as directory:
    root = Path(directory)
    project = root/'project'
    project.mkdir()
    log = root/'audit.jsonl'
    fixture = fixture.replace('timeout=JOB_TIMEOUT','timeout='+str(job_timeout))
    command = [str(a.qbox.resolve()),'agent','--workspace',str(project),'--arch',a.arch,
               '--accel',a.accel,'--payload-mode',a.payload_mode,'--timeout',str(job_timeout+90),
               '--kernel',str((a.assets/'vmlinuz').resolve()),'--initrd',str((a.assets/'agents.img').resolve())]
    if a.audit: command += ['--audit-log',str(log)]
    result = subprocess.run(command+['--','python3','-c',fixture],input=b'',capture_output=True,timeout=job_timeout+100)
    assert result.returncode==0,(result.returncode,result.stdout,result.stderr)
    assert (project/'opencode-result').read_text()=='qbox-opencode-ok'
    if a.audit:
        records=[json.loads(line) for line in log.read_text().splitlines()]
        assert records[-1]['complete'],records[-1]
        assert any(r.get('address')=='127.0.0.1' for r in records),'local provider connection absent'
        assert any(r.get('comm')=='bash' and r['event']=='exec' for r in records),'tool execution absent'
print('OpenCode headless prompt, streamed tool call, guest-local provider, audit and host writeback passed')
