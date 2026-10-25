#!/usr/bin/python3 -I
"""Root-only VM227 two-port production runner; credentials never enter tools."""
import argparse,fcntl,hashlib,json,os,sys,time,urllib.request,urllib.error,uuid
from pathlib import Path
MACHINE='5f20c5fdcf174e398af109874389db81'
PROFILE='/etc/virp-c-cage/twoport-runner.json'
ROOT='/var/lib/virp-cage-twoport'
MODEL='gpt-6-astra'

def main():
 if os.geteuid()!=0 or Path('/etc/machine-id').read_text().strip()!=MACHINE:raise ValueError('wrong_open_runner_identity')
 os.umask(0o077);sys.dont_write_bytecode=True
 sys.path.insert(0,str(Path(__file__).absolute().parent))
 from port_owner_service import protected
 from port_provider import NoRedirect,ENDPOINT,unique
 from twoport_transport import CanaryTransport
 from helper import durable_write
 from open_canary import validate
 from twoport_model import run,TOOL,INSTRUCTIONS
 protected(__file__);raw=protected(PROFILE,secret=True).read_bytes();p=json.loads(raw)
 if set(p)!={'schema','model','files'} or p['schema']!='kestrel-open-cage/1' or p['model']!=MODEL:raise ValueError('invalid_open_runner_profile')
 def guard():
  if protected(PROFILE,secret=True).read_bytes()!=raw:raise ValueError('runner_profile_changed')
  for name,digest in p['files'].items():
   if hashlib.sha256(protected(name).read_bytes()).hexdigest()!=digest:raise ValueError('runner_file_changed')
 guard();root=protected(ROOT,secret=True,directory=True)
 parser=argparse.ArgumentParser();g=parser.add_mutually_exclusive_group(required=True);g.add_argument('--prompt');g.add_argument('--command');a=parser.parse_args()
 with (root/'lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  directory=root/uuid.uuid4().hex;directory.mkdir(mode=0o700);(directory/'transport').mkdir(mode=0o700)
  transport=CanaryTransport(directory/'transport',request_validator=validate);index=0
  def record(event):
   nonlocal index
   index+=1;durable_write(directory/(str(index).zfill(4)+'.json'),json.dumps(event).encode())
  def call(q):guard();return transport.call(q)
  if a.command:
   q=validate({'operation':'port_open_execute','request_id':uuid.uuid4().hex,'command':a.command,'rationale':'Owner-directed two-port production qualification through the C gate.'});record({'type':'helper_request','request':q});result=call(q)
  else:
   key=protected('/etc/openai-cage/api.key',secret=True).read_text().strip()
   opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
   def provider(inputs):
    guard();body=json.dumps({'model':MODEL,'reasoning':{'effort':'low'},'store':False,'instructions':INSTRUCTIONS,'input':inputs,'tools':[TOOL],'parallel_tool_calls':False,'max_output_tokens':1800}).encode()
    if len(body)>524288:raise ValueError('model_input_limit')
    req=urllib.request.Request(ENDPOINT,data=body,headers={'Authorization':'Bearer '+key,'Content-Type':'application/json'},method='POST')
    try:
     with opener.open(req,timeout=45) as response:
      if response.geturl()!=ENDPOINT or response.status!=200:raise ValueError('unexpected_provider_response')
      data=response.read(131073)
    except urllib.error.HTTPError as e:
     code=e.code;e.close();raise ValueError('provider_http_'+str(code)) from None
    if len(data)>131072:raise ValueError('provider_output_limit')
    return json.loads(data,object_pairs_hook=unique)
   result=run(provider,call,a.prompt,record,max_turns=28)
  durable_write(directory/'result.json',json.dumps(result).encode());print(json.dumps({'record':str(directory),'result':result}))
if __name__=='__main__':
 try:main()
 except Exception as e:print(json.dumps({'ok':False,'error_type':type(e).__name__,'outcome':'inspect retained attempts; no automatic retry'}));sys.exit(1)
