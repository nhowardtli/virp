"""Fixed VM227-to-VM105 transport with retained, non-retried attempts.

The root runner owns this adapter and the SSH key. A wait timeout does not kill
the SSH process, resend input, or imply remote completion. Inspection reports
local process evidence only; it never releases a runner/server recovery latch.
"""
import hashlib,json,math,os,re,subprocess,time
from pathlib import Path
from helper import durable_write
from port_owner_service import protected
from port_runner import validate,encode

KEY='/etc/virp-cml-cage/transport.key'
KNOWN_HOSTS='/etc/virp-cml-cage/known_hosts'
LIMIT_EXEC=('import os,resource,signal,sys;'
 'resource.setrlimit(resource.RLIMIT_CORE,(0,0));'
 'resource.setrlimit(resource.RLIMIT_FSIZE,(65536,65536));'
 'signal.signal(signal.SIGXFSZ,signal.SIG_DFL);'
 'os.execve(sys.argv[1],sys.argv[1:],os.environ)')

class TransportRefused(ValueError):pass

def argv():
 return ['/usr/bin/ssh','-T','-F','/dev/null','-o','BatchMode=yes','-o','IdentitiesOnly=yes',
  '-o','IdentityAgent=none','-o','StrictHostKeyChecking=yes','-o','UpdateHostKeys=no',
  '-o','UserKnownHostsFile='+KNOWN_HOSTS,'-o','GlobalKnownHostsFile=/dev/null',
  '-o','ForwardAgent=no','-o','ClearAllForwardings=yes','-o','ProxyCommand=none',
  '-o','ControlMaster=no','-o','ControlPath=none','-o','ConnectTimeout=5',
  '-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no',
  '-o','KbdInteractiveAuthentication=no','-i',KEY,'-p','1122','virp-cage-test@10.0.50.105','fixed-read']

def process_identity(pid):
 try:raw=(Path('/proc')/str(pid)/'stat').read_bytes()
 except FileNotFoundError:return None
 tail=raw.rsplit(b')',1)[1].split()
 return {'start_ticks':int(tail[19]),'state':tail[0].decode('ascii')}

def unique(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise ValueError('duplicate_key')
  result[key]=value
 return result

class CanaryTransport:
 def __init__(self,root,*,wait_seconds=60,protect=protected,identity=os.geteuid):
  if identity()!=0:raise TransportRefused('trusted_runner_requires_root')
  if type(wait_seconds) not in (int,float) or not math.isfinite(wait_seconds) or not 0<wait_seconds<=60:raise TransportRefused('invalid_observation_wait')
  self.root=protect(root,secret=True,directory=True);self.protect=protect;self.wait=wait_seconds
  self.protect(KEY,secret=True);self.protect(KNOWN_HOSTS)
  self.command=argv();self.processes={}
  self.boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
 def attempt(self,rid):
  if not isinstance(rid,str) or not re.fullmatch('[a-f0-9]{32}',rid):raise TransportRefused('invalid_transport_request_id')
  return self.root/rid
 def call(self,q):
  validate(q);rid=q['request_id'];directory=self.attempt(rid)
  self.protect(self.root,secret=True,directory=True)
  self.protect(KEY,secret=True);self.protect(KNOWN_HOSTS)
  try:directory.mkdir(mode=0o700)
  except FileExistsError:raise TransportRefused('attempt_already_exists') from None
  durable_write(directory/'request.json',encode(q)+b'\n')
  durable_write(directory/'launch-intent.json',encode({'request_id':rid,'boot_id':self.boot,'argv_sha256':hashlib.sha256(encode(self.command)).hexdigest(),'time_ns':time.time_ns()}))
  # Regular files survive the runner's exit and avoid a parent pipe closure
  # cancelling a helper that is still completing its authorized transaction.
  try:
   with open(directory/'request.json','rb') as input_file,open(directory/'stdout','xb') as output,open(directory/'stderr','xb') as error:
    os.chmod(directory/'stdout',0o600);os.chmod(directory/'stderr',0o600)
    # Limit retained stdout/stderr to64KiB each. An overflow is a transport
    # failure with unresolved intent, never a fabricated device E_SIZE result.
    launch=['/usr/bin/python3','-I','-c',LIMIT_EXEC,*self.command]
    proc=subprocess.Popen(launch,stdin=input_file,stdout=output,stderr=error,
     start_new_session=True,close_fds=True,cwd='/',env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'})
   self.processes[rid]=proc
   identity=process_identity(proc.pid)
   durable_write(directory/'process.json',encode({'pid':proc.pid,'boot_id':self.boot,'identity':identity,'request_id':rid}))
  except Exception:
   raise TransportRefused('transport_launch_unresolved') from None
  try:proc.wait(timeout=self.wait)
  except subprocess.TimeoutExpired:
   if proc.poll() is None:
    durable_write(directory/'wait-expired.json',encode({'request_id':rid,'pid':proc.pid,'time_ns':time.time_ns(),'action':'none; original process retained'}))
    raise TransportRefused('transport_still_running') from None
  self.record_exit(rid,proc.returncode)
  if proc.returncode!=0:raise TransportRefused('transport_exit_unresolved')
  path=self.protect(directory/'stdout',secret=True)
  with path.open('rb') as f:raw=f.read(8193)
  if len(raw)>8192:raise TransportRefused('transport_reply_oversized')
  try:reply=json.loads(raw,object_pairs_hook=unique)
  except (ValueError,UnicodeError):raise TransportRefused('invalid_transport_reply') from None
  if not isinstance(reply,dict):raise TransportRefused('invalid_transport_reply')
  return reply
 def record_exit(self,rid,code):
  path=self.attempt(rid)/'exit.json';body={'request_id':rid,'returncode':code}
  if os.path.lexists(path):
   if json.loads(self.protect(path,secret=True).read_bytes())!=body:raise TransportRefused('transport_exit_record_changed')
  else:durable_write(path,encode(body))
 def inspect(self,rid):
  directory=self.protect(self.attempt(rid),secret=True,directory=True)
  record=directory/'process.json'
  if not os.path.lexists(record):return {'request_id':rid,'state':'launch_unresolved','outcome':'unresolved'}
  p=json.loads(self.protect(record,secret=True).read_bytes())
  if p['boot_id']!=Path('/proc/sys/kernel/random/boot_id').read_text().strip():return {'request_id':rid,'state':'host_rebooted','outcome':'unresolved'}
  child=self.processes.get(rid)
  if child is not None and child.poll() is not None:self.record_exit(rid,child.returncode)
  exit_path=directory/'exit.json'
  if os.path.lexists(exit_path):
   value=json.loads(self.protect(exit_path,secret=True).read_bytes())
   return {'request_id':rid,'state':'exited','returncode':value['returncode'],'outcome':'requires_bound_reply_and_server_evidence'}
  live=process_identity(p['pid'])
  if live is None:state='not_running'
  elif p['identity'] is None or live['start_ticks']!=p['identity']['start_ticks']:state='pid_identity_changed'
  elif live['state']=='Z':state='exited_unreaped'
  else:state='running'
  return {'request_id':rid,'pid':p['pid'],'state':state,'outcome':'unresolved'}
