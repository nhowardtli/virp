#!/usr/bin/python3 -I
"""Root-only VM227 canary qualification entrypoint, source-only until deployed.

The operator chooses one finite operation. Model tools never receive shell,
private API/SSH keys, profile paths, target selection or approval authority.
No lease renewal, deployment, recovery-latch clearing or production route.
"""
import argparse,fcntl,hashlib,json,os,re,stat,sys,uuid
from pathlib import Path

MACHINE='5f20c5fdcf174e398af109874389db81'
MODEL='gpt-6-astra'
SHARED_CONFIG_MODEL='gpt-4.1-mini-2025-04-14'
CONFIG='/etc/openai-cage/api.json'
API_KEY='/etc/openai-cage/api.key'
KNOWN_HOSTS='/etc/virp-cml-cage/known_hosts'
CONFIG_SHA='154479036de9bdb6c35b3961af83c28d7369d01d536652f4c78323069ec20823'
HOSTS_SHA='ecded7c1fb0e8dc4433eeaa8e2a0edb5ba4034ecdd67d945d6301c930a046ff2'
PROFILE='/etc/virp-cml-cage/port-runner.json'
ROOT='/var/lib/virp-cml-cage/port'
MODULES=frozenset(('port_cage_service.py','port_model.py','port_provider.py','port_runner.py',
 'port_transport.py','port_owner_service.py','port_plan.py','helper.py'))

class CageRefused(ValueError):pass

def protected(path,*,secret=False,directory=False):
 p=Path(path)
 if not p.is_absolute():raise CageRefused('unprotected_cage_path')
 for item in (p,*p.parents):
  info=item.lstat()
  if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise CageRefused('unprotected_cage_path')
 info=p.stat()
 if directory and not stat.S_ISDIR(info.st_mode):raise CageRefused('expected_cage_directory')
 if not directory and not stat.S_ISREG(info.st_mode):raise CageRefused('expected_cage_file')
 if secret and info.st_mode&0o077:raise CageRefused('cage_secret_permissions_too_broad')
 return p

def validate_profile(p):
 try:
  expected={'schema','machine_id','model','api_config_sha256','known_hosts_sha256','module_sha256'}
  if set(p)!=expected or p['schema']!='kestrel-port-cage/1':raise ValueError()
  if (p['machine_id'],p['model'],p['api_config_sha256'],p['known_hosts_sha256'])!=(MACHINE,MODEL,CONFIG_SHA,HOSTS_SHA):raise ValueError()
  if set(p['module_sha256'])!=MODULES or any(not re.fullmatch('[a-f0-9]{64}',v) for v in p['module_sha256'].values()):raise ValueError()
 except (KeyError,TypeError,ValueError):raise CageRefused('invalid_fixed_cage_profile') from None

def main():
 if os.geteuid()!=0 or Path('/etc/machine-id').read_text().strip()!=MACHINE:raise CageRefused('cage_host_identity_mismatch')
 os.umask(0o077);sys.dont_write_bytecode=True;protected(__file__)
 profile_raw=protected(PROFILE,secret=True).read_bytes();p=json.loads(profile_raw);validate_profile(p)
 module_dir=Path(__file__).absolute().parent
 def guard():
  if os.geteuid()!=0 or Path('/etc/machine-id').read_text().strip()!=MACHINE:raise CageRefused('cage_host_identity_mismatch')
  if protected(PROFILE,secret=True).read_bytes()!=profile_raw:raise CageRefused('cage_profile_changed')
  for name,digest in p['module_sha256'].items():
   if hashlib.sha256(protected(module_dir/name).read_bytes()).hexdigest()!=digest:raise CageRefused('cage_module_changed')
  for path,digest in ((CONFIG,CONFIG_SHA),(KNOWN_HOSTS,HOSTS_SHA)):
   if hashlib.sha256(protected(path,secret=True).read_bytes()).hexdigest()!=digest:raise CageRefused('cage_config_or_host_pin_changed')
  if json.loads(protected(CONFIG,secret=True).read_bytes()).get('model')!=SHARED_CONFIG_MODEL:raise CageRefused('cage_model_changed')
 guard();sys.path.insert(0,str(module_dir))
 from helper import durable_write
 from port_model import run
 from port_plan import OPS
 from port_provider import ResponsesProvider
 from port_runner import PortRunner,encode
 from port_transport import CanaryTransport
 parser=argparse.ArgumentParser(description=__doc__)
 action=parser.add_mutually_exclusive_group(required=True)
 action.add_argument('--operation',choices=sorted(OPS));action.add_argument('--inspect',metavar='REQUEST_ID')
 parser.add_argument('--prompt',default='Qualify the owner-selected canary port operation, verify it, then restore and verify the original baseline.')
 args=parser.parse_args()
 root=protected(ROOT,secret=True,directory=True)
 for name in ('journal','transport','transcripts'):protected(root/name,secret=True,directory=True)
 if args.inspect:
  # Read-only process inspection remains available while the model-run lock
  # is held. It never dispatches or releases an unresolved request.
  transport=CanaryTransport(root/'transport',protect=protected)
  print(json.dumps(transport.inspect(args.inspect)));return
 lock=root/'model.lock'
 if os.path.lexists(lock):protected(lock,secret=True)
 fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
 try:
  protected(lock,secret=True)
  try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
  except BlockingIOError:raise CageRefused('cage_model_run_active') from None
  transport=CanaryTransport(root/'transport',protect=protected)
  runner=PortRunner(root/'journal',protect=protected)
  transcript=root/'transcripts'/uuid.uuid4().hex;transcript.mkdir(mode=0o700)
  directory_fd=os.open(root/'transcripts',os.O_RDONLY|os.O_DIRECTORY)
  try:os.fsync(directory_fd)
  finally:os.close(directory_fd)
  index=0;provider=None
  def record(event):
   nonlocal index
   index+=1;durable_write(transcript/(f'{index:04d}.json'),encode(event))
  def model(inputs,allowed):
   nonlocal provider
   guard()
   if provider is None:
    # Lazy loading lets the controller restore a previously confirmed apply
    # without an API call. Keys are never passed to model inputs or tools.
    key=protected(API_KEY,secret=True).read_text().strip()
    provider=ResponsesProvider(MODEL,key,guard=guard)
   return provider(inputs,allowed)
  def call(q):guard();return transport.call(q)
  result=run(model,runner,call,operation=args.operation,prompt=args.prompt,record=record)
  durable_write(transcript/'result.json',encode(result))
  print(json.dumps({'transcript':str(transcript),'result':result}))
 finally:os.close(fd)

if __name__=='__main__':
 try:main()
 except Exception as error:
  print(json.dumps({'ok':False,'error':str(error) if isinstance(error,CageRefused) else type(error).__name__}))
  sys.exit(1)
