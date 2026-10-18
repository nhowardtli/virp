#!/usr/bin/python3 -I
"""Fixed VM105 lab entrypoint. Test approval only; never install in production.

The SSH forced command must authenticate virp-cage-test before its fixed sudo
wrapper invokes this file without arguments. No caller-selected paths, targets,
keys or lease lengths. No lease renewal, recovery-marker clearing or deployment.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

MACHINE='29f08b6f35114d0c8b5909eb8a26ad60'
TARGET={'device':'kestrel-ios','host':'192.168.255.10','port':'Ethernet0/1','device_node_id':260,'transport_port':22}
PRODUCER='e054b6cfbff8423fe82780e6f8bee02348c8f07ca9819cadc58d5d019e0d2de7'
TEST_PUBLIC='6a0e1c17b9eb7fd0a3bc2e92a5fbf79dd18e06c9b8001a4d5bd95fcdf67f9f83'
BINARY='/opt/virp-canary/bin/virp-onode-prod'
CONFIG='/etc/virp-canary/devices.json'
PUBLIC='/etc/virp-canary/chain-sign.pub'
SOCKET='/run/virp-canary/onode.sock'
CHAIN='/var/lib/virp-canary/chain.db'
SCOPE='/var/lib/virp-cml-phase11'
PROFILE='/etc/virp-canary/port-helper.json'
KEY='/root/canary-test-approver.key'
ARGV=[BINARY,'-3','-k','/etc/virp-canary/onode.key','-d',CONFIG,'-s',SOCKET,
 '-n','104','-c',CHAIN,'-C','/etc/virp-canary/chain.key','-S','/etc/virp-canary/chain-sign.key',
 '-a','/var/lib/virp-canary/approvals','-A','/etc/virp-canary/approvers.json','-E','cml-v3-20261016']
MODULES=frozenset(('helper.py','recovery.py','port_authorize.py','port_canary_owner.py',
 'port_canary_service.py','port_challenge.py','port_duo.py','port_endpoint.py','port_evidence.py',
 'port_flow.py','port_ledger.py','port_native.py','port_native_approval.py','port_owner.py',
 'port_owner_service.py','port_plan.py','port_prepare.py','port_result.py','port_runtime.py',
 'port_scope.py','port_services.py','port_transaction.py'))

class HostRefused(ValueError):pass

def protect(path,*,secret=False,directory=False):
 # Bootstrap protection uses only the standard library, before importing any
 # local executable module or reading any private key. Reject symlink parents.
 p=Path(path)
 if not p.is_absolute():raise HostRefused('unprotected_path')
 for candidate in (p,*p.parents):
  info=candidate.lstat()
  if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise HostRefused('unprotected_path')
 info=p.stat()
 if directory and not stat.S_ISDIR(info.st_mode):raise HostRefused('expected_directory')
 if not directory and not stat.S_ISREG(info.st_mode):raise HostRefused('expected_regular_file')
 if secret and info.st_mode&0o077:raise HostRefused('secret_permissions_too_broad')
 return p

def validate_profile(p):
 try:
  if set(p)!={'schema','runtime','lease_seconds','chain_session','protected_ports','module_sha256'} or p['schema']!='kestrel-port-canary/1':raise ValueError()
  if type(p['lease_seconds'])is not int or not 1<=p['lease_seconds']<=36000:raise ValueError()
  if not re.fullmatch('kestrel-cml-port-[a-z0-9-]{1,80}',p['chain_session']):raise ValueError()
  if not isinstance(p['protected_ports'],list) or any(x!='Ethernet0/1' for x in p['protected_ports']):raise ValueError()
  if set(p['module_sha256'])!=MODULES or any(not re.fullmatch('[a-f0-9]{64}',v) for v in p['module_sha256'].values()):raise ValueError()
  r=p['runtime']
  fixed={'machine_id':MACHINE,'sudo_user':'virp-cage-test','requester':'virp-kreq','requester_uid':980,
   'daemon_uid':995,'target':TARGET,'public_key_hex':PRODUCER,'service':'virp-canary',
   'binary':BINARY,'config':CONFIG,'public_key':PUBLIC}
  if any(type(r[k])is not type(v) or r[k]!=v for k,v in fixed.items()):raise ValueError()
  if r['argv']!=ARGV:raise ValueError()
 except (KeyError,TypeError,ValueError,IndexError):raise HostRefused('invalid_fixed_canary_profile') from None

def decode_test_key(raw,public=bytes.fromhex(TEST_PUBLIC)):
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
 from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
 if len(raw)!=64 or raw[32:]!=public:raise HostRefused('canary_test_key_pin_mismatch')
 key=Ed25519PrivateKey.from_private_bytes(raw[:32])
 if key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)!=public:raise HostRefused('canary_test_key_pin_mismatch')
 return key

class CanaryClient:
 def __init__(self,store):self.store=store
 def call(self,q):
  from port_owner_service import dispatch
  if isinstance(q,dict) and set(q)=={'action','transaction_id'} and q['action']=='authorize':
   return {'ok':True,'transaction_id':q['transaction_id'],**self.store.authorize(q['transaction_id'])}
  return dispatch(q,self.store,lambda:None,{'kestrel-ios'})

def main():
 if len(sys.argv)!=1:raise HostRefused('canary_arguments_denied')
 if os.geteuid()!=0 or os.environ.get('SUDO_USER')!='virp-cage-test' or Path('/etc/machine-id').read_text().strip()!=MACHINE:raise HostRefused('canary_host_identity_mismatch')
 os.umask(0o077)
 protect(__file__)
 p=json.loads(protect(PROFILE,secret=True).read_bytes());validate_profile(p)
 module_dir=Path(__file__).absolute().parent
 for name,digest in p['module_sha256'].items():
  if hashlib.sha256(protect(module_dir/name).read_bytes()).hexdigest()!=digest:raise HostRefused('canary_module_pin_mismatch')
  # Recheck executable module bytes on every subsequent scope check, too.
  path=str(module_dir/name)
  if path in p['runtime']['files'] and p['runtime']['files'][path]!=digest:raise HostRefused('canary_module_pin_mismatch')
  p['runtime']['files'][path]=digest
 sys.path.insert(0,str(module_dir))
 from helper import Socket
 from recovery import Ledger,RequesterSocket
 from port_canary_owner import CanaryOwnerRequests
 from port_endpoint import dispatch,validate_request
 from port_ledger import EventLedger
 from port_native import NativePort
 from port_runtime import RuntimePins
 from port_scope import ScopeGuard
 from port_services import PortServices
 from port_transaction import Transactions
 raw=sys.stdin.buffer.read(4097)
 if len(raw)>4096:raise HostRefused('canary_request_too_large')
 q=json.loads(raw);validate_request(q)
 runtime=RuntimePins(p['runtime'],protect=protect)
 scope=ScopeGuard(SCOPE,check_runtime=runtime,protect=protect)
 with scope.locked():
  # Refuse expired work authority, STOP/pending and wrong binaries before
  # opening mutable state or loading the private test approver key.
  scope.check()
  root=Path(SCOPE);protect(root/'records',secret=True,directory=True)
  protect(root/'v3-recovery',secret=True,directory=True)
  for filename in ('port-transactions.db','port-test-owner.db'):
   for suffix in ('','-wal','-shm','-journal'):
    f=root/(filename+suffix)
    if os.path.lexists(f):protect(f,secret=True)
  key=decode_test_key(protect(KEY,secret=True).read_bytes())
  public=bytes.fromhex(TEST_PUBLIC);producer=bytes.fromhex(PRODUCER)
  boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  execute=RequesterSocket(SOCKET,'virp-kreq',980);control=Socket(SOCKET)
  ledger=Ledger(CHAIN,execute,producer,append_transport=control)
  events=EventLedger(CHAIN,execute,producer,p['chain_session'],append_transport=control)
  tx=Transactions(str(root/'port-transactions.db'),public,owner='canary-test-approver',boot_id=boot,
    max_lease_seconds=p['lease_seconds'],required_approval_method='test')
  owner=None
  try:
   owner=CanaryOwnerRequests(str(root/'port-test-owner.db'),public,key.sign,boot_id=boot,max_lease_seconds=p['lease_seconds'],
    producers={'kestrel-ios':{'public_key':producer,'node_id':260,'chain_session':p['chain_session']}})
   def native(body):
    return NativePort(body=body,transport=execute,control_transport=control,ledger=ledger,
     records=root/'records',recovery_dir=root/'v3-recovery',public_key=producer,node_id=260,
     chain_session=p['chain_session'],approval_session='approval:kestrel-ios@cml-v3-20261016',
     approver_public_key=public,operator='canary-test-approver',guard=scope.check,stop=scope.stop)
   def bootstrap(read):
    # Explicit lab authority for the one YELLOW config read. The model cannot
    # provide a command/challenge and production has no equivalent auto-grant.
    if read.body!={'target':TARGET}:raise HostRefused('canary_bootstrap_target_mismatch')
    command='show running-config interface Ethernet0/1'
    pid=read.propose(command)['reference']['proposal_id'];challenge=read.challenge(pid,command)
    scope.check();read.submit(challenge,key.sign(bytes.fromhex(challenge['canonical'])))
    return pid
   services=PortServices(tx,events,CanaryClient(owner),scope,TARGET,native,bootstrap,protected_ports=p['protected_ports'])
   result=dispatch(q,services,scope,lease_seconds=p['lease_seconds'])
   print(json.dumps(result))
  finally:
   if owner is not None:owner.close()
   tx.close()

if __name__=='__main__':
 try:main()
 except Exception as error:
  # Never print a traceback or arbitrary exception text containing key/config
  # data. Known structured refusals contain only fixed reason identifiers.
  known=isinstance(error,HostRefused) or (type(error).__module__=='port_transaction' and type(error).__name__=='Refused')
  print(json.dumps({'ok':False,'error':str(error) if known else type(error).__name__}))
  sys.exit(1)
