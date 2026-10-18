#!/usr/bin/python3 -I
"""Temporary VM105 non-BLACK lab endpoint. No approvals, no production route.

The native RED ceiling decides command risk. This helper fixes identity/target,
records intent and v3 output, and retains unresolved execution evidence.
"""
import hashlib,json,os,re,sqlite3,sys,time,uuid
from pathlib import Path

MACHINE='29f08b6f35114d0c8b5909eb8a26ad60'
PROFILE='/etc/virp-canary/open-helper.json'
ROOT='/var/lib/virp-cml-phase11'
DEVICE='kestrel-ios'
UID=979
class OpenRefused(ValueError):pass

def validate(q):
 if not isinstance(q,dict) or set(q)!={'operation','request_id','rationale','command'}:raise OpenRefused('invalid_open_request')
 if q['operation']!='open_execute' or not isinstance(q['request_id'],str) or not re.fullmatch('[a-f0-9]{32}',q['request_id']):raise OpenRefused('invalid_open_request')
 if not isinstance(q['rationale'],str) or not 20<=len(q['rationale'])<=1000:raise OpenRefused('invalid_open_rationale')
 if not isinstance(q['command'],str) or not 1<=len(q['command'])<=1024 or any(ord(c)<32 or ord(c)>126 for c in q['command']):raise OpenRefused('invalid_open_command')
 return q

def main():
 if len(sys.argv)!=1 or os.geteuid()!=0 or os.environ.get('SUDO_USER')!='virp-cage-test' or Path('/etc/machine-id').read_text().strip()!=MACHINE:raise OpenRefused('open_identity_mismatch')
 os.umask(0o077)
 # This file is independently pinned by the root-controlled forced router.
 sys.path.insert(0,str(Path(__file__).absolute().parent))
 from port_owner_service import protected
 from port_scope import ScopeGuard
 from port_runtime import probe_service
 from recovery import RequesterSocket,Ledger,canonical
 from helper import Socket,execute_observed,durable_write
 protected(__file__);p=json.loads(protected(PROFILE,secret=True).read_bytes());original=canonical(p)
 if set(p)!={'schema','files','public_key','argv','authorization_sha256'} or p['schema']!='kestrel-open-canary/1':raise OpenRefused('invalid_open_profile')
 required={'/etc/virp-canary/devices.json','/opt/virp-canary/bin/virp-onode-prod'}
 modules=Path(__file__).absolute().parent
 required|={str(modules/n) for n in ('open_canary.py','helper.py','recovery.py','port_owner_service.py','port_scope.py','port_runtime.py','port_transaction.py','port_plan.py')}
 if not required<=set(p['files']) or not re.fullmatch('[a-f0-9]{64}',p['authorization_sha256']):raise OpenRefused('incomplete_open_pins')
 def guard():
  if canonical(json.loads(protected(PROFILE,secret=True).read_bytes()))!=original:raise OpenRefused('open_profile_changed')
  for name,digest in p['files'].items():
   if hashlib.sha256(protected(name).read_bytes()).hexdigest()!=digest:raise OpenRefused('open_runtime_changed')
  c=json.loads(protected('/etc/virp-canary/devices.json').read_bytes())
  if c.get('gate_default_mode')!='enforce' or c.get('evidence_required') is not True or c.get('socket_uid_tier_ceilings',{}).get(str(UID))!='red':raise OpenRefused('open_ceiling_changed')
  if len(c['devices'])!=1:raise OpenRefused('open_target_changed')
  d=c['devices'][0]
  if (d.get('hostname'),d.get('host'),d.get('port'),int(d['node_id'],16))!=(DEVICE,'192.168.255.10',22,260):raise OpenRefused('open_target_changed')
  live=probe_service('virp-canary');binary='/opt/virp-canary/bin/virp-onode-prod'
  if not live.get('active') or live['executable']!=binary or live['binary_sha256']!=p['files'][binary] or live['argv']!=p['argv'] or live['effective_uid']!=995:raise OpenRefused('open_process_changed')
 raw=sys.stdin.buffer.read(4097)
 if len(raw)>4096:raise OpenRefused('request_too_large')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise OpenRefused('duplicate_key')
   d[k]=v
  return d
 q=validate(json.loads(raw,object_pairs_hook=unique));scope=ScopeGuard(ROOT,check_runtime=guard,limit=256)
 with scope.locked():
  scope.check()
  # Serialize with the earlier transaction workflow, never interleave config.
  with sqlite3.connect('file:'+ROOT+'/port-transactions.db?mode=ro',uri=True) as db:
   if db.execute("select id from transactions where state not in ('restored','expired-before-apply','preflight-refused')").fetchone():raise OpenRefused('prior_transaction_open')
  scope.reserve({k:q[k] for k in ('operation','request_id','rationale')})
  transport=RequesterSocket('/run/virp-canary/onode.sock','virp-open-test',UID);control=Socket('/run/virp-canary/onode.sock')
  public=bytes.fromhex(p['public_key']);session='kestrel-open-canary-20261018'
  ledger=Ledger('/var/lib/virp-canary/chain.db',transport,public,control)
  intent={'schema':'kestrel-open-intent/1',**q,'device':DEVICE,'authorization_sha256':p['authorization_sha256'],'approval_mode':'owner-delegated-no-per-command-approval','time_ns':time.time_ns()}
  ledger.append(canonical(intent),session,'intent:'+q['request_id'])
  try:
   frame,result=execute_observed(transport,{'action':'execute','device':DEVICE,'command':q['command']},public_key=public,node_id=260,
    device_id=int.from_bytes(hashlib.sha256(DEVICE.encode()).digest()[:8],'big'),path=Path(ROOT)/'records'/(q['request_id']+'.open.frame'),chain_session=session,artifact_id='open:'+q['request_id'],recovery_dir=Path(ROOT)/'v3-recovery')
   receipt=ledger.verify(frame,session,'open:'+q['request_id'])
   if result.get('recovery_required'):scope.stop('open_outcome_unresolved')
   reply={'ok':result['subtype']==7,'request_id':q['request_id'],'command':q['command'],'result':result,'receipt':receipt,'approval_mode':intent['approval_mode']}
   durable_write(Path(ROOT)/'records'/(q['request_id']+'.open.result.json'),canonical(reply));print(json.dumps(reply))
  except BaseException:
   scope.stop('open_execution_interrupted');raise
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'ok':False,'error':str(e) if isinstance(e,OpenRefused) else type(e).__name__}));sys.exit(1)
