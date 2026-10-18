#!/usr/bin/python3 -I
"""Production two-port standing delegation. Root trusted adapter, no model creds."""
import hashlib,json,os,sys,time
from pathlib import Path
MACHINE='294b84478a324262bc7daea9bc314553'
PROFILE='/etc/virp-kestrel/twoport.json'
ROOT='/var/lib/virp-kestrel-twoport'
DEVICE='SW-3850'
UID=979

def main():
 if os.geteuid()!=0 or os.environ.get('SUDO_USER')!='virp-cage227' or Path('/etc/machine-id').read_text().strip()!=MACHINE:raise ValueError('twoport_identity_mismatch')
 os.umask(0o077);sys.dont_write_bytecode=True
 sys.path.insert(0,str(Path(__file__).absolute().parent))
 from port_owner_service import protected
 from standing_scope import StandingScope
 from twoport_plan import plan,PORTS
 from open_canary import validate
 from port_runtime import probe_service
 from recovery import RequesterSocket,Ledger,canonical
 from helper import Socket,execute_observed,durable_write
 protected(__file__);p=json.loads(protected(PROFILE,secret=True).read_bytes());original=canonical(p)
 if set(p)!={'schema','files','public_key','argv','authorization_sha256'} or p['schema']!='kestrel-twoport/1':raise ValueError('invalid_profile')
 def guard():
  if canonical(json.loads(protected(PROFILE,secret=True).read_bytes()))!=original:raise ValueError('profile_changed')
  for name,digest in p['files'].items():
   if hashlib.sha256(protected(name).read_bytes()).hexdigest()!=digest:raise ValueError('runtime_changed')
  old=Path('/var/lib/virp-cage227')
  if any(os.path.lexists(old/n) for n in ('STOP','v3-recovery/pending.json','description-grant.json')):raise ValueError('prior_scope_not_clear')
  c=json.loads(protected('/etc/virp-kestrel/devices.json').read_bytes())
  if c.get('gate_default_mode')!='enforce' or c.get('evidence_required') is not True or c.get('socket_uid_tier_ceilings',{}).get(str(UID))!='red':raise ValueError('ceiling_changed')
  if len(c['devices'])!=1:raise ValueError('target_changed')
  d=c['devices'][0]
  if (d.get('hostname'),d.get('host'),d.get('port'))!=(DEVICE,'10.0.10.2',2223):raise ValueError('target_changed')
  live=probe_service('virp-kestrel-candidate');binary='/usr/local/lib/virp-kestrel-v3/virp-onode-prod'
  if not live.get('active') or live['executable']!=binary or live['binary_sha256']!=p['files'][binary] or live['argv']!=p['argv'] or live['effective_uid']!=981:raise ValueError('process_changed')
 raw=sys.stdin.buffer.read(4097)
 if len(raw)>4096:raise ValueError('request_too_large')
 def unique(pairs):
  d={}
  for k,v in pairs:
   if k in d:raise ValueError('duplicate_key')
   d[k]=v
  return d
 q=validate(json.loads(raw,object_pairs_hook=unique));commands=plan(q['command'])
 scope=StandingScope(ROOT,check_runtime=guard,limit=512,binding={'device':DEVICE,'ports':list(PORTS),'authorization_sha256':p['authorization_sha256']})
 with scope.locked():
  scope.check()
  # Deployment starts read-only. Engineer must retain chained baselines and
  # install the exact reviewed active VLAN set before any configuration.
  if len(commands)>1:
   ready=json.loads(protected(ROOT+'/write-ready.json',secret=True).read_bytes())
   if ready['authorization_sha256']!=p['authorization_sha256'] or ready['ports']!=list(PORTS):raise ValueError('preflight_not_bound')
   line=commands[2]
   for prefix in ('switchport access vlan ','switchport trunk allowed vlan '):
    if line.startswith(prefix) and not set(map(int,line[len(prefix):].split(',')))<=set(ready['active_vlans']):raise ValueError('vlan_not_preflight_active')
  scope.reserve({k:q[k] for k in ('operation','request_id','rationale')})
  transport=RequesterSocket('/run/virp-kestrel/onode.sock','virp-twoport',UID);control=Socket('/run/virp-kestrel/onode.sock')
  public=bytes.fromhex(p['public_key']);session='kestrel-twoport-20261018'
  ledger=Ledger('/var/lib/virp-kestrel/chain.db',transport,public,control)
  ledger.append(canonical({'schema':'kestrel-twoport-intent/1',**q,'rendered':commands,'device':DEVICE,'authorization_sha256':p['authorization_sha256'],'authority':'standing-owner-delegation','lease_enforcement':'none; explicit standing scope','time_ns':time.time_ns()}),session,'intent:'+q['request_id'])
  results=[]
  try:
   for i,command in enumerate(commands):
    scope.check();aid=q['request_id']+'-'+str(i)
    frame,result=execute_observed(transport,{'action':'execute','device':DEVICE,'command':command},public_key=public,node_id=0x4b535452,
     device_id=int.from_bytes(hashlib.sha256(DEVICE.encode()).digest()[:8],'big'),path=Path(ROOT)/'records'/(aid+'.frame'),chain_session=session,artifact_id='twoport:'+aid,recovery_dir=Path(ROOT)/'v3-recovery')
    receipt=ledger.verify(frame,session,'twoport:'+aid);results.append({'command':command,'result':result,'receipt':receipt})
    if result.get('recovery_required') or result['subtype']!=7:
     scope.stop('twoport_exchange_failed');break
   ok=len(results)==len(commands) and all(x['result']['subtype']==7 and not x['result'].get('recovery_required') for x in results)
   reply={'ok':ok,'request_id':q['request_id'],'command':q['command'],'exchanges':results,'result':{'output':'\n'.join(x['result']['output'] for x in results),'recovery_required':not ok},'authority':'standing-owner-delegation'}
   durable_write(Path(ROOT)/'records'/(q['request_id']+'.result.json'),canonical(reply));print(json.dumps(reply))
  except BaseException:
   scope.stop('twoport_execution_interrupted');raise
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'ok':False,'error_type':type(e).__name__,'error':str(e) if type(e) is ValueError else 'inspect server retained evidence'}));sys.exit(1)
