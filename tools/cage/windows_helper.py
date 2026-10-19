#!/usr/bin/python3 -I
"""Trusted VM scope; all managed commands execute through native VIRP v3."""
import fcntl,hashlib,json,os,pathlib,sys,time
P=pathlib.Path;ROOT=P('/var/lib/virp-kestrel-windows-scope');PROFILE=P('/etc/virp-kestrel-windows/profile.json');MODULES='/usr/local/lib/virp-kestrel-windows'
def main():
 if os.geteuid()!=0 or os.environ.get('SUDO_USER')!='virp-cage227' or P('/etc/machine-id').read_text().strip()!='294b84478a324262bc7daea9bc314553':raise ValueError('caller_identity_denied')
 os.umask(0o077);sys.dont_write_bytecode=True
 sys.path.insert(0,MODULES)
 from windows_policy import validate,unique,COMMANDS,parse_native_output
 from port_owner_service import protected
 from port_runtime import probe_service
 from recovery import RequesterSocket,Ledger,canonical
 from helper import Socket,execute_observed,durable_write
 raw=sys.stdin.buffer.read(4097)
 if len(raw)>4096:raise ValueError('request_too_large')
 q=validate(json.loads(raw,object_pairs_hook=unique));p=json.loads(protected(PROFILE,secret=True).read_bytes())
 with open(ROOT/'lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  if (ROOT/'STOP').exists() or (ROOT/'v3-recovery/pending.json').exists():raise ValueError('scope_stopped_or_unresolved')
  for file,digest in p['files'].items():
   if hashlib.sha256(protected(file).read_bytes()).hexdigest()!=digest:raise ValueError('runtime_changed')
  live=probe_service('virp-kestrel-windows');binary='/usr/local/lib/virp-kestrel-v3/virp-onode-prod'
  if not live.get('active') or live['executable']!=binary or live['binary_sha256']!=p['files'][binary] or live['argv']!=p['argv'] or live['effective_uid']!=976:raise ValueError('process_changed')
  if len(list((ROOT/'records').glob('*.request.json')))>=256:raise ValueError('attempt_limit')
  durable_write(ROOT/'records'/(q['request_id']+'.request.json'),canonical(q))
  transport=RequesterSocket('/run/virp-kestrel-windows/onode.sock','virp-winreq',975);control=Socket('/run/virp-kestrel-windows/onode.sock');public=bytes.fromhex(p['public_key'])
  ledger=Ledger('/var/lib/virp-kestrel-windows/chain.db',transport,public,control);session='kestrel-windows-20261019';command=COMMANDS[q['action']]
  ledger.append(canonical({'schema':'kestrel-windows-intent/1',**q,'command':command,'authorization_sha256':p['authorization_sha256'],'time_ns':time.time_ns()}),session,'intent:'+q['request_id'])
  frame,result=execute_observed(transport,{'action':'execute','device':'colo-pve1-windows','command':command},public_key=public,node_id=0x4b57494e,device_id=int.from_bytes(hashlib.sha256(b'colo-pve1-windows').digest()[:8],'big'),path=ROOT/'records'/(q['request_id']+'.frame'),chain_session=session,artifact_id='windows:'+q['request_id'],recovery_dir=ROOT/'v3-recovery')
  receipt=ledger.verify(frame,session,'windows:'+q['request_id']);body=None
  if result['subtype']==7 and not result.get('recovery_required'):
   try:body=parse_native_output(result['output'],command)
   except ValueError:pass
  ok=isinstance(body,dict) and body.get('ok') is True and body.get('target')=='colo-windows2025'
  reply={'ok':ok,'request_id':q['request_id'],'target':q['target'],'action':q['action'],'observation':body,'native':result,'receipt':receipt,'recovery_required':bool(result.get('recovery_required'))}
  durable_write(ROOT/'records'/(q['request_id']+'.result.json'),canonical(reply));print(json.dumps(reply))
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'ok':False,'reason':str(e) if isinstance(e,ValueError) else type(e).__name__}));sys.exit(1)
