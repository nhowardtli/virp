"""Fail-closed local runtime pins, independent of model input.

Protected profile provisioning is an administrative deployment operation. This
module does not write config, restart a service, or contact a network device.
"""
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
from port_owner_service import protected
from port_transaction import Refused,canonical,validate_target

def probe_service(service):
 if not isinstance(service,str) or not re.fullmatch('virp-[a-z0-9-]{1,64}',service):raise Refused('invalid_service_pin')
 output=subprocess.check_output(['/usr/bin/systemctl','show',service,'--property=MainPID,ActiveState','--no-pager'],timeout=10,text=True)
 fields=dict(line.split('=',1) for line in output.splitlines() if '=' in line)
 pid=int(fields.get('MainPID','0'))
 if fields.get('ActiveState')!='active' or pid<=0:return {'active':False}
 proc=Path('/proc')/str(pid)
 # Check PID/start time on both sides to reject restart races while inspecting.
 before=(proc/'stat').read_bytes()
 start=before.rsplit(b')',1)[1].split()[19]
 exe=os.readlink(proc/'exe')
 digest=hashlib.sha256((proc/'exe').read_bytes()).hexdigest()
 argv=[x.decode() for x in (proc/'cmdline').read_bytes().split(b'\0') if x]
 uid_line=next(line for line in (proc/'status').read_text().splitlines() if line.startswith('Uid:'))
 effective_uid=int(uid_line.split()[2])
 after=(proc/'stat').read_bytes().rsplit(b')',1)[1].split()[19]
 if start!=after:raise Refused('runtime_process_changed')
 return {'active':True,'executable':exe,'binary_sha256':digest,'argv':argv,'effective_uid':effective_uid}

class RuntimePins:
 def __init__(self,profile,*,protect=protected,identity=None,process_probe=probe_service):
  self.profile=json.loads(canonical(profile));self.protect=protect;self.probe=process_probe
  validate_target(self.profile['target'])
  self.identity=identity or self.local_identity
  p=self.profile
  if p['requester_uid']!=980:raise Refused('invalid_requester_pin')
  if type(p['daemon_uid'])is not int or p['daemon_uid']<=0:raise Refused('invalid_daemon_uid_pin')
  if any(path not in p['files'] for path in (p['binary'],p['config'],p['public_key'])):raise Refused('missing_runtime_file_pin')
  if any(not re.fullmatch('[a-f0-9]{64}',v) for v in p['files'].values()):raise Refused('invalid_runtime_file_pin')
  if (not isinstance(p['argv'],list) or not p['argv'] or p['argv'][0]!=p['binary'] or
      p['argv'].count('-d')!=1 or p['argv'].index('-d')+1>=len(p['argv']) or
      p['argv'][p['argv'].index('-d')+1]!=p['config']):raise Refused('invalid_runtime_argv_pin')
 def local_identity(self):
  return (os.geteuid(),os.environ.get('SUDO_USER'),Path('/etc/machine-id').read_text().strip(),pwd.getpwnam(self.profile['requester']).pw_uid)
 def __call__(self):
  p=self.profile
  if self.identity()!=(0,p['sudo_user'],p['machine_id'],p['requester_uid']):raise Refused('runtime_identity_mismatch')
  data={}
  for path,digest in p['files'].items():
   protected_path=self.protect(path)
   if path==p['config'] and protected_path.stat().st_mode&0o007:raise Refused('runtime_config_permissions')
   raw=protected_path.read_bytes()
   if hashlib.sha256(raw).hexdigest()!=digest:raise Refused('runtime_file_changed')
   data[path]=raw
  if data[p['public_key']]!=bytes.fromhex(p['public_key_hex']):raise Refused('runtime_producer_pin_mismatch')
  cfg=json.loads(data[p['config']])
  if cfg.get('gate_default_mode')!='enforce' or cfg.get('evidence_required') is not True or cfg.get('socket_uid_tier_ceilings',{}).get(str(p['requester_uid']))!='green':raise Refused('runtime_gate_policy_changed')
  target=p['target'];matches=[d for d in cfg['devices'] if d.get('hostname')==target['device']]
  if len(matches)!=1:raise Refused('runtime_target_changed')
  d=matches[0]
  try:node=int(d['node_id'],16) if isinstance(d['node_id'],str) else d['node_id']
  except (ValueError,KeyError,TypeError):raise Refused('runtime_target_changed') from None
  if d.get('host')!=target['host'] or node!=target['device_node_id'] or d.get('port',22)!=target['transport_port']:raise Refused('runtime_target_changed')
  live=self.probe(p['service'])
  if live.get('effective_uid')!=p['daemon_uid'] or live.get('active') is not True or live.get('executable')!=p['binary'] or live.get('binary_sha256')!=p['files'][p['binary']] or live.get('argv')!=p['argv']:raise Refused('runtime_process_pin_mismatch')
