"""Closed grammar and pinned, single-use authorization for a VM reboot fixture."""
import re,time
TARGET='colo-vm231'
COMMANDS={'status':'qm status 231','reboot':'qm reboot 231'}
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError('duplicate_key')
  d[k]=v
 return d
def validate(q):
 if not isinstance(q,dict) or set(q)!={'operation','request_id','target','action','rationale'}:raise ValueError('invalid_request_fields')
 if q['operation']!='vm_execute' or q['target']!=TARGET or q['action'] not in COMMANDS:raise ValueError('outside_vm_scope')
 if not isinstance(q['request_id'],str) or not re.fullmatch('[a-f0-9]{32}',q['request_id']):raise ValueError('invalid_request_id')
 if not isinstance(q['rationale'],str) or not 20<=len(q['rationale'])<=1000 or any(ord(c)<32 for c in q['rationale']):raise ValueError('invalid_rationale')
 return q
def command_action(command):
 for action,want in COMMANDS.items():
  if command==want:return action
 raise ValueError('command_not_allowed')
def authorize(grant,identity,boot_id,*,consumed,stopped,now=None):
 if stopped:raise ValueError('scope_stopped')
 if consumed:raise ValueError('grant_already_consumed')
 if set(grant)!={'schema','target','identity','expected_boot_id','expires','authorization_sha256'} or grant['schema']!='kestrel-vm-grant/1' or grant['target']!=TARGET:raise ValueError('invalid_grant')
 if grant['identity']!=identity:raise ValueError('target_identity_changed')
 if grant['expected_boot_id']!=boot_id:raise ValueError('boot_precondition_changed')
 if not isinstance(grant['expires'],(int,float)) or (time.time() if now is None else now)>=grant['expires']:raise ValueError('grant_expired')
 if not re.fullmatch('[a-f0-9]{64}',grant['authorization_sha256']):raise ValueError('invalid_authorization_digest')

def parse_native_output(output,command):
 import json
 prefix='colo-pve1-vm231$ '+command+'\n'
 if not isinstance(output,str) or not output.startswith(prefix):raise ValueError('unexpected_native_output')
 body=json.loads(output[len(prefix):],object_pairs_hook=unique)
 if not isinstance(body,dict) or body.get('target')!=TARGET:raise ValueError('invalid_device_result')
 return body
