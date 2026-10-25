"""Exact Windows provisioning scope. No caller-supplied execution payloads."""
import re,json
TARGET='colo-windows2025'
COMMANDS={'status':'qm status 233','provision':'qm create 233'}
def unique(pairs):
 d={}
 for k,v in pairs:
  if k in d:raise ValueError('duplicate_key')
  d[k]=v
 return d
def validate(q):
 if not isinstance(q,dict) or set(q)!={'operation','request_id','target','action','rationale'}:raise ValueError('invalid_request_fields')
 if q['operation']!='windows_execute' or q['target']!=TARGET or q['action'] not in COMMANDS:raise ValueError('outside_windows_scope')
 if not isinstance(q['request_id'],str) or not re.fullmatch('[a-f0-9]{32}',q['request_id']):raise ValueError('invalid_request_id')
 if not isinstance(q['rationale'],str) or not 20<=len(q['rationale'])<=1000 or any(ord(c)<32 for c in q['rationale']):raise ValueError('invalid_rationale')
 return q
def command_action(c):
 for a,w in COMMANDS.items():
  if c==w:return a
 raise ValueError('command_not_allowed')
def parse_native_output(output,command):
 prefix='colo-pve1-windows$ '+command+'\n'
 if not isinstance(output,str) or not output.startswith(prefix):raise ValueError('unexpected_native_output')
 body=json.loads(output[len(prefix):],object_pairs_hook=unique)
 if not isinstance(body,dict) or body.get('target')!=TARGET:raise ValueError('invalid_device_result')
 return body

def installation_media_detached(config):
 """Proxmox retains empty optical drives in boot order; reject any live media."""
 order=config.get('boot','').removeprefix('order=').split(';')
 return bool(order and order[0]=='sata0' and len(order)==len(set(order)) and set(order)<= {'sata0','ide0','ide1','ide2'} and all(config.get(k)=='none,media=cdrom' for k in ['ide0','ide1','ide2']))
