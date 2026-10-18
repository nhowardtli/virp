"""Finite cage request dispatcher. The protected host entrypoint owns adapters.

No supplied CLI, target, transaction ID, lease or approval status is accepted.
Caller holds the scope lock. Request/response files are private helper records;
they are not represented as native execution observations or signed narration.
"""
import re
from helper import durable_write
from port_plan import OPS
from port_transaction import Refused,canonical

PREPARE={"port_prepare_"+name:name for name in OPS}
STEPS={"port_"+name:name for name in ('preflight','apply','verify','restore','verify_restored')}
OPERATIONS=tuple([*PREPARE,'port_authorize',*STEPS,'port_status'])

def validate_request(q):
 if not isinstance(q,dict) or set(q)!={'operation','request_id','rationale'}:raise Refused('invalid_request_fields')
 if not isinstance(q['operation'],str) or q['operation'] not in OPERATIONS:raise Refused('operation_denied')
 if not isinstance(q['request_id'],str) or not re.fullmatch('[a-f0-9]{32}',q['request_id']):raise Refused('invalid_request_id')
 if not isinstance(q['rationale'],str) or not 20<=len(q['rationale'])<=1000:raise Refused('invalid_rationale')

def dispatch(q,services,scope,*,lease_seconds):
 validate_request(q)
 if type(lease_seconds)is not int or not 1<=lease_seconds<=36000:raise Refused('invalid_provisioned_lease')
 scope.check();operation=q['operation'];record=None
 if operation!='port_status':record=scope.reserve(q)
 if operation in PREPARE:
  tid=services.prepare(PREPARE[operation]);state=services.status(tid)
 else:
  tid=services.current()
  if tid is None:
   if operation!='port_status':raise Refused('no_port_transaction')
   state={'state':'absent'}
  elif operation=='port_authorize':state=services.authorize(tid,lease_seconds)
  elif operation in STEPS:state=services.step(tid,STEPS[operation])
  else:state=services.status(tid)
 if state.get('id',tid)!=tid:raise Refused('backend_transaction_changed')
 result={'ok':True,'operation':operation,'request_id':q['request_id'],'transaction_id':tid,
         **{k:state[k] for k in ('state','expired','close_reason') if k in state}}
 if record is not None:
  durable_write(record.with_name(q['request_id']+'.result.json'),canonical(result))
 return result
