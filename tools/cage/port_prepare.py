"""Collect authenticated baseline, render one finite op and prefile proposals.

Internal trusted API under the scope lock. A config-read native approval must
already have been independently issued. This module does not grant that read or
promote its YELLOW classification to GREEN. No supplied outputs are accepted.
"""
import re
import time
from port_evidence import commands,preconditions
from port_result import capture_after
from port_plan import OPS
from port_transaction import Refused,validate_target

class PortPreparation:
 def __init__(self,transactions,events,read_native,native_factory,scope,*,protected_ports,wall_ns=time.time_ns):
  if set(read_native.body)!={'target'}:raise Refused('baseline_adapter_must_be_read_only')
  validate_target(read_native.body['target'])
  self.tx=transactions;self.events=events;self.read=read_native;self.factory=native_factory
  self.scope=scope;self.protected=frozenset(protected_ports);self.now=wall_ns
 def prepare(self,operation,*,config_proposal_id,verification_budget=4):
  if operation not in OPS:raise Refused('unsupported_port_operation')
  if not isinstance(config_proposal_id,str) or not re.fullmatch('[a-f0-9]{32}',config_proposal_id):raise Refused('independent_config_read_authority_required')
  if type(verification_budget)is not int or not 2<=verification_budget<=8:raise Refused('invalid_verification_budget')
  self.scope.check();target=self.read.body['target'];port=target['port']
  self.tx.assert_target_available(target)
  if port in self.protected:raise Refused('protected_port')
  started=self.now();outputs={};hashes=[]
  for name,cmd in commands(port).items():
   self.scope.check()
   observed=self.read.observe(cmd,proposal_id=config_proposal_id if name=='config' else None)
   result=observed['result']
   capture=capture_after(raw=observed['raw'],public_key=self.read.public_key,session_id=bytes.fromhex(result['session_id']),
    node_id=self.read.node_id,device_id=self.read.device_id,command=cmd,after_sequence=-1,now_ns=self.now(),
    ledger=self.read.ledger,chain_session=self.read.chain_session,artifact_id=observed['artifact_id'],not_before_ns=started,min_chain_sequence=-1)
   outputs[name]=capture['output'];hashes.append(capture['frame_sha256'])
  if not 0<=self.now()-started<=30000000000:raise Refused('baseline_collection_stale')
  plan=preconditions(outputs,port,operation,protected_ports=self.protected)
  native=self.factory({'target':target,'plan':plan})
  def propose(cmd):
   self.scope.check();return native.propose(cmd)['reference']
  inventory={'forward':propose(plan['forward']),'restore':propose(plan['rollback']),
             'preflight':propose(commands(port)['config']),
             'verify':[propose(commands(port)['config']) for _ in range(verification_budget)]}
  body={'target':target,'plan':plan,'verification':[commands(port)['switchport'],commands(port)['config']],
        'precondition_hashes':hashes,'native_proposals':inventory}
  tid=self.tx.create(body);self.tx.flush(self.events)
  return tid
