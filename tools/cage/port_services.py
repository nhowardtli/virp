"""Trusted adapter assembly behind the finite cage dispatcher.

No credentials are loaded here. The host entrypoint supplies a separately
qualified bootstrap config-read authority and owner transport. Canary fixtures
may use a test approver; production must use its independent owner service.
"""
import json
from port_authorize import PortAuthorization
from port_flow import PortFlow
from port_prepare import PortPreparation
from port_plan import OPS
from port_transaction import Refused,canonical,digest,validate_target

class PortServices:
 def __init__(self,transactions,events,owner,scope,target,native_factory,bootstrap_read,*,protected_ports):
  validate_target(target)
  self.tx=transactions;self.events=events;self.owner=owner;self.scope=scope
  self.target=json.loads(canonical(target));self.native=native_factory;self.bootstrap=bootstrap_read
  self.protected=frozenset(protected_ports)
 def body(self,tid):
  _,body=self.tx._get(tid)
  if body['target']!=self.target:raise Refused('service_target_mismatch')
  return body
 def current(self):
  self.scope.check()
  for row in self.tx.db.execute('SELECT id,body,hash FROM transactions ORDER BY rowid DESC'):
   body=json.loads(row['body'])
   if digest(body)!=row['hash']:raise Refused('approved_bundle_tampered')
   if body['target']==self.target:self.body(row['id']);return row['id']
  return None
 def status(self,tid):
  self.scope.check();self.body(tid)
  result=self.tx.status(tid);self.tx.flush(self.events);return result
 def prepare(self,operation):
  self.scope.check()
  if operation not in OPS:raise Refused('unsupported_port_operation')
  self.tx.assert_target_available(self.target)
  read=self.native({'target':self.target})
  pid=self.bootstrap(read)
  return PortPreparation(self.tx,self.events,read,self.native,self.scope,protected_ports=self.protected).prepare(operation,config_proposal_id=pid)
 def authorize(self,tid,seconds):
  self.scope.check();self.body(tid)
  return PortAuthorization(self.tx,self.events,self.owner,self.scope,tid).authorize(seconds)
 def step(self,tid,verb):
  self.scope.check();body=self.body(tid)
  if verb not in ('preflight','apply','verify','restore','verify_restored'):raise Refused('ordinary_port_verb_denied')
  return PortFlow(self.tx,self.events,self.native(body),self.owner,self.scope,tid,protected_ports=self.protected).step(verb)
