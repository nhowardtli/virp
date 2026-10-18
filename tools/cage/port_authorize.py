"""One-shot owner approval handoff. No retry or lease restart after ambiguity."""
from port_transaction import Refused,digest

class PortAuthorization:
 def __init__(self,transactions,events,owner,scope,transaction_id):
  self.tx=transactions;self.events=events;self.owner=owner;self.scope=scope;self.tid=transaction_id
 def call(self,q):
  self.scope.check()
  reply=self.owner.call({'transaction_id':self.tid,**q})
  if not isinstance(reply,dict) or reply.get('ok') is not True or reply.get('transaction_id')!=self.tid:raise Refused('owner_authorization_refused_or_mismatched')
  return reply
 def authorize(self,seconds):
  self.scope.check();self.tx.flush(self.events)
  self.tx.begin_authorization(self.tid,seconds)
  try:
   self.tx.flush(self.events);_,body=self.tx._get(self.tid)
   self.call({'action':'prepare','body':body,'lease_seconds':seconds,'executor_boot_id':self.tx.boot_id})
   authorized=self.call({'action':'authorize'})
   if authorized.get('plan_sha256')!=digest(body) or type(authorized.get('expires_ns'))is not int:raise Refused('owner_authorization_binding_invalid')
   a=self.tx.approval_request(self.tid,1,authorization=authorized['authorization'])
   remaining=(authorized['expires_ns']-a['issued_ns'])//1000000000
   if remaining<1:raise Refused('owner_lease_already_elapsed')
   # Bind to the captured issue instant; the signer independently enforces its
   # original Duo deadline. Delay cannot restart the approved duration.
   a['lease_seconds']=min(seconds,remaining)
   signature=bytes.fromhex(self.call({'action':'sign_envelope','envelope':a})['signature'])
   self.scope.check();self.tx.approve(a,signature);self.tx.flush(self.events)
   return self.tx.status(self.tid)
  except BaseException:
   self.scope.stop('owner_authorization_interrupted')
   raise
