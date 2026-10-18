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
   approved=authorized.get('approved_ns');duration=authorized.get('max_lease_seconds')
   if (type(approved)is not int or type(duration)is not int or not 1<=duration<=seconds
       or authorized['expires_ns']!=approved+duration*1000000000
       or authorized['authorization'].get('approved_ns')!=approved):raise Refused('owner_authorization_binding_invalid')
   # Preserve the original decision instant rather than rounding a subsecond
   # remainder down to zero. Sampling boot time first makes this conservative.
   boot=self.tx.boottime();now=self.tx.wall_ns()
   if approved>now:raise Refused('owner_clock_ahead')
   if now>=authorized['expires_ns']:raise Refused('owner_lease_already_elapsed')
   a=self.tx.approval_request(self.tid,duration,authorization=authorized['authorization'])
   a['issued_ns']=approved;a['issued_boottime']=boot-(now-approved)/1000000000
   signature=bytes.fromhex(self.call({'action':'sign_envelope','envelope':a})['signature'])
   self.scope.check();self.tx.approve(a,signature);self.tx.flush(self.events)
   return self.tx.status(self.tid)
  except BaseException:
   self.scope.stop('owner_authorization_interrupted')
   raise
