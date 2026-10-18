"""Explicit standing delegation adapter. Existing leased scopes are unchanged.

The root deployment binds an owner authorization digest and exact resource set.
Revocation, uncertain outcomes, serialization and durable attempt limits remain.
"""
import hashlib,json,os,re
from port_scope import ScopeGuard
from port_transaction import Refused
class StandingScope(ScopeGuard):
 def __init__(self,*args,binding,**kwargs):
  super().__init__(*args,**kwargs)
  self.binding=json.loads(json.dumps(binding))
  if set(self.binding)!={'device','ports','authorization_sha256'} or not re.fullmatch('[a-f0-9]{64}',self.binding['authorization_sha256']):raise Refused('invalid_standing_binding')
 def check(self):
  self.require_lock()
  if os.path.lexists(self.scope/'STOP'):raise Refused('scope_stopped')
  if os.path.lexists(self.scope/'v3-recovery/pending.json'):raise Refused('pending_outcome_requires_reconciliation')
  raw=self.protect(self.scope/'policy.json',secret=True).read_bytes();digest=hashlib.sha256(raw).hexdigest()
  if self.policy_hash is not None and self.policy_hash!=digest:raise Refused('scope_policy_changed')
  p=json.loads(raw)
  if p!={'schema':'kestrel-standing-scope/1',**self.binding}:raise Refused('standing_scope_mismatch')
  self.runtime();self.policy_hash=digest
  return p
