"""Explicit lab test signer; never installed by the production owner service.

Key loading and VM105 identity/pin checks belong to its protected lab entrypoint.
No Duo is contacted, and every signed envelope says method=test. Production
Transactions defaults to method=duo and rejects these envelopes independently.
"""
import uuid
from port_owner import OwnerRequests
from port_transaction import Refused

class CanaryOwnerRequests(OwnerRequests):
 authorization_method='test'
 def __init__(self,path,public_key,sign,**options):
  if 'owner' in options:raise Refused('fixed_canary_test_identity')
  if set(options.get('producers') or {})-{'kestrel-ios'}:raise Refused('canary_target_only')
  super().__init__(path,public_key,sign,owner='canary-test-approver',**options)
 def prepare(self,tid,body,**options):
  if body.get('target',{}).get('device')!='kestrel-ios':raise Refused('canary_target_only')
  return super().prepare(tid,body,**options)
 def authorize(self,tid):
  with self.atomic():
   row,body=self.get(tid,'prepared')
   if body['target']['device']!='kestrel-ios':raise Refused('canary_target_only')
   reference='canary-test-'+uuid.uuid4().hex;approved=self.now()
   # Existing database column name retained; the envelope/event identify this
   # as test authority explicitly. This value is not represented as a Duo ID.
   self.db.execute("UPDATE owner_requests SET state='authorized',duo_txid=?,authorized_ns=?,deadline=? WHERE id=?",(reference,approved,self.clock()+row['lease'],tid))
   self.event(tid,'test_authorized',authorization_reference=reference,plan_sha256=row['hash'],operator=self.owner)
  return {'plan_sha256':row['hash'],'approved_ns':approved,'expires_ns':approved+row['lease']*1000000000,
          'max_lease_seconds':row['lease'],'authorization':{'method':'test','reference':reference,'approved_ns':approved}}
