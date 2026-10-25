import unittest
from port_owner_service import dispatch,ServiceRefused
class Store:
 def __init__(self):self.calls=[]
 def prepare(self,*a,**kw):self.calls.append((a,kw))
 def authorize(self,tid,duo):self.calls.append((tid,duo));return {'plan_sha256':'a'*64}
 def sign_envelope(self,*a):self.calls.append(a);return b'a'*64
class Entry(unittest.TestCase):
 def setUp(self):self.store=Store();self.duo_calls=0
 def duo(self):self.duo_calls+=1;return 'duo'
 def call(self,q):return dispatch(q,self.store,self.duo,{'kestrel-ios'})
 def test_unsupported_actions_and_extra_fields_rejected(self):
  for q in [{},[],{'action':'shell','command':'anything'},{'action':'authorize','transaction_id':'x','owner':'attacker'}]:
   with self.assertRaises(ServiceRefused):self.call(q)
  self.assertEqual(self.store.calls,[]);self.assertEqual(self.duo_calls,0)
 def test_prepare_scope_checked_before_store(self):
  q={'action':'prepare','transaction_id':'x','body':{'target':{'device':'SW-3850'}},'lease_seconds':10,'executor_boot_id':'boot'}
  with self.assertRaises(ServiceRefused):self.call(q)
  self.assertEqual(self.store.calls,[])
 def test_duo_only_loaded_for_authorize(self):
  self.call({'action':'sign_envelope','transaction_id':'x','envelope':{}});self.assertEqual(self.duo_calls,0)
  self.call({'action':'authorize','transaction_id':'x'});self.assertEqual(self.duo_calls,1)
if __name__=='__main__':unittest.main()
