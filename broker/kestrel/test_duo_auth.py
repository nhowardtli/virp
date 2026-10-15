import unittest
from duo_auth import DuoAuth
from approval_plan import Refused
class Tests(unittest.TestCase):
 def client(self):return DuoAuth('api-12345678.duosecurity.com','fixture-ikey','fixture-skey')
 def test_non_auth_never_pushes(self):
  c=self.client();c.call=lambda *a: self.fail('unexpected request')
  for result in ['allow','deny','enroll','unknown']:
   with self.assertRaises(Refused):c.push('nhoward-admin',{'result':result},{})
 def test_verified_push_not_downgraded(self):
  c=self.client();c.call=lambda *a:self.fail('unexpected request')
  with self.assertRaises(Refused):c.push('nhoward-admin',{'result':'auth','verification_code':'1234'},{})
 def test_exact_context_and_transaction_passed(self):
  c=self.client();calls=[]
  def call(*args):calls.append(args);return {'txid':'fixture-transaction'}
  c.call=call
  result=c.push('nhoward-admin',{'result':'auth','txid':'preauth-tx','devices':[{'device':'DPIN','capabilities':['push']}]},{'SHA256':'a'*64,'Target':'10.0.10.2'})
  self.assertEqual(result,'fixture-transaction');self.assertEqual(len(calls),1)
  params=calls[0][2];self.assertEqual(params['factor'],'push');self.assertEqual(params['device'],'DPIN');self.assertEqual(params['txid'],'preauth-tx');self.assertIn('a'*64,params['pushinfo'])
 def test_ambiguous_device_rejected(self):
  c=self.client();c.call=lambda *a:self.fail('unexpected request')
  with self.assertRaises(Refused):c.push('nhoward-admin',{'result':'auth','devices':[{'device':'a','capabilities':['push']},{'device':'b','capabilities':['push']}]},{})
 def test_wrong_tenant_rejected(self):
  for h in ['api-12345678.duosecurity.com.evil','http://api-12345678.duosecurity.com','localhost','api-12345678.duosecurity.com:443']:
   with self.assertRaises(Refused):DuoAuth(h,'fixture','fixture')
if __name__=='__main__':unittest.main()
