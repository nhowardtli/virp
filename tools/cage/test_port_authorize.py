"""Synthetic Duo/owner transport; public signatures are real generated test keys."""
import tempfile,unittest,uuid
from pathlib import Path
from types import SimpleNamespace
import test_port_pipeline,test_port_owner
from port_authorize import PortAuthorization
from port_transaction import Transactions,Refused
from port_owner_service import dispatch

class AuthorizationTests(unittest.TestCase):
 def setUp(self):
  self.p=test_port_pipeline.Pipeline();self.p.setUp();self.tmp=tempfile.TemporaryDirectory();self.calls=[];self.stops=[];self.delay=0;self.lost=None
  self.tx=Transactions(str(Path(self.tmp.name)/'tx.db'),self.p.pub,owner='test-owner',boot_id='executor',max_lease_seconds=60,wall_ns=lambda:self.p.wall,boottime=lambda:self.p.boot)
  self.tid=self.tx.create(self.p.body);self.tx.flush(self.p.fixture.ledger)
  self.flow=PortAuthorization(self.tx,self.p.fixture.ledger,SimpleNamespace(call=self.owner),SimpleNamespace(check=lambda:None,stop=self.stops.append),self.tid)
 def tearDown(self):self.tx.close();self.tmp.cleanup();self.p.tearDown()
 def owner(self,q):
  self.calls.append(q['action'])
  def duo():
   d=test_port_owner.Duo();d.push=lambda *args:'test-'+uuid.uuid4().hex;return d
  reply=dispatch(q,self.p.owner,duo,{'kestrel-ios'})
  if q['action']=='authorize':self.p.wall+=int(self.delay*1e9);self.p.boot+=self.delay
  if q['action']==self.lost:raise TimeoutError('synthetic lost owner response')
  return reply
 def test_full_owner_handoff_binds_exact_transaction(self):
  result=self.flow.authorize(10);self.assertEqual(result['state'],'approved')
  self.assertEqual(self.calls,['prepare','authorize','sign_envelope'])
  row,_=self.tx._get(self.tid);self.assertEqual(row['expires_ns'],self.p.wall+10000000000)
  self.assertEqual(self.stops,[])
 def test_delayed_duo_reply_cannot_restart_lease(self):
  initial=self.p.wall;self.delay=3.5;self.flow.authorize(10)
  row,_=self.tx._get(self.tid);self.assertLessEqual(row['expires_ns'],initial+10000000000)
  self.assertGreater(row['expires_ns'],self.p.wall)
 def test_repeated_call_never_repeats_push(self):
  self.flow.authorize(10)
  with self.assertRaises(Refused):self.flow.authorize(10)
  self.assertEqual(self.calls,['prepare','authorize','sign_envelope'])
 def test_lost_owner_response_does_not_retry(self):
  self.lost='authorize'
  with self.assertRaises(TimeoutError):self.flow.authorize(10)
  with self.assertRaisesRegex(Refused,'owner_authorization_already_started'):self.flow.authorize(10)
  self.assertEqual(self.calls,['prepare','authorize']);self.assertEqual(self.stops,['owner_authorization_interrupted'])
  self.assertEqual(self.tx.status(self.tid)['state'],'prepared')
 def test_expired_response_never_requests_signature(self):
  self.delay=11
  with self.assertRaisesRegex(Refused,'owner_lease_already_elapsed'):self.flow.authorize(10)
  self.assertEqual(self.calls,['prepare','authorize']);self.assertEqual(self.tx.status(self.tid)['state'],'prepared')
 def test_lost_signature_never_activates_or_reissues(self):
  self.lost='sign_envelope'
  with self.assertRaises(TimeoutError):self.flow.authorize(10)
  with self.assertRaises(Refused):self.flow.authorize(10)
  self.assertEqual(self.calls.count('sign_envelope'),1);self.assertEqual(self.tx.status(self.tid)['state'],'prepared')
if __name__=='__main__':unittest.main()
