"""Preparation uses synthetic signed frames; native proposal adapter is mocked."""
import tempfile,unittest
from pathlib import Path
from types import SimpleNamespace
import test_port_flow
from port_prepare import PortPreparation
from port_transaction import Transactions,Refused
from test_port_fixtures import proposal_inventory

class PreparationTests(unittest.TestCase):
 def setUp(self):
  self.f=test_port_flow.FlowTests();self.f.setUp();self.tmp=tempfile.TemporaryDirectory();self.f.native.body={'target':self.f.p.body['target']}
  self.tx=Transactions(str(Path(self.tmp.name)/'tx.db'),self.f.p.pub,owner='test-owner',boot_id='executor',max_lease_seconds=60,wall_ns=lambda:self.f.p.wall,boottime=lambda:self.f.p.boot)
  self.proposed=[];self.protected=set();self.stop=[]
  def factory(body):
   self.rendered=body
   def propose(command):
    self.proposed.append(command);ref=proposal_inventory()['forward'];return {'reference':ref}
   return SimpleNamespace(propose=propose)
  self.prep=PortPreparation(self.tx,self.f.p.fixture.ledger,self.f.native,factory,SimpleNamespace(check=lambda:None,stop=self.stop.append),protected_ports=self.protected,wall_ns=lambda:self.f.p.wall)
 def tearDown(self):self.tx.close();self.tmp.cleanup();self.f.tearDown()
 def test_collects_full_set_before_rendering_and_prefiles_inventory(self):
  tid=self.prep.prepare('mode_access',config_proposal_id='1'*32,verification_budget=4)
  _,body=self.tx._get(tid)
  self.assertEqual(len(body['precondition_hashes']),7);self.assertEqual(len(self.proposed),7)
  self.assertEqual(self.proposed[:2],[body['plan']['forward'],body['plan']['rollback']])
  self.assertEqual(len(body['native_proposals']['verify']),4)
  self.assertEqual(self.f.calls[0][1],'1'*32)
  self.assertEqual(self.tx.status(tid)['state'],'prepared')
  self.assertEqual(self.tx.events(tid)[0]['bundle'],body)
 def test_missing_neighbor_proof_prevents_proposals(self):
  self.f.failure='neighbor'
  with self.assertRaises(ValueError):self.prep.prepare('mode_access',config_proposal_id='1'*32)
  self.assertEqual(self.proposed,[]);self.assertEqual(self.tx.db.execute('select count(*) from transactions').fetchone()[0],0)
 def test_unsupported_operation_never_reads(self):
  with self.assertRaises(Refused):self.prep.prepare('reload',config_proposal_id='1'*32)
  self.assertEqual(self.f.calls,[])
 def test_missing_read_authority_never_reads(self):
  with self.assertRaises(Refused):self.prep.prepare('mode_access',config_proposal_id=None)
  self.assertEqual(self.f.calls,[])
 def test_stale_signed_evidence_never_proposes(self):
  self.f.failure='stale'
  with self.assertRaises(ValueError):self.prep.prepare('mode_access',config_proposal_id='1'*32)
  self.assertEqual(self.proposed,[])
 def test_second_preparation_refused_before_device_reads(self):
  self.prep.prepare('mode_access',config_proposal_id='1'*32);calls=len(self.f.calls)
  with self.assertRaisesRegex(Refused,'target_transaction_open'):self.prep.prepare('mode_access',config_proposal_id='2'*32)
  self.assertEqual(len(self.f.calls),calls)
if __name__=='__main__':unittest.main()
