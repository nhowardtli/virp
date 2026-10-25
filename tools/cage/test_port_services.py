import unittest
from types import SimpleNamespace
import test_port_transaction
from port_services import PortServices
from port_transaction import Refused

class ServiceTests(unittest.TestCase):
 def setUp(self):
  self.f=test_port_transaction.TransactionTests();self.f.setUp();self.calls=[]
  self.services=PortServices(self.f.store,lambda e:{'artifact_id':e['event_id'],'chain_entry_hash':'a'*64},None,SimpleNamespace(check=lambda:None),self.f.body['target'],lambda body:self.calls.append(body),lambda native:self.calls.append('bootstrap'),protected_ports=set())
 def tearDown(self):self.f.tearDown()
 def test_current_and_status_select_fixed_target(self):
  self.assertEqual(self.services.current(),self.f.tid)
  self.assertEqual(self.services.status(self.f.tid)['state'],'prepared')
 def test_other_target_cannot_use_existing_transaction(self):
  self.services.target={'device':'SW-3850','host':'10.0.10.2','port':'GigabitEthernet1/0/22','device_node_id':0x0a000a02,'transport_port':2223}
  self.assertIsNone(self.services.current())
  with self.assertRaisesRegex(Refused,'service_target_mismatch'):self.services.step(self.f.tid,'apply')
  self.assertEqual(self.calls,[])
 def test_existing_transaction_blocks_before_bootstrap(self):
  with self.assertRaisesRegex(Refused,'target_transaction_open'):self.services.prepare('mode_access')
  self.assertEqual(self.calls,[])
 def test_recovery_and_replay_not_ordinary_service_verbs(self):
  for verb in ('reconcile','replay','reload'):
   with self.assertRaises(Refused):self.services.step(self.f.tid,verb)
  self.assertEqual(self.calls,[])
 def test_unsupported_operation_never_bootstraps_read(self):
  with self.assertRaises(Refused):self.services.prepare('trunk')
  self.assertEqual(self.calls,[])
if __name__=='__main__':unittest.main()
