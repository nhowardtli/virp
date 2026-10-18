import copy,tempfile,unittest,uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from port_canary_owner import CanaryOwnerRequests
from port_owner import OwnerRequests
from port_transaction import Transactions,Refused
from port_plan import plan
from test_port_fixtures import proposal_inventory

class CanaryOwnerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);self.now=1000000000000
  self.owner=CanaryOwnerRequests(str(self.root/'owner.db'),self.pub,self.key.sign,boot_id='owner',max_lease_seconds=60,wall_ns=lambda:self.now,boottime=lambda:100)
  self.tx=Transactions(str(self.root/'tx.db'),self.pub,owner='canary-test-approver',boot_id='canary',max_lease_seconds=60,required_approval_method='test',wall_ns=lambda:self.now,boottime=lambda:100)
  self.body={'target':{'device':'kestrel-ios','host':'192.168.255.10','port':'Ethernet0/1','device_node_id':260,'transport_port':22},'plan':plan('interface Ethernet0/1\n shutdown\nend','Ethernet0/1','mode_access'),'verification':['show interfaces Ethernet0/1 switchport','show running-config interface Ethernet0/1'],'precondition_hashes':['a'*64],'native_proposals':proposal_inventory()}
  self.tid=self.tx.create(self.body)
 def tearDown(self):self.owner.close();self.tx.close();self.tmp.cleanup()
 def test_explicit_test_method_signs_and_production_method_rejects(self):
  self.owner.prepare(self.tid,self.body,lease_seconds=10,executor_boot_id='canary')
  result=self.owner.authorize(self.tid);self.assertEqual(result['authorization']['method'],'test')
  a=self.tx.approval_request(self.tid,10,authorization=result['authorization']);sig=self.owner.sign_envelope(self.tid,a)
  self.tx.required_approval_method='duo'
  with self.assertRaises(Refused):self.tx.approve(a,sig)
  self.tx.required_approval_method='test';self.tx.approve(a,sig)
  self.assertEqual(self.tx.status(self.tid)['state'],'approved')
 def test_production_target_cannot_be_prepared(self):
  body=copy.deepcopy(self.body);body['target']={'device':'SW-3850','host':'10.0.10.2','port':'GigabitEthernet1/0/22','device_node_id':0x0a000a02,'transport_port':2223}
  with self.assertRaisesRegex(Refused,'canary_target_only'):self.owner.prepare(uuid.uuid4().hex,body,lease_seconds=10,executor_boot_id='canary')
 def test_repeated_test_authorization_refuses(self):
  self.owner.prepare(self.tid,self.body,lease_seconds=10,executor_boot_id='canary');self.owner.authorize(self.tid)
  with self.assertRaises(Refused):self.owner.authorize(self.tid)
 def test_production_owner_class_has_no_test_authorize(self):
  self.assertEqual(OwnerRequests.authorization_method,'duo')
  self.assertNotEqual(OwnerRequests.authorize,CanaryOwnerRequests.authorize)
if __name__=='__main__':unittest.main()
