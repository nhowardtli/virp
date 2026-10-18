import hashlib,struct,unittest,copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from port_native_approval import verify_approval
class NativeApproval(unittest.TestCase):
 def setUp(self):
  self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);self.now=1000000000000
  self.command='interface Ethernet0/1 switchport mode access';self.pid='12'*16
  self.raw=struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(self.pid),hashlib.sha256(self.command.encode()).digest(),260,self.now,300)
  self.body={'proposal_id':self.pid,'command_hash':hashlib.sha256(self.command.encode()).hexdigest(),'device':'kestrel-ios','device_node_id':260,'approved_at_ns':str(self.now),'ttl_seconds':300,'approver_key_id':hashlib.sha256(self.pub).hexdigest()[:32],'operator':'test-approver','body_version':2,'approver_signature':self.key.sign(self.raw).hex()}
 def check(self,body=None,**extra):
  opts=dict(public_key=self.pub,proposal_id=self.pid,device='kestrel-ios',device_node_id=260,command=self.command,operator='test-approver',now_ns=self.now);opts.update(extra);return verify_approval(body or self.body,**opts)
 def test_exact_native_artifact(self):self.assertEqual(self.check(),self.raw)
 def test_field_tampering_refused(self):
  for key,value in [('proposal_id','34'*16),('command_hash','0'*64),('device','SW-3850'),('device_node_id',1),('approved_at_ns',str(self.now+1)),('ttl_seconds',301),('approver_key_id','0'*32),('operator','other'),('body_version',1),('approver_signature','0'*128)]:
   with self.subTest(key=key),self.assertRaises(ValueError):self.check({**self.body,key:value})
 def test_wrong_external_pin_refused(self):
  with self.assertRaises(ValueError):self.check(public_key=b'0'*32)
 def test_expiry_and_future_refused(self):
  for now in [self.now-1,self.now+300000000000]:
   with self.assertRaises(ValueError):self.check(now_ns=now)
 def test_exact_decimal_timestamp_no_float_or_bool(self):
  for value in [float(self.now),True,'1e12','-1',None]:
   with self.assertRaises(ValueError):self.check({**self.body,'approved_at_ns':value})

class ArtifactTests(unittest.TestCase):
 def setUp(self):
  import test_port_ledger
  from port_transaction import canonical
  from port_native_approval import ApprovalLedger
  NativeApproval.setUp(self);self.fixture=test_port_ledger.LedgerTests();self.fixture.setUp()
  self.raw_body=canonical(self.body);self.aid='approval:'+self.pid
  e={'artifact_hash':hashlib.sha256(self.raw_body).hexdigest(),'artifact_hash_alg':'sha256','artifact_id':self.aid,'artifact_schema_version':1,'artifact_type':'approval','monotonic_ns':1,'previous_entry_hash':'0'*64,'sequence':0,'session_id':'approval:kestrel-ios@cml-v3-20261016','signer_node_id':260,'signer_org_id':'local','timestamp_ns':self.now}
  raw=canonical(e);e.update(chain_entry_hash=hashlib.sha256(raw).hexdigest(),chain_sig_key_id=hashlib.sha256(self.fixture.pub).hexdigest()[:32],chain_sig=self.fixture.key.sign(b'VIRP-CHAIN-ENTRY-SIG-v1\0'+raw).hex());self.entry=e
  self.fixture.db.execute('insert into chain_entries values('+','.join('?' for _ in e)+')',tuple(e.values()))
  self.fixture.db.execute('insert into artifacts values(?,?,?)',(self.aid,e['artifact_hash'],self.raw_body.decode()));self.fixture.db.commit()
  self.ledger=ApprovalLedger(self.fixture.path,self.fixture,self.fixture.pub,'approval:kestrel-ios@cml-v3-20261016')
 def tearDown(self):self.fixture.tearDown()
 def check(self,**extra):
  args=dict(expected_chain_hash=self.entry['chain_entry_hash'],public_key=self.pub,proposal_id=self.pid,device='kestrel-ios',device_node_id=260,command=self.command,operator='test-approver',now_ns=self.now);args.update(extra);return self.ledger.verify(**args)
 def test_native_signature_and_exact_chain_artifact(self):self.assertEqual(self.check()['artifact_bytes'],self.raw_body)
 def test_wrong_reply_chain_hash_refused(self):
  with self.assertRaises(ValueError):self.check(expected_chain_hash='f'*64)
 def test_altered_body_refused(self):
  self.fixture.db.execute("update artifacts set artifact_content='{}'");self.fixture.db.commit()
  with self.assertRaises(ValueError):self.check()
 def test_duplicate_approval_entry_refused(self):
  self.fixture.db.execute('insert into chain_entries select * from chain_entries');self.fixture.db.commit()
  with self.assertRaises(ValueError):self.check()
 def test_broken_chain_refused(self):
  self.fixture.broken=True
  with self.assertRaises(ValueError):self.check()
 def test_wrong_approver_pin_refused_even_with_valid_producer(self):
  with self.assertRaises(ValueError):self.check(public_key=b'z'*32)
if __name__=='__main__':unittest.main()
