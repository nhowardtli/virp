"""Synthetic integration: no Cisco, no live Duo, no claim of device qualification."""
import hashlib,json,struct,tempfile,unittest,uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
import test_port_ledger
import test_port_owner
from port_transaction import Transactions,Refused
from port_owner import OwnerRequests
from port_plan import plan

class Pipeline(unittest.TestCase):
 def setUp(self):
  self.fixture=test_port_ledger.LedgerTests();self.fixture.setUp();self.tmp=tempfile.TemporaryDirectory();self.wall=1000000000000;self.boot=100.0
  self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  self.tx=Transactions(str(Path(self.tmp.name)/'tx.db'),self.pub,owner='test-owner',wall_ns=lambda:self.wall,boottime=lambda:self.boot,boot_id='executor',max_lease_seconds=60)
  self.body={'target':{'device':'kestrel-ios','host':'192.168.255.10','port':'Ethernet0/1','device_node_id':260,'transport_port':22},'plan':plan('interface Ethernet0/1\n shutdown\nend','Ethernet0/1','mode_access'),'verification':['show interfaces Ethernet0/1 switchport','show running-config interface Ethernet0/1'],'precondition_hashes':['a'*64]}
  self.tid=self.tx.create(self.body)
  self.owner=OwnerRequests(str(Path(self.tmp.name)/'owner.db'),self.pub,self.key.sign,owner='test-owner',boot_id='owner',max_lease_seconds=60,wall_ns=lambda:self.wall,boottime=lambda:self.boot,producers={'kestrel-ios':{'public_key':self.fixture.pub,'node_id':260,'chain_session':'test-session'}})
  self.owner.prepare(self.tid,self.body,lease_seconds=10,executor_boot_id='executor');authorization=self.owner.authorize(self.tid,test_port_owner.Duo())
  a=self.tx.approval_request(self.tid,10,authorization=authorization['authorization']);signature=self.owner.sign_envelope(self.tid,a);self.tx.approve(a,signature);self.flush()
 def tearDown(self):self.owner.close();self.tx.close();self.fixture.tearDown();self.tmp.cleanup()
 def flush(self):self.tx.flush(self.fixture.ledger)
 def proof(self,event):
  self.fixture.db.row_factory=__import__('sqlite3').Row
  return dict(self.fixture.db.execute('select * from chain_entries where artifact_id=?',(event['event_id'],)).fetchone())
 def request(self,verb):
  self.flush();r=self.tx.begin(self.tid,verb);self.flush()
  cmd=self.body['plan']['forward' if verb=='apply' else 'rollback'] if verb in ('apply','restore') else self.body['verification'][1]
  pid=uuid.uuid4().hex
  q={'proposal_id':pid,'device':'kestrel-ios','command':cmd,'device_node_id':260,'tier':'RED' if verb in ('apply','restore') else 'YELLOW','ttl_seconds':300,'canonical':struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(pid),hashlib.sha256(cmd.encode()).digest(),260,self.wall,300).hex()}
  self.tx.reserve_native(r,q);self.flush();intent=self.tx.events(self.tid)[-1]
  raw=self.tx.native_signable(r,pid);sig=self.owner.sign_native(self.tid,intent,self.proof(intent),q)
  self.key.public_key().verify(sig,raw);self.flush();self.tx.require_dispatch(r);return r
 def test_approval_expiry_restore_and_owner_close(self):
  r=self.request('apply');self.tx.finish(r,'executed',observation_hash='b'*64);self.flush()
  self.wall+=11000000000;self.boot+=11
  with self.assertRaises(Refused):self.tx.begin(self.tid,'unrelated_read')
  self.flush();r=self.request('restore');self.tx.finish(r,'executed',observation_hash='c'*64);self.flush()
  r=self.request('verify_restored');self.tx.finish(r,'matches',observation_hash='d'*64);self.flush()
  end=self.tx.events(self.tid)[-1];self.owner.accept_close(self.tid,end,self.proof(end))
  self.assertEqual(self.tx.status(self.tid)['state'],'restored')
  self.assertEqual(self.owner.db.execute('select state from owner_requests').fetchone()[0],'closed')
  self.assertEqual(self.fixture.db.execute('select count(*) from chain_entries').fetchone()[0],len(self.tx.events(self.tid)))
 def test_expiry_before_apply_closes_without_native_signature(self):
  self.wall+=11000000000;self.boot+=11
  with self.assertRaises(Refused):self.tx.begin(self.tid,'apply')
  self.flush();end=self.tx.events(self.tid)[-1];self.owner.accept_close(self.tid,end,self.proof(end))
  self.assertEqual(self.owner.db.execute('select count(*) from native_signatures').fetchone()[0],0)
if __name__=='__main__':unittest.main()
