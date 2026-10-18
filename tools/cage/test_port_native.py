import hashlib,tempfile,unittest,struct
from pathlib import Path
from types import SimpleNamespace
from port_native import NativePort
from port_plan import plan
from port_transaction import Refused
from test_port_fixtures import proposal_inventory
class NativeAdapter(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.calls=[];self.guards=0;self.stops=[]
  self.body={'target':{'device':'kestrel-ios','host':'192.168.255.10','port':'Ethernet0/1','device_node_id':260,'transport_port':22},'plan':plan('interface Ethernet0/1\n shutdown\nend','Ethernet0/1','mode_access'),'verification':['show interfaces Ethernet0/1 switchport','show running-config interface Ethernet0/1'],'precondition_hashes':['a'*64],'native_proposals':proposal_inventory()}
  self.ledger=SimpleNamespace(db='/unused',verify=lambda raw,sid,aid:{'session_id':sid,'artifact_id':aid,'chain_entry_hash':'b'*64,'sequence':1})
  self.native=NativePort(body=self.body,transport=SimpleNamespace(management=self.management),ledger=self.ledger,records=self.tmp.name,recovery_dir=self.tmp.name,public_key=b'x'*32,node_id=260,chain_session='test',approval_session='approval:kestrel-ios@test',approver_public_key=b'y'*32,operator='test',guard=self.guard,stop=self.stops.append,observer=self.observe,wall_ns=lambda:1000)
 def tearDown(self):self.tmp.cleanup()
 def guard(self):self.guards+=1
 def management(self,q):self.fail('unexpected management request')
 def observe(self,transport,request,**kw):
  self.calls.append((request,kw));raw=b'fixture frame'
  return raw,{'frame_sha256':hashlib.sha256(raw).hexdigest(),'subtype':7,'output':'fixture','session_id':'1'*32}
 def test_fixed_command_target_and_v3_helper_binding(self):
  r=self.native.observe('show interfaces Ethernet0/1 switchport');q,kw=self.calls[0]
  self.assertEqual(q,{'action':'execute','device':'kestrel-ios','command':'show interfaces Ethernet0/1 switchport'})
  self.assertEqual(kw['node_id'],260);self.assertEqual(kw['public_key'],b'x'*32);self.assertEqual(self.guards,1)
  self.assertTrue(Path(r['path']+'.json').exists())
 def test_caller_cannot_change_bound_target_after_construction(self):
  self.body['target']['device']='other-device'
  self.native.observe('show interfaces Ethernet0/1 switchport')
  self.assertEqual(self.calls[0][0]['device'],'kestrel-ios')
 def test_baseline_collection_needs_no_placeholder_plan(self):
  read=NativePort(body={'target':self.body['target']},transport=self.native.transport,ledger=self.ledger,records=self.tmp.name,recovery_dir=self.tmp.name,public_key=b'x'*32,node_id=260,chain_session='test',approval_session='approval:kestrel-ios@test',approver_public_key=b'y'*32,operator='test',guard=self.guard,stop=self.stops.append,observer=self.observe,wall_ns=lambda:1000)
  with self.assertRaises(Refused):read.observe(self.body['plan']['forward'])
  read.observe('show interfaces Ethernet0/1 switchport');self.assertEqual(len(self.calls),1)
 def test_other_command_or_port_never_dispatched(self):
  for cmd in ['reload','show running-config','interface Ethernet0/2 switchport mode access']:
   with self.assertRaises(Refused):self.native.observe(cmd)
  self.assertEqual(self.calls,[])
 def test_guard_blocks_before_dispatch(self):
  def blocked():raise Refused('work_lease_inactive')
  self.native.guard=blocked
  with self.assertRaisesRegex(Refused,'work_lease_inactive'):self.native.observe(self.body['plan']['forward'])
  self.assertEqual(self.calls,[])
 def test_invalid_proposal_id_never_dispatched(self):
  with self.assertRaises(Refused):self.native.observe(self.body['plan']['forward'],proposal_id='wrong')
  self.assertEqual(self.calls,[])
 def test_preapproval_success_requires_stop(self):
  with self.assertRaisesRegex(Refused,'stop_required'):self.native.propose(self.body['plan']['forward'])
  self.assertEqual(self.stops,['unexpected_preapproval_result'])
 def native_challenge(self):
  cmd=self.body['plan']['forward'];pid=self.body['native_proposals']['forward']['proposal_id']
  raw=struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(pid),hashlib.sha256(cmd.encode()).digest(),260,1000,300)
  return {'proposal_id':pid,'device':'kestrel-ios','device_node_id':260,'command':cmd,'tier':'YELLOW','ttl_seconds':300,'canonical':raw.hex()}
 def test_challenge_uses_separate_control_identity(self):
  q=self.native_challenge();calls=[]
  self.native.control=SimpleNamespace(management=lambda request:calls.append(request) or q)
  self.assertEqual(self.native.challenge(q['proposal_id'],q['command']),q)
  self.assertEqual(calls,[{'action':'approval_challenge','proposal_id':q['proposal_id']}]);self.assertEqual(self.calls,[])
 def submit_fixture(self,**changes):
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
  from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
  key=Ed25519PrivateKey.generate();self.native.approver_public_key=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  q=self.native_challenge();calls=[];self.submits=calls
  reply={'already_approved':False,'proposal_id':q['proposal_id'],'operator':'test','approver_key_id':hashlib.sha256(self.native.approver_public_key).hexdigest()[:32],'chain_entry_hash':'c'*64,**changes}
  self.native.control=SimpleNamespace(management=lambda request:calls.append(request) or reply)
  self.proofs=[];self.native.approvals=SimpleNamespace(verify=lambda **args:self.proofs.append(args) or {'verified':True})
  return q,key.sign(bytes.fromhex(q['canonical']))
 def test_submit_checks_signature_and_signed_native_artifact(self):
  q,sig=self.submit_fixture();self.assertTrue(self.native.submit(q,sig)['verified'])
  self.assertEqual(len(self.submits),1);self.assertEqual(self.proofs[0]['expected_chain_hash'],'c'*64)
  self.assertEqual(self.submits[0]['signature'],sig.hex());self.assertEqual(self.calls,[])
 def test_idempotent_or_wrong_owner_submit_not_claimed_fresh(self):
  for changes in [{'already_approved':True},{'operator':'other'},{'approver_key_id':'0'*32}]:
   q,sig=self.submit_fixture(**changes)
   with self.assertRaises(Refused):self.native.submit(q,sig)
   self.assertEqual(self.proofs,[])
 def test_wrong_signature_stops_before_control_submit(self):
  from cryptography.exceptions import InvalidSignature
  q,_=self.submit_fixture()
  with self.assertRaises(InvalidSignature):self.native.submit(q,b'0'*64)
  self.assertEqual(self.submits,[])
 def test_failed_chain_verification_not_returned_as_success(self):
  def broken(*a):raise ValueError('broken chain')
  self.ledger.verify=broken
  with self.assertRaises(ValueError):self.native.observe('show interfaces Ethernet0/1 switchport')
if __name__=='__main__':unittest.main()
