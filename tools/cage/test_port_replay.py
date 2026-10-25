import hashlib,json,unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from port_replay import verify_pair
from port_transaction import canonical

class ReplayTests(unittest.TestCase):
 def setUp(self):
  self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  self.pid='a'*32;self.command='interface Ethernet0/1 switchport mode access'
  self.outcome={'proposal_id':self.pid,'device':'kestrel-ios','command_hash':hashlib.sha256(self.command.encode()).hexdigest(),'success':True,'approval_entry_hash':'c'*64}
  self.rejection={'schema':'gate_rejection/1','reason':'approval_reused','error_code':-37,'approval_id':self.pid,'proposal_id':self.pid,'device':'kestrel-ios','command':self.command,'executed':False,'original_outcome_id':'outcome:'+self.pid}
 def signed(self,body,kind,aid,sid,timestamp):
  raw=canonical(body);e={'artifact_hash':hashlib.sha256(raw).hexdigest(),'artifact_hash_alg':'sha256','artifact_id':aid,'artifact_schema_version':'1','artifact_type':kind,'monotonic_ns':1,'previous_entry_hash':'0'*64,'sequence':1,'session_id':sid,'signer_node_id':260,'signer_org_id':'test','timestamp_ns':timestamp}
  payload=canonical(e);e.update(chain_entry_hash=hashlib.sha256(payload).hexdigest(),chain_sig_key_id=hashlib.sha256(self.pub).hexdigest()[:32],chain_sig=self.key.sign(b'VIRP-CHAIN-ENTRY-SIG-v1\0'+payload).hex())
  return e,raw
 def pair(self):
  return self.signed(self.rejection,'gate_rejection','replay:'+self.pid+':17','gate-enforce:kestrel-ios@test',200),self.signed(self.outcome,'outcome','outcome:'+self.pid,'approval:kestrel-ios@test',100)
 def check(self,pair=None,**changes):
  rejection,outcome=pair or self.pair()
  args={'public_key':self.pub,'node_id':260,'device':'kestrel-ios','command':self.command,'proposal_id':self.pid,'gate_session':'gate-enforce:kestrel-ios@test','approval_session':'approval:kestrel-ios@test','prior_outcome_hash':outcome[0]['artifact_hash'],'not_before_ns':150}
  args.update(changes);return verify_pair(rejection,outcome,**args)
 def test_signed_rejection_links_unchanged_successful_outcome(self):
  r=self.check();self.assertEqual(r['error_code'],-37);self.assertEqual(r['original_outcome_id'],'outcome:'+self.pid)
 def test_semantic_rejection_forgery_refused_even_with_valid_signature(self):
  for key,value in [('executed',True),('error_code',0),('approval_id','b'*32),('original_outcome_id','outcome:'+'b'*32),('device','SW-3850'),('command','reload')]:
   old=dict(self.rejection);self.rejection[key]=value
   with self.assertRaises(ValueError):self.check()
   self.rejection=old
 def test_modified_prior_outcome_refused(self):
  with self.assertRaises(ValueError):self.check(prior_outcome_hash='0'*64)
 def test_unknown_original_result_not_successful_replay_acceptance(self):
  self.outcome['success']=False
  with self.assertRaises(ValueError):self.check()
 def test_stale_or_wrong_chain_rejection_refused(self):
  for change in ({'not_before_ns':201},{'gate_session':'gate-enforce:kestrel-ios@other'},{'node_id':261}):
   with self.assertRaises(ValueError):self.check(**change)
 def test_wrong_signature_and_artifact_bytes_refuse(self):
  pair=self.pair();pair[0][0]['chain_sig']='0'*128
  with self.assertRaises(ValueError):self.check(pair)
  rejection,outcome=self.pair()
  with self.assertRaises(ValueError):self.check(((rejection[0],b'{}'),outcome))
 def test_exported_signature_wrapper_is_supported(self):
  pair=self.pair()
  for e,raw in pair:
   e['signature']={'signature_scheme':'ed25519-detached-v1','signing_key_id':e.pop('chain_sig_key_id'),'signature_hex':e.pop('chain_sig')}
  self.assertEqual(self.check(pair)['error_code'],-37)
if __name__=='__main__':unittest.main()
