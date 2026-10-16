"""Recovery must never turn uncertainty or a failed attestation into permission."""
import hashlib,json,pathlib,tempfile,unittest
from unittest.mock import patch
import recovery

class RecoveryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name);self.scope=self.root/'scope';self.scope.mkdir();(self.scope/'v3-recovery').mkdir();self.pending=self.scope/'v3-recovery/pending.json'
  self.request={'action':'execute','device':'ios','command':'interface Ethernet0/1 description TEST'}
  self.intent={'artifact_id':'unknown','chain_session':'old','request_sha256':hashlib.sha256(json.dumps(self.request,sort_keys=True,separators=(',',':')).encode()).hexdigest(),'time_ns':1}
  self.pending.write_text(json.dumps(self.intent));self.frame=self.root/'old.frame';self.frame.write_bytes(b'unknown');pathlib.Path(str(self.frame)+'.intent.json').write_bytes(self.pending.read_bytes())
  self.calls=[];self.record=None
  self.profile={'scope':str(self.scope),'unknown_frame':str(self.frame),'request':self.request,'node_id':260,'device_id':42,'public_key':'11'*32,'pending_sha256':hashlib.sha256(self.pending.read_bytes()).hexdigest(),'read_command':'show interfaces Ethernet0/1','interface':'Ethernet0/1','expected_description':'','expected_admin_down':True,'chain_session':'recovery-test'}
 def chain(self,raw,sid,aid):self.calls.append(('verify',sid,aid));return {'chain_entry_hash':hashlib.sha256(raw).hexdigest(),'session_id':sid,'artifact_id':aid,'sequence':0}
 def append(self,body,sid,aid):self.record=json.loads(body);self.calls.append(('append',sid,aid));return self.chain(body,sid,aid)
 def read(self,*a,**kw):
  self.calls.append(('read',a[1]));kw['path'].write_bytes(b'read');return b'read',{'version':3,'subtype':7,'output':'Ethernet0/1 is administratively down, line protocol is down (disabled)\n','public_signature_verified':True,'chain_entry':{'session_id':'recovery-test','sequence':0,'chain_entry_hash':'a'*64}}
 def run_recovery(self,**kw):
  return recovery.reconcile(self.profile,object(),verify_entry=self.chain,append_record=self.append,**kw)
 def mocks(self):
  return patch.multiple(recovery,verify_unknown=lambda *a,**k:{'frame_sha256':hashlib.sha256(b'unknown').hexdigest(),'session_id':'11'*16,'output':'ERROR: outcome UNKNOWN'},execute_observed=self.read)
 def test_success_archives_pending_and_links_both_observations(self):
  (self.scope/'STOP').write_bytes(b'operator stop')
  with self.mocks():r=self.run_recovery()
  self.assertFalse(self.pending.exists());self.assertEqual((self.scope/'STOP').read_bytes(),b'operator stop');self.assertEqual(self.record['original_outcome'],'UNKNOWN');self.assertEqual(self.record['resolution'],'current_state_verified');self.assertEqual(self.record['unknown']['artifact_id'],'unknown');self.assertTrue(pathlib.Path(r['archived_pending']).exists());self.assertEqual(sum(x[0]=='read' for x in self.calls),1)
 def test_reused_recovery_cannot_read_again(self):
  with self.mocks():self.run_recovery()
  n=len(self.calls)
  with self.mocks(),self.assertRaises((ValueError,FileNotFoundError)):self.run_recovery()
  self.assertEqual(len(self.calls),n)
 def test_changed_pending_refused_before_read(self):
  self.pending.write_text('{}')
  with self.mocks(),self.assertRaises(ValueError):self.run_recovery()
  self.assertFalse(self.calls)
 def test_original_request_mismatch_refused(self):
  self.profile['request']['command']='reload'
  with self.mocks(),self.assertRaises(ValueError):self.run_recovery()
  self.assertFalse(self.calls)
 def test_recovery_command_cannot_be_a_write(self):
  self.profile['read_command']='configure terminal'
  with self.mocks(),self.assertRaises(ValueError):self.run_recovery()
  self.assertFalse(self.calls)
 def test_wrong_state_keeps_pending(self):
  self.profile['expected_description']='DIFFERENT'
  with self.mocks(),self.assertRaises(ValueError):self.run_recovery()
  self.assertTrue(self.pending.exists());self.assertIsNone(self.record)
 def test_read_error_keeps_pending_and_cannot_retry(self):
  with self.mocks(),patch.object(recovery,'execute_observed',side_effect=TimeoutError),self.assertRaises(TimeoutError):self.run_recovery()
  with self.mocks(),self.assertRaises((ValueError,FileExistsError)):self.run_recovery()
  self.assertTrue(self.pending.exists())
 def test_append_lost_reply_keeps_pending_and_cannot_retry(self):
  with self.mocks(),patch.object(self,'append',side_effect=TimeoutError),self.assertRaises(TimeoutError):self.run_recovery()
  with self.mocks(),self.assertRaises((ValueError,FileExistsError)):self.run_recovery()
  self.assertTrue(self.pending.exists())
 def test_bad_original_signature_never_reads(self):
  with self.mocks(),patch.object(recovery,'verify_unknown',side_effect=ValueError),self.assertRaises(ValueError):self.run_recovery()
  self.assertFalse(self.calls)
 def test_original_missing_from_chain_never_reads(self):
  with self.mocks(),patch.object(self,'chain',side_effect=ValueError),self.assertRaises(ValueError):self.run_recovery()
  self.assertFalse(any(x[0]=='read' for x in self.calls))
 def test_uncertain_reconciliation_never_releases(self):
  def failed(*a,**k):return b'bad',{'subtype':15,'output':'ERROR: outcome UNKNOWN','recovery_required':True}
  with self.mocks(),patch.object(recovery,'execute_observed',side_effect=failed),self.assertRaises(ValueError):self.run_recovery()
  self.assertTrue(self.pending.exists());self.assertIsNone(self.record)
 def test_pending_mutation_during_read_never_releases(self):
  def mutate(*a,**k):self.pending.write_bytes(b'changed');return self.read(*a,**k)
  with self.mocks(),patch.object(recovery,'execute_observed',side_effect=mutate),self.assertRaises(ValueError):self.run_recovery()
  self.assertEqual(self.pending.read_bytes(),b'changed');self.assertIsNone(self.record)

class SignatureTests(unittest.TestCase):
 def test_historical_unknown_requires_real_signature_and_binding(self):
  from test_helper import Contract
  f=Contract();f.setUp();p={'public_key':f.pub.hex(),'node_id':256,'device_id':55,'request':{'command':f.command}}
  raw=f.frame(typ=15,body=b'ERROR: outcome UNKNOWN on test',timestamp=f.now-500_000_000_000)
  self.assertTrue(recovery.verify_unknown(raw,p)['public_signature_verified'])
  for b in (raw[:-1]+bytes([raw[-1]^1]),f.frame(),f.frame(typ=15,body=b'ERROR: driver execute failed')):
   with self.assertRaises(ValueError):recovery.verify_unknown(b,p)
  p['request']['command']='reload'
  with self.assertRaises(ValueError):recovery.verify_unknown(raw,p)
 def test_chain_entry_signature_pin_and_hash(self):
  from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
  from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
  key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  e=dict(artifact_hash='a'*64,artifact_hash_alg='sha256',artifact_id='id',artifact_schema_version='1',artifact_type='evidence_item',monotonic_ns=1,previous_entry_hash='b'*64,sequence=0,session_id='s',signer_node_id=260,signer_org_id='local',timestamp_ns=2)
  b=recovery.canonical(e);e.update(chain_entry_hash=recovery.digest(b),chain_sig_key_id=recovery.digest(pub)[:32],chain_sig=key.sign(b'VIRP-CHAIN-ENTRY-SIG-v1\0'+b).hex())
  recovery.verify_entry_signature(e,pub)
  e['sequence']=1
  with self.assertRaises(ValueError):recovery.verify_entry_signature(e,pub)
 def test_public_error_does_not_leak_unrecognized_exception_text(self):
  from helper import public_error
  self.assertEqual(public_error(ValueError('unresolved_attempt_requires_reconciliation')),'unresolved_attempt_requires_reconciliation')
  self.assertEqual(public_error(ValueError('secret detail')),'ValueError')

class AuthorityTests(unittest.TestCase):
 def test_append_uses_separate_root_transport(self):
  class T:
   def __init__(self):self.calls=[]
   def management(self,q):self.calls.append(q);return {}
  requester=T();root=T();ledger=recovery.Ledger('/unused',requester,b'1'*32,root)
  with patch.object(ledger,'verify',return_value={'checked':True}):self.assertEqual(ledger.append(b'{}','s','id'),{'checked':True})
  self.assertEqual(requester.calls,[]);self.assertEqual(root.calls[0]['action'],'chain_append');self.assertEqual(root.calls[0]['artifact_type'],'evidence_item')
 def test_requester_identity_mismatch_never_executes(self):
  from types import SimpleNamespace
  with patch.object(recovery.pwd,'getpwnam',return_value=SimpleNamespace(pw_uid=981)),patch.object(recovery.subprocess,'check_output') as child,self.assertRaises(ValueError):recovery.RequesterSocket('/sock','virp-kreq',980)
  child.assert_not_called()

class StateFormattingTests(unittest.TestCase):
 def test_ios_trailing_space_is_not_state_drift(self):
  p={'interface':'Ethernet0/1','expected_admin_down':True,'expected_description':''}
  recovery.check_state({'subtype':7,'output':'Ethernet0/1 is administratively down, line protocol is down (disabled) \r\n'},p)
 def test_duplicate_or_changed_header_refused(self):
  p={'interface':'Ethernet0/1','expected_admin_down':True,'expected_description':''}
  for text in ['Ethernet0/1 is up, line protocol is up\n', 'Ethernet0/1 is administratively down, line protocol is down (disabled)\n'*2]:
   with self.assertRaises(ValueError):recovery.check_state({'subtype':7,'output':text},p)

class ReviewedRetryTests(unittest.TestCase):
 setUp=RecoveryTests.setUp
 chain=RecoveryTests.chain
 append=RecoveryTests.append
 read=RecoveryTests.read
 run_recovery=RecoveryTests.run_recovery
 mocks=RecoveryTests.mocks
 def test_review_never_retries_uncertain_read(self):
  with self.mocks(),patch.object(recovery,'execute_observed',side_effect=TimeoutError),self.assertRaises(TimeoutError):self.run_recovery()
  with self.assertRaises((ValueError,FileNotFoundError)):recovery.review_failed_read(self.profile,verify_entry=self.chain,append_record=self.append,reason='Inspect the failed read before another reconciliation.')
  self.assertTrue(self.pending.exists())
 def test_review_never_retries_ambiguous_append(self):
  with self.mocks(),patch.object(self,'append',side_effect=TimeoutError),self.assertRaises(TimeoutError):self.run_recovery()
  with self.assertRaises(ValueError):recovery.review_failed_read(self.profile,verify_entry=self.chain,append_record=self.append,reason='Inspect the failed append before another reconciliation.')
  self.assertTrue(self.pending.exists())
 def test_review_archives_failed_attempt_before_new_read(self):
  self.profile['expected_description']='DIFFERENT'
  with self.mocks(),self.assertRaises(ValueError):self.run_recovery()
  before=len(self.calls)
  with patch.object(recovery,'decode',return_value={'subtype':7}):
   # The fake raw frame must reach the bounded envelope length gate.
   journal=self.scope/'v3-recovery/reconciliations'/self.profile['pending_sha256'];(journal/'read.frame').write_bytes(b'0'*196)
   r=recovery.review_failed_read(self.profile,verify_entry=self.chain,append_record=self.append,reason='The state checker rejected harmless IOS header spacing; preserve this attempt and capture fresh evidence.')
  self.assertTrue(self.pending.exists());self.assertTrue(pathlib.Path(r['archived_attempt']).exists());self.assertEqual(sum(c[0]=='read' for c in self.calls[before:]),0)
