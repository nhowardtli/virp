"""Failure/restart contract: never redispatch an ambiguous observation attempt."""
import hashlib,json,pathlib,tempfile,unittest
from unittest.mock import patch
from helper import execute_observed

class Transport:
 def __init__(self,fail=None):self.calls=[];self.fail=fail
 def management(self,q):
  a=q['action'];self.calls.append(a)
  if a=='session_hello':return {'client_nonce':q['client_nonce'],'session_id':'11'*16,'server_nonce':'22'*8}
  if a=='session_bind':return {'active':True,'status':'bound'}
  if a=='session_close' and self.fail=='close':raise OSError('close failed')
  if a=='chain_append':
   if self.fail=='append':raise OSError('append failed')
   return {'session_id':'test','chain_entry_hash':'a'*64,'sequence':0}
  return {}
 def raw(self,q):
  self.calls.append('execute')
  if self.fail=='execute':raise TimeoutError('reply lost')
  return b'raw-frame'

class Attempts(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)
 def call(self,t,name='one',**kw):
  return execute_observed(t,{'action':'execute','device':'test','command':'show version'},public_key=b'0'*32,node_id=1,device_id=1,path=self.root/name,chain_session='test',artifact_id=name,**kw)
 def decoded(self):return patch('helper.decode',return_value={'version':3,'subtype':7,'output':'observed'})
 def test_existing_frame_prevents_dispatch(self):
  (self.root/'one').write_bytes(b'prior');t=Transport()
  with self.decoded(),self.assertRaises((ValueError,FileExistsError)):self.call(t)
  self.assertEqual(t.calls,[])
 def test_ambiguous_timeout_prevents_same_attempt_after_restart(self):
  with self.assertRaises(TimeoutError):self.call(Transport('execute'))
  t=Transport()
  with self.decoded(),self.assertRaises((ValueError,FileExistsError)):self.call(t)
  self.assertEqual(t.calls,[])
 def test_completed_attempt_cannot_dispatch_twice(self):
  with self.decoded():self.call(Transport())
  t=Transport()
  with self.decoded(),self.assertRaises((ValueError,FileExistsError)):self.call(t)
  self.assertEqual(t.calls,[])
 def test_pending_scope_blocks_new_request(self):
  with self.assertRaises(TimeoutError):self.call(Transport('execute'),recovery_dir=self.root/'recovery')
  t=Transport()
  with self.assertRaises(ValueError):self.call(t,'two',recovery_dir=self.root/'recovery')
  self.assertEqual(t.calls,[])
 def test_success_releases_scope(self):
  with self.decoded():
   self.call(Transport(),recovery_dir=self.root/'recovery');self.call(Transport(),'two',recovery_dir=self.root/'recovery')
  self.assertFalse((self.root/'recovery/pending.json').exists())
 def test_invalid_frame_preserved_without_chain_claim(self):
  t=Transport()
  with self.assertRaises(ValueError):self.call(t)
  self.assertEqual((self.root/'one.unverified.frame').read_bytes(),b'raw-frame')
  self.assertNotIn('chain_append',t.calls)
 def test_close_failure_keeps_verified_frame_and_pending(self):
  with self.decoded(),self.assertRaises(OSError):self.call(Transport('close'),recovery_dir=self.root/'recovery')
  self.assertEqual((self.root/'one').read_bytes(),b'raw-frame')
  self.assertTrue((self.root/'recovery/pending.json').exists())
 def test_append_failure_no_retry(self):
  t=Transport('append')
  with self.decoded(),self.assertRaises(OSError):self.call(t)
  self.assertEqual(t.calls.count('execute'),1);self.assertEqual(t.calls.count('chain_append'),1)
  self.assertEqual((self.root/'one').read_bytes(),b'raw-frame')
 def test_close_failure_does_not_replace_original_error(self):
  t=Transport('close')
  with patch('helper.decode',side_effect=ValueError('bad signature')),self.assertRaisesRegex(ValueError,'bad signature'):self.call(t)
