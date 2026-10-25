import hashlib,json,pathlib,sqlite3,tempfile,unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization as s
import publisher as p

class PublisherTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=pathlib.Path(self.tmp.name)
  self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(s.Encoding.Raw,s.PublicFormat.Raw);self.kid=hashlib.sha256(self.pub).hexdigest()[:32]
  self.db=self.root/'chain.db';c=sqlite3.connect(self.db)
  c.execute('CREATE TABLE chain_heads(session_id TEXT,last_sequence INTEGER,last_entry_hash TEXT,head_sig TEXT,head_sig_key_id TEXT)');c.commit();c.close()
  (self.root/'pub').write_bytes(self.pub)
  self.cfg={'format':'virp-kestrel-publisher/1','enabled':True,'sessions':['new-rw'],'chain_db':str(self.db),'chain_public_key':str(self.root/'pub'),'chain_signing_key':str(self.root/'private'),'heads':str(self.root/'heads'),'client':'/bin/false','witness_url':'http://127.0.0.1:18791','witness_public_key':str(self.root/'witness')}
  (self.root/'witness').write_text('ab'*32)
 def head(self,sid='new-rw',seq=0,digest='ab'*32,key=None,kid=None):
  key=key or self.key;b=p.canonical(sid,seq,digest)
  sig=key.sign(b'VIRP-CHAIN-HEAD-SIG-v1\0'+b).hex()
  c=sqlite3.connect(self.db);c.execute('INSERT INTO chain_heads VALUES(?,?,?,?,?)',(sid,seq,digest,sig,kid or self.kid));c.commit();c.close()
 def test_missing_session_refuses_without_submit(self):
  self.head('old');self.assertRaises(ValueError,p.selected_heads,self.cfg)
 def test_only_explicit_session(self):
  self.head();self.head('old');self.assertEqual([r['session_id'] for r in p.selected_heads(self.cfg)],['new-rw'])
 def test_wrong_signer_refused(self):
  self.head(key=Ed25519PrivateKey.generate());self.assertRaises(ValueError,p.selected_heads,self.cfg)
 def test_wrong_key_id_refused(self):
  self.head(kid='00'*16);self.assertRaises(ValueError,p.selected_heads,self.cfg)
 def test_unsigned_head_refused(self):
  self.head();c=sqlite3.connect(self.db);c.execute("UPDATE chain_heads SET head_sig='' ");c.commit();c.close();self.assertRaises(ValueError,p.selected_heads,self.cfg)
 def test_unsafe_session_refused(self):
  self.cfg['sessions']=['../escape'];self.assertRaises(ValueError,p.validate_config,self.cfg)
 def test_duplicate_sessions_refused(self):
  self.cfg['sessions']=['new-rw','new-rw'];self.assertRaises(ValueError,p.validate_config,self.cfg)
 def test_nonloopback_submission_refused(self):
  self.cfg['witness_url']='http://example.com';self.assertRaises(ValueError,p.validate_config,self.cfg)
 def test_empty_selection_refused_when_enabled(self):
  self.cfg['sessions']=[];self.assertRaises(ValueError,p.validate_config,self.cfg)
 def test_disabled_never_reads_database(self):
  self.cfg['enabled']=False;self.cfg['sessions']=[]
  with patch.object(p,'selected_heads',side_effect=AssertionError):self.assertEqual(p.run(self.cfg)['state'],'disabled')
 def test_dry_run_does_not_write(self):
  self.head();result=p.run(self.cfg,dry_run=True);self.assertEqual(result['state'],'validated');self.assertFalse((self.root/'heads').exists())
 def test_head_filename_is_collision_resistant(self):
  self.assertNotEqual(p.basename('a:b',0),p.basename('a_b',0))
 def test_receipt_binding_rejects_other_submitter(self):
  h={'session_id':'new-rw','last_sequence':0,'head_hash':'ab'*32,'key_id':self.kid}
  receipt={'v':'virp-witness-receipt/1','submission':{'chain_id':hashlib.sha256(b'new-rw').hexdigest(),'sequence':0,'head_hash':'ab'*32,'key_id':'00'*16}}
  self.assertRaises(ValueError,p.check_binding,receipt,h)
 def test_submit_success_requires_verified_receipt(self):
  self.head()
  with patch.object(p,'invoke') as call:
   call.return_value={'returncode':0,'stdout':'','stderr':''}
   self.assertRaises(ValueError,p.run,self.cfg)
 def test_partial_receipt_is_preserved_before_retry(self):
  self.head();root=self.root/'heads';root.mkdir();h=p.selected_heads(self.cfg)[0];f=root/(p.basename('new-rw',0)+'.witness.json');f.write_text('{bad')
  with patch.object(p,'invoke',return_value={'returncode':1,'stdout':'','stderr':'transport unavailable'}):self.assertRaises(ValueError,p.run,self.cfg)
  self.assertEqual(f.read_text(),'{bad');self.assertTrue(list(root.glob('*.invalid-*')))

if __name__=='__main__':unittest.main()
