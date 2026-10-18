import hashlib,json,sqlite3,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from port_transaction import canonical
from port_ledger import EventLedger

class LedgerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.path=Path(self.tmp.name)/'chain.db'
  self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
  self.db=sqlite3.connect(self.path)
  self.db.executescript('''CREATE TABLE chain_entries(artifact_hash TEXT,artifact_hash_alg TEXT,artifact_id TEXT,artifact_schema_version INTEGER,artifact_type TEXT,monotonic_ns INTEGER,previous_entry_hash TEXT,sequence INTEGER,session_id TEXT,signer_node_id INTEGER,signer_org_id TEXT,timestamp_ns INTEGER,chain_entry_hash TEXT,chain_sig_key_id TEXT,chain_sig TEXT); CREATE TABLE artifacts(artifact_id TEXT,artifact_hash TEXT,artifact_content TEXT);''')
  self.calls=0;self.broken=False;self.lose_reply=False
  self.ledger=EventLedger(self.path,self,self.pub,'test-session')
  self.event={'schema':'kestrel-port-event/1','event_id':'a'*32,'transaction_id':'b'*32,'type':'proposal','time_ns':1}
 def tearDown(self):self.db.close();self.tmp.cleanup()
 def management(self,q):
  if q['action']=='chain_verify':return {'valid':not self.broken,'entries_checked':q['to_sequence']+1,'executions_open':0}
  self.calls+=1
  seq=self.db.execute('select count(*) from chain_entries').fetchone()[0]
  e=dict(artifact_hash=q['artifact_hash'],artifact_hash_alg='sha256',artifact_id=q['artifact_id'],artifact_schema_version=1,artifact_type='evidence_item',monotonic_ns=1,previous_entry_hash='0'*64,sequence=seq,session_id=q['session_id'],signer_node_id=260,signer_org_id='test',timestamp_ns=1)
  raw=canonical(e);e.update(chain_entry_hash=hashlib.sha256(raw).hexdigest(),chain_sig_key_id=hashlib.sha256(self.pub).hexdigest()[:32],chain_sig=self.key.sign(b'VIRP-CHAIN-ENTRY-SIG-v1\0'+raw).hex())
  self.db.execute('INSERT INTO chain_entries VALUES('+','.join('?' for _ in e)+')',tuple(e.values()))
  self.db.execute('INSERT INTO artifacts VALUES(?,?,?)',(q['artifact_id'],q['artifact_hash'],q['artifact_content']));self.db.commit()
  if self.lose_reply:raise TimeoutError('append reply lost')
  return {'ok':True}
 def test_append_and_retry_returns_same_verified_receipt(self):
  first=self.ledger(self.event);self.assertEqual(first,self.ledger(self.event));self.assertEqual(self.calls,1)
 def test_lost_reply_retry_does_not_append_twice(self):
  self.lose_reply=True
  with self.assertRaises(TimeoutError):self.ledger(self.event)
  self.lose_reply=False;self.ledger(self.event);self.assertEqual(self.calls,1)
 def test_same_id_different_bytes_refused(self):
  self.ledger(self.event)
  with self.assertRaises(ValueError):self.ledger({**self.event,'type':'approval'})
  self.assertEqual(self.calls,1)
 def test_invalid_signature_refused_on_retry(self):
  self.ledger(self.event);self.db.execute("update chain_entries set chain_sig=?",('00'*64,));self.db.commit()
  with self.assertRaises(ValueError):self.ledger(self.event)
 def test_broken_chain_refused(self):
  self.broken=True
  with self.assertRaises(ValueError):self.ledger(self.event)
 def test_duplicate_entry_refused(self):
  self.ledger(self.event);self.db.execute('insert into chain_entries select * from chain_entries');self.db.commit()
  with self.assertRaises(ValueError):self.ledger(self.event)
 def test_artifact_bytes_tampered_refused(self):
  self.ledger(self.event);self.db.execute("update artifacts set artifact_content='{}'");self.db.commit()
  with self.assertRaises(ValueError):self.ledger(self.event)
if __name__=='__main__':unittest.main()
