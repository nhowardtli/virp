import base64,hashlib,importlib.util,json,pathlib,sqlite3,tempfile,unittest
spec=importlib.util.spec_from_file_location('exporter',pathlib.Path(__file__).with_name('virp_export_bundle.py'))
exporter=importlib.util.module_from_spec(spec);spec.loader.exec_module(exporter)

class ExportEncoding(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.db=self.root/'chain.db'
  self.conn=sqlite3.connect(self.db)
  self.conn.executescript('CREATE TABLE chain_entries(session_id TEXT,sequence INTEGER,chain_entry_hash TEXT,previous_entry_hash TEXT,timestamp_ns INTEGER,monotonic_ns INTEGER,artifact_type TEXT,artifact_id TEXT,artifact_hash TEXT,artifact_hash_alg TEXT,artifact_schema_version TEXT,signer_node_id INTEGER,signer_org_id TEXT,chain_hmac TEXT); CREATE TABLE chain_heads(session_id TEXT,last_sequence INTEGER,last_entry_hash TEXT,head_hmac TEXT); CREATE TABLE artifacts(artifact_hash TEXT,artifact_content);')
 def tearDown(self):self.conn.close();self.tmp.cleanup()
 def export(self,raw,stored):
  digest=hashlib.sha256(raw).hexdigest()
  self.conn.execute('INSERT INTO chain_entries VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',('test',0,'a'*64,'b'*64,1,1,'observation','frame',digest,'sha256','1',260,'test',''))
  self.conn.execute('INSERT INTO artifacts VALUES(?,?)',(digest,stored));self.conn.commit()
  exporter.export(str(self.db),str(self.root/'bundle'),'unit test')
  return (self.root/'bundle/artifacts'/digest).read_bytes()
 def test_base64_transport_restores_original_binary_frame(self):
  raw=b'\x03\x00\xffsigned frame bytes\x00'
  self.assertEqual(self.export(raw,'base64:'+base64.b64encode(raw).decode()),raw)
 def test_literal_utf8_preserved_exactly(self):
  raw='{"schema":"test","note":"café"}'.encode()
  self.assertEqual(self.export(raw,raw.decode()),raw)
 def test_blob_preserved_even_when_prefix_looks_like_encoding(self):
  raw=b'base64:AA=='
  self.assertEqual(self.export(raw,raw),raw)
 def test_malformed_encoded_storage_refuses_without_partial_bundle(self):
  with self.assertRaises(ValueError):self.export(b'frame','base64:!!!')
  self.assertFalse((self.root/'bundle').exists())
if __name__=='__main__':unittest.main()
