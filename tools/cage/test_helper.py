import base64, hashlib, pathlib, struct, tempfile, time, unittest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from helper import decode, store, bind

class Contract(unittest.TestCase):
 def setUp(self):
  self.key=Ed25519PrivateKey.generate(); self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  self.sid=bytes.fromhex('12'*16); self.command='show version'; self.now=time.time_ns()
 def frame(self, **kw):
  d=dict(version=3,channel=1,tier=1,reserved=0,node=256,timestamp=self.now,seq=1,sid=self.sid,device=55,command=hashlib.sha256(self.command.encode()).digest(),typ=7,scope=1,body=b'FRRouting')
  d.update(kw); p=b'VIRP-XO1'+struct.pack('!BBH',d['typ'],d['scope'],len(d['body']))+d['body']
  b=struct.pack('!BBBBQQQ16sQ32sI',*[d[x] for x in ['version','channel','tier','reserved','node','timestamp','seq','sid','device','command']],len(p))+p+b'\0'*32
  return b+self.key.sign(b)
 def check(self, b, **kw):
  args=dict(public_key=self.pub,session_id=self.sid,node_id=256,device_id=55,command=self.command,after_sequence=0,now_ns=self.now);args.update(kw);return decode(b,**args)
 def test_output(self):self.assertEqual(self.check(self.frame())['output'],'FRRouting')
 def test_refusal(self):self.assertEqual(self.check(self.frame(typ=15,tier=3,body=b'refused'))['subtype'],15)
 def test_bound_fields(self):
  for changes in [dict(version=1),dict(channel=2),dict(reserved=1),dict(node=1),dict(device=1),dict(sid=b'2'*16),dict(command=b'3'*32),dict(seq=0),dict(timestamp=self.now-121_000_000_000),dict(timestamp=self.now+121_000_000_000),dict(typ=6),dict(scope=2),dict(body=b'\xff')]:
   with self.subTest(changes=changes),self.assertRaises(ValueError):self.check(self.frame(**changes))
 def test_tampering(self):
  b=self.frame()
  for i in (0,28,88,len(b)-1):
   q=bytearray(b);q[i]^=1
   with self.assertRaises(ValueError):self.check(bytes(q))
 def test_wrong_key(self):
  with self.assertRaises(ValueError):self.check(self.frame(),public_key=b'0'*32)
 def test_lengths(self):
  b=self.frame()
  for x in (b'',b[:80],b[:-1],b+b'x'):
   with self.assertRaises(ValueError):self.check(x)
 def test_store_exact(self):
  with tempfile.TemporaryDirectory() as td:
   calls=[];b=self.frame();p=pathlib.Path(td)/'observation'
   out=store(b,p,'session','id',lambda r:calls.append(r) or {'session_id':'session','chain_entry_hash':'a'*64,'sequence':0})
   self.assertEqual(p.read_bytes(),b);self.assertEqual(base64.b64decode(calls[0]['artifact_content'][7:]),b)
   self.assertEqual(calls[0]['artifact_hash'],hashlib.sha256(b).hexdigest())
 def test_maximum_signed_frame_decode(self):
  frame=self.frame(body=b'x'*(65536-196))
  self.assertEqual(len(frame),65536)
  self.assertEqual(len(self.check(frame)['output']),65536-196)
  with self.assertRaisesRegex(ValueError,'oversized_v3_frame'):
   self.check(self.frame(body=b'x'*(65537-196)))
 def test_large_store_exact_and_bounded(self):
  for size in (9659, 65536):
   with tempfile.TemporaryDirectory() as td:
    b=b'x'*size;calls=[];p=pathlib.Path(td)/'obs'
    store(b,p,'session','id',lambda r:calls.append(r) or {'session_id':'session','chain_entry_hash':'a'*64,'sequence':0})
    self.assertEqual(base64.b64decode(calls[0]['artifact_content'][7:]),b)
    self.assertEqual(p.read_bytes(),b)
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'obs';b=b'x'*65537
   with self.assertRaises(ValueError):store(b,p,'s','i',lambda r:self.fail('oversize append'))
   self.assertEqual(p.read_bytes(),b)
 def test_store_failure_preserves_frame_no_retry(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'obs';b=self.frame();calls=[]
   def fail(r):calls.append(r);raise ValueError('store failed')
   with self.assertRaises(ValueError):store(b,p,'session','id',fail)
   self.assertEqual(p.read_bytes(),b);self.assertEqual(len(calls),1)
 def test_duplicate_storage_refused(self):
  with tempfile.TemporaryDirectory() as td:
   p=pathlib.Path(td)/'obs';p.write_bytes(b'prior')
   with self.assertRaises(FileExistsError):store(self.frame(),p,'s','i',lambda r:self.fail('dispatch'))
class Binding(unittest.TestCase):
 def test_bind_failure_stops_before_execute(self):
  class T:
   def __init__(self):self.calls=[]
   def management(self,r):
    self.calls.append(r)
    if r['action']=='session_hello':return dict(client_nonce=r['client_nonce'],session_id='11'*16,server_nonce='22'*8)
    return {'active':False,'status':'refused'}
  t=T()
  with self.assertRaises(ValueError):bind(t,'test')
  self.assertEqual([r['action'] for r in t.calls],['session_hello','session_bind'])
 def test_wrong_nonce_no_bind(self):
  class T:
   def management(self,r):
    assert r['action']=='session_hello'
    return {'client_nonce':'wrong'}
  with self.assertRaises(ValueError):bind(T(),'test')
 def test_append_ack_wrong_session(self):
  with tempfile.TemporaryDirectory() as td:
   with self.assertRaises(ValueError):store(b'frame',pathlib.Path(td)/'obs','expected','id',lambda r: {'session_id':'other','chain_entry_hash':'a'*64,'sequence':0})

if __name__=='__main__':unittest.main()

class ExecuteContract(unittest.TestCase):
 def test_bind_failure_never_dispatches(self):
  from helper import execute_observed
  class T:
   def management(self,r):raise ValueError('bind refused')
   def raw(self,r):raise AssertionError('execute dispatched')
  with tempfile.TemporaryDirectory() as td, self.assertRaises(ValueError):
   execute_observed(T(), {'command':'show version'}, public_key=b'0'*32,
                    node_id=1, device_id=1, path=pathlib.Path(td)/'f', chain_session='s',artifact_id='i')
