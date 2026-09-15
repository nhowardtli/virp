import unittest,importlib.util,tempfile,pathlib,struct,base64,json,hmac,hashlib,datetime
s=importlib.util.spec_from_file_location('issuer','deploy/demo/issuer.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
def key(n=1):
 def f(b):return struct.pack('>I',len(b))+b
 return 'ssh-ed25519 '+base64.b64encode(f(b'ssh-ed25519')+f(bytes([n])*32)).decode()
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.p=pathlib.Path(self.tmp.name)/'keys';self.p.touch();self.events=[];self.now=1789490000;self.issuer=m.Issuer(self.p,self.events.append,lambda:self.now)
 def tearDown(self):self.tmp.cleanup()
 def request(self,k=None):return dict(name='Fixture Visitor',email='fixture@example.invalid',pubkey=k or key(),ts=self.now)
 def test_hmac_and_timestamp(self):
  raw=json.dumps(self.request()).encode();secret=b'fixture-secret';sig=hmac.new(secret,raw,hashlib.sha256).hexdigest()
  self.assertEqual(m.signed_request(raw,sig,secret,self.now),self.request())
  for body,signature,now in [(raw+b' ',sig,self.now),(raw,'0'*64,self.now),(raw,sig,self.now+121)]:
   with self.assertRaises(ValueError):m.signed_request(body,signature,secret,now)
 def test_key_validation(self):
  self.assertEqual(m.key_info(key())[0],key())
  for v in ['ssh-rsa AAAA',key()+'\nssh-ed25519 AAAA','x'*1025,'ssh-ed25519 AAAA','command="x" '+key()]:
   with self.assertRaises(ValueError):m.key_info(v)
 def test_issue_expiry_and_no_pii(self):
  r=self.issuer.issue(self.request());line=self.p.read_text();expected=datetime.datetime.fromtimestamp(self.now+86400,datetime.timezone.utc).strftime('%Y%m%d%H%M')
  self.assertIn('restrict,pty,expiry-time="'+expected+'",command="/usr/local/bin/virp-shell"',line)
  self.assertNotIn('fixture@example.invalid',json.dumps(self.events));self.assertEqual(self.events[0]['event'],'issue')
 def test_duplicate_and_cap(self):
  for n in range(1,51):self.issuer.issue(self.request(key(n)))
  before=self.p.read_bytes()
  for k in [key(),key(51)]:
   with self.assertRaises(ValueError):self.issuer.issue(self.request(k))
  self.assertEqual(before,self.p.read_bytes());self.assertEqual(self.events[-1]['event'],'refusal')
 def test_prune(self):
  self.issuer.issue(self.request());self.assertEqual(self.issuer.prune(),0);self.now+=86460
  self.assertEqual(self.issuer.prune(),1);self.assertEqual(self.p.read_text(),'');self.assertEqual(self.events[-1]['event'],'expiry-prune')
 def test_gate_failure_cannot_issue_or_prune(self):
  def fail(e):raise RuntimeError('fixture gate refusal')
  issuer=m.Issuer(self.p,fail,lambda:self.now)
  with self.assertRaises(RuntimeError):issuer.issue(self.request())
  self.assertEqual(self.p.read_bytes(),b'')
  self.issuer.issue(self.request());self.now+=86460;before=self.p.read_bytes()
  with self.assertRaises(RuntimeError):issuer.prune()
  self.assertEqual(before,self.p.read_bytes())
if __name__=='__main__':unittest.main()
