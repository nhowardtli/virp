import json,subprocess,unittest
from types import SimpleNamespace
from port_owner_remote import argv,exchange,HOST,COMMAND
from port_transaction import Refused
class Remote(unittest.TestCase):
 def test_pinned_fixed_command_no_shell_or_agent(self):
  args=argv('/private/key','/public/pins');self.assertEqual(args[-2:],[HOST,COMMAND])
  for x in ['StrictHostKeyChecking=yes','IdentityAgent=none','ForwardAgent=no','ClearAllForwardings=yes','ProxyCommand=none','ControlPath=none']:self.assertIn(x,args)
 def test_request_stays_on_stdin(self):
  calls=[]
  def run(args,**kw):calls.append((args,kw));return SimpleNamespace(returncode=0,stdout=b'{"ok":true}',stderr=b'')
  q={'action':'prepare','body':'$(no shell)'};self.assertTrue(exchange(['fixed'],q,run=run)['ok'])
  self.assertEqual(json.loads(calls[0][1]['input']),q);self.assertNotIn('shell',calls[0][1])
 def test_timeout_is_single_attempt(self):
  calls=[]
  def run(*a,**kw):calls.append(1);raise subprocess.TimeoutExpired('fixed',1)
  with self.assertRaisesRegex(Refused,'indeterminate_no_retry'):exchange(['fixed'],{'action':'authorize'},run=run)
  self.assertEqual(calls,[1])
 def test_explicit_denial_never_approval(self):
  def run(*a,**kw):return SimpleNamespace(returncode=1,stdout=b'{"ok":false,"error":"duo_denied"}',stderr=b'')
  self.assertEqual(exchange(['fixed'],{'action':'authorize'},run=run),{'ok':False,'error':'duo_denied'})
 def test_bad_output_and_failed_exit_refused(self):
  for code,out in [(0,b'not json'),(0,b'[]'),(0,b'{"ok":1}'),(1,b'{"ok":true}'),(0,b'x'*131073)]:
   with self.subTest(code=code,out=out[:20]),self.assertRaises(Refused):exchange(['fixed'],{'action':'status'},run=lambda *a,**kw:SimpleNamespace(returncode=code,stdout=out,stderr=b''))
if __name__=='__main__':unittest.main()
