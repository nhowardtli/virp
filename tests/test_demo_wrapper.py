import unittest,tempfile,pathlib,os,runpy,sys
from unittest.mock import patch
class WrapperTests(unittest.TestCase):
 def test_authentication_context_selects_only_matching_seat(self):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d);auth=root/'auth';keys=root/'keys';auth.write_text('publickey ssh-ed25519 AAAAFIXTURE\n');auth.chmod(0o600)
   seat='a'*96;keys.write_text('restrict,pty,expiry-time="202609161200",command="/usr/local/bin/virp-shell" ssh-ed25519 AAAAFIXTURE demo:'+seat+'\n')
   realpath=pathlib.Path
   def mapped(p):return keys if str(p)=='/etc/ssh/authorized_keys.d/virp-demo' else realpath(p)
   with patch.dict(os.environ,{'SSH_USER_AUTH':str(auth)}),patch('pathlib.Path',side_effect=mapped),patch('os.execv',side_effect=SystemExit) as execute,patch.object(sys,'argv',['virp-shell']):
    with self.assertRaises(SystemExit):runpy.run_path('deploy/demo/shell.wrapper',run_name='__main__')
   self.assertEqual(execute.call_args.args[1],['sudo','-n','-u','virp-shell','--','/usr/bin/python3','/usr/local/lib/virp/virp-shell','--demo-seat',seat])
 def test_unsafe_auth_context_never_executes(self):
  with tempfile.TemporaryDirectory() as d:
   auth=pathlib.Path(d)/'auth';auth.write_text('publickey ssh-ed25519 AAAAFIXTURE\n');auth.chmod(0o644)
   with patch.dict(os.environ,{'SSH_USER_AUTH':str(auth)}),patch('os.execv') as execute:
    with self.assertRaises(SystemExit):runpy.run_path('deploy/demo/shell.wrapper',run_name='__main__')
   execute.assert_not_called()
if __name__=='__main__':unittest.main()
