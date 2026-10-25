import unittest
from open_canary import validate
class OpenTests(unittest.TestCase):
 def request(self):return {'operation':'port_open_execute','request_id':'a'*32,'rationale':'Inspect the isolated canary for qualification.','command':'show version'}
 def test_scope_journal_accepts_open_operation(self):
  import tempfile
  from pathlib import Path
  from port_scope import ScopeGuard
  with tempfile.TemporaryDirectory() as d:
   root=Path(d);(root/'records').mkdir()
   scope=ScopeGuard(root,check_runtime=lambda:None,protect=lambda p,**kw:Path(p))
   scope.check=lambda:{'authorization_sha256':'a'*64}
   q=self.request();scope.reserve({k:q[k] for k in ('operation','request_id','rationale')})
   self.assertTrue((root/'records'/(q['request_id']+'.request.json')).exists())
 def test_green_yellow_red_are_not_helper_filtered(self):
  for cmd in ('show version','show running-config','configure terminal','interface Ethernet0/1 switchport port-security','reload'):
   q=self.request();q['command']=cmd;self.assertEqual(validate(q),q)
 def test_target_approval_and_host_override_refuse(self):
  for key in ('device','host','proposal_id','approval','socket'):
   q=self.request();q[key]='override'
   with self.assertRaises(ValueError):validate(q)
 def test_invalid_request(self):
  for key,value in [('command','x\nreload'),('command',''),('command','x'*1025),('request_id','../x'),('rationale','short')]:
   q=self.request();q[key]=value
   with self.assertRaises(ValueError):validate(q)
if __name__=='__main__':unittest.main()
