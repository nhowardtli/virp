import json,tempfile,unittest
from pathlib import Path
from standing_scope import StandingScope
from port_transaction import Refused
class StandingTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  (self.root/'records').mkdir();(self.root/'v3-recovery').mkdir()
  self.binding={'device':'SW-3850','ports':['GigabitEthernet1/0/22','GigabitEthernet1/0/23'],'authorization_sha256':'a'*64}
  self.policy={'schema':'kestrel-standing-scope/1',**self.binding}
  self.save();self.s=StandingScope(self.root,check_runtime=lambda:None,binding=self.binding,protect=lambda p,**kw:Path(p))
 def tearDown(self):self.tmp.cleanup()
 def save(self):(self.root/'policy.json').write_text(json.dumps(self.policy))
 def test_no_clock_dependency(self):
  with self.s.locked():self.assertEqual(self.s.check(),self.policy)
 def test_no_implicit_migration_of_lease(self):
  self.policy={'expires':99999999999,**self.binding};self.save()
  with self.s.locked(),self.assertRaises(Refused):self.s.check()
 def test_scope_binding(self):
  for k,v in [('device','other'),('ports',['GigabitEthernet1/0/24']),('authorization_sha256','b'*64)]:
   old=self.policy[k];self.policy[k]=v;self.save()
   with self.s.locked(),self.assertRaises(Refused):self.s.check()
   self.policy[k]=old
 def test_markers_retained(self):
  for n in ('STOP','v3-recovery/pending.json'):
   p=self.root/n;p.write_text('evidence')
   with self.s.locked(),self.assertRaises(Refused):self.s.check()
   self.assertEqual(p.read_text(),'evidence');p.unlink()
 def test_changed_policy_refused(self):
  with self.s.locked():
   self.s.check();self.policy['extra']=True;self.save()
   with self.assertRaises(Refused):self.s.check()
if __name__=='__main__':unittest.main()
