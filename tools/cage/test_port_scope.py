import json
import tempfile
import unittest
from pathlib import Path
from port_scope import ScopeGuard
from port_transaction import Refused

class ScopeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  (self.root/'records').mkdir();(self.root/'v3-recovery').mkdir()
  self.policy={'expires':200,'expires_boot':200,'boot_id':'boot\n','authorization_sha256':'a'*64}
  self.save();self.checks=[]
  self.guard=ScopeGuard(self.root,check_runtime=lambda:self.checks.append(True),wall=lambda:100,boottime=lambda:100,boot_id=lambda:'boot\n',protect=lambda p,**kw:Path(p))
 def tearDown(self):self.tmp.cleanup()
 def save(self):(self.root/'policy.json').write_text(json.dumps(self.policy))
 def test_lock_required_and_single_owner(self):
  with self.assertRaisesRegex(Refused,'scope_lock_required'):self.guard.check()
  with self.guard.locked():
   self.guard.check()
   other=ScopeGuard(self.root,check_runtime=lambda:None,protect=lambda p,**kw:Path(p))
   with self.assertRaisesRegex(Refused,'scope_busy'):
    with other.locked():pass
  self.assertEqual(len(self.checks),1)
 def test_expiry_at_boundary_on_either_clock(self):
  for name in ('expires','expires_boot'):
   self.policy[name]=100;self.save()
   with self.guard.locked():
    with self.assertRaisesRegex(Refused,'work_lease_inactive'):self.guard.check()
   self.policy[name]=200
  self.assertEqual(self.checks,[])
 def test_stop_and_pending_never_cleared(self):
  for name in ('STOP','v3-recovery/pending.json'):
   p=self.root/name;p.write_text('evidence')
   with self.guard.locked():
    with self.assertRaises(Refused):self.guard.check()
   self.assertEqual(p.read_text(),'evidence');p.unlink()
 def test_dangling_marker_symlink_still_blocks(self):
  (self.root/'STOP').symlink_to(self.root/'missing')
  with self.guard.locked():
   with self.assertRaisesRegex(Refused,'scope_stopped'):self.guard.check()
 def test_invalid_deadlines_and_boot_refuse(self):
  for change in ({'expires':float('nan')},{'expires':True},{'expires_boot':float('inf')},{'boot_id':'other'}):
   original=dict(self.policy);self.policy.update(change);self.save()
   with self.guard.locked():
    with self.assertRaises(Refused):self.guard.check()
   self.policy=original
 def test_reservation_is_durable_unique_and_consumes_budget(self):
  with self.guard.locked():
   self.guard.reserve({'operation':'port_prepare','request_id':'1'*32,'rationale':'test bounded transaction'})
   with self.assertRaisesRegex(Refused,'request_already_recorded'):
    self.guard.reserve({'operation':'port_prepare','request_id':'1'*32,'rationale':'test bounded transaction'})
  record=json.loads((self.root/'records'/('1'*32+'.request.json')).read_text())
  self.assertEqual(record['authorization_sha256'],'a'*64)
 def test_budget_applies_to_new_request_not_continuation(self):
  self.guard.limit=1
  (self.root/'records'/'old.request.json').write_text('{}')
  with self.guard.locked():
   self.guard.check()
   with self.assertRaisesRegex(Refused,'attempt_limit'):
    self.guard.reserve({'operation':'port_prepare','request_id':'1'*32,'rationale':'test bounded transaction'})
 def test_stop_latch_preserves_first_reason(self):
  with self.guard.locked():
   self.guard.stop('unexpected_preapproval_result')
   before=(self.root/'STOP').read_bytes();self.guard.stop('later_reason')
  self.assertEqual(before,(self.root/'STOP').read_bytes())
 def test_policy_change_mid_operation_refuses(self):
  with self.guard.locked():
   self.guard.check();self.policy['expires']=250;self.save()
   with self.assertRaisesRegex(Refused,'scope_policy_changed'):self.guard.check()
if __name__=='__main__':unittest.main()
