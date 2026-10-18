import copy,unittest
from vm_acceptance import verify_reboot
class Acceptance(unittest.TestCase):
 def setUp(self):
  b=dict(target='colo-vm231',identity={'uuid':'fixed'},machine_id='m',boot_id='before',guest_ready=True,state='status: running')
  self.rows=[dict(action='status',ok=True,observation=b),dict(action='reboot',ok=True,observation=dict(target='colo-vm231',accepted=True,before=b,task='UPID:abc')),dict(action='status',ok=True,observation=dict(b,boot_id='after'))]
 def test_complete(self):self.assertTrue(verify_reboot(self.rows)['reboot_verified'])
 def test_same_boot(self):
  self.rows[-1]['observation']['boot_id']='before'
  with self.assertRaises(ValueError):verify_reboot(self.rows)
 def test_accepted_only(self):
  with self.assertRaises(ValueError):verify_reboot(self.rows[:-1])
 def test_changed_machine(self):
  self.rows[-1]['observation']['machine_id']='other'
  with self.assertRaises(ValueError):verify_reboot(self.rows)
 def test_duplicate_write(self):
  self.rows.insert(2,copy.deepcopy(self.rows[1]))
  with self.assertRaises(ValueError):verify_reboot(self.rows)
 def test_false_success(self):
  self.rows[1]['ok']=False
  with self.assertRaises(ValueError):verify_reboot(self.rows)
if __name__=='__main__':unittest.main()
