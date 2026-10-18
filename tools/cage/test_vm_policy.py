import unittest,time,copy
from vm_policy import *
class Policy(unittest.TestCase):
 def setUp(self):
  self.q=dict(operation='vm_execute',request_id='a'*32,target=TARGET,action='status',rationale='Read the isolated guest state before proceeding.')
  self.g=dict(schema='kestrel-vm-grant/1',target=TARGET,identity={'vmid':231},expected_boot_id='boot',expires=200,authorization_sha256='b'*64)
 def test_valid(self):self.assertEqual(validate(self.q),self.q);authorize(self.g,{'vmid':231},'boot',consumed=False,stopped=False,now=100)
 def test_targets(self):
  for target in ['colo-vm211','231',231,None,'colo-vm231; reboot']:
   with self.assertRaises(ValueError):validate(dict(self.q,target=target))
 def test_actions(self):
  for action in ['reset','shutdown','destroy','reboot; id','status\nreboot']:
   with self.assertRaises(ValueError):validate(dict(self.q,action=action))
 def test_extra(self):
  with self.assertRaises(ValueError):validate(dict(self.q,command='id'))
 def test_duplicate(self):
  with self.assertRaises(ValueError):unique([('action','status'),('action','reboot')])
 def test_commands(self):
  for command in ['qm reboot 211','qm reboot 231 --forceStop 1','sudo qm reboot 231','qm reboot 231; id','qm reboot 231\n','/usr/sbin/qm reboot 231','reboot','qm destroy 231']:
   with self.assertRaises(ValueError):command_action(command)
 def test_replay_stop_expiry_identity_boot(self):
  cases=[dict(consumed=True,stopped=False,now=100),dict(consumed=False,stopped=True,now=100),dict(consumed=False,stopped=False,now=200)]
  for kw in cases:
   with self.assertRaises(ValueError):authorize(self.g,{'vmid':231},'boot',**kw)
  with self.assertRaises(ValueError):authorize(self.g,{'vmid':211},'boot',consumed=False,stopped=False,now=100)
  with self.assertRaises(ValueError):authorize(self.g,{'vmid':231},'newboot',consumed=False,stopped=False,now=100)

class NativeOutput(unittest.TestCase):
 def test_exact_envelope(self):
  self.assertTrue(parse_native_output('colo-pve1-vm231$ qm status 231\n{"target":"colo-vm231","ok":true}\n','qm status 231')['ok'])
 def test_wrong_command_or_trailing_noise(self):
  for body in ['colo-pve1-vm231$ qm reboot 231\n{"target":"colo-vm231"}', 'colo-pve1-vm231$ qm status 231\n{"target":"colo-vm231"}\nwarning', 'colo-pve1-vm231$ qm status 231\n{"target":"colo-vm211"}']:
   with self.assertRaises(ValueError):parse_native_output(body,'qm status 231')

if __name__=='__main__':unittest.main()
