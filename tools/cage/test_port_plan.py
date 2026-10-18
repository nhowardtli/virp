import unittest
from port_plan import plan, config_lines, verify
BASE='x#show running-config interface Ethernet0/1\nBuilding configuration...\nCurrent configuration : 39 bytes\n!\ninterface Ethernet0/1\n shutdown\nend'
class PortPlanTests(unittest.TestCase):
 def test_routine_yellow_security_red(self):
  for op in ('mode_access','vlan_10','portfast'):
   self.assertEqual(plan(BASE,'Ethernet0/1',op,active_vlans={10})['tier'],'YELLOW')
  self.assertEqual(plan(BASE.replace(' shutdown',' switchport mode access\n shutdown'),'Ethernet0/1','security_enable')['tier'],'RED')
 def test_absent_mode_restores_absence(self):
  p=plan(BASE,'Ethernet0/1','mode_access');self.assertEqual(p['rollback'],'interface Ethernet0/1 no switchport mode');self.assertIn(' switchport mode access',p['expected'])
 def test_explicit_vlan_restored(self):
  p=plan(BASE.replace(' shutdown',' switchport access vlan 20\n shutdown'),'Ethernet0/1','vlan_10',active_vlans={10,20});self.assertEqual(p['rollback'],'interface Ethernet0/1 switchport access vlan 20')
 def test_unrelated_diff_rejected(self):
  p=plan(BASE,'Ethernet0/1','portfast');self.assertFalse(verify(p,BASE.replace(' shutdown',' spanning-tree portfast\n description unexpected\n shutdown')))
 def test_exact_verification(self):
  p=plan(BASE,'Ethernet0/1','portfast');self.assertTrue(verify(p,BASE.replace(' shutdown',' spanning-tree portfast\n shutdown')))
 def test_invalid_capture(self):
  for b in [BASE.replace('\nend',''),BASE.replace('Ethernet0/1\n','Ethernet0/2\n'),BASE.replace(' shutdown',' no shutdown'),BASE.replace(' shutdown',' shutdown\n shutdown')]:
   with self.assertRaises(ValueError):plan(b,'Ethernet0/1','mode_access')
 def test_target_and_operation_fixed(self):
  for port,op in [('Vlan10','mode_access'),('Ethernet0/2','mode_access'),('Ethernet0/1','shutdown'),('Ethernet0/1','mode_trunk')]:
   with self.assertRaises(ValueError):plan(BASE,port,op)
 def test_security_requires_static_access(self):
  with self.assertRaises(ValueError):plan(BASE,'Ethernet0/1','security_enable')
 def test_each_supported_profile_roundtrip(self):
  b=BASE.replace(' shutdown',' switchport mode access\n shutdown')
  for op in ['vlan_10','portfast','security_enable','security_maximum_2','security_violation_restrict']:
   p=plan(b,'Ethernet0/1',op,active_vlans={10});self.assertEqual(p['before'],config_lines(b,'Ethernet0/1'));self.assertNotEqual(p['expected'],p['before'])
 def test_missing_vlan_rejected_before_render(self):
  with self.assertRaisesRegex(ValueError,'vlan_not_active'):plan(BASE,'Ethernet0/1','vlan_10',active_vlans={1})
 def test_tampered_plan_refused(self):
  p=plan(BASE,'Ethernet0/1','portfast');p['expected']=p['before']
  self.assertFalse(verify(p,BASE))
 def test_other_interface_in_capture_rejected(self):
  with self.assertRaises(ValueError):config_lines(BASE.replace('interface Ethernet0/1','interface Ethernet0/2\ninterface Ethernet0/1'),'Ethernet0/1')
if __name__=='__main__':unittest.main()
