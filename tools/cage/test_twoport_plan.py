import unittest
from twoport_plan import plan
class PlanTests(unittest.TestCase):
 def test_reads_both_ports(self):
  for n in (22,23):
   c=f'show running-config interface GigabitEthernet1/0/{n}'
   self.assertEqual(plan(c),[c])
 def test_write_renders_fixed_context(self):
  self.assertEqual(plan('interface GigabitEthernet1/0/23 no shutdown'),['configure terminal','interface GigabitEthernet1/0/23','no shutdown','end'])
 def test_escape_refused(self):
  for c in ('reload','write memory','configure terminal','interface range Gi1/0/22-23','interface GigabitEthernet1/0/24 shutdown','interface Vlan10 shutdown','interface GigabitEthernet1/0/22 shutdown\nreload','interface GigabitEthernet1/0/22 description test;reload','interface GigabitEthernet1/0/22 ip address 1.2.3.4 255.255.255.0','show running-config','show interfaces GigabitEthernet1/0/22 | redirect flash:x'):
   with self.subTest(c=c),self.assertRaises(ValueError):plan(c)
 def test_features(self):
  for c in ('description KESTREL-TEST-22','switchport mode access','switchport mode trunk','switchport access vlan 10','switchport trunk allowed vlan 10,20','spanning-tree portfast','spanning-tree bpduguard enable','switchport port-security','switchport port-security maximum 2','switchport port-security violation restrict','switchport nonegotiate','speed auto','duplex auto','shutdown','no shutdown'):
   self.assertEqual(plan('interface GigabitEthernet1/0/22 '+c)[2],c)
 def test_bad_vlan_and_description(self):
  for c in ('switchport access vlan 0','switchport access vlan 4095','switchport trunk allowed vlan all','description x','description KESTREL-X interface Gi1/0/24'):
   with self.assertRaises(ValueError):plan('interface GigabitEthernet1/0/22 '+c)
if __name__=='__main__':unittest.main()
