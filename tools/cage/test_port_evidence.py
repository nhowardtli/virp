import unittest
from port_evidence import preconditions
PORT='Ethernet0/1'
def fixture():
 return {
 'config':'interface Ethernet0/1\n switchport mode access\n shutdown\nend',
 'switchport':'Name: Et0/1\nSwitchport: Enabled\nAdministrative Mode: static access\nOperational Mode: down\nAccess Mode VLAN: 1 (default)',
 'mac':'Mac Address Table\n-------------------------------------------\nVlan    Mac Address       Type        Ports\n----    -----------       --------    -----',
 'cdp':'Total cdp entries displayed : 0',
 'lldp':'Total entries displayed: 0',
 'channel':'Number of channel-groups in use: 0\nNumber of aggregators: 0\nGroup Port-channel Protocol Ports\n------+-------------+-----------+-----------------------------------------------',
 'vlans':'VLAN Name Status Ports\n---- -------------------------------- --------- -------------------------------\n1 default active Et0/1\n10 lab active\n1002 fddi-default act/unsup',
 }
class Preconditions(unittest.TestCase):
 def check(self,d=None,op='vlan_10'):return preconditions(d or fixture(),PORT,op,protected_ports=set())
 def test_complete_baseline(self):self.assertEqual(self.check()['expected'],[' shutdown',' switchport access vlan 10',' switchport mode access'])
 def test_missing_and_extra_evidence_refused(self):
  for key in fixture():
   d=fixture();del d[key]
   with self.assertRaises(ValueError):self.check(d)
  d=fixture();d['extra']='anything'
  with self.assertRaises(ValueError):self.check(d)
 def test_lldp_disabled_is_not_no_neighbor(self):
  d=fixture();d['lldp']='% LLDP is not enabled'
  with self.assertRaises(ValueError):self.check(d)
 def test_neighbor_and_mac_refused(self):
  for key,value in [('lldp','Total entries displayed: 1'),('cdp','Total cdp entries displayed : 1'),('mac',fixture()['mac']+'\n10 0011.2233.4455 DYNAMIC Et0/1')]:
   d=fixture();d[key]=value
   with self.assertRaises(ValueError):self.check(d)
 def test_channel_unknown_or_nonzero_refused(self):
  for value in ['','Number of channel-groups in use: 1\nNumber of aggregators: 1','% Invalid input detected']:
   d=fixture();d['channel']=value
   with self.assertRaises(ValueError):self.check(d)
 def test_missing_inactive_duplicate_vlan_refused(self):
  for value in ['10 lab active','10 lab suspended','10 lab active\n10 other active']:
   d=fixture();d['vlans']=value
   with self.assertRaises(ValueError):self.check(d)
 def test_truncated_empty_mac_refused(self):
  for value in ['','Mac Address Table','Mac Address Table\nVlan Mac Address Type Ports']:
   d=fixture();d['mac']=value
   with self.assertRaises(ValueError):self.check(d)
 def test_up_or_wrong_port_refused(self):
  for old,new in [('Operational Mode: down','Operational Mode: static access'),('Et0/1','Et0/2')]:
   d=fixture();d['switchport']=d['switchport'].replace(old,new)
   with self.assertRaises(ValueError):self.check(d)
 def test_protected_port_refused(self):
  with self.assertRaises(ValueError):preconditions(fixture(),PORT,'vlan_10',protected_ports={PORT})
 def test_dynamic_mode_only_allows_mode_access(self):
  d=fixture();d['config']=d['config'].replace(' switchport mode access\n','');d['switchport']=d['switchport'].replace('static access','dynamic auto')
  with self.assertRaises(ValueError):self.check(d)
  self.assertEqual(self.check(d,'mode_access')['operation'],'mode_access')
class VerifiedCapture(unittest.TestCase):
 def setUp(self):
  from test_helper import Contract
  self.frames=Contract();self.frames.setUp();self.frames.command='show interfaces Ethernet0/1 switchport'
  self.calls=[]
 def verify(self,raw,sid,aid):
  self.calls.append((raw,sid,aid));return {'chain_entry_hash':'c'*64}
 def capture(self,raw=None,**overrides):
  from port_evidence import verified_capture
  f=self.frames
  args=dict(public_key=f.pub,session_id=f.sid,node_id=256,device_id=55,command=f.command,after_sequence=0,now_ns=f.now,ledger=self,chain_session='chain',artifact_id='artifact')
  args.update(overrides)
  return verified_capture(raw or f.frame(body=('canary#'+f.command+'\n'+fixture()['switchport']).encode()),**args)
 def test_public_signature_and_membership_required(self):
  result=self.capture();self.assertEqual(result['output'],fixture()['switchport']);self.assertEqual(len(self.calls),1)
 def test_wrong_pin_and_session_fail_before_ledger(self):
  for args in [dict(public_key=b'x'*32),dict(session_id=b'y'*16),dict(now_ns=self.frames.now+121000000000)]:
   with self.assertRaises(ValueError):self.capture(**args)
  self.assertEqual(self.calls,[])
 def test_rejection_frame_not_evidence(self):
  with self.assertRaises(ValueError):self.capture(self.frames.frame(typ=15,tier=3,body=b'refused'))
  self.assertEqual(self.calls,[])
 def test_chain_failure_refuses_signed_output(self):
  class Broken:
   def verify(self,*args):raise ValueError('broken chain')
  with self.assertRaises(ValueError):self.capture(ledger=Broken())
 def test_command_echo_and_cli_errors_refused(self):
  for output in ['canary#show version\nwrong','canary#'+self.frames.command+'\n% Invalid input','canary#'+self.frames.command+'\n--More--']:
   with self.assertRaises(ValueError):self.capture(self.frames.frame(body=output.encode()))
if __name__=='__main__':unittest.main()
