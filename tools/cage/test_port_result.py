import unittest
from port_plan import plan
from port_result import compare, capture_after, compare_preflight
from test_port_evidence import fixture
class Comparisons(unittest.TestCase):
 def setUp(self):
  d=fixture();self.p=plan(d['config'],'Ethernet0/1','vlan_10',active_vlans={10})
  self.before={'config':d['config'],'switchport':d['switchport']}
  self.after={'config':d['config'].replace(' shutdown',' switchport access vlan 10\n shutdown'),'switchport':d['switchport'].replace('1 (default)','10 (lab)')}
 def test_exact_forward_and_restore(self):
  self.assertEqual(compare(self.p,self.after),'matches');self.assertEqual(compare(self.p,self.before,restore=True),'matches')
 def test_config_only_does_not_prove_operational_vlan(self):
  d={**self.after,'switchport':self.before['switchport']};self.assertEqual(compare(self.p,d),'mismatch')
 def test_unrelated_config_drift_refused(self):
  d={**self.after,'config':self.after['config'].replace(' shutdown',' description unexpected\n shutdown')};self.assertEqual(compare(self.p,d),'mismatch')
 def test_enabled_or_wrong_port_refused(self):
  for old,new in [('Operational Mode: down','Operational Mode: static access'),('Et0/1','Et0/2')]:
   d={**self.after,'switchport':self.after['switchport'].replace(old,new)};self.assertEqual(compare(self.p,d),'mismatch')
 def test_missing_extra_and_unparseable_reads_unknown(self):
  for d in [{'config':self.after['config']},{**self.after,'extra':'output'},{**self.after,'switchport':'% Invalid input'}]:self.assertEqual(compare(self.p,d),'unknown')
class PreflightComparison(unittest.TestCase):
 def setUp(self):
  self.outputs=fixture();self.body={'target':{'port':'Ethernet0/1'},'plan':plan(self.outputs['config'],'Ethernet0/1','vlan_10',active_vlans={10})}
 def test_complete_unchanged_preconditions(self):self.assertEqual(compare_preflight(self.body,self.outputs,protected_ports=set()),'matches')
 def test_config_drift_before_apply(self):
  self.outputs['config']=self.outputs['config'].replace(' shutdown',' description changed\n shutdown')
  self.assertEqual(compare_preflight(self.body,self.outputs,protected_ports=set()),'mismatch')
 def test_neighbor_or_missing_evidence_blocks(self):
  self.outputs['lldp']='Total entries displayed: 1'
  self.assertEqual(compare_preflight(self.body,self.outputs,protected_ports=set()),'unknown')
  del self.outputs['lldp'];self.assertEqual(compare_preflight(self.body,self.outputs,protected_ports=set()),'unknown')
class Ordering(unittest.TestCase):
 def setUp(self):
  from test_helper import Contract
  self.f=Contract();self.f.setUp();self.f.command='show interfaces Ethernet0/1 switchport';self.receipt={'session_id':'chain','sequence':5,'chain_entry_hash':'d'*64};self.calls=0
 def verify(self,*args):self.calls+=1;return self.receipt
 def capture(self,**extra):
  f=self.f;raw=f.frame(body=('canary#'+f.command+'\n'+fixture()['switchport']).encode())
  args=dict(raw=raw,public_key=f.pub,session_id=f.sid,node_id=256,device_id=55,command=f.command,after_sequence=0,now_ns=f.now,ledger=self,chain_session='chain',artifact_id='id',not_before_ns=f.now,min_chain_sequence=4)
  args.update(extra);return capture_after(**args)
 def test_post_apply_observation_accepted(self):self.assertIn('output',self.capture())
 def test_signed_read_predating_apply_refused(self):
  with self.assertRaises(ValueError):self.capture(not_before_ns=self.f.now+1)
 def test_prior_or_other_chain_entry_refused(self):
  for receipt in [{'session_id':'chain','sequence':4},{'session_id':'other','sequence':9}]:
   self.receipt=receipt
   with self.assertRaises(ValueError):self.capture()
if __name__=='__main__':unittest.main()
