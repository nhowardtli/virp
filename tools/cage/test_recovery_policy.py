import copy,unittest
from recovery_policy import enable_root_attestation
class PolicyTests(unittest.TestCase):
 def baseline(self):return {'socket_allowed_uids':[980],'socket_uid_action_allow':{'980':['execute','chain_append']},'socket_uid_chain_append_types':{'980':['observation']},'socket_uid_tier_ceilings':{'980':'green'},'devices':[{'hostname':'unchanged'}]}
 def test_exact_transition_preserves_requester_and_other_fields(self):
  c=self.baseline();before=copy.deepcopy(c);n=enable_root_attestation(c);self.assertEqual(c,before);self.assertEqual(n['socket_allowed_uids'],[980,0]);self.assertEqual(n['socket_uid_action_allow']['0'],['chain_append']);self.assertEqual(n['socket_uid_chain_append_types']['0'],['evidence_item']);self.assertEqual(n['socket_uid_tier_ceilings']['0'],'green')
  for k in ['socket_uid_action_allow','socket_uid_chain_append_types','socket_uid_tier_ceilings']:del n[k]['0']
  n['socket_allowed_uids'].remove(0);self.assertEqual(n,before)
 def test_drift_and_repeat_refused(self):
  for key,value in [('socket_allowed_uids',[980,0]),('socket_uid_action_allow',{'980':['execute'],'0':[]}),('socket_uid_chain_append_types',{'980':['observation'],'0':[]}),('socket_uid_tier_ceilings',{'980':'red'}),('socket_uid_chain_append_types',{'980':['observation','evidence_item']})]:
   c=self.baseline();c[key]=value
   with self.subTest(key=key),self.assertRaises(ValueError):enable_root_attestation(c)
  with self.assertRaises(ValueError):enable_root_attestation(enable_root_attestation(self.baseline()))
if __name__=='__main__':unittest.main()
