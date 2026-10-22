import copy,tempfile,unittest,pathlib,time
from timed_standing import TimedStanding,Refused,digest
class Tests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.now=[100.0];self.a={'ports':['GigabitEthernet1/0/22','GigabitEthernet1/0/23'],'vlans':[50,80],'catalogue':'existing-only','authorization':'TEST FIXTURE ONLY; no owner signature'};self.p={'forward':['first','second'],'restore':['original-baseline']};self.l={'authority_sha256':digest(self.a),'issued_wall':100.,'expires_wall':102.,'issued_boot':100.,'expires_boot':102.,'boot_id':'test','plan_sha256':digest(self.p)};self.calls=[]
 def make(self):return TimedStanding(str(pathlib.Path(self.tmp.name)/'state.db'),self.a,self.l,wall=lambda:self.now[0],boot=lambda:self.now[0])
 def dispatch(self,c,phase):self.calls.append((c,phase));self.now[0]+=3;return True
 def test_mid_transaction_expiry_restores_original(self):
  x=self.make().run('a',self.p,dispatch=self.dispatch,verify_restore=lambda:True);self.assertEqual(self.calls,[('first','forward'),('original-baseline','restore')]);self.assertTrue(x['expired']);self.assertEqual(x['state'],'restored')
 def test_preexpired_no_dispatch(self):
  t=self.make();self.now[0]=103
  with self.assertRaises(Refused):t.run('a',self.p,dispatch=self.dispatch,verify_restore=lambda:True)
  self.assertEqual(self.calls,[])
 def test_tampered_authority_no_dispatch(self):
  t=self.make();self.a['vlans'].append(10)
  with self.assertRaises(Refused):t.run('a',self.p,dispatch=self.dispatch,verify_restore=lambda:True)
 def test_changed_restore_no_dispatch(self):
  t=self.make();p=copy.deepcopy(self.p);p['restore']=['different']
  with self.assertRaises(Refused):t.run('a',p,dispatch=self.dispatch,verify_restore=lambda:True)
 def test_unknown_blocks_repeat_and_new_id(self):
  t=self.make()
  with self.assertRaises(Refused):t.run('a',self.p,dispatch=lambda *a:None,verify_restore=lambda:True)
  for rid in ['a','b']:
   with self.assertRaises(Refused):t.run(rid,self.p,dispatch=self.dispatch,verify_restore=lambda:True)
  self.assertEqual(self.calls,[])
 def test_clock_rewind_no_dispatch(self):
  t=self.make();self.now[0]=99
  with self.assertRaises(Refused):t.run('a',self.p,dispatch=self.dispatch,verify_restore=lambda:True)
 def test_unknown_restore_latched(self):
  t=self.make()
  with self.assertRaises(Refused):t.run('a',self.p,dispatch=lambda c,phase:True if phase=='forward' else None,verify_restore=lambda:True)
  self.assertEqual(t.db.execute('select state from attempts').fetchone()[0],'recovery_required')
 def test_restart_preserves_attempt(self):
  t=self.make()
  with self.assertRaises(Refused):t.run('a',self.p,dispatch=lambda *a:None,verify_restore=lambda:True)
  t.db.close();t=self.make()
  with self.assertRaises(Refused):t.run('a',self.p,dispatch=self.dispatch,verify_restore=lambda:True)
if __name__=='__main__':unittest.main(verbosity=2)
