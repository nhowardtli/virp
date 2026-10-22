import copy,json,pathlib,unittest,sys
import reconcile_switch as r
class Tests(unittest.TestCase):
 @classmethod
 def setUpClass(cls):
  cls.source=json.loads(pathlib.Path(sys.argv[-2]).read_text());cls.corr=json.loads(pathlib.Path(sys.argv[-1]).read_text());cls.pub=bytes.fromhex(cls.source['producer_public_key']);cls.row=next(x for x in cls.source['records'] if r.adjudicate(x,cls.pub,cls.corr)['status']=='EFFECT_CORROBORATED_EXIT_UNVERIFIED')
 def test_all251_no_fabricated_exit(self):
  result=r.run(self.source,self.corr);self.assertEqual(result['original_artifacts'],251);self.assertNotIn('EXECUTED_CONFIRMED',result['counts']);self.assertTrue(all(x['exit_code_trusted'] is False for x in result['records']))
 def test_changed_native_exit_flag_fails_signature(self):
  row=copy.deepcopy(self.row);b=json.loads(row['artifact_content']);b['exit_code_trusted']=True;row['artifact_content']=json.dumps(b);self.assertEqual(r.adjudicate(row,self.pub,self.corr)['reason'],'native_gate_artifact_not_authenticated')
 def test_wrong_principal_not_corroborated(self):
  corr=copy.deepcopy(self.corr)
  for x in corr['tacacs_pairs']:x[1]='other'
  self.assertEqual(r.adjudicate(self.row,self.pub,corr)['status'],'UNRESOLVED')
 def test_reordered_archive_rejected(self):
  corr=copy.deepcopy(self.corr);corr['switch_archive_pairs'].reverse();self.assertEqual(r.adjudicate(self.row,self.pub,corr)['status'],'UNRESOLVED')
 def test_wrong_time_rejected(self):
  corr=copy.deepcopy(self.corr)
  for x in corr['tacacs_pairs']:x[0]='2026-10-22 00:00:00 +0000'
  self.assertEqual(r.adjudicate(self.row,self.pub,corr)['status'],'UNRESOLVED')
 def test_wrong_key_rejected(self):self.assertEqual(r.adjudicate(self.row,b'\0'*32,self.corr)['status'],'UNRESOLVED')
 def test_missing_archive_rejected(self):
  corr=copy.deepcopy(self.corr);corr['switch_archive_pairs']=[];self.assertEqual(r.adjudicate(self.row,self.pub,corr)['status'],'UNRESOLVED')
if __name__=='__main__':
 suite=unittest.defaultTestLoader.loadTestsFromTestCase(Tests);result=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(not result.wasSuccessful())
