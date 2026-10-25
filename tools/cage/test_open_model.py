import json,unittest
from open_model import run
class ModelTests(unittest.TestCase):
 def test_red_command_no_approval_hop(self):
  responses=iter([{'status':'completed','output':[{'type':'function_call','name':'virp_execute','call_id':'one','arguments':json.dumps({'command':'configure terminal','rationale':'Enter configuration mode on the isolated test device.'})}]},{'status':'completed','output':[]}]);calls=[]
  def transport(q):calls.append(q);return {'request_id':q['request_id'],'command':q['command'],'result':{'recovery_required':False}}
  r=run(lambda x:next(responses),transport,'test',lambda x:None)
  self.assertTrue(r['ok']);self.assertEqual(len(calls),1);self.assertEqual(calls[0]['command'],'configure terminal');self.assertNotIn('proposal_id',calls[0])
 def test_unknown_stops_no_retry(self):
  c={'status':'completed','output':[{'type':'function_call','name':'virp_execute','call_id':'one','arguments':json.dumps({'command':'show version','rationale':'Read the test device version for qualification.'})}]};calls=[]
  def transport(q):calls.append(q);return {'request_id':q['request_id'],'command':q['command'],'result':{'recovery_required':True}}
  r=run(lambda x:c,transport,'test',lambda x:None);self.assertFalse(r['ok']);self.assertEqual(len(calls),1)
if __name__=='__main__':unittest.main()
