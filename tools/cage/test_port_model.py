import json,tempfile,unittest
from pathlib import Path
from port_model import run
from port_runner import PortRunner

class ModelTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.runner=PortRunner(Path(self.tmp.name),protect=lambda p,**kw:Path(p));self.calls=[];self.events=[]
  self.steps=['port_prepare_mode_access','port_authorize','port_preflight','port_apply','port_verify','port_restore','port_verify_restored']
 def tearDown(self):self.tmp.cleanup()
 def response(self,op,index):return {'output':[{'type':'function_call','name':'virp_port','call_id':'call'+str(index),'arguments':json.dumps({'operation':op,'rationale':'owner-scoped isolated port qualification'})}]}
 def provider(self,steps):
  stream=iter([self.response(op,i) for i,op in enumerate(steps)]+[{'output':[{'type':'message','content':[{'type':'output_text','text':'All done!'}]}]}])
  return lambda inputs,allowed:next(stream)
 def transport(self,q):
  self.calls.append(q['operation']);state=dict(zip(self.steps,['prepared','approved','preflight_verified','applied','verified','restore_applied','restored']))[q['operation']]
  return {'ok':True,**{k:q[k] for k in ('operation','request_id')},'transaction_id':'b'*32,'state':state,'expired':False,'close_reason':'roundtrip_complete' if state=='restored' else None}
 def execute(self,provider,transport=None):return run(provider,self.runner,transport or self.transport,operation='mode_access',prompt='Qualify this owner-selected canary operation.',record=self.events.append)
 def test_full_roundtrip_requires_seven_ordered_calls(self):
  result=self.execute(self.provider(self.steps));self.assertTrue(result['ok']);self.assertEqual(self.calls,self.steps)
  self.assertFalse(result['evidence_verified_independently'])
 def test_model_early_finish_after_apply_restores_under_existing_transaction(self):
  result=self.execute(self.provider(self.steps[:4]))
  self.assertFalse(result['ok']);self.assertEqual(result['recovery']['state'],'restored')
  self.assertEqual(self.calls,self.steps[:4]+['port_restore','port_verify_restored'])
 def test_model_cannot_choose_another_operation_or_free_cli(self):
  for op in ('port_prepare_vlan_10','reload'):
   result=self.execute(self.provider([op]));self.assertFalse(result['ok'])
  self.assertEqual(self.calls,[])
 def test_parallel_tool_calls_are_rejected_before_any_dispatch(self):
  response=self.response(self.steps[0],0);response['output']+=self.response(self.steps[1],1)['output']
  self.assertFalse(self.execute(lambda inputs,allowed:response)['ok']);self.assertEqual(self.calls,[])
 def test_transport_ambiguity_never_triggers_restore_or_retry(self):
  def transport(q):
   if q['operation']=='port_apply':self.calls.append('port_apply');raise TimeoutError()
   return self.transport(q)
  result=self.execute(self.provider(self.steps),transport)
  self.assertFalse(result['ok']);self.assertEqual(result['recovery']['state'],'reconciliation_required')
  self.assertEqual(self.calls,self.steps[:4])
 def test_unknown_never_triggers_restore(self):
  def transport(q):
   result=self.transport(q)
   if q['operation']=='port_apply':result['state']='unknown'
   return result
  result=self.execute(self.provider(self.steps),transport)
  self.assertFalse(result['ok']);self.assertEqual(result['recovery']['state'],'reconciliation_required');self.assertEqual(self.calls,self.steps[:4])
 def test_provider_failure_after_apply_uses_only_approved_restore(self):
  provider=self.provider(self.steps[:4]);counter=0
  def fail(inputs,allowed):
   nonlocal counter
   counter+=1
   if counter==5:raise RuntimeError('private provider error must not be echoed')
   return provider(inputs,allowed)
  result=self.execute(fail);self.assertFalse(result['ok']);self.assertEqual(result['recovery']['state'],'restored')
  self.assertNotIn('private provider',json.dumps(result))
 def test_skipped_forward_verification_is_not_qualification_success(self):
  result=self.execute(self.provider(self.steps[:4]+self.steps[5:]))
  self.assertFalse(result['ok']);self.assertEqual(result['result']['state'],'restored')
  self.assertEqual(result['reason'],'forward_verification_not_passed')
 def test_transcript_failure_after_apply_does_not_prevent_authorized_restore(self):
  def record(event):
   if event['type']=='helper_result' and event['result']['state']=='applied':raise OSError('record unavailable')
   self.events.append(event)
  result=run(self.provider(self.steps),self.runner,self.transport,operation='mode_access',prompt='Qualify the owner-selected canary.',record=record)
  self.assertFalse(result['ok']);self.assertFalse(result['transcript_complete'])
  self.assertEqual(result['recovery']['state'],'restored');self.assertEqual(self.calls,self.steps[:4]+self.steps[5:])

if __name__=='__main__':unittest.main()
