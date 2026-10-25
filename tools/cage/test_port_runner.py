import json,tempfile,unittest
from pathlib import Path
from port_runner import PortRunner,RunnerRefused

class RunnerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.calls=[]
  self.runner=PortRunner(self.root,protect=lambda p,**kw:Path(p))
 def tearDown(self):self.tmp.cleanup()
 def transport(self,q):
  self.calls.append(q)
  state={'port_prepare_mode_access':'prepared','port_authorize':'approved','port_preflight':'preflight_verified','port_apply':'applied','port_verify':'verified','port_restore':'restore_applied','port_verify_restored':'restored'}[q['operation']]
  return {'ok':True,'operation':q['operation'],'request_id':q['request_id'],'transaction_id':'b'*32,'state':state,'expired':False,'close_reason':'roundtrip_complete' if state=='restored' else None}
 def ask(self,operation,transport=None):return self.runner.request(operation,'isolated canary port transaction test',transport or self.transport)
 def prefix(self):
  for operation in ('port_prepare_mode_access','port_authorize','port_preflight','port_apply'):self.ask(operation)
 def test_seven_step_roundtrip_and_completion(self):
  self.prefix()
  for operation in ('port_verify','port_restore','port_verify_restored'):self.ask(operation)
  self.assertEqual(self.runner.completion()['state'],'restored');self.assertEqual(len(self.calls),7)
 def test_cannot_report_completion_after_apply(self):
  self.prefix()
  with self.assertRaisesRegex(RunnerRefused,'transaction_not_closed'):self.runner.completion()
 def test_out_of_order_and_duplicate_apply_never_reach_transport(self):
  with self.assertRaises(RunnerRefused):self.ask('port_apply')
  self.prefix();count=len(self.calls)
  with self.assertRaises(RunnerRefused):self.ask('port_apply')
  self.assertEqual(len(self.calls),count)
 def test_timeout_persists_across_runner_restart_and_does_not_retry(self):
  def lost(q):self.calls.append(q);raise TimeoutError('untrusted transport detail')
  with self.assertRaisesRegex(RunnerRefused,'transport_outcome_unresolved'):self.ask('port_prepare_mode_access',lost)
  self.runner=PortRunner(self.root,protect=lambda p,**kw:Path(p))
  with self.assertRaisesRegex(RunnerRefused,'prior_request_unresolved'):self.ask('port_prepare_mode_access')
  self.assertEqual(len(self.calls),1)
 def test_reply_binding_failure_blocks_followup(self):
  def wrong(q):return {**self.transport(q),'request_id':'c'*32}
  with self.assertRaises(RunnerRefused):self.ask('port_prepare_mode_access',wrong)
  replies=list(self.root.glob('*.reply.json'));self.assertEqual(len(replies),1)
  self.assertEqual(json.loads(replies[0].read_text())['request_id'],'c'*32)
  with self.assertRaisesRegex(RunnerRefused,'prior_request_unresolved'):self.ask('port_prepare_mode_access')
 def test_transaction_cannot_change_mid_run(self):
  self.ask('port_prepare_mode_access')
  def wrong(q):return {**self.transport(q),'transaction_id':'c'*32}
  with self.assertRaises(RunnerRefused):self.ask('port_authorize',wrong)
 def test_unknown_halts_without_retry_or_restore(self):
  for op in ('port_prepare_mode_access','port_authorize','port_preflight'):self.ask(op)
  def unknown(q):return {**self.transport(q),'state':'unknown'}
  self.ask('port_apply',unknown);count=len(self.calls)
  for op in ('port_apply','port_restore'):
   with self.assertRaises(RunnerRefused):self.ask(op)
  self.assertEqual(len(self.calls),count)
 def test_verification_mismatch_allows_only_restore(self):
  self.prefix()
  self.ask('port_verify',lambda q:{**self.transport(q),'state':'verify_failed'})
  with self.assertRaises(RunnerRefused):self.ask('port_verify')
  self.ask('port_restore');self.ask('port_verify_restored');self.runner.completion()
 def test_journal_is_written_before_transport(self):
  def inspect(q):
   self.assertEqual(len(list(self.root.glob('*.request.json'))),1)
   self.assertEqual(len(list(self.root.glob('*.result.json'))),0)
   return self.transport(q)
  self.ask('port_prepare_mode_access',inspect)
 def test_refusal_does_not_become_success(self):
  with self.assertRaises(RunnerRefused):self.ask('port_prepare_mode_access',lambda q:{'ok':False,'error':'work_lease_inactive'})
  with self.assertRaisesRegex(RunnerRefused,'prior_request_unresolved'):self.runner.completion()
 def test_restart_after_apply_preserves_restore_path(self):
  self.prefix();self.runner=PortRunner(self.root,protect=lambda p,**kw:Path(p))
  self.ask('port_restore');self.ask('port_verify_restored')
  self.assertEqual(self.runner.completion()['state'],'restored')
 def test_orphan_result_refuses_before_transport(self):
  (self.root/('00000001-'+'d'*32+'.result.json')).write_text('{}')
  with self.assertRaisesRegex(RunnerRefused,'orphan_runner_result'):self.ask('port_prepare_mode_access')
  self.assertEqual(self.calls,[])

if __name__=='__main__':unittest.main()
