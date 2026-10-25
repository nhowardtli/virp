import json,tempfile,unittest,uuid
from pathlib import Path
from types import SimpleNamespace
from port_endpoint import dispatch,validate_request,OPERATIONS
from port_scope import ScopeGuard
from port_transaction import Refused

class EndpointTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);(self.root/'records').mkdir();(self.root/'v3-recovery').mkdir()
  (self.root/'policy.json').write_text(json.dumps({'expires':200,'expires_boot':200,'boot_id':'boot','authorization_sha256':'a'*64}))
  self.scope=ScopeGuard(self.root,check_runtime=lambda:None,wall=lambda:100,boottime=lambda:100,boot_id=lambda:'boot',protect=lambda p,**kw:Path(p))
  self.calls=[];self.tid='b'*32
  self.services=SimpleNamespace(prepare=lambda op:self.calls.append(('prepare',op)) or self.tid,current=lambda:self.tid,status=lambda tid:{'id':tid,'state':'prepared'},authorize=lambda tid,seconds:self.calls.append(('authorize',tid,seconds)) or {'id':tid,'state':'approved'},step=lambda tid,verb:self.calls.append(('step',tid,verb)) or {'id':tid,'state':'applied'})
 def tearDown(self):self.tmp.cleanup()
 def request(self,op):return {'operation':op,'request_id':uuid.uuid4().hex,'rationale':'owner-scoped bounded port test'}
 def run_request(self,q):
  with self.scope.locked():return dispatch(q,self.services,self.scope,lease_seconds=60)
 def test_fixed_prepare_and_root_selected_lease(self):
  q=self.request('port_prepare_mode_access');r=self.run_request(q)
  self.assertEqual(r['transaction_id'],self.tid);self.assertEqual(self.calls,[('prepare','mode_access')])
  self.run_request(self.request('port_authorize'));self.assertEqual(self.calls[-1],('authorize',self.tid,60))
 def test_model_cannot_supply_cli_target_approval_or_lease(self):
  for key,value in [('command','reload'),('target','SW-3850'),('transaction_id','c'*32),('approved',True),('lease_seconds',36000)]:
   q={**self.request('port_apply'),key:value}
   with self.assertRaises(Refused):self.run_request(q)
  self.assertEqual(self.calls,[]);self.assertEqual(list((self.root/'records').iterdir()),[])
 def test_unknown_operation_never_reaches_backend(self):
  for op in ['reload','port_replay','port_apply;reload','port_prepare_trunk']:
   with self.assertRaises(Refused):self.run_request(self.request(op))
  self.assertEqual(self.calls,[])
 def test_request_id_cannot_be_reused(self):
  q=self.request('port_apply');self.run_request(q)
  with self.assertRaisesRegex(Refused,'request_already_recorded'):self.run_request(q)
  self.assertEqual(len(self.calls),1)
 def test_stop_and_expired_scope_prevent_dispatch(self):
  (self.root/'STOP').write_text('preserve')
  with self.assertRaisesRegex(Refused,'scope_stopped'):self.run_request(self.request('port_apply'))
  self.assertEqual(self.calls,[])
 def test_scope_lock_is_required(self):
  with self.assertRaisesRegex(Refused,'scope_lock_required'):dispatch(self.request('port_apply'),self.services,self.scope,lease_seconds=60)
 def test_status_does_not_consume_attempt_budget(self):
  r=self.run_request(self.request('port_status'));self.assertEqual(r['state'],'prepared')
  self.assertEqual(list((self.root/'records').iterdir()),[])
 def test_sqlite_expired_flag_is_a_json_boolean(self):
  self.services.status=lambda tid:{'id':tid,'state':'prepared','expired':0,'close_reason':None}
  self.assertIs(self.run_request(self.request('port_status'))['expired'],False)
 def test_catalogue_contains_no_free_cli_or_qualification_bypass(self):
  self.assertNotIn('port_reconcile',OPERATIONS);self.assertNotIn('port_replay',OPERATIONS)
  self.assertEqual(set(OPERATIONS),{'port_prepare_mode_access','port_prepare_vlan_10','port_prepare_portfast','port_prepare_security_enable','port_prepare_security_maximum_2','port_prepare_security_violation_restrict','port_authorize','port_preflight','port_apply','port_verify','port_restore','port_verify_restored','port_status'})
if __name__=='__main__':unittest.main()
