import ast,copy,unittest,tempfile,json,hashlib,io,contextlib
from unittest.mock import patch
import port_cage_service as service

class CageServiceTests(unittest.TestCase):
 def profile(self):return {'schema':'kestrel-port-cage/1','machine_id':service.MACHINE,'model':service.MODEL,'api_config_sha256':service.CONFIG_SHA,'known_hosts_sha256':service.HOSTS_SHA,'module_sha256':{n:'a'*64 for n in service.MODULES}}
 def test_pinned_vm_and_existing_model(self):service.validate_profile(self.profile())
 def test_model_host_or_credential_path_override_refuses(self):
  for key,value in [('machine_id','production'),('model','other-model'),('api_config_sha256','0'*64),('known_hosts_sha256','0'*64),('private_key','/tmp/key')]:
   p=self.profile();p[key]=value
   with self.assertRaises(service.CageRefused):service.validate_profile(p)
 def test_module_omission_refuses(self):
  p=self.profile();del p['module_sha256']['port_model.py']
  with self.assertRaises(service.CageRefused):service.validate_profile(p)
 def test_wrong_machine_refuses_before_profile_or_keys(self):
  with patch.object(service.os,'geteuid',return_value=0),patch.object(service.Path,'read_text',return_value='other-host'),patch.object(service,'protected') as protect:
   with self.assertRaisesRegex(service.CageRefused,'cage_host_identity_mismatch'):service.main()
   protect.assert_not_called()
 def test_nonroot_refuses_before_machine_or_profile_read(self):
  with patch.object(service.os,'geteuid',return_value=1000),patch.object(service.Path,'read_text') as read:
   with self.assertRaises(service.CageRefused):service.main()
   read.assert_not_called()
 def test_manifest_covers_module_level_local_imports(self):
  root=service.Path(service.__file__).parent
  for filename in service.MODULES:
   for node in ast.parse((root/filename).read_text()).body:
    names=[node.module] if isinstance(node,ast.ImportFrom) else [a.name for a in node.names] if isinstance(node,ast.Import) else []
    for name in names:
     target=(name or '').split('.')[0]+'.py'
     if (root/target).exists():self.assertIn(target,service.MODULES,(filename,target))
 def assembled(self,*,unresolved=False):
  # Simulated host identity/custody, fake provider and fake SSH adapter. This
  # exercises assembly/key laziness; it is not VM227 or device qualification.
  import port_provider,port_transport
  from types import SimpleNamespace
  with tempfile.TemporaryDirectory() as directory:
   root=service.Path(directory);state=root/'state';state.mkdir()
   for name in ('journal','transport','transcripts'):(state/name).mkdir()
   cfg=root/'api.json';cfg.write_text(json.dumps({'model':service.SHARED_CONFIG_MODEL}))
   hosts=root/'known_hosts';hosts.write_text('synthetic public host pin')
   key=root/'api.key';key.write_text('unit-test-key')
   p=self.profile();p['api_config_sha256']=hashlib.sha256(cfg.read_bytes()).hexdigest();p['known_hosts_sha256']=hashlib.sha256(hosts.read_bytes()).hexdigest()
   modules=service.Path(service.__file__).parent
   p['module_sha256']={name:hashlib.sha256((modules/name).read_bytes()).hexdigest() for name in service.MODULES}
   profile=root/'profile.json';profile.write_text(json.dumps(p))
   if unresolved:(state/'journal'/('00000001-'+'a'*32+'.request.json')).write_text(json.dumps({'operation':'port_prepare_mode_access','request_id':'a'*32,'rationale':'prior synthetic unresolved request'}))
   calls=[];model_calls=[];original_read=service.Path.read_text
   def read(path,*args,**kwargs):
    if str(path)=='/etc/machine-id':return service.MACHINE
    if unresolved and path==key:raise AssertionError('API key must not be read for unresolved recovery')
    return original_read(path,*args,**kwargs)
   def model(inputs,allowed):
    operation='port_verify' if 'port_verify' in allowed else allowed[0];model_calls.append(operation)
    return {'output':[{'type':'function_call','name':'virp_port','call_id':str(len(model_calls)), 'arguments':json.dumps({'operation':operation,'rationale':'synthetic host assembly qualification'})}]}
   states={'port_prepare_mode_access':'prepared','port_authorize':'approved','port_preflight':'preflight_verified','port_apply':'applied','port_verify':'verified','port_restore':'restore_applied','port_verify_restored':'restored'}
   def transport(q):
    calls.append(q);state=states[q['operation']]
    return {'ok':True,'operation':q['operation'],'request_id':q['request_id'],'transaction_id':'b'*32,'state':state,'expired':False,'close_reason':'roundtrip_complete' if state=='restored' else None}
   with contextlib.ExitStack() as stack:
    for name,value in [('CONFIG',str(cfg)),('API_KEY',str(key)),('KNOWN_HOSTS',str(hosts)),('CONFIG_SHA',p['api_config_sha256']),('HOSTS_SHA',p['known_hosts_sha256']),('PROFILE',str(profile)),('ROOT',str(state))]:stack.enter_context(patch.object(service,name,value))
    stack.enter_context(patch.object(service.os,'geteuid',return_value=0));stack.enter_context(patch.object(service.Path,'read_text',new=read))
    stack.enter_context(patch.object(service,'protected',side_effect=lambda path,**kw:service.Path(path)))
    stack.enter_context(patch.object(service.sys,'argv',['runner','--operation','mode_access']))
    stack.enter_context(patch.object(service.sys,'path',list(service.sys.path)))
    stack.enter_context(patch.object(service.sys,'dont_write_bytecode',True))
    provider=stack.enter_context(patch.object(port_provider,'ResponsesProvider',return_value=model))
    stack.enter_context(patch.object(port_transport,'CanaryTransport',return_value=SimpleNamespace(call=transport)))
    output=io.StringIO()
    with contextlib.redirect_stdout(output):service.main()
    result=json.loads(output.getvalue())['result']
    if unresolved:
     provider.assert_not_called();self.assertFalse(result['ok']);self.assertEqual(calls,[])
    else:
     self.assertTrue(result['ok']);self.assertEqual(len(calls),7);provider.assert_called_once()
     self.assertEqual(provider.call_args.args,(service.MODEL,'unit-test-key'))
    for path in state.rglob('*.json'):self.assertNotIn('unit-test-key',original_read(path))
 def test_full_simulated_host_assembly(self):self.assembled()
 def test_unresolved_attempt_prevents_model_and_key_loading(self):self.assembled(unresolved=True)

if __name__=='__main__':unittest.main()
