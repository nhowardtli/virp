import json,unittest,subprocess,tempfile,pathlib,os
import port_canary_router as router

class RouterTests(unittest.TestCase):
 def raw(self,operation):return json.dumps({'operation':operation,'request_id':'a'*32,'rationale':'fixed canary qualification request'}).encode()
 def test_open_mode_requires_explicit_router_opt_in(self):
  q=json.loads(self.raw('open_execute'));q['command']='configure terminal';raw=json.dumps(q).encode()
  with self.assertRaises(router.RouterRefused):router.select(raw)
  self.assertEqual(router.select(raw,allow_open=True),router.OPEN_SERVICE)
  q['device']='production'
  with self.assertRaises(router.RouterRefused):router.select(json.dumps(q).encode(),allow_open=True)
 def test_routes_only_named_port_operations(self):
  for op in router.PORT_OPERATIONS:self.assertEqual(router.select(self.raw(op)),router.PORT_SERVICE)
 def test_known_legacy_operations_preserved(self):
  for op in router.LEGACY_OPERATIONS:self.assertEqual(router.select(self.raw(op)),router.LEGACY_SERVICE)
 def test_unknown_or_path_input_refuses(self):
  for op in ('port_reconcile','port_replay','port_shell','reload','/tmp/service','../legacy','sw_apply_description','sw_apply_restore','sw_replay_description'):
   with self.assertRaises(router.RouterRefused):router.select(self.raw(op))
 def test_extra_fields_and_duplicate_keys_refuse(self):
  raw=self.raw('port_apply')
  for bad in (raw[:-1]+b',"command":"reload"}',raw[:-1]+b',"operation":"status"}',b'[]',b'null'):
   with self.assertRaises(router.RouterRefused):router.select(bad)
 def test_length_and_bad_encoding_refuse(self):
  for raw in (b'x'*4097,b'\xff',b'{'):
   with self.assertRaises(router.RouterRefused):router.select(raw)
 def test_port_operations_match_actual_dispatcher(self):
  from port_endpoint import OPERATIONS
  self.assertEqual(router.PORT_OPERATIONS,set(OPERATIONS))
 def test_exec_handoff_preserves_request_and_has_no_supervising_child(self):
  with tempfile.TemporaryDirectory() as directory:
   target=pathlib.Path(directory)/'receive.py'
   target.write_text('import json,os,sys;print(json.dumps({"pid":os.getpid(),"raw":sys.stdin.buffer.read().decode(),"caller":os.environ.get("SUDO_USER"),"leaked":os.environ.get("VIRP_TEST_SECRET")}))')
   code='import sys;sys.path.insert(0,sys.argv[1]);import port_canary_router as r;r.handoff(sys.argv[2],sys.argv[3].encode())'
   raw=self.raw('port_apply').decode()
   child=subprocess.Popen(['/usr/bin/python3','-I','-c',code,str(pathlib.Path(router.__file__).parent),str(target),raw],stdout=subprocess.PIPE,text=True,env={**os.environ,'VIRP_TEST_SECRET':'must-not-propagate'})
   output,_=child.communicate(timeout=5);self.assertEqual(child.returncode,0)
   result=json.loads(output);self.assertEqual(result['pid'],child.pid)
   self.assertEqual(result['raw'],raw+'\n');self.assertEqual(result['caller'],'virp-cage-test');self.assertIsNone(result['leaked'])

if __name__=='__main__':unittest.main()
