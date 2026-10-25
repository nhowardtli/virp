import json,os,subprocess,tempfile,time,unittest
from pathlib import Path
from unittest.mock import patch
from port_transport import CanaryTransport,TransportRefused,argv

class TransportTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.clients=[]
  self.q={'operation':'port_apply','request_id':'a'*32,'rationale':'isolated canary transport qualification'}
 def tearDown(self):
  for c in self.clients:
   for proc in c.processes.values():proc.wait(timeout=5)
  self.tmp.cleanup()
 def client(self,seconds=.5):
  c=CanaryTransport(self.root,wait_seconds=seconds,protect=lambda p,**kw:Path(p),identity=lambda:0);self.clients.append(c);return c
 def command(self,source):return ['/usr/bin/python3','-I','-c',source]
 def test_fixed_canary_ssh_cannot_select_target_or_command(self):
  a=argv();self.assertEqual(a[-2:],['virp-cage-test@10.0.50.105','fixed-read'])
  self.assertIn('1122',a);self.assertIn('IdentityAgent=none',a);self.assertIn('ProxyCommand=none',a);self.assertIn('ControlPath=none',a)
 def test_completed_response_preserves_exact_attempt(self):
  code='import sys,json; q=json.load(sys.stdin); print(json.dumps({"ok":True,"request_id":q["request_id"]}))'
  with patch('port_transport.argv',return_value=self.command(code)):
   c=self.client();self.assertEqual(c.call(self.q),{'ok':True,'request_id':'a'*32})
  self.assertEqual(c.inspect('a'*32)['state'],'exited')
  self.assertEqual(c.inspect('a'*32)['returncode'],0)
  with self.assertRaisesRegex(TransportRefused,'attempt_already_exists'):c.call(self.q)
 def test_wait_timeout_does_not_kill_or_restart_process(self):
  code='import time;time.sleep(.4);print("{}")'
  with patch('port_transport.argv',return_value=self.command(code)):
   c=self.client(.03)
   with self.assertRaisesRegex(TransportRefused,'transport_still_running'):c.call(self.q)
  self.assertIsNone(c.processes['a'*32].poll());self.assertEqual(c.inspect('a'*32)['state'],'running')
  resumed=self.client();self.assertEqual(resumed.inspect('a'*32)['state'],'running')
  with self.assertRaisesRegex(TransportRefused,'attempt_already_exists'):resumed.call(self.q)
  c.processes['a'*32].wait(timeout=2)
  self.assertEqual(c.inspect('a'*32)['state'],'exited')
 def test_invalid_reply_remains_private_and_unresolved(self):
  with patch('port_transport.argv',return_value=self.command('import sys;sys.stdout.buffer.write(b"\\xff")')):
   c=self.client()
   with self.assertRaisesRegex(TransportRefused,'invalid_transport_reply'):c.call(self.q)
  self.assertEqual((self.root/('a'*32)/'stdout').read_bytes(),b'\xff')
 def test_duplicate_json_reply_keys_refuse(self):
  with patch('port_transport.argv',return_value=self.command('print(\'{"ok":false,"ok":true}\')')):
   with self.assertRaises(TransportRefused):self.client().call(self.q)
 def test_child_does_not_inherit_model_api_secret(self):
  with patch.dict(os.environ,{'VIRP_TEST_SECRET':'never-forward'}),patch('port_transport.argv',return_value=self.command('import os,json;print(json.dumps({"secret":os.environ.get("VIRP_TEST_SECRET")}))')):
   self.assertEqual(self.client().call(self.q),{'secret':None})
 def test_failed_launch_keeps_intent_and_refuses_retry(self):
  with patch('port_transport.argv',return_value=['/nonexistent/virp-test-only']):
   c=self.client()
   with self.assertRaisesRegex(TransportRefused,'transport_exit_unresolved'):c.call(self.q)
  self.assertTrue((self.root/('a'*32)/'request.json').exists())
  with self.assertRaisesRegex(TransportRefused,'attempt_already_exists'):c.call(self.q)
 def test_output_flood_is_capped_and_never_accepted(self):
  code='import os;os.write(1,b"x"*65536);os.write(1,b"y"*65536)'
  with patch('port_transport.argv',return_value=self.command(code)):
   c=self.client()
   with self.assertRaisesRegex(TransportRefused,'transport_exit_unresolved'):c.call(self.q)
  self.assertLessEqual((self.root/('a'*32)/'stdout').stat().st_size,65536)
  with self.assertRaisesRegex(TransportRefused,'attempt_already_exists'):c.call(self.q)
 def test_late_response_cannot_trigger_runner_retry(self):
  from port_runner import PortRunner,RunnerRefused
  journal=self.root/'runner';journal.mkdir(mode=0o700)
  runner=PortRunner(journal,protect=lambda p,**kw:Path(p))
  code='import json,sys,time;q=json.load(sys.stdin);time.sleep(.3);print(json.dumps(dict(operation=q["operation"],request_id=q["request_id"],ok=True,transaction_id="b"*32,state="prepared",expired=False,close_reason=None)))'
  with patch('port_transport.argv',return_value=self.command(code)):
   c=self.client(.03)
   with self.assertRaisesRegex(RunnerRefused,'transport_outcome_unresolved'):runner.request('port_prepare_mode_access','local delayed transport test only',c.call)
  rid=next(iter(c.processes));self.assertEqual(c.inspect(rid)['state'],'running')
  c.processes[rid].wait(timeout=2)
  with self.assertRaisesRegex(RunnerRefused,'prior_request_unresolved'):runner.request('port_prepare_mode_access','local delayed transport test only',c.call)
  self.assertEqual(len(c.processes),1)
 def test_reused_pid_or_reboot_is_unresolved_without_relaunch(self):
  with patch('port_transport.argv',return_value=self.command('import time;time.sleep(.4)')):
   c=self.client(.03)
   with self.assertRaises(TransportRefused):c.call(self.q)
  resumed=self.client()
  with patch('port_transport.process_identity',return_value={'start_ticks':-1,'state':'S'}):
   self.assertEqual(resumed.inspect('a'*32)['state'],'pid_identity_changed')
  with patch('port_transport.Path.read_text',return_value='different-boot'):
   self.assertEqual(resumed.inspect('a'*32)['state'],'host_rebooted')
  self.assertEqual(resumed.processes,{})

if __name__=='__main__':unittest.main()
