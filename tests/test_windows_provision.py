import unittest,sys,pathlib,json
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools/cage'))
from windows_policy import validate,command_action,parse_native_output
from windows_model import run
class WindowsScope(unittest.TestCase):
 def request(self,**kw):
  q={'operation':'windows_execute','request_id':'a'*32,'target':'colo-windows2025','action':'status','rationale':'Inspect installation progress through the broker.'};q.update(kw);return q
 def test_accept_exact(self):self.assertEqual(validate(self.request())['action'],'status')
 def test_no_target_escape(self):
  for t in ['colo-vm107','colo-vm211','colo-pve1',233,None]:
   with self.assertRaises(ValueError):validate(self.request(target=t))
 def test_no_payload(self):
  with self.assertRaises(ValueError):validate(self.request(command='powershell whoami'))
 def test_no_shell_or_other_vm(self):
  for c in ['qm create 107','qm create 233; id','qm create 233 --hookscript x','qm guest exec 233','qm destroy 233','qm create 233\n','--worker']:
   with self.assertRaises(ValueError):command_action(c)
 def test_native_identity(self):
  with self.assertRaises(ValueError):parse_native_output('colo-pve1-vm231$ qm status 233\n{}','qm status 233')
 def test_duplicate_fields(self):
  from windows_policy import unique
  with self.assertRaises(ValueError):json.loads('{"action":"status","action":"provision"}',object_pairs_hook=unique)
 def test_no_false_model_completion(self):
  result=run(lambda i:{'status':'completed','output':[]},lambda q:None,'Install Windows',lambda e:None)
  self.assertFalse(result['ok'])
 def test_helper_refusal_stops(self):
  def provider(i):return {'status':'completed','output':[{'type':'function_call','name':'virp_windows','call_id':'1','arguments':json.dumps({'target':'colo-windows2025','action':'provision','rationale':'Create the requested Windows evaluation VM.'})}]}
  count=[]
  def transport(q):count.append(q);return {'ok':False}
  result=run(provider,transport,'Install Windows',lambda e:None);self.assertFalse(result['ok']);self.assertEqual(len(count),1)

class EndpointBoundaries(unittest.TestCase):
 def test_wrong_guest_identity(self):
  import windows_pve as e
  from unittest.mock import patch
  with patch.object(e,'state',return_value={'uuid':'expected'}),patch.object(e.P,'read_text',return_value='name: windows-server-2025\nsmbios1: uuid=other\nnet0: e1000=02:54:4C:49:02:33,bridge=vmbr0'):
   with self.assertRaisesRegex(ValueError,'guest_identity_changed'):e.pinned()
 def test_stop_blocks_dispatch(self):
  import windows_pve as e,tempfile
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d,patch.object(e,'ROOT',pathlib.Path(d)),patch.object(e.subprocess,'run') as proc:
   (pathlib.Path(d)/'STOP').write_text('stop')
   with self.assertRaisesRegex(ValueError,'scope_stopped'):e.command(['qm','create','233'])
   proc.assert_not_called()
 def test_worker_cannot_restart_consumed_reservation(self):
  import windows_pve as e,tempfile
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d,patch.object(e,'ROOT',pathlib.Path(d)),patch.object(e,'state',return_value={'phase':'installing'}),patch.object(e.subprocess,'run') as proc:
   with self.assertRaisesRegex(ValueError,'worker_already_dispatched'):e.worker()
   proc.assert_not_called()
 def test_state_durable_roundtrip(self):
  import windows_pve as e,tempfile
  from unittest.mock import patch
  with tempfile.TemporaryDirectory() as d,patch.object(e,'ROOT',pathlib.Path(d)):
   e.update(phase='reserved',uuid='test');self.assertEqual(e.state()['phase'],'reserved');self.assertEqual((pathlib.Path(d)/'state.json').stat().st_mode&0o777,0o600)

class MediaVerification(unittest.TestCase):
 def test_empty_optical_boot_entries_are_safe(self):
  from windows_policy import installation_media_detached
  c={'boot':'order=sata0;ide0;ide2;ide1',**{k:'none,media=cdrom' for k in ['ide0','ide1','ide2']}}
  self.assertTrue(installation_media_detached(c))
  for change in [{'boot':'order=ide0;sata0'},{'boot':'order=sata0;net0'},{'ide2':'local:iso/answer.iso,media=cdrom'},{'ide1':'iso-store:iso/virtio-win.iso,media=cdrom'}]:
   self.assertFalse(installation_media_detached({**c,**change}))
class ForcedEntry(unittest.TestCase):
 def test_health_is_fixed_unprivileged_read(self):
  import runpy,os
  from unittest.mock import patch
  f=pathlib.Path(__file__).resolve().parents[1]/'tools/cage/windows_ssh_entry.py'
  with patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':'uptime'}),patch('subprocess.call',return_value=0) as call:
   with self.assertRaises(SystemExit) as e:runpy.run_path(str(f))
   self.assertEqual(e.exception.code,0);self.assertEqual(call.call_args.args[0],['/usr/bin/uptime']);self.assertNotIn('shell',call.call_args.kwargs)
 def test_health_does_not_allow_payloads(self):
  import runpy,os
  from unittest.mock import patch
  f=pathlib.Path(__file__).resolve().parents[1]/'tools/cage/windows_ssh_entry.py'
  for cmd in ['uptime; id','uptime -p','uptime\n','sh','qm create 233 --hookscript evil']:
   with patch.dict(os.environ,{'SSH_ORIGINAL_COMMAND':cmd}),patch('subprocess.call') as call:
    with self.assertRaises(SystemExit) as e:runpy.run_path(str(f))
    self.assertEqual(e.exception.code,1);call.assert_not_called()
if __name__=='__main__':unittest.main()
