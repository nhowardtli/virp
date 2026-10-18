import hashlib,json,tempfile,unittest,os
from unittest.mock import patch
from pathlib import Path
from port_runtime import RuntimePins,probe_service
from port_transaction import Refused

class RuntimeTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
  self.target={'device':'kestrel-ios','host':'192.168.255.10','port':'Ethernet0/1','device_node_id':260,'transport_port':22}
  self.cfg={'gate_default_mode':'enforce','evidence_required':True,'socket_uid_tier_ceilings':{'980':'green'},'devices':[{'hostname':'kestrel-ios','host':'192.168.255.10','node_id':'00000104','port':22}]}
  self.files={'binary':b'binary','config':json.dumps(self.cfg).encode(),'public_key':b'p'*32,'module':b'module'}
  self.pins={}
  for name,raw in self.files.items():
   p=self.root/name;p.write_bytes(raw);p.chmod(0o640 if name=='config' else 0o644);self.pins[str(p)]=hashlib.sha256(raw).hexdigest()
  self.profile={'machine_id':'host','sudo_user':'cage-user','requester':'virp-kreq','requester_uid':980,'service':'virp-canary','daemon_uid':995,'credential_gid':os.getgid(),'binary':str(self.root/'binary'),'config':str(self.root/'config'),'public_key':str(self.root/'public_key'),'public_key_hex':(b'p'*32).hex(),'files':self.pins,'target':self.target}
  self.profile['argv']=[self.profile['binary'],'-d',self.profile['config']]
  self.process={'groups':[os.getgid()],'effective_uid':995,'active':True,'executable':self.profile['binary'],'binary_sha256':self.pins[self.profile['binary']],'argv':[self.profile['binary'],'-d',self.profile['config']]}
  self.guard=RuntimePins(self.profile,protect=lambda p,**kw:Path(p),identity=lambda:(0,'cage-user','host',980),process_probe=lambda s:self.process,group_members=lambda gid:{995})
 def tearDown(self):self.tmp.cleanup()
 def test_process_probe_reads_real_proc_fields(self):
  with patch('port_runtime.subprocess.check_output',return_value='MainPID='+str(os.getpid())+'\nActiveState=active\n'):
   found=probe_service('virp-canary')
  self.assertEqual(found['effective_uid'],os.geteuid());self.assertEqual(found['executable'],os.readlink('/proc/self/exe'))
  self.assertTrue(found['argv']);self.assertEqual(len(found['binary_sha256']),64)
 def test_exact_pins_pass(self):self.guard()
 def test_file_change_refuses(self):
  for name in self.files:
   p=self.root/name;p.write_bytes(b'changed')
   with self.assertRaisesRegex(Refused,'runtime_file_changed'):self.guard()
   p.write_bytes(self.files[name])
 def test_shared_socket_group_cannot_read_credentials(self):
  self.guard.group_members=lambda gid:{995,980}
  with self.assertRaisesRegex(Refused,'credential_group_not_daemon_only'):self.guard()
 def test_daemon_must_actually_have_private_read_group(self):
  self.process['groups']=[]
  with self.assertRaisesRegex(Refused,'runtime_process_pin_mismatch'):self.guard()
 def test_root_config_must_have_expected_private_group(self):
  self.guard.profile['credential_gid']=os.getgid()+10000
  with self.assertRaisesRegex(Refused,'runtime_config_permissions'):self.guard()
 def test_device_credentials_cannot_be_world_readable(self):
  (self.root/'config').chmod(0o644)
  with self.assertRaisesRegex(Refused,'runtime_config_permissions'):self.guard()
 def test_identity_mismatch_refuses(self):
  for identity in [(1,'cage-user','host',980),(0,'other','host',980),(0,'cage-user','other',980),(0,'cage-user','host',981)]:
   self.guard.identity=lambda:identity
   with self.assertRaisesRegex(Refused,'runtime_identity_mismatch'):self.guard()
 def test_running_binary_and_config_must_match(self):
  for change in ({'effective_uid':0},{'active':False},{'executable':'/other'},{'binary_sha256':'0'*64},{'argv':[self.profile['binary'],'-d','/other']}):
   saved=dict(self.process);self.process.update(change)
   with self.assertRaises(Refused):self.guard()
   self.process=saved
 def test_profile_cannot_mutate_after_constructor(self):
  self.profile['files'][self.profile['binary']]='0'*64
  self.guard()
 def test_policy_semantics_checked_even_if_hash_provisioned(self):
  for change in ({'gate_default_mode':'observe'},{'evidence_required':False},{'socket_uid_tier_ceilings':{'980':'red'}}):
   config={**self.cfg,**change};raw=json.dumps(config).encode();(self.root/'config').write_bytes(raw)
   self.guard.profile['files'][str(self.root/'config')]=hashlib.sha256(raw).hexdigest()
   with self.assertRaisesRegex(Refused,'runtime_gate_policy_changed'):self.guard()
 def test_target_port_and_node_checked_even_if_hash_provisioned(self):
  for key,value in [('host','192.0.2.1'),('node_id','00000105'),('port',2022)]:
   config=json.loads(json.dumps(self.cfg));config['devices'][0][key]=value
   raw=json.dumps(config).encode();(self.root/'config').write_bytes(raw)
   self.guard.profile['files'][str(self.root/'config')]=hashlib.sha256(raw).hexdigest()
   with self.assertRaisesRegex(Refused,'runtime_target_changed'):self.guard()
if __name__=='__main__':unittest.main()
