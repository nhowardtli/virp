import copy
import ast
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,PrivateFormat,NoEncryption
import port_canary_service as host

class CanaryHostTests(unittest.TestCase):
 def test_manifest_covers_transitive_local_imports(self):
  root=host.Path(host.__file__).parent
  for name in host.MODULES:
   tree=ast.parse((root/name).read_text())
   for node in ast.walk(tree):
    names=[node.module] if isinstance(node,ast.ImportFrom) else [a.name for a in node.names] if isinstance(node,ast.Import) else []
    for imported in names:
     filename=(imported or '').split('.')[0]+'.py'
     if (root/filename).exists():self.assertIn(filename,host.MODULES,(name,filename))
 def profile(self):
  return {'schema':'kestrel-port-canary/1','lease_seconds':60,'chain_session':'kestrel-cml-port-test',
   'protected_ports':[],'module_sha256':{n:'a'*64 for n in host.MODULES},
   'runtime':{'machine_id':host.MACHINE,'sudo_user':'virp-cage-test','requester':'virp-kreq','requester_uid':980,
    'target':copy.deepcopy(host.TARGET),'public_key_hex':host.PRODUCER,'service':'virp-canary',
    'binary':host.BINARY,'config':host.CONFIG,'public_key':host.PUBLIC,'daemon_uid':995,
    'argv':list(host.ARGV),'files':{},'credential_gid':1234}}
 def test_fixed_canary_profile(self):host.validate_profile(self.profile())
 def test_production_or_changed_target_refuses(self):
  for field,value in [('machine_id','production'),('sudo_user','nhoward'),('requester_uid',0),('daemon_uid',0),('public_key_hex','0'*64)]:
   p=self.profile();p['runtime'][field]=value
   with self.assertRaises(host.HostRefused):host.validate_profile(p)
  p=self.profile();p['runtime']['target']['device']='SW-3850'
  with self.assertRaises(host.HostRefused):host.validate_profile(p)
 def test_runtime_socket_chain_epoch_cannot_change(self):
  for token in (host.SOCKET,host.CHAIN,'cml-v3-20261016'):
   p=self.profile();p['runtime']['argv'][p['runtime']['argv'].index(token)]='other'
   with self.assertRaises(host.HostRefused):host.validate_profile(p)
 def test_duplicate_runtime_flag_refuses(self):
  p=self.profile();p['runtime']['argv']+=['-s',host.SOCKET]
  with self.assertRaises(host.HostRefused):host.validate_profile(p)
 def test_missing_module_or_added_input_refuses(self):
  p=self.profile();p['module_sha256'].pop('port_flow.py')
  with self.assertRaises(host.HostRefused):host.validate_profile(p)
  p=self.profile();p['private_key']='/tmp/key'
  with self.assertRaises(host.HostRefused):host.validate_profile(p)
 def test_invalid_lease_or_chain_refuses(self):
  for field,value in [('lease_seconds',True),('lease_seconds',36001),('chain_session','approval:other'),('protected_ports',['bad'])]:
   p=self.profile();p[field]=value
   with self.assertRaises(host.HostRefused):host.validate_profile(p)
 def test_raw_key_checks_derived_public_and_suffix(self):
  key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  seed=key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
  self.assertEqual(host.decode_test_key(seed+pub,pub).public_key().public_bytes(Encoding.Raw,PublicFormat.Raw),pub)
  for raw,pin in [(seed,pub),(seed+b'\x00'*32,pub),(seed+pub,b'\x00'*32)]:
   with self.assertRaises(host.HostRefused):host.decode_test_key(raw,pin)
 def test_production_owner_not_accepted_as_canary_key(self):
  key=Ed25519PrivateKey.generate();pub=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  seed=key.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
  with self.assertRaises(host.HostRefused):host.decode_test_key(seed+pub)
 def test_wrong_machine_refuses_before_profile_or_key_read(self):
  with patch.object(host.sys,'argv',['service']),patch.object(host.os,'geteuid',return_value=0),patch.dict(host.os.environ,{'SUDO_USER':'virp-cage-test'}),patch.object(host.Path,'read_text',return_value='not-vm105'),patch.object(host,'protect') as protect:
   with self.assertRaisesRegex(host.HostRefused,'canary_host_identity_mismatch'):host.main()
   protect.assert_not_called()
 def test_caller_cannot_select_profile_or_key_path(self):
  with patch.object(host.sys,'argv',['service','--profile','/tmp/other']),patch.object(host,'protect') as protect:
   with self.assertRaisesRegex(host.HostRefused,'canary_arguments_denied'):host.main()
   protect.assert_not_called()

if __name__=='__main__':unittest.main()
