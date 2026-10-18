import copy,json,sqlite3,tempfile,unittest,hashlib,struct,uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from port_plan import plan
from port_transaction import Transactions, Refused, canonical, DOMAIN
BASE='canary#show running-config interface Ethernet0/1\ninterface Ethernet0/1\n shutdown\nend'
class Clock:
 def __init__(self):self.wall=1000000000000;self.boot=100.0
 def tick(self,n):self.wall+=int(n*1e9);self.boot+=n
class TransactionTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.clock=Clock();self.key=Ed25519PrivateKey.generate()
  pub=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
  self.dbpath=str(Path(self.tmp.name)/'state.db');self.public=pub;self.store=self.open()
  self.body={'target':{'device':'kestrel-ios','host':'192.168.255.10','port':'Ethernet0/1'},'plan':plan(BASE,'Ethernet0/1','mode_access'),'verification':['show interfaces Ethernet0/1 switchport','show running-config interface Ethernet0/1'],'precondition_hashes':['a'*64]}
  self.tid=self.store.create(self.body)
 def open(self):return Transactions(self.dbpath,self.public,owner='test-approver',wall_ns=lambda:self.clock.wall,boottime=lambda:self.clock.boot,boot_id='boot1',max_lease_seconds=300)
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def approve(self,seconds=10):
  a=self.store.approval_request(self.tid,seconds);signature=self.key.sign(DOMAIN+canonical(a));self.store.approve(a,signature);return a,signature
 def flush(self):
  self.store.flush(lambda event:{'chain_entry_hash':'b'*64,'artifact_id':event['event_id']})
 def begin(self,verb):
  self.flush();request=self.store.begin(self.tid,verb);self.flush();self.native(request);self.store.require_dispatch(request);return request
 def challenge(self,r):
  cmd=self.body['plan']['forward' if r['verb']=='apply' else 'rollback'] if r['verb'] in ('apply','restore') else 'show running-config interface Ethernet0/1'
  pid=uuid.uuid4().hex
  return {'proposal_id':pid,'device':'kestrel-ios','command':cmd,'device_node_id':0xc0a8ff0a,'tier':'RED' if r['verb'] in ('apply','restore') else 'YELLOW','ttl_seconds':300,'canonical':struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(pid),hashlib.sha256(cmd.encode()).digest(),0xc0a8ff0a,self.clock.wall,300).hex()}
 def native(self,r):
  challenge=self.challenge(r);pid=self.store.reserve_native(r,challenge);self.flush();self.store.native_signable(r,pid);self.flush();return pid
 def test_missing_native_issuance_blocks_dispatch(self):
  self.approve();self.flush();r=self.store.begin(self.tid,'apply');self.flush()
  with self.assertRaisesRegex(Refused,'native_approval_issuance_required'):self.store.require_dispatch(r)
 def test_native_signature_issued_once(self):
  self.approve();self.flush();r=self.store.begin(self.tid,'apply');self.flush();pid=self.native(r)
  with self.assertRaises(Refused):self.store.native_signable(r,pid)
 def test_native_scope_does_not_follow_caller(self):
  self.approve();self.flush();r=self.store.begin(self.tid,'apply');self.flush();q=self.challenge(r);q['command']='interface Ethernet0/2 shutdown'
  with self.assertRaises(Refused):self.store.reserve_native(r,q)
 def test_expiry_between_native_reservation_and_signature(self):
  self.approve(1);self.flush();r=self.store.begin(self.tid,'apply');self.flush();pid=self.store.reserve_native(r,self.challenge(r));self.flush();self.clock.tick(2)
  with self.assertRaises(Refused):self.store.native_signable(r,pid)
 def test_native_signature_requires_chain_receipt(self):
  self.approve();self.flush();r=self.store.begin(self.tid,'apply');self.flush();pid=self.store.reserve_native(r,self.challenge(r))
  with self.assertRaises(Refused):self.store.native_signable(r,pid)

 def apply(self):
  r=self.begin('apply');self.store.finish(r,'executed',observation_hash='c'*64)
 def test_full_roundtrip_once(self):
  self.approve();self.apply();r=self.begin('verify');self.store.finish(r,'matches',observation_hash='d'*64)
  r=self.begin('restore');self.store.finish(r,'executed',observation_hash='e'*64)
  r=self.begin('verify_restored');self.store.finish(r,'matches',observation_hash='f'*64)
  self.assertEqual(self.store.status(self.tid)['state'],'restored')
  with self.assertRaises(Refused):self.begin('apply')
 def test_closed_transaction_does_not_expire_again(self):
  self.approve();self.apply();r=self.begin('restore');self.store.finish(r,'executed',observation_hash='e'*64)
  r=self.begin('verify_restored');self.store.finish(r,'matches',observation_hash='f'*64)
  before=self.store.events(self.tid);self.clock.tick(100)
  self.assertEqual(self.store.status(self.tid)['state'],'restored')
  self.assertEqual(self.store.events(self.tid),before)
 def test_expiry_after_apply_narrows_and_restores(self):
  self.approve(1);self.apply();self.clock.tick(2)
  with self.assertRaises(Refused):self.begin('unrelated_read')
  r=self.begin('restore');self.store.finish(r,'executed',observation_hash='e'*64)
  r=self.begin('verify_restored');self.store.finish(r,'matches',observation_hash='f'*64)
  events=[e['type'] for e in self.store.events(self.tid)]
  self.assertLess(events.index('apply_outcome'),events.index('lease_expired'))
  self.assertLess(events.index('lease_expired'),events.index('restore_intent'))
  self.assertEqual(self.store.status(self.tid)['close_reason'],'lease_expired')
 def test_expiry_before_apply_never_dispatches(self):
  self.approve(1);self.clock.tick(2)
  with self.assertRaises(Refused):self.begin('apply')
  self.assertEqual(self.store.status(self.tid)['state'],'expired-before-apply')
 def test_tampered_store_refuses_restore(self):
  self.approve();self.apply();self.clock.tick(20)
  db=sqlite3.connect(self.dbpath);b=copy.deepcopy(self.body);b['plan']['rollback']='interface Ethernet0/2 shutdown';db.execute('update transactions set body=? where id=?',(canonical(b).decode(),self.tid));db.commit();db.close()
  with self.assertRaises(Refused):self.begin('restore')
 def test_wrong_signature_or_owner_refused(self):
  a=self.store.approval_request(self.tid,10)
  with self.assertRaises(Refused):self.store.approve(a,b'0'*64)
  a['owner']='someone-else'
  with self.assertRaises(Refused):self.store.approve(a,self.key.sign(DOMAIN+canonical(a)))
 def test_consumed_approval_refused(self):
  a,s=self.approve()
  with self.assertRaises(Refused):self.store.approve(a,s)
 def test_crash_after_intent_does_not_retry(self):
  self.approve();self.begin('apply');self.store.close();self.store=self.open()
  with self.assertRaises(Refused):self.begin('apply')
  with self.assertRaises(Refused):self.begin('restore')
 def test_chain_failure_prevents_dispatch(self):
  self.approve();self.flush();r=self.store.begin(self.tid,'apply')
  with self.assertRaises(Refused):self.store.require_dispatch(r)
  with self.assertRaises(RuntimeError):self.store.flush(lambda e:(_ for _ in ()).throw(RuntimeError('offline')))
  with self.assertRaises(Refused):self.store.require_dispatch(r)
 def test_ambiguous_apply_only_reconciliation(self):
  self.approve();r=self.begin('apply');self.store.finish(r,'unknown',observation_hash='c'*64)
  with self.assertRaises(Refused):self.begin('restore')
  r=self.begin('reconcile');self.store.finish(r,'matches_forward',observation_hash='d'*64)
  self.begin('restore')
 def test_clock_rollback_cannot_extend_lease(self):
  self.approve(1);self.clock.boot+=2;self.clock.wall-=10000000000
  with self.assertRaises(Refused):self.begin('apply')
 def test_reboot_refuses(self):
  self.approve();self.store.boot_id='boot2'
  with self.assertRaises(Refused):self.begin('apply')
 def test_no_replay_of_same_request(self):
  self.approve();r=self.begin('apply');self.store.finish(r,'executed',observation_hash='c'*64)
  with self.assertRaises(Refused):self.store.require_dispatch(r)
  with self.assertRaises(Refused):self.store.finish(r,'executed',observation_hash='c'*64)
 def test_expiry_between_intent_and_dispatch(self):
  self.approve(1);self.flush();r=self.store.begin(self.tid,'apply');self.flush();self.clock.tick(2)
  with self.assertRaises(Refused):self.store.require_dispatch(r)
  self.assertEqual(self.store.status(self.tid)['state'],'expired-before-apply')
 def test_double_dispatch_rejected(self):
  self.approve();r=self.begin('apply')
  with self.assertRaises(Refused):self.store.require_dispatch(r)
 def test_database_deadline_tamper_refused(self):
  self.approve(1)
  self.store.db.execute('update transactions set expires_ns=expires_ns+100000000000,deadline=deadline+100 where id=?',(self.tid,))
  with self.assertRaises(Refused):self.begin('apply')
 def test_lease_outside_maximum_refused(self):
  for n in [0,301,True,1.5]:
   with self.assertRaises(Refused):self.store.approval_request(self.tid,n)
 def test_forged_render_rejected_even_with_rehashed_body(self):
  b=copy.deepcopy(self.body);b['plan']['forward']='interface Ethernet0/2 shutdown'
  from port_transaction import digest
  b['plan']['bundle_sha256']=digest({k:v for k,v in b['plan'].items() if k!='bundle_sha256'})
  with self.assertRaises(Refused):self.store.create(b)
 def test_unauthorized_verification_command_rejected(self):
  b=copy.deepcopy(self.body);b['verification'].append('show running-config')
  with self.assertRaises(Refused):self.store.create(b)
 def test_verification_failure_permits_exact_restore(self):
  self.approve();self.apply();r=self.begin('verify');self.store.finish(r,'mismatch',observation_hash='d'*64)
  r=self.begin('restore');self.assertEqual(r['verb'],'restore')
 def test_two_connections_cannot_begin_same_apply(self):
  self.approve();self.begin('apply');other=self.open()
  try:
   with self.assertRaises(Refused):other.begin(self.tid,'apply')
  finally:other.close()
if __name__=='__main__':unittest.main()
