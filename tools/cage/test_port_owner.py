from test_port_fixtures import proposal_inventory
import tempfile,unittest,uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from port_transaction import canonical,DOMAIN,digest
from port_plan import plan
from port_owner import OwnerRequests,Refused
class Duo:
 def __init__(self,allow=True):self.allow=allow;self.pushes=0;self.context=None
 def preauth(self,owner):return {'result':'auth'}
 def push(self,owner,pre,context):self.pushes+=1;self.context=context;return 'duo-test-transaction-1234'
 def wait(self,txid):return {'result':'allow' if self.allow else 'deny','status':'allow' if self.allow else 'deny'}
class OwnerTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw);self.now=1000000000000;self.clock=100.0
  self.store=OwnerRequests(str(Path(self.tmp.name)/'owner.db'),self.pub,self.key.sign,owner='test-owner',boot_id='ownerboot',max_lease_seconds=300,wall_ns=lambda:self.now,boottime=lambda:self.clock)
  self.tid=uuid.uuid4().hex
  self.body={'target':{'device':'kestrel-ios','host':'192.168.255.10','port':'Ethernet0/1','device_node_id':260,'transport_port':22},'plan':plan('interface Ethernet0/1\n shutdown\nend','Ethernet0/1','mode_access'),'verification':['show interfaces Ethernet0/1 switchport','show running-config interface Ethernet0/1'],'precondition_hashes':['a'*64],'native_proposals':proposal_inventory()}
  self.store.prepare(self.tid,self.body,lease_seconds=60,executor_boot_id='executorboot')
 def tearDown(self):self.store.close();self.tmp.cleanup()
 def authorized_ns(self):
  row=self.store.db.execute('select authorized_ns from owner_requests where id=?',(self.tid,)).fetchone();return row[0] or self.now
 def envelope(self):return {'schema':'kestrel-port-approval/1','approval_id':uuid.uuid4().hex,'transaction_id':self.tid,'plan_sha256':digest(self.body),'owner':'test-owner','issued_ns':self.now,'lease_seconds':60,'boot_id':'executorboot','issued_boottime':1000.0,'authorization':{'method':'duo','reference':'duo-test-transaction-1234','approved_ns':self.authorized_ns()}}
 def test_duo_bound_to_plan_and_signature(self):
  duo=Duo();self.store.authorize(self.tid,duo);e=self.envelope();sig=self.store.sign_envelope(self.tid,e)
  self.key.public_key().verify(sig,DOMAIN+canonical(e));self.assertEqual(duo.context['SHA256'],digest(self.body));self.assertEqual(duo.pushes,1)
 def test_no_sign_without_duo(self):
  with self.assertRaises(Refused):self.store.sign_envelope(self.tid,self.envelope())
 def test_denied_duo_cannot_sign(self):
  with self.assertRaises(Refused):self.store.authorize(self.tid,Duo(False))
  with self.assertRaises(Refused):self.store.sign_envelope(self.tid,self.envelope())
 def test_no_repeated_push(self):
  d=Duo();self.store.authorize(self.tid,d)
  with self.assertRaises(Refused):self.store.authorize(self.tid,d)
  self.assertEqual(d.pushes,1)
 def test_no_second_signature(self):
  self.store.authorize(self.tid,Duo());self.store.sign_envelope(self.tid,self.envelope())
  with self.assertRaises(Refused):self.store.sign_envelope(self.tid,self.envelope())
 def test_envelope_tampering_refused(self):
  self.store.authorize(self.tid,Duo())
  for key,value in [('plan_sha256','b'*64),('owner','attacker'),('lease_seconds',300),('boot_id','other'),('issued_ns',self.now-31000000000)]:
   with self.subTest(key=key),self.assertRaises(Refused):self.store.sign_envelope(self.tid,{**self.envelope(),key:value})
 def test_duo_reference_bound_into_signature(self):
  self.store.authorize(self.tid,Duo());a=self.envelope();a['authorization']={**a['authorization'],'reference':'different-duo-transaction'}
  with self.assertRaises(Refused):self.store.sign_envelope(self.tid,a)
 def test_signer_crash_cannot_retry(self):
  self.store.authorize(self.tid,Duo())
  def lost(data):raise TimeoutError('unknown signer result')
  self.store.sign=lost
  with self.assertRaises(TimeoutError):self.store.sign_envelope(self.tid,self.envelope())
  self.store.sign=self.key.sign
  with self.assertRaises(Refused):self.store.sign_envelope(self.tid,self.envelope())
 def test_no_bypass_on_duo_preauth_allow(self):
  d=Duo();d.preauth=lambda owner:{'result':'allow'}
  with self.assertRaises(Refused):self.store.authorize(self.tid,d)
  self.assertEqual(d.pushes,0)
 def test_delay_after_duo_does_not_extend_lease(self):
  self.store.authorize(self.tid,Duo());self.now+=10000000000;self.clock+=10
  with self.assertRaises(Refused):self.store.sign_envelope(self.tid,self.envelope())
  a={**self.envelope(),'lease_seconds':50};self.assertEqual(len(self.store.sign_envelope(self.tid,a)),64)
 def test_expired_owner_authorization_cannot_be_refreshed(self):
  self.store.authorize(self.tid,Duo());self.now+=61000000000;self.clock+=61
  with self.assertRaises(Refused):self.store.sign_envelope(self.tid,self.envelope())
 def test_lease_starts_after_duo_not_at_preparation(self):
  self.now+=120000000000;self.clock+=120;self.store.authorize(self.tid,Duo());sig=self.store.sign_envelope(self.tid,self.envelope());self.assertEqual(len(sig),64)

class NativeOwnerTests(unittest.TestCase):
 envelope=OwnerTests.envelope
 authorized_ns=OwnerTests.authorized_ns
 tearDown=OwnerTests.tearDown
 def setUp(self):
  OwnerTests.setUp(self);self.producer=Ed25519PrivateKey.generate();self.producer_pub=self.producer.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  self.store.producers={'kestrel-ios':{'public_key':self.producer_pub,'node_id':260,'chain_session':'test-port'}}
  self.store.authorize(self.tid,Duo());self.a=self.envelope();self.store.sign_envelope(self.tid,self.a)
 def intent(self,phase='forward',sequence=1):
  import struct,hashlib
  cmd=self.body['plan'][phase] if phase in ('forward','rollback') else 'show running-config interface Ethernet0/1'
  name={'rollback':'restore'}.get(phase,phase)
  refs=self.body['native_proposals']['verify'] if name=='verify' else [self.body['native_proposals'][name]]
  pid=refs[0]['proposal_id']
  challenge={'proposal_id':pid,'device':'kestrel-ios','command':cmd,'device_node_id':260,'tier':'YELLOW' if phase in ('forward','rollback') else 'YELLOW','ttl_seconds':300,'canonical':struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(pid),hashlib.sha256(cmd.encode()).digest(),260,self.now,300).hex()}
  event={'schema':'kestrel-port-event/1','type':'native_approval_intent','transaction_id':self.tid,'event_id':uuid.uuid4().hex,'request_id':uuid.uuid4().hex,'approval_id':self.a['approval_id'],'command':cmd,'canonical':challenge['canonical'],'proposal_id':pid,'time_ns':self.now}
  e={'artifact_hash':digest(event),'artifact_hash_alg':'sha256','artifact_id':event['event_id'],'artifact_schema_version':1,'artifact_type':'evidence_item','monotonic_ns':1,'previous_entry_hash':'0'*64,'sequence':sequence,'session_id':'test-port','signer_node_id':260,'signer_org_id':'local','timestamp_ns':self.now}
  raw=canonical(e);e.update(chain_entry_hash=hashlib.sha256(raw).hexdigest(),chain_sig_key_id=hashlib.sha256(self.producer_pub).hexdigest()[:32],chain_sig=self.producer.sign(b'VIRP-CHAIN-ENTRY-SIG-v1\0'+raw).hex())
  return event,e,challenge
 def test_native_exact_signature_once(self):
  event,e,q=self.intent();sig=self.store.sign_native(self.tid,event,e,q);self.key.public_key().verify(sig,bytes.fromhex(q['canonical']))
  with self.assertRaises(Refused):self.store.sign_native(self.tid,event,e,q)
 def test_native_new_forward_proposal_not_second_apply(self):
  self.store.sign_native(self.tid,*self.intent())
  with self.assertRaises(Refused):self.store.sign_native(self.tid,*self.intent(sequence=2))
 def test_native_wrong_producer_refused(self):
  event,e,q=self.intent();e['chain_sig']='00'*64
  with self.assertRaises(ValueError):self.store.sign_native(self.tid,event,e,q)
 def test_native_unsigned_event_change_refused(self):
  event,e,q=self.intent();event['approval_id']='0'*32
  with self.assertRaises(Refused):self.store.sign_native(self.tid,event,e,q)
 def test_native_restore_without_forward_refused(self):
  with self.assertRaises(Refused):self.store.sign_native(self.tid,*self.intent('rollback'))
 def test_native_expired_forward_refused_but_restore_allowed(self):
  self.store.sign_native(self.tid,*self.intent());self.now+=61000000000;self.clock+=61
  sig=self.store.sign_native(self.tid,*self.intent('rollback',2));self.assertEqual(len(sig),64)
 def test_native_expiry_blocks_first_forward(self):
  self.now+=610000000000;self.clock+=610
  with self.assertRaises(Refused):self.store.sign_native(self.tid,*self.intent())
 def test_native_late_proposal_refused_with_valid_producer_intent(self):
  event,e,q=self.intent();pid=uuid.uuid4().hex;raw=bytes.fromhex(q['canonical']);q['proposal_id']=pid;q['canonical']=(raw[:4]+bytes.fromhex(pid)+raw[20:]).hex()
  event.update(proposal_id=pid,canonical=q['canonical']);e['artifact_hash']=digest(event)
  fields={k:v for k,v in e.items() if k not in ('chain_entry_hash','chain_sig_key_id','chain_sig')};raw=canonical(fields)
  e['chain_entry_hash']=__import__('hashlib').sha256(raw).hexdigest();e['chain_sig']=self.producer.sign(b'VIRP-CHAIN-ENTRY-SIG-v1\0'+raw).hex()
  with self.assertRaisesRegex(Refused,'not_in_owner_approved_inventory'):self.store.sign_native(self.tid,event,e,q)
 def test_native_missing_profile_refused(self):
  self.store.producers={}
  with self.assertRaises(Refused):self.store.sign_native(self.tid,*self.intent())

if __name__=='__main__':unittest.main()
