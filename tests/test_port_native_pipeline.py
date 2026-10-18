#!/usr/bin/env python3
"""Actual local C socket/chain pipeline with simulated device I/O, never Cisco.

Run via make test-port-native-pipeline CISCO=1. No network target is contacted.
Fresh test keys and all mutable state live in one private temporary directory.
"""
import base64,hashlib,json,os,pathlib,sqlite3,subprocess,sys,tempfile,time,unittest,uuid,socket
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/'tools/cage'))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
from helper import Socket
from recovery import Ledger
from port_ledger import EventLedger
from port_native import NativePort
from port_prepare import PortPreparation
from port_authorize import PortAuthorization
from port_flow import PortFlow
from port_scope import ScopeGuard
from port_transaction import Transactions
from port_canary_owner import CanaryOwnerRequests
from port_canary_service import CanaryClient
from port_owner_service import dispatch
from port_replay import verify_pair
from port_services import PortServices
from port_runner import PortRunner
from port_endpoint import dispatch as cage_dispatch

class NativePipeline(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='virp-port-native-');self.root=pathlib.Path(self.tmp.name);self.addCleanup(self.cleanup)
  self.key=Ed25519PrivateKey.generate();self.pub=self.key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
  registry=[{'key_id':hashlib.sha256(self.pub).hexdigest()[:32],'algorithm':'ed25519','public_key':base64.b64encode(self.key.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)).decode(),'operator':'canary-test-approver','enabled':True}]
  (self.root/'approvers.json').write_text(json.dumps(registry));(self.root/'approvers.json').chmod(0o600)
  self.log=open(self.root/'daemon.log','wb');binary=pathlib.Path(os.environ.get('VIRP_PORT_FIXTURE',str(pathlib.Path(__file__).resolve().parents[1]/'build/port_native_fixture')))
  self.assertTrue(binary.is_file(),'native fixture binary must be built; this is not a skipped test')
  self.proc=subprocess.Popen([str(binary),str(self.root)],stdout=self.log,stderr=self.log)
  deadline=time.monotonic()+10
  while not (self.root/'onode.sock').exists():
   if self.proc.poll() is not None:raise AssertionError((self.root/'daemon.log').read_text())
   if time.monotonic()>=deadline:raise AssertionError('fixture startup timeout')
   time.sleep(.02)
  self.producer=(self.root/'sign.pub').read_bytes();self.transport=Socket(str(self.root/'onode.sock'))
  self.chain='kestrel-local-port-test';self.approval_session='approval:kestrel-ios@port-test'
  self.ledger=Ledger(self.root/'chain.db',self.transport,self.producer)
  self.events=EventLedger(self.root/'chain.db',self.transport,self.producer,self.chain)
  (self.root/'records').mkdir();(self.root/'v3-recovery').mkdir()
  self.boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text()
  (self.root/'policy.json').write_text(json.dumps({'expires':time.time()+120,'expires_boot':time.clock_gettime(time.CLOCK_BOOTTIME)+120,'boot_id':self.boot,'authorization_sha256':'a'*64}))
  self.scope=ScopeGuard(self.root,check_runtime=lambda:self.assertIsNone(self.proc.poll()),protect=lambda p,**kw:pathlib.Path(p))
  self.target={'device':'kestrel-ios','host':'192.168.255.10','port':'Ethernet0/1','device_node_id':260,'transport_port':22}
  self.tx=Transactions(str(self.root/'transactions.db'),self.pub,owner='canary-test-approver',boot_id=self.boot.strip(),max_lease_seconds=60,required_approval_method='test')
  self.owner=CanaryOwnerRequests(str(self.root/'owner.db'),self.pub,self.key.sign,boot_id=self.boot.strip(),max_lease_seconds=60,producers={'kestrel-ios':{'public_key':self.producer,'node_id':260,'chain_session':self.chain}})
 def cleanup(self):
  if hasattr(self,'owner'):self.owner.close()
  if hasattr(self,'tx'):self.tx.close()
  if hasattr(self,'transport'):
   try:self.transport.management({'action':'shutdown'})
   except ValueError:pass  # Native shutdown closes the socket without a reply.
  if hasattr(self,'proc'):
   # Wake the native idle select after its shutdown flag was set. This sends
   # no request/device command and is fixture cleanup, not restart qualification.
   try:
    with socket.socket(socket.AF_UNIX) as wake:wake.connect(str(self.root/'onode.sock'))
   except OSError:pass
   self.proc.wait(timeout=35)

  if hasattr(self,'log'):self.log.close()
  if os.environ.get('VIRP_KEEP_PORT_FIXTURE')=='1':
   # Only a test process invokes this; directory contains generated test keys.
   print('LOCAL SYNTHETIC FIXTURE:',self.root);self.tmp._finalizer.detach()
  else:self.tmp.cleanup()
 def native(self,body):
  return NativePort(body=body,transport=self.transport,ledger=self.ledger,records=self.root/'records',recovery_dir=self.root/'v3-recovery',public_key=self.producer,node_id=260,chain_session=self.chain,approval_session=self.approval_session,approver_public_key=self.pub,operator='canary-test-approver',guard=self.scope.check,stop=self.scope.stop)
 def call(self,q):
  return CanaryClient(self.owner).call(q)
 def prepare_flow(self,seconds=60):
  read=self.native({'target':self.target});cmd='show running-config interface Ethernet0/1'
  reference=read.propose(cmd)['reference'];challenge=read.challenge(reference['proposal_id'],cmd)
  read.submit(challenge,self.key.sign(bytes.fromhex(challenge['canonical'])))
  tid=PortPreparation(self.tx,self.events,read,self.native,self.scope,protected_ports=set()).prepare('mode_access',config_proposal_id=reference['proposal_id'],verification_budget=4)
  PortAuthorization(self.tx,self.events,self,self.scope,tid).authorize(seconds)
  _,body=self.tx._get(tid)
  return tid,PortFlow(self.tx,self.events,self.native(body),self,self.scope,tid,protected_ports=set())
 def verify_all_chains(self):
  with sqlite3.connect(self.root/'chain.db') as db:
   sessions=list(db.execute('select session_id,max(sequence) from chain_entries group by session_id'))
  for sid,high in sessions:
   result=self.transport.management({'action':'chain_verify','session_id':sid,'from_sequence':0,'to_sequence':high})
   self.assertTrue(result['valid']);self.assertEqual(result['entries_checked'],high+1);self.assertEqual(result['executions_open'],0)
 def test_native_lease_expiry_and_tamper_cases(self):
  with self.scope.locked():
   tid,flow=self.prepare_flow(3);flow.step('preflight');flow.step('apply')
   time.sleep(3.1)
   with self.assertRaisesRegex(ValueError,'verb_not_allowed'):flow.step('unrelated_green_read')
   flow.step('restore');self.assertEqual(flow.step('verify_restored')['state'],'restored')
   kinds=[e['type'] for e in self.tx.events(tid)]
   required=['approval','apply_outcome','lease_expired','restore_outcome','verify_restored_outcome','close']
   self.assertEqual([k for k in kinds if k in required],required)
   self.assertEqual(self.tx.events(tid)[-1]['reason'],'lease_expired')
   self.assertEqual(json.loads((self.root/'device-state.json').read_text()),{'access':False,'writes':2})
   # Expiry before apply closes without a device write.
   early,flow=self.prepare_flow(1);time.sleep(1.1)
   with self.assertRaises(ValueError):flow.step('preflight')
   self.assertEqual(flow.close_owner()['state'],'expired-before-apply')
   self.assertEqual(json.loads((self.root/'device-state.json').read_text())['writes'],2)
   # Tamper root-held proposal bytes only in this isolated test fixture.
   tampered,flow=self.prepare_flow(60);flow.step('preflight');flow.step('apply')
   row,body=self.tx._get(tampered);original_store_bytes=row['body'];body['plan']['before'].append(' description tampered')
   self.tx.db.execute('update transactions set body=? where id=?',(json.dumps(body),tampered))
   before=json.loads((self.root/'device-state.json').read_text())
   with self.assertRaisesRegex(ValueError,'approved_bundle_tampered'):flow.step('restore')
   self.assertEqual(json.loads((self.root/'device-state.json').read_text()),before)
   # Undo only our deliberate test injection, preserving the approved original
   # bytes and every consumed approval/state field; this is not a recovery API.
   self.tx.db.execute('update transactions set body=? where id=?',(original_store_bytes,tampered))
   flow.step('restore');self.assertEqual(flow.step('verify_restored')['state'],'restored')
   self.assertEqual(json.loads((self.root/'device-state.json').read_text()),{'access':False,'writes':4})
   self.verify_all_chains()
   print('LOCAL SYNTHETIC: expiry narrowed authority, original approval restored, pre-apply expiry wrote nothing, tampered rollback refused; native chains clean')
 def test_native_unknown_response_stops_without_retry(self):
  with self.scope.locked():
   tid,flow=self.prepare_flow();flow.step('preflight')
   (self.root/'drop-next-response').write_text('local test fault injection')
   self.assertEqual(flow.step('apply')['state'],'unknown')
   self.assertTrue((self.root/'STOP').exists());self.assertTrue((self.root/'v3-recovery/pending.json').exists())
   self.assertEqual(json.loads((self.root/'device-state.json').read_text()),{'access':True,'writes':1})
   with self.assertRaisesRegex(ValueError,'scope_stopped'):flow.step('apply')
   with self.assertRaisesRegex(ValueError,'scope_stopped'):flow.step('restore')
   self.assertEqual(json.loads((self.root/'device-state.json').read_text())['writes'],1)
   _,body=self.tx._get(tid);pid=body['native_proposals']['forward']['proposal_id']
   with sqlite3.connect(self.root/'chain.db') as db:
    raw=db.execute('select artifact_content from artifacts where artifact_id=?',('outcome:'+pid,)).fetchone()[0]
   self.assertIs(json.loads(raw)['success'],False);self.verify_all_chains()
   print('LOCAL SYNTHETIC: dropped response produced native signed UNKNOWN, one simulated dispatch, STOP/pending preserved, no retry or restore bypass')
 def test_native_socket_roundtrip_and_replay(self):
  with self.scope.locked():
   def bootstrap(read):
    cmd='show running-config interface Ethernet0/1'
    reference=read.propose(cmd)['reference'];challenge=read.challenge(reference['proposal_id'],cmd)
    read.submit(challenge,self.key.sign(bytes.fromhex(challenge['canonical'])))
    return reference['proposal_id']
   services=PortServices(self.tx,self.events,self,self.scope,self.target,self.native,bootstrap,protected_ports=set())
   runner_root=self.root/'runner';runner_root.mkdir(mode=0o700)
   runner=PortRunner(runner_root,protect=lambda p,**kw:pathlib.Path(p))
   def ask(operation):
    return runner.request(operation,'local synthetic cage dispatcher qualification',
     lambda q:cage_dispatch(q,services,self.scope,lease_seconds=60))
   tid=ask('port_prepare_mode_access')['transaction_id']
   self.assertEqual(ask('port_authorize')['state'],'approved')
   for verb,state in [('preflight','preflight_verified'),('apply','applied'),('verify','verified'),('restore','restore_applied'),('verify_restored','restored')]:
    self.assertEqual(ask('port_'+verb)['state'],state)
   self.assertEqual(len(list((self.root/'records').glob('*.request.json'))),7)
   self.assertEqual(runner.completion()['state'],'restored')
   _,body=self.tx._get(tid);native=self.native(body)
   state=json.loads((self.root/'device-state.json').read_text());self.assertEqual(state,{'access':False,'writes':2})
   pid=body['native_proposals']['forward']['proposal_id']
   with sqlite3.connect(self.root/'chain.db') as db:
    db.row_factory=sqlite3.Row
    original=dict(db.execute('select * from chain_entries where artifact_id=?',('outcome:'+pid,)).fetchone())
    original_bytes=db.execute('select artifact_content from artifacts where artifact_id=?',('outcome:'+pid,)).fetchone()[0].encode()
   started=time.time_ns();replayed=native.observe(body['plan']['forward'],proposal_id=pid)
   self.assertEqual(replayed['result']['subtype'],15);self.assertIn('approval_reused, err=-37',replayed['result']['output'])
   with sqlite3.connect(self.root/'chain.db') as db:
    db.row_factory=sqlite3.Row
    row=dict(db.execute("select * from chain_entries where artifact_id like ?",('replay:'+pid+':%',)).fetchone())
    raw=db.execute('select artifact_content from artifacts where artifact_id=?',(row['artifact_id'],)).fetchone()[0].encode()
    self.assertEqual(dict(db.execute('select * from chain_entries where artifact_id=?',('outcome:'+pid,)).fetchone()),original)
    self.assertEqual(db.execute('select artifact_content from artifacts where artifact_id=?',('outcome:'+pid,)).fetchone()[0].encode(),original_bytes)
    sessions=[(r[0],r[1]) for r in db.execute('select session_id,max(sequence) from chain_entries group by session_id')]
   result=verify_pair((row,raw),(original,original_bytes),public_key=self.producer,node_id=260,device='kestrel-ios',command=body['plan']['forward'],proposal_id=pid,gate_session='gate-enforce:kestrel-ios@port-test',approval_session=self.approval_session,prior_outcome_hash=original['artifact_hash'],not_before_ns=started)
   self.assertEqual(result['error_code'],-37)
   self.assertEqual(json.loads((self.root/'device-state.json').read_text())['writes'],2)
   for sid,high in sessions:
    verified=self.transport.management({'action':'chain_verify','session_id':sid,'from_sequence':0,'to_sequence':high})
    self.assertTrue(verified['valid']);self.assertEqual(verified['entries_checked'],high+1);self.assertEqual(verified['executions_open'],0)
   frames=list((self.root/'records').glob('*.v3.frame'));self.assertTrue(frames);self.assertTrue(all(p.read_bytes()[0]==3 for p in frames))
   print('LOCAL SYNTHETIC:',len(frames),'v3 frames,',len(sessions),'native chains, apply/restore once, replay -37, state restored')
if __name__=='__main__':unittest.main()
