#!/usr/bin/env python3
"""Actual local C socket/chain pipeline with simulated device I/O, never Cisco.

Run via make test-port-native-pipeline CISCO=1. No network target is contacted.
Fresh test keys and all mutable state live in one private temporary directory.
"""
import base64,hashlib,json,os,pathlib,sqlite3,subprocess,sys,tempfile,time,unittest,uuid
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
from port_owner_service import dispatch
from port_replay import verify_pair

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
  if hasattr(self,'proc'):self.proc.wait(timeout=35)  # Native idle select has a 30-second heartbeat.
  if hasattr(self,'log'):self.log.close()
  if os.environ.get('VIRP_KEEP_PORT_FIXTURE')=='1':
   # Only a test process invokes this; directory contains generated test keys.
   print('LOCAL SYNTHETIC FIXTURE:',self.root);self.tmp._finalizer.detach()
  else:self.tmp.cleanup()
 def native(self,body):
  return NativePort(body=body,transport=self.transport,ledger=self.ledger,records=self.root/'records',recovery_dir=self.root/'v3-recovery',public_key=self.producer,node_id=260,chain_session=self.chain,approval_session=self.approval_session,approver_public_key=self.pub,operator='canary-test-approver',guard=self.scope.check,stop=self.scope.stop)
 def call(self,q):
  if q['action']=='authorize':return {'ok':True,'transaction_id':q['transaction_id'],**self.owner.authorize(q['transaction_id'])}
  return dispatch(q,self.owner,lambda:None,{'kestrel-ios'})
 def test_native_socket_roundtrip_and_replay(self):
  with self.scope.locked():
   read=self.native({'target':self.target});cmd='show running-config interface Ethernet0/1'
   # Explicit local test-key bootstrap; no production/Duo claim.
   reference=read.propose(cmd)['reference'];challenge=read.challenge(reference['proposal_id'],cmd)
   read.submit(challenge,self.key.sign(bytes.fromhex(challenge['canonical'])))
   prep=PortPreparation(self.tx,self.events,read,self.native,self.scope,protected_ports=set())
   tid=prep.prepare('mode_access',config_proposal_id=reference['proposal_id'],verification_budget=4)
   approved=PortAuthorization(self.tx,self.events,self,self.scope,tid).authorize(60)
   self.assertEqual(approved['state'],'approved')
   _,body=self.tx._get(tid);native=self.native(body)
   flow=PortFlow(self.tx,self.events,native,self,self.scope,tid,protected_ports=set())
   for verb,state in [('preflight','preflight_verified'),('apply','applied'),('verify','verified'),('restore','restore_applied'),('verify_restored','restored')]:
    self.assertEqual(flow.step(verb)['state'],state)
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
