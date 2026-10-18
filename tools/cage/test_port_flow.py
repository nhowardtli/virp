"""Synthetic coordinator/helper wiring; no live device or Duo acceptance."""
import base64,hashlib,json,struct,unittest
from types import SimpleNamespace
from helper import decode
from port_flow import PortFlow
from port_evidence import commands
from port_transaction import Refused
import test_port_pipeline
from test_port_evidence import fixture

class FlowTests(unittest.TestCase):
 def setUp(self):
  self.p=test_port_pipeline.Pipeline();self.p.setUp();self.calls=[];self.stops=[];self.failure=None
  self.native=SimpleNamespace(body=self.p.body,public_key=self.p.fixture.pub,node_id=260,device_id=42,chain_session='test-session',ledger=self.p.fixture.ledger.native,observe=self.observe,challenge=self.challenge,submit=lambda q,s:{'entry':{'session_id':'approval:kestrel-ios@test','artifact_id':'approval:'+q['proposal_id'],'artifact_hash':'d'*64,'chain_entry_hash':'e'*64}})
  self.flow=PortFlow(self.p.tx,self.p.fixture.ledger,self.native,SimpleNamespace(call=self.owner),SimpleNamespace(check=lambda:None,stop=self.stops.append),self.p.tid,protected_ports=set(),wall_ns=lambda:self.p.wall)
 def tearDown(self):self.p.tearDown()
 def owner(self,q):
  if q['action']=='sign_native':return {'ok':True,'transaction_id':self.p.tid,'signature':self.p.owner.sign_native(self.p.tid,q['event'],q['entry'],q['challenge']).hex()}
  if q['action']=='close':self.p.owner.accept_close(self.p.tid,q['event'],q['entry']);return {'ok':True,'transaction_id':self.p.tid}
  self.fail('unexpected owner action')
 def challenge(self,pid,cmd):
  raw=struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(pid),hashlib.sha256(cmd.encode()).digest(),260,self.p.wall,300)
  return {'proposal_id':pid,'device':'kestrel-ios','device_node_id':260,'command':cmd,'tier':'YELLOW' if cmd.startswith('interface ') else 'YELLOW','ttl_seconds':300,'canonical':raw.hex()}
 def observe(self,cmd,proposal_id=None):
  self.calls.append((cmd,proposal_id))
  if self.failure=='transport':raise TimeoutError('synthetic lost response')
  p=self.p.body['plan'];state=self.p.tx.status(self.p.tid)['state']
  changed=state in ('verifying','restoring')
  d=fixture();d['config']='interface Ethernet0/1\n'+'\n'.join(p['expected' if changed else 'before'])+'\nend'
  d['switchport']=d['switchport'].replace('static access','static access' if changed else 'dynamic auto')
  bycmd={v:d[k] for k,v in commands('Ethernet0/1').items()}
  text='canary#'+cmd+'\n'+bycmd.get(cmd,'configuration accepted')
  if self.failure=='neighbor' and cmd==commands('Ethernet0/1')['lldp']:text='canary#'+cmd+'\nTotal entries displayed: 1'
  typ=15 if self.failure=='unknown' else 7
  if typ==15:text='ERROR: outcome UNKNOWN synthetic timeout'
  payload=b'VIRP-XO1'+struct.pack('!BBH',typ,1,len(text.encode()))+text.encode()
  timestamp=self.p.wall-(121000000000 if self.failure=='stale' else 0)
  sid=b'x'*16
  unsigned=struct.pack('!BBBBQQQ16sQ32sI',3,1,1,0,260,timestamp,1,sid,42,hashlib.sha256(cmd.encode()).digest(),len(payload))+payload+b'\0'*32
  raw=unsigned+self.p.fixture.key.sign(unsigned);aid='frame-'+str(len(self.calls))
  self.p.fixture.management({'action':'chain_append','session_id':'test-session','artifact_type':'observation','artifact_id':aid,'artifact_hash':hashlib.sha256(raw).hexdigest(),'artifact_content':'base64:'+base64.b64encode(raw).decode()})
  result=decode(raw,public_key=self.native.public_key,session_id=sid,node_id=260,device_id=42,command=cmd,after_sequence=-1,now_ns=timestamp)
  return {'raw':raw,'result':result,'artifact_id':aid,'receipt':self.native.ledger.verify(raw,'test-session',aid)}
 def test_full_machine_compared_roundtrip(self):
  for verb,state in [('preflight','preflight_verified'),('apply','applied'),('verify','verified'),('restore','restore_applied'),('verify_restored','restored')]:
   self.assertEqual(self.flow.step(verb)['state'],state)
  self.assertEqual([c for c,_ in self.calls if c.startswith('interface ')],[self.p.body['plan']['forward'],self.p.body['plan']['rollback']])
  reports=[e for e in self.p.fixture.db.execute("select artifact_content from artifacts") if 'machine_comparison' in e[0]]
  self.assertEqual(len(reports),5);self.assertEqual(self.stops,[])
  self.assertEqual(json.loads(reports[0][0])['native_approval']['session_id'],'approval:kestrel-ios@test')
  self.assertEqual(self.p.tx.events(self.p.tid)[0]['bundle'],self.p.body)
 def test_unrelated_read_never_dispatched(self):
  with self.assertRaises(Refused):self.flow.step('show_version')
  self.assertEqual(self.calls,[])
 def test_neighbor_blocks_apply(self):
  self.failure='neighbor';self.assertEqual(self.flow.step('preflight')['state'],'preflight-refused')
  with self.assertRaises(Refused):self.flow.step('apply')
  self.assertFalse(any(c.startswith('interface ') for c,_ in self.calls))
 def test_lease_expiry_restores_under_original_approval(self):
  self.flow.step('preflight');self.flow.step('apply');self.p.wall+=11000000000;self.p.boot+=11
  with self.assertRaises(Refused):self.flow.step('unrelated_read')
  self.flow.step('restore');self.assertEqual(self.flow.step('verify_restored')['state'],'restored')
  self.assertEqual(self.p.tx.db.execute('select count(*) from approvals').fetchone()[0],1)
 def test_unknown_records_signed_frame_and_stops(self):
  self.flow.step('preflight');self.failure='unknown'
  self.assertEqual(self.flow.step('apply')['state'],'unknown');self.assertEqual(self.stops,['native_outcome_unproven'])
 def test_transport_loss_does_not_fabricate_result_or_retry(self):
  self.flow.step('preflight');self.failure='transport'
  with self.assertRaises(TimeoutError):self.flow.step('apply')
  self.assertEqual(self.p.tx.status(self.p.tid)['state'],'applying');self.assertEqual(self.stops,['port_step_interrupted'])
  with self.assertRaises(Refused):self.flow.step('apply')
  self.assertEqual(sum(c.startswith('interface ') for c,_ in self.calls),1)
 def test_stale_read_cannot_be_declared_success(self):
  self.failure='stale'
  with self.assertRaises(ValueError):self.flow.step('preflight')
  self.assertEqual(self.p.tx.status(self.p.tid)['state'],'preflighting');self.assertEqual(self.stops,['port_step_interrupted'])
if __name__=='__main__':unittest.main()
