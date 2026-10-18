"""Trusted port-transaction state, not a cage RPC or a native-approval bypass.

Only an independent Ed25519 approver may activate a plan. A root adapter must
verify source observations, native approvals, and signed ledger receipts. The
model receives verb names only. Native command approvals remain mandatory.
"""
from contextlib import contextmanager
import hashlib
import json
import math
import re
import sqlite3
import time
import uuid
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from port_plan import plan as render
from port_challenge import validate as validate_challenge

DOMAIN = b'VIRP-PORT-TRANSACTION-APPROVAL-v1\x00'
TARGETS = {('kestrel-ios','192.168.255.10','Ethernet0/1'):{'device_node_id':260,'transport_port':22},
           ('SW-3850','10.0.10.2','GigabitEthernet1/0/22'):{'device_node_id':0x0a000a02,'transport_port':2223}}
class Refused(ValueError):pass

def canonical(obj):return json.dumps(obj,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
def digest(obj):return hashlib.sha256(canonical(obj)).hexdigest()
def hex64(value):return isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value)

def validate_bundle(body):
 # Validate finite render grammar even though this is a trusted internal API.
 try:
  target=body['target'];p=body['plan'];port=target['port']
  if set(body)!={'target','plan','verification','precondition_hashes'}:raise ValueError()
  if set(target)!={'device','host','port','device_node_id','transport_port'} or tuple(target[k] for k in ('device','host','port')) not in TARGETS:raise ValueError()
  pins=TARGETS[tuple(target[k] for k in ('device','host','port'))]
  if any(type(target[k])is not int or target[k]!=v for k,v in pins.items()):raise ValueError()
  if p['port']!=port or p['save'] is not False:raise ValueError()
  if digest({k:v for k,v in p.items() if k!='bundle_sha256'})!=p['bundle_sha256']:raise ValueError()
  baseline='interface '+port+'\n'+'\n'.join(p['before'])+'\nend'
  rebuilt=render(baseline,port,p['operation'],active_vlans={10})
  for k in ('forward','rollback','before','expected','tier','schema','operation'):
   if p[k]!=rebuilt[k]:raise ValueError()
  if body['verification']!=['show interfaces '+port+' switchport','show running-config interface '+port]:raise ValueError()
  if not body['precondition_hashes'] or not all(hex64(x) for x in body['precondition_hashes']):raise ValueError()
 except (KeyError,TypeError,ValueError):raise Refused('invalid_transaction_bundle') from None

class Transactions:
 def __init__(self,path,public_key,*,owner,wall_ns=time.time_ns,boottime=None,boot_id,max_lease_seconds,required_approval_method="duo"):
  self.key=Ed25519PublicKey.from_public_bytes(public_key)
  self.required_approval_method=required_approval_method
  self.owner=owner;self.wall_ns=wall_ns;self.boottime=boottime or (lambda:time.clock_gettime(time.CLOCK_BOOTTIME));self.boot_id=boot_id;self.max_lease_seconds=max_lease_seconds
  self.db=sqlite3.connect(path,isolation_level=None,timeout=10)
  self.db.row_factory=sqlite3.Row
  self.db.execute('PRAGMA synchronous=FULL');self.db.execute('PRAGMA journal_mode=WAL')
  self.db.executescript('''
   CREATE TABLE IF NOT EXISTS transactions(id TEXT PRIMARY KEY,body TEXT NOT NULL,hash TEXT NOT NULL,
    state TEXT NOT NULL,boot TEXT NOT NULL,approval TEXT,signature TEXT,expires_ns INTEGER,
    deadline REAL,expired INTEGER NOT NULL DEFAULT 0,close_reason TEXT);
   CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,transaction_id TEXT UNIQUE NOT NULL);
   CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,transaction_id TEXT NOT NULL,verb TEXT NOT NULL,
    dispatched INTEGER NOT NULL DEFAULT 0,finished INTEGER NOT NULL DEFAULT 0);
   CREATE TABLE IF NOT EXISTS native_issuances(proposal_id TEXT PRIMARY KEY,request_id TEXT NOT NULL,
    command TEXT NOT NULL,challenge TEXT NOT NULL,issued INTEGER NOT NULL DEFAULT 0,
    UNIQUE(request_id,command));
   CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,
    transaction_id TEXT NOT NULL,body TEXT NOT NULL,receipt TEXT);
  ''')
 def close(self):self.db.close()
 @contextmanager
 def atomic(self):
  self.db.execute('BEGIN IMMEDIATE')
  try:
   yield
   self.db.execute('COMMIT')
  except BaseException:
   self.db.execute('ROLLBACK');raise
 def _event(self,tid,kind,**data):
  eid=uuid.uuid4().hex
  e={'schema':'kestrel-port-event/1','event_id':eid,'transaction_id':tid,'type':kind,'time_ns':self.wall_ns(),**data}
  self.db.execute('INSERT INTO events(event_id,transaction_id,body) VALUES(?,?,?)',(eid,tid,canonical(e).decode()))
 def _get(self,tid):
  row=self.db.execute('SELECT * FROM transactions WHERE id=?',(tid,)).fetchone()
  if row is None:raise Refused('unknown_transaction')
  body=json.loads(row['body'])
  if digest(body)!=row['hash']:raise Refused('approved_bundle_tampered')
  if row['boot']!=self.boot_id:raise Refused('boot_changed_reconciliation_required')
  if row['approval']:
   approval=json.loads(row['approval'])
   if approval['plan_sha256']!=row['hash'] or approval['transaction_id']!=tid:raise Refused('approval_binding_changed')
   if approval['owner']!=self.owner or approval['boot_id']!=self.boot_id or approval['authorization']['method']!=self.required_approval_method:raise Refused('stored_approval_context_changed')
   if row['expires_ns']!=approval['issued_ns']+approval['lease_seconds']*1000000000 or row['deadline']!=approval['issued_boottime']+approval['lease_seconds']:raise Refused('approved_deadline_tampered')
   try:self.key.verify(bytes.fromhex(row['signature']),DOMAIN+canonical(approval))
   except (InvalidSignature,ValueError):raise Refused('stored_approval_invalid') from None
  return row,body
 def create(self,body):
  validate_bundle(body)
  tid=uuid.uuid4().hex
  with self.atomic():
   self.db.execute('INSERT INTO transactions(id,body,hash,state,boot) VALUES(?,?,?,?,?)',(tid,canonical(body).decode(),digest(body),'prepared',self.boot_id))
   self._event(tid,'proposal',plan_sha256=digest(body))
  return tid
 def approval_request(self,tid,seconds,*,authorization):
  row,_=self._get(tid)
  if row['state']!='prepared':raise Refused('approval_already_processed')
  if type(seconds)is not int or not 1<=seconds<=self.max_lease_seconds:raise Refused('invalid_lease')
  return {'schema':'kestrel-port-approval/1','approval_id':uuid.uuid4().hex,'transaction_id':tid,
          'plan_sha256':row['hash'],'owner':self.owner,'issued_ns':self.wall_ns(),'lease_seconds':seconds,'boot_id':self.boot_id,'issued_boottime':self.boottime(),'authorization':authorization}
 def approve(self,a,signature):
  try:
   if set(a)!={'schema','approval_id','transaction_id','plan_sha256','owner','issued_ns','lease_seconds','boot_id','issued_boottime','authorization'}:raise ValueError()
   if a['schema']!='kestrel-port-approval/1' or a['owner']!=self.owner or a['boot_id']!=self.boot_id:raise ValueError()
   if not re.fullmatch('[a-f0-9]{32}',a['approval_id']):raise ValueError()
   if type(a['issued_ns'])is not int or not 0<=self.wall_ns()-a['issued_ns']<=120000000000:raise ValueError()
   if type(a['lease_seconds'])is not int or not 1<=a['lease_seconds']<=self.max_lease_seconds:raise ValueError()
   if type(a['issued_boottime']) not in (int,float) or not math.isfinite(a['issued_boottime']) or not 0<=self.boottime()-a['issued_boottime']<=120:raise ValueError()
   auth=a['authorization']
   if set(auth)!={'method','reference','approved_ns'} or auth['method']!=self.required_approval_method or auth['method'] not in ('duo','test'):raise ValueError()
   if not re.fullmatch('[A-Za-z0-9-]{16,128}',auth['reference']) or type(auth['approved_ns'])is not int or not auth['approved_ns']<=a['issued_ns']:raise ValueError()
   self.key.verify(signature,DOMAIN+canonical(a))
  except (ValueError,KeyError,TypeError,InvalidSignature):raise Refused('invalid_approval') from None
  expiry=a['issued_ns']+a['lease_seconds']*1000000000
  if expiry<=self.wall_ns() or a['issued_boottime']+a['lease_seconds']<=self.boottime():raise Refused('approval_lease_already_expired')
  with self.atomic():
   row,_=self._get(a['transaction_id'])
   if row['state']!='prepared' or row['hash']!=a['plan_sha256']:raise Refused('approval_reused_or_wrong_bundle')
   if self.db.execute('SELECT 1 FROM approvals WHERE id=?',(a['approval_id'],)).fetchone():raise Refused('approval_reused')
   self.db.execute('INSERT INTO approvals VALUES(?,?)',(a['approval_id'],a['transaction_id']))
   self.db.execute("UPDATE transactions SET state='approved',approval=?,signature=?,expires_ns=?,deadline=? WHERE id=?",(canonical(a).decode(),signature.hex(),expiry,a['issued_boottime']+a['lease_seconds'],a['transaction_id']))
   self._event(a['transaction_id'],'approval',approval=a,signature=signature.hex())
 def _refresh(self,tid):
  with self.atomic():
   row,_=self._get(tid)
   if row['state'] not in ('restored','expired-before-apply') and row['approval'] and not row['expired'] and (self.wall_ns()>=row['expires_ns'] or self.boottime()>=row['deadline']):
    self.db.execute('UPDATE transactions SET expired=1 WHERE id=?',(tid,))
    self._event(tid,'lease_expired',approval_id=json.loads(row['approval'])['approval_id'],transaction_state=row['state'])
    req=self.db.execute("SELECT dispatched FROM requests WHERE transaction_id=? AND verb='apply' ORDER BY rowid DESC LIMIT 1",(tid,)).fetchone()
    if row['state']=='approved' or (row['state']=='applying' and req and not req['dispatched']):
     self.db.execute("UPDATE transactions SET state='expired-before-apply',close_reason='lease_expired' WHERE id=?",(tid,))
     self._event(tid,'close',reason='expired-before-apply')
 def status(self,tid):
  self._refresh(tid);row,_=self._get(tid)
  return {k:row[k] for k in ('id','state','expired','close_reason')}
 def begin(self,tid,verb):
  self._refresh(tid)
  with self.atomic():
   row,body=self._get(tid)
   allowed={'apply':('approved',),'verify':('applied','verified'),'restore':('applied','verified','verify_failed'),
            'verify_restored':('restore_applied',),'reconcile':('unknown',)}
   if verb not in allowed or row['state'] not in allowed[verb]:raise Refused('verb_not_allowed_in_transaction_state')
   if not row['approval'] or (row['expired'] and verb=='apply'):raise Refused('lease_expired')
   if self.db.execute('SELECT 1 FROM events WHERE transaction_id=? AND receipt IS NULL',(tid,)).fetchone():raise Refused('chain_receipt_required')
   rid=uuid.uuid4().hex
   self.db.execute('INSERT INTO requests(id,transaction_id,verb) VALUES(?,?,?)',(rid,tid,verb))
   state={'apply':'applying','verify':'verifying','restore':'restoring','verify_restored':'verifying_restore','reconcile':'reconciling'}[verb]
   self.db.execute('UPDATE transactions SET state=? WHERE id=?',(state,tid))
   self._event(tid,verb+'_intent',request_id=rid,approval_id=json.loads(row['approval'])['approval_id'],plan_sha256=row['hash'])
   return {'transaction_id':tid,'request_id':rid,'verb':verb}
 def _request(self,r):
  if not isinstance(r,dict) or set(r)!={'transaction_id','request_id','verb'}:raise Refused('invalid_request')
  q=self.db.execute('SELECT * FROM requests WHERE id=?',(r['request_id'],)).fetchone()
  if q is None or q['transaction_id']!=r['transaction_id'] or q['verb']!=r['verb'] or q['finished']:raise Refused('request_reused_or_mismatched')
  row,body=self._get(r['transaction_id']);return q,row,body
 def _native_command(self,q,row,body,command):
  if q['dispatched']:raise Refused('dispatch_already_consumed')
  if not row['approval'] or (q['verb']=='apply' and (row['expired'] or self.wall_ns()>=row['expires_ns'] or self.boottime()>=row['deadline'])):raise Refused('lease_expired')
  if q['verb'] in ('apply','restore'):
   expected=body['plan']['forward' if q['verb']=='apply' else 'rollback'];tier='RED'
  else:
   expected='show running-config interface '+body['target']['port'];tier='YELLOW'
  if command!=expected:raise Refused('native_command_outside_approved_plan')
  return tier
 def reserve_native(self,r,challenge):
  self._refresh(r['transaction_id'])
  with self.atomic():
   q,row,body=self._request(r)
   command=challenge.get('command');tier=self._native_command(q,row,body,command)
   validate_challenge(challenge,device=body['target']['device'],command=command,
    node_id=body['target']['device_node_id'],now_ns=self.wall_ns(),tier=tier)
   if self.db.execute('SELECT 1 FROM events WHERE transaction_id=? AND receipt IS NULL',(row['id'],)).fetchone():raise Refused('chain_receipt_required')
   try:self.db.execute('INSERT INTO native_issuances(proposal_id,request_id,command,challenge) VALUES(?,?,?,?)',(challenge['proposal_id'],r['request_id'],command,canonical(challenge).decode()))
   except sqlite3.IntegrityError:raise Refused('native_approval_already_reserved') from None
   self._event(row['id'],'native_approval_intent',request_id=r['request_id'],proposal_id=challenge['proposal_id'],command=command,canonical=challenge['canonical'],approval_id=json.loads(row['approval'])['approval_id'])
  return challenge['proposal_id']
 def native_signable(self,r,proposal_id):
  # Trusted independent approver adapter only. No cage endpoint exposes these
  # bytes for arbitrary signing. A signature is issued once, before dispatch.
  self._refresh(r['transaction_id'])
  with self.atomic():
   q,row,body=self._request(r)
   n=self.db.execute('SELECT * FROM native_issuances WHERE proposal_id=? AND request_id=?',(proposal_id,r['request_id'])).fetchone()
   if n is None or n['issued']:raise Refused('native_approval_unknown_or_reused')
   tier=self._native_command(q,row,body,n['command'])
   if json.loads(n['challenge'])['proposal_id']!=proposal_id:raise Refused('native_proposal_binding_changed')
   raw=validate_challenge(json.loads(n['challenge']),device=body['target']['device'],command=n['command'],node_id=body['target']['device_node_id'],now_ns=self.wall_ns(),tier=tier)
   if self.db.execute('SELECT 1 FROM events WHERE transaction_id=? AND receipt IS NULL',(row['id'],)).fetchone():raise Refused('chain_receipt_required')
   self.db.execute('UPDATE native_issuances SET issued=1 WHERE proposal_id=?',(proposal_id,))
   self._event(row['id'],'native_signature_issuance',request_id=r['request_id'],proposal_id=proposal_id)
   return raw
 def require_dispatch(self,r):
  self._refresh(r['transaction_id'])
  with self.atomic():
   q,row,body=self._request(r)
   if q['dispatched']:raise Refused('dispatch_already_consumed')
   if row['state']=='expired-before-apply' or (q['verb']=='apply' and (row['expired'] or self.wall_ns()>=row['expires_ns'] or self.boottime()>=row['deadline'])):raise Refused('lease_expired')
   if self.db.execute('SELECT 1 FROM events WHERE transaction_id=? AND receipt IS NULL',(row['id'],)).fetchone():raise Refused('chain_receipt_required')
   needed=body['plan']['forward' if q['verb']=='apply' else 'rollback'] if q['verb'] in ('apply','restore') else 'show running-config interface '+body['target']['port']
   n=self.db.execute('SELECT issued FROM native_issuances WHERE request_id=? AND command=?',(r['request_id'],needed)).fetchone()
   if n is None or not n['issued']:raise Refused('native_approval_issuance_required')
   self.db.execute('UPDATE requests SET dispatched=1 WHERE id=?',(r['request_id'],))
   # Durable reservation before device dispatch. A crash here requires reconciliation.
   if q['verb'] in ('apply','restore'):return body['plan']['forward' if q['verb']=='apply' else 'rollback']
   return list(body['verification'])
 def record_interruption(self,r,reason):
  # Root adapter only, after establishing the request worker is no longer
  # active. This is a helper event, never fabricated native UNKNOWN evidence.
  if reason not in ('transport_lost','worker_lost','signer_indeterminate'):raise Refused('invalid_interruption_reason')
  self._refresh(r['transaction_id'])
  with self.atomic():
   q,row,_=self._request(r)
   if row['state'] in ('restored','expired-before-apply'):raise Refused('transaction_already_closed')
   self.db.execute('UPDATE requests SET finished=1 WHERE id=?',(r['request_id'],))
   self.db.execute("UPDATE transactions SET state='unknown' WHERE id=?",(row['id'],))
   self._event(row['id'],'helper_interruption',request_id=r['request_id'],reason=reason,
    dispatch_reserved=bool(q['dispatched']),native_result_available=False)
 def finish(self,r,outcome,*,observation_hash):
  if not hex64(observation_hash):raise Refused('missing_observation')
  self._refresh(r['transaction_id'])
  with self.atomic():
   q,row,_=self._request(r)
   if not q['dispatched']:raise Refused('request_not_dispatched')
   verb=q['verb'];next_state=None;reason=None
   if verb in ('apply','restore'):
    if outcome=='executed':next_state='applied' if verb=='apply' else 'restore_applied'
    elif outcome=='unknown':next_state='unknown'
   elif verb=='verify':
    if outcome=='matches':next_state='verified'
    elif outcome=='mismatch':next_state='verify_failed'
    elif outcome=='unknown':next_state='unknown'
   elif verb=='verify_restored':
    if outcome=='matches':next_state='restored';reason='lease_expired' if row['expired'] else 'roundtrip_complete'
    elif outcome in ('mismatch','unknown'):next_state='unknown'
   elif verb=='reconcile':
    if outcome=='matches_forward':next_state='applied'
    elif outcome=='matches_before':next_state='restored';reason='reconciled_to_baseline'
    elif outcome=='unknown':next_state='unknown'
   if next_state is None:raise Refused('invalid_outcome')
   self.db.execute('UPDATE requests SET finished=1 WHERE id=?',(r['request_id'],))
   self.db.execute('UPDATE transactions SET state=?,close_reason=? WHERE id=?',(next_state,reason,row['id']))
   self._event(row['id'],verb+'_outcome',request_id=r['request_id'],outcome=outcome,observation_hash=observation_hash)
   if reason:self._event(row['id'],'close',reason=reason)
 def events(self,tid):return [json.loads(x[0]) for x in self.db.execute('SELECT body FROM events WHERE transaction_id=? ORDER BY seq',(tid,))]
 def flush(self,append_verified):
  # Adapter MUST verify existing identical artifact on retry after ambiguous append.
  # Holding the local writer lock serializes outbox delivery across processes.
  with self.atomic():
   for row in self.db.execute('SELECT seq,body FROM events WHERE receipt IS NULL ORDER BY seq').fetchall():
    event=json.loads(row['body']);receipt=append_verified(event)
    if not isinstance(receipt,dict) or not hex64(receipt.get('chain_entry_hash')) or receipt.get('artifact_id')!=event['event_id']:raise Refused('invalid_ledger_receipt')
    self.db.execute('UPDATE events SET receipt=? WHERE seq=?',(canonical(receipt).decode(),row['seq']))
