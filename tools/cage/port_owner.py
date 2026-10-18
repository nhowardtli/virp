"""Independent owner coordinator library, never a cage-facing signing service.

A protected entrypoint must authenticate/pin the requesting executor and read
keys and Duo configuration locally. This module has no network or credential
loading code. Production must fix owner=nhoward-admin; tests use a distinct key.
"""
from contextlib import contextmanager
import json
import math
import re
import sqlite3
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from recovery import verify_entry_signature
from port_challenge import validate as validate_challenge
from port_transaction import canonical,digest,validate_bundle,DOMAIN,Refused

class OwnerRequests:
 def __init__(self,path,public_key,sign,*,owner,boot_id,max_lease_seconds,wall_ns=time.time_ns,boottime=None,producers=None):
  self.producers=producers or {}
  self.key=Ed25519PublicKey.from_public_bytes(public_key);self.sign=sign;self.owner=owner
  self.boot_id=boot_id;self.maximum=max_lease_seconds;self.now=wall_ns
  self.clock=boottime or (lambda:time.clock_gettime(time.CLOCK_BOOTTIME))
  self.db=sqlite3.connect(path,isolation_level=None,timeout=10);self.db.row_factory=sqlite3.Row
  self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA synchronous=FULL')
  self.db.executescript('''
   CREATE TABLE IF NOT EXISTS owner_requests(id TEXT PRIMARY KEY,body TEXT NOT NULL,hash TEXT NOT NULL,
    lease INTEGER NOT NULL,executor_boot TEXT NOT NULL,owner_boot TEXT NOT NULL,state TEXT NOT NULL,
    duo_txid TEXT UNIQUE,envelope TEXT,signature TEXT,deadline REAL,authorized_ns INTEGER);
   CREATE TABLE IF NOT EXISTS native_signatures(proposal_id TEXT PRIMARY KEY,transaction_id TEXT NOT NULL,
    phase TEXT NOT NULL,event_id TEXT UNIQUE NOT NULL,request_id TEXT UNIQUE NOT NULL,
    state TEXT NOT NULL,signature TEXT);
   CREATE TABLE IF NOT EXISTS owner_events(seq INTEGER PRIMARY KEY,transaction_id TEXT NOT NULL,body TEXT NOT NULL);
  ''')
 def close(self):self.db.close()
 @contextmanager
 def atomic(self):
  self.db.execute('BEGIN IMMEDIATE')
  try:yield;self.db.execute('COMMIT')
  except BaseException:self.db.execute('ROLLBACK');raise
 def event(self,tid,kind,**details):
  body={'type':kind,'transaction_id':tid,'time_ns':self.now(),**details}
  self.db.execute('INSERT INTO owner_events(transaction_id,body) VALUES(?,?)',(tid,canonical(body).decode()))
 def get(self,tid,state):
  r=self.db.execute('SELECT * FROM owner_requests WHERE id=?',(tid,)).fetchone()
  if r is None or r['state']!=state:raise Refused('owner_state_or_replay_refused')
  if r['owner_boot']!=self.boot_id:raise Refused('owner_reboot_requires_reconciliation')
  body=json.loads(r['body'])
  if digest(body)!=r['hash']:raise Refused('owner_plan_tampered')
  return r,body
 def prepare(self,tid,body,*,lease_seconds,executor_boot_id):
  validate_bundle(body)
  if not isinstance(tid,str) or not re.fullmatch('[a-f0-9]{32}',tid):raise Refused('invalid_transaction_id')
  if type(lease_seconds)is not int or not 1<=lease_seconds<=self.maximum:raise Refused('invalid_owner_lease')
  if not isinstance(executor_boot_id,str) or not re.fullmatch('[a-zA-Z0-9-]{1,64}',executor_boot_id):raise Refused('invalid_executor_boot')
  with self.atomic():
   try:self.db.execute('INSERT INTO owner_requests(id,body,hash,lease,executor_boot,owner_boot,state) VALUES(?,?,?,?,?,?,?)',(tid,canonical(body).decode(),digest(body),lease_seconds,executor_boot_id,self.boot_id,'prepared'))
   except sqlite3.IntegrityError:raise Refused('owner_request_already_exists') from None
   self.event(tid,'prepared',plan_sha256=digest(body))
 def authorize(self,tid,duo):
  with self.atomic():
   row,body=self.get(tid,'prepared')
   self.db.execute("UPDATE owner_requests SET state='push_started' WHERE id=?",(tid,))
   self.event(tid,'push_started',plan_sha256=row['hash'])
  pre=duo.preauth(self.owner)
  if pre.get('result')!='auth':raise Refused('explicit_duo_factor_required')
  context={'Plan':tid,'SHA256':row['hash'],'Target':body['target']['host']+':'+str(body['target']['transport_port']),
   'Interface':body['target']['port'],'Forward':body['plan']['forward'],
   'Restore':body['plan']['rollback'],'Lease seconds':str(row['lease']),
   'Scope':'Apply once, verify, restore baseline, verify; no save'}
  txid=duo.push(self.owner,pre,context)
  if not isinstance(txid,str) or not re.fullmatch('[A-Za-z0-9-]{16,128}',txid):raise Refused('invalid_duo_transaction')
  with self.atomic():
   current,_=self.get(tid,'push_started')
   if current['hash']!=row['hash']:raise Refused('owner_context_changed')
   self.db.execute("UPDATE owner_requests SET state='push_pending',duo_txid=? WHERE id=?",(txid,tid))
   self.event(tid,'push_pending',duo_txid=txid,plan_sha256=row['hash'])
  result=duo.wait(txid)
  with self.atomic():
   current,_=self.get(tid,'push_pending')
   if current['duo_txid']!=txid or current['hash']!=row['hash']:raise Refused('duo_binding_changed')
   allowed=result.get('result')=='allow' and result.get('status')=='allow'
   approved_ns=self.now()
   self.db.execute('UPDATE owner_requests SET state=?,authorized_ns=?,deadline=? WHERE id=?',('authorized' if allowed else 'denied',approved_ns,self.clock()+row['lease'],tid))
   self.event(tid,'authorized' if allowed else 'denied',duo_txid=txid,plan_sha256=row['hash'])
  if not allowed:raise Refused('duo_denied')
  return {'plan_sha256':row['hash'],'approved_ns':approved_ns,'expires_ns':approved_ns+row['lease']*1000000000,'max_lease_seconds':row['lease'],'authorization':{'method':'duo','reference':txid,'approved_ns':approved_ns}}
 def sign_envelope(self,tid,a):
  with self.atomic():
   row,_=self.get(tid,'authorized')
   if self.clock()>=row['deadline'] or self.now()>=row['authorized_ns']+row['lease']*1000000000:raise Refused('owner_approval_expired')
   try:
    if set(a)!={'schema','approval_id','transaction_id','plan_sha256','owner','issued_ns','lease_seconds','boot_id','issued_boottime','authorization'}:raise ValueError()
    if a['authorization']!={'method':'duo','reference':row['duo_txid'],'approved_ns':row['authorized_ns']}:raise ValueError()
    if a['schema']!='kestrel-port-approval/1' or a['transaction_id']!=tid or a['plan_sha256']!=row['hash'] or a['owner']!=self.owner:raise ValueError()
    if a['boot_id']!=row['executor_boot'] or type(a['lease_seconds'])is not int or not 1<=a['lease_seconds']<=row['lease']:raise ValueError()
    if not re.fullmatch('[a-f0-9]{32}',a['approval_id']):raise ValueError()
    if type(a['issued_ns'])is not int or not 0<=self.now()-a['issued_ns']<=30000000000:raise ValueError()
    if type(a['issued_boottime'])not in (int,float) or not math.isfinite(a['issued_boottime']) or a['issued_boottime']<0:raise ValueError()
    if a['issued_ns']<row['authorized_ns'] or a['issued_ns']+a['lease_seconds']*1000000000>row['authorized_ns']+row['lease']*1000000000:raise ValueError()
    remaining=(a['issued_ns']+a['lease_seconds']*1000000000-self.now())/1000000000
    if remaining<=0:raise ValueError()
   except (TypeError,KeyError,ValueError):raise Refused('owner_envelope_binding_invalid') from None
   self.db.execute("UPDATE owner_requests SET state='signature_started',envelope=?,deadline=? WHERE id=?",(canonical(a).decode(),min(row['deadline'],self.clock()+remaining),tid))
   self.event(tid,'signature_started',approval_id=a['approval_id'],duo_txid=row['duo_txid'],plan_sha256=row['hash'])
  signature=self.sign(DOMAIN+canonical(a))
  self.key.verify(signature,DOMAIN+canonical(a))
  with self.atomic():
   current,_=self.get(tid,'signature_started')
   if current['envelope']!=canonical(a).decode():raise Refused('signed_envelope_changed')
   self.db.execute("UPDATE owner_requests SET state='signed',signature=? WHERE id=?",(signature.hex(),tid))
   self.event(tid,'signed',approval_id=a['approval_id'],duo_txid=row['duo_txid'],plan_sha256=row['hash'],signature=signature.hex())
  return signature

 def sign_native(self,tid,event,entry,challenge):
  with self.atomic():
   row,body=self.get(tid,'signed')
   a=json.loads(row['envelope']);target=body['target'];profile=self.producers.get(target['device'])
   if profile is None:raise Refused('producer_pin_not_configured')
   self.key.verify(bytes.fromhex(row['signature']),DOMAIN+canonical(a))
   if a['plan_sha256']!=row['hash'] or a['transaction_id']!=tid:raise Refused('owner_signed_plan_changed')
   verify_entry_signature(entry,profile['public_key'])
   if (entry['artifact_hash']!=digest(event) or entry['artifact_id']!=event.get('event_id')
       or entry['artifact_type']!='evidence_item' or entry['session_id']!=profile['chain_session']
       or entry['signer_node_id']!=profile['node_id']):raise Refused('native_intent_chain_binding_invalid')
   if (event.get('schema')!='kestrel-port-event/1' or event.get('type')!='native_approval_intent'
       or event.get('transaction_id')!=tid or event.get('approval_id')!=a['approval_id']
       or event.get('canonical')!=challenge.get('canonical') or event.get('proposal_id')!=challenge.get('proposal_id')
       or event.get('command')!=challenge.get('command')
       or not re.fullmatch('[a-f0-9]{32}',str(event.get('request_id','')))):
    raise Refused('native_intent_approval_binding_invalid')
   if type(event.get('time_ns'))is not int or not 0<=self.now()-event['time_ns']<=120000000000:raise Refused('native_intent_stale')
   command=event['command'];p=body['plan']
   if command==p['forward']:phase='forward';tier='RED'
   elif command==p['rollback']:phase='restore';tier='RED'
   elif command=='show running-config interface '+target['port']:
    phase='preflight' if challenge['proposal_id']==body['native_proposals']['preflight']['proposal_id'] else 'verify';tier='YELLOW'
   else:raise Refused('native_command_outside_owner_approval')
   inventory=body['native_proposals'];refs=inventory['verify'] if phase=='verify' else [inventory[phase]]
   if challenge['proposal_id'] not in {ref['proposal_id'] for ref in refs}:raise Refused('native_proposal_not_in_owner_approved_inventory')
   if phase in ('forward','preflight'):
    if self.clock()>=row['deadline'] or self.now()>=a['issued_ns']+a['lease_seconds']*1000000000:raise Refused('owner_approval_expired')
   elif not self.db.execute("SELECT 1 FROM native_signatures WHERE transaction_id=? AND phase='forward' AND state='signed'",(tid,)).fetchone():
    raise Refused('native_forward_not_issued')
   if phase in ('forward','restore','preflight') and self.db.execute('SELECT 1 FROM native_signatures WHERE transaction_id=? AND phase=?',(tid,phase)).fetchone():raise Refused('native_phase_already_issued')
   if phase=='verify' and self.db.execute("SELECT COUNT(*) FROM native_signatures WHERE transaction_id=? AND phase='verify'",(tid,)).fetchone()[0]>=8:raise Refused('native_verification_budget_exhausted')
   raw=validate_challenge(challenge,device=target['device'],command=command,node_id=target['device_node_id'],now_ns=self.now(),tier=tier)
   try:self.db.execute('INSERT INTO native_signatures(proposal_id,transaction_id,phase,event_id,request_id,state) VALUES(?,?,?,?,?,?)',(challenge['proposal_id'],tid,phase,event['event_id'],event['request_id'],'signing'))
   except sqlite3.IntegrityError:raise Refused('native_signature_reused') from None
   self.event(tid,'native_signing',phase=phase,proposal_id=challenge['proposal_id'],intent_chain_entry=entry['chain_entry_hash'],approval_id=a['approval_id'])
  signature=self.sign(raw);self.key.verify(signature,raw)
  with self.atomic():
   self.get(tid,'signed')
   self.db.execute("UPDATE native_signatures SET state='signed',signature=? WHERE proposal_id=?",(signature.hex(),challenge['proposal_id']))
   self.event(tid,'native_signed',phase=phase,proposal_id=challenge['proposal_id'],signature=signature.hex())
  return signature

 def accept_close(self,tid,event,entry):
  with self.atomic():
   row,body=self.get(tid,'signed');profile=self.producers.get(body['target']['device'])
   if profile is None:raise Refused('producer_pin_not_configured')
   verify_entry_signature(entry,profile['public_key'])
   if (entry['artifact_hash']!=digest(event) or entry['artifact_id']!=event.get('event_id')
       or entry['artifact_type']!='evidence_item' or entry['session_id']!=profile['chain_session']
       or entry['signer_node_id']!=profile['node_id'] or event.get('schema')!='kestrel-port-event/1'
       or event.get('transaction_id')!=tid or event.get('type')!='close'
       or event.get('reason') not in ('roundtrip_complete','lease_expired','reconciled_to_baseline','expired-before-apply','preflight-mismatch','preflight-unproven')):
    raise Refused('owner_close_binding_invalid')
   self.db.execute("UPDATE owner_requests SET state='closed' WHERE id=?",(tid,))
   self.event(tid,'closed',reason=event['reason'],chain_entry_hash=entry['chain_entry_hash'])
