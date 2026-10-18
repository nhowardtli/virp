"""External-pin checks for existing native approval body_version=2 artifacts.

No new approval or chain format. Reconstruct the 72-byte VAP1 payload from the
artifact fields, never accept a caller-supplied alternative signed payload.
"""
import hashlib
import json
import re
import sqlite3
import struct
from pathlib import Path
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from recovery import verify_entry_signature

def verify_approval(body,*,public_key,proposal_id,device,device_node_id,command,operator,now_ns):
 try:
  if body['body_version']!=2 or body['proposal_id']!=proposal_id or body['device']!=device or body['operator']!=operator:raise ValueError()
  if type(body['device_node_id'])is not int or body['device_node_id']!=device_node_id:raise ValueError()
  if type(body['ttl_seconds'])is not int or body['ttl_seconds']!=300:raise ValueError()
  if body['approver_key_id']!=hashlib.sha256(public_key).hexdigest()[:32]:raise ValueError()
  if body['command_hash']!=hashlib.sha256(command.encode('ascii')).hexdigest():raise ValueError()
  timestamp=body['approved_at_ns']
  if type(timestamp)is int:issued=timestamp
  elif isinstance(timestamp,str) and re.fullmatch('[1-9][0-9]{0,19}',timestamp):issued=int(timestamp)
  else:raise ValueError()
  if not 0<=issued<=now_ns<issued+300000000000:raise ValueError()
  if not re.fullmatch('[a-f0-9]{32}',proposal_id):raise ValueError()
  canonical=struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(proposal_id),bytes.fromhex(body['command_hash']),device_node_id,issued,300)
  Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(body['approver_signature']),canonical)
 except (KeyError,TypeError,ValueError,UnicodeError,struct.error,InvalidSignature):
  raise ValueError('native_approval_artifact_invalid') from None
 return canonical

class ApprovalLedger:
 def __init__(self,db,transport,producer_public_key,approval_session):
  self.db=db;self.transport=transport;self.pin=producer_public_key;self.session=approval_session
 def verify(self,*,expected_chain_hash,**expected):
  sid=self.session;prefix='approval:'+expected['device'];aid='approval:'+expected['proposal_id']
  if not isinstance(sid,str) or not (sid==prefix or sid.startswith(prefix+'@')):raise ValueError('native_approval_session_pin_invalid')
  with sqlite3.connect('file:'+str(Path(self.db).resolve())+'?mode=ro',uri=True) as db:
   db.row_factory=sqlite3.Row
   rows=db.execute('SELECT * FROM chain_entries WHERE session_id=? AND artifact_id=?',(sid,aid)).fetchall()
   if len(rows)!=1:raise ValueError('native_approval_not_unique_in_chain')
   entry=dict(rows[0]);verify_entry_signature(entry,self.pin)
   if entry['artifact_type']!='approval' or entry['chain_entry_hash']!=expected_chain_hash:raise ValueError('native_approval_chain_binding_invalid')
   artifacts=db.execute('SELECT artifact_content FROM artifacts WHERE artifact_id=? AND artifact_hash=?',(aid,entry['artifact_hash'])).fetchall()
   if len(artifacts)!=1:raise ValueError('native_approval_artifact_missing_or_duplicate')
   raw=artifacts[0][0]
   if isinstance(raw,str):raw=raw.encode()
   if hashlib.sha256(raw).hexdigest()!=entry['artifact_hash']:raise ValueError('native_approval_artifact_hash_invalid')
   body=json.loads(raw);verify_approval(body,**expected)
   high=db.execute('SELECT MAX(sequence) FROM chain_entries WHERE session_id=?',(sid,)).fetchone()[0]
  result=self.transport.management({'action':'chain_verify','session_id':sid,'from_sequence':0,'to_sequence':high})
  if result.get('valid')is not True or result.get('entries_checked')!=high+1 or result.get('executions_open')!=0:raise ValueError('native_approval_chain_invalid')
  return {'entry':entry,'artifact':body,'artifact_bytes':raw}
