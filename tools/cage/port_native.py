"""Trusted fixed-port adapter to the existing helper/C execute path.

Caller owns the outer scope lock and supplies a guard that checks protected
host/config/binary pins, lease and STOP/pending markers. This internal library
has no cage RPC or direct SSH/device execution facility. No keys are loaded.
"""
import hashlib
import json
import re
import time
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from helper import execute_observed,durable_write
from port_challenge import validate as validate_challenge
from port_evidence import commands
from port_native_approval import ApprovalLedger,ProposalLedger
from port_transaction import Refused,canonical,validate_target_plan,validate_target

class NativePort:
 def __init__(self,*,body,transport,ledger,records,recovery_dir,public_key,node_id,
              chain_session,approval_session,approver_public_key,operator,guard,stop,
              control_transport=None,observer=execute_observed,wall_ns=time.time_ns):
  if 'plan' in body:validate_target_plan(body['target'],body['plan'])
  else:validate_target(body['target'])
  self.body=json.loads(canonical(body));self.target=self.body['target'];self.transport=transport;self.ledger=ledger
  self.control=control_transport or transport
  self.records=Path(records);self.recovery_dir=Path(recovery_dir);self.public_key=public_key
  self.node_id=node_id;self.chain_session=chain_session;self.approver_public_key=approver_public_key
  self.operator=operator;self.guard=guard;self.stop=stop;self.observer=observer;self.now=wall_ns
  self.device_id=int.from_bytes(hashlib.sha256(self.target['device'].encode()).digest()[:8],'big')
  self.allowed=set(commands(self.target['port']).values())
  if 'plan' in self.body:self.allowed|={self.body['plan']['forward'],self.body['plan']['rollback']}
  self.approvals=ApprovalLedger(ledger.db,transport,public_key,approval_session,node_id)
  self.proposals=ProposalLedger(ledger.db,transport,public_key,approval_session,node_id)
 def tier(self,command):
  if 'plan' in self.body and command in (self.body['plan']['forward'],self.body['plan']['rollback']):return 'RED'
  if command==commands(self.target['port'])['config']:return 'YELLOW'
  raise Refused('native_approval_not_required_for_command')
 def observe(self,command,*,proposal_id=None):
  if command not in self.allowed:raise Refused('command_outside_fixed_port_bundle')
  if proposal_id is not None and not re.fullmatch('[a-f0-9]{32}',proposal_id):raise Refused('invalid_native_proposal_id')
  self.guard()
  rid=uuid.uuid4().hex;aid='port:'+rid;path=self.records/(rid+'.v3.frame')
  request={'action':'execute','device':self.target['device'],'command':command}
  if proposal_id is not None:request['proposal_id']=proposal_id
  started=self.now()
  raw,result=self.observer(self.transport,request,public_key=self.public_key,node_id=self.node_id,
   device_id=self.device_id,path=path,chain_session=self.chain_session,artifact_id=aid,recovery_dir=self.recovery_dir)
  receipt=self.ledger.verify(raw,self.chain_session,aid)
  if hashlib.sha256(raw).hexdigest()!=result['frame_sha256']:raise Refused('observed_frame_hash_mismatch')
  record={'request':request,'request_started_ns':started,'artifact_id':aid,'chain_session':self.chain_session,
          'result':result,'verified_chain_receipt':receipt}
  durable_write(Path(str(path)+'.json'),canonical(record))
  return {'raw':raw,'result':result,'receipt':receipt,'artifact_id':aid,'path':str(path),'request_started_ns':started}
 def propose(self,command):
  tier=self.tier(command)
  observed=self.observe(command);r=observed['result']
  if r['subtype']!=15 or not r['output'].startswith('ERROR: tier gate blocked '):
   self.stop('unexpected_preapproval_result')
   raise Refused('unexpected_preapproval_result_stop_required')
  ids=re.findall(r'\bproposal_id=([a-f0-9]{32})\b',r['output'])
  if len(ids)!=1:raise Refused('native_proposal_id_not_unique')
  proof=self.proposals.verify(proposal_id=ids[0],device=self.target['device'],device_node_id=self.target['device_node_id'],command=command,tier=tier,not_before_ns=observed['request_started_ns'],now_ns=self.now())
  return proof
 def challenge(self,proposal_id,command):
  self.guard()
  value=self.control.management({'action':'approval_challenge','proposal_id':proposal_id})
  validate_challenge(value,device=self.target['device'],command=command,node_id=self.target['device_node_id'],now_ns=self.now(),tier=self.tier(command))
  if value['proposal_id']!=proposal_id:raise Refused('native_challenge_proposal_changed')
  return value
 def submit(self,challenge,signature):
  self.guard();command=challenge['command']
  raw=validate_challenge(challenge,device=self.target['device'],command=command,node_id=self.target['device_node_id'],now_ns=self.now(),tier=self.tier(command))
  Ed25519PublicKey.from_public_bytes(self.approver_public_key).verify(signature,raw)
  key_id=hashlib.sha256(self.approver_public_key).hexdigest()[:32]
  reply=self.control.management({'action':'approval_submit','proposal_id':challenge['proposal_id'],'key_id':key_id,'signature':signature.hex()})
  if (reply.get('already_approved') is not False or reply.get('proposal_id')!=challenge['proposal_id']
      or reply.get('approver_key_id')!=key_id or reply.get('operator')!=self.operator):raise Refused('native_approval_submit_not_fresh_or_wrong_owner')
  return self.approvals.verify(expected_chain_hash=reply['chain_entry_hash'],public_key=self.approver_public_key,
   proposal_id=challenge['proposal_id'],device=self.target['device'],device_node_id=self.target['device_node_id'],
   command=command,operator=self.operator,now_ns=self.now())
