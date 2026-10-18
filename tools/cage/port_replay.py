"""Public-pin semantic check for a native replay refusal and its prior outcome.

Supplement to full chain/witness verification, not a substitute. No execution,
key loading or approval issuance. Exact original artifact bytes are required.
"""
import hashlib
import json
import re
from recovery import verify_entry_signature

def verify_artifact(pair,*,public_key,node_id,session,kind):
 entry,raw=pair;e=dict(entry)
 if 'signature' in e:
  sig=e['signature']
  if sig.get('signature_scheme')!='ed25519-detached-v1':raise ValueError('unsupported_replay_signature_scheme')
  e['chain_sig_key_id']=sig['signing_key_id'];e['chain_sig']=sig['signature_hex']
 verify_entry_signature(e,public_key)
 if e['signer_node_id']!=node_id or e['session_id']!=session or e['artifact_type']!=kind or e['artifact_hash_alg']!='sha256':raise ValueError('replay_artifact_binding_invalid')
 if hashlib.sha256(raw).hexdigest()!=e['artifact_hash']:raise ValueError('replay_artifact_bytes_changed')
 body=json.loads(raw)
 if not isinstance(body,dict):raise ValueError('invalid_replay_artifact')
 return e,body

def verify_pair(rejection,outcome,*,public_key,node_id,device,command,proposal_id,
                gate_session,approval_session,prior_outcome_hash,not_before_ns):
 if not re.fullmatch('[a-f0-9]{32}',proposal_id) or not re.fullmatch('[a-f0-9]{64}',prior_outcome_hash):raise ValueError('invalid_replay_pins')
 r,b=verify_artifact(rejection,public_key=public_key,node_id=node_id,session=gate_session,kind='gate_rejection')
 o,original=verify_artifact(outcome,public_key=public_key,node_id=node_id,session=approval_session,kind='outcome')
 expected={'schema':'gate_rejection/1','reason':'approval_reused','error_code':-37,'approval_id':proposal_id,
           'proposal_id':proposal_id,'device':device,'command':command,'original_outcome_id':'outcome:'+proposal_id}
 if any(b.get(k)!=v for k,v in expected.items()) or b.get('executed') is not False:raise ValueError('native_replay_refusal_invalid')
 if not re.fullmatch('replay:'+proposal_id+':[0-9]+',r['artifact_id']):raise ValueError('native_replay_id_invalid')
 if o['artifact_id']!='outcome:'+proposal_id or o['artifact_hash']!=prior_outcome_hash:raise ValueError('original_outcome_changed')
 if (original.get('proposal_id')!=proposal_id or original.get('device')!=device or original.get('success') is not True
     or original.get('command_hash')!=hashlib.sha256(command.encode()).hexdigest()):raise ValueError('original_successful_outcome_unproven')
 if type(r['timestamp_ns'])is not int or type(o['timestamp_ns'])is not int or r['timestamp_ns']<max(o['timestamp_ns'],not_before_ns):raise ValueError('replay_predates_attempt_or_original_outcome')
 return {'error_code':-37,'executed':False,'proposal_id':proposal_id,'original_outcome_id':o['artifact_id'],
         'original_outcome_hash':o['artifact_hash'],'original_outcome_entry':o['chain_entry_hash'],
         'rejection_entry':r['chain_entry_hash']}
