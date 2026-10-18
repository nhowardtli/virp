"""Trusted bounded transaction workflow; no model-supplied CLI or verdict.

The endpoint must hold ScopeGuard.locked across a step and provision all
adapters from protected inputs. An exception leaves state unresolved and latches
STOP. It never synthesizes a native UNKNOWN, clears pending, or retries dispatch.
"""
import hashlib
import re
import time
import uuid
from port_evidence import commands
from port_result import capture_after,compare,compare_preflight
from port_transaction import Refused,canonical,digest

class PortFlow:
 def __init__(self,transactions,events,native,owner,scope,transaction_id,*,protected_ports,wall_ns=time.time_ns):
  self.tx=transactions;self.events=events;self.native=native;self.owner=owner;self.scope=scope
  self.tid=transaction_id;self.protected=frozenset(protected_ports);self.now=wall_ns
  _,body=self.tx._get(self.tid)
  if canonical(body)!=canonical(native.body):raise Refused('native_transaction_bundle_mismatch')
  self.body=body
 def flush(self):self.tx.flush(self.events)
 def owner_call(self,q):
  reply=self.owner.call({'transaction_id':self.tid,**q})
  if not isinstance(reply,dict) or reply.get('ok') is not True or reply.get('transaction_id')!=self.tid:raise Refused('owner_step_refused_or_mismatched')
  return reply
 def last_event(self,kind,request_id=None):
  events=[e for e in self.tx.events(self.tid) if e['type']==kind and (request_id is None or e.get('request_id')==request_id)]
  if not events:raise Refused('required_transaction_event_missing')
  return events[-1]
 def native_id(self,verb):
  phase={'apply':'forward','restore':'restore','preflight':'preflight'}.get(verb,'verify')
  inv=self.body['native_proposals'];refs=inv['verify'] if phase=='verify' else [inv[phase]]
  for ref in refs:
   if not self.tx.db.execute('SELECT 1 FROM native_issuances WHERE proposal_id=?',(ref['proposal_id'],)).fetchone():return ref['proposal_id']
  raise Refused('approved_native_inventory_exhausted')
 def close_owner(self):
  status=self.tx.status(self.tid);self.flush()
  if status['state'] in ('restored','expired-before-apply','preflight-refused'):
   event=self.last_event('close')
   self.owner_call({'action':'close','event':event,'entry':self.events.proof(event)})
  return status
 def step(self,verb):
  self.scope.check();self.tx.status(self.tid);self.flush()
  request=self.tx.begin(self.tid,verb)
  try:
   self.flush();return self._step(request)
  except BaseException:
   # Do not turn an exception into a signed native result. Recovery must first
   # establish worker/daemon state; the original request remains outstanding.
   self.scope.stop('port_step_interrupted')
   raise
 def _step(self,request):
  verb=request['verb'];p=self.body['plan'];port=self.body['target']['port']
  intent=self.last_event(verb+'_intent',request['request_id']);intent_entry=self.events.proof(intent)
  config=commands(port)['config']
  command=p['forward' if verb=='apply' else 'rollback'] if verb in ('apply','restore') else config
  pid=self.native_id(verb);challenge=self.native.challenge(pid,command)
  self.tx.reserve_native(request,challenge);self.flush()
  native_intent=self.last_event('native_approval_intent',request['request_id'])
  raw=self.tx.native_signable(request,pid);self.flush()
  signature=bytes.fromhex(self.owner_call({'action':'sign_native','event':native_intent,'entry':self.events.proof(native_intent),'challenge':challenge})['signature'])
  if raw!=bytes.fromhex(challenge['canonical']):raise Refused('native_signable_changed')
  approval=self.native.submit(challenge,signature)
  approval_ref={k:approval['entry'][k] for k in ('session_id','artifact_id','artifact_hash','chain_entry_hash')}
  self.scope.check();dispatch=self.tx.require_dispatch(request)
  dispatch_commands=[dispatch] if isinstance(dispatch,str) else dispatch
  captures=[];outputs={};unknown=False;names={v:k for k,v in commands(port).items()}
  for cmd in dispatch_commands:
   self.scope.check()
   observed=self.native.observe(cmd,proposal_id=pid if cmd==command else None)
   result=observed['result'];captures.append({'command':cmd,'frame_sha256':result['frame_sha256'],'receipt':observed['receipt']})
   if result['subtype']!=7:
    unknown=True;break
   if verb in ('apply','restore'):
    # A successful transport response is only 'applied', never 'verified'.
    if re.search(r'(?m)^\s*(?:%|ERROR:)',result['output']):unknown=True
   else:
    capture=capture_after(raw=observed['raw'],public_key=self.native.public_key,session_id=bytes.fromhex(result['session_id']),
     node_id=self.native.node_id,device_id=self.native.device_id,command=cmd,after_sequence=-1,now_ns=self.now(),
     ledger=self.native.ledger,chain_session=self.native.chain_session,artifact_id=observed['artifact_id'],
     not_before_ns=intent['time_ns'],min_chain_sequence=intent_entry['sequence'])
    outputs[names[cmd]]=capture['output']
  if not captures:raise Refused('missing_step_observations')
  if unknown:outcome='unknown'
  elif verb in ('apply','restore'):outcome='executed'
  elif verb=='preflight':
   # Freshness covers the entire collection, not merely its last read.
   if not 0<=self.now()-intent['time_ns']<=30000000000:raise Refused('preflight_collection_stale')
   outcome=compare_preflight(self.body,outputs,protected_ports=self.protected)
  elif verb in ('verify','verify_restored'):outcome=compare(p,outputs,restore=verb=='verify_restored')
  else:
   before=compare(p,outputs,restore=True);forward=compare(p,outputs)
   outcome='matches_before' if before=='matches' else 'matches_forward' if forward=='matches' else 'unknown'
  report={'schema':'kestrel-port-event/1','event_id':uuid.uuid4().hex,'transaction_id':self.tid,
          'type':'machine_comparison','time_ns':self.now(),'request_id':request['request_id'],'verb':verb,
          'plan_sha256':digest(self.body),'outcome':outcome,'observations':captures,'native_approval':approval_ref}
  receipt=self.events(report)
  self.tx.finish(request,outcome,observation_hash=captures[-1]['frame_sha256'],evidence={k:receipt[k] for k in ('artifact_id','artifact_hash','chain_entry_hash')})
  self.flush()
  if unknown or outcome=='unknown':self.scope.stop('native_outcome_unproven' if unknown else 'comparison_unproven')
  return self.close_owner()
