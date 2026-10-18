"""Bounded model loop for one owner-selected canary port qualification.

Provider, journal and transport are trusted adapters supplied by a protected
entrypoint. Model text never authorizes execution or proves device state. This
module contains no API credential loading, SSH or direct device execution.
"""
import json
from port_plan import OPS
from port_runner import CLOSED,NEXT,RESULTS,RunnerRefused,encode

class ModelStopped(ValueError):pass

def last_state(runner):
 with runner.locked():state,_,_=runner.history();return state

def restore_confirmed(runner,transport):
 """Only the already-approved baseline restore; never repair pending state."""
 try:
  state=last_state(runner)
  if state['state']=='unknown':return {'state':'reconciliation_required','reason':'native_outcome_unresolved'}
  if state['state'] in ('applied','verified','verify_failed'):
   state=runner.request('port_restore','Trusted controller restores the approved baseline after model workflow stopped.',transport)
  if state['state']=='restore_applied':
   state=runner.request('port_verify_restored','Trusted controller verifies the approved baseline restore after model workflow stopped.',transport)
  if state['state'] in CLOSED:return runner.completion()
  if state['state']=='unknown':return {'state':'reconciliation_required','reason':'restore_outcome_unresolved'}
  return {'state':state['state'],'action':'none; no confirmed apply to restore'}
 except Exception:return {'state':'reconciliation_required','reason':'runner_or_transport_unresolved'}

def unique(pairs):
 value={}
 for k,v in pairs:
  if k in value:raise ModelStopped('duplicate_model_argument')
  value[k]=v
 return value

def run(provider,runner,transport,*,operation,prompt,record,max_turns=12):
 if operation not in OPS:raise ModelStopped('owner_operation_not_supported')
 if not isinstance(prompt,str) or not 1<=len(prompt)<=4000:raise ModelStopped('invalid_owner_prompt')
 if type(max_turns)is not int or not 7<=max_turns<=12:raise ModelStopped('invalid_model_turn_bound')
 selected='port_prepare_'+operation;allowed=frozenset({selected,*RESULTS})
 inputs=[{'role':'user','content':prompt}];call_ids=set();verified=False;transcript_ok=True
 def emit(event):
  nonlocal transcript_ok
  try:record(event)
  except Exception:
   transcript_ok=False;raise ModelStopped('transcript_write_failed') from None
 try:
  initial=last_state(runner)
  if initial['state'] not in CLOSED|{'absent'}:raise ModelStopped('prior_transaction_open')
  for turn in range(max_turns):
   state=last_state(runner)
   available=({selected} if state['state'] in CLOSED|{'absent'} else NEXT[state['state']])&allowed
   emit({'type':'model_request','turn':turn,'allowed_operations':sorted(available)})
   response=provider(inputs,tuple(sorted(available)))
   if not isinstance(response,dict) or len(encode(response))>131072:raise ModelStopped('invalid_model_response')
   emit({'type':'model_response','turn':turn,'response':response,'authority':'untrusted_model_output'})
   if response.get('status','completed')!='completed':raise ModelStopped('model_response_incomplete')
   output=response.get('output')
   if not isinstance(output,list) or any(not isinstance(x,dict) for x in output):raise ModelStopped('invalid_model_output')
   calls=[x for x in output if x.get('type')=='function_call']
   if not calls:raise ModelStopped('model_ended_before_transaction_closed')
   if len(calls)!=1:raise ModelStopped('parallel_model_calls_denied')
   c=calls[0];cid=c.get('call_id')
   if c.get('name')!='virp_port' or not isinstance(cid,str) or not 1<=len(cid)<=128 or cid in call_ids:raise ModelStopped('invalid_or_reused_model_call')
   args=c.get('arguments')
   if not isinstance(args,str) or len(args)>4096:raise ModelStopped('invalid_model_arguments')
   try:a=json.loads(args,object_pairs_hook=unique)
   except (ValueError,TypeError):raise ModelStopped('invalid_model_arguments') from None
   if not isinstance(a,dict) or set(a)!={'operation','rationale'} or not isinstance(a['operation'],str) or a['operation'] not in available:raise ModelStopped('model_operation_not_authorized')
   call_ids.add(cid);inputs.extend(output)
   result=runner.request(a['operation'],a['rationale'],transport)
   emit({'type':'helper_result','call_id':cid,'result':result,'authority':'bound_helper_reply; independent evidence verification separate'})
   inputs.append({'type':'function_call_output','call_id':cid,'output':json.dumps(result)})
   if result['state']=='verified':verified=True
   if result['state']=='unknown':raise ModelStopped('helper_outcome_unknown')
   if result['state'] in CLOSED:
    completed=runner.completion()
    return {'ok':result['state']=='restored' and verified,'result':completed,
     'reason':'roundtrip_complete' if verified and result['state']=='restored' else 'forward_verification_not_passed',
     'transcript_complete':transcript_ok,'evidence_verified_independently':False}
  raise ModelStopped('model_turn_limit')
 except Exception as error:
  public_error=isinstance(error,(ModelStopped,RunnerRefused)) or (type(error).__module__=='port_provider' and type(error).__name__=='ProviderRefused')
  reason=str(error) if public_error else 'runner_or_provider_failed'
  recovery=restore_confirmed(runner,transport)
  try:emit({'type':'workflow_stopped','reason':reason,'recovery':recovery})
  except ModelStopped:pass
  return {'ok':False,'error':reason,'recovery':recovery,'transcript_complete':transcript_ok,'evidence_verified_independently':False}
