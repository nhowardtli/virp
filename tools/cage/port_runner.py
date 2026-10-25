"""Trusted runner protocol/journal, not an approval or transport implementation.

Install only behind a root-owned fixed canary transport. The model supplies an
operation and rationale; this layer creates IDs and preserves ambiguous calls.
The server remains the execution authority. These local records are helper
attestations, not signed chain entries or independent evidence verification.
"""
from contextlib import contextmanager
import fcntl,json,os,re,uuid
from pathlib import Path
from helper import durable_write
from port_owner_service import protected
from port_plan import OPS

PREPARE=frozenset('port_prepare_'+op for op in OPS)
CLOSED=frozenset(('restored','expired-before-apply','preflight-refused'))
NEXT={'absent':PREPARE,'prepared':{'port_authorize'},'approved':{'port_preflight'},
 'preflight_verified':{'port_apply'},'applied':{'port_verify','port_restore'},
 'verified':{'port_restore'},'verify_failed':{'port_restore'},'restore_applied':{'port_verify_restored'},'unknown':set()}
RESULTS={'port_authorize':{'approved'},'port_preflight':{'preflight_verified','preflight-refused','expired-before-apply','unknown'},
 'port_apply':{'applied','unknown'},'port_verify':{'verified','verify_failed','unknown'},
 'port_restore':{'restore_applied','unknown'},'port_verify_restored':{'restored','unknown'}}

class RunnerRefused(ValueError):pass
def encode(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()

def validate(q):
 if not isinstance(q,dict) or set(q)!={'operation','request_id','rationale'}:raise RunnerRefused('invalid_runner_request')
 if not isinstance(q['operation'],str) or q['operation'] not in PREPARE|RESULTS.keys():raise RunnerRefused('invalid_runner_operation')
 if not isinstance(q['request_id'],str) or not re.fullmatch('[a-f0-9]{32}',q['request_id']):raise RunnerRefused('invalid_runner_request_id')
 if not isinstance(q['rationale'],str) or not 20<=len(q['rationale'])<=1000:raise RunnerRefused('invalid_runner_rationale')

def check_reply(q,r,previous):
 fields={'ok','operation','request_id','transaction_id','state','expired','close_reason'}
 if not isinstance(r,dict) or set(r)!=fields or r['ok'] is not True:raise RunnerRefused('helper_refused_or_invalid_reply')
 if r['operation']!=q['operation'] or r['request_id']!=q['request_id']:raise RunnerRefused('helper_reply_binding_mismatch')
 if not isinstance(r['transaction_id'],str) or not re.fullmatch('[a-f0-9]{32}',r['transaction_id']):raise RunnerRefused('helper_transaction_id_invalid')
 if q['operation'] not in PREPARE and r['transaction_id']!=previous['transaction_id']:raise RunnerRefused('helper_transaction_changed')
 if type(r['expired'])is not bool or (r['close_reason'] is not None and not isinstance(r['close_reason'],str)):raise RunnerRefused('invalid_helper_state')
 allowed={'prepared'} if q['operation'] in PREPARE else RESULTS[q['operation']]
 if not isinstance(r['state'],str) or r['state'] not in allowed:raise RunnerRefused('unexpected_helper_state')

class PortRunner:
 def __init__(self,root,*,protect=protected):
  self.root=Path(root);self.protect=protect
 @contextmanager
 def locked(self):
  self.protect(self.root,secret=True,directory=True)
  path=self.root/'lock'
  if os.path.lexists(path):self.protect(path,secret=True)
  fd=os.open(path,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
  try:
   self.protect(path,secret=True)
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:raise RunnerRefused('runner_busy') from None
   yield
  finally:os.close(fd)
 def history(self):
  state={'state':'absent','transaction_id':None};transactions=set();records=sorted(self.root.glob('*.request.json'))
  for sequence,path in enumerate(records,1):
   match=re.fullmatch(r'([0-9]{8})-([a-f0-9]{32})\.request\.json',path.name)
   if not match or int(match[1])!=sequence:raise RunnerRefused('runner_journal_order_invalid')
   q=json.loads(self.protect(path,secret=True).read_bytes());validate(q)
   if q['request_id']!=match[2]:raise RunnerRefused('runner_journal_id_invalid')
   allowed=PREPARE if state['state'] in CLOSED else NEXT[state['state']]
   if q['operation'] not in allowed:raise RunnerRefused('runner_journal_transition_invalid')
   result=path.with_name(path.name.replace('.request.json','.result.json'))
   if not os.path.lexists(result):raise RunnerRefused('prior_request_unresolved')
   r=json.loads(self.protect(result,secret=True).read_bytes());check_reply(q,r,state)
   if q['operation'] in PREPARE:
    if r['transaction_id'] in transactions:raise RunnerRefused('runner_transaction_reused')
    transactions.add(r['transaction_id'])
   state=r
  expected={p.name.replace('.request.json','.result.json') for p in records}
  if {p.name for p in self.root.glob('*.result.json')}!=expected:raise RunnerRefused('orphan_runner_result')
  return state,len(records),transactions
 def request(self,operation,rationale,transport):
  q={'operation':operation,'request_id':uuid.uuid4().hex,'rationale':rationale};validate(q)
  with self.locked():
   state,count,transactions=self.history();allowed=PREPARE if state['state'] in CLOSED else NEXT[state['state']]
   if operation not in allowed:raise RunnerRefused('runner_operation_out_of_order')
   if count>=99999999:raise RunnerRefused('runner_journal_limit')
   stem=f'{count+1:08d}-'+q['request_id']
   durable_write(self.root/(stem+'.request.json'),encode(q))
   try:
    r=transport(dict(q));reply_bytes=encode(r)
    if len(reply_bytes)>8192:raise RunnerRefused('oversized_helper_reply')
    # Preserve a mismatched/refused reply privately before interpreting it;
    # never pass unchecked fields or exception text back to the model.
    durable_write(self.root/(stem+'.reply.json'),reply_bytes)
    check_reply(q,r,state)
    if operation in PREPARE and r['transaction_id'] in transactions:raise RunnerRefused('runner_transaction_reused')
    durable_write(self.root/(stem+'.result.json'),encode(r))
   except BaseException as error:
    # Preserve the unresolved intent. No automatic retry, cancellation,
    # native UNKNOWN synthesis or clearing of the server's recovery markers.
    durable_write(self.root/(stem+'.error.json'),encode({'request_id':q['request_id'],'kind':type(error).__name__,'outcome':'unresolved'}))
    raise RunnerRefused('transport_outcome_unresolved') from None
   return r
 def completion(self):
  with self.locked():
   state,_,_=self.history()
   if state['state'] not in CLOSED:raise RunnerRefused('transaction_not_closed')
   return {'state':state['state'],'transaction_id':state['transaction_id'],'close_reason':state['close_reason'],
           'evidence_verified_independently':False}
