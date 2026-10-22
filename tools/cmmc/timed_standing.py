"""Branch candidate: timed envelope over an existing two-port standing grant.

Trusted adapter supplies protected authority, exact forward/restore plans and
verified device callbacks. This is NOT a native C lease claim or a cage RPC.
No signing, renewal, authority widening, automatic UNKNOWN replay, or prod use.
"""
import hashlib,json,math,pathlib,sqlite3,time
class Refused(ValueError):pass
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def digest(x):return hashlib.sha256(canonical(x)).hexdigest()
class TimedStanding:
 def __init__(self,db,authority,lease,*,wall=time.time,boot=time.monotonic,boot_id='test'):
  self.wall=wall;self.boot=boot;self.boot_id=boot_id;self.authority=authority;self.lease=lease
  if authority.get('ports')!=['GigabitEthernet1/0/22','GigabitEthernet1/0/23'] or authority.get('vlans')!=[50,80]:raise Refused('scope_mismatch')
  if set(lease)!={'authority_sha256','issued_wall','expires_wall','issued_boot','expires_boot','boot_id','plan_sha256'}:raise Refused('lease_fields')
  if lease['authority_sha256']!=digest(authority) or lease['boot_id']!=boot_id:raise Refused('lease_binding')
  for k in ['issued_wall','expires_wall','issued_boot','expires_boot']:
   if type(lease[k]) not in [int,float] or not math.isfinite(lease[k]):raise Refused('invalid_time')
  if not 0<lease['expires_wall']-lease['issued_wall']<=300 or lease['expires_wall']-lease['issued_wall']!=lease['expires_boot']-lease['issued_boot']:raise Refused('lease_duration')
  self.pin=digest({'authority':authority,'lease':lease})
  self.db=sqlite3.connect(db,isolation_level=None);self.db.execute('PRAGMA synchronous=FULL');self.db.execute('CREATE TABLE IF NOT EXISTS attempts(id TEXT PRIMARY KEY,pin TEXT,plan_hash TEXT,state TEXT)')
 def guard(self):
  if digest({'authority':self.authority,'lease':self.lease})!=self.pin:raise Refused('lease_or_authority_changed')
  if self.lease['boot_id']!=self.boot_id:raise Refused('boot_changed')
  if self.wall()<self.lease['issued_wall'] or self.boot()<self.lease['issued_boot']:raise Refused('clock_rewind')
 def expired(self):
  self.guard();return self.wall()>=self.lease['expires_wall'] or self.boot()>=self.lease['expires_boot']
 def run(self,request_id,plan,*,dispatch,verify_restore):
  # Caller must validate exact rendering against twoport_plan and signed baseline.
  self.guard()
  if digest(plan)!=self.lease['plan_sha256']:raise Refused('plan_binding')
  if self.expired():raise Refused('expired_before_dispatch')
  if not plan.get('forward') or not plan.get('restore'):raise Refused('missing_exact_recovery')
  try:self.db.execute('INSERT INTO attempts VALUES(?,?,?,?)',(request_id,self.pin,digest(plan),'reserved'))
  except sqlite3.IntegrityError:raise Refused('request_replay') from None
  if self.db.execute("SELECT count(*) FROM attempts WHERE state NOT IN ('restored','expired_before_dispatch')").fetchone()[0]>1:
   self.db.execute("UPDATE attempts SET state='blocked_concurrent' WHERE id=?",(request_id,));raise Refused('prior_unreconciled_attempt')
  sent=0
  try:
   for command in plan['forward']:
    if self.expired():break
    # Durable uncertain state exists BEFORE dispatch. Crash cannot replay it.
    self.db.execute("UPDATE attempts SET state='dispatching' WHERE id=?",(request_id,))
    outcome=dispatch(command,'forward')
    if outcome is not True:raise Refused('unknown_forward_outcome')
    sent+=1;self.db.execute("UPDATE attempts SET state='applied' WHERE id=?",(request_id,))
   if not sent:
    self.db.execute("UPDATE attempts SET state='expired_before_dispatch' WHERE id=?",(request_id,));return {'state':'expired_before_dispatch','forward':0,'restore':0}
   # Only the ORIGINAL pinned restore is permitted after expiry; no new plan.
   self.guard();self.db.execute("UPDATE attempts SET state='restoring' WHERE id=?",(request_id,))
   for command in plan['restore']:
    self.guard()
    if dispatch(command,'restore') is not True:raise Refused('unknown_restore_outcome')
   if verify_restore() is not True:raise Refused('restore_not_verified')
   self.db.execute("UPDATE attempts SET state='restored' WHERE id=?",(request_id,))
   return {'state':'restored','expired':self.expired(),'forward':sent,'restore':len(plan['restore'])}
  except BaseException:
   self.db.execute("UPDATE attempts SET state='recovery_required' WHERE id=?",(request_id,));raise
