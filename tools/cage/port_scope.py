"""Outer work-scope guard. Does not renew leases or clear recovery markers.

The request lock spans the entire helper operation. Runtime pin checking is a
trusted deployment adapter, not caller/model input. Transaction expiry recovery
remains subordinate to this independent work scope and its STOP marker.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import time
from helper import durable_write
from port_owner_service import protected
from port_transaction import Refused, canonical

class ScopeGuard:
 def __init__(self,scope,*,check_runtime,limit=96,wall=time.time,
              boottime=lambda:time.clock_gettime(time.CLOCK_BOOTTIME),
              boot_id=lambda:Path('/proc/sys/kernel/random/boot_id').read_text(),
              protect=protected):
  self.scope=Path(scope);self.runtime=check_runtime;self.limit=limit
  self.wall=wall;self.boot=boottime;self.boot_id=boot_id;self.protect=protect
  self.fd=None;self.policy_hash=None
 @contextmanager
 def locked(self):
  if self.fd is not None:raise Refused('scope_already_locked')
  self.protect(self.scope,secret=True,directory=True)
  lock=self.scope/'lock'
  if os.path.lexists(lock):self.protect(lock,secret=True)
  fd=os.open(lock,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
  try:
   self.protect(lock,secret=True)
   try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
   except BlockingIOError:raise Refused('scope_busy') from None
   self.fd=fd;self.policy_hash=None
   yield self
  finally:
   self.fd=None;self.policy_hash=None;os.close(fd)
 def require_lock(self):
  if self.fd is None:raise Refused('scope_lock_required')
 def check(self):
  self.require_lock()
  if os.path.lexists(self.scope/'STOP'):raise Refused('scope_stopped')
  if os.path.lexists(self.scope/'v3-recovery/pending.json'):raise Refused('pending_outcome_requires_reconciliation')
  raw=self.protect(self.scope/'policy.json',secret=True).read_bytes()
  digest=hashlib.sha256(raw).hexdigest()
  if self.policy_hash is not None and self.policy_hash!=digest:raise Refused('scope_policy_changed')
  p=json.loads(raw)
  for key in ('expires','expires_boot'):
   if type(p.get(key)) not in (int,float) or not math.isfinite(p[key]):raise Refused('invalid_work_lease')
  if p.get('boot_id')!=self.boot_id() or self.wall()>=p['expires'] or self.boot()>=p['expires_boot']:raise Refused('work_lease_inactive')
  if not isinstance(p.get('authorization_sha256'),str) or not re.fullmatch('[a-f0-9]{64}',p['authorization_sha256']):raise Refused('missing_work_authorization_hash')
  self.runtime();self.policy_hash=digest
  return p
 def reserve(self,request):
  p=self.check()
  if not isinstance(request,dict) or set(request)!={'operation','request_id','rationale'}:raise Refused('invalid_request_fields')
  if not isinstance(request['request_id'],str) or not re.fullmatch('[a-f0-9]{32}',request['request_id']):raise Refused('invalid_request_id')
  if not isinstance(request['operation'],str) or not re.fullmatch('port_[a-z_]{1,40}',request['operation']):raise Refused('invalid_operation')
  if not isinstance(request['rationale'],str) or not 20<=len(request['rationale'])<=1000:raise Refused('invalid_rationale')
  records=self.protect(self.scope/'records',secret=True,directory=True)
  path=records/(request['request_id']+'.request.json')
  if os.path.lexists(path):raise Refused('request_already_recorded')
  if len(list(records.glob('*.request.json')))>=self.limit:raise Refused('attempt_limit')
  durable_write(path,canonical({**request,'time':self.wall(),'authorization_sha256':p['authorization_sha256']}))
  return path
 def stop(self,reason):
  self.require_lock()
  if not isinstance(reason,str) or not re.fullmatch('[a-z_]{1,100}',reason):raise Refused('invalid_stop_reason')
  path=self.scope/'STOP'
  if not os.path.lexists(path):durable_write(path,canonical({'reason':reason,'time':self.wall()}))
