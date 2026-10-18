#!/usr/bin/python3 -I
"""Canary-only fixed-command router, staged for bounded port qualification.

No deployment or lease renewal. The existing authenticated forced command may
invoke this without arguments after its two destinations have been pinned.
Old description writes are not exposed alongside open port transactions.
"""
import hashlib,json,os,re,stat,sys
from pathlib import Path

MACHINE='29f08b6f35114d0c8b5909eb8a26ad60'
PROFILE='/etc/virp-canary/port-router.json'
PORT_SERVICE='/opt/virp-canary/cage/port_canary_service.py'
LEGACY_SERVICE='/usr/local/libexec/virp-cml-cage-legacy'
PORT_OPERATIONS=frozenset('port_prepare_'+x for x in ('mode_access','vlan_10','portfast','security_enable','security_maximum_2','security_violation_restrict'))|frozenset(('port_authorize','port_preflight','port_apply','port_verify','port_restore','port_verify_restored','port_status'))
LEGACY_OPERATIONS=frozenset(('status','stop','sw_description','sw_port_switchport','sw_port_errors','sw_port_status','sw_trunks','sw_red_refusal','sw_vlan_brief','sw_port_mac','sw_port_cdp','sw_port_lldp','sw_etherchannel'))

class RouterRefused(ValueError):pass

def unique(pairs):
 result={}
 for key,value in pairs:
  if key in result:raise RouterRefused('duplicate_json_key')
  result[key]=value
 return result

OPEN_SERVICE='/opt/virp-canary/cage/open_canary.py'

def select(raw,allow_open=False):
 try:
  if not isinstance(raw,bytes) or len(raw)>4096:raise ValueError()
  q=json.loads(raw,object_pairs_hook=unique)
  if allow_open and isinstance(q,dict) and q.get('operation')=='open_execute':
   if set(q)!={'operation','request_id','rationale','command'}:raise ValueError()
   if not isinstance(q['command'],str) or not 1<=len(q['command'])<=1024:raise ValueError()
   q={k:v for k,v in q.items() if k!='command'}
  if not isinstance(q,dict) or set(q)!={'operation','request_id','rationale'}:raise ValueError()
  if not isinstance(q['request_id'],str) or not re.fullmatch('[a-f0-9]{32}',q['request_id']):raise ValueError()
  if not isinstance(q['rationale'],str) or not 20<=len(q['rationale'])<=1000:raise ValueError()
  op=q['operation']
  if not isinstance(op,str):raise ValueError()
  if op=='open_execute' and allow_open:return OPEN_SERVICE
  if op in PORT_OPERATIONS:return PORT_SERVICE
  if op in LEGACY_OPERATIONS:return LEGACY_SERVICE
  raise RouterRefused('operation_denied')
 except (ValueError,TypeError,UnicodeError):raise RouterRefused('invalid_or_denied_request') from None

def protected(path,*,secret=False):
 p=Path(path)
 if not p.is_absolute():raise RouterRefused('unprotected_router_path')
 for item in (p,*p.parents):
  st=item.lstat()
  if stat.S_ISLNK(st.st_mode) or st.st_uid!=0 or st.st_mode&0o022:raise RouterRefused('unprotected_router_path')
 st=p.stat()
 if not stat.S_ISREG(st.st_mode) or (secret and st.st_mode&0o077):raise RouterRefused('unprotected_router_file')
 return p

def handoff(target,raw):
 # Exec, not a timed child: this router never kills an in-flight helper.
 # Input is <=4096 bytes; a temporary anonymous file avoids pipe-capacity
 # deadlocks and contains no credentials. Both destinations independently
 # check their work lease, identity, scope lock and runtime before dispatch.
 fd=os.memfd_create('virp-canary-request',os.MFD_CLOEXEC)
 try:
  data=raw.rstrip(b'\r\n')+b'\n'
  if os.write(fd,data)!=len(data):raise RouterRefused('request_handoff_short_write')
  os.lseek(fd,0,os.SEEK_SET);os.dup2(fd,0,inheritable=True)
 finally:
  if fd!=0:os.close(fd)
 env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','SUDO_USER':'virp-cage-test','PYTHONDONTWRITEBYTECODE':'1'}
 os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-B',target],env)

def main():
 if len(sys.argv)!=1 or os.geteuid()!=0 or os.environ.get('SUDO_USER')!='virp-cage-test' or Path('/etc/machine-id').read_text().strip()!=MACHINE:raise RouterRefused('canary_router_identity_mismatch')
 os.umask(0o077);protected(__file__)
 p=json.loads(protected(PROFILE,secret=True).read_bytes(),object_pairs_hook=unique)
 if set(p) not in ({'schema','port_sha256','legacy_sha256'},{'schema','port_sha256','legacy_sha256','open_sha256'}) or p['schema']!='kestrel-port-router/1':raise RouterRefused('invalid_router_profile')
 destinations=[(PORT_SERVICE,'port_sha256'),(LEGACY_SERVICE,'legacy_sha256')]
 if 'open_sha256' in p:destinations.append((OPEN_SERVICE,'open_sha256'))
 for path,key in destinations:
  if not isinstance(p[key],str) or not re.fullmatch('[a-f0-9]{64}',p[key]) or hashlib.sha256(protected(path).read_bytes()).hexdigest()!=p[key]:raise RouterRefused('router_destination_changed')
 raw=sys.stdin.buffer.read(4097);target=select(raw,allow_open='open_sha256' in p);handoff(target,raw)

if __name__=='__main__':
 try:main()
 except Exception as error:
  print(json.dumps({'ok':False,'error':str(error) if isinstance(error,RouterRefused) else type(error).__name__}))
  sys.exit(1)
