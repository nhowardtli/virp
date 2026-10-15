#!/usr/bin/python3 -I
"""Root-only owner control-plane entry point on AAA CT224; never cage-facing."""
import base64,configparser,hashlib,json,os,pathlib,subprocess,sys,tempfile
sys.path.insert(0,'/usr/local/lib/kestrel-approval')
from approval_plan import Plans,Refused
from duo_auth import DuoAuth
ROOT=pathlib.Path('/var/lib/kestrel-approval')

def main():
 if os.geteuid()!=0:raise Refused('owner_control_plane_only')
 os.umask(0o077)
 raw=sys.stdin.buffer.read(65537)
 if len(raw)>65536:raise Refused('request_oversized')
 q=json.loads(raw);action=q.get('action')
 s=Plans(str(ROOT/'plans.db'))
 try:
  if action=='create':
   if set(q)!={'action','before','after','forward','restore','lease_expires_ns'}:raise Refused('invalid_fields')
   if q['before']!='' or q['after']!='KESTREL-QUAL-20261015':raise Refused('test_scope_only')
   for name in ['forward','restore']:
    if q[name].get('device_node_id')!=0x0A000A02:raise Refused('device_node_pin_mismatch')
   pid=s.create(q['before'],q['after'],q['forward'],q['restore'],q['lease_expires_ns'])
   print(json.dumps({'plan_id':pid,'state':'prepared'}));return
  if action not in ('authorize','sign','verified'):raise Refused('unknown_action')
  pid=q['plan_id']
  if action=='authorize':
   if set(q)!={'action','plan_id'}:raise Refused('invalid_fields')
   cfg=configparser.ConfigParser();cfg.read('/opt/duoauthproxy/conf/authproxy.cfg');c=cfg['radius_server_auto']
   hashed=s.authorize(pid,DuoAuth(c['api_host'],c['ikey'],c['skey']))
   print(json.dumps({'plan_id':pid,'plan_hash':hashed,'state':'approved'}));return
  if action=='sign':
   if set(q)!={'action','plan_id','phase','observed_description'}:raise Refused('invalid_fields')
   def sign(raw):
    with tempfile.NamedTemporaryFile(dir=ROOT) as f:
     f.write(raw);f.flush();os.fsync(f.fileno())
     r=subprocess.run(['/usr/bin/openssl','pkeyutl','-sign','-rawin','-inkey','/etc/kestrel-approval/signing.pem','-in',f.name],capture_output=True,check=True)
    if len(r.stdout)!=64:raise Refused('invalid_signature_length')
    return r.stdout.hex()
   signature=s.sign_once(pid,q['phase'],q['observed_description'],sign)
   print(json.dumps({'plan_id':pid,'phase':q['phase'],'signature':signature}));return
  if set(q)!={'action','plan_id','phase','observed_description','evidence_hash'}:raise Refused('invalid_fields')
  s.verified(pid,q['phase'],q['observed_description'],q['evidence_hash'])
  print(json.dumps({'plan_id':pid,'phase':q['phase'],'verified':True}))
 finally:s.db.close()
if __name__=='__main__':
 try:main()
 except Exception as e:
  print(json.dumps({'ok':False,'error':str(e) if isinstance(e,Refused) else type(e).__name__}));sys.exit(1)
