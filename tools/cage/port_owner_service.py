#!/usr/bin/python3 -I
"""Root-only, one-request owner control-plane entrypoint; no listening service.

Install beside its modules in a root-owned directory. The transport/forced
command must authenticate the executor separately; being a JSON client confers
no access. Nothing here is to be installed in the cage or exposed as its RPC.
"""
import argparse
import configparser
import json
import os
from pathlib import Path
import stat
import sys

class ServiceRefused(ValueError):pass

def protected(path,*,secret=False,directory=False):
 p=Path(path)
 if not p.is_absolute() or p.is_symlink():raise ServiceRefused('unprotected_path')
 p=p.resolve(strict=True)
 for candidate in (p,*p.parents):
  info=candidate.stat()
  if info.st_uid!=0 or info.st_mode&0o022:raise ServiceRefused('unprotected_path')
 info=p.stat()
 if directory and not stat.S_ISDIR(info.st_mode):raise ServiceRefused('expected_directory')
 if not directory and not stat.S_ISREG(info.st_mode):raise ServiceRefused('expected_regular_file')
 if secret and info.st_mode&0o077:raise ServiceRefused('secret_permissions_too_broad')
 return p

def dispatch(q,store,duo_factory,allowed_devices):
 fields={
  'prepare':{'action','transaction_id','body','lease_seconds','executor_boot_id'},
  'authorize':{'action','transaction_id'},
  'sign_envelope':{'action','transaction_id','envelope'},
  'sign_native':{'action','transaction_id','event','entry','challenge'},
  'close':{'action','transaction_id','event','entry'},
  'status':{'action','transaction_id'},
 }
 if not isinstance(q,dict) or q.get('action') not in fields or set(q)!=fields[q['action']]:raise ServiceRefused('invalid_action_or_fields')
 action=q['action'];tid=q['transaction_id']
 if action=='prepare':
  if q['body'].get('target',{}).get('device') not in allowed_devices:raise ServiceRefused('target_not_provisioned')
  store.prepare(tid,q['body'],lease_seconds=q['lease_seconds'],executor_boot_id=q['executor_boot_id'])
  return {'ok':True,'transaction_id':tid,'state':'prepared'}
 if action=='authorize':return {'ok':True,'transaction_id':tid,**store.authorize(tid,duo_factory())}
 if action=='sign_envelope':signature=store.sign_envelope(tid,q['envelope'])
 elif action=='sign_native':signature=store.sign_native(tid,q['event'],q['entry'],q['challenge'])
 elif action=='close':
  store.accept_close(tid,q['event'],q['entry']);return {'ok':True,'transaction_id':tid,'state':'closed'}
 else:
  row=store.db.execute('SELECT state,hash FROM owner_requests WHERE id=?',(tid,)).fetchone()
  if row is None:raise ServiceRefused('unknown_transaction')
  return {'ok':True,'transaction_id':tid,'state':row['state'],'plan_sha256':row['hash']}
 return {'ok':True,'transaction_id':tid,'signature':signature.hex()}

def main():
 if os.geteuid()!=0:raise ServiceRefused('owner_control_plane_requires_root')
 os.umask(0o077)
 protected(__file__)
 module_dir=Path(__file__).resolve().parent
 for name in ('port_owner.py','port_duo.py','port_transaction.py','port_plan.py','port_challenge.py','port_evidence.py','recovery.py','helper.py'):
  protected(module_dir/name)
 sys.path.insert(0,str(Path(__file__).resolve().parent))
 from port_owner import OwnerRequests
 from port_duo import DuoAuth
 from cryptography.hazmat.primitives.serialization import load_pem_private_key,Encoding,PublicFormat
 from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--profile',required=True)
 args=parser.parse_args();profile=json.loads(protected(args.profile,secret=True).read_text())
 expected={'schema','machine_id','database','private_key','public_key_hex','duo_config','duo_section','max_lease_seconds','producers'}
 if set(profile)!=expected or profile['schema']!='kestrel-port-owner/1':raise ServiceRefused('invalid_owner_profile')
 if Path('/etc/machine-id').read_text().strip()!=profile['machine_id']:raise ServiceRefused('owner_host_mismatch')
 maximum=profile['max_lease_seconds']
 if type(maximum)is not int or not 1<=maximum<=36000:raise ServiceRefused('invalid_maximum_lease')
 db=Path(profile['database']);protected(db.parent,secret=True,directory=True)
 if db.exists() or db.is_symlink():protected(db,secret=True)
 key=load_pem_private_key(protected(profile['private_key'],secret=True).read_bytes(),password=None)
 if not isinstance(key,Ed25519PrivateKey):raise ServiceRefused('owner_key_not_ed25519')
 pub=bytes.fromhex(profile['public_key_hex'])
 if pub!=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw):raise ServiceRefused('owner_key_pin_mismatch')
 producers={}
 for device,p in profile['producers'].items():
  if device not in ('SW-3850','kestrel-ios') or set(p)!={'public_key_hex','node_id','chain_session'}:raise ServiceRefused('invalid_producer_profile')
  public=bytes.fromhex(p['public_key_hex'])
  if len(public)!=32 or type(p['node_id'])is not int or p['node_id']<=0:raise ServiceRefused('invalid_producer_pin')
  producers[device]={'public_key':public,'node_id':p['node_id'],'chain_session':p['chain_session']}
 if not producers:raise ServiceRefused('missing_producer_profiles')
 def duo():
  cfg=configparser.ConfigParser(interpolation=None);cfg.read(protected(profile['duo_config'],secret=True))
  c=cfg[profile['duo_section']];return DuoAuth(c['api_host'],c['ikey'],c['skey'])
 raw=sys.stdin.buffer.read(131073)
 if len(raw)>131072:raise ServiceRefused('owner_request_too_large')
 q=json.loads(raw)
 store=OwnerRequests(str(db),pub,key.sign,owner='nhoward-admin',boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),max_lease_seconds=maximum,producers=producers)
 try:print(json.dumps(dispatch(q,store,duo,set(producers))))
 finally:store.close()

if __name__=='__main__':
 try:main()
 except Exception as error:
  # Do not echo config-parser errors, paths, request data or credential values.
  print(json.dumps({'ok':False,'error':str(error) if isinstance(error,ServiceRefused) or (type(error).__module__=='port_transaction' and type(error).__name__=='Refused') else type(error).__name__}))
  sys.exit(1)
