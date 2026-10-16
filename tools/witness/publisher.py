#!/usr/bin/env python3
"""Bounded signed-head publisher. Never writes the chain or chooses sessions.

The daemon owns signing; this process validates its head before asking the
existing witness client to submit. Receipts are reverified on every invocation.
Transport errors cannot fail a daemon append. No runtime key generation.
"""
import argparse,fcntl,hashlib,json,os,pathlib,re,shutil,sqlite3,subprocess,time
from urllib.parse import urlsplit
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIELDS={'format','enabled','sessions','chain_db','chain_public_key','chain_signing_key','heads','client','witness_url','witness_public_key'}
SAFE=re.compile(r'[A-Za-z0-9_:@+-][A-Za-z0-9._:@+-]{0,127}\Z')

def validate_config(c):
 if not isinstance(c,dict) or set(c)!=FIELDS or c['format']!='virp-kestrel-publisher/1':raise ValueError('invalid configuration schema')
 if type(c['enabled']) is not bool:raise ValueError('enabled must be boolean')
 sessions=c['sessions']
 if not isinstance(sessions,list) or len(sessions)>64 or any(not isinstance(x,str) or not SAFE.fullmatch(x) for x in sessions) or len(set(sessions))!=len(sessions):raise ValueError('invalid session allowlist')
 if c['enabled'] and not sessions:raise ValueError('enabled publisher requires explicit sessions')
 for k in ('chain_db','chain_public_key','chain_signing_key','heads','client','witness_public_key'):
  if not isinstance(c[k],str) or not pathlib.Path(c[k]).is_absolute():raise ValueError('absolute path required: '+k)
 u=urlsplit(c['witness_url'])
 if u.scheme!='http' or u.hostname!='127.0.0.1' or u.username or u.password or u.path not in ('','/') or u.query or u.fragment or not u.port:raise ValueError('submit endpoint must be pinned loopback tunnel')
 return c

def canonical(sid,seq,digest):
 return json.dumps({'last_entry_hash':digest,'last_sequence':seq,'session_id':sid,'v':'VIRP-CHAIN-HEAD-v1'},separators=(',',':')).encode()

def public_key(path):
 b=pathlib.Path(path).read_bytes()
 if len(b)==32:return b
 try:b=bytes.fromhex(b.decode().strip())
 except (UnicodeError,ValueError):raise ValueError('invalid public key') from None
 if len(b)!=32:raise ValueError('expected 32-byte public key')
 return b

def selected_heads(c):
 validate_config(c);pub=public_key(c['chain_public_key']);kid=hashlib.sha256(pub).hexdigest()[:32];key=Ed25519PublicKey.from_public_bytes(pub)
 db=sqlite3.connect(pathlib.Path(c['chain_db']).as_uri()+'?mode=ro',uri=True);db.row_factory=sqlite3.Row
 try:
  db.execute('BEGIN');out=[]
  for sid in c['sessions']:
   rows=db.execute('SELECT session_id,last_sequence,last_entry_hash,head_sig,head_sig_key_id FROM chain_heads WHERE session_id=?',(sid,)).fetchall()
   if len(rows)!=1:raise ValueError('selected session missing or ambiguous: '+sid)
   h=dict(rows[0]);seq=h['last_sequence'];digest=h['last_entry_hash']
   if type(seq)is not int or seq<0 or not isinstance(digest,str) or not re.fullmatch('[0-9a-f]{64}',digest):raise ValueError('invalid head fields')
   if h['head_sig_key_id']!=kid:raise ValueError('head signer differs from pinned node key')
   raw=canonical(sid,seq,digest)
   try:key.verify(bytes.fromhex(h['head_sig']),b'VIRP-CHAIN-HEAD-SIG-v1\0'+raw)
   except Exception:raise ValueError('head signature failed: '+sid) from None
   h.update(canonical=raw,head_hash=hashlib.sha256(raw).hexdigest(),key_id=kid);out.append(h)
  return out
 finally:db.close()

def basename(sid,seq):return hashlib.sha256(sid.encode()).hexdigest()+'-'+str(seq)+'.head'

def durable(path,data):
 path=pathlib.Path(path);tmp=path.with_name(path.name+'.tmp-'+str(os.getpid()))
 with tmp.open('xb') as f:f.write(data);f.flush();os.fsync(f.fileno())
 os.replace(tmp,path);fd=os.open(path.parent,os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)

def invoke(args):
 r=subprocess.run(args,capture_output=True,text=True,timeout=45)
 return {'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}

def check_binding(receipt,h):
 if not isinstance(receipt,dict) or receipt.get('v')!='virp-witness-receipt/1':raise ValueError('invalid receipt schema')
 expected={'chain_id':hashlib.sha256(h['session_id'].encode()).hexdigest(),'sequence':h['last_sequence'],'head_hash':h['head_hash'],'key_id':h['key_id']}
 sub=receipt.get('submission')
 if not isinstance(sub,dict) or any(sub.get(k)!=v for k,v in expected.items()):raise ValueError('receipt does not bind selected head and submitter')

def verify_receipt(c,h,path,receipt):
 try:doc=json.loads(receipt.read_text());check_binding(doc,h)
 except (OSError,ValueError) as e:raise ValueError('receipt unavailable or binding failed: '+str(e)) from None
 r=invoke([c['client'],'verify','--receipt',str(receipt),'--head-file',str(path),'--witness-pubkey',c['witness_public_key'],'--submitter-pubkey',c['chain_public_key'],'--json'])
 try:report=json.loads(r['stdout']);props={x['name']:x['status'] for x in report['properties']}
 except (ValueError,KeyError,TypeError):raise ValueError('receipt verifier produced no valid report') from None
 required=('leaf binding','head binding','witness signature','submitter signature')
 if r['returncode']!=0 or any(props.get(k)!='VERIFIED' for k in required):raise ValueError('receipt verification failed')
 return doc

def run(c,dry_run=False):
 validate_config(c)
 if not c['enabled']:return {'state':'disabled','submitted':0}
 heads=selected_heads(c);public_key(c['witness_public_key'])
 if dry_run:return {'state':'validated','sessions':[h['session_id'] for h in heads],'submitted':0}
 root=pathlib.Path(c['heads']);root.mkdir(mode=0o700,parents=True,exist_ok=True);results=[]
 with (root/'.lock').open('a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  for h in heads:
   path=root/basename(h['session_id'],h['last_sequence']);receipt=path.with_name(path.name+'.witness.json')
   if path.exists() and path.read_bytes()!=h['canonical']:raise ValueError('immutable head file differs')
   if not path.exists():durable(path,h['canonical'])
   try:doc=verify_receipt(c,h,path,receipt);state='already_verified'
   except ValueError:
    if receipt.exists():
     backup=receipt.with_name(receipt.name+'.invalid-'+str(time.time_ns()));durable(backup,receipt.read_bytes())
    r=invoke([c['client'],'submit','--witness',c['witness_url'],'--head-file',str(path),'--key',c['chain_signing_key']])
    if r['returncode']!=0:raise ValueError('witness submission failed; evidence retained')
    doc=verify_receipt(c,h,path,receipt);state='submitted_verified'
   results.append({'session_id':h['session_id'],'sequence':h['last_sequence'],'head_hash':h['head_hash'],'state':state})
   if len(heads)>1:time.sleep(1.2)
 return {'state':'complete','results':results,'submitted':sum(x['state']=='submitted_verified' for x in results)}

def main():
 p=argparse.ArgumentParser();p.add_argument('--config',required=True);p.add_argument('--dry-run',action='store_true');a=p.parse_args();os.umask(0o077)
 try:print(json.dumps(run(json.loads(pathlib.Path(a.config).read_text()),a.dry_run),indent=2))
 except Exception as e:print(json.dumps({'state':'failed','error':str(e)}));return 1
 return 0
if __name__=='__main__':raise SystemExit(main())
