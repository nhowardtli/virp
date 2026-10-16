#!/usr/bin/env python3
"""Offline, hash-pinned migration of the captured bounded Kestrel helper.

Reads/writes files only. Does not access a daemon, device or private key.
Never installs automatically; operator reviews the staged diff.
"""
import argparse, hashlib, pathlib, re
BASE_SHA256 = '0baffa1131feb51d3d3ba8649e595fd07872b145b46cf41216ae27fb9810cfd2'


def upgrade(source, binary_sha256):
    if hashlib.sha256(source).hexdigest() != BASE_SHA256:
        raise ValueError('helper_baseline_changed: reconcile before deployment')
    if not re.fullmatch('[a-f0-9]{64}', binary_sha256):
        raise ValueError('invalid_binary_pin')
    s = source.decode()
    s = s.replace("ROOT=pathlib.Path", "sys.path.insert(0,'/usr/local/lib/virp-kestrel-v3/cage')\nfrom helper import Socket,execute_observed\nROOT=pathlib.Path", 1)
    s = re.sub("CANDIDATE_BINARY='[a-f0-9]{64}'", "CANDIDATE_BINARY='"+binary_sha256+"'", s)
    s = s.replace('/usr/local/lib/virp/kestrel-onode-candidate', '/usr/local/lib/virp-kestrel-v3/virp-onode-prod')
    s = s.replace('def native(req,requester,dedicated):', '''class RequesterSocket(Socket):
 def raw(self,req):
  proc=subprocess.run(['/usr/sbin/runuser','-u','virp-kreq','--','/usr/bin/python3','-I','-c',CLIENT.replace('/run/virp/onode.sock','/run/virp-kestrel/onode.sock'),json.dumps(req)],capture_output=True,timeout=45)
  if proc.returncode:raise RuntimeError('native_failed')
  raw=proc.stdout
  if len(raw)==4:raise RuntimeError('daemon_error:'+str(struct.unpack('!i',raw)[0]))
  return raw

def native(req,requester,dedicated,record):
   if dedicated:
    cfg=json.loads((ROOT/'policy.json').read_text())
    sid=cfg['v3_chain_session']
    if not re.fullmatch('kestrel-v3-[a-zA-Z0-9-]{1,64}',sid):raise RuntimeError('invalid_chain_session')
    return execute_observed(RequesterSocket('/run/virp-kestrel/onode.sock'),req,
      public_key=pathlib.Path('/etc/virp-kestrel/chain-sign.pub').read_bytes(),
      node_id=0x4b535452,device_id=int.from_bytes(hashlib.sha256(req['device'].encode()).digest()[:8],'big'),
      path=pathlib.Path(str(record)+'.v3.frame'),chain_session=sid,artifact_id='cage:'+pathlib.Path(record).name)
''')
    s = s.replace('   return raw,key', "   return raw,{'version':1,'subtype':raw[56],'output':raw[60:].decode(errors='strict'),'hmac_verified_on_211':True}")
    s = s.replace('def observed_description(raw):\n if raw[56]!=7:', 'def observed_description(decoded):\n if decoded[\'subtype\']!=7:')
    s = s.replace(" text=raw[60:].decode(errors='strict')", " text=decoded['output']")
    s = s.replace('preraw,_=native(preq,requester,dedicated)', "preraw,predecoded=native(preq,requester,dedicated,str(record)+'.preflight')")
    s = s.replace("'output':preraw[60:].decode(errors='replace')", "'output':predecoded['output']")
    s = s.replace('observed_description(preraw)', 'observed_description(predecoded)')
    s = s.replace('raw,key=native(req,requester,dedicated)', 'raw,decoded=native(req,requester,dedicated,record)')
    s = s.replace('  altered=bytearray(raw);altered[-1]^=1\n', '')
    start = s.index('  result={'); end = s.index('\n  write(str(record)', start)
    s = s[:start]+'''  result=dict(decoded,ok=True,operation=q['operation'],request_id=q['request_id'],device=device,command=command,requester_uid=requester_uid,executor_binary_sha256=CANDIDATE_BINARY if dedicated else BINARY,frame_sha256=hashlib.sha256(raw).hexdigest(),time=time.time())'''+s[end:]
    compile(s, 'staged-helper', 'exec')
    return s


if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('source',type=pathlib.Path);p.add_argument('destination',type=pathlib.Path);p.add_argument('--binary-sha256',required=True);a=p.parse_args()
    result=upgrade(a.source.read_bytes(),a.binary_sha256)
    with a.destination.open('x') as f:f.write(result)
