#!/usr/bin/python3 -I
"""Fixed production forced-command router; owner stop remains usable without lease."""
import fcntl,os,sys,json,subprocess
from pathlib import Path
if os.geteuid()!=0 or os.environ.get('SUDO_USER')!='virp-cage227':sys.exit(1)
raw=sys.stdin.buffer.readline(8193)
if len(raw)>8192 or not raw.endswith(b'\n'):sys.exit(1)
try:q=json.loads(raw)
except Exception:sys.exit(1)
if not isinstance(q,dict):sys.exit(1)
if q.get('operation')=='status':
 root=Path('/var/lib/virp-kestrel-twoport');old=Path('/var/lib/virp-cage227')
 busy=False
 with open(root/'lock','r') as lock:
  try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);fcntl.flock(lock,fcntl.LOCK_UN)
  except BlockingIOError:busy=True
 stopped=any(os.path.lexists(x/'STOP') for x in (root,old))
 pending=any(os.path.lexists(x/'v3-recovery/pending.json') for x in (root,old))
 print(json.dumps({'ok':not stopped and (busy or not pending),'state':'stopped' if stopped else 'executing' if busy else 'reconciliation-required' if pending else 'ready','in_flight':busy,'authority':'standing-owner-delegation','expiry':None,'device':'SW-3850','ports':['GigabitEthernet1/0/22','GigabitEthernet1/0/23'],'stopped':stopped,'pending':pending,'write_ready':(root/'write-ready.json').exists(),'requests':len(list((root/'records').glob('*.request.json'))),'limit':512,'status_evidence':'helper control state; not a signed device observation'}));sys.exit(0)
if q.get('operation')=='stop':
 sys.path.insert(0,'/usr/local/lib/virp-kestrel-twoport')
 from helper import durable_write
 p=Path('/var/lib/virp-kestrel-twoport/STOP')
 if not os.path.lexists(p):durable_write(p,b'{"reason":"owner_requested_stop"}')
 print(json.dumps({'ok':True,'state':'stopped','scope':'twoport'}));sys.exit(0)
path='/usr/local/lib/virp-kestrel-twoport/twoport_helper.py' if q.get('operation')=='port_open_execute' else '/usr/local/lib/virp-kestrel-twoport/legacy-helper'
p=subprocess.run(['/usr/bin/python3','-I',path],input=raw)
sys.exit(p.returncode)
