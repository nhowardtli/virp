#!/usr/bin/env python3
"""Operator-run local chain verification. No execute/device requests."""
import argparse, json, pathlib, sqlite3, subprocess
from helper import Socket

p=argparse.ArgumentParser();p.add_argument('--db',required=True);p.add_argument('--socket',required=True);p.add_argument('--requester');a=p.parse_args()
class Requester(Socket):
 def raw(self,req):
  if not a.requester:return super().raw(req)
  # Only this fixed read-only management operation is relayed to the requester.
  assert req['action']=='chain_verify'
  code='import sys,json;sys.path.insert(0,sys.argv[1]);from helper import Socket;sys.stdout.buffer.write(Socket(sys.argv[2]).raw(json.loads(sys.argv[3])))'
  return subprocess.check_output(['/usr/sbin/runuser','-u',a.requester,'--','/usr/bin/python3','-I','-c',code,str(pathlib.Path(__file__).resolve().parent),a.socket,json.dumps(req)],timeout=60)
c=sqlite3.connect('file:'+str(pathlib.Path(a.db).resolve())+'?mode=ro',uri=True)
checks=[]
for sid,high,count in c.execute('SELECT session_id,MAX(sequence),COUNT(*) FROM chain_entries GROUP BY session_id'):
 r=Requester(a.socket).management(dict(action='chain_verify',session_id=sid,from_sequence=0,to_sequence=high))
 assert r['valid'] is True and r['entries_checked']==count==high+1 and r['executions_open']==0,(sid,r)
 checks.append(dict(session_id=sid,**r))
assert checks,'empty chain is not a qualification'
print(json.dumps(checks,indent=2))
