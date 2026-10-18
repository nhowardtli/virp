#!/usr/bin/python3 -I
"""Owner-only status/revocation transport. No model invocation or device command."""
import os,sys,json,subprocess,uuid
from pathlib import Path
if os.geteuid()!=0 or Path('/etc/machine-id').read_text().strip()!='5f20c5fdcf174e398af109874389db81' or len(sys.argv)!=2 or sys.argv[1] not in ('status','stop'):sys.exit(1)
sys.path.insert(0,str(Path(__file__).absolute().parent))
from twoport_transport import argv,KEY,KNOWN_HOSTS
from port_owner_service import protected
protected(__file__);protected(KEY,secret=True);protected(KNOWN_HOSTS)
q={'operation':sys.argv[1],'request_id':uuid.uuid4().hex,'rationale':'Owner requests the standing two-port scope state or immediate revocation.'}
r=subprocess.run(argv(),input=json.dumps(q)+'\n',text=True,capture_output=True,timeout=15)
if r.returncode:print(json.dumps({'ok':False,'error':'control_transport_failed'}));sys.exit(1)
j=json.loads(r.stdout);print(json.dumps(j,indent=2))
