#!/usr/bin/python3 -I
"""Owner-facing cage control: revoke/status only; cannot mint reboot grants."""
import json,subprocess,sys
sys.path.insert(0,'/opt/virp-vm-cage')
from twoport_transport import argv
if len(sys.argv)!=2 or sys.argv[1] not in ('status','stop'):sys.exit(2)
r=subprocess.run(argv(),input=json.dumps({'operation':'vm_control','action':sys.argv[1]})+'\n',text=True,capture_output=True,timeout=15)
print(r.stdout,end='');sys.exit(r.returncode)
