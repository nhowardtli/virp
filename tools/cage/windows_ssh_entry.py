#!/usr/bin/python3 -I
import os,subprocess,sys
c=os.environ.get('SSH_ORIGINAL_COMMAND','')
if c=='uptime':sys.exit(subprocess.call(['/usr/bin/uptime'],env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'}))
if c not in ('qm status 233','qm create 233'):sys.exit(1)
sys.exit(subprocess.call(['/usr/bin/sudo','-n','/usr/bin/python3','-I','/usr/local/lib/kestrel-windows/windows_pve.py',c]))
