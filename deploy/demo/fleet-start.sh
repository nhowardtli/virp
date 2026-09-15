#!/bin/bash
set -euo pipefail
cd /usr/local/lib/virp/demo
python3 -c 'from network import require_demo_vm; require_demo_vm()'
python3 fleet.py
containerlab deploy --reconfigure -t /opt/frr-ospf-lab/frr-ospf.clab.yml
# Pin directly from the freshly provisioned containers; never network TOFU.
python3 - <<'PY'
from pathlib import Path
import subprocess
rows=[]
for i in range(1,5):
    for kind in ('ed25519','rsa','ecdsa'):
        pub=subprocess.check_output(['docker','exec',f'clab-frr-ospf-frr{i}','cat',f'/etc/ssh/ssh_host_{kind}_key.pub'],text=True).split()
        rows.append(f'172.31.219.{10+i} '+ ' '.join(pub[:2]))
Path('/etc/virp/demo-known-hosts').write_text('\n'.join(rows)+'\n')
PY
