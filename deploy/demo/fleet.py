#!/usr/bin/env python3
"""Prepare the owner-supplied offline FRR ring, exclusively on enrolled VM219."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import yaml
from network import require_demo_vm

require_demo_vm()
root = Path('/opt/frr-ospf-lab')
subprocess.run(['docker', 'image', 'inspect', 'frr-ssh:10.2.1'], check=True, stdout=subprocess.DEVNULL)
Path('/etc/virp').mkdir(exist_ok=True)
env = Path('/etc/virp/autopilot.env')
if not env.exists():
    fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write('VIRP_DEMO_FRR_PASSWORD=' + secrets.token_hex(24) + '\n')
values = dict(line.split('=', 1) for line in env.read_text().splitlines() if '=' in line)
secret = Path('/etc/virp-demo/frr-password')
fd = os.open(secret, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write(values['VIRP_DEMO_FRR_PASSWORD'] + '\n')
source = Path(__file__).resolve().parent
subprocess.run(['install', '-m', '0700', str(source / 'frr-init.sh'), str(root / 'demo-init.sh')], check=True)
p = root / 'frr-ospf.clab.yml'
topo = yaml.safe_load(p.read_text())
topo['mgmt'] = {'network': 'virp-demo', 'bridge': 'br-demo', 'ipv4-subnet': '172.31.219.0/24', 'ipv4-gw': '172.31.219.1', 'external-access': False, 'driver-opts': {'com.docker.network.bridge.enable_ip_masquerade': 'false'}}
defaults = topo['topology']['defaults']
defaults['image-pull-policy'] = 'Never'
defaults['exec'] = ['/bin/sh /demo-init.sh']
for i in range(1, 5):
    node = topo['topology']['nodes']['frr' + str(i)]
    node['mgmt-ipv4'] = '172.31.219.' + str(10 + i)
    node['binds'] = [v for v in node['binds'] if '/demo-init.sh' not in v and '/run/demo-password' not in v]
    node['binds'] += [str(root / 'demo-init.sh') + ':/demo-init.sh:ro', str(secret) + ':/run/demo-password:ro']
p.write_text(yaml.safe_dump(topo, sort_keys=False))
# The supplied image is loaded, not rebuilt. Document a safe future recipe.
(root / 'Dockerfile').write_text('FROM frr-ssh:10.2.1\n# Runtime demo-init.sh renders ${VIRP_DEMO_FRR_PASSWORD} from the VM-only secret.\n# No password in build arguments or image layers.\n')
print('Prepared four FRR nodes; password omitted from output; image pull policy Never')
