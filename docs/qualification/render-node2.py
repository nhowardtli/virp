#!/usr/bin/env python3
"""Render the actual node2 template using synthetic credentials only."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

with tempfile.TemporaryDirectory(prefix='node2-render-') as tmp:
    root = Path(tmp)
    env_file = root / 'fixture.env'
    env_file.write_text('VIRP_UID=999\nWAZUH_USER=fixture-wazuh\nWAZUH_PASS=fixture-only\nLIBRENMS_TOKEN=fixture-only\nPEER_USER=fixture-peer\nPEER_PASS=fixture-only\n')
    env_file.chmod(0o600)
    out = root / 'rendered.json'
    env = dict(os.environ, VIRP_RENDER_ENV_FILE=str(env_file),
               VIRP_RENDER_TEMPLATE='deploy/devices.node2.template.json',
               VIRP_RENDER_OUT=str(out))
    subprocess.run(['bash', 'deploy/render-devices.sh'], env=env, check=True)
    data = json.loads(out.read_text())
    assert [d['hostname'] for d in data['devices']] == ['wazuh-lab', 'librenms-lab', 'virp-lab-peer']
    assert 'list_sessions' in data['socket_uid_action_allow']['999']
    assert 'list_sessions' in data['socket_uid_action_allow']['1000']
    assert data['evidence_required'] is True
    assert set(map(int, data['socket_allowed_uids'])) == {999, 1000}
    print(json.dumps({'check': 'node2_template_render', 'result': 'PASS',
                      'devices': [d['hostname'] for d in data['devices']],
                      'rendered_sha256': hashlib.sha256(out.read_bytes()).hexdigest(),
                      'credentials': 'synthetic; no production values',
                      'limit': 'override path does not exercise root:virp production ownership'}, indent=2))
