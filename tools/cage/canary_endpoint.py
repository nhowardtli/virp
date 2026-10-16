#!/usr/bin/python3 -I
"""Disposable canary endpoint; NOT a replacement for production grant policy."""
import fcntl, hashlib, json, os, pathlib, re, signal, sys, time
sys.path.insert(0, '/opt/virp-canary/cage')
from helper import Socket, durable_write, execute_observed
ROOT = pathlib.Path('/var/lib/virp-canary-cage')
OPS = {'canary_green': 'show version', 'canary_red': 'configure terminal'}

def main():
    os.umask(0o077); signal.alarm(60)
    if os.geteuid() != 0 or os.environ.get('SUDO_USER') != 'virp-cage-test':
        raise ValueError('identity_denied')
    line = sys.stdin.buffer.readline(8193)
    if len(line) > 8192 or not line.endswith(b'\n'):
        raise ValueError('request_size')
    q = json.loads(line)
    if set(q) != {'operation', 'request_id', 'rationale'} or q['operation'] not in OPS:
        raise ValueError('operation_denied')
    if not re.fullmatch('[a-f0-9]{32}', q['request_id']) or not 20 <= len(q['rationale']) <= 1000:
        raise ValueError('request_invalid')
    with open(ROOT/'lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cfg = json.loads((ROOT/'policy.json').read_text())
        if time.time() >= cfg['expires'] or (ROOT/'STOP').exists() or cfg['boot_id'] != pathlib.Path('/proc/sys/kernel/random/boot_id').read_text():
            raise ValueError('lease_inactive')
        if len(list((ROOT/'records').glob('*.request.json'))) >= 8:
            raise ValueError('attempt_limit')
        if hashlib.sha256(pathlib.Path('/opt/virp-canary/bin/virp-onode-prod').read_bytes()).hexdigest() != cfg['binary_sha256']:
            raise ValueError('binary_changed')
        p = json.loads(pathlib.Path('/etc/virp-canary/devices.json').read_text())
        if p.get('gate_default_mode') != 'enforce' or p.get('evidence_required') is not True or p['socket_uid_tier_ceilings'].get('0') != 'green':
            raise ValueError('gate_policy_changed')
        targets = [d for d in p['devices'] if d['hostname'] == 'canary-frr1']
        if len(targets) != 1 or targets[0]['host'] != '172.31.250.2':
            raise ValueError('target_changed')
        prefix = ROOT/'records'/q['request_id']
        durable_write(prefix.with_suffix('.request.json'), json.dumps(q).encode())
        transport = Socket('/run/virp-canary/onode.sock')
        command = OPS[q['operation']]
        raw, result = execute_observed(transport, dict(action='execute', device='canary-frr1', command=command),
                        public_key=pathlib.Path('/etc/virp-canary/chain-sign.pub').read_bytes(),
                        node_id=256, device_id=int.from_bytes(hashlib.sha256(b'canary-frr1').digest()[:8], 'big'),
                        path=prefix.with_suffix('.frame'), chain_session=cfg['chain_session'], artifact_id='cage:'+q['request_id'])
        result.update(ok=True, operation=q['operation'], request_id=q['request_id'])
        durable_write(prefix.with_suffix('.result.json'), json.dumps(result).encode())
        print(json.dumps(result))

if __name__ == '__main__':
    try: main()
    except Exception as e:
        print(json.dumps({'ok': False, 'error': str(e) if isinstance(e, ValueError) else type(e).__name__})); sys.exit(1)
