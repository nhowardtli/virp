#!/usr/bin/env python3
"""Reset VM219 only, preserving its demo signing and approval keys."""
import argparse
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import re
from network import require_demo_vm

STATE = Path('/var/lib/virp')
PRISTINE = Path('/var/lib/virp-demo-pristine')
MARKER = Path('/run/virp-demo-resetting')


def manifest(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob('*')) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture', action='store_true')
    args = parser.parse_args()
    require_demo_vm()
    with open('/run/virp-demo-reset.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.capture and PRISTINE.exists():
            raise RuntimeError('pristine already exists; refusing overwrite')
        if not args.capture:
            expected = json.loads((PRISTINE / 'manifest.json').read_text())
            if manifest(PRISTINE / 'state') != expected:
                raise RuntimeError('pristine manifest mismatch')
        MARKER.touch(mode=0o644)
        # New demo logins refuse while marker exists. Retire all old REPLs.
        for uid in ('1500', '988'):
            subprocess.run(['pkill', '-KILL', '-u', uid], check=False)
        console = subprocess.run(
            ['systemctl', 'is-active', '--quiet', 'virp-demo-console.service'],
            check=False).returncode == 0
        if console:
            subprocess.run(['systemctl', 'stop', 'virp-demo-console.service'], check=True)
        subprocess.run(['systemctl', 'stop', 'virp-onode'], check=True)
        if args.capture:
            PRISTINE.mkdir(mode=0o700)
            shutil.copytree(STATE, PRISTINE / 'state', copy_function=shutil.copy2)
            # copytree does not preserve owners; record and restore explicitly.
            (PRISTINE / 'manifest.json').write_text(json.dumps(manifest(PRISTINE / 'state'), sort_keys=True))
            print('CAPTURE: quiescent chain, approvals, proposal state, WAL/SHM if present')
        else:
            shutil.rmtree(STATE)
            shutil.copytree(PRISTINE / 'state', STATE, copy_function=shutil.copy2)
            subprocess.run(['chown', '-R', 'virp:virp', str(STATE)], check=True)
            # The console is stopped: retire yesterday's approvals and receipts.
            # Persistent login rate limits and the VM-only key remain intact.
            for suffix in ('', '-wal', '-shm', '-journal'):
                Path('/var/lib/virp-demo-console/console.db' + suffix).unlink(missing_ok=True)
            for path in Path('/var/lib/virp-demo-console').glob('export-*'):
                if re.fullmatch(r'export-[0-9a-f-]{36}', path.name):
                    if path.is_symlink():
                        path.unlink()
                    elif path.is_dir():
                        shutil.rmtree(path)
            print('RESTORE: pristine manifest verified; O-Node and console proposal state reset')
        subprocess.run(['systemctl', 'start', 'virp-onode'], check=True)
        if console:
            subprocess.run(['systemctl', 'start', 'virp-demo-console.service'], check=True)
        # The marker remains on failure, refusing visitors until repaired.
        MARKER.unlink()
        print('PASS: virp-onode started; visitor logins reopened')


if __name__ == '__main__':
    main()
