#!/usr/bin/env python3
"""Operator-run .211 staging only. Never restarts or activates anything."""
import argparse, hashlib, json, os, pathlib, pwd, shutil, stat, time
from upgrade_production_helper import upgrade


def main():
    p=argparse.ArgumentParser();p.add_argument('--stage',required=True,type=pathlib.Path);a=p.parse_args()
    if os.geteuid()!=0:raise SystemExit('root required for protected staging')
    os.umask(0o077)
    assert pathlib.Path('/etc/machine-id').read_text().strip()=='294b84478a324262bc7daea9bc314553', 'wrong host'
    exe=pwd.getpwnam('virp-kexec');uid=str(pwd.getpwnam('virp-kreq').pw_uid)
    key=pathlib.Path('/etc/virp-kestrel/chain-sign.key');st=key.lstat()
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode)==0o600 and st.st_uid==exe.pw_uid and st.st_gid==exe.pw_gid and st.st_size==64,'key metadata mismatch'
    pub=pathlib.Path('/etc/virp-kestrel/chain-sign.pub');ps=pub.lstat()
    assert stat.S_ISREG(ps.st_mode) and ps.st_size==32 and not ps.st_mode & 0o022,'public key metadata mismatch'
    # No private key is opened or copied. The daemon validates seed/public consistency.
    helper=pathlib.Path('/usr/local/sbin/virp-cage227-read')
    binary=pathlib.Path('/usr/local/lib/virp-kestrel-v3/virp-onode-prod')
    staged_helper=upgrade(helper.read_bytes(),hashlib.sha256(binary.read_bytes()).hexdigest())
    unit=pathlib.Path('/etc/systemd/system/virp-kestrel-candidate.service');text=unit.read_text()
    lines=[x for x in text.splitlines() if x.startswith('ExecStart=')]
    assert len(lines)==1 and lines[0].startswith('ExecStart=/usr/local/lib/virp/kestrel-onode-candidate '),'unexpected service command'
    assert ' -S ' not in lines[0] and ' -3' not in lines[0], 'already migrated'
    assert 'User=virp-kexec\n' in text and 'Group=virp-kexec\n' in text
    assert not pathlib.Path('/etc/systemd/system/virp-kestrel-candidate.service.d').exists(),'existing overrides need reconciliation'
    newunit=text.replace(lines[0],lines[0].replace('/usr/local/lib/virp/kestrel-onode-candidate',str(binary))+' -3 -S /etc/virp-kestrel/chain-sign.key')
    config=pathlib.Path('/etc/virp-kestrel/devices.json');cfg=json.loads(config.read_text())
    assert cfg.get('gate_default_mode')=='enforce' and cfg.get('evidence_required') is True and cfg['socket_uid_tier_ceilings'][uid]=='green'
    assert len(cfg['devices'])==1 and cfg['devices'][0]['hostname']=='SW-3850' and cfg['devices'][0]['host']=='10.0.10.2','target drift'
    actions=cfg['socket_uid_action_allow'][uid]
    for action in ('execute','session_hello','session_bind','session_close','chain_append','chain_verify'):
        if action not in actions:actions.append(action)
    types=cfg.setdefault('socket_uid_chain_append_types',{}).setdefault(uid,[])
    if 'observation' not in types:types.append('observation')
    lease=pathlib.Path('/var/lib/virp-cage227/policy.json');policy=json.loads(lease.read_text())
    policy['v3_chain_session']='kestrel-v3-'+time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
    a.stage.mkdir(mode=0o700);(a.stage/'before').mkdir(mode=0o700);(a.stage/'after').mkdir(mode=0o700)
    for path in (helper,unit,config,lease):shutil.copy2(path,a.stage/'before'/path.name)
    (a.stage/'after'/helper.name).write_text(staged_helper)
    (a.stage/'after'/unit.name).write_text(newunit)
    (a.stage/'after'/config.name).write_text(json.dumps(cfg,indent=2)+'\n')
    (a.stage/'after'/lease.name).write_text(json.dumps(policy,indent=2)+'\n')
    (a.stage/'metadata.json').write_text(json.dumps({'chain_session':policy['v3_chain_session'],'binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'requester_uid':int(uid)},indent=2))
    print('Staged only. Existing grants, lease deadlines, STOP file and chain untouched.')

if __name__=='__main__':main()
