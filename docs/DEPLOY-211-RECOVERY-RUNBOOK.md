# Keyboard runbook: dedicated Kestrel UNKNOWN recovery update

Prepared October16; **not executed on .211**. Canary phase12 passed. This updates
only `virp-kestrel-candidate`, its helper and endpoint. It supersedes the initial
installation runbook for this upgrade. Do not run bare `make install-prod`: that
target installs the main instance, outside this change's scope.

Qualified source: `6b11bdc2a767adab2310cb2f034f5a3b89d6b67c` on
`feat/v3-execute-path`, including C UNKNOWN fix90558ec and recovery98e0cc8.
The installed canary C binary is90558ec; subsequent changes are Python/docs only.
Build from the pinned source and record the resulting binary hash; a rebuild's
version string/hash need not equal the earlier canary artifact.

## 1. Snapshot and stage

At the pve1 keyboard, confirm VM211 is the intended production node, then:

```sh
sudo -n qm config 211
sudo -n qm snapshot 211 before-phase12-recovery --description 'Before dedicated Kestrel recovery update'
sudo -n qm listsnapshot 211
```

Stop if snapshot creation fails. Retain independent console recovery. Copy the
pinned checkout to `/home/nhoward/virp-phase12-source` on .211 using the existing
pinned management channel. Do not copy canary configs, credentials, profiles,
chains or test approver keys. On .211:

```sh
cd /home/nhoward/virp-phase12-source
 test "$(git rev-parse HEAD)" = 6b11bdc2a767adab2310cb2f034f5a3b89d6b67c
 test -z "$(git status --porcelain)"
make CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 WAZUH=1 JUNIPER=1 LIBRENMS=1 PBS=1 ZAMMAD=1 all-tests
sha256sum build/virp-onode-prod tools/cage/helper.py tools/cage/recovery.py
```

Run each step only after its preceding command succeeds. No Rust toolchain change.

## 2. Provisioned key contract

Existing private key: `/etc/virp-kestrel/chain-sign.key`, owner/group
`virp-kexec:virp-kexec`,0600, regular non-symlink file, exactly64 raw bytes:
libsodium Ed25519 seed32 followed by matching public32. Public counterpart:
`/etc/virp-kestrel/chain-sign.pub`, root:root0644, exactly32 raw bytes. Parent:
root:virp-kexec0750. The daemon validates the seed/public pairing. Preserve the
existing service key path and audit epoch. Do not print, regenerate, enroll,
commit or stage the private key. Confirm metadata with `stat`, not `cat`.

## 3. Guarded installation

This procedure fails on a pre-existing STOP, pending marker, active description
grant, expired lease, changed machine/baseline, or changed root/requester policy.
**Do not clear these guards to make an installation pass.** Record the precise
condition and arrange its separate disposition. A root-only recovery permission
is proposed here, not granted to Kestrel: root may append evidence_item only;
UID980 remains observation-only. No root execute/chain_verify permission.

The following Python is run as root on .211 from the staged checkout. It holds
the existing cage lock, creates its own STOP and leaves that STOP in place after
installation. It does not contact any switch. A failure after STOP creation
leaves containment in place; use the rollback section instead of rerunning.

```sh
sudo -n python3 - <<'PY'
import ast,fcntl,hashlib,json,os,pathlib,pwd,shutil,sqlite3,subprocess,time
P=pathlib.Path;os.umask(0o077)
r=P('/var/lib/virp-cage227');b=P('/root/phase12-recovery-deploy')
src=P('/home/nhoward/virp-phase12-source');binary=P('/usr/local/lib/virp-kestrel-v3/virp-onode-prod')
helper=binary.parent/'cage/helper.py';recovery=binary.parent/'cage/recovery.py'
endpoint=P('/usr/local/sbin/virp-cage227-read');cfgpath=P('/etc/virp-kestrel/devices.json')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert P('/etc/machine-id').read_text().strip()=='294b84478a324262bc7daea9bc314553'
assert subprocess.check_output(['git','-C',str(src),'rev-parse','HEAD'],text=True).strip()=='6b11bdc2a767adab2310cb2f034f5a3b89d6b67c'
assert not subprocess.check_output(['git','-C',str(src),'status','--porcelain'])
assert pwd.getpwnam('virp-kreq').pw_uid==980
assert sha(binary)=='18b87ac7c381b1ae2569a9c76230d05cba1cd596f004f2403bc8f0f229f7d2d2'
assert sha(helper)=='fff8bc6baec3edb5e5c4c5981043e876b2e934ac1069692614813c912afc83ee'
assert sha(endpoint)=='79a043fe73f14881c94a034fad263a46f8de90d78b8edc0b713dcff2661d0007'
main=P('/usr/local/lib/virp/virp-onode-prod');mainsha=sha(main)
assert mainsha=='8a11330b2a398ebc934c2b05717b889e5211b69ea8e2a6629460bf8d061ec38c'
assert not recovery.exists()
with (r/'lock').open('a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 policy=(r/'policy.json').read_bytes();lease=json.loads(policy)
 assert time.time()<lease['expires'] and time.clock_gettime(time.CLOCK_BOOTTIME)<lease['expires_boot']
 assert P('/proc/sys/kernel/random/boot_id').read_text()==lease['boot_id']
 assert not any((r/n).exists() for n in ['STOP','v3-recovery/pending.json','description-grant.json'])
 cfg=json.loads(cfgpath.read_text());actions=cfg['socket_uid_action_allow'];types=cfg['socket_uid_chain_append_types']
 assert actions['0']==[],'Root baseline differs; inspect instead of expanding it'
 assert types['980']==['observation']
 assert cfg['gate_default_mode']=='enforce' and cfg['evidence_required'] is True
 assert cfg['socket_uid_tier_ceilings']['980']=='green'
 actions['0']=['chain_append'];types['0']=['evidence_item']
 newsha=sha(src/'build/virp-onode-prod');old=endpoint.read_text()
 needle="CANDIDATE_BINARY='18b87ac7c381b1ae2569a9c76230d05cba1cd596f004f2403bc8f0f229f7d2d2'"
 assert old.count(needle)==1
 new=old.replace(needle,"CANDIDATE_BINARY='"+newsha+"'")
 assert 'from helper import Socket,execute_observed' in new
 new=new.replace('from helper import Socket,execute_observed','from helper import Socket,execute_observed,public_error',1)
 needle='str(e) if isinstance(e,RuntimeError) else type(e).__name__'
 assert new.count(needle)==1
 new=new.replace(needle,'str(e) if isinstance(e,RuntimeError) else public_error(e)')
 def ops(s):return next(ast.literal_eval(n.value) for n in ast.parse(s).body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='OPS' for t in n.targets))
 assert ops(old)==ops(new);compile(new,str(endpoint),'exec')
 b.mkdir(mode=0o700)
 for p,n in [(binary,'binary.before'),(helper,'helper.before'),(endpoint,'endpoint.before'),(cfgpath,'devices.before.json')]:shutil.copy2(p,b/n)
 (b/'policy.before.json').write_bytes(policy)
 with (r/'STOP').open('x') as f:f.write('phase12 deployment; retain until separate resume\n');f.flush();os.fsync(f.fileno())
 subprocess.run(['systemctl','stop','virp-kestrel-candidate'],check=True)
 s=sqlite3.connect('file:/var/lib/virp-kestrel/chain.db?mode=ro',uri=True);d=sqlite3.connect(b/'chain.before.db');s.backup(d)
 assert d.execute('PRAGMA integrity_check').fetchone()[0]=='ok';d.close();s.close()
 def install(raw,path,mode):
  tmp=path.with_name(path.name+'.phase12-new')
  with tmp.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
  os.chmod(tmp,mode);os.chown(tmp,0,0);os.replace(tmp,path)
  fd=os.open(str(path.parent),os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 install((src/'build/virp-onode-prod').read_bytes(),binary,0o755)
 install((src/'tools/cage/helper.py').read_bytes(),helper,0o644)
 install((src/'tools/cage/recovery.py').read_bytes(),recovery,0o700)
 install(new.encode(),endpoint,endpoint.stat().st_mode & 0o777)
 # Preserve config ownership/mode: service must retain its existing read access.
 cfgpath.write_text(json.dumps(cfg));fd=os.open(str(cfgpath),os.O_RDONLY);os.fsync(fd);os.close(fd)
 subprocess.run(['systemctl','start','virp-kestrel-candidate'],check=True)
 assert sha(main)==mainsha and (r/'policy.json').read_bytes()==policy
 (b/'installed.json').write_text(json.dumps({'source':'6b11bdc','binary':sha(binary),'helper':sha(helper),'recovery':sha(recovery),'endpoint':sha(endpoint),'STOP_retained':True},indent=2))
 print('Installed; STOP retained. Run chain verification next.')
PY
```

The root action baseline assertion is deliberately strict: current .211 policy
was not read during canary work. A mismatch is a contract gap to inspect, not a
reason to remove the assertion or grant root general access. This deployment
script has been syntax-checked, not executed or qualified on production.

## 4. Restart/status and chain verification

```sh
sudo -n systemctl status virp-kestrel-candidate --no-pager
sudo -n python3 - <<'PY'
import json,pathlib,sqlite3,subprocess
code="import sys,json;sys.path.insert(0,'/usr/local/lib/virp-kestrel-v3/cage');from helper import Socket;print(json.dumps(Socket('/run/virp-kestrel/onode.sock').management(json.loads(sys.argv[1]))))"
db=sqlite3.connect('file:/var/lib/virp-kestrel/chain.db?mode=ro',uri=True);checks=[]
for sid,hi,n in db.execute('SELECT session_id,MAX(sequence),COUNT(*) FROM chain_entries GROUP BY session_id'):
 q={'action':'chain_verify','session_id':sid,'from_sequence':0,'to_sequence':hi}
 v=json.loads(subprocess.check_output(['runuser','-u','virp-kreq','--','python3','-I','-c',code,json.dumps(q)],text=True))
 assert v['valid'] and v['executions_open']==0 and v['entries_checked']==n
 checks.append({'session_id':sid,**v})
pathlib.Path('/root/phase12-recovery-deploy/chain-verify.json').write_text(json.dumps(checks,indent=2))
print(json.dumps(checks,indent=2))
PY
```

Record source, actual binary/helper/endpoint hashes, snapshot, key_id (public),
service state, verification counts and retained STOP in `DEPLOYED.md`. Do not
call a restart a production RW qualification. Before any later resume, verify
root execute/approval remain denied, requester evidence_item append is denied,
requester observation append remains allowed, and catalogue/grants are unchanged.
A production recovery needs its own protected profile bound to the actual pending
UNKNOWN and expected state; never copy the canary profile. Missing/unverified,
v1/HMAC, or DRIVER_ERROR evidence is outside this recovery contract. Keep pending.

A new production RW qualification is a separate bounded run with fresh
nhoward-admin Duo approval, restore, replay refusal and reconciliation, followed
by portable verification and witness submission. No such run is part of this
installation. No AWS change is needed or authorized by this runbook.

## 5. Rollback

Keep STOP; stop only the candidate service. From the root keyboard:

```sh
systemctl stop virp-kestrel-candidate
cp -p /root/phase12-recovery-deploy/binary.before /usr/local/lib/virp-kestrel-v3/virp-onode-prod
cp -p /root/phase12-recovery-deploy/helper.before /usr/local/lib/virp-kestrel-v3/cage/helper.py
cp -p /root/phase12-recovery-deploy/endpoint.before /usr/local/sbin/virp-cage227-read
cp -p /root/phase12-recovery-deploy/devices.before.json /etc/virp-kestrel/devices.json
```

If recovery.py was installed, archive it on the same filesystem:

```sh
test ! -e /usr/local/lib/virp-kestrel-v3/cage/recovery.py.phase12-disabled
mv -n /usr/local/lib/virp-kestrel-v3/cage/recovery.py /usr/local/lib/virp-kestrel-v3/cage/recovery.py.phase12-disabled
chmod 0700 /usr/local/lib/virp-kestrel-v3/cage/recovery.py.phase12-disabled
systemctl start virp-kestrel-candidate
```

Stop if any command fails. Repeat chain_verify above with the restored helper.
Keep STOP until separately reconciled/authorized. If older code cannot verify
new records, leave the service stopped and preserve evidence. **Never restore
the database, consumed approvals or snapshot over newer evidence.** VM snapshot
is disaster recovery material; preserve current disk/evidence before using it.
