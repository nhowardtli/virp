# Operator keyboard runbook: Kestrel execute-v3 on .211

**Qualification prerequisites cleared on October 16.** Dedicated VM103
`virp-qualify` now replaces the conflicted public-lab VM100 for this work.
Code `b7496fb` passed the full regression battery and a model-driven cage GREEN
read/RED refusal with exact v3 storage and independent public-key verification.
Production baseline `140f6f9` is reconciled in `d46802d`, with follow-up test-build
fixes `7f74291` and `b7496fb`. See [the phase-one record](TLI-ROLLOUT-PHASE1.md).

This releases the procedure for the owner to run at the keyboard, as requested.
It does not claim .211 is deployed or production RW is newly qualified.

This runbook is **not executed**. .211 was not accessed during helper qualification.
Target only `virp-kestrel-candidate`; the main `virp-onode` service stays separate.
Use branch `feat/v3-execute-path`, qualified code commit `b7496fb` plus the documentation-only release commit.
The canary helper uses the same `execute_observed` consumer as the staged production
helper. The production grant adapter is checked offline; this is not a claim of a
new production RW qualification. The existing Duo approver/coordinator stays in place.

## Provisioned key contract

Before starting, the owner provisions:

- Private path: `/etc/virp-kestrel/chain-sign.key`
- Owner/group: `virp-kexec:virp-kexec`; mode **0600**.
- Exactly **64 raw bytes**, libsodium Ed25519 secret key layout: 32-byte seed
  followed by its corresponding 32-byte public key. Not PEM, hex, base64 or a
  seed-only file. Regular file, no symlink. The daemon checks the seed/public pair.
- Public counterpart: `/etc/virp-kestrel/chain-sign.pub`, exactly **32 raw bytes**,
  root-owned, mode **0644**, with no group/other write permission. It must match
  the private key. Only this public file is consumed by the helper.
- Keep parent `/etc/virp-kestrel` root-owned, group `virp-kexec`, mode 0750.

The daemon uses `-3 -S /etc/virp-kestrel/chain-sign.key`. No key material is
created, printed, enrolled, committed or copied into a checkout by this procedure.
Keep production private keys on .211. Existing HMAC keys remain necessary for
legacy chain compatibility; they are not used by the new execute-v3 consumer.

## 1. Snapshot and acquire a clean checkout

On the ThinkPad, verify VM211 identity and snapshot success before proceeding:

```bash
ssh nhoward@10.0.10.10 'sudo -n qm config 211'
ssh nhoward@10.0.10.10 'sudo -n qm snapshot 211 before-kestrel-cage-v3 --description "Before Kestrel execute-v3 and helper migration"'
ssh nhoward@10.0.10.10 'sudo -n qm listsnapshot 211'
```

Then on .211 at the keyboard. Stop on any failed command. Do not run with
shell tracing (`set -x`); configuration backups contain device credentials.
Use a fresh checkout; do not overwrite the candidate's existing source tree:

```bash
set -euo pipefail
umask 077
git clone --branch feat/v3-execute-path --single-branch git@github.com:nhowardtli/virp.git "$HOME/virp-kestrel-v3-deploy"
cd "$HOME/virp-kestrel-v3-deploy"
test -z "$(git status --porcelain)"
git merge-base --is-ancestor b7496fb HEAD
git log -1 --oneline
test -f docs/CAGE-V3-RELEASED
# Stop if code has changed beyond the qualified build; documentation may advance.
git diff --exit-code b7496fb HEAD -- . ':!docs' ':!DEPLOYED.md'
python3 -c 'import cryptography'
make test-cage-v3
make prod
```

The branch preserves the candidate's Cisco password-challenge restrictions and
TACACS denial handling from `1c63e91`/`52562b4`, plus strict-KEX signaling. No
Rust changes. A changed helper/unit/target baseline is a stop condition: retain
the diagnostic and reconcile it; do not bypass the staging checks.

## 2. Install into the isolated candidate directory and stage helper/config

`install-prod` below does not replace the main daemon binary or restart a service.
The repository's install helper captures deployment recovery material and prints
a deployment record. Capture that output explicitly below; `deploy-record` does not
write `DEPLOYED.md` by itself. Keep host deployment records outside commits.

```bash
sudo -n make install-prod VIRP_INSTALL_DIR=/usr/local/lib/virp-kestrel-v3
sudo -n install -d -m 0755 /usr/local/lib/virp-kestrel-v3/cage
sudo -n install -m 0644 tools/cage/helper.py tools/cage/verify_local_chain.py /usr/local/lib/virp-kestrel-v3/cage/
sudo -n python3 tools/cage/stage_production.py --stage /root/kestrel-v3-deploy
sudo -n python3 -m py_compile /root/kestrel-v3-deploy/after/virp-cage227-read
sudo -n systemd-analyze verify /root/kestrel-v3-deploy/after/virp-kestrel-candidate.service
```

Staging verifies key **metadata only**, helper baseline hash, machine identity,
service account/command, target identity, GREEN requester ceiling and enforcing
gate. It preserves existing action privileges and adds only observation appends
with an explicit artifact-type policy. It does not approve a proposal, extend a
lease, remove a STOP file, or modify device credentials. It captures the exact
original helper, unit, config and lease under root-only `before/`.

Review the nonsecret changes locally (do not paste private config into chat):

```bash
sudo -n diff -u /root/kestrel-v3-deploy/before/virp-cage227-read /root/kestrel-v3-deploy/after/virp-cage227-read || test "$?" -eq 1
sudo -n diff -u /root/kestrel-v3-deploy/before/virp-kestrel-candidate.service /root/kestrel-v3-deploy/after/virp-kestrel-candidate.service || test "$?" -eq 1
```

## 3. Quiesce, backup live evidence, activate the paired update, restart

Stop new cage calls and let the helper lock become available. The persistent
STOP marker remains set until the owner deliberately opens a fresh bounded
lease. The following refuses an in-flight helper; it does not kill one.

```bash
sudo -n touch /var/lib/virp-cage227/STOP
sudo -n chmod 0600 /var/lib/virp-cage227/STOP
sudo -n flock -n /var/lib/virp-cage227/lock /bin/true
sudo -n systemctl stop virp-kestrel-candidate
sudo -n tar -C /var/lib -cpf /root/kestrel-v3-deploy/chain-before.tar virp-kestrel
sudo -n install -o root -g root -m 0755 /root/kestrel-v3-deploy/after/virp-cage227-read /usr/local/sbin/virp-cage227-read
sudo -n install -o root -g root -m 0644 /root/kestrel-v3-deploy/after/virp-kestrel-candidate.service /etc/systemd/system/virp-kestrel-candidate.service
sudo -n install -o virp-kexec -g virp-kexec -m 0400 /root/kestrel-v3-deploy/after/devices.json /etc/virp-kestrel/devices.json
sudo -n install -o root -g root -m 0600 /root/kestrel-v3-deploy/after/policy.json /var/lib/virp-cage227/policy.json
sudo -n systemctl daemon-reload
sudo -n systemctl restart virp-kestrel-candidate
sudo -n systemctl is-active virp-kestrel-candidate
sudo -n journalctl -u virp-kestrel-candidate -n 40 --no-pager
```

Any signing-key inconsistency or startup error: STOP and use rollback. Do not
fall back to v1 or disable evidence enforcement. Service boot enablement remains
unchanged. Snapshot rollback is emergency recovery, not routine code rollback.

## 4. Verify all chain ranges and record the actual deployment

This performs management reads only; it issues no switch commands. A default
`chain_verify` ending at zero checks only sequence zero, so use the explicit
per-session maxima script:

```bash
sudo -n python3 /usr/local/lib/virp-kestrel-v3/cage/verify_local_chain.py --db /var/lib/virp-kestrel/chain.db --socket /run/virp-kestrel/onode.sock --requester virp-kreq | sudo -n tee /root/kestrel-v3-deploy/chain-verify.json
sudo -n make deploy-record VIRP_INSTALL_DIR=/usr/local/lib/virp-kestrel-v3 | sudo -n tee /root/kestrel-v3-deploy/DEPLOYED.md
sudo -n systemctl show virp-kestrel-candidate -p MainPID -p ExecStart -p User -p Group | sudo -n tee /root/kestrel-v3-deploy/live-service.txt
sudo -n sha256sum /usr/local/lib/virp-kestrel-v3/virp-onode-prod /usr/local/lib/virp-kestrel-v3/cage/helper.py /usr/local/sbin/virp-cage227-read | sudo -n tee /root/kestrel-v3-deploy/live-hashes.txt
sudo -n sh -c 'cat /root/kestrel-v3-deploy/live-service.txt /root/kestrel-v3-deploy/live-hashes.txt /root/kestrel-v3-deploy/metadata.json /root/kestrel-v3-deploy/chain-verify.json >> /root/kestrel-v3-deploy/DEPLOYED.md'
```

Require every chain valid, complete entry counts, and zero open executions.
Check the running executable as well:

```bash
sudo -n sh -c 'pid=$(systemctl show virp-kestrel-candidate -p MainPID --value); test "$pid" -gt 1; live=$(sha256sum /proc/"$pid"/exe); disk=$(sha256sum /usr/local/lib/virp-kestrel-v3/virp-onode-prod); test "${live%% *}" = "${disk%% *}"'
```

Stop if it is not the installed binary. The record is installation/startup evidence,
not an unperformed production RW claim. Keep the STOP marker and expired grants
intact. The next owner-opened lease/RW test must independently prove the production
path; no switch command or lease extension is part of this runbook.

New execute observations are immutable v3 bytes, independently checked before
storage in the existing chain format. Existing v1/v2 bytes remain unchanged.
No historical frame is converted or represented as publicly verifiable v3.
No AWS enrollment, witness submission or `virp-verify 0.1.3 VERIFIED` claim here.

## 5. Rollback the helper/unit/config together, preserve all evidence

Use on failure; STOP stays set. Never restore an old chain over the current one.
Keep failed observation spool and current chain for investigation:

```bash
sudo -n touch /var/lib/virp-cage227/STOP
sudo -n flock -n /var/lib/virp-cage227/lock /bin/true
sudo -n systemctl stop virp-kestrel-candidate
sudo -n tar -C /var/lib -cpf /root/kestrel-v3-deploy/failed-evidence.tar virp-kestrel virp-cage227
sudo -n install -o root -g root -m 0755 /root/kestrel-v3-deploy/before/virp-cage227-read /usr/local/sbin/virp-cage227-read
sudo -n install -o root -g root -m 0644 /root/kestrel-v3-deploy/before/virp-kestrel-candidate.service /etc/systemd/system/virp-kestrel-candidate.service
sudo -n install -o virp-kexec -g virp-kexec -m 0400 /root/kestrel-v3-deploy/before/devices.json /etc/virp-kestrel/devices.json
sudo -n install -o root -g root -m 0600 /root/kestrel-v3-deploy/before/policy.json /var/lib/virp-cage227/policy.json
sudo -n systemctl daemon-reload
sudo -n systemctl restart virp-kestrel-candidate
sudo -n systemctl is-active virp-kestrel-candidate
sudo -n python3 /usr/local/lib/virp-kestrel-v3/cage/verify_local_chain.py --db /var/lib/virp-kestrel/chain.db --socket /run/virp-kestrel/onode.sock --requester virp-kreq | sudo -n tee /root/kestrel-v3-deploy/rollback-chain-verify.json
```

The original candidate binary was never overwritten. Leave the provisioned
signing key and new evidence in place. If old daemon startup/verification fails,
leave cage stopped and service stopped; investigate using retained evidence and
PVE console recovery. Do not erase chains or revert VM snapshot over unexported
new evidence. Record the rollback command, time, live hash and verification
result in `/root/kestrel-v3-deploy/DEPLOYED.md`.
