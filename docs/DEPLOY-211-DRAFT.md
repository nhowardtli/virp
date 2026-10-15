# .211 deployment draft — STOP before execution

Not executed. Canary code is ecb2051 (v3 implementation 62ba679).

## Concrete contract gap

Fresh read of .211 `/usr/local/sbin/virp-cage227-read` on October 15:
line 27 rejects `raw[0] != 1`; lines 28–29 verify the legacy O-Key HMAC;
lines 34/84/91 decode fixed v1 offsets. It has no SESSION_HELLO/BIND flow.
Turning on `-3` breaks this consumer. Its pinned candidate binary hash must
also be updated only after the integrated helper/binary pair is qualified.
This is the first production stop condition, not an approval request.

The running Kestrel candidate is a separate service/binary/config/chain from
`virp-onode.service`. A default `make install-prod` targets the MAIN daemon's
path and does not deploy the Kestrel candidate. Do not replace either blindly.
The candidate's hardware-specific changes must be retained when integrating.

No chain-sign key exists in the observed `/etc/virp/keys` or
`/etc/virp-kestrel` inventories, and neither live service has `-S`.
There is no real .211 chain-sign key_id to enroll yet. Never enroll the
canary key or the witness example's public test key as .211.

## Required deployment order after resolving the helper contract

These are draft commands, not an executable deployment authorization/checklist
completion. The integrated commit and helper must first pass the same canary
loop with public-key verification and observation appends. Keep private keys
on .211; test approver is never installed on production.

1. On the ThinkPad, snapshot VM211 through the authenticated PVE management path:

```sh
ssh nhoward@10.0.10.10 'sudo -n qm snapshot 211 before-v3-kestrel --description "Before integrated Kestrel execute-v3 deployment"'
```

2. On .211, in the clean checkout of the **qualified integrated commit**:

```sh
git status --porcelain
# STOP if not empty or if the integrated commit has not been qualified.
# Install to an isolated location, preserving the currently running main daemon.
sudo -n make install-prod VIRP_INSTALL_DIR=/usr/local/lib/virp-kestrel-v3
sudo -n make deploy-record VIRP_INSTALL_DIR=/usr/local/lib/virp-kestrel-v3
```

`install-prod` captures recovery material and writes DEPLOYED.md. Do not claim
that installation alone changes the active service. Capture existing candidate
unit/helper and binary before changing their paths/pins. The qualified helper
must use the v3 public key, bind a session, distinguish signed DEVICE_OUTPUT vs
ERROR, and append the exact observed frames. It must not acquire device or
signing credentials.

3. Provision the node-local signing key once (never overwrite an existing key):

```sh
sudo -n test ! -e /etc/virp-kestrel/chain-sign.key
# Fresh service inspection confirmed User=virp-kexec.
sudo -n -u virp-kexec /usr/local/lib/virp-kestrel-v3/virp-tool keygen chainsign /etc/virp-kestrel/chain-sign
```

The inspected service account is virp-kexec. The private file stays mode 0600
owned by the daemon account. Extend the candidate unit's existing ExecStart
with `-3 -S /etc/virp-kestrel/chain-sign.key`, preserving all other options and
using `/usr/local/lib/virp-kestrel-v3/virp-onode-prod`. Deploy the qualified
helper and its exact binary/public-key pins as the same change.

```sh
sudo -n systemctl daemon-reload
sudo -n systemctl restart virp-kestrel-candidate
sudo -n systemctl is-active virp-kestrel-candidate
sudo -n journalctl -u virp-kestrel-candidate -n 40 --no-pager
```

4. Bind a fresh helper session; do the next bounded Kestrel RW/restore run.
Verify all entries, not just default sequence zero: enumerate each session's
maximum sequence and issue chain_verify from 0 through that maximum, requiring
valid=true, executions_open=0 and the expected entry count. Check every new
execute observation's v3 signature and append bytes. Record live process hash,
service command, source commit, session IDs and restore evidence in DEPLOYED.md.
Roll back the candidate unit/helper/binary together if verification fails;
preserve the failed chain and observations rather than deleting evidence.

## Witness enrollment draft (AWS not changed)

The known registry shape is `{"keys":[...]}`. Add this object only after the
real node public key exists and its custody/identity is checked:

```json
{"key_id":"SHA256_OF_RAW_211_PUBLIC_KEY_FIRST_16_BYTES_HEX","algorithm":"ed25519","public_key_hex":"RAW_211_CHAIN_SIGN_PUBLIC_KEY_64_HEX","comment":"Kestrel C O-Node .211 execute-v3"}
```

Generate the concrete object on .211 using only the public file:

```sh
sudo -n python3 - <<'PY'
import hashlib,json,pathlib
p=pathlib.Path('/etc/virp-kestrel/chain-sign.pub').read_bytes()
assert len(p)==32
print(json.dumps({'key_id':hashlib.sha256(p).hexdigest()[:32],
 'algorithm':'ed25519','public_key_hex':p.hex(),
 'comment':'Kestrel C O-Node .211 execute-v3'}))
PY
```

Later enrollment goes into AWS `/etc/virp-witness/submitters.json`, preserving
all other keys. The submitter must use this same local signing key and the
pinned witness public key; capture and verify receipts. No AWS operation or
submitter installation is part of this completed canary deployment.
Today's original v1 Kestrel frames cannot be converted without changing their
signed bytes. The publicly witnessed packet must come from the next RW run.
