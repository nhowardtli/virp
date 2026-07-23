# VIRP Approval Flow — propose → approve → apply

Status: implemented (C daemon + virp-tool). The daemon is the SOLE
chain.db writer; approvals are signed externally (software key or PKCS#11
hardware) and submitted over the socket. Approver keys are enrolled in a
registry. ProVerif modeling of the approval flow is deferred.

## What it is

A command the tier gate blocks under ENFORCE (tier above `gate_max_tier`,
or UNCLASSIFIED) can be escalated to a human instead of dying at the gate.
The default gate max tier is unchanged. BLACK-tier commands are never
proposable or approvable.

```
AI layer                 O-Node (CT 211, sole chain writer)     Approver
--------                 ----------------------------------     --------
execute "configure…"  →  gate: block (RED > YELLOW)
                         + signed rejection (proposal_id=…)
                         + PROPOSAL chain entry
                                            virp approve <id>:
                              ← APPROVAL_CHALLENGE ─ canonical bytes ─→
                                            sign canonical (SW key / PIV)
                              ← APPROVAL_SUBMIT {sig, key_id} ─────────
                         verify sig vs registry
                         + APPROVAL chain entry (key_id + operator)
execute + proposal_id →  gate: verify approval
                         sig → hash → device → TTL → consume
                         → execute → OUTCOME chain entry
                           (links PROPOSAL + APPROVAL)
```

## Canonical payload (the signed bytes)

The approver signs a padding-free binary payload the daemon builds from
its own proposal record (never from client input), the same discipline as
v2 observations. All multi-byte fields are big-endian:

```
off  0  magic        "VAP1"              (4 bytes)
off  4  proposal_id  raw 16 bytes        (the random id, hex-decoded)
off 20  command_hash raw 32 bytes        (SHA-256 of the canonical command)
off 52  device_id    8 bytes             (device node_id)
off 60  approved_at  8 bytes             (ns since epoch)
off 68  ttl_seconds  4 bytes
= 72 bytes
```

CHALLENGE stamps `approved_at = now`, `ttl = 300 s`, persists a pending
challenge so SUBMIT reconstructs the exact bytes, and returns the 72 bytes
(hex) plus the proposal summary for display. SUBMIT reconstructs the bytes
itself and verifies. APPLY reconstructs them from the stored approval
record and re-verifies, so a tampered record field fails the signature.
(Nanosecond timestamps are stored in the JSON records as decimal strings —
they exceed 2^53 and a JSON number would round-trip lossily.)

### Signature encodings (wire choice)

Signatures are a fixed 64 bytes on the wire for both algorithms:

- **ECDSA-P256** — raw `r || s` (each 32 bytes). This is exactly what
  `CKM_ECDSA` returns from a PIV token; the daemon converts it to DER for
  OpenSSL verification. For CKM_ECDSA the client pre-hashes (SHA-256) the
  canonical bytes.
- **Ed25519** — the native 64-byte signature over the canonical bytes.

## Apply-side check order and DISTINCT rejection codes

| Check                                   | Failure code                              |
|-----------------------------------------|-------------------------------------------|
| proposal not already outcome-consumed   | `VIRP_ERR_APPROVAL_CONSUMED` (-42)        |
| key_id enrolled                         | `VIRP_ERR_APPROVAL_KEY_UNENROLLED` (-43)  |
| enrolled key enabled                    | `VIRP_ERR_APPROVAL_KEY_DISABLED` (-44)    |
| signature over canonical (enrolled key) | `VIRP_ERR_APPROVAL_BAD_SIGNATURE` (-40)   |
| command_hash match                      | `VIRP_ERR_APPROVAL_HASH_MISMATCH` (-38)   |
| device + node_id match                  | `VIRP_ERR_APPROVAL_DEVICE_MISMATCH` (-39) |
| TTL (300 s from approval)               | `VIRP_ERR_APPROVAL_EXPIRED` (-36)         |
| single-use consume                      | `VIRP_ERR_APPROVAL_REUSED` (-37)          |
| no approval record / proposal           | `VIRP_ERR_APPROVAL_NOT_FOUND` (-41)       |

Single-use consumption is persisted to `<dir>/consumed.list` (write-temp →
fsync → rename); a failed persist REJECTS the apply (fail closed). Consumed
state survives restarts.

### L1 — RESOLVED

The live-proof finding L1 (re-approval of an already-executed proposal
minted a fresh, misleading approval) is **fixed**. Enforcement point:
both `APPROVAL_CHALLENGE` and `APPROVAL_SUBMIT` refuse a proposal that
already has an `outcome:<id>` chain entry, with the distinct code
`approval_proposal_consumed` (-42). The check
(`virp_chain_artifact_exists`) runs before signature verification and
fails closed on a query error. There is no override flag this session.

## Approver registry — /etc/virp/approvers.json

The daemon enrolls approver PUBLIC keys from `/etc/virp/approvers.json`
(only public keys — no secret material ever enters the daemon). It is a
JSON array of:

```json
{
  "key_id":     "<32 lowercase hex>",   // SHA-256(raw pubkey)[:16]
  "algorithm":  "ecdsa-p256" | "ed25519",
  "public_key": "<base64 SubjectPublicKeyInfo (DER)>",
  "operator":   "<human identifier>",
  "enabled":    true
}
```

- `key_id` is uniformly `SHA-256(raw public key)[:16]` (the 32-byte
  Ed25519 key, or the 65-byte uncompressed EC point). The declared
  `key_id`/`algorithm` are cross-checked against the actual key at load;
  a mislabeled entry is rejected.
- Malformed entries are logged and skipped — one bad entry never disables
  the rest. A registry that enrolls zero usable keys leaves the flow
  disabled (fail safe).
- **Revocation = set `"enabled": false`** (or remove the entry) and
  restart at the next deliberate deploy. Applies signed by a disabled key
  are rejected with -44.
- **Two-key recommendation:** enroll a primary and a backup key (e.g. two
  YubiKeys), the backup `"enabled": false` until needed, so a lost primary
  never locks out approvals.

An example ships at `docs/approvers.example.json`. Generate entries with
`virp enroll` (below) — never hand-compute `key_id`.

## YubiKey PIV enrollment (slot 9c, touch-policy ALWAYS)

Generate the signing key ON the token so the private key never exists off
it, with touch required for every signature:

```
ykman piv keys generate --algorithm ECCP256 \
    --pin-policy ONCE --touch-policy ALWAYS 9c /tmp/9c.pub.pem
ykman piv certificates generate --subject "CN=virp-approver" 9c /tmp/9c.pub.pem
# Export the public SPKI as base64 and build the registry entry:
SPKI=$(openssl pkey -pubin -in /tmp/9c.pub.pem -outform DER | base64 -w0)
build/virp enroll --spki "$SPKI" --operator nhoward-yubikey-9c
```

Paste the printed JSON object into `/etc/virp/approvers.json` and deploy.
For a software (Ed25519) key instead: `virp-tool keygen approval <prefix>`
then `virp enroll --key <prefix>.pub --operator <name>`.

## Operator workflow / live proof sequence

The daemon loads `/etc/virp/approvers.json` (`-A`) and uses
`/var/lib/virp/approvals` (`-a`) by default. `virp` is a hardlink of
`virp-tool`. The PKCS#11 build (`make virp-tool-pkcs11`) adds `--pkcs11`.

```
# 1. A blocked command files a proposal; capture proposal_id.
sudo -u virp-onode virp exec R1 "configure terminal"

# 2. Approve with the PIV key (challenge → sign on token → submit).
#    Prompts for the PIN on the terminal, then "touch your key".
virp approve <proposal-id> \
    --pkcs11 /usr/lib/x86_64-linux-gnu/opensc-pkcs11.so --slot 9c

# 3. Apply — re-submits the exact command with the reference.
sudo -u virp-onode virp apply <proposal-id>

# 4. A second apply must be rejected: approval_reused (-37).
sudo -u virp-onode virp apply <proposal-id>

# 5. A re-approve of the executed proposal must be rejected:
#    approval_proposal_consumed (-42)  [L1].
virp approve <proposal-id> --pkcs11 … --slot 9c

# 6. Audit: PROPOSAL → APPROVAL(key_id, operator) → OUTCOME, hash-linked.
virp chain tail -n 12
```

`virp approve` never opens chain.db and never writes an approval record —
it is a pure client of `APPROVAL_CHALLENGE`/`APPROVAL_SUBMIT`. All chain
writes (PROPOSAL, APPROVAL, OUTCOME) are made by the daemon.

## Chain audit trail

All three entries share chain session `approval:<device>`:

- `proposal:<id>` — proposal JSON (device, session, exact command,
  command_hash, proposer, timestamp)
- `approval:<id>` — approval binding + **key_id + operator** (daemon-written)
- `outcome:<id>` — links `proposal_entry_hash` + `approval_entry_hash`,
  device, command_hash, success

An approved apply that reaches execution ALWAYS emits an OUTCOME, even if
the device itself then fails the command — the approval is consumed by the
attempt, not by success.

## PKCS#11 note

Real-hardware exercise (YubiKey PIV via `opensc-pkcs11.so`) is out of
scope in the CI/build container (no token, no module). The signer plumbing
is validated against a mock PKCS#11 module
(`tests/mock_pkcs11.c`, `make test-pkcs11`) driven through the real signer:
it produces a raw `r||s` signature the daemon's registry verify path
accepts. The PIN is read from the terminal (getpass), never argv;
`VIRP_PKCS11_PIN` is an env-only automation hook.

## Deferred / findings

- **Approval-flow ProVerif model** — not modeled this session.
- **L2 (from live testing):** interactive `[confirm]` prompts and config
  mode wedge the SSH session; the driver should answer/decline prompts and
  exit config mode after an approved config-entering command. Not fixed.
- **L3 (from live testing):** a blocked command to a busy/unreachable
  device reports connect-failure instead of the gate decision (the gate
  runs after the connection attempt). Not fixed.

## Scope notes

- The Go port implements none of this and REFUSES any execute carrying
  `proposal_id` with `ErrApprovalNotFound` (-41).
- `batch_execute` items may not carry `proposal_id`; the whole batch is
  refused. Approvals are single-command by design.
- Error observations (including approval rejections) are v1
  master-key-signed messages.
