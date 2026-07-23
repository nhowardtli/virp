# VIRP Approval Flow — propose → approve → apply

Status: implemented (C daemon + virp-tool). ProVerif modeling of this
flow is deliberately deferred to a follow-up session.

## What it is

Commands blocked by the tier gate under ENFORCE (tier above
`gate_max_tier`, or UNCLASSIFIED) can be escalated to a human instead of
dying at the gate. The default gate max tier is unchanged. BLACK-tier
commands are never proposable or approvable.

```
AI layer                    O-Node (CT 211)              Human approver
--------                    ---------------              --------------
execute "configure ..."  →  gate: block (RED > YELLOW)
                            + signed rejection
                            + PROPOSAL chain entry
                            + proposals/<id>.rec
                            payload carries proposal_id=<id>
                                                         virp approve <id>
                                                         (signs with approval.key,
                                                          APPROVAL chain entry,
                                                          approvals/<id>.rec,
                                                          300 s TTL, single use)
execute + proposal_id    →  gate: verify approval
                            sig → hash → device → TTL → consume
                            → execute → OUTCOME chain entry
                              (links PROPOSAL + APPROVAL)
```

Apply-side check order and DISTINCT rejection codes:

| Check                         | Failure code                             |
|-------------------------------|------------------------------------------|
| Ed25519 signature (approval key) | `VIRP_ERR_APPROVAL_BAD_SIGNATURE` (-40) |
| command_hash match            | `VIRP_ERR_APPROVAL_HASH_MISMATCH` (-38)  |
| device + node_id match        | `VIRP_ERR_APPROVAL_DEVICE_MISMATCH` (-39)|
| TTL (300 s from approval)     | `VIRP_ERR_APPROVAL_EXPIRED` (-36)        |
| single-use consume            | `VIRP_ERR_APPROVAL_REUSED` (-37)         |
| no approval record on disk    | `VIRP_ERR_APPROVAL_NOT_FOUND` (-41)      |

Single-use consumption is persisted to `<dir>/consumed.list` with the
same write-temp → fsync → rename pattern as the observation seqstore;
a failed persist REJECTS the apply (fail closed, matching af92763).
Consumed state survives daemon restarts.

## Keys — generation, separation, rotation

The approval key is a dedicated **Ed25519 keypair**, cryptographically
distinct from the O-Key (a 32-byte symmetric HMAC secret). The daemon
loads ONLY the public half and refuses a 64-byte secret-key file; the
secret half lives with the approver. The observer therefore can never
mint approvals for its own escalations, and the approver never holds
observation-signing material.

Generate (run once, as root, on CT 211):

```
build/virp-tool keygen approval /etc/virp/keys/approval
# → /etc/virp/keys/approval.pub  (0644 ok — public)
# → /etc/virp/keys/approval.key  (0600 — approver only)
```

The prod daemon picks up `/etc/virp/keys/approval.pub` and
`/var/lib/virp/approvals` by default (`-A` / `-a` to override). If the
public key is absent the flow is disabled and plain gate blocking is
unchanged.

### Rotation procedure

1. Generate the new pair under a staging name:
   `virp-tool keygen approval /etc/virp/keys/approval-new`
2. Let any in-flight approvals expire (TTL is 300 s — wait 5 minutes,
   or verify `approvals/` holds nothing unconsumed you care about).
3. Atomically swap: `mv approval-new.pub approval.pub && mv
   approval-new.key approval.key`
4. Restart virp-onode at the next deliberate deploy (the daemon reads
   the pub key at startup). Old approvals become invalid the moment the
   daemon holds the new public key — signature check fails first.
5. Record the new key id (printed at keygen) in the ops log.

Rotate immediately if: the approver's workstation/session is suspected
compromised, an approval appears on the chain that no human remembers
issuing, or as part of the scheduled credential-rotation window.

## Operator workflow (live proof sequence shape)

```
# 1. AI submits a blocked command; the signed rejection contains
#    "proposal_id=<32 hex>". [GATE] log shows "proposal filed".
# 2. Approve (run as root or the daemon user so file perms line up):
build/virp approve <proposal-id> \
    --chain-db /var/lib/virp/chain.db --chain-key <chain-key-path>
# 3. Apply — re-submits the EXACT proposed command with the reference:
build/virp apply <proposal-id>
# 4. A second `virp apply <proposal-id>` must return
#    "apply rejected (approval_reused, err=-37)".
```

`virp` is a hardlink of `virp-tool` created by the build. `approve`
defaults to `--dir /var/lib/virp/approvals --key
/etc/virp/keys/approval.key --pub /etc/virp/keys/approval.pub`; pass
`--chain-db/--chain-key` so the APPROVAL entry lands on the same chain
the daemon writes (multi-process SQLite access is safe — appends use
BEGIN IMMEDIATE).

File permissions: proposals are written by the daemon (0640), approvals
by the approver (0644 — a signed public statement the daemon must be
able to read regardless of which user approved).

## Chain audit trail

All three entries share chain session `approval:<device>`:

- `proposal:<id>` — artifact: proposal JSON (device, session, exact
  command, command_hash, proposer, timestamp)
- `approval:<id>` — artifact: signed approval JSON (binding + key id)
- `outcome:<id>` — artifact: links `proposal_entry_hash` +
  `approval_entry_hash`, device, command_hash, and whether the device
  reported success

An approved apply that reaches execution ALWAYS emits an OUTCOME entry,
even if the device itself then fails the command — the approval is
consumed by the attempt, not by success.

## Scope notes

- **FINDING (next session): second chain writer.** `virp approve
  --chain-db/--chain-key` writes chain.db directly from the CLI using
  the daemon's chain key — a second writer on the daemon's database and
  a second holder of K_chain. Better design: the CLI only signs the
  approval record, submits it over the framed socket, and the DAEMON
  appends the APPROVAL chain entry (single writer, chain key never
  leaves the daemon). Not changed in this session.
- **FINDING L1 (from live testing 2026-07-23, deferred): re-approval of
  an executed proposal mints a valid new approval.** Single-use is
  keyed on the consumed proposal_id at APPLY time; `virp approve` will
  re-sign a proposal whose OUTCOME already exists (live evidence: chain
  `approval:R1` seq=6 re-approves f9e1… 32 s after its outcome at
  seq=4 — see `docs/LIVE-PROOF-2026-07-23.md`). The consumed store
  still blocks re-execution, but the fresh approval record is
  misleading audit state. Fix direction: `virp approve` refuses a
  proposal that already has an OUTCOME chain entry unless an explicit
  `--re-approve` flag is given. Not implemented.
- **FINDING L2 (from live testing 2026-07-23, deferred): interactive
  prompts and config mode wedge the SSH session.** IOS `[confirm]`
  prompts are not answered by the driver (console hangs; next
  submission reports `cannot connect` until the watchdog recycles),
  and a successful `configure terminal` apply leaves the device in
  config mode, blocking subsequent connects. Fix direction: the driver
  answers/declines confirmation prompts explicitly and exits config
  mode (or resets the session) after an approved config-entering
  command. Not implemented.
- **FINDING L3 (pre-existing, now observed live): a blocked command to
  a busy/unreachable device reports connect-failure instead of the
  gate decision** — the gate check runs after the connection attempt.
  Fix direction: evaluate the gate before connecting. Not implemented.

- The Go port implements none of this and REFUSES any execute carrying
  `proposal_id` with `ErrApprovalNotFound` (-41) rather than silently
  serving it as a plain execute.
- `batch_execute` items may not carry `proposal_id`; the whole batch is
  refused. Approvals are single-command by design.
- Error observations (including approval rejections) are v1
  master-key-signed messages — same as every other error path today.
