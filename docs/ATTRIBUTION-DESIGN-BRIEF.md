# Design brief — attributing a chain entry to the principal that wrote it

Status: BRIEF. Nothing here is implemented. Written 2026-09-02 out of the
v0.2.1 work, which made uid a first-class policy input and in doing so
made the gap below hard to keep ignoring.

## The question the chain cannot answer

For an entry appended through the control socket, the chain does not
record **which principal appended it**.

`chain_entries` carries `session_id`, `sequence`, the hash links, the
artifact identity, `chain_hmac`, and `signer_node_id` / `signer_org_id`.
The signer fields identify *the node* that signed the entry. There is no
column for the calling uid, and the artifact rows do not carry one
either.

So "who wrote this record?" is answerable as "this node did", and no
more precisely than that.

## How attribution is done today, and why that is not enough

Today a reader recovers the principal by **reading the session id and
inferring the owner from its prefix** — `autopilot:*` is taken to mean
the autopilot, an `ncfed*` prefix the federation bridge, and so on. The
30-day export used for the v0.2.1 fixture says this in its own provenance
note: *"uid is attributed from the session-prefix -> owning client
mapping"*.

Three things are wrong with that.

**1. The prefix is chosen by the caller, not assigned by the daemon.**
A socket `chain_append` carries whatever `session_id` string the client
sends. Nothing binds that string to the peer uid — there are 54 uses of
the peer uid in the daemon and not one of them is compared against the
session id. Any uid permitted to append at all may append under any
session name, including one that reads as another component's.

**2. It is a naming convention, so it is not enforced and can drift.**
Nothing rejects a new component that picks a colliding prefix, and
nothing notices when one does.

**3. It has already produced an unresolvable case.** The same export
found 196 `observation` entries sitting under the federation bridge's
session prefix. They cannot be the bridge's: that uid's `chain_append`
has been narrowed to the `fed_*` triple since 2026-08-11, and the bridge
has worked throughout. They are almost certainly pre-narrowing history
written by a different principal — but "almost certainly" is the whole
problem, and the rows could not be re-queried to settle it. The fixture
records the exclusion as `attribution_caveat` so it is at least visible
rather than silent.

That is the failure mode in one line: **the ledger contains records whose
author cannot be determined from the ledger.**

## Why this matters more after v0.2.1

v0.2.1 makes the calling uid a policy input. `socket_uid_chain_append_types`
decides, per uid, which artifact types may be appended, and the daemon
refuses anything outside that list.

That policy is enforced **at write time** and recorded **nowhere**. An
auditor reading the chain later cannot confirm that the policy was in
force, cannot confirm which uid an entry was admitted for, and therefore
cannot detect a window in which the policy was wrong, absent, or
bypassed. The `node_config` entry records the boot posture, which bounds
*when* a configuration was live, but no entry records *which principal* a
given append was authorised for.

The v0.2.0 incident is the concrete case. Reconstructing which appends
were refused, for which uid, meant reading the daemon journal, because
the chain could not say. The journal is not evidence in the sense the
chain is: it is not hash-linked, not signed, and rotates.

## What a fix has to do

1. Record the principal **as observed by the daemon** (the peer uid from
   the socket), never as asserted by the caller.
2. Bind it into the entry hash, so it cannot be edited afterwards without
   breaking the chain, exactly as the other entry fields are.
3. Survive an existing chain: 273239 entries exist and must keep
   verifying, so any change has to be compatible with entries that
   predate it.
4. Distinguish "no principal recorded" (an old or daemon-minted entry)
   from "principal recorded as X". These must never collapse into the
   same value.
5. Say something honest about daemon-minted entries. `gate_intent`,
   `gate_execution`, `gate_rejection`, `outcome`, `node_config` and
   `proposal` are written by the daemon itself, not through a socket
   append. Their principal is the daemon, and that should be explicit
   rather than blank.

## Options

### A. A `principal_uid` column on `chain_entries`, covered by the hash

Add the peer uid, and a small enum for how it was obtained
(`peer-credential`, `daemon-internal`, `unrecorded-legacy`), and include
both in the entry hash preimage for entries written after the change.

- *For:* directly answers the question; queryable without parsing bodies;
  tamper-evident through the existing hash chain.
- *Against:* changes the hash preimage, so it is a schema and format
  change with a version gate. Old entries must keep hashing the old way,
  which means the verifier carries both rules permanently.

### B. Put the principal in the artifact body instead

Have the daemon inject the observed uid into the stored artifact content.

- *For:* no schema change to `chain_entries`; the body is already hashed,
  so it is covered.
- *Against:* the daemon would be rewriting a caller-supplied body, which
  breaks the property that the stored artifact is exactly what was
  submitted and complicates every signature check over that body. It also
  buries a queryable fact inside JSON. **Not recommended.**

### C. Bind the session prefix to the uid at write time

Keep attribution in the session id, but have the daemon *enforce* that a
uid may only append under session prefixes assigned to it, as a per-uid
policy in the same shape as `socket_uid_chain_append_types`.

- *For:* small, no format change, reuses the policy machinery just built,
  and fixes the "any uid may write under any name" hole immediately.
- *Against:* does not record the principal — it only makes the existing
  inference trustworthy going forward. A reader still infers rather than
  reads, and the 196-row case would still be unresolvable because the
  binding did not exist when those rows were written.

### D. Signed per-principal append receipts

A side structure in which each append is acknowledged with a signature
over (entry hash, principal), retained alongside the chain.

- *For:* no change to the chain format at all.
- *Against:* a second artifact to store, verify and keep in sync, with
  its own loss and divergence modes. It answers the question only when
  the receipt store is intact, which is a weaker guarantee than the chain
  itself. Largest surface of the four.

## Recommendation

**A, with C as an immediate and independently useful step.**

C is small, needs no format change, and closes the caller-controlled
naming hole now — it makes today's inference sound going forward even if
A is never built. A is the real answer, because only A makes the
principal a recorded fact rather than a reconstruction.

Doing C first also de-risks A: once prefixes are bound to uids, the
migration to a recorded principal can be checked against an already
consistent history.

## Compatibility

- Entries written before the change carry `unrecorded-legacy` and hash
  under the old preimage. They must continue to verify unchanged; a
  verifier that fails them would invalidate 273239 existing entries.
- The verifier reports an unrecorded principal as exactly that. It must
  never render as uid 0, an empty string, or "unknown" — the v0.2.0
  `build_id="unknown"` defect is the direct precedent for how a
  placeholder that reads like a value hides a missing one.
- The boundary between old and new must itself be visible in the chain,
  so a reader can tell where recorded attribution begins. The
  `node_config` entry is the natural place to state it.

## What this does not solve

- It attributes an append to a **uid on this host**, not to a person. A
  service account is a service account, and anyone who can run as that
  uid is indistinguishable from it.
- It does not make the daemon's own entries more trustworthy than the
  daemon. If the daemon is compromised, it records whatever it likes.
- It does not retroactively attribute existing entries. The 196 rows stay
  unresolved; nothing recorded later can fix a fact that was never
  written down.

## Open questions

- Should a uid's *policy at the time of the append* be recorded too, or
  is the `node_config` boot posture plus a recorded principal enough to
  reconstruct it? Recording the policy per entry is precise but
  expensive; reconstructing it assumes no mid-run reload.
- Should an append by a uid with no recorded principal support be refused
  outright once A ships, or recorded as `unrecorded`? Refusing is
  cleaner; it also means a daemon upgrade can stop a working component.
- Does the federation bridge need the *remote* principal recorded as well
  as the local uid? Today `fed_*` entries carry the bridge's uid, which
  says how the record arrived and nothing about who originated it.
