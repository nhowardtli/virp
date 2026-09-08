# D-1 Detached Ed25519 Chain Signing — Deployment Notes

Branch: `feat/detached-chain-signing`. **Deployment is OUT OF SCOPE for the
implementing session** — this file records the path; it does not execute
any of it. Do NOT touch `/opt/virp`, `.211`, any installed binary, live
key, live database, or running service from the implementing session.

## What D-1 is

Detached Ed25519 signatures beside every chain entry and per-session head,
over the SAME canonical bytes already hashed and HMAC'd. A third party can
then verify chain entries with the signer's PUBLIC key alone — no chain
key. It is a pure addition and opt-in: absent the `-S` flag the daemon
behaves exactly as today. See `SECURITY.md` "Detached Ed25519 Chain
Signing (D-1)" and `docs/DRAFT07-NOTES.md` §2.

## The invariant (must hold at every step)

The canonical bytes, the SHA-256 entry hash, the K_chain HMAC, the head
canonical/HMAC, the milestone canonical and the genesis rule are
byte-identical to the pre-D-1 tree. Verify before and after any change:

```
make test-chain-invariant     # C + Python locks vs D-0 Appendix A fixtures
```

## Deployment path (AFTER merge review — not done here)

1. **Merge** `feat/detached-chain-signing` to `main` after review.
2. **Burn in on the home-lab O-node (VM 313, governing pve-lab) FIRST.**
   Never `.211` first.
3. Only after a clean burn-in on 313: **.211**.

Each node, in order:

### a. Generate the chain-signing keypair (once per node)

```
virp-tool keygen chainsign /etc/virp/keys/chain-sign
#   -> /etc/virp/keys/chain-sign.key  (0600, DAEMON HOST ONLY)
#   -> /etc/virp/keys/chain-sign.pub  (32 raw bytes, distribute to verifiers)
chown virp:virp /etc/virp/keys/chain-sign.key
chmod 0600 /etc/virp/keys/chain-sign.key   # keygen already sets this; confirm
```

The secret is per-node and never leaves the host. Existing files are never
overwritten — to regenerate, remove both first (a new key starts new
sessions signed under a new key_id; it does not re-sign old sessions).

### b. Add `-S` to the daemon unit

`deploy/virp-onode.service` ExecStart gains one line (do NOT edit
`DEPLOYED.md` — that reflects the installed system, not this branch):

```
ExecStart=/usr/local/lib/virp/virp-onode-prod \
    -k /etc/virp/keys/onode.key \
    -s /run/virp/onode.sock \
    -d /run/virp/devices.json \
    -c /var/lib/virp/chain.db \
    -C /etc/virp/keys/chain.key \
    -S /etc/virp/keys/chain-sign.key      # <-- D-1, opt-in
```

`-S` requires `-c`/`-C`. Fail-closed: if `-S` is present and the key will
not load, the daemon REFUSES to start (it never runs silently unsigned).
`make check-deploy-unit` compares the tracked unit to the installed one; if
you adopt `-S` in the tracked unit, update the unit-drift allowlist the
same way the other flags are handled.

### c. Publish the public key for verifiers

The API server publishes it on `/api/key` (`chain_signing` block) from
`VIRP_CHAIN_SIGN_PUB` (default `/etc/virp/keys/chain-sign.pub`). Set that
env for the API service if the path differs. Distribute the `.pub` (or its
`key_id`) out of band as well.

### d. Rollback

Remove `-S` from the unit and restart. The sig columns remain in the DB
(harmless, unread by the pre-D-1 path); new appends simply stop signing.
No data migration ever runs.

## Verification after cut-over

A born-signed session verifies at all three tiers. From a copy of the DB
(verify a cleanly copied file, never the live WAL DB):

```
# asymmetric — public key ONLY, the third-party path:
virp chain verify --db chain.db --pubkey chain-sign.pub

# symmetric (unchanged) and keyless remain available:
virp chain verify --db chain.db --key chain.key
virp chain verify --db chain.db --keyless
```

`report/verify.py` gains the same asymmetric tier (optional PyNaCl/
`cryptography` backend; UNCHECKED with a reason if absent).

### Index the copy first, then verify

**If you are handed a chain database, run this before you verify it:**

    sqlite3 chain.db ".backup copy.db"     # verify a copy, never the live DB
    virp chain index  --db copy.db         # WRITES the index to the copy
    virp chain verify --db copy.db --pubkey chain-sign.pub

Skipping the middle step is the difference between a verify that finishes in
under a minute and one that does not finish at all.

**Why it is needed.** Every hash-keyed body lookup during a verify resolves an
entry by `chain_entry_hash`. Without `idx_chain_entry_hash` that is a full
table scan per lookup — measured 55 ms per entry on a 367k-entry chain, once
per `gate_intent` and once per closer.

The daemon creates that index on first open. **A verifier never can:**
`virp_chain_open_verifier()` opens `SQLITE_OPEN_READONLY` and runs no schema,
deliberately — a verifier must not be able to write to the artefact it is
judging. So a database that no updated daemon has opened read-write arrives
without the index and stays that way, and the third-party path above is exactly
the case where that happens.

`virp chain index` is the explicit, opt-in way to close that gap. It **writes**,
which is why it is a separate operator-run command on a copy rather than
something the verifier does quietly on your behalf.

**It cannot change a verdict.** `CREATE UNIQUE INDEX` derives an index from
rows that are already present; it cannot alter an entry, a hash or an HMAC. A
verify afterwards reaches the verdict it would have reached on the unindexed
file, sooner. The UNIQUE-ness is itself a check: on this schema
`chain_entry_hash` is sha256 over a canonical form that includes
`(session_id, sequence)`, which is already UNIQUE — so the index *failing* to
build means two entries share a hash, which is a SHA-256 collision or a
tampered database. Treat that as a finding, not an inconvenience.

Measured 2026-09-08, against the pre-deploy snapshot of virp-lab's chain
(368,183 entries, genuinely unindexed):

| | |
|---|---|
| `chain index` build | **2.00 s** |
| size added | ~26 MB |
| `verify --session gate-enforce:pbs-lab` after | **6.94 s** |
| the same verify before | **did not finish in 119 s** |

It is idempotent (a second run reports the index is already present and does
nothing) and refuses a database with no `chain_entries` table rather than
indexing whatever was named by mistake.

## Boundaries / open items for the draft-07 text

- **Daemon-compromise boundary is unchanged.** A compromised daemon holds
  the signing secret and can sign a forged chain — the daemon is the
  attester. The public key removes CONSUMER forge capability (verify
  without the chain key), not attester compromise.
- **K_chain holder can still rewrite history.** D-1 adds an adversary class
  the HMAC never covered (a verifier holding no secret); it does not remove
  the K_chain-holder class. External anchoring (e.g. the D-0 seal cadence,
  transparency log) remains future work.
- **Milestones are unsigned in D-1** (HMAC only). Signing the milestone
  canonical is a clean follow-on and a draft-07 consideration; nothing
  depends on a milestone signature today.
- **Key rotation is per session.** A new signing key changes the key_id on
  the sessions born after it; there is deliberately no re-signing of old
  sessions. A verifier partitions sessions by key_id and needs each key it
  wants to check. Publishing a small key_id → pubkey history (rotation log)
  belongs in the bundle/verifier layer, not this tree.
- **Bundle era labelling** lives outside this tree. The C tree emits only
  storage-level facts (`chain_format: v1`,
  `signature_scheme: ed25519-detached-v1`, `signing_key_id`); the bundle
  layer maps those to the era vocabulary.
