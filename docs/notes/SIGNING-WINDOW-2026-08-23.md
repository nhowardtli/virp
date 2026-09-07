# The 2026-08-23 signing window on 313

**Ruling: `autopilot:2026-08-23` is BROKEN, permanently, by design.**

Same shape of ruling as the Sep 3 camera SCAR: the evidence is what it
is, the verifier cannot honestly say otherwise, and the reason is written
down here instead of being softened in code.

## What happened

Chain signing was enabled on `virp-onode-home` (VM 313, node 13) for the
first time ever at **2026-08-23 17:48:11Z**. It did not come up cleanly.

```
17:48:11  [Chain] Detached Ed25519 chain signing ENABLED
                  (scheme ed25519-detached-v1, key_id c1104805e1044d63a0c531eb7a025e68)
17:48:40  [O-Node] Signal received, shutting down...
17:48:42  [ChainSign] chain-signing secret key /etc/virp/keys/chain-sign.key has
                      insecure mode 0644 — any group/world access makes every
                      local reader a chain forger. Refusing to load.
17:48:42  [Chain] chain-signing key load failed: Signing key not loaded
17:48:42  [O-Node] FATAL: chain signing was requested (-S /etc/virp/keys/chain-sign.key)
                   but could not be enabled: Signing key not loaded. Refusing to start.
17:48:42  systemd[1]: virp-onode.service: Scheduled restart job, restart counter is at 1.
          ... crash loop ...
17:57:37  [Chain] Detached Ed25519 chain signing ENABLED (key_id c1104805...)
```

The refusal is the control working: the daemon would not run with a
world-readable signing key. (The key is `0600` today; see the follow-up
below.)

Then, eight minutes later, **a restart came up with signing off**:

```
18:05:30  systemd[1]: Started virp-onode.service
18:05:30  [Chain] Initialized: db=/var/lib/virp/chain.db node=13 org=local
18:05:30  [O-Node] Trust chain enabled: db=/var/lib/virp/chain.db
18:05:30  [Watchdog] Started — connecting 38 enabled devices
          ^^ no "chain signing ENABLED" line for this process
18:07:51  systemd[1]: Stopping virp-onode.service
18:08:02  [Chain] Detached Ed25519 chain signing ENABLED (key_id c1104805...)
```

**Window: 18:05:30Z to 18:07:51Z, 2 minutes 21 seconds.** Fifteen entries
were written in it, and every one is unsigned. They are the only unsigned
entries anywhere on 313 after 17:56:58Z.

## Affected entries

| session | sequences | written | shape |
|---|---|---|---|
| `autopilot:2026-08-23` | **24–35** (12 entries, all `observation`) | 18:05:41.647Z – 18:05:41.764Z | signed 0–23, **unsigned 24–35**, signed 36–863 |
| `burnin-rollback:2026-08-23` | 0–2 (3 entries, all `observation`) | 18:07:18.847Z – 18:07:18.848Z | wholly unsigned |

Neighbours of the gap in `autopilot:2026-08-23`:

```
seq=23  2026-08-23 17:57:47.081Z  observation  signed=True
seq=24  2026-08-23 18:05:41.647Z  observation  signed=False
...
seq=35  2026-08-23 18:05:41.764Z  observation  signed=False
seq=36  2026-08-23 18:15:02.995Z  observation  signed=True
```

## The ruling

`burnin-rollback:2026-08-23` is wholly unsigned and grades
**`UNSIGNED_ERA`**, alongside the 16 genuinely pre-signing sessions. It
carries no signature to strip.

`autopilot:2026-08-23` grades **`BROKEN`, and stays BROKEN.** It is
signed, then unsigned, then signed again: two transitions.

**The verifier cannot distinguish a restart window from a stripped run.**
Both look identical in the database: a contiguous run of entries whose
`chain_sig` is empty, inside a session whose other entries are signed and
whose head is signed. An attacker who stripped signatures from twelve
consecutive entries would produce byte-for-byte the same shape. The only
thing that separates the two readings is the journal, and the journal is
not evidence the chain carries — it is a different artifact on a
different host with a different retention policy, and a verifier that
consulted it would be trusting the very machine under examination.

So `SIGNED_FROM_N` is deliberately restricted to a single unsigned
**prefix**: unsigned entries that stop once signing starts and never
resume. That shape is unforgeable in the direction that matters — an
attacker gains nothing by stripping a prefix that predates the key,
because those entries were never covered anyway. A gap that opens *after*
signatures have begun is a different claim, and it is refused.

Pinned by `tests/test_chain_signing_migration.c`:

- `test_signed_unsigned_signed_is_broken` builds this exact shape and
  asserts BROKEN,
- `test_no_flag_can_excuse_signed_unsigned_signed` runs all four
  combinations of the keyless, symmetric and asymmetric tiers and asserts
  that whenever the asymmetric tier runs the answer is BROKEN, and that
  when it does not the era says `NOT_GRADED` rather than implying the
  signatures were fine.

## What this costs

One session of 864 entries, of which 852 are signed and verify, reads
BROKEN forever. That is the honest answer. The twelve entries in the
window are still hash-linked, still HMAC-authenticated under `K_chain`,
and still bound to their artifact bodies; what they are not is covered by
a signature, and no grade should say they are.

If that session's content matters for an audit, the supporting evidence
is this note plus the journal excerpt above, presented beside the
verifier output rather than folded into it.

## Follow-up

- `/etc/virp/keys/chain-sign.key` is `0600 virp:virp` as of 2026-09-07,
  so the condition that caused the crash loop is fixed. Whether the key
  should be **rotated** because it spent an unknown period at `0644` is
  an open decision: any local reader during that window could have copied
  it, and a copy is a forging capability for the whole chain from
  2026-08-23 onward. Rotating means a new `key_id` and a documented
  second cutover; not rotating means accepting that exposure. Nobody has
  ruled yet.
