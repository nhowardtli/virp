# Bridge change: `fed_observation` + reply handling + retry idempotency (rev 2)

Target: **netclaw (10.0.30.30)**, the installed copy
`/usr/local/lib/virp/virp-bridge-mcp.py` — the file the running MCP
registration actually invokes. The repo copy under `~/netclaw/mcp-servers/`
is **not** the live one; edit the installed path (or edit the repo copy and
reinstall it, but verify the running registration resolves to what you
edited before believing the change is live).

Written from the wire contract, not from the file: this host cannot reach
netclaw (one-way trust — netclaw dials in over the ssh streamlocal forward,
and uid 993 is barred from originating IP connections by the nft egress
rule). Treat the code below as the specification and map it onto whatever
the bridge's actual append helper looks like.

## Rev 2 — what changed since rev 1

Rev 1 had two requirements (the type change and wait-on-success). Rev 2
adds a third, **correlation uniqueness**, after the 2026-08-16
live-chain audit found 32 federation correlations carrying multiple
*distinct* stored bodies. The mechanism — read from the real bridge
code, correcting this document's earlier requeue theory — is that
`corr = sha256(peer|request_id|device|command)` with `peer` and
`request_id` both `"unknown"` on every call, so **every repeat of the
same command on the same device, ever, minted the SAME correlation id**;
each invocation's body then differed by its `submitted_at` timestamp.
Six days of one Nexus poll landed as six distinct "request" bodies
under one artifact_id. Nothing was corrupted — GATE 2 passed each
self-consistent pair honestly and the store keeps colliding ids side by
side — but a correlation that names six different "requests" is
provenance nobody can read back as one event.

(The "50 FAILED entries" the 2026-08-16 report showed for these were a
verifier bug — it joined bodies by `artifact_id` alone instead of
`(artifact_id, artifact_hash)` — fixed on the same branch. The daemon
now also refuses the pattern at append time: **GATE 5**, error `-51`.
Consequence that makes the bridge fix MANDATORY before the daemon
deploy: under the unsalted scheme, every routine repeated read would
draw `-51` and federation would quietly break for repeat commands.)

## Why (rev 1 recap)

`cbdc5d24` (Item 8) narrowed uid 993's `chain_append` to
`fed_request`/`fed_outcome`. The bridge's middle append — the signed
observation body — has been refused ever since, while the `fed_outcome`
citing it kept landing. 54 outcomes on the live chain cite evidence the
chain never stored.

The daemon side (branch `fix/fed-observation-link`) adds a third
externally-submittable type, `fed_observation`; arms GATE 4 (an outcome
whose cited body is not in `artifacts` is refused); and arms GATE 5 (a
federation artifact_id reused with different bytes is refused).

## The change

Exactly three things.

### 1. The middle append's `artifact_type`

```diff
     # 2/3 — the signed observation body: the evidence the outcome cites
     resp = chain_append(
         session_id     = session_id,
-        artifact_type  = "observation",
+        artifact_type  = "fed_observation",
         artifact_id    = f"ncfed-obs-{correlation[:32]}",
         artifact_hash  = obs_sha,
         artifact_content = obs_b64,
     )
```

Nothing else about that append moves. In particular:

- `artifact_hash` stays `sha256(obs_raw)` over the **raw decoded wire
  message** — not over the `base64:` string. The daemon recomputes it the
  same way (`virp_chain_artifact_digest`) and GATE 2 refuses a mismatch
  with `-18`.
- `artifact_id` stays `ncfed-obs-<correlation[:32]>`.
- The body stays `base64:`-prefixed.
- `fed_observation` is 15 characters, which fits `artifact_type[16]`
  intact. Do not rename it.

GATE 3 verifies the signature on this body exactly as it does for
`observation`, so it must remain a genuine signed observation.

### 2. The outcome must wait on that append succeeding

The outcome may only be submitted **after** the observation append
returns success. This is enforced daemon-side — GATE 4 refuses an
outcome whose cited body is not yet stored — so a bridge that fires the
two concurrently, or that submits the outcome regardless, will lose the
outcome.

### 3. One correlation per invocation

The correlation hash gains per-invocation entropy, so each call to
`submit_federated_command` is its own correlation and a repeat of the
same read tomorrow is a *different* one (as applied on netclaw
2026-08-16):

```python
nonce = os.urandom(16).hex()
corr = hashlib.sha256(
    ("%s|%s|%s|%s|%.9f|%s" % (provenance["peer"],
                              provenance["request_id"],
                              device, command, now, nonce)).encode()
).hexdigest()
```

Within one invocation the three bodies are each built exactly once (the
existing code already does this — `chain_append` serializes its dict
argument once per call, deterministically). A transport-level resend of
the SAME invocation reuses `corr` with byte-identical content, which
the daemon accepts. If anything ever rebuilds a submission outside its
original invocation, the rebuild **mints a NEW correlation and abandons
the old one**. Same correlation + different bytes must be impossible in
the fixed bridge; GATE 5 refuses it with `-51` as a backstop, so `-51`
in the bridge log means the salting failed or a legacy pre-fix
correlation id was reused — either way stop, don't resubmit.

**The null path is closed by withholding, not by a new outcome form.**
16 of the 54 unbacked outcomes carry `"observation_sha256": null`,
produced by the error branch: when `gate_execute` returned
`error_code`, no observation existed, but step 4 still filed a
`fed_outcome` whose `result.get("observation_sha256")` was None. The
fix: on a transport/typed error the bridge records the outcome entry as
withheld in its return value and **returns before step 4** — no outcome
entry at all. A citation-free "transport error" outcome form was
considered and rejected: the deployed GATE 4 scanner deliberately
requires a quoted 64-hex citation, and defining a legal citation-free
outcome would re-open the exact hole GATE 4 closes. Nothing is lost:
the step-1 `fed_request` keeps the attempt request_id-correlated, the
caller sees `outcome: "error"` live, and the daemon journal holds the
typed error.

### The full fixed flow — as applied to `submit_federated_command`

Three changed regions, applied to the installed copy on netclaw
2026-08-16 (backup `virp-bridge-mcp.py.bak-20260816-rev2`):

1. **Correlation minting** — the nonce+timestamp salt above.
2. **Error branch** — on `error_code` from `gate_execute`, record the
   outcome entry as `withheld` in the returned `result["chain"]` and
   `return result` before step 4. Step 1's `fed_request` has already
   landed, so the errored attempt stays request_id-correlated.
3. **Step 3** — `artifact_type` becomes `"fed_observation"` (nothing
   else about the append moves), and after it:

```python
        if not ok:
            result["chain"]["outcome_entry"] = {
                "ok": False, "artifact_id": "ncfed-out-%s" % corr[:32],
                "withheld": "fed_observation append refused; an outcome "
                            "may not cite an unstored body",
                "observation_error": (receipt.get("error_code")
                                      if isinstance(receipt, dict)
                                      else None),
            }
            return result
```

Step 4 is unchanged: with regions 2 and 3 in place it is only reachable
when a stored observation exists, so `outcome_body["observation_sha256"]`
is always the real digest — the identical string passed as step 3's
`artifact_hash`. That identity is the whole link. `chain_append` itself
needed no changes: it already computes `sha256` over the exact bytes it
sends and already returns an `ok` flag distinguishing error frames.

## Reading the daemon's reply

`chain_append` responses are framed:

| Response | Meaning |
|---|---|
| **> 4 bytes** | success — a signed `CHAIN_ENTRY` observation whose payload is `{"chain_entry_hash", "previous_entry_hash", "sequence", "session_id", "signer_node_id", "signer_org_id"}` |
| **exactly 4 bytes** | typed error, big-endian **signed** int32 (negative) |

Errors worth distinguishing:

| Value | Name | Means | Bridge response |
|---|---|---|---|
| `-4` | `VIRP_ERR_INVALID_TYPE` | unknown `artifact_type` — **what today's daemon returns for `fed_observation`, until the daemon side is deployed** | withhold outcome; retry later (byte-identical) |
| `-50` | `VIRP_ERR_ACTION_FORBIDDEN` | Item 8 narrowing, or GATE 4 refusing an unbacked/null-citing outcome | withhold outcome; do not retry until fixed |
| `-18` | `VIRP_ERR_CHAIN_BROKEN` | GATE 2 — declared `artifact_hash` != sha256 of the submitted body | bug in the bridge's own hashing; do not retry |
| `-51` | `VIRP_ERR_DUPLICATE_MISMATCH` | **GATE 5 — this correlation id is already stored with different bytes.** With per-invocation salting this should never fire; if it does, the salting failed or a legacy pre-fix correlation id was reused | stop; never resubmit this correlation with different bytes. A fresh invocation mints its own correlation anyway |

The installed bridge's `chain_append` already reads the reply: its `ok`
flag is false on a typed-error frame and the error code is in the
returned receipt dict — the withhold logic keys off exactly that. A
byte-identical resubmission of something already stored **succeeds**
(fresh success frame, second chain entry recording the retry, no second
body row) — no special case needed for "it actually landed last time."

## Deploy ordering

**Bridge first is safe.** Between this change and the daemon deploy,
today's daemon rejects `fed_observation` at GATE 1 with `-4` — the same
refusal it already gives `observation`. Nothing degrades that was working.

One behaviour change in that window: with the wait-on-success above, the
bridge withholds the `fed_outcome` instead of filing a dangling one, so
**no `fed_outcome` lands at all** until the daemon is deployed. The device
read still executes and still returns to the caller; only the provenance
record is skipped. That is a cleaner failure than a dangling pointer, but
it is a change — keep the window short.

Daemon-first would break federation twice over: `fed_observation` never
landing is the rev-1 problem, and — with the unsalted bridge — every
routine repeat of a previously-run command would draw `-51` at step 1.
The salted bridge must be live before the daemon restarts.

## Verifying, after both sides are live

One real GREEN federated read, then read-only against the chain:

```sql
-- all three appends for one correlation
SELECT artifact_type, artifact_id, artifact_hash
FROM artifacts
WHERE artifact_id LIKE '%' || substr('<correlation>', 1, 32)
ORDER BY created_at_ns;

-- the link itself: must return exactly one row
SELECT a.artifact_type, a.artifact_id
FROM artifacts o
JOIN artifacts a
  ON a.artifact_hash = json_extract(o.artifact_content, '$.observation_sha256')
WHERE o.artifact_type = 'fed_outcome'
  AND o.artifact_id  = 'ncfed-out-<correlation[:32]>';
```

Then the retry drill: force one deliberate resubmission of the same
correlation and confirm it lands byte-identical **or** is refused —
never same-id-different-hash:

```sql
-- must return NO rows with created_at_ns after the deploy timestamp
SELECT artifact_id,
       count(*)                    AS bodies,
       count(DISTINCT artifact_hash) AS distinct_hashes
FROM artifacts
WHERE artifact_id LIKE 'ncfed-%'
GROUP BY artifact_id
HAVING count(DISTINCT artifact_hash) > 1
   AND max(created_at_ns) > <deploy_ns>;
```

Then `make test-fed-outcome-observation` with
`VIRP_FED_SINCE=<deploy date>`, which scopes the audit to what the fixed
daemon wrote. The pre-existing unbacked outcomes (55 by the time both
sides were patched: the original 54 plus one zammad-ro read that landed
through the old bridge at 2026-08-16 20:17 UTC, minutes before the
bridge edit) are **not** repaired — the chain is append-only and those
bodies were never stored, so they stay as the honest record. The 32
pre-existing multi-body correlations likewise stay; they are healthy
side-by-side storage, correctly graded once the verifier joins on
`(artifact_id, artifact_hash)`.
