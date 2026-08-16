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
adds a third, **retry idempotency**, after the 2026-08-16 live-chain
audit found 32 federation correlations carrying multiple *distinct*
stored bodies — the bridge requeues an unacknowledged submission and
re-serializes it each attempt (fresh timestamp → new hash → new
self-consistent body under the same correlation id; one `fed_request`
accumulated seven). Nothing was corrupted — GATE 2 passed each pair
honestly and the store keeps colliding ids side by side — but a
correlation that names seven different "requests" is provenance nobody
can read back as one event.

(The "50 FAILED entries" the 2026-08-16 report showed for these were a
verifier bug — it joined bodies by `artifact_id` alone instead of
`(artifact_id, artifact_hash)` — fixed on the same branch. The daemon
now also refuses the pattern at append time: **GATE 5**, error `-51`.)

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

### 3. Serialize once, hash once, hold the bytes

Every string the three appends send must be built **exactly once per
correlation**, at build time, and held. A retry — in-process or from the
requeue — resends the held byte-identical buffers. It never
re-serializes a dict, never refreshes a timestamp, never recomputes a
hash from anything but the held bytes.

**Where to hold them:** at the same scope and lifetime as the
correlation id itself. The moment the device read returns and the
correlation is minted, build the complete per-correlation record and
make *it* the thing the send path and the requeue both consume:

```python
rec = {
    "correlation": correlation,
    "session_id":  session_id,
    "req_json":    req_json,                                  # built once
    "obs_raw":     obs_raw,                                   # signed wire bytes
    "obs_sha":     hashlib.sha256(obs_raw).hexdigest(),       # hashed once
    "obs_b64":     "base64:" + base64.b64encode(obs_raw).decode(),
    "out_json":    None,                                      # filled below
}
rec["out_json"] = json.dumps({..., "observation_sha256": rec["obs_sha"]})
```

If the requeue persists to disk, it persists these strings — not the
inputs they were built from. If a rebuild is ever unavoidable (the held
record is gone), the rebuilt submission **mints a NEW correlation id and
abandons the old one**. Same correlation + different bytes must be
impossible in the fixed bridge; the daemon's GATE 5 now refuses it with
`-51` as a backstop, and `-51` in the bridge log means this requirement
has been violated (or a legacy pre-fix correlation is being requeued —
drop it).

**The null path must be unreachable.** 16 of the 54 unbacked outcomes
carry `"observation_sha256": null`. Find what currently produces that —
almost certainly a fallback of the shape `obs_sha if append_ok else
None`, or an outcome built before the observation exists — and delete
it. In the fixed flow `out_json` is built once from the held `obs_sha`
string, and an outcome is only ever submitted after the observation
append succeeded, so there is no state in which a null could be emitted.
GATE 4 refuses null citations anyway; the point is the bridge should
have no code path that tries.

### The full fixed flow

```python
# 1/3 — request provenance
if not append_ok(chain_append(artifact_type="fed_request",
                              artifact_id=f"ncfed-req-{correlation[:32]}",
                              artifact_hash=sha256_hex(rec["req_json"]),
                              artifact_content=rec["req_json"], ...)):
    log.warning("fed_request append failed; continuing")   # non-fatal

# 2/3 — the signed body. FATAL: the outcome cites this.
resp = chain_append(
    session_id       = rec["session_id"],
    artifact_type    = "fed_observation",
    artifact_id      = f"ncfed-obs-{rec['correlation'][:32]}",
    artifact_hash    = rec["obs_sha"],
    artifact_content = rec["obs_b64"],
)
if not append_ok(resp):
    # Do NOT file an outcome citing a body that is not stored. That is
    # exactly the defect this change exists to end: an outcome that
    # reads like evidence and resolves to nothing.
    log.error("fed_observation append refused (%s) — withholding "
              "fed_outcome for correlation %s",
              append_err(resp), rec["correlation"])
    return   # the device read already happened and still returns to the
             # caller; only the provenance record is skipped

# 3/3 — the outcome, citing a body now known to be stored
chain_append(
    session_id       = rec["session_id"],
    artifact_type    = "fed_outcome",
    artifact_id      = f"ncfed-out-{rec['correlation'][:32]}",
    artifact_hash    = sha256_hex(rec["out_json"]),
    artifact_content = rec["out_json"],       # plain JSON, NOT base64
)
```

`rec["out_json"]` carries `"observation_sha256": rec["obs_sha"]` — the
same value passed as the middle append's `artifact_hash`. Those two must
be the identical string; that identity is the whole link.

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
| `-51` | `VIRP_ERR_DUPLICATE_MISMATCH` | **GATE 5 — this correlation id is already stored with different bytes.** A retry re-serialized (requirement 3 violated), or a legacy pre-fix correlation was requeued | stop retrying this correlation; mint a new one or drop it. Never resubmit the same id with the same non-identical bytes |

If the bridge currently treats "any 4-byte reply" as success, or ignores
the reply, that must change — the wait-on-success in step 2 depends on
reading it. A byte-identical resubmission of something already stored
**succeeds** (fresh success frame, second chain entry recording the
retry, no second body row) — the retry loop needs no special case for
"it actually landed last time."

```python
def append_ok(resp):
    return resp is not None and len(resp) > 4

def append_err(resp):
    if resp is None:            return "no reply"
    if len(resp) != 4:          return "ok"
    return int.from_bytes(resp[:4], "big", signed=True)
```

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

After the daemon deploy, any **legacy** correlation still sitting in
netclaw's requeue from before the fix will draw `-51` (its id is already
stored under the old bytes). Expected once per legacy item: log it,
drop the item. It must not loop.

Daemon-first would hard-break federation and must not be done.

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
daemon wrote. The 54 pre-existing unbacked outcomes are **not** repaired —
the chain is append-only and those bodies were never stored, so they stay
as the honest record. The 32 pre-existing multi-body correlations
likewise stay; they are healthy side-by-side storage, correctly graded
once the verifier joins on `(artifact_id, artifact_hash)`.
