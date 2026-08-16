# Bridge change: submit the middle body as `fed_observation`

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

## Why

`cbdc5d24` (Item 8) narrowed uid 993's `chain_append` to
`fed_request`/`fed_outcome`. The bridge's middle append — the signed
observation body — has been refused ever since, while the `fed_outcome`
citing it kept landing. 54 outcomes on the live chain cite evidence the
chain never stored.

The daemon side (branch `fix/fed-observation-link`) adds a third
externally-submittable type, `fed_observation`, and arms GATE 4: an
outcome whose cited body is not in `artifacts` is refused.

## The change

Exactly two things.

### 1. The middle append's `artifact_type`

```diff
     # 2/3 — the signed observation body: the evidence the outcome cites
     resp = chain_append(
         session_id     = session_id,
-        artifact_type  = "observation",
+        artifact_type  = "fed_observation",
         artifact_id    = f"ncfed-obs-{correlation[:32]}",
         artifact_hash  = hashlib.sha256(obs_raw).hexdigest(),
         artifact_content = "base64:" + base64.b64encode(obs_raw).decode(),
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
returns success. This is now enforced daemon-side — GATE 4 refuses an
outcome whose cited body is not yet stored — so a bridge that fires the
two concurrently, or that submits the outcome regardless, will lose the
outcome.

```python
# 1/3 — request provenance
if not append_ok(chain_append(artifact_type="fed_request", ...)):
    log.warning("fed_request append failed; continuing")   # non-fatal

# 2/3 — the signed body. FATAL: the outcome cites this.
obs_sha = hashlib.sha256(obs_raw).hexdigest()
resp = chain_append(
    session_id       = session_id,
    artifact_type    = "fed_observation",
    artifact_id      = f"ncfed-obs-{correlation[:32]}",
    artifact_hash    = obs_sha,
    artifact_content = "base64:" + base64.b64encode(obs_raw).decode(),
)
if not append_ok(resp):
    # Do NOT file an outcome citing a body that is not stored. That is
    # exactly the defect this change exists to end: an outcome that
    # reads like evidence and resolves to nothing.
    log.error("fed_observation append refused (%s) — withholding "
              "fed_outcome for correlation %s", append_err(resp), correlation)
    return   # the device read already happened and still returns to the
             # caller; only the provenance record is skipped

# 3/3 — the outcome, citing a body now known to be stored
chain_append(
    session_id       = session_id,
    artifact_type    = "fed_outcome",
    artifact_id      = f"ncfed-out-{correlation[:32]}",
    artifact_hash    = hashlib.sha256(out_json.encode()).hexdigest(),
    artifact_content = out_json,          # plain JSON, NOT base64
)
```

`out_json` keeps `"observation_sha256": obs_sha` — the same value passed
as the middle append's `artifact_hash`. Those two must be the identical
string; that identity is the whole link.

Never emit `"observation_sha256": null`. 16 rows on the live chain do,
and GATE 4 now refuses them.

## Reading the daemon's reply

`chain_append` responses are framed:

| Response | Meaning |
|---|---|
| **> 4 bytes** | success — a signed `CHAIN_ENTRY` observation whose payload is `{"chain_entry_hash", "previous_entry_hash", "sequence", "session_id", "signer_node_id", "signer_org_id"}` |
| **exactly 4 bytes** | typed error, big-endian **signed** int32 (negative) |

Errors worth distinguishing:

| Value | Name | Means |
|---|---|---|
| `-4` | `VIRP_ERR_INVALID_TYPE` | unknown `artifact_type` — **what today's daemon returns for `fed_observation`, until the daemon side is deployed** |
| `-50` | `VIRP_ERR_ACTION_FORBIDDEN` | Item 8 narrowing, or GATE 4 refusing an unbacked outcome |
| `-18` | `VIRP_ERR_CHAIN_BROKEN` | GATE 2 — declared `artifact_hash` != sha256 of the submitted body |

If the bridge currently treats "any 4-byte reply" as success, or ignores
the reply, that must change — the wait-on-success in step 2 depends on
reading it.

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

Then `make test-fed-outcome-observation` with
`VIRP_FED_SINCE=<deploy date>`, which scopes the audit to what the fixed
daemon wrote. The 54 pre-existing unbacked outcomes are **not** repaired —
the chain is append-only and those bodies were never stored, so they stay
as the honest record.
