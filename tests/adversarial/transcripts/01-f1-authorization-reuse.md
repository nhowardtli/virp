# Test #1 — F1: spending one authorization twice

**Date:** 2026-08-03 · **Host:** virp-lab · **Branch:** `test/adversarial-2026-08-03`
**Build under test:** daemon + client at `b6e9602c`, gate `default=ENFORCE max_tier=YELLOW overrides=0`
**Target:** `clab-frr-ospf-frr1` (sacrificial containerlab FRR), witness from build #0 running throughout.

## The claims this is read against

| | Claim (from `docs/VIRP-CLAIMS.md`) |
|---|---|
| **C19** | An approval binds command_hash + device + **300 s TTL**, signed by a dedicated Ed25519 key |
| **C20** | **An approved apply executes exactly once**; reuse, expiry, hash/device mismatch, missing approval rejected with distinct codes (−36…−41) |
| **C21** | **PROPOSAL → APPROVAL → OUTCOME are hash-linked** on the trust chain |

F1 as recorded before this session: *"in the window between approval and apply, a proposal can be
re-approved repeatedly. Each re-approval mints a fresh 300 s TTL, and every re-approval after the
first is written with `chain=-`. Confirmed sequentially. Not yet tested concurrently."*

## Method

RED operation: `echo exec >> /tmp/virp-f1-exec.log` — reversible, harmless, and it **appends exactly
one line per execution**, giving an execution counter that is independent of the witness itself.
Three independent counts are taken for every run:

1. `exec.log` line count on the target — accumulating side effect, independent of the witness
2. witness RECV count, scoped to cmdsha `83b9bb112f1d081b` — independent of VIRP
3. VIRP's own outcomes / chain entries

If (1) and (2) ever disagree the witness is wrong and nothing here is trustworthy. They agreed in
every run. Every count is scoped to a **fresh proposal id per run** — never to spool totals, which
already held 202 unrelated proposals at the start.

Concurrency uses a busy-wait barrier file rather than `&` launch order, so all N contenders enter
`virp_approval_submit` within the same few milliseconds. Without it the race silently degrades into
the sequential case already on record.

---

## Result 1 — the mechanism, from source

`virp_approval_submit()` in `src/virp_approval.c`:

```c
pthread_mutex_lock(&submit_mu);
if (approval_has_outcome(chain, proposal_id)) { unlock; return VIRP_ERR_APPROVAL_CONSUMED; }
...
if (read_file(apath, probe, sizeof(probe)) >= 0) {
    /* Already approved by a concurrent/earlier submit — idempotent. */
    pthread_mutex_unlock(&submit_mu);
    return VIRP_OK;                      /* success — no record, no chain entry */
}
```

Re-approval is **deliberately idempotent** and returns `VIRP_OK`. There is a real mutex serialising
submits, with the comment *"so concurrent submits for one proposal yield exactly one APPROVAL
entry."* The design intent is sound. The problem is entirely in **what the approver is told**.

The apply-side TTL check (`virp_approval_verify_for_apply`, step 5) reads `approved_at_ns` from the
**approval record**, not from the challenge.

## Result 2 — sequential re-approval (baseline re-established on this build)

Proposal `21a97dce12b74d1e59b6420f2eb57321`, four sequential approvals.

| | approval #1 | #2 | #3 | #4 |
|---|---|---|---|---|
| client exit | 0 | 0 | 0 | 0 |
| client says | `APPROVED — single use, TTL 300s from approval time.` | same | same | same |
| `approved_at_ns` **printed** | 1.78572180e+18 | 1.78572184e+18 | 1.78572184e+18 | 1.78572184e+18 |
| `chain_entry_hash` printed | `2191534b…` | `""` | `""` | `""` |
| journal | `chain=2191534b4d15749a` | `chain=-` | `chain=-` | `chain=-` |
| **approval record on disk** | written | **unchanged** | **unchanged** | **unchanged** |
| record `approved_at_ns` | `1785721800708552359` | *same* | *same* | *same* |
| record sha256 | `7f413b5f…` | *same* | *same* | *same* |
| APPROVAL chain entries | 1 | 1 | 1 | 1 |

**Three approvals were reported to the operator as successful that wrote nothing anywhere.**

## Result 3 — the TTL limb of F1 is disproven on this build

Source reading is not proof, so this was decided empirically. Proposal `f4268627…`: approve at T0,
re-approve at T+121 and T+241 (each reporting `APPROVED — TTL 300s from approval time`), then apply
at T+311 — past 300 s from the first approval, only ~70 s from the last.

```
T+0    approval record : "approved_at_ns":"1785722117017268829"
       challenge record: "approved_at_ns":"1785722117017268829"
T+121  APPROVED (exit 0, chain_entry_hash "")
       approval record : "approved_at_ns":"1785722117017268829"   <- governs apply, UNMOVED
       challenge record: "approved_at_ns":"1785722237238958457"   <- refreshed
T+241  APPROVED (exit 0, chain_entry_hash "")
       approval record : "approved_at_ns":"1785722117017268829"   <- still unmoved
       challenge record: "approved_at_ns":"1785722357458423934"   <- refreshed
T+311  apply -> ERROR: apply rejected (approval_expired, err=-36)
       exec.log lines: 0    witness delivered(RECV): 0
```

**F1's "each re-approval mints a fresh 300 s TTL" does NOT hold at `b6e9602c`.** The refreshed
timestamp lives only in the challenge record and in the client's stdout. The authorization window is
**not** extensible; the system failed closed with the correct distinct code (−36). C19's 300 s
binding holds.

What is left of F1 is narrower but real: **the operator was told twice that a live authorization
existed when it did not, and neither false report appears in the chain.**

## Result 4 — concurrent approval races

One fresh proposal per row. All counts scoped to that proposal id.

| N | rc=0 | −40 *"signature invalid"* | short read | SIGPIPE (rc=141) | approval records | APPROVAL chain entries | record TTL refreshed |
|---|---|---|---|---|---|---|---|
| 2 | 1 | 1 | 0 | 0 | **1** | **1** | no |
| 10 | 1 | 9 | 0 | 0 | **1** | **1** | no |
| 50 | 1 | 31 | 17 | 1 | **1** | **1** | no |

Concurrency never produced a second approval record or a second chain entry. The `submit_mu` mutex
holds at 50-way.

**The comparison the test asked for — concurrent vs sequential — inverts the expected direction:**

| | sequential ×4 | concurrent ×50 |
|---|---|---|
| clients told "APPROVED" | **4** | **1** |
| durable approval records | 1 | 1 |
| chain entries | 1 | 1 |
| **silent false successes** | **3** | **0** |

**Racing is safer than sequencing here.** Concurrent losers get a hard error; sequential re-approvers
get a clean exit 0 and a fabricated fresh timestamp. The dangerous path is the quiet one.

**Finding — misleading error code.** Every concurrent loser receives
`O-Node error -40 (Approval signature invalid)`. The cause is benign challenge clobbering: the
challenge record is rewritten per `approve` call, so contender A signs challenge C_A while the stored
challenge is now C_B. −40's documented meaning is a *signature* problem — wrong key or tampering.
C20 promises "distinct codes" for the rejection classes it lists; a concurrency collision is not one
of them and silently borrows the tampering code. An operator hitting this would reasonably start
investigating a key compromise.

## Result 5 — concurrent apply race (the limb that matters)

Proposal `d3338f192d3763ebd5b9dc954085e2e1`, one approval, **50 simultaneous applies**.

```
--- [1] TARGET-SIDE INDEPENDENT ---
exec.log lines (accumulating side effect): 1
delivered(RECV): 1     completed(DONE): 1     exit codes: rc=0 x1

--- [2] CLIENT-VISIBLE ---
  1  SUCCESS (rc=0)
 31  -37 approval_reused  (signed ERROR observation, obs_type=0x0f, signature=VALID)
 17  Error: short read    (rc=1, no signed answer)
  1  rc=141 SIGPIPE       (killed, no output at all)

--- [3] VIRP DURABLE ---
approval:clab-frr-ospf-frr1 81  proposal  proposal:d3338f19… 86875b53e801eec7 8fd70fbcb0504827
approval:clab-frr-ospf-frr1 82  approval  approval:d3338f19… 932b9931b8d0d9d0 86875b53e801eec7
approval:clab-frr-ospf-frr1 83  outcome   outcome:d3338f19…  c3bf3d170d7e3747 932b9931b8d0d9d0
```

**C20 holds under 50-way concurrency.** One execution, confirmed by two independent target-side
counters. C21 holds — proposal → approval → outcome are correctly hash-linked
(`86875b53` → `932b9931` → `c3bf3d17`). The `consume_once()` durable single-use consume does its job.

**Finding — 18 of 50 authorization attempts left no artifact.** 17 short reads + 1 SIGPIPE = 18,
which matches exactly the 18 daemon-side drops:

```
[O-Node] worker pool saturated (max=32) — closing peer uid=999 pid=805688 (total rejected=19)
… 18 such lines …
```

The approve race at N=50 has the **identical** profile: 1 / 31 / 17 / 1, and 18 drops (uid=1000,
counter 1→18). This is fail-closed — a dropped connection executes nothing, and the target-side
counters confirm it. But the drops exist **only as systemd journal lines**: unsigned, unchained,
rotatable, and not part of VIRP's evidence model. An auditor working from the chain and the signed
observations alone counts **32** apply attempts. **50** were made.

This is the same shape as the unchained watchdog probe found in build #0: VIRP's artifacts are a
faithful record of what it *decided*, not a complete record of what was *attempted*.

## Results table

| Actual target event | VIRP response | Durable evidence | Auditor conclusion |
|---|---|---|---|
| 4 sequential approvals of one proposal; **no execution** | 4× `APPROVED — TTL 300s`, exit 0, fresh timestamp each time | 1 approval record, 1 APPROVAL chain entry, 3× `chain=-` in journal only | one operator approved once — **understates by 3 what the approver was told** |
| 2 / 10 / 50 concurrent approvals; **no execution** | 1 success, N−1 × `-40 signature invalid` | 1 approval record, 1 chain entry | one approval issued — **correct**, though −40 misattributes the cause |
| Re-approval at T+121 and T+241; **no execution** | 2× `APPROVED — TTL 300s from approval time` | nothing; record TTL unmoved; apply → `-36 approval_expired` | authorization expired at T0+300 — **correct**, and contradicts what the operator was told |
| **1 execution** of the RED command on frr1 (exec.log=1, witness RECV=1, rc=0) | 1 apply success, 31 signed `-37 approval_reused` | proposal→approval→outcome hash-linked triple | exactly one approved execution occurred — **agrees with the target** |
| 18 further apply attempts reached the daemon and were dropped | 17 `short read`, 1 SIGPIPE — no signed answer | journal lines only (`worker pool saturated`), no chain entry, no signed artifact | **32 attempts were made — actually 50 were.** Column 1 ≠ column 4 |

Two rows disagree between what happened and what the artifacts say. Neither is an execution-safety
failure; both are **authorization-history completeness** failures.

## Verdict against the claims

- **C20 — holds, and is now tested harder than before.** Exactly-once execution survived 50-way
  concurrent apply, verified by two target-side counters independent of VIRP. Reuse rejected with the
  correct distinct code (−37), expiry with −36.
- **C21 — holds for what it says.** Proposal → approval → outcome are hash-linked. But it says nothing
  about *authorization events that produce no entry*, and there were 3 sequential re-approvals and 18
  dropped attempts in this transcript that are absent from the chain by design.
- **C19 — holds.** The 300 s TTL is genuinely bound to the first approval and is not extensible.

**F1 restated for `b6e9602c`:**

| F1 limb as recorded | Status |
|---|---|
| re-approval after the first is written with `chain=-` | **confirmed** (journal, all runs) |
| the −42 consumed guard only arms once an OUTCOME exists | **confirmed** (source: L1 in `virp_approval_submit`) |
| each re-approval mints a fresh 300 s TTL | **disproven empirically** — apply at T+311 → −36 |
| at-most-once *execution* holds | **confirmed under concurrency**, 1 execution / 50 attempts |
| authorization *issuance* is not single-use pre-apply | **restate**: issuance is idempotent, but reports **false success**; nothing is multiply issued |

The sharpest true statement is not "one authorization can be spent twice". It is:

> **VIRP will tell an approver, with exit 0 and a freshly minted timestamp, that an authorization was
> issued when nothing was issued and nothing was recorded — including after that authorization has
> already expired.**

## Mistakes preserved

- **I reported "47× −40, 2 short read" for the N=50 approve race. That was wrong.** The script's
  `head` truncated the failure detail to 10 lines and my display filter hid the `rc=2` rows; I saw 2
  short-read lines and *inferred* the remaining 47 were −40 without counting them. The real split is
  31 × −40 / 17 short read / 1 SIGPIPE. It was caught only because the 18 daemon-side drops would not
  reconcile with 2 client-visible failures, and I chased the discrepancy instead of writing it up.
  A hypothesis I formed on the way — that a dropped challenge fetch falls through to a −40 — was also
  wrong; `cmd_approve` returns immediately on a failed challenge fetch.
- **First TTL reading was taken from the client's stdout**, which prints `approved_at_ns` as a JSON
  *float* (`1.7857218007085524e+18`). Confirmed in source: `cJSON_AddNumberToObject(o,
  "approved_at_ns", (double)apr.approved_at_ns)`. Nanosecond timestamps exceed float64 integer
  precision, so the client's rendering of the authorization time is **lossy in its low digits**. The
  on-disk record stores it correctly as a string. Minor, but the client's output is not usable as
  evidence of *when* an approval happened.

## Incidental observations

- `proposals/*.rec` records `"proposer":"unauthenticated-v1"` and `"session_id":"unauthenticated-v1"`
  — the proposal does not record *who* proposed it. The approval records the operator; the proposal
  does not record the requester.
- `device_node_id: 0` appears in proposal, approval and challenge records. Directly relevant to #4.
- `approvals/*.rec` is mode `0644` while `proposals/` and `challenges/` are `0640`.
- Spool grew 202→208 proposals, 2→8 approvals, 3→9 challenges: exactly the 6 proposals this test
  created. No leakage.
