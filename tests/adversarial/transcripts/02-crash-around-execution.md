# Test #2 — Crash around execution

**Date:** 2026-08-03 · **Host:** virp-lab · **Branch:** `test/adversarial-2026-08-03`
**System under test:** `build-fi/virp-onode-prod` at `b6e9602c` + fault-injection, run in the
foreground against an isolated socket/chain/spool. Witness from build #0 running throughout.

## The claims this is read against

- **C20** — an approved apply executes exactly once; reuse rejected, *reuse surviving daemon restart*
- **C21** — PROPOSAL → APPROVAL → OUTCOME are hash-linked on the trust chain

The state being hunted: **TARGET: operation happened / VIRP: no durable outcome.**

## Isolation (rule 3), verified not asserted

| | |
|---|---|
| binary | `build-fi/virp-onode-prod`, built by `make onode-fi` into `BUILD_DIR=build-fi` |
| define | `-DVIRP_FAULT_INJECT` via the existing `CFLAGS_EXTRA` hook |
| socket / chain / spool | `/run/virp-fi/{onode.sock,chain.db,approvals}` — production never contacted |
| keys | freshly generated for the lab; the production O-Key and approver key are never used |
| how it dies | `kill(getpid(), SIGKILL)` — **not** `abort()`/`exit()`, which would run atexit handlers and flush stdio, quietly persisting state a real crash destroys |

Verified after the fact:

```
FI symbol in build-fi binary          : 2      FI string: 1
FI symbol in rebuilt PROD binary      : 0      FI string: 0
/usr/local/lib/virp/virp-onode-prod   : db8f3fab…d5154  (unchanged from session start)
running daemon exe                    : /usr/local/lib/virp/virp-onode-prod
virp-onode-fi in install dir          : absent
```

The instrumentation lives in the shared sources, so the prod binary was **rebuilt from the
instrumented tree** and checked to contain no trace of it.

## The path under test

```
A. virp_approval_verify_consume()  -> consume_once() writes consumed.list   DURABLE
B. drv->execute()                  -> TARGET EXECUTES
C. virp_build_observation_v2()     -> signed observation built
D. approval_emit_outcome()         -> virp_chain_append()  then  virp_chain_artifact_store()
```

The authorization is **durably spent before the device is touched**, and the outcome is written
**after**. Crash points were placed at every boundary: `pre_consume`, `post_consume`, `pre_exec`,
`post_exec`, `pre_outcome`, `mid_outcome` (between the two calls in D), plus an **in-flight**
external SIGKILL that no code boundary chooses.

Target operation: `echo fi >> /tmp/virp-fi-exec.log` — RED by absence, reversible, and it appends
one line per execution. Three independent counts per run: the target's own accumulating file, the
witness RECV/DONE pair, and VIRP's chain.

---

## Results — every boundary

| crash point | target executed | `consumed.list` | chain outcome | client saw | retry after restart |
|---|---|---|---|---|---|
| *none* (control) | **1** | 1 | 1 (body present) | success, signed obs | `-37`, no re-execution |
| `pre_consume` | 0 | 0 | 0 | `Error: short read` | **succeeds**, executes once — correct |
| `post_consume` | **0** | **1** | 0 | `Error: short read` | `-37`, no execution |
| `pre_exec` | **0** | **1** | 0 | `Error: short read` | `-37`, no execution |
| `post_exec` | **1** | 1 | **0** | `Error: short read` | `-37`, no re-execution |
| `pre_outcome` | **1** | 1 | **0** | `Error: short read` | `-37`, no re-execution |
| `mid_outcome` | **1** | 1 | 1 entry, **body absent** | `Error: short read` | `-37`, no re-execution |
| **in-flight SIGKILL** | **1 — completed 4 s after the daemon died** | 1 | **0** | `Error: short read` | — |

**C20 is never violated.** No boundary produced a second execution. The durable
`consume_once()` holds across process death, which is exactly what "reuse surviving daemon restart"
promises. `pre_consume` correctly allows a retry because nothing was spent.

### The state exists, and it is reachable three ways

`post_exec`, `pre_outcome` and the in-flight kill all land on:

> **the target executed the RED command, and VIRP's chain contains no outcome.**

Independently confirmed each time by two target-side counters that do not consult VIRP
(`exec.log` line count = 1, witness `delivered(RECV)=1 completed(DONE)=1 rc=0`).

The in-flight case is the one that matters operationally, because nothing about it is contrived:

```
target state at kill time:
    slow.log : started 90791          <- operation began
    exec.log :                        <- not yet finished
    >>> SIGKILL sent to daemon
--- after waiting out the operation ---
    slow.log (began)     : started 90791
    exec.log (completed) : fi-slow-COMPLETED 90791     <- finished ANYWAY
```

**The device completed the operation four seconds after VIRP ceased to exist.** Losing the daemon
does not abort, undo, or even interrupt work already handed to the target. Any claim that a crashed
VIRP means "the operation did not happen" is false.

### The disabling detail: these states are indistinguishable

| crash point | did the device execute? | chain contents |
|---|---|---|
| `post_consume` | **no** | proposal + approval, no outcome |
| `pre_exec` | **no** | proposal + approval, no outcome |
| `post_exec` | **yes** | proposal + approval, no outcome |
| `pre_outcome` | **yes** | proposal + approval, no outcome |
| in-flight kill | **yes** | proposal + approval, no outcome |

Five different physical realities, **one chain state**. From VIRP's artifacts an auditor cannot tell
whether the device was touched. Worse, the safe reading and the dangerous reading are the same
shape: "an approval that was never applied" and "an approval that was applied and whose result was
lost" are byte-identical on the chain.

The spool holds one extra bit — `consumed.list` separates `pre_consume` from the rest — but it does
**not** separate `post_consume` (burned, device untouched) from `post_exec` (device executed). It is
also a spool file, not chain evidence: unsigned, un-hash-linked, and outside everything C21 covers.

### `post_consume` — a finding in the opposite direction

Crash after the authorization is spent but before the device is contacted:

- device: **nothing happened**
- VIRP: authorization **permanently burned**, `-37` forever, no chain record of why

Fail-closed and safe, but it is a **silent denial of authorization**: the approval is destroyed, the
chain shows an approval that simply never produced an outcome, and nothing anywhere records that the
operation was never attempted. The operator must obtain a fresh approval with no artifact explaining
the first one's fate.

### `mid_outcome` — a chain entry committing to evidence that does not exist

`approval_emit_outcome()` calls `virp_chain_append()` and then `virp_chain_artifact_store()`. The
append is transactional (`BEGIN IMMEDIATE` → `COMMIT`); the artifact store is a **separate call
outside that transaction**. Killing between them:

```
artifact_id                    entry_commits_to    body
proposal:6706791f…             9b31b76c946ce7ab    len=342
approval:6706791f…             4473f235d9a1af92    len=311
outcome:6706791f…              084ec9b615015718    *** BODY MISSING ***
```

The chain asserts an outcome exists and commits to its hash; the object is unrecoverable. The
hash-link is intact, so **C21's "hash-linked" property survives while the evidence does not**.

## The verifier

`virp_chain_verify_session()` exists and is good — per-entry HMAC, prev-hash linkage, and (since
2026-08-01) completeness against a signed head record. **But it is not exposed by the CLI.**
`virp chain` offers only `tail`, which prints entries and verifies nothing. An auditor handed a
`chain.db` has no shipped command to run. I had to write one
(`tests/adversarial/verifier/virp-chain-verify.c`) to complete this transcript.

Run against the crash-damaged lab chain — three unrecorded executions, one burned authorization, one
body-less outcome:

```
approval:clab-frr-ospf-frr1      VALID  entries=21  to_seq=20
gate-enforce:clab-frr-ospf-frr1  VALID  entries=9   to_seq=8

-- entries committing to an artifact body that is NOT stored --
   approval:… seq=18 outcome:6706791f… commits to 084ec9b615015718... (body absent)

sessions verified=2 broken=0  entries-with-missing-body=1
```

**Both sessions VALID.** VIRP's own verification passes on a chain that is materially wrong about
what happened to the device. The body-absence line is from a check I added; it is not part of VIRP's
verification.

### Production control

The same verifier over a **copy** of the production chain (never verified in place):

```
sessions verified=43 broken=0  entries-with-missing-body=21
```

All 43 sessions valid. Of the 21 body-less entries, **20 are `gatereject-*`** — the known pre-fix set
described in DEPLOYED.md "Update 2026-07-30 — gate-reason retention", not a new problem. The 21st was
a today-dated `obs:librenms-lab:…` entry, which I checked before reporting: **the body is present in
the live database.** The copy caught the daemon between `chain_append` and `artifact_store` — the
same non-atomic window `mid_outcome` exploits, here reached by snapshotting rather than crashing.
That is worth stating on its own: **any backup or snapshot of the chain DB can capture an entry
without its body**, and would fail an integrity check that a live read passes.

## Results table

| Actual target event | VIRP response | Durable evidence | Auditor conclusion |
|---|---|---|---|
| RED command executed once (exec.log=1, witness RECV=1 rc=0), daemon killed at `post_exec` | `Error: short read` — no signed answer | proposal + approval, **no outcome**; approval consumed | "approved, never applied" — **the device was changed** |
| RED command executed once, daemon killed at `pre_outcome` | `Error: short read` | proposal + approval, **no outcome** | identical to the row above and to the two rows below — indistinguishable |
| Operation **completed 4 s after the daemon died** (in-flight SIGKILL) | `Error: short read` | proposal + approval, **no outcome** | "approved, never applied" — **false** |
| **Nothing executed**; daemon killed at `post_consume` | `Error: short read` | proposal + approval, **no outcome**; approval consumed | same artifacts as the executed cases — **safe reality, identical evidence** |
| RED command executed once, killed at `mid_outcome` | `Error: short read` | outcome **entry** present, artifact **body absent**; chain still verifies VALID | "executed, outcome recorded" — the outcome cannot be produced |
| Nothing executed; killed at `pre_consume` | `Error: short read` | proposal + approval, nothing consumed | correct; retry legitimately succeeds |

Rows 1–4 have **column 1 and column 4 in direct disagreement**, and rows 1–4 are mutually
indistinguishable from the artifacts alone. Flagging that loudly: this is the sharpest
column-1-vs-column-4 divergence found so far in this program.

## What this does and does not mean

It does **not** doom VIRP, and the prompt already anticipated why: remote side effects are inherently
ambiguous. No protocol can guarantee that a process which dies mid-operation knows what the far side
did. C20 is intact — nothing executed twice, ever, at any boundary.

What it determines is **what VIRP may truthfully claim**. Today the artifacts support:

> "every execution VIRP recorded happened exactly once"

They do **not** support:

> "every execution that happened was recorded"

and the gap between those two sentences is invisible in the chain. An auditor reading a
proposal+approval with no outcome will naturally conclude the operation did not run. On this
evidence that conclusion is unsound.

## Scope limits of this test — stated so nothing is overclaimed

1. **SIGKILL is process death, not power loss.** The chain runs `journal_mode=WAL` with
   `synchronous=NORMAL`, which survives process death but does **not** guarantee a committed
   transaction against host power loss. Every "the chain entry survived" result here is a statement
   about process crash only. Power-loss durability is untested.
2. **One driver.** Only `linux`/SSH. The API drivers (wazuh, librenms, pbs) have different
   in-flight semantics and are not covered.
3. **The witness sees SSH only**, and is inside the target (build #0 §7).

## Mistakes preserved

- **First control run failed with `cannot connect`** — the lab daemon refused the target because it
  had no `known_hosts` entry: `[SSH-HK] Unknown host key … Set VIRP_SSH_TOFU=1 or add key manually`.
  That is the control working correctly, fail-closed, no TOFU. Fixed by seeding via `ssh-keyscan`
  and then **verifying the three scanned keys are byte-identical to the ones production already
  trusts** for 172.20.20.5, so the lab trusts nothing production does not.
- **Second control run failed with `cannot load proposal … from /var/lib/virp/approvals`** — `virp
  apply` reads the proposal from a local `--dir` that defaults to the *production* spool. The isolated
  run needed `--dir /run/virp-fi/approvals`. Worth noting beyond my error: **`apply` silently reads
  the production spool by default even when `--socket` points elsewhere**, so the two flags can
  disagree about which VIRP instance you are talking to.
- **My first known_hosts comparison compared against the wrong file** — I overwrote `kh_prod.txt`
  with a second `sudo cat` of a path that does not exist (`/var/lib/virp/known_hosts`), producing an
  empty file and a bogus "DIFFER" result. The real file is `/var/lib/virp/.virp/known_hosts`. Redone;
  it matched.
- **`--spki` was the wrong enroll flag** for a raw 32-byte public key (`Error: bad base64 SPKI`);
  `--key` is correct. The `||` fallback in my counter printed `0` twice for a missing
  `consumed.list`, briefly making the output read as two fields. Both fixed mid-run.
- **I nearly reported a production integrity gap that was not one.** The verifier flagged a
  today-dated observation with a missing body in my production *copy*. Checking the live database
  first showed the body present — a snapshot race, not a gap. The check turned into a finding in its
  own right, but only because I did not report the first reading.
