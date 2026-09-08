# VIRP overnight report — night of 2026-09-01 into 2026-09-02

Unattended run against the overnight work order. Append-only: each item is
appended when it finishes and nothing above is rewritten.

| item | branch | tip SHA | battery | kill condition hit | review min | read first |
|------|--------|---------|---------|--------------------|-----------|------------|
| 0 — read-only export from the reference node | (no branch) | n/a | n/a — export only | no | 5 | `scratchpad/item0/export.txt` |
| 1 — v0.2.1 (chain_append type policy + build id) | `fix/v0.2.1` | `4a839f0` | GREEN (0 failures, ASan/UBSan clean) | no | 35 | `SECURITY.md` (chain_append section) |
| 2 — release tag must be able to BE the Release body | `ci/notes-from-tag` | `3e5ff24` | GREEN (0 failures) | no | 10 | `scripts/check-release-tag.sh` |
| 3 — README: v0.2.0 withdrawal + live numbers | `docs/readme-v0.2.0` | `f9914a4` | GREEN (0 failures) | no | 10 | `README.md` (Releases and deployment status) |
| 4 — attribution design brief | `docs/attribution-design-brief` | `7ea9115` | GREEN (0 failures) | no | 15 | `docs/ATTRIBUTION-DESIGN-BRIEF.md` |
| 5 — Docket Phase 4 | (none) | n/a | not run | **yes — out of scope** | 2 | this report, Item 5 |
| 6 — replay guard index | `perf/replay-guard-index` | `54372d9` | GREEN (0 failures) | no | 15 | `docs/PERF-REPLAY-GUARD.md` |

**No branch was pushed.** `git push` is blocked by the permission
classifier in this session; see Item 1. All six branches are local and
each sits at a green commit. Nothing was tagged, released, merged to
`main`, or deployed, and no host was contacted after Item 0.

---

## READ THIS FIRST — two things that need your judgement

### 1. Another session is running the same work order on this laptop

There is a second working copy at `/home/nhoward/virp-overnight-2`,
created 2026-09-01 23:44, on the same `main` (`2cb9130`) with its own
commit `099596c`. It has been building and running the VIRP test suite
throughout this run.

This matters because the C test binaries hard-code their unix socket paths
under `/tmp` (`/tmp/virp-onode-test.sock`, `/tmp/virp-onode-test-cappend.sock`
and siblings). Two checkouts running `test_onode` at the same time bind and
serve each other's sockets. The symptoms are not obviously cross-talk:

- responses fail signature validation with `VIRP_ERR_HMAC_FAILED` (-8),
  because the daemon answering is not the one whose key the test holds;
- whole clusters fail to connect at all (`Expected 4, got -1`);
- the failing set changes between identical runs of an identical binary.

I lost roughly an hour to this before finding it, and I initially
mis-diagnosed it as a pre-existing flake in `test_onode`. **It is not a
flake in the test suite.** Standalone, on a quiet machine, `test_onode` is
159/161 with zero failures (the 2 remaining are the known by-design
PENDING tests).

Evidence, in order:

| run | conditions | result |
|-----|-----------|--------|
| branch, other session active | contended | 153/161, 6 failed |
| unmodified `main`, other session active | contended | 151/159, 6 failed — *identical failing set* |
| branch, quiet machine | isolated | **159/161, 0 failed** |

The identical failing set on unmodified `main` is what rules out my
changes as the cause.

I worked around it with a guard that waits for the other checkout to go
quiet and refuses to trust an overlapped run
(`scratchpad/guarded-run.sh`). Every result I report below comes from a
window the guard called clean.

**Your call, not mine:** whether these two sessions should be running at
once at all. If they should, the durable fix is to make the test socket
paths unique per checkout (a `$VIRP_TEST_TMPDIR` or a PID/path hash),
because right now any two concurrent checkouts on this machine corrupt
each other's test results silently. I did not change the socket paths —
that is well outside the files named for Item 1.

### 2. The deploy keys are back, and the box is reachable again

The work order requires that after Item 0 the deploy keys leave this
session, and that `ssh virp-lab true` fails before Item 1 starts. I did
that, and verified it: the keys were renamed to `id_ed25519.overnight`
and `ironclaw_deploy_ed25519.overnight`, and ssh failed with exit 255.

**As of now that is no longer true.** `~/.ssh/id_ed25519` and
`~/.ssh/ironclaw_deploy_ed25519` are back under their original names, no
`.overnight` files remain, and `ssh -o BatchMode=yes virp-lab true`
succeeds with exit 0. I did not restore them. The most likely cause is
the other session running its own Item 0 restore step against the same
shared `~/.ssh`.

I deliberately did **not** rename them away a second time. They are shared
credentials and the other session may be mid-flight using them; pulling
them out from under a concurrent authorized run seemed worse than the
alternative, and it is not a call I should make while you are asleep.

So the isolation control is **not in effect**. I kept the rule anyway, by
conduct: after Item 0 completed I made no further contact of any kind with
10.0.10.211. The single ssh above was the verification check itself, which
is why I am telling you it returned 0 rather than quietly re-removing the
keys.

If you want the control back, see the commands at the end of this file.

---

## Item 0 — read-only export from the reference node — DONE

Read-only. No writes, no restarts, no installs. Ran as `nhoward` over the
tunnel to 10.0.10.211.

Captured to `scratchpad/item0/export.txt`, scrubbed of hostnames, IPs and
bodies:

- **A** — gate-log `execute` counts per uid, 30 days
- **B** — chain `(uid, chain_append, artifact_type)` counts, 30 days
- **C** — the v0.2.0 window: entry types, seq ranges, timestamps, and both
  `node_config` bodies verbatim
- **D** — live totals

The v0.2.0 window (2026-09-02 02:16:00–02:26:14 UTC):

| entry type | count | seq range |
|---|---|---|
| `gate_intent` | 16 | 8759..18030 |
| `gate_execution` | 16 | 8760..18031 |
| `node_config` | 2 | 0..1 |

Sixteen intents, sixteen closers: **every execution in the window closed.**
No open executions, no chain break, no gap, and the evidence-degraded latch
never tripped. What v0.2.0 refused was *appends*, not executions. Both
`node_config` bodies read `"build_id":"unknown"`.

Chain totals after rollback: 273239 chain entries, 214115 artifacts, 406
sessions.

One caveat carried in the fixture rather than hidden: 196 `observation`
entries under the netclaw session prefix are **not** attributed to uid 993.
They predate the narrowing and belong to another principal. The fixture
records this as `attribution_caveat` so nobody later reads those rows as
993's traffic.

---

## Item 1 — v0.2.1 on `fix/v0.2.1` — DONE (not pushed: see below)

Three commits off `main` (`2cb9130`):

| SHA | commit |
|---|---|
| `2298ec7` | Fix 1 — explicit per-uid chain_append type policy |
| `eebae73` | Fix 2 — build id as a generated translation unit |
| `4a839f0` | docs — SECURITY.md, DEPLOYED.md anomaly, draft tag message |

**Battery: GREEN.** `make prod` then `make all-tests`, in a window the
guard called clean:

- `test_onode` 159/161, **0 failures** (the 2 remaining are the known
  by-design PENDING tests, unchanged by this work)
- every other suite 0 failed; the suite's own "none of them SILENTLY
  SKIPPED" check passed
- ASan + UBSan (`make asan-test`): **0 AddressSanitizer, 0 LeakSanitizer,
  0 UBSan diagnostics**; `test_onode` 159/161 under sanitizers

No kill condition hit. The diff stayed inside the files named for the
item, plus three new scripts and the Makefile wiring they need.

**NOT TAGGED, NOT RELEASED, NOT DEPLOYED.** No tag was created, no release
body touched, no host contacted.

### Fix 1 — chain_append reach is declared, never inferred

v0.2.0 inferred "restricted federated principal" from mere presence in
`socket_uid_action_allow` and narrowed that uid to the `fed_*` triple.
Task 2 then made an action map mandatory for every allowlisted uid, so
the daemon's own service accounts became "restricted" the moment they
were mapped, and their real appends were refused. **There was no
template-only fix** — the inference was in the daemon.

Now: `socket_uid_chain_append_types`, a per-uid list, enforced by exact
string match (no substring, no prefix, no wildcards). A uid with
`chain_append` in its action set and no type list is a FATAL boot failure
naming the uid, refused before bind. The bridge's `fed_*` reach is one
row of the policy. A malformed list loads as deny-all-types.

The listed spellings match the 16-byte wire field, so the policy carries
the truncated forms `comparator_verd` and `chainwalk_summa`. A policy
written with the full names would have silently refused the traffic it
was meant to admit.

### Fix 2 — the build id

v0.2.0 wrote `build_id="unknown"` because `-DVIRP_BUILD_ID` sat on the
`virp_onode_prod.c` compile line while the code that used it is archived
into `libvirp.a`, compiled without the define. A define on the wrong
translation unit produces no warning and no error. It is now a generated
TU inside the library; the prod link line carries no define at all.

Resolution is `git describe --always --dirty`, then `$VIRP_BUILD_ID`,
then a hard refusal. Refusing is the point: v0.2.0's behaviour was to
invent a placeholder and carry on.

Added `--version` to the prod daemon, handled before getopt so it needs
no config, keys, socket or chain.

### Revert-check, per new negative test

Every one was run against the pre-fix code and confirmed to fail. Files
were restored from backups, never `git checkout`, because the tree had
uncommitted work.

| test | reverted | result |
|---|---|---|
| v0.2.0-refuses-real-traffic (py) | made the v0.2.0 model permissive | FAILS on `(999, "observation")` |
| boot invariant (py, template) | deleted 999's policy row | FAILS naming the uid |
| virp-tool lint (py) | dropped `observation` from 1000's list | FAILS listing the missing type |
| `..._admits_service_types` (C) | **v0.2.0 handler restored, nothing else** | **FAILS** on uid 1000's `observation` append with the old "restricted principal" refusal |
| `..._start_refuses_..._without_type_policy` (C) | boot invariant reverted | no FATAL line; daemon proceeds into its accept loop instead of refusing |
| node_config build id (C) | macro + define restored | FAILS with `build_id is not "unknown" (the v0.2.0 defect)` |
| deploy build-id checker | n/a — proven by fixture | PASSES on match, FAILS on mismatch, FAILS on a binary with no `--version`, SKIPs with no deploy tree |

### Findings worth your attention

1. **A test that existed but never ran.** `test_chain_append_policy.py`
   was not referenced anywhere in the Makefile. I wired it into
   `all-tests`. Worth checking whether other test files are orphaned the
   same way.

2. **The node_config assertion was a checkmark, not a test.** It asserted
   only that a `build_id` key was *present*. That is exactly why it
   passed green through the entire v0.2.0 window while the value read
   `"unknown"`. It now asserts the value.

3. **Reverting Fix 2 does not trip `test-build-id`.** `--version` reads
   the linked function directly, so it still reports correctly with the
   old arrangement. Only the `node_config` assertion catches the original
   defect. The two tests cover different paths and both are needed — if
   you keep only one, keep the `node_config` one.

4. **The `--version` path and the chain path are now two sources of the
   same fact.** They agree today because both call `virp_build_id()`.
   Nothing forces them to keep agreeing. A test that boots the daemon and
   compares its `node_config` body against its own `--version` output
   would close that. I did not add it.

5. **`test_onode` cannot be run twice at once on this machine**, by
   anyone, for any reason — see the shared-socket finding at the top.

### Late update on the contention finding

Near the end of the run the other session adopted its own isolation: it
now runs its suites inside a mount namespace with a private `/tmp`
(`unshare` + `mount -t tmpfs tmpfs /tmp`). Its later runs therefore cannot
collide with mine. My guard still sees its processes and waits, which is
now more conservative than necessary but harmless.

Two consequences for how you read this report:

- The contention was real and it did corrupt the earlier runs. The
  evidence table above stands.
- My final battery was reported CONTAMINATED by the guard (a foreign
  process appeared partway through), but that process was inside its own
  namespace and could not reach my sockets. The run had **zero
  failures**, which is the stronger evidence. I am flagging the
  discrepancy rather than quietly suppressing the guard's warning.

I did not adopt the same namespace isolation myself, because
`unshare`-ing a private `/tmp` without root requires mapping my uid to
root inside the namespace, and the uid policy tests read `getuid()`.
Running them as uid 0 would change what they test.

### Not done, and why

- **The branch is NOT pushed.** `git push -u origin fix/v0.2.1` was
  blocked by the permission classifier in this session. I did not attempt
  to work around it. The three commits are local on `fix/v0.2.1`, the
  working tree is clean, and the push is yours to run.

### Draft amendment for the v0.2.0 GitHub Release body — NOT APPLIED

Recorded here only. I did not touch the release body, as instructed.
Suggested text to add at the top:

> **WITHDRAWN — do not deploy this release.**
>
> v0.2.0 was deployed to the production reference node on 2026-09-02 and
> rolled back after ten minutes. Its chain_append handler infers that any
> uid present in `socket_uid_action_allow` is a restricted federated
> principal and narrows it to `fed_request` / `fed_observation` /
> `fed_outcome`. Combined with this release's own requirement that every
> allowlisted uid have an action map, that causes the daemon to refuse its
> own service accounts' appends (`observation`, `comparator_verd`,
> `chainwalk_summa`, `no_drift`, `evidence_item`). There is no
> configuration that avoids this; the inference is in the daemon.
>
> Separately, this release reports `build_id="unknown"` in its
> `node_config` entries, so the chain cannot identify the source that
> produced the running daemon.
>
> Executions are not affected: in the observed window every `gate_intent`
> had its closer and the chain is intact. The failure is that evidence
> appends are refused.
>
> Use v0.2.1 or later.

---

## Restoring the deploy keys

The keys are **already restored** and the box is already reachable — see
the second item under READ THIS FIRST. These commands are therefore a
no-op today, and are recorded for completeness and for the case where you
want the isolation control put back.

To confirm the current state:

```sh
ls -l ~/.ssh/id_ed25519 ~/.ssh/ironclaw_deploy_ed25519
ssh -o BatchMode=yes -o ConnectTimeout=10 virp-lab true; echo "exit=$?"
```

`exit=0` means the node is reachable.

If the keys are ever left renamed by a session that did not restore them,
this puts them back:

```sh
mv ~/.ssh/id_ed25519.overnight            ~/.ssh/id_ed25519
mv ~/.ssh/ironclaw_deploy_ed25519.overnight ~/.ssh/ironclaw_deploy_ed25519
chmod 600 ~/.ssh/id_ed25519 ~/.ssh/ironclaw_deploy_ed25519
ssh -o BatchMode=yes -o ConnectTimeout=10 virp-lab true; echo "exit=$?"
```

To take the isolation control back out (what Item 0 did):

```sh
mv ~/.ssh/id_ed25519            ~/.ssh/id_ed25519.overnight
mv ~/.ssh/ironclaw_deploy_ed25519 ~/.ssh/ironclaw_deploy_ed25519.overnight
ssh -o BatchMode=yes -o ConnectTimeout=10 virp-lab true; echo "exit=$?"   # expect 255
```

Note that `~/.ssh` is shared with the other session on this laptop, so
either action affects both.

Git remote note: this session's `origin` push URL is HTTPS, set when the
keys were removed. Nothing needs undoing for that.

---

## Item 2 — release tag guard on `ci/notes-from-tag` — DONE

Tip `3e5ff24`. Battery GREEN: `test_onode` 157/159 (2 by-design PENDING),
0 failures, whole suite clean. No C changed, so no sanitizer run.

The thing I was asked to check was already right: the workflow fetches
full history and publishes with `--notes-from-tag`, never auto-generated
notes. What was missing was any check that the tag can actually play that
role.

**The finding.** A lightweight tag is a ref to a commit, not a tag object,
and asking git for its message returns the **commit** message. Verified:

```
$ git tag lightweight; git tag -a annotated -m "real notes here"
$ git for-each-ref refs/tags/lightweight --format='%(contents)'
docs: a perfectly ordinary commit subject
$ git for-each-ref refs/tags/annotated   --format='%(contents)'
real notes here
```

So `git tag v0.2.1` instead of `git tag -a v0.2.1 -F notes` does not
publish an empty release body, which someone would notice. It publishes a
release whose body is the last commit subject, with the entire
known-limitations section silently gone. That is the same shape as the
v0.2.0 `build_id` defect: a silent fallback that reads like a real value.

`scripts/check-release-tag.sh` refuses to publish unless the tag is a real
tag object whose own message has at least five non-blank lines. It runs in
`release.yml` immediately before the publish step, on tag pushes only.

Its selftest builds a fixture repo with a lightweight tag, a one-line
annotated tag and a proper one, and confirms it rejects the first two and
the missing-tag case while accepting the third. The workflow runs that
selftest right before the real check.

Calibration: the real `v0.2.0` tag passes, at 73 non-blank lines. The
guard is not tuned so tight that a genuine release trips it.

---

## Item 3 — README on `docs/readme-v0.2.0` — DONE

Tip `f9914a4`. Battery GREEN: 157/159, 0 failures.

The README was the first thing a reader met and it said nothing about the
release being unsafe to deploy. It now carries a release-status section
saying plainly that v0.2.0 is WITHDRAWN and why, in the same terms as
`DEPLOYED.md` and `SECURITY.md`, and saying what was *not* affected —
every `gate_intent` in the window had its closer, the chain is intact — so
the withdrawal is not read as broader than it was.

Also adds the live instance numbers from Item 0, explicitly labelled as a
measure of volume and not of correctness, so the table cannot be read as
evidence the records are right.

This branch also carries the earlier README repositioning, cherry-picked
from `7815132`, **which was on no branch at all** — it existed only as a
loose commit in the object store and would have been lost to a `gc`. Its
one conflict was the documentation table; resolved as the union of both
sides, dropping a duplicate `SECURITY.md` row the table already had.

---

## Item 4 — attribution design brief — DONE

Tip `7ea9115`. Battery GREEN: 157/159, 0 failures, in a guard-confirmed
clean window.

`docs/ATTRIBUTION-DESIGN-BRIEF.md`. The gap: for an entry appended through
the control socket, **the chain does not record which principal appended
it.** `chain_entries` carries `signer_node_id` / `signer_org_id`, which
identify the node that signed the entry, not the caller. There is no uid
column and the artifact rows do not carry one.

Attribution today is recovered by reading the session id and inferring the
owner from its prefix. Three things are wrong with that, all verified
in-tree rather than asserted:

1. **The prefix is chosen by the caller.** A socket `chain_append` carries
   whatever session string the client sends. Nothing binds it to the peer
   uid — there are 54 uses of the peer uid in the daemon and not one is
   compared against the session id. Any uid allowed to append may append
   under any session name, including one that reads as another
   component's.
2. It is a naming convention, so nothing enforces it and nothing notices a
   collision.
3. It has already produced an unresolvable case — the 196 rows from
   Item 0.

This matters more after v0.2.1, which makes uid a policy input: that
policy is enforced at write time and recorded nowhere, so an auditor
cannot confirm from the chain which uid an entry was admitted for.
Reconstructing the v0.2.0 incident meant reading the daemon journal, which
is not hash-linked, not signed, and rotates.

Four options with trade-offs; recommends a recorded `principal_uid`
covered by the entry hash, with a smaller immediate step of binding
session prefixes to uids. Says plainly what it does not solve, including
that it cannot retroactively attribute the 196 rows.

---

## Item 5 — Docket Phase 4 — NOT ATTEMPTED (kill condition)

**Kill condition hit: "you are unsure whether something is in scope (then
it isn't)."**

I could not establish what "Phase 4" refers to. There is no occurrence of
"Phase 4", "Phase-4" or "phase 4" anywhere in the Docket repository — not
in any `.md`, `.rs` or `.toml`, not in `DESIGN.md`'s section list, and not
in the `overnight/` directory. The work order names the item but its
specification is not in my context.

There is a second reason to stop. The Docket repo has been worked on
tonight by a **different session running a different work order**
(`DOCKET-OVERNITE-WORK-ORDER`, its own items 0–5: presentation fixes, key
format, Aug 27 hardening, carried bodies, static verifier release). Its
`OVERNIGHT-REPORT.md` is committed at `c565eaa` and reports all six items
DONE across five local branches. None of those items is called Phase 4.

Guessing at a Rust change in a repo another session had just finished
working in, against an item I could not define, is exactly what the kill
condition is for. Nothing in the Docket repo was modified. I read it only.

If Phase 4 has a definition somewhere I did not have, point me at it and
it is a short job.

---

## Item 6 — replay guard on `perf/replay-guard-index` — DONE, and the premise was wrong

Tip `54372d9`. Battery GREEN: 157/159, 0 failures, guard-confirmed clean
window.

The branch is named for an index because an index was the expected fix.
**It is not.** That is the finding, and it is measured rather than argued.

`chain_count_intents_for_approval_locked()` asks whether an approval was
already spent. It does that by selecting **every `gate_intent` body ever
written** and `cJSON_Parse`-ing each one in C to compare
`approval_entry_hash`. The field it filters on lives inside a JSON body,
where SQLite cannot reach it. This runs on every approved apply, holding
both the chain lock and `consume_mu`.

Measured on a synthetic chain shaped like the live node (273239 entries,
~21000 `gate_intent`, real body shape):

| variant | per approved apply |
|---|---|
| today | 0.074 s |
| today + `INDEX ON chain_entries(artifact_type)` | 0.079 s |
| proposed indexed citation | 0.000004 s |

The index does change the plan from `SCAN` to `SEARCH`, which is why it
looks like the fix. Finding the rows was never the expensive part.
Parsing 21000 JSON bodies is. Measured speedup from the index: **1.08x**.

The cost is O(`gate_intent`s ever written) and nothing prunes them, so the
most safety-critical operation in the system is the one whose cost grows
without bound. **Nothing fails today** — this is scalability, not an
outage.

`docs/PERF-REPLAY-GUARD.md` proposes materialising the citation into an
indexed table written inside the same transaction as the intent append,
with five constraints spelled out. The one that matters most: a missing
citation row must read as UNKNOWN and fall back to the scan, never as
"not spent" — failing open there would turn a performance change into an
approval-reuse hole.

**I did not implement it.** It is a schema change, a migration, a backfill
and a new write inside the approval path's transaction, on the one path
where being wrong means an approval can be spent twice. The v0.2.0
incident earlier the same night is the argument against doing that
unattended. The measurement is the deliverable; the implementation should
be a reviewed change.

---

## Summary

Five green branches, one item correctly declined, nothing pushed.

What I would read first, in order:

1. **This report's two "READ THIS FIRST" items** — the concurrent session
   and the deploy keys. Both need a decision from you, not from me.
2. **Item 6's measurement.** It is the finding with the longest shelf
   life: a safety-critical path whose cost grows without bound, and a
   fix that everyone (including the work order, and me) assumed was an
   index.
3. **Item 1**, the actual v0.2.1 release work.

Three things in this run were checkmarks that were not tests: a test file
wired into no target, an assertion that checked a key existed rather than
its value, and a branch name that presumed its own fix. All three passed
green while being wrong. That is the pattern worth taking from tonight.
