# HAM review remediation, 2026-09-06

## Morning summary

All sixteen items were worked. Fifteen landed as code or docs across four
branches, every one of them with a regression test that was proven to
fail against the unfixed code first. `make all-tests` exits 0 on every
branch, with the same two known-PENDING failures the baseline has.

Merge in this order, after your own three (fix/autopilot-home,
feat/autopilot-home-battery, feat/tacacs-server):
`fix/ham-tacacs-authz`, `fix/ham-tacacs-evidence`, `fix/ham-verifier`,
`fix/ham-json-hygiene`. Expect one trivial Makefile conflict on the
`all-tests` line between the first two branches: keep both target names.

Nothing was deployed and nothing on any remote host was touched. The
daemons on 313 and .211 run from `/usr/local/lib/virp/`, so none of this
changes production behaviour tonight.

Four things need you, not me. Item 7 changes what the verifier says about
a real chain and is DEPLOY-GATED: run the read-only baseline in section 7
against a copy of each production chain before it installs anywhere. The
`tacacs_accounting/2` schema exists but the receivers keep emitting `/1`
until you set `emit_schema_version: 2` on 313 and .211. The
`approved.conf` anchor test belongs on `feat/tacacs-server`, which owns
that file. And the public `virp-verify` and Docket ports are not done:
neither repo is checked out here.

One thing you should know that was not on the list: `tests/test_tacacs_authz.py`
has its `if __name__ == "__main__"` block at line 442 of 1642, so running
it directly executes 37 of its 129 tests, and the file is not in
`all-tests` at all. All 129 pass under pytest. That is 92 attack-suite
tests nobody has been running.

---

## 1. Summary table

| # | branch | commit | status | test |
|---|---|---|---|---|
| 1 | `fix/ham-tacacs-authz` | `cfb998b` | DONE | `TestItem1SingleUseUnderConcurrency` |
| 2 | `fix/ham-tacacs-authz` | `ccf3a29` | DONE | `TestItem2GrantBindsThePrincipal` |
| 3 | `fix/ham-tacacs-authz` | `ef43297` | DONE | `TestItem3CleartextOnTheAuthorizationListener` |
| 4 | `fix/ham-tacacs-evidence` | `b140ceb` | DONE (a-d); e FOLLOW-UP | `TestItem4ProducerSignatureIsATrustDecision`, `TestItem4dThePublicVerifierAgrees` |
| 5 | `fix/ham-tacacs-evidence` (a-c), `fix/ham-tacacs-authz` (d) | `0e6c0e5`, `6ee717c` | DONE | `TestItem5ReconciliationBindsThePrincipal`, `TestItem5dIdentityFollowsTheOperation` |
| 6 | `fix/ham-tacacs-authz` | `6ee717c` | DONE (signature half); approved.conf half FOLLOW-UP | `TestItem6CompilerVerifiesTheApproverSignature` |
| 7 | `fix/ham-verifier` | `9be0354` | DONE, **DEPLOY-GATED** | `tests/test_chain_signing_migration.c` |
| 8 | `fix/ham-verifier` | `c0188e1` | DONE (a-c); d FOLLOW-UP | `tests/test_obs_v3_vectors.py` |
| 9 | `fix/ham-json-hygiene` | `50a5872` | DONE, **DEPLOY-GATED** | `tests/test_json_hygiene.c` item 9 |
| 10 | `fix/ham-json-hygiene` | `1e98bd5` | DONE, **DEPLOY-GATED** | `tests/test_json_hygiene.c` item 10 |
| 11 | `fix/ham-verifier` | `647b451` | DONE (doc only) | n/a |
| 12 | `fix/ham-json-hygiene` | `7044f87` | DONE, **DEPLOY-GATED** | `tests/test_json_hygiene.c` item 12 |
| 13 | `fix/ham-verifier` | `b00adb3` | DONE | `tests/test_verifier_error.py` |
| 14 | `fix/ham-verifier` | `2460f36` | DONE (doc only) | n/a |
| 15 | `fix/ham-tacacs-evidence` | `b140ceb` | DONE | `TestItem15SourceStrength` |
| 16 | `fix/ham-json-hygiene` | `770a241` | DONE | `tests/test_json_hygiene.c` item 16 |

Branch heads: `fix/ham-tacacs-authz` `6ee717c`, `fix/ham-tacacs-evidence`
`b140ceb`, `fix/ham-verifier` `2460f36`, `fix/ham-json-hygiene` `bba6b25`
(the last commit on that branch is this report; the item 16 fix is
`770a241`). All four are pushed. All four are based on local `main`
`315e551`.
## 2. Phase 0 recon

### Repository

Working checkout: `/home/nhoward/virp` (`origin git@github.com:nhowardtli/virp.git`).
Chosen over the other 20-odd `~/virp*` trees because it is the only one whose
HEAD is 2026-09-06 and the only one carrying `tacacs/`.

Tree was **clean** at start (`git status --porcelain` empty). No stash was
taken; nothing was discarded.

Checked out branch at start: `feat/virp-sean-seat` (f7ed20b). Restored at end.

### HEADs

| ref | sha |
|---|---|
| `main` (local) | `315e551` |
| `origin/main` | `cb4589e` |
| `feat/virp-sean-seat` | `f7ed20b` |

`main` and `origin/main` are **DIVERGED, pre-existing**: local main is ahead 9
(the fix A-F TACACS/SSH merges) and behind 5 (the autopilot-home merges pushed
from elsewhere). No `tacacs/` or `report/` file differs between them; the delta
is `Makefile`, `autopilot/virp_autopilot.py`, `include/virp.h`,
`include/virp_ssh_io.h`, `src/drivers/driver_cisco.c`, `src/virp_message.c`,
`src/virp_ssh_io.c`, `DEPLOYED.md`, four `deploy/` files and five test files.

This means the §6 end-of-run check "`git log origin/main..main` is empty"
CANNOT pass tonight and did not pass at the start either. I did not touch main
in either direction. See DECISIONS.

### Branches asked about

| branch | local | origin |
|---|---|---|
| `feat/tacacs-authz` | 949eefa | 949eefa |
| `feat/tacacs-server` | absent | 2598de3 |
| `feat/tacacs-accounting` | 0839d80 | **ABSENT** |
| `feat/2960-governed` | absent | e71dfb7 |
| `fix/autopilot-home` | absent | 5e3eb0c |
| `feat/autopilot-home-battery` | absent | 2761edd |
| `feat/device-enabled-flag` | fe330ba | **ABSENT** |
| `fix/export-head-entry-race` | d1d33f4 | d1d33f4 |

`feat/tacacs-accounting` and `feat/device-enabled-flag` exist ONLY on this
machine. They are unpushed local work; I did not touch or push them.

### Where the findings' files live

`virp_tacacs_authzd.py` is on **main**, on `origin/main`, on
`feat/tacacs-authz` and on `origin/feat/tacacs-server`. It was NOT lost with
the ThinkPad. Items 1, 2, 3 and 6 were therefore all workable.

| file | path | on main? |
|---|---|---|
| authorization daemon | `tacacs/virp_tacacs_authzd.py` | yes |
| authorization engine | `tacacs/virp_tacacs_authz.py` | yes |
| accounting receiver | `tacacs/virp_tacacs_recv.py` | yes |
| reconciler | `tacacs/virp_tacacs_reconcile.py` | yes |
| policy compiler | `tacacs/virp_tacacs_policy.py` | yes |
| TACACS+ codec | `tacacs/virp_tacacs_codec.py` | yes |
| Python verifier | `report/verify.py` (a LIBRARY, no `main()`) | yes |
| report CLIs | `report/virp_report.py`, `report/virp_evidence_report.py` | yes |
| chain | `src/virp_chain.c` (canonical builder at 1133) | yes |
| approval | `src/virp_approval.c` | yes |
| O-Node | `src/virp_onode.c` (string helper at 104) | yes |
| API server | `api/server.py` | yes |
| docs | `docs/TACACS-ACCOUNTING.md`, `SECURITY.md` | yes |

**Not present anywhere in the repo:** the -07 draft text (no hit for
"External Authorization Binding" or "device_accounting"), and any
canonical-format-window planning doc (the only hit for "CANONICAL-FORMAT" is
`docs/HASH-BOUNDARY.md`). `approved.conf` and the tac_plus-ng config generator
(`deploy/tacacs/gen-green-conf.py`, `deploy/tacacs/tac_plus-ng.cfg`,
`deploy/tacacs/tacacs-reload`) exist ONLY on `origin/feat/tacacs-server`.

### Build environment

Everything the reviewer's sandbox lacked is present here. Nothing was
installed; nothing needed to be.

- `sodium.h`, `libssh2.h`, `sqlite3.h` all present in `/usr/include`. cJSON is
  vendored at `src/third_party/`.
- Python 3.12.3 with `paramiko`, `pytest`, `cryptography`, `nacl`, `fastapi`,
  `httpx`, `reportlab` all importable system-wide.

**No finding in this report is unexecuted.** Every C item was built and run on
this machine.

### Baseline: `make all-tests` on main (315e551)

```
EXIT=0
```

435 `[PASS]` lines, 2 `[FAIL]` lines. Both failures are the already-tracked
`gate_execution/2` three-valued `executed` semantic, marked in the harness as
`[PENDING] known-failing by design; NOT a pass`, and they do not fail the
target. Contrary to the note in my working memory, flagless `make all-tests`
does NOT fail on this tree for the refusal-contract or chainsign-vectors
reasons: it exits 0.

Baseline suite counts (the ones that print a total):
3/3, 5/5, 199/199, 22/22, 107/107, 74/74, 246/246, 19/19, 17/17, 26/26,
44 unittest, 39 unittest (1 skipped), 22/22, 52, 4, 23, 50 (2 skipped),
48 (6 skipped), 33, 7, 11, 49, 11, 9, 6, 15, 6, 7, 3, 4, 5, 14, 17, 11, 33,
9, 1, 3, 7, 15.

`tests/test_tacacs_authz.py` is NOT in `all-tests` and, run directly, executes
only 37 of its 129 tests. See FOLLOW-UPS.

---

## 3. Per-item blocks

### Item 1 (P0) — a single-use grant could authorize N times

**Finding.** `virp_tacacs_authzd.py` is a threaded server. The request
path snapshotted the policy, authorized against the snapshot, and
consumed the grant under a SEPARATE, later acquisition of the same lock.

**Files.** `tacacs/virp_tacacs_authzd.py`.

**Reproduction.** A harness that replays the reviewed handler sequence
verbatim (`store.load()`, `store.snapshot()`, `az.authorize(policy, ...)`,
`store.consume(gid)`), 16 threads on a barrier, 40 iterations, against a
`uses=1` grant:

```
iteration  1: a uses=1 grant authorized 16 times
iteration  2: a uses=1 grant authorized 16 times
iteration  5: a uses=1 grant authorized 13 times
...
iteration 39: a uses=1 grant authorized 8 times
worst case across 40 iterations: 16 PASS_ADD from a single-use grant
EXIT=1
```

37 of 40 iterations over-authorized. One human approval became sixteen
authorized commands.

**Fix.** `PolicyStore.authorize_and_reserve()` does the decision and the
reservation under ONE lock, and fsyncs the decrement inside that critical
section. A grant is AVAILABLE, RESERVED or SPENT; a competing request
sees RESERVED and SPENT alike as spent. The only path back to AVAILABLE
is `release()`, used in the one case where nothing can have reached the
router (the chain append failed before any reply was built). A send that
fails AFTER the reply was serialized keeps the grant consumed and records
`GRANT_CONSUMED_UNSENT`, because we cannot prove the router did not act
on it. `authorize_and_reserve()` also returns the policy sha256 AS
DECIDED AGAINST, taken before the reservation changes it, so the chained
record still names the policy that produced the decision.

**Verification.** 6 tests, including 40 iterations of 16 racing threads
asserting exactly one PASS, a `uses=3` grant asserting exactly three, a
durability check across a fresh `PolicyStore` on the same file, and a
source pin that the request path cannot go back to deciding against a
snapshot. `make all-tests` EXIT=0.

**Commit.** `cfb998b`.

**Notes.** `snapshot()` + `az.authorize()` + `consume()` remain available
for callers that already hold a decision; the request path no longer uses
them, and the source pin enforces that.

---

### Item 2 (P0) — a grant did not bind the TACACS username

**Finding.** `_grant_matches()` compared device and command only, and
`authorize()` special-cased `virp-ro` and routed every other username
through write-grant matching.

**Files.** `tacacs/virp_tacacs_authz.py`, `tacacs/virp_tacacs_policy.py`.

**Reproduction.**

```
FAIL: test_only_the_named_principal_passes
AssertionError: 'PASS_ADD' != 'FAIL' : user 'nate': got PASS_ADD (grant g-appr-1)

FAIL: test_unknown_principal_is_refused_before_any_grant_is_read
AssertionError: 'PASS_ADD' != 'FAIL'
```

A grant issued for `virp-rw` returned PASS_ADD for `nate`, for
`eviluser`, and for `breakglass`.

**Fix.** The grant key is principal + device + exact command spelling; a
grant with no `user` matches nothing. A principal outside the gate
identity set fails closed BEFORE any grant is read, with a reason that
names the identity. The compiler refuses to ISSUE a grant for a non-gate
principal. `virp-ro` and `virp-rw` are defined once, in
`virp_tacacs_authz`, and the compiler imports them; they were literals in
three places before.

The `exit` / `quit` / `end` / `terminal length 0` exemptions stay open to
everyone, deliberately: they cannot alter state or reveal anything, and
denying them would strand a session in config mode and lose its
accounting. Stated in the code.

**Verification.** 6 tests: PASS only for the named principal across
virp-rw / nate / eviluser / breakglass / virp-ro; a missing username
fails closed; a grant issued for `virp-ro` does not pass for `virp-rw`;
the compiler refuses; and a source pin that the compiler cannot re-type
the identity string.

**Commit.** `ccf3a29`.

---

### Item 3 (P0) — the authorization listener accepted TACACS cleartext

**Finding.** `if hdr["unencrypted"] or secret is None: plain = raw_body`.

**Files.** `tacacs/virp_tacacs_authzd.py`, `docs/TACACS-ACCOUNTING.md`.

**Reproduction.** End to end against the real `AuthorServer` on a
loopback port, with a real config, a real producer key, a real ledger and
a stub O-Node that accepts the chain append:

```
FAIL: test_cleartext_from_a_configured_source_is_refused
AssertionError: 'PASS_ADD' != 'FAIL' : grant g-appr-1

FAIL: test_a_refused_cleartext_request_never_reserves_a_grant
AssertionError: 'FAIL' != 'PASS_ADD' : the cleartext refusal spent the grant
```

A cleartext AUTHOR request from a source WITH a configured secret
returned PASS_ADD and spent the single-use grant.

**Fix.** The flag from a configured source is a hard FAIL, decisioned and
ledgered as `CLEARTEXT_REJECTED`, taken before any policy is evaluated,
so no grant is reserved. The body is still decoded-as-received and still
chained: the record must say what arrived, only the decision is refused.
Both listeners now carry a comment saying why they differ, so a later
tidy-up of "the two decoders" cannot collapse them.

**Verification.** 5 tests, including the control case (same grant, same
command, same identity, secret applied: PASS_ADD) so the test cannot pass
by denying everything, and a source pin that the accounting receiver
stays permissive.

**Commit.** `ef43297`.

**Notes.** The unconfigured-source case was NOT changed to FAIL; see
DECISIONS.

---

### Item 4 — the producer signature was not part of any trust decision

**Finding.** `/1` bodies carry `producer_sig` and nothing verified it;
`/1` carries no producer key id, so no consumer could pick a key to try.

**Files.** `tacacs/virp_tacacs_recv.py`,
`tacacs/virp_tacacs_reconcile.py`, `report/verify.py`,
`report/virp_report.py`, `docs/TACACS-ACCOUNTING.md`.

**Reproduction.** Code read plus the schema: `producer_sign()` adds
`producer_sig` and nothing anywhere calls a verify; `build_receipt()`
emits no `producer_key_id`; `read_chain()` accepted any `evidence_item`
whose body said `schema: tacacs_accounting/1`. The new tests fail against
the unfixed code by API absence, which is why the finding is documented
by the shape of the code rather than by a runtime failure: there was no
verification path to fail.

**Fix.**

- **(a)** `tacacs_accounting/2` = `/1` plus `producer_key_id`,
  `producer_signature_scheme`, `producer_signature`. `PRODUCER_CANONICAL`
  is defined exactly in `docs/TACACS-ACCOUNTING.md` with a worked vector
  (throwaway seed `000102...1f`, pubkey `03a107bf...`, key_id
  `56475aa7...`), and a test asserts every part of that vector appears in
  the document, so code and doc cannot drift. `producer_key_id` is INSIDE
  the signed bytes.
- **(b)** The receiver emits `/1` unless its config sets
  `emit_schema_version: 2`. Flipping it means editing that host's config
  and restarting it.
- **(c)** Reconciliation reads both and carries
  `tacacs_producer_signature`: VERIFIED / FAILED / ABSENT. ABSENT is
  deliberately not FAILED.
- **(d)** `report/verify.py` grades the same property, exposed through
  `virp-report --tacacs-producer-pubkey` (public key only). It
  reimplements the canonical string rather than importing the producer's;
  the two are held byte-identical by test.

**Verification.** 21 tests across items 4 and 15, plus 9 cross-verifier
tests. `make all-tests` EXIT=0.

**Commit.** `b140ceb`.

**Notes.** No `/1` record is rewritten anywhere. (e) is a FOLLOW-UP:
neither the public `virp-verify` repo nor Docket is checked out on this
machine.

---

### Item 5 — reconciliation and gate_execution did not bind the device principal

**Finding.** The matcher used device + command + time, and
`gate_execution` carried no device-side principal at all.

**Files.** `src/virp_onode.c`, `tacacs/virp_tacacs_reconcile.py`,
`tests/test_tacacs_accounting.py`, `docs/TACACS-ACCOUNTING.md`.

**Reproduction.** The scenario from the finding, as a test:

```
FAIL: test_the_one_second_human_does_not_match_the_gate
```

19:00:00 the gate runs `show running-config` as `virp-ro`; 19:00:01 a
human runs the same command as `nhoward`; same device. Graded MATCHED
before the fix: the human corroborated the gate.

**Fix.** (a) `gate_execution` bodies carry `device_principal`, taken from
the device descriptor the dispatch used, never from the request;
`body_version: 2`, absent reads as 1. This is a body field, not a
canonical-form field. (b) Where both sides carry a principal, exact match
is REQUIRED; where the gate record is legacy the match grades
`MATCHED_LEGACY_NO_PRINCIPAL`, never promoted, never counted toward
corroboration, and a bound candidate is preferred over a legacy one.
(c) The 19:00:00 / 19:00:01 case is pinned as NOT a match alongside the
same-principal case that must still match. (d) On the authz branch:
pinned that the chained decision names the principal it decisioned, on a
pass, on an identity refusal and on a cleartext refusal.

**Verification.** 5 + 3 tests. Six existing accounting tests now assert
`MATCHED_LEGACY_NO_PRINCIPAL`, which is what their fixtures actually are;
`gate_body()` takes an optional principal so the bound path is exercised
too.

**Commits.** `0e6c0e5` (a-c), `6ee717c` (d).

---

### Item 6 — the grant issuer did not verify the approval signature

**Finding.** The chained approval body carried `approver_key_id` but no
signature, so `approval_trusted` was binding correctness alone.

**Files.** `src/virp_approval.c`, `tacacs/virp_tacacs_policy.py`,
`tests/test_tacacs_authz.py`, `docs/TACACS-ACCOUNTING.md`.

**Reproduction.** An approval whose `approver_key_id` is the string
`deadbeef` repeated four times, with no signature anywhere:

```
approval_trusted        : True
trust_basis             : ['command_hash_binding', 'command_hash_recomputed', 'device_agreement']
trust_not_established   : ['approver_signature']
grants rendered         : 2
  GRANT g-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa device=R1 command='interface Loopback99' uses=1
  GRANT g-configentry-R1 device=R1 command='configure terminal' uses=1
refusals                : []
```

Two grants, including `configure terminal`, zero refusals, from an
approval nobody signed.

**Fix.** Path (a) of the two the review offered, because it leaves the
canonical form untouched. `src/virp_approval.c` writes
`approver_signature` into the approval ARTIFACT BODY (`body_version: 2`).
The compiler RECONSTRUCTS the 72-byte canonical payload from the body's
own fields and verifies against its own pinned registry
(`--approver-registry`, required). Reconstructing rather than reading a
carried payload is what makes the signature bind the fields. The
algorithm comes from the pinned registry entry, never from the body.

A grant is emitted only when the signature verified under a pinned,
enabled key AND the hash binding holds AND the hash recomputes AND the
devices agree AND the approval has not expired AND it was not already
compiled. Each failure is its own refusal reason. The replay check reads
the compiler's own prior `policy_rendered` records from the chain, not a
local file.

**Verification.** 10 tests, including the fail-first unpinned-key case, a
tampered command digest, a tampered TTL (proving every field the payload
covers is bound), a replay, no registry at all, a legacy signature-less
body, and a byte-layout check of the reconstructed payload against
`include/virp_approval.h`.

**Commit.** `6ee717c`.

**Notes.** `TestApprovalTrustBasis` in `tests/test_tacacs_authz.py`
recorded the old finding as settled; its docstring now records that it is
closed, and its "matching pair is trusted" case asserts the new rule. The
`approved.conf` half of item 6 is a FOLLOW-UP: that file does not exist
on `main`.

---

### Item 7 (DEPLOY-GATED) — pre-signing sessions false-failed

**Finding.** The C verifier inferred signed-ness from
`(verify_sig_enabled && entry_sig_cols)`, both of which are properties of
the DATABASE and the operator, not of the session.

**Files.** `src/virp_chain.c`, `report/verify.py`,
`docs/VERIFIER-SEMANTICS.md`, `tests/test_chain_signing_migration.c`.

**Reproduction.** The real migration sequence: write a session with
signing off, enable signing, write a second session, reopen the verifier
with the pubkey.

```
  [TEST] migration: a pre-signing session PASSES under the pubkey
FAIL: pre-signing session did not verify (rc=0 detail=Missing Ed25519
signature at sequence 0 in a signed session (stripped signature))
  [TEST] migration: the born-signed session still verifies signed   PASS
  [TEST] migration: a STRIPPED signature in a signed session still FAILS PASS
  [TEST] migration: an all-stripped session reads unsigned, as Python does
FAIL: an all-unsigned session is not a signature FAILURE
  [TEST] migration: the range verify API reaches the same conclusion
FAIL: range verify of the pre-signing session failed (rc=0 detail=Missing
Ed25519 signature at sequence 0 in a signed session (stripped signature))
=== Results: 2 passed, 3 failed ===
```

**Fix.** The C verifier decides per session from that session's own head,
and from its entries where the head carries no signature, mirroring
`report/verify.py` exactly including the mid-session case. The shared rule
is written down once in `docs/VERIFIER-SEMANTICS.md` and both code paths
point at it. The range API asks the same question, so it can no longer
disagree with the session API.

Stripping stays fatal where it is an attack: a session whose head is
still signed IS signed, and a missing entry signature inside it still
FAILS. That case is pinned alongside the migration case.

**Verification.** 5 tests, `=== Results: 5 passed, 0 failed ===`.
`make all-tests` EXIT=0.

**Commit.** `9be0354`. **DEPLOY-GATED** — see section 7.

---

### Item 8 — v3 observations the daemon accepts, the verifier could not

**Finding.** The C observation verifier accepts v1, v2 and v3;
`report/verify.py` knew v2-else-v1.

**Files.** `report/verify.py`, `tests/test_obs_ed25519.c`,
`tests/test_obs_v3_vectors.py`, `docs/DRAFT07-NOTES.md`.

**Reproduction.** Against a v3 frame the C code had just minted:

```
frame version byte: 3
OLD report/verify.py on a v3 frame the daemon accepts:
    ('FAIL', 'declared length 256 != stored bytes 219')
   with no O-Key: ('UNCHECKED', 'no O-Key available')
```

**Fix.** Teach the verifier, not disable the ingestion: 313 runs with
chain signing and the camera/Spark path is the likely producer.
`report/verify.py` implements the v3 span exactly as
`virp_verify_observation_ed25519` does — header || payload || HMAC, with
the HMAC trailer INSIDE the signed span — with the structural gate before
the signature so "header illegal" and "signature bad" stay distinct.
Without the public key a v3 frame is UNCHECKED with a stated reason.

The vectors are minted by the C code itself: `tests/test_obs_ed25519.c`
gains an env-gated emitter (`VIRP_OBS_V3_OUT`, public key only), and the
Python test verifies them. Neither side runs the other's crypto.

**Verification.** `=== Results: 36 passed, 0 failed ===`: each frame
verifies; each flipped byte of header, payload, HMAC trailer and
signature FAILS; a wrong key FAILS; an appended or truncated byte FAILS;
no key is UNCHECKED with a reason. Item 8b pins that the execute path
still bounds `obs_version` at 2 and defaults to 1.

**Commit.** `c0188e1`. (d) is a FOLLOW-UP.

---

### Item 9 (DEPLOY-GATED) — nanosecond timestamps through IEEE-754 doubles

**Finding.** cJSON `valuedouble` in C, `int(float(...))` in Python.

**Files.** `src/virp_onode.c`, `tacacs/virp_tacacs_policy.py`,
`report/virp_report.py`, `docs/EVIDENCE-INTEGERS.md`.

**Reproduction.** Both languages, on the real parse paths:

```
value                     : 1788722800424766173
Python int(float(str(v))) : 1788722800424766208
difference                : 35

wire      : 1788722800424766173
cJSON     : 1788722800424766208
delta     : 35
```

**Fix.** The rule is stated in `docs/EVIDENCE-INTEGERS.md` and enforced at
the ingress: a decimal string is accepted exactly, a JSON number only
STRICTLY inside 2^53, anything larger is refused rather than truncated.
Strictly, because the literal 2^53+1 decodes to exactly 2^53 and is the
one value a `<=` test would let through looking safe. Every consumer of
`expires_at_ns`, `from_sequence`, `to_sequence`, `obs_version`,
`max_commands` and `supported_channels` inherits it. `evidence_int()` in
the policy compiler turns an inexact value into a REFUSAL with a reason.

`src/virp_approval.c` already did the producing half correctly; this
generalises that decision.

**Verification.** 8 tests through the real `parse_request()`.

**Commit.** `50a5872`. **DEPLOY-GATED** (ingress behaviour change).

**Notes.** Deliberately not changed: the canonical object's own timestamp
fields (a format-window change; the C producer formats them with `%llu`
so the canonical bytes are exact today) and `tacacs_accounting/2`'s
`recv_utc_ns` (a `/2` body is `/1` plus three signature fields and
nothing else). Both are recorded in the doc and under FOLLOW-UPS.

---

### Item 10 (DEPLOY-GATED) — JSON strings truncated into fixed buffers

**Finding.** `json_extract_string_cjson` snprintf'd into a fixed buffer
and returned success on overflow.

**Files.** `src/virp_onode.c`, `autopilot/virp_autopilot.py`,
`tests/test_onode.c`.

**Reproduction.** With `session_id` at `char[64]`, a 63-character id and
a 64-character id differing only in their last byte both arrived as the
same 63 bytes. Before the fix the ingress ACCEPTED the over-length value
(`onode_parse_request_fuzz` returned true); the test that pins the
refusal fails against unfixed code with "an over-length session_id was
accepted (and truncated)".

**Fix.** Reject at the HELPER, so every caller inherits it. The chain
fields refuse the WHOLE request.

The known legacy shape is preserved: `comparator_verdict` (18) and
`chainwalk_summary` (17) have always reached the daemon truncated, and
those spellings stay in the indirect-type policy lists on both sides
forever. A NEW append carrying the full name is now REJECTED.
`autopilot/virp_autopilot.py` was the one client sending the long form
and now sends the alias through a named constant. Two cases in
`tests/test_onode.c` did the same.

**Verification.** 5 tests: the longest legal id is accepted, one byte
over is refused, the long type is refused, both aliases still accepted.

**Commit.** `1e98bd5`. **DEPLOY-GATED** (ingress behaviour change).

---

### Item 11 — artifact_type[16] is architectural debt (planning only)

**Deliverable.** `docs/CANONICAL-FORMAT-WINDOW.md`. There was no single
place listing what waits on a canonical-format change; the four tracked
items were scattered across `SECURITY.md`, `docs/HASH-BOUNDARY.md` and a
TODO in `src/virp_onode.c`. The doc collects them, adds
`artifact_type[16]` as item 5, states both candidate shapes
(variable-length type with a registry, or type+schema promoted to first
class), recommends the second, and fixes the compatibility approach: a
chain-format-version bump with the verifier selecting the old fixed-width
form by version, no entry ever rewritten, and the truncated aliases kept
verifiable forever. It also states the rule: do not add more
abbreviations, and nothing on the list may be implemented outside the
window.

**Commit.** `647b451`.

---

### Item 12 (DEPLOY-GATED) — canonical string rules were not enforced

**Finding.** `build_canonical_json` pastes strings with a raw `%s` and
nothing validated the inputs.

**Files.** `src/virp_chain.c`, `include/virp_chain.h`,
`src/virp_onode.c`.

**Reproduction.** A `session_id` containing a double quote produced a
canonical object that is not JSON; the producer and the verifier built
the SAME malformed bytes, so the hashes agreed and the entry verified.
Before the fix, `virp_chain_append(&st, "sess\"ion", ...)` returned
VIRP_OK and the entry re-verified; the ingress accepted it too. Both are
now pinned as refusals, and both fail against unfixed code.

**Fix.** `virp_chain_canonical_string_ok()` is the one validator, next to
the canonicalizer it protects. Rejects `"`, `\`, control bytes below
0x20, 0x7F, and ill-formed UTF-8 (over-long encodings, surrogates, above
U+10FFFF, truncated sequences, lone continuation bytes). Called from
`chain_append_locked` (the one place every append passes through), from
`virp_chain_init` and `virp_chain_open_verifier_ex` for `signer_org_id`,
and from `parse_request` on the RAW value before the copy.

This is VALIDATION, not a format change: the canonical form is
byte-identical for every conformant value and every entry already written
re-verifies unchanged.

**Verification.** 18 tests: the predicate against every rejection class,
the ingress against three shapes, and the append path against three, with
a conformant append still succeeding so the validator cannot pass by
refusing everything.

**Commit.** `7044f87`. **DEPLOY-GATED** (append-path behaviour change).

---

### Item 13 — verifier storage errors were graded like evidence

**Finding.** In `src/virp_chain.c`:

```c
return 0;   /* cannot read the store: report unverifiable, not broken */
```

0 is also the code for "no body was retained".

**Files.** `include/virp_chain.h`, `src/virp_chain.c`, `report/verify.py`,
`report/virp_report.py`, `tests/test_chain.c`,
`tests/test_verifier_error.py`.

**Reproduction.** On the pre-fix Python side, a `chain_heads` table that
EXISTS but cannot be read:

```
OLD report/virp_report.py, chain_heads present but unreadable:
   load_heads -> None
```

`None` is the LEGACY-DATABASE answer, which the report renders as
COMPLETENESS_UNPROVABLE, an evidence grade, for what was the verifier
failing to read a table that is right there. On the C side the defect is
the quoted line itself.

**Fix.** `VERIFIER_ERROR` as a third top-level outcome. C: the binding
check returns -2, the walk stops, and the result struct carries
`verifier_error` plus a detail with `valid` false and every count
INCOMPLETE. Python: `verify.VERIFIER_ERROR` and `verify.VerifierError`;
storage failures raise it and `virp-report` exits **4**, distinct from the
1 that means the chain is broken. `no such table: chain_heads` still
reads as a legacy database: the guard must not over-fire.

**Verification.** 11 tests. `tests/test_chain.c`'s rolled-back-append
case, which dropped the artifacts table and then asserted the session
still verified, now asserts VERIFIER_ERROR first, restores an empty
store, and then makes its original assertion.

**Commit.** `b00adb3`.

---

### Item 14 — api/server.py is trusted-side (doc only)

**Deliverable.** A section in `SECURITY.md`, plus the same sentence in
`load_okey()` at the point where the custody actually happens. It states
that the O-Key is symmetric, that a process holding it can forge any
observation the daemon could have signed, that the AI host runs the
model, the VIRP client and a forwarded O-Node socket and nothing else,
and that the deployment would look fine afterwards, which is why the rule
is written down rather than left to judgement at install time. It also
states the contrast that makes the rule usable: the asymmetric public
keys MAY cross the boundary.

**Commit.** `2460f36`.

**Notes.** No doc describing Sean's hosted seat exists in this repo; the
section is written to cover it anyway.

---

### Item 15 — cleartext receipts graded like authenticated ones

**Finding.** Reconciliation let a cleartext or unconfigured-source
receipt match exactly like a shared-secret-decoded one.

**Files.** `tacacs/virp_tacacs_reconcile.py`, `docs/TACACS-ACCOUNTING.md`.

**Fix.** `source_strength` as an independent axis:
TLS_AUTHENTICATED / SHARED_SECRET_DECODED / CLEARTEXT /
UNCONFIGURED_SOURCE / MALFORMED. Matching still shows correlation for all
of them; only SHARED_SECRET_DECODED or better AND producer signature
VERIFIED earns `corroborated_by_independent_device_evidence`. Everything
else is `correlated_unauthenticated_source`.

**Verification.** 6 tests, one per strength value plus the closed
vocabulary, plus the corroboration gate from both directions. The
record's "CLAIM, not a cryptographic verdict" sentence is pinned
verbatim.

**Commit.** `b140ceb`.

---

### Item 16 — fixed 2048-byte canonicalization buffer

**Finding.** `snprintf` returns the length it WOULD have written; that
return was hashed.

**Files.** `src/virp_chain.c`.

**Fix.** Both the append and the verify path clamp
`clen < 0 || (size_t)clen >= sizeof(canonical)`. The append side returns
VIRP_ERR_BUFFER_TOO_SMALL with the transaction rolled back; the verify
side states VERIFIER_ERROR in the detail. Nothing is widened.

**Verification.** 3 tests: the widest entry every field can legally hold
still fits with room, and the clamp is present on both paths.

**Commit.** `770a241`.

---

## 4. DECISIONS

Every judgment call made in Nate's absence, with the alternative not
taken.

1. **Worked in `/home/nhoward/virp`.** The only `~/virp*` tree whose HEAD
   is 2026-09-06 and the only one with `tacacs/`. Alternative: ask, which
   was not available; or `virp-remediation-2026-08-31`, which is 30
   commits behind and has no TACACS work.

2. **Based every branch on LOCAL `main` (`315e551`), not `origin/main`
   (`cb4589e`).** `main` is what the checkout resolves and is a superset
   of the reviewed TACACS state. Alternative: base on `origin/main`,
   which would have kept the branches clean relative to what is pushed
   but would have dropped the fix A-F merges the review was written
   against. Consequence: pushing these branches also publishes main's 9
   unpushed commits under other names. That is your own work, backed up,
   not mine.

3. **Did not touch `main` in either direction**, so the §6 check
   "`git log origin/main..main` is empty" still fails, as it did before I
   started. Alternative: pull/merge to reconcile them, which is a
   history decision that is yours.

4. **Left the unconfigured-source case on the authorization listener as
   ERROR, not FAIL** (item 3). It is already refused before any policy is
   evaluated, so the security property the review asked for holds.
   Changing it would alter the `tacacs_authorization/1` decision
   vocabulary for a case the review did not show as exploitable, and the
   reconciler reads that vocabulary. Alternative: change it to FAIL as
   the item's parenthetical says. The test accepts either, so flipping it
   later is one line.

5. **`tacacs_accounting/2` does NOT carry a `producer_signature_scheme`
   the verifier trusts** — it carries the field, but the algorithm used
   for verification comes from the verifier's own pinned registry entry.
   A body-declared scheme is attacker material deciding how the body gets
   checked. Alternative: dispatch on the body's field, as a literal
   reading of item 4a would have.

6. **The `/2` producer canonical string does NOT implement -07's "reject
   if a string member needs escaping".** `json.dumps` is a real
   serializer, it escapes deterministically, and both the signer and
   every verifier call the same function, so the ambiguity -07 guards
   against does not arise. Applying the rejection rule would make the
   receiver DROP exactly the packets it exists to record. The -07 rule is
   enforced where it belongs, on the C canonicalizer, as item 12.
   Alternative: reject, and lose the evidence.

7. **Item 6 took path (a), the signature in the approval BODY**, not
   path (b), the compiler fetching through the gate's read path. (a)
   leaves the canonical form untouched and needs no read-path trust.
   Alternative: (b), which would have avoided a daemon change but would
   have had the compiler ask the checked party for the evidence.

8. **The approval body does NOT carry the 72-byte signed payload**, only
   the signature; the consumer reconstructs the payload from the body's
   own fields. A carried payload could verify while the body said
   something else. Alternative: carry it, which is simpler and weaker.

9. **Item 6's `approved.conf` half was not implemented here.**
   `deploy/tacacs/gen-green-conf.py`, `tac_plus-ng.cfg` and
   `tacacs-reload` exist only on `origin/feat/tacacs-server`. Writing
   them on this branch would duplicate files that branch owns and
   guarantee a conflict. Alternative: create a fifth branch off
   `feat/tacacs-server`, which the run plan did not call for. FOLLOW-UP.

10. **Items 4, 5 and 15 could not be one commit per finding as written.**
    They interleave inside `reconcile()` and in one test file. I split
    them into two commits that each build and pass standing alone: item 5
    alone, then items 4 and 15 together (15's corroboration grade depends
    on 4's producer status, so they are one change). Alternative: three
    commits, two of which would not have built.

11. **Item 16's verify-side clamp does NOT set item 13's
    `verifier_error` field**, because that field is added on
    `fix/ham-verifier` and item 16 is on `fix/ham-json-hygiene`. It
    states VERIFIER_ERROR in the detail text instead, and the code
    comment says to wire the field once both land. Alternative: make
    `fix/ham-json-hygiene` depend on `fix/ham-verifier`, which would have
    forced a merge order.

12. **Item 8 taught the verifier rather than disabling v3 ingestion**, as
    the item directed, and I confirmed the reasoning holds: normal
    execution is capped at `obs_version` 2 and the camera/Spark path is
    the likely producer.

13. **Item 9's safe-range bound is STRICT (`< 2^53`), not `<=`.** The
    literal 2^53+1 decodes to exactly 2^53 and is the single value a `<=`
    test would accept as safe. The cost is the one value 2^53, which the
    rule says to send as a string anyway. Alternative: parse the raw JSON
    token for every integer key, which is a much larger change to the
    ingress for one value.

14. **Six existing accounting tests and one authz test were updated**
    because items 5 and 6 changed the semantic they pinned
    (`MATCHED` -> `MATCHED_LEGACY_NO_PRINCIPAL`; binding correctness is
    no longer sufficient trust). Both are recorded in their commit
    messages and their docstrings now record the change rather than
    hiding it. Alternative: leave them failing.

15. **Two cases in `tests/test_onode.c` and one client
    (`autopilot/virp_autopilot.py`) now send the truncated artifact-type
    aliases explicitly**, which item 10 called for. What is stored is
    unchanged; only who does the truncating.

16. **Did NOT fix the misplaced `unittest.main()` in
    `tests/test_tacacs_authz.py`**, which is why only 37 of its 129 tests
    run when the file is executed directly, and did not wire that file
    into `all-tests`. Neither is one of the sixteen items and the run
    plan says not to improve adjacent code. It is under FOLLOW-UPS with
    the evidence. Alternative: fix it, and surface an unknown number of
    consequences in a night that had sixteen items.

17. **New HAM tests went into NEW files with their own Makefile
    targets**, rather than into `tests/test_tacacs_authz.py`, precisely
    because of (16): tests appended to that file after line 442 would not
    have run.

18. **Every branch's full-suite run was re-run when two `make all-tests`
    processes overlapped** on the shared `build/` directory and the
    shared `/tmp` test databases, producing 5 spurious failures. The
    numbers reported here are from clean, serial runs.

---

## 5. SKIPPED

Nothing was skipped outright. Two sub-items were not implemented, both
recorded above and below:

- **Item 4(e)** — porting the producer-signature grading to the public
  `virp-verify` repo and to Docket. Neither is checked out on this
  machine (`~/virp-verify-public` and `~/virp-verify-0.1.1` are a release
  tarball and an extracted binary, not the source repo). FOLLOW-UP.
- **Item 6, the `approved.conf` emission half** — the files live only on
  `origin/feat/tacacs-server`. FOLLOW-UP, see DECISIONS 9.
- **Item 8(d) and item 13's cross-repo ports** — same reason as 4(e).

---

## 6. FOLLOW-UPS

1. **`tests/test_tacacs_authz.py` runs 37 of its 129 tests.** The
   `if __name__ == "__main__": unittest.main()` block is at line 442 of
   1642, so everything after it is dead when the file is executed
   directly. All 129 pass under `python3 -m pytest`. The file is also not
   in `all-tests` at all. That is 92 attack-suite tests (A8-A10, the
   canonicalizer corpus, the bundle export, the break-glass template, the
   vty binding) that nobody has been running. Two-line fix: move the
   block to the end, add the file to a target.

2. **`tacacs/virp_tacacs_policy.py` has the same shape:**
   `sys.exit(main())` sits above `build_render_refused_record()`. Harmless
   on import, dead when run as a script.

3. **Port item 4(d) and item 13 to the public `virp-verify`** on a branch
   `feat/tacacs-producer-signature`, and to Docket. Do not release.

4. **Port item 6's `approved.conf` anchor test to
   `feat/tacacs-server`**: the emitted rule text must contain no `^` or
   `$` anchors, must use `\A ... \z`, one command per rule, no unescaped
   regex metacharacters from the command, and a TTL that budgets the
   0-8 s spawnd signal window plus ~4 s re-exec.

5. **RFC 9887 (TACACS+ over TLS)** is the eventual transport answer for
   both listeners. IOS 15.2 in the lab does not support it. Noted in
   `docs/TACACS-ACCOUNTING.md`.

6. **`tacacs_accounting` `recv_utc_ns` / `recv_monotonic_ns` are JSON
   numbers above 2^53.** Python signs and verifies these bodies with
   exact integer parsing so nothing is wrong today, but a Go or
   JavaScript consumer would corrupt them. Converting them to decimal
   strings is a `/3` change. Recorded in `docs/EVIDENCE-INTEGERS.md`.

7. **Flipping the receivers to `/2`** needs you at 313 (uid 992) and .211
   (uid 995): set `emit_schema_version: 2` in the receiver config and
   restart. Consumers already read both. Do the consumers first.

8. **Item 16's verify-side clamp should set item 13's `verifier_error`
   field** once `fix/ham-verifier` and `fix/ham-json-hygiene` are both on
   main. One line, and the comment at the site says so.

9. **Merge conflict, expected and trivial:** `fix/ham-tacacs-authz` and
   `fix/ham-tacacs-evidence` each add a target name to the `all-tests`
   line in the Makefile. Resolution: keep both, so the line reads
   `... test-tacacs test-tacacs-ham test-tacacs-evidence-ham
   test-tacacs-identities ...`. Both also touch
   `docs/TACACS-ACCOUNTING.md` in different sections.
   `fix/ham-json-hygiene` and `fix/ham-verifier` both touch
   `src/virp_chain.c` in different functions.

10. **No systemd unit file in the repo was modified**, so the
    apt/unattended-upgrade daemon restart pin on your backlog is
    untouched by tonight's work.

11. **Nothing under `/etc`, `/usr/local` or `/var` was modified.**
    Verified by inspection: no `install-*` target was invoked, no
    `sudo`, and every file written is inside the repo or the session
    scratchpad.

---

## 7. DEPLOY GATES

Four items change what the daemon or the verifier does with a real chain:
**7** (verifier signed-ness), **9** (numeric ingress), **10** (string
ingress) and **12** (canonical-string validation). None of them may be
installed anywhere until the baseline below is run against a COPY of each
production chain and the numbers come back unchanged.

Run as root or as `virp`, on the host, **against a copy**, never against
the live database:

```bash
# 1. Take the copy. WAL-aware: the -wal and -shm must come with it.
sudo systemctl stop virp-onode          # or leave running and use .backup
sudo cp -a /var/lib/virp/chain.db     /var/tmp/chain-baseline.db
sudo cp -a /var/lib/virp/chain.db-wal /var/tmp/chain-baseline.db-wal 2>/dev/null
sudo cp -a /var/lib/virp/chain.db-shm /var/tmp/chain-baseline.db-shm 2>/dev/null
sudo systemctl start virp-onode

# 2. Baseline, with the CURRENTLY INSTALLED binary and verifier.
cd /path/to/virp
python3 - <<'PY' > /var/tmp/chain-baseline-BEFORE.txt
import sys; sys.path.insert(0, "report")
import chain_read, verify, virp_report
with chain_read.open_chain("/var/tmp/chain-baseline.db",
                           allow_immutable=True) as r:
    entries, artifacts = virp_report.load_evidence(r)
    heads = load = virp_report.load_heads(r)
    v, s = verify.verify_chain(entries, artifacts, heads=heads,
                               selection_complete=True)
print("entries          :", s["entries"])
print("sessions         :", s["sessions"])
print("entry_hash       :", s["entry_hash"])
print("link             :", s["link"])
print("artifact_bind    :", s["artifact_bind"])
print("obs_hmac         :", s["obs_hmac"])
print("failed_entries   :", len(s["failed_entries"]))
print("unverifiable     :", len(s["unverifiable_entries"]))
print("heads            :", s["heads"]["tally"] if "heads" in s else "n/a")
PY

# 3. Same command with the NEW tree checked out, same copy.
#    Diff the two files. They must be IDENTICAL, with these exceptions:
#      - "verifier_error" appears as a new key and must be None
#      - nothing else changes
```

And the C side, same copy, both binaries:

```bash
sudo -u virp ./build/virp-tool chain verify \
     --db /var/tmp/chain-baseline.db \
     --chain-key /etc/virp/keys/chain.key > /var/tmp/c-verify-BEFORE.txt
# then the new binary, same arguments, diff.
```

**Expected, per item:**

- **Item 7.** Every session that verified before must still verify, and
  the count of entries graded unsigned should INCREASE on any chain that
  predates chain signing (those sessions were FAILING). No session that
  passed may now fail. `head_sig_ok` and `entries_signed` for born-signed
  sessions must be unchanged.
- **Items 9, 10, 12.** These are INGRESS changes: they cannot alter the
  verdict on an existing entry, because they refuse new requests rather
  than reinterpreting old ones. The baseline must therefore be BYTE
  IDENTICAL. If it is not, stop: something is reinterpreting stored data
  and that was not the intent.
- **Item 10 additionally:** before installing on a host running the
  autopilot, confirm the autopilot on that host is the version that sends
  the aliases. An old autopilot against a new daemon loses its
  `comparator_verd` and `chainwalk_summa` appends to a refusal. Same
  branch, so merging solves it; a partial deploy does not.
- **Item 12 additionally:** grep the live chain for any existing
  `session_id`, `artifact_id` or `artifact_type` that the new validator
  would refuse. There should be none, but a single hit means an existing
  producer is emitting a non-conformant string and would start failing:

```sql
SELECT DISTINCT session_id FROM chain_entries
 WHERE session_id GLOB '*["\]*' OR session_id GLOB '*[^ -~]*';
SELECT DISTINCT artifact_id FROM chain_entries
 WHERE artifact_id GLOB '*["\]*';
SELECT DISTINCT artifact_type FROM chain_entries
 WHERE artifact_type GLOB '*["\]*';
```

Expected: three empty result sets.

The 2,211 truncated legacy librenms bodies stay UNVERIFIABLE by design
and must not be rewritten. The single pre-existing `artifact_bind` FAIL
on session `virp-cli:pbs-lab` sequence 0 must still be exactly one.

---

## 8. Final test numbers

`make all-tests`, clean serial run, on this machine
(Linux 7.0.0-30-generic, gcc 13.3, Python 3.12.3, libsodium / libssh2 /
sqlite3 headers present, `paramiko` / `cryptography` / `nacl` / `fastapi`
/ `httpx` / `reportlab` importable):

| branch | exit | `[PASS]` | `[FAIL]` |
|---|---|---|---|
| `main` (baseline, `315e551`) | **0** | 435 | 2 |
| `fix/ham-tacacs-authz` | **0** | 435 | 2 |
| `fix/ham-tacacs-evidence` | **0** | 435 | 2 |
| `fix/ham-verifier` | **0** | 471 | 2 |
| `fix/ham-json-hygiene` | **0** | 435 | 2 |

The two `[FAIL]` lines are identical on every branch including the
baseline: the already-tracked `gate_execution/2` three-valued `executed`
semantic, marked in the harness as
`[PENDING] known-failing by design; NOT a pass`. They do not fail the
target.

The `[PASS]` counter only counts the C harnesses that emit that token, so
it moves only where a C suite grew. The verifier branch's +36 is
`tests/test_obs_v3_vectors.py`'s assertions, which print in the same
format.

New suites, per branch, inside those runs:

| branch | target | result |
|---|---|---|
| `fix/ham-tacacs-authz` | `test-tacacs-ham` | 30 tests, OK |
| `fix/ham-tacacs-evidence` | `test-tacacs-evidence-ham` | 30 tests, OK |
| `fix/ham-verifier` | `test-chain-signing-migration` | 5 passed, 0 failed |
| `fix/ham-verifier` | `test-obs-v3-vectors` | 36 passed, 0 failed |
| `fix/ham-verifier` | `test-verifier-error` | 11 tests, OK (1 skipped) |
| `fix/ham-json-hygiene` | `test-json-hygiene` | 33 passed, 0 failed |

145 new assertions across six suites, every one of them wired into
`all-tests`.

The one skip is `test_a_truncated_database_exits_verifier_error_not_a_finding`:
this sqlite build opens a truncated file without erroring at the point
the test cuts it, so the case skips loudly rather than passing silently.
The table-level cases around it cover the same guard.

### Existing tests changed, and why

| file | change |
|---|---|
| `tests/test_tacacs_accounting.py` | six assertions `MATCHED` -> `MATCHED_LEGACY_NO_PRINCIPAL`; `gate_body()` gains an optional principal (item 5) |
| `tests/test_tacacs_authz.py` | `TestApprovalTrustBasis` docstring records the finding as CLOSED; its "matching pair is trusted" case asserts that bindings alone are no longer sufficient (item 6) |
| `tests/test_onode.c` | two `ca_append` calls send `comparator_verd` / `chainwalk_summa` explicitly (item 10) |
| `tests/test_chain.c` | the rolled-back-append case asserts VERIFIER_ERROR with the store dropped, restores it, then makes its original assertion (item 13) |

Nothing else in the existing suites was touched.
