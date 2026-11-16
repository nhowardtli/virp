# O-Node security review — notes

Branch `security/onode-review-1`. Scope: `src/virp_onode.c`,
`src/virp_onode_prod.c`, `src/virp_onode_main.c`, `include/*.h`, plus
the chain, approval, policy and driver sources the reviewer did not have.

Every finding was checked against the code before anything was changed.
This file records, per ID: what was verified, what changed, and what was
left alone or deferred, with the reason. Commit hashes and the
per-commit verification results are in the pull request's findings
table; they are not repeated here because they change if the branch is
rebased.

## Read this first

**Nothing in the chain canonical form, any wire format or any on-disk
record layout was changed.** Three things come close enough to say out
loud:

- **M6 adds an index** to `chain.db`:
  `CREATE INDEX IF NOT EXISTS idx_chain_artifact_hash ON
  chain_entries(artifact_hash)`. No row, column or canonical byte
  changes. It is created on the next writer open (0.5 s per 500,000
  entries, measured on a synthetic table; roughly 40 MB per 500,000
  entries, estimated from the key size, not measured) and can be dropped
  with `DROP INDEX`. It follows the existing `idx_chain_artifact_id` /
  `idx_chain_entry_hash` pattern. If you would rather not take a schema
  addition in this branch, M6 is the commit to hold back.
- **M8 changes three JSON value types** the daemon *emits*:
  `intent_ns`, `emitted_ns` and `approved_at_ns` go from JSON numbers
  (rounded through a `double`) to decimal strings, as
  `docs/EVIDENCE-INTEGERS.md` already requires. Existing chain bodies
  keep the numeric form.
- **Additive fields only** elsewhere: `uid` and `device_known` on
  `gate_rejection/1` bodies, ten members on the `chain_verify` responses,
  a new error code `VIRP_ERR_RATE_LIMITED` (-57).

**Changes an operator or a client will notice** are collected under
[Deployment notes](#deployment-notes). The ones most likely to matter on
the first restart: `-k` is now mandatory for `virp-onode-prod`; a config
with `socket_allowed_uids` must also have `socket_uid_tier_ceilings`;
unknown top-level config keys are fatal; and under owner policy some
commands are gated at a higher tier than before (H4).

## Status at a glance

| ID | Status | Summary |
|----|--------|---------|
| H1 | fixed | Replay guard keyed on consumed.list, the chain's own APPROVAL entry, and intents by proposal id |
| H2 | fixed | `executed` at most once, JSON boolean |
| H3 | not-a-bug (defaults) / fixed (docs) | Drivers already default to RED; stale tier documentation corrected; one real bug found in `onode_set_uid_ceilings` |
| H4 | fixed | Policy mode consults the driver classifier; stricter tier wins |
| M1 | fixed | Whole buffer, exact length, no duplicate root keys |
| M2 | fixed | Over-length / mistyped optional fields reject; hex lengths exact |
| M3 | fixed | Device name validated at ingress; `gate-separator:_unknown` |
| M4 | fixed, one part deferred | Intent bodies validated; responses built with cJSON; row+body atomicity deferred |
| M5 | fixed | Reserved session prefixes refused externally |
| M6 | fixed | One observation hash, one registration — inside the append transaction |
| M7 | fixed | Hostnames that cannot be a session id are refused |
| M8 | fixed | ns fields as decimal strings |
| M9 | fixed | Policy refusals chained and signed |
| M10 | fixed | Peer uid on rejections and on the proposer |
| M11 | fixed | Verify responses carry the verifier's full verdict |
| M12 | fixed | Signed error when the session is lost after dispatch |
| M13 | fixed | Proposal id precedes the command; buffer sized |
| M14 | fixed | Absolute receive deadline, send timeout, per-uid worker cap |
| M15 | fixed, one part deferred | Range cap and per-uid verify budget; whole-session verify still holds the chain lock |
| M16 | fixed | Proposal dedupe and per-uid rate limit |
| M17 | fixed | Batch `pthread_create` checked |
| M18 | fixed | Signal-safe shutdown, eventfd wake, acknowledgement |
| M19 | fixed | Session owned by the binding uid |
| M20 | fixed | Instance lock; persisted v1 sequence high-water |
| M21 | fixed | `-O` observation key; `-k` mandatory |
| M22 | fixed | Unknown config keys fatal; ceilings required with an allowlist |
| M23 | fixed | Gate config values strict |
| M24 | fixed | `parse_uid` for map keys; duplicates refused |
| M25 | fixed | Declared-but-empty `protected_vmids` fatal |
| M26 | fixed | Production refuses `evidence_required: false`; override removed |
| LOW | fixed | One commit; see below |
| FINALLY | done | Fuzz targets, CI, this file |

## How each fix was shown to matter

The rule was "every fix gets a regression test that fails before the
fix". For each finding the new test was run twice: against the fixed
tree, and against the tree with only that finding's source change
reverted. The second run's failures are the evidence the test tests
something. Where the pre-fix code would not link against the new test
(the test calls a function the fix introduced) a scratch copy of the test
without that call was built against the previous commit's source; where
the pre-fix behaviour was a hang it was run under `timeout`.

Results that were worse than the finding described:

- **M17**: with the second of three batch threads failing to start, the
  old code did not just mis-report the item — the process **aborted** in
  `pthread_join` on an uninitialised thread id.
- **LOW (SESSION_BIND)**: a daemon with no protocol context
  **segfaulted** on the first bind.
- **LOW (listen_fd)**: after a failed bind, `onode_destroy()` closed a
  descriptor number that had since been reused by something else. The
  test opens a canary descriptor after the failure and watches teardown
  close it.
- **M14**: the slow sender held a worker for 19.9 s (the whole frame);
  the stalled reader was still blocked in `send()` when the test was
  killed.
- **M18**: `onode_start()` returned 30.02 s after `onode_shutdown()`.
- **M20**: the second daemon did not refuse; it bound the first one's
  socket path and served.

Two findings have a test that does **not** fail before the change,
because there was nothing wrong to fix:

- **H3, driver defaults.** `tests/test_driver_route_defaults.c` passes
  on unmodified `main`. It is a pin, not a regression.
- **M22, shipped templates.** `t_M22_shipped_templates_still_load`
  asserts the stricter loader does not refuse the repository's own
  configs.

LOW items with no dedicated test, verified by inspection: the
`EVP_Digest` failure path (no way to make OpenSSL's SHA-256 fail from a
test), the `cJSON_free` pairing, and the locked counter reads (exercised
under ThreadSanitizer through `test_onode_review`, which reported
nothing before or after).

## Verification procedure

After each commit: clean build (`make all`, `make prod`,
`make demo-daemon`), the full battery (`make all-tests`), `scripts/check-obs-build-ordering.sh`,
`make asan-test`, and ThreadSanitizer over the threaded suites. This ran
in a second worktree so that work on the next finding could not disturb
it.

Things worth knowing about that procedure:

- **The battery must run under `umask 022`.** With `umask 002` the
  unmodified `main` fails `test-consume-ordering`: the fixture writes its
  approver registry group-writable and the registry loader (correctly)
  refuses it. CI uses 022. This is a property of the fixtures, not of
  this branch, and was left alone.
- **ThreadSanitizer needs ASLR off** on this toolchain (`setarch -R`);
  otherwise libtsan aborts at startup. `make tsan-test` does it.
- **TSan on unmodified `main` reported two data races, both in the test
  harnesses** (`volatile int` stop flags in `test_onode_concurrency.c`
  and `test_chain_concurrency.c`), none in the daemon. They are fixed in
  the `test(tsan)` commit so a TSan report now means the daemon. The
  three commits before that one were verified with exactly those two
  reports allowed and no others.
- **The battery was run in parallel (`make -j6 all-tests`) with a
  sequential re-run on any failure**, from H4 onward, to keep the
  per-commit cost down. A real failure fails both ways; a collision
  between two suites sharing a `/tmp` fixture path costs a re-run and
  cannot become a pass.
- **Three commits were amended locally before anything was pushed**, and
  each one and everything after it was verified again under its new
  hash. Nothing was force-pushed; the branch had not been pushed.
  - *M6* broke an existing `test_onode.c` case that re-registered an
    observation hash another test had already registered — the exact
    behaviour M6 forbids. The test was given its own commitment.
  - *M20* had a bug of its own, found on re-reading: a state started
    again without being destroyed was refused by its own instance lock
    (a second open of the lockfile is a second open file description).
    Fixed, with a check in the M20 test.
  - *LOW* changed the heartbeat's `rnode_ok` to false, and an existing
    `test_onode.c` assertion expected 1. The per-commit run caught it;
    the assertion now states the new contract.
- **Two false alarms, both from the verification harness and not from
  the code.** `test_operability` aborted once because a stale socket
  from a verification run I had interrupted was still in `/tmp`; it
  passes on a clean `/tmp`. And the M3 commit's *build* step failed once
  with a corrupt-archive link error: the script had given `all` and
  `prod` to a single `make -j`, and `prod` is a recursive make that
  recompiles the same objects into the same `build/`. The script now
  builds the three targets one after another, as CI does, and that
  commit was verified again.

**Not run locally:** the clang/libFuzzer build (`make
fuzz-onode-parsers`). The build host has no clang. The gcc smoke target
(`make fuzz-onode-parsers-smoke`) was run; the libFuzzer build is
exercised by CI.

---

## HIGH

### H1 — approved-apply replay guard

**Verified.** `apr.chain_entry_hash` is read from the third line of
`approvals/<id>.rec` (`approval_load_raw`). The approver's signature
covers the canonical payload reconstructed from the first line; the
third line is not covered. The guard in `onode_execute_legacy` was
`if (refuse_err == VIRP_OK && apr.chain_entry_hash[0])`, so an empty
field skipped it, and a different value made the count zero.
`virp_approval_commit_consume_locked` returning `APPROVAL_REUSED` was
logged ("continuing to execute"). All three replays in the finding were
reproduced.

**Changed.** Under `consume_lock`, before the intent is committed:

- (a) `virp_approval_is_consumed_locked()` — new, read-only — refuses if
  the proposal is already on `consumed.list`. A list that exists and
  cannot be read is a refusal.
- (b) `virp_chain_approval_entry_hash()` — new — reads the entry hash of
  the `approval` entry with `artifact_id = "approval:<proposal_id>"`.
  Refused unless exactly one exists and it equals the record's hash
  (constant-time). An empty record hash now refuses.
- (c) Prior intents are counted by the chain's approval entry hash *and*
  by proposal id (`virp_chain_count_intents_for_proposal()`, new).
- (d) `REUSED` from the post-intent cache write is a refusal. Because the
  intent is already committed at that point, it is closed with a failed
  `outcome` so the verifier does not grade a refusal as an open
  execution.

**Error codes.** (a), (c), (d): `APPROVAL_REUSED`. (b):
`APPROVAL_NOT_FOUND` — the record names no APPROVAL entry the chain
holds. There is no dedicated "record does not match the chain" code and
adding one was not necessary to fix the finding; the message says
exactly what happened.

**Left as is.** The intent counts scan every `gate_intent` body, as the
existing hash-keyed count does. An intent entry whose body row had been
deleted from `artifacts` would not be counted; that requires write
access to `chain.db`, which the verifier detects and which is outside
what this guard is for.

### H2 — `fed_outcome_citation`

**Verified.** `cJSON_GetObjectItemCaseSensitive` returns the first
member of a name; `cJSON_IsTrue` is false for `1` and `"true"`. All
three bodies in the finding were accepted as error-backed outcomes
claiming nothing.

**Changed.** `executed` is counted over the root's members: more than
one, or one that is not a JSON boolean, makes the citation
`FED_CITE_NONE` and GATE 4 refuses the outcome. Absent still means no
claim.

**Found later by the fuzz harness** and fixed in the fuzz commit: the
function set the execution flag even when it returned `FED_CITE_NONE`.
Unreachable through the one caller, but wrong.

### H3 — tier consistency

**Verified, and the premise is false.** `asa_route_command`,
`junos_route_command` and `fg_route_command` each end in
`return best ? best->tier : VIRP_TIER_RED`, with a comment recording
that they *used* to return YELLOW. `pa_route_command` and
`cisco_gate_tier` do the same. Existing suites already cover ASA and
JunOS. **No default was changed.**

**Changed.**

- `tests/test_driver_route_defaults.c`: one table, all five classifiers,
  unmapped commands and `NULL` → RED. In `make test-drivers`.
- Blocked-address comment in `virp_onode.c`: "RED by absence" was false.
  A FortiGate `config ...` is RED by an explicit `{ "config", RED }` row;
  absence would also give RED. The comment now says both, and that the
  argument does not cover pve1 (linux driver).
- `onode_effective_max_tier` / `onode_ceiling_source`: both comments
  still described a tighten-only helper. Since 2026-09-15 an explicit
  per-uid row decides in both directions.
- `virp_onode.h`: the per-uid ceiling docs said BLACK selects
  passthrough. It is retired and rejected.
- `virp.h`: `VIRP_TIER_YELLOW` was "single approval required". At the
  default YELLOW ceiling it executes with no approval. The block now
  states what the gate does.
- `virp_driver_zammad.h`: the YELLOW write row's safety argument leaned
  on "the helper only ever tightens". It rests on uid 993's GREEN config
  row and the comment now says so — including that raising that row
  would let the remote requester execute the write.
- `virp_onode.h` blocklist doc and `virp_onode_prod.c` ceiling doc.

**Found while documenting.** `onode_set_uid_ceilings` validated and
stored in one pass: a call rejected for a bad tier at index N had
already overwritten rows 0..N-1 of the live table. It now validates
first. Test: `t_H3_uid_ceiling_contract`.

### H4 — policy mode and the driver classifier

**Verified.** Under `policy_call.policy` the tier was the policy's
effect class and `gate_classify()` was never called.
`onode_approval_challenge` skipped the driver whenever
`virp_policy_classify` recognised the command.

**Changed.** `gate_policy_tier()`:

- driver BLACK → BLACK, unless `virp_policy_reboot_permitted()` says
  this action is the typed reboot (evaluated under
  `virp_policy_dispatch_enter`, the context the driver backstop sees);
- driver UNCLASSIFIED → UNCLASSIFIED (blocks);
- otherwise the higher tier.

`onode_approval_challenge` uses the same function.

**Consequence — please read.** Commands in the policy grammar that a
driver's table does not list at the policy's tier are now gated at the
driver's. With today's tables:

| driver | command | policy tier | driver tier (now applied) |
|--------|---------|-------------|---------------------------|
| linux / proxmox | `hostname` | GREEN | RED |
| linux / proxmox | `uname -sr` | GREEN | RED |
| linux / proxmox | `qm status <id>`, `pct status <id>` | GREEN | RED |
| linux / proxmox | `qm start <id>` | YELLOW | RED |
| cisco_asa | `show ip route` | GREEN | RED |
| juniper | `show clock`, `show ip route` | GREEN | RED |
| fortigate | `show version`, `show clock`, `show interfaces`, `show interfaces status`, `show ip route` | GREEN | RED |

The reboots (`reload`, `reload noconfirm`, `request system reboot`,
`execute reboot`, `reboot`, `systemctl reboot`) are driver-BLACK and
stay permitted as the policy's typed reboot. The health reads
(`uptime`, `show version` on Cisco/ASA/JunOS, `get system status`) are
unaffected.

Several of the rows above are commands the vendor does not have (JunOS
has no `show ip route`), so RED is arguably right. The linux rows are
real reads that an `observe` or `supervised` principal could run before
and now needs approval for. If that is not wanted, the fix is a GREEN
row in the linux gate table — a driver change, deliberately not made
here.

---

## MEDIUM

### M1 — whole buffer, exact length, duplicate keys

**Verified.** `cJSON_Parse` stops after the first value; a raw NUL
shortens the C string; `GetObjectItem` takes the first of a duplicated
key. Four request shapes were shown accepted before and refused after.

**Changed.** Both parsers start at `onode_parse_root_object(json, len)`.
`parse_request` and `parse_batch_commands` take the frame length;
`validate_turn`'s re-parse uses the same function.

**Decisions.**

- A root object with more than 64 members is refused before the
  quadratic duplicate scan. The wire vocabulary is about forty keys.
- Duplicate keys inside a batch *item* are refused too — same ambiguity.
- Duplicates inside nested objects (a validator manifest) are not
  policed here.

### M2 — over-length optional fields, hex lengths

**Verified.** Over-length and absent were indistinguishable for every
field outside the chain trio. An over-long `constraints` stored an
intent with none.

**Changed.** `json_extract_optional_string`: present-but-over-length or
present-but-not-a-string rejects the request. `hex_decode_exact` for
nonces and session id. `parse_u8_csv` replaces `strtok` + `atoi` + cast
for `versions` / `algorithms`.

**Decisions.**

- JSON `null` is treated as absent. Any other non-string type rejects.
- `SESSION_HELLO` without a `client_nonce` is still accepted (the server
  nonce is what makes the session id fresh). A supplied nonce must be
  exact. `SESSION_BIND` requires all three hex fields.

### M3 — device name

**Verified.** `separator_refuse_chain` built its session id from the
request's device string before the device was looked up.

**Changed.** Canonical-string check at both ingresses. The device is
resolved before recording; unknown devices are filed under
`gate-separator:_unknown`. The body keeps the claimed name and gains
`device_known`. `onode_add_device` refuses the hostname `_unknown`.

### M4 — intent store / get

**Verified.** `intent_format_json` pasted three stored texts in as raw
JSON values and two as unescaped strings. A stored `constraints` of
`{},"signature_hmac":"…"` produced a signed response with two
`signature_hmac` members.

**Changed.** As the finding asks, with one deliberate difference:

- `intent_json` is stored **byte-for-byte**, not re-serialized.
  `intent_hash` must equal `sha256(intent_json)`; re-serializing the
  body would break the commitment that check had just established.
  `proposed_actions` and `constraints` are stored re-serialized.
- All three are embedded as parsed values on `intent_get`. A legacy row
  whose text does not parse is refused rather than signed.
- Timestamps and the sequence are emitted as raw integer tokens, so the
  wire bytes for well-formed input are unchanged and exact.
- `virp_chain_artifact_store`'s return is checked.

**Deferred.** The intent row and its artifact body are two statements.
If the second fails the request now fails, but the row exists without a
body and a retry is refused as a duplicate id. Making them one
transaction needs a chain function that stores both
(`virp_chain_intent_store_with_artifact`, say), which is a chain API
addition and was not attempted.

**Not policed.** The `session_id` recorded on an intent's *artifact row*
is caller-supplied and is not a chain session.

### M5 — reserved sessions

**Verified.** GATE 1 reserved types, nothing reserved sessions.

**Changed.** `chain_append` and `validate_turn` refuse a session id
starting with `gate-enforce:`, `gate-separator:`, `approval:` or
`node-config:`. For `validate_turn` both the request's `session_id` and
the manifest's root `session_id` are checked.

**"The native-epoch prefix" does not exist.** The epoch is a *suffix*,
`<session>@<epoch>`, applied in `chain_append_locked` to three of the
reserved prefixes. The prefix refusal already covers those. The nearest
equivalent was implemented: with an epoch configured, an external
session id ending in `@<epoch>` is refused.

**Noted, out of scope.** `validator_parse_manifest` copies the
manifest's `session_id` with `snprintf` into a fixed buffer
(`src/virp_validator.c`), i.e. truncates. The prefix check here runs on
the full string, and truncation cannot change a prefix, so M5 holds; the
truncation itself is a validator matter.

### M6 — one observation, one registration

**Verified.** Nothing prevented the same signed observation being
registered again under another id or session.

**The chain API allows it**, so it is implemented in the append
transaction: `virp_chain_append_external()` sets a flag that makes
`chain_append_core_locked` run the check after `BEGIN IMMEDIATE`. The
socket handler uses it; `virp_chain_append*()` are unchanged, because
tools and fixtures build chains directly and many reuse a placeholder
hash.

**The index.** See [Read this first](#read-this-first). Without it the
check is a full scan inside the write transaction: 69 ms per append at
500,000 entries (measured), against 0.007 ms.

**Before deploying**, this lists what is already duplicated:

```sql
SELECT artifact_hash, COUNT(*) AS entries,
       COUNT(DISTINCT artifact_id || '|' || session_id) AS registrations
FROM chain_entries
WHERE artifact_type IN ('observation', 'fed_observation')
GROUP BY artifact_hash
HAVING registrations > 1;
```

Existing rows are untouched. But if this returns rows from a current
client, that client re-registers observations and will start receiving
`-51`.

**Residual.** A principal allowed to append observations could register
a hash before its rightful owner does, and the owner's append would then
be refused. It needs the observation bytes in advance and an appender
uid; noted, not addressed.

### M7 — hostnames

**Verified against `virp_chain.c`.** `session_id` is `char[64]`. The
plain form is copied with `snprintf` (truncated) while the last-entry
lookup uses the full string, so the second append retries sequence 0 and
fails the UNIQUE constraint.

**Changed.** `onode_add_device` refuses a hostname that fails the
canonical-string check or whose longest derived id exceeds 63 bytes: 48
bytes with no epoch, 33 with a 16-character one. `onode_start` repeats
the check because the epoch is set after the devices load. The shipped
templates' longest hostname is 18.

### M8 — nanosecond fields

See [Read this first](#read-this-first). Readers checked:
`report/verify.py`, `report/virp_report.py`, the C verifier,
`src/virp_tool.c` (uses the `canonical` hex), `tacacs/` (reads the
approval *record*, already a string, through `evidence_int`),
`autopilot/`, `api/`, `tools/`, and the sibling Rust tree. None parses
the three as numbers from daemon output.
`tests/adversarial/f1-approve-race.sh` greps the challenge text and was
updated.

### M9 — policy refusals

**Verified.** `return VIRP_ERR_ACTION_FORBIDDEN` with a stderr line.

**Changed.** The request is marked refused and travels the normal path;
`onode_execute_legacy` answers first with `policy_refuse_obs()`. Going
through the legacy path means a v3 node wraps it like any other refusal.

**Client-visible.** These requests now return a signed ERROR
observation instead of `-50`. `tests/test_policy_daemon.c` asserted the
bare code at six sites and was updated; its "nothing dispatched"
assertions are unchanged. The bare code remains for the recursion guard
and for a journal that cannot settle a finished attempt.

### M10 — peer uid

Additive `uid` on the tier, separator and replay rejections. Proposer
is `"<session marker> uid:<n>"`; the record's `session_id` keeps the
bare marker.

### M11 — verify responses

Ten members added, one builder for both actions, cJSON. `error_detail`
is now present on both. `to_sequence` is echoed as a raw integer token.

### M12 — session lost after dispatch

**Verified.** Both paths returned the bare `SESSION_INVALID`, the same
code as the pre-dispatch refusal.

**Changed.** `gate_observation_unavailable_obs()`. It carries no device
output, so it is not the master-key downgrade the v2 path forbids. For
v3, if the staged result was itself an ERROR its text is relayed rather
than replaced by a claim of execution.

### M13 — proposal id

**Verified**, and the layout change needed care: two in-repo clients
parse this text.

- `tools/cage/port_native.py` requires the message to **start with**
  `ERROR: tier gate blocked `.
- `tools/virp-shell.py` matched `tier gate blocked '<cmd>' on …`.

So the id is placed *after* the fixed prefix and *before* the command:

    ERROR: tier gate blocked proposal_id=<32 hex> '<command>' on '<device>' (tier=… max=…)

The cage's prefix test still holds; the shell's pattern now accepts the
optional id and still reads old daemons. A refusal that files no
proposal (BLACK) is byte-identical to before.

**Pre-existing limit, unchanged.** A command whose canonical form
exceeds 511 bytes cannot have a proposal filed (the command hash's
buffer). Its refusal now arrives whole, with no id.

### M14 — client I/O

One absolute `CLOCK_MONOTONIC` deadline per request; `SO_SNDTIMEO`
(10 s); `ONODE_MAX_WORKERS_PER_UID` (half the pool, build-time
overridable). A connection over the cap is closed at accept, like a
saturated pool.

### M15 — verify bounds

**Changed.**

- A ranged `CHAIN_VERIFY` over 50,000 entries is refused with
  `MESSAGE_TOO_LARGE`. Verify cost was measured at about 23 µs per entry,
  so a full-size request holds the chain lock for about a second.
- Per uid: one verify in flight, and 20 s of verify time per 60 s
  window, then `RATE_LIMITED`. Time is metered, not requests, because
  the autopilot's chainwalk verifies every session back to back.
- `tools/virp-shell.py`: `show chain` verified each listed session from
  0 to its last sequence in one request. For a session over the cap it
  now verifies the newest 50,000 entries and labels the row `(tail)`.

**Deferred — "do not hold exec_mutex behind a verify".** The execute
path holds the device's `exec_mutex` while it commits the pre-dispatch
intent, which needs the chain lock a verify holds. The cap bounds every
ranged verify and the budget bounds any one uid. What is left:
`CHAIN_VERIFY_SESSION` on a very large session still holds the chain
lock for its whole walk. It has no range to cap — covering the whole
session against its signed head is its purpose.

Removing it properly means running verifies on their own read-only
SQLite connection (WAL allows a reader beside the writer), so they never
take the append lock. `virp_chain_open_verifier_ex()` exists for offline
use, but whether a second handle grades the signature tiers identically
to the writer's own, with the daemon's keys, needs establishing before
the daemon's verdicts are moved onto it. That is a chain design change
and was not attempted here.

### M16 — proposals

Dedupe key is `(device, command hash, proposer)` with the proposal's own
hash, so a whitespace variant is the same proposal. Only an *open*
proposal is reused. 20 new proposals per uid per 60 s; past it the
refusal is unchanged but carries no id. The cache is in memory: after a
restart the first repeat files one more.

### M17 — batch threads

See [How each fix was shown to matter](#how-each-fix-was-shown-to-matter).
An item with no thread carries `RATE_LIMITED`. Thread creation goes
through `ONODE_PTHREAD_CREATE`, a compile-time seam that is
`pthread_create` unless a test including the source defines it.

### M18 — shutdown

`running` is atomic; an eventfd wakes the loop; the handlers call
`onode_shutdown()` and nothing else; a request before the loop starts is
latched; the shutdown action is acknowledged with
`{"status":"shutting_down"}` *before* shutdown is requested.

### M19 — session ownership

`SESSION_BIND` records the peer uid against the session generation.
Another uid's `SESSION_CLOSE` is `ACTION_FORBIDDEN`; another uid's v2/v3
execute is `SESSION_INVALID` before dispatch. A session bound without
the socket handler (tests) has no owner record.

**Operational consequence.** There is one session per daemon. The uid
that binds it holds it until it closes or it idles out (5 minutes);
another uid can no longer take it over by closing it. Two uids that both
need session-bound execution will take turns at best.

### M20 — instance lock and sequence

**Lock.** `flock(LOCK_EX | LOCK_NB)` on `<socket_path>.lock`, taken
before the stale socket is unlinked, held until `onode_destroy()`.

**Sequence.** `onode_set_seq_store(path)`. A durable reservation is kept
1024 ahead and extended before any number above it is issued; a clean
shutdown writes the exact value. `virp-onode-prod` uses
`<chain.db>.v1seq` — beside the chain, because `/run` does not survive a
reboot — and refuses to start if it cannot be set up. If a later
reservation cannot be written the daemon keeps running and logs once:
the sequence stays monotonic for that run and the exposure is the next
restart. The mock daemon configures none.

### M21 — observation key and `-k`

`-O <path>`; the equality requirement is gone. **`-3` without `-O`
still falls back to the `-S` key, with a warning**, so a unit written as
`-3 -S … -E …` keeps starting. A missing `-k` is fatal and is checked
before the options that need privileged files, which is what makes it
testable (`tests/test_prod_cli.sh`).

### M22 — config strictness

Unknown top-level keys are fatal. A key beginning with `_` is an
annotation — the shipped templates use them for rationale — and is
ignored. An explicit `socket_allowed_uids` requires
`socket_uid_tier_ceilings`.

`deploy/devices.node2.template.json` was the one shipped config with an
allowlist and no ceilings. It gained a map giving both uids `yellow`,
which is what they were already getting from `gate_max_tier`.

### M23 / M24 / M25 — config values

- **M23**: `gate_max_tier`, `gate_default_mode`, `gate_mode`,
  `gate_modes` — wrong type, unrecognised value, too many entries, or
  both mode keys together are fatal.
- **M24**: `parse_uid` for the action and type maps; a uid named twice
  is fatal. A malformed *value* still installs deny-all, as before.
- **M25**: `protected_vmids` declared but empty is fatal, including an
  explicitly empty array, matching `protected_agents`.

### M26 — `evidence_required`

`load_devices_production()` refuses `false`; `main()` calls it and no
longer assigns the flag. `load_devices()` remains the lab loader (mock
daemon, fixtures) and keeps the opt-out.

---

## LOW

One commit. Everything on the list was done:

| Item | What changed |
|------|--------------|
| Stack size | Workers and batch threads get an explicit 4 MiB (`ONODE_THREAD_STACK_BYTES`). The buffers were left on the stack. |
| `onode_start` | `mkdir`'s return decides; `listen_fd = -1` after an error close; `SOCK_CLOEXEC`, `accept4`. |
| Shared state | `prev_okey_accepts` atomic; `observations_sent`, `seq_num`, `reconnects`, `connections[]` read under their locks. |
| `EVP_Digest` | Checked. On failure the hash is the empty string, which every consumer refuses. |
| `cJSON_free` | Used for every `cJSON_PrintUnformatted` result. |
| Heartbeat | `rnode_ok` is false (the O-Node cannot observe the R-Node). The 16-bit count saturates. `virp-tool` and the shell render 0 as "not reported". |
| Framed errors | HEARTBEAT, LIST, LIST_FLEET answer failures. SHUTDOWN is acknowledged (M18). `jlen` checked in SESSION_HELLO. |
| `state->ctx` | NULL-checked in SESSION_BIND and SESSION_HELLO. |
| Range checks | `port`, `api_port` 1..65535; `node_id` 1–8 hex digits or a 32-bit integer; `device_id` likewise in 64 bits; `-n` 1–8 hex digits, non-zero; `-W` 1..604800. A present-but-invalid config value refuses the config. |
| Mock main | `load_devices_json` and its helpers removed. `VIRP_ALLOWED_UIDS` removed. |

On `VIRP_ALLOWED_UIDS`: "fix or remove" — removed. It installed an
explicit allowlist, and `onode_start()` refuses an explicit allowlist
with no action map, which the mock binary cannot supply. Setting the
variable could only stop the daemon starting. `SECURITY.md` listed it as
a working control and no longer does.

---

## FINALLY

**Fuzz targets.** `tests/fuzz_onode_parsers.c`, three targets from one
source. `make fuzz-onode-parsers` (clang) and
`make fuzz-onode-parsers-smoke` (gcc, deterministic). The two new entry
points abort on a postcondition violation, and one fired on the first
run — see H2.

**CI.** The ASan+UBSan job the review asked for already existed
(`sanitizers`). `test_onode_review` was added to `asan-test`, so the
review's regressions run there. Added: a `thread-sanitizer` job and the
fuzz steps.

---

## Deployment notes

Things that change on the first restart with this branch.

**Will refuse to start if not addressed**

- `virp-onode-prod` without `-k`. (The canonical unit passes it.)
- A config with `socket_allowed_uids` and no `socket_uid_tier_ceilings`.
  Checked: the three shipped templates and the cage's
  `recovery_policy.py` baseline have it (node2 was updated). Any config
  not in this repository needs looking at.
- A config with a top-level key the loader does not know and that does
  not start with `_`.
- A config with an unusable `gate_max_tier` / `gate_default_mode` /
  `gate_modes`, a non-uid key in the per-uid maps, a declared-but-empty
  `protected_vmids`, an out-of-range `port` / `node_id` / `device_id`,
  or `"evidence_required": false`.
- A hostname longer than 48 bytes (33 with a 16-character `-E` epoch).
- A second daemon on a socket path that is already being served.
- A `<chain.db>.v1seq` that exists and is not a number, or cannot be
  written. The file is created on first start; the directory must be
  writable by the daemon (it is where `chain.db` lives).

**Clients will see**

- Policy refusals as signed ERROR observations, not `-50` (M9).
- `proposal_id=` before the command in a tier refusal (M13).
- `approved_at_ns` as a string in the challenge and result (M8).
- `-15` for a ranged verify over 50,000 entries and `-57` when over the
  verify budget (M15).
- `-51` when registering an observation hash already registered under
  another id or session (M6).
- `-30` / `-50` when using or closing a session another uid bound (M19).
- A framed `{"status":"shutting_down"}` in answer to `shutdown` (M18).
- `rnode_ok` = 0 in heartbeats (LOW).
- Requests that were silently reshaped and are now refused: trailing
  bytes after the JSON, duplicate root keys, an over-length or mistyped
  optional field, a malformed nonce, a non-canonical device name
  (M1–M3).

**Will behave differently**

- Under owner policy, the commands in the H4 table need approval where
  they did not.
- With `-3` and no `-O`, a warning on every start (M21).
- One uid can hold at most half the worker pool (M14).
- A uid that repeats a refused command gets the same proposal back; past
  20 new proposals a minute it gets refusals with no id (M16).

## Things noticed and not touched

Outside the review's findings; recorded so they are not lost.

- `validator_parse_manifest` truncates the manifest `session_id` with
  `snprintf` (see M5).
- The battery's dependence on `umask 022`, and suites that use fixed
  `/tmp` paths, which is what prevents running two batteries at once and
  what produced the `test_operability` false alarm.
- `virp_chain_entry_commits_to()` (GATE 4) was an unindexed scan of
  `chain_entries.artifact_hash` on every `fed_outcome`. The M6 index
  makes it a lookup as a side effect.
- The apply-time intent counts parse every `gate_intent` body on each
  approved apply. Fine at today's scale; it grows with the chain.
- A v1 sequence is 32 bits. `onode_set_seq_store()` refuses at startup
  if the stored value is within one reservation block of the limit, but
  nothing guards the counter itself against wrapping inside a single
  run. Four billion signed messages away; noted, not addressed.
