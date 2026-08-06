# Test #4 — Audit blockers: parser bounds, approval attribution, framing, identity

**Date:** 2026-08-04 · **Host:** virp-lab · **Branch:** `test/adversarial-2026-08-03`
**Baseline:** `20fffc00` (transcript 03 tip). Nothing pushed, nothing installed;
production daemon untouched. All work in `~/virp-work`, `/opt/virp` fast-forwarded
only at session end.

---

## Task 0 — findings on record before any code was changed

### 0a. send_framed() and the raw-send inventory

**Headline: the reviewer's citation is accurate for this branch, but the framing
is wrong — nothing was "missed" by 5cd1e2d9. The whole commit is absent from
this branch.**

`git merge-base --is-ancestor 5cd1e2d9 20fffc00` → **not an ancestor** (same for
the merge `5459c5f4`). This branch forked from main at `b6e9602c`, before the
Aug 2 review fixes merged. On main, `send_framed()` routes through `send_all()`
(per the 5cd1e2d9 diff); on this branch, `send_all()` does not exist anywhere in
the tree, and `send_framed()` at `src/virp_onode.c:1931-1937` is exactly the
code the reviewer quoted:

```c
static void send_framed(int fd, const void *buf, size_t len)
{
    uint32_t net_len = htonl((uint32_t)len);
    send(fd, &net_len, 4, MSG_NOSIGNAL);
    if (len > 0)
        send(fd, buf, len, MSG_NOSIGNAL);
}
```

Raw unlooped socket output at 20fffc00:

1. `src/virp_onode.c:1934,1936` — `send_framed()`: two raw `send()` calls,
   return values ignored. A short write on the 4-byte prefix desyncs framing
   permanently. Covered by 5cd1e2d9 on main.
2. `src/virp_onode.c:2033` — the unframed v1 courtesy error
   (`VIRP_ERR_PROTOCOL_VERSION` to a legacy client): raw `send()`, return
   ignored. Also covered by 5cd1e2d9 on main.
3. `src/virp_tool.c:608-609` — CLI client framed request send: three `write()`
   calls checked for exact byte count but **no EINTR retry and no short-write
   loop**. NOT covered by 5cd1e2d9 (that commit touched the daemon only). A
   signal landing mid-write or a genuinely short write produces a spurious
   "Error: send failed" — fails loudly rather than desyncing, but it is the
   same class of bug and a genuinely missed call site.

Audited and clean (not socket output paths, or already correct):
- `src/virp_crypto.c:304` — proper short-write/EINTR loop (file I/O).
- `src/virp_federation.c:144,151` — single small key-file writes, count
  checked, file I/O.
- `src/driver_panos.c:323` `pa_io_write()` — loops on short writes and EAGAIN
  over libssh2.
- `src/virp_ssh_io.c` — writes go through the `io->write` callback, backed by
  the looping `pa_io_write`.
- `api/server.py:485` — Python uses `sock.sendall()`.
- Go port — `net.Conn.Write` guarantees full write or error by contract.

**Task 3 plan:** cherry-pick 5cd1e2d9 (send_all + its daemon call sites + its
tests) onto this branch, then fix `virp_tool.c` client sends in the same
commit-per-task discipline, plus a send_framed-specific short-write test.

### 0b. Observation version selection, every path (report only — no changes)

- **C parser default:** `parse_request()` at `src/virp_onode.c:390` sets
  `req->obs_version = 1` when the key is absent. Present-but-invalid (0, >2,
  non-numeric) rejects the request — a typo cannot silently downgrade
  (`src/virp_onode.c:390-399`). Reviewer's citation is accurate.
- **Single REST (`api/server.py:497` `onode_execute()`):** sends only
  `{action, device, command}`. `obs_version` appears **nowhere** in
  `api/server.py` (grep: zero hits) → daemon defaults to **v1**.
- **Batch (`_batch_execute_chunk()` / `onode_batch_execute()`):** same — no
  `obs_version` in the request → top-level default **v1** applied to every
  item (`src/virp_onode.c:2546-2549` copies the top-level value into each
  batch item).
- **`/api/sweep` (`api/server.py:1026`):** delegates to `onode_batch_execute()`
  → **v1**.
- **CLI (`src/virp_tool.c`):** `obs_version` appears nowhere in the file → the
  CLI never sends it → **v1**.
- **Go port (`implementations/go/virp/onode.go:44`):** `ObsVersion int
  json:"obs_version,omitempty"`. As a *server* it refuses `obs_version >= 2`
  with `ErrSessionInvalid` (-30) since the port has no session support
  (onode.go:274,319 — added by af927631). No Go client code sets it → **v1**.
- **The July 20 fix (`af927631`, actually committed Jul 21):** fixed the batch
  handler serving master-key v1 for items of an *explicit* `obs_version=2`
  batch (parser honored the key, handler ignored it). It routes batch items
  through `onode_execute_obs()` with the top-level version and made
  no-session fail per-item with SESSION_INVALID. It did **not** pin batch to
  v2 — it only stopped the explicit downgrade. Absent key still means v1.

**Net current behavior: every production execution path — single REST, batch,
sweep, CLI, Go — runs v1 (legacy master-key) observations unless a client
explicitly sends `obs_version: 2`, and no shipped client does.** Flipping the
default is a protocol decision deferred to a later session, as instructed.

---
## Task 1 — `b3ecfb80` — embedded lengths bounded by the actual payload

**Decision: `obs_length <= payload_len - 4`, not `==`.** Spec §9
(draft-howard-virp-03, `docs/VIRP-SPEC-RFC-v2.md:906-912`) defines the field as
"the exact number of bytes of device output that follow" explicitly so parsers
can "distinguish between device output and any future trailer fields" —
trailers are an anticipated extension point, so the C wire parser tolerates
them. The canonical bd46d28 precedent (`virp_bridge.parse_observation`)
enforces exact `==` — but at the *evidence* layer, for v1 evidence where no
trailer is defined, and its docstring explicitly says it compensates for the C
parser's missing bounds check. That stricter app-layer check is untouched and
remains a second line of defense. Recorded in a code comment at the check.

**Caller audit (`*data_len` consumers):**
- `src/virp_tool.c:279` — `hex_dump(data, data_len)`: overread up to ~64KB.
- `src/virp_tool.c:715` — `printf("%.*s", (int)data_len, data)`: overread.
- `src/virp_tool.c:726-728` — `memcpy` bounded by 2048 but sized from
  `data_len`: overread up to 2KB.
- `src/virp_tool.c:770-771` — `memcpy(out, data, min(data_len, out_max-1))`:
  overread up to out_max; with `payload_len == 4` and a nonzero claim, `data`
  was NULL while `data_len` was nonzero → `memcpy(out, NULL, n)`.
- Python bridge — already rejected mismatches (bd46d28).
All are fixed at the source: the parser now refuses to return an unbacked
`data_len` (`VIRP_ERR_INVALID_LENGTH`).

**Sibling found and fixed in the same commit:** `virp_parse_proposal()`
trusted the wire `obs_ref_count` (u32) — a 12-byte payload claiming 2^32-1
refs handed back a refs pointer callers would walk out of bounds (only
fuzz/test callers in-tree today, but it is a public API). Now mirrors the
builder: `count >= 1` (`NO_EVIDENCE`), `count <= VIRP_MAX_OBS_REFS`
(`MESSAGE_TOO_LARGE`), refs must fit (`INVALID_LENGTH`).
`virp_parse_heartbeat`/`hello`/`approval` read only fixed offsets under
minimum-size checks — clean. Python batch response parsing
(`_batch_execute_chunk`) bounds-checks per-item lengths — clean.

**Failure demonstrated at 20fffc00** (tests written first, run against
unfixed lib):

```
[Embedded-Length Bounds]
  test_parse_obs_truncated_claim      [FAIL] Expected -7, got 0
  test_parse_obs_oversized_length     [FAIL] Expected -7, got 0
  test_parse_obs_zero_length_data     [PASS]   (legal-case guard)
  test_parse_obs_exact_boundary       [PASS]   (legal-case guard)
  test_parse_obs_trailer_allowed      [PASS]   (documents the <= choice)
  test_parse_proposal_refs_overrun    [FAIL] Expected -7, got 0
  test_parse_proposal_count_over_max  [FAIL] Expected -15, got 0
  test_parse_proposal_zero_refs       [FAIL] Expected -12, got 0
  Results: 59/64 passed  (5 FAILED)
```

After fix: core 59/59. Malformed embedded-length cases added to
`fuzz_boundary()` (the repo's operative corpus — `make fuzz` runs in CI).

**Surprising:** `tests/fuzz_libfuzzer.c:42` called `virp_parse_observation`
with a stale pre-refactor signature `(data, size, char*, sizeof, size_t*)` —
the harness **did not compile**, so `make fuzz-libfuzzer` has been broken for
as long as that signature has been dead. Call fixed (and extended to
`virp_parse_proposal`); verified with `gcc -fsyntax-only` since this host has
no clang to actually run libFuzzer.

**Sanitizers:** full `make asan-test` (clean rebuild, gcc ASan+UBSan): core
59/59, onode 69/69, ssh-io 10/10, fg-scrub 4/4, chain 23/23, zero sanitizer
reports. `fuzz_virp` rebuilt under the same flags (verified `__asan` symbols
present): random 100k + mutation 100k + boundary all clean. Python
verify/bridge/parse-bounds: 29/29.

**Operational note:** after `make asan-test`, `build/libvirp.so` is left
ASan-instrumented; loading it via ctypes silently kills the Python test
process (buffered pytest output lost, looks like "no output, exit 0" behind a
pipe). `make clean && make` before running Python suites.

---
## Task 2 — `27ad2b5f` — approval-submit attribution: the loser learns who won

Confirmed exactly as cited: `*out` was filled with the submitter's identity
before the mutex (src/virp_approval.c, pre-fix ~690-700), and the
already-exists path returned bare `VIRP_OK` — the losing approver of a race
got "approved" with its own identity while the winner's record was canonical.
The daemon then *signed* that misattribution into an APPROVAL_RESULT
observation and logged it.

**Fix shape:**
- `approval_record_load()` extracted from `virp_approval_verify_consume()` —
  the on-disk record now has exactly one parser, shared by apply and by the
  submit already-exists path (single answer to "who is the approver of
  record").
- Already-exists returns `VIRP_APPROVAL_ALREADY_EXISTS` (+1, the enum's first
  success-class code) with `*out` = the canonical record. A corrupt/unloadable
  record surfaces its load error instead of OK.
- Caller audit: `onode_approval_submit()` (src/virp_onode.c) treats the new
  code as success, logs `submit idempotent: submitted_key=X
  approver_of_record=Y`, adds `already_approved` to the result JSON.
  `cmd_approve` (src/virp_tool.c) prints "ALREADY APPROVED … this submission
  was NOT recorded" instead of claiming the approval. `api/server.py` and the
  Go port never call submit (Go has no approval store) — no other callers.

**Failure demonstrated** (fix stashed, tests kept, at 27ad2b5f^ behavior):

```
[TEST] Concurrency: two submits for one proposal -> one chain entry FAIL: exactly one winner (line 746)
[TEST] Concurrency: race loser gets winner's identity + already-exists FAIL: exactly one winner (line 828)
=== Results: 21 passed, 2 failed ===
```

(Both failures are the unfixed both-return-VIRP_OK behavior.)

**Fixed:** approval 23/23 — the new two-different-approvers race asserts the
loser's `*out` carries the winner's key id, operator, timestamp and chain
hash; the persisted record (loaded via the same path apply uses) and the
single chain entry attribute the winner; and the record still
verify-consumes exactly once (consumed.list untouched). Core 59/59, onode
69/69 after the change.

---
## Task 3 — `3163365c` — send_framed via send_all, plus the CLI writer

Per Task 0a: this branch predates the Aug 2 fix entirely, so the resolution
was a cherry-pick of `5cd1e2d9` (applied cleanly: `send_all()`, the 0/-1
`send_framed`/`send_framed_error` contract, 11 gated call sites, the v1
courtesy error, both send_all unit tests) — the reviewer's line citation was
accurate *for this branch*, and stale only in the sense that main already
carried the fix.

Two additions beyond the cherry-pick:
- `src/virp_tool.c` `onode_framed_roundtrip()` — the client-side missed call
  site from 0a: three `write()` calls with exact-count checks but no
  EINTR/short-write loop. Converted to a `write_all()` with send_all
  semantics.
- A **send_framed-specific** short-write test (the cherry-picked pair only
  drives `send_all` directly): two frames through a 4 KiB SO_SNDBUF
  socketpair under SIGUSR1-without-SA_RESTART bombardment; asserts exact
  framing recovery — both length prefixes, all payload bytes, frame 2
  starting exactly at frame 1's end, no surplus. `send_framed` made
  non-static for the test (send_all precedent). `shutdown(sv[0], SHUT_WR)`
  before `pthread_join`, per the Aug 2 lesson.

**Failure demonstrated** by temporarily restoring the pre-fix send_framed
body (raw unlooped sends) and running the new test:

```
  test_send_framed_short_write_no_desync                       [FAIL]
    Expected 131087, got 16136 at line 1567
```

~115 KiB silently dropped mid-frame. Fixed: onode 72/72, approval 23/23
(the CLI e2e tests exercise the tool's write_all path over the live socket).

---
## Task 4 — `6ce8544e` — duplicate device identity fatal at config load

`onode_add_device()` accepted any identity collision. Fixed at the same choke
point that derives device_id (so explicit-vs-derived collisions are caught):
duplicate hostname, node_id, or device_id → `VIRP_ERR_DUPLICATE_DEVICE` (-46),
stderr names both devices with all three identity fields. Both loaders refuse
the WHOLE config on a duplicate (skipping one of the pair would leave the
first-listed device answering for both); dev main previously ignored the
loader's return value entirely — it now exits on a refused config, prod main
already did. node_id 0 (= absent) is exempt from the node_id comparison:
never routed, and approval binding pairs it with the still-unique hostname.

**Python registry had the same gap twice** (fixed under this task; only the
Go side is note-only):
- `yaml.safe_load` keeps the *last* duplicate mapping key — two devices
  sharing a hostname silently collapsed into whichever was defined later.
  Now a strict SafeLoader refuses duplicate keys with key + line number.
- `node_id_to_hostname()` builds an int→hostname map where a duplicate
  node_id silently overwrote. `load_devices()` now refuses duplicate
  node_ids compared as integers ('01010101' vs '1010101' still collide).

**Go-side gap (NOTED, not fixed):** `implementations/go/main.go
loadDevices()` → `ONode.AddDevice()` (onode.go:141) appends blindly — no
hostname/node_id uniqueness check (the Go port has no device_id at all).
Same class of gap as the C side had; left for the Go port's maintainer.

Out of scope honored: approvals stay bound to node_id; no rebinding.

**Failure demonstrated at pre-fix code** (behavior files stashed, tests kept):
```
  test_add_device_rejects_duplicate_identities  Expected -46, got 0 at line 2311
  test_load_devices_duplicate_identities_fatal  Expected -1, got 2 at line 2364
  Results: 74/76 passed  (2 FAILED)
```
Python pre-fix: 3 failed (dup hostname key, dup node_id, dup id different
spelling), 2 guard tests passed. Fixed: onode 74/74, registry pytest 5/5.

No production impact risk found: no devices.yaml exists in the repo or
/opt/virp (deployer-specific, env-pathed), and any collision-free config
loads identically.

---
## Post-rewrite hash map (2026-08-05)

The branch's local history was rewritten on 2026-08-05 to correct the
author name (Nick Howard → Nate Howard); trees are byte-identical.
Commit hashes cited in this transcript and in transcripts/03-fixes.md
map as follows:

| cited (old) | current (new) |
|---|---|
| 8d2d49ae | ced8e20a |
| ba6d6d14 | 3e5c7e57 |
| 6732d9eb | 50722cdd |
| f93324a6 | 919b2f5a |
| 20fffc00 | fff4dfd8 |
| b3ecfb80 | 5bab16bd |
| 27ad2b5f | 74ae4d2e |
| 3163365c | 02ca40bf |
| 6ce8544e | 7f884e80 |
