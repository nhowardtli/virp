# VIRP Audit Remediation — Close-Out Report

**Date:** 2026-04-12
**Audited by:** External review
**Remediated by:** Nate Howard + Claude Code
**Branch:** main
**Build:** `make CISCO=1 FORTIGATE=1 LINUX=1` (all items), `make dev-full` / `make prod-full` (full driver set)

---

## Summary

All 10 audit findings remediated in 11 commits. 37 tests added or updated (25 C, 12 Python). Build stays clean under `-Wall -Wextra -Werror -pedantic` across all 7 drivers.

One follow-up action is pending: deletion of the legacy string-search JSON parser after 48 hours of dual-parse validation in the lab.

---

## Items

### 1. CRITICAL — virp_verify ctypes signature wrong
**Commit:** `e21a09d`
**Defect:** Python bridge declared `virp_verify` with 3 args; C signature takes 4 (`ctx` added in context refactor). Any call to `verify_observation()` segfaulted.
**Fix:** Added `ctypes.c_void_p` (ctx, passed as NULL) to argtypes and call site.
**Test:** `tests/test_bridge_verify.py` — sign-then-verify round-trip, tamper detection, wrong-key rejection. Old 3-arg signature confirmed segfault (exit 139).

### 2. CRITICAL — Bridge references symbols not in library
**Commit:** `63d5ea8`
**Defect:** `fg_route_command` (function) and `FG_ROUTE_TABLE_SIZE` (data) referenced by bridge but never compiled into `libvirp.so`.
**Fix:** Path (b) — removed dead bindings. `fg_route_table_full.c` has no function implementation, no header, no Makefile integration. Left dated TODO.
**Test:** `VIRPBridge()` instantiates; `nm build/libvirp.so | grep fg_route` returns empty.

### 3. HIGH — Python reimplements HMAC verification
**Commit:** `6fac817`
**Defect:** `server.py` verified HMACs in pure Python (`hmac.new`), duplicating C `virp_verify`. Two implementations will drift.
**Fix:** Primary verification routes through `VIRPBridge.verify_observation()` (C library). Python fallback fenced behind `VIRP_ALLOW_PY_FALLBACK=1` with per-use warning.
**Test:** `tests/test_hmac_parity.py` — C and Python agree on valid, tampered, wrong-key, and multi-payload inputs (4 tests).

### 4. HIGH — Tier constant drift (BLACK = 0x04 vs 0xFF)
**Commit:** `1d29820`
**Defect:** `server.py` defined `BLACK` as `0x04`; `include/virp.h` defines `VIRP_TIER_BLACK` as `0xFF`.
**Fix:** Corrected dict. Added `scripts/gen_constants.py` that parses `include/virp.h` and emits `api/_virp_constants.py` so Python constants cannot drift from C.
**Test:** Generated constants verified: `VIRP_TIER_BLACK=0xFF`, `VIRP_MAX_PAYLOAD_SIZE=65480`.

### 5. HIGH — Per-connection concurrency hole in batch_execute
**Commit:** `a056606`
**Defect:** `batch_execute` threads sharing the same device raced on the `virp_conn_t*` (libssh2 session). Previously guarded by rejecting duplicate devices (overly conservative).
**Fix:** Added `pthread_mutex_t exec_mutex[ONODE_MAX_DEVICES]` to `onode_state_t`. Held during the entire execute path in `onode_execute`. Removed duplicate-device rejection — same-device batching now safe.
**Test:** `test_batch_same_device_concurrent` — 8 parallel commands to same device, all 8 valid signed observations with unique sequence numbers. 24/24 pass.

### 6. HIGH — No SSH host key verification
**Commit:** `8a7ad44`
**Defect:** All 6 SSH drivers authenticated without checking the remote host key. MITM trivial.
**Fix:** Shared `src/virp_ssh_hostkey.c` with `virp_ssh_verify_hostkey()` — loads `~/.virp/known_hosts`, rejects mismatch, TOFU on first use. Called after handshake, before auth, in all 6 drivers.
**TOFU control:** `VIRP_SSH_TOFU=1` env var overrides at runtime. `VIRP_SSH_TOFU_DEFAULT` compile flag baked into dev builds (`make dev-full`) but NOT prod builds (`make prod-full`).
**Error codes:** `VIRP_ERR_HOST_KEY_MISMATCH` (-33), `VIRP_ERR_HOST_KEY_UNKNOWN` (-34).
**Test:** All 7 drivers compile clean. 24/24 O-Node tests pass (mock driver unaffected).

### 7. HIGH — Wazuh driver disables TLS verification
**Commit:** `90f7d03`
**Defect:** `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` set to 0 in both auth and execute paths.
**Fix:** Default ON (`VERIFYPEER=1`, `VERIFYHOST=2`). Opt-out: `VIRP_WAZUH_INSECURE=1` with startup warning. Custom CA: `VIRP_CA_BUNDLE` env var.
**Test:** Builds clean. Wazuh live tests require Wazuh Manager instance.

### 8. MEDIUM-HIGH — O-Node socket framing and JSON parsing

#### Step 1: Socket framing (commit `c6871c2`)
**Defect:** Single `recv()` into fixed buffer treated as complete request. No framing, no version negotiation.
**Fix:** v2 framing: `[4B big-endian payload length][0x02 version byte][JSON]`. `recv_exact()` handles EAGAIN, EOF, partial-read. v1 detection: first byte non-zero -> unframed `VIRP_ERR_PROTOCOL_VERSION` (-35) -> close. Batch responses accumulated into single frame.
**Test:** `test_v1_unframed_client_rejected` — sends raw JSON, asserts `-35` error code. 25/25 pass.

#### Step 2: JSON parser (commit `c4f7bcd`)
**Defect:** `json_extract_string` used `strstr` to find keys — matched nested keys, no real JSON parsing, fragile on edge cases.
**Fix:** Vendored cJSON v1.7.18 (MIT, pinned commit `acc76239`). `parse_request()` and `parse_batch_commands()` use cJSON. Old parser retained under `VIRP_JSON_DUAL_PARSE` compile flag for side-by-side validation.
**Dual-parse results:** All disagreements are known false positives (old parser's strstr matching nested batch keys). Zero real behavioral differences.
**Pending:** Delete old parser + `VIRP_JSON_DUAL_PARSE` flag in one atomic commit after 48 hours of clean dual-parse in the lab.

### 9. MEDIUM — parse_virp_message() trusts header length
**Commit:** `ebd99c5`
**Defect:** `payload_len = length - VIRP_HEADER_SIZE` without checking `length <= len(msg)`. Oversized length field reads past buffer silently.
**Fix:** Added two bounds checks: `length >= VIRP_HEADER_SIZE` and `length <= len(msg)`. Both raise `ValueError` with descriptive message.
**Test:** `tests/test_parse_message_bounds.py` — truncated, oversized, undersized, too-short, and valid message. 5/5 pass.

### 10. LOW — Makefile target drift (dead PALOALTO := 1)
**Commit:** `508a04c`
**Defect:** `prod: PALOALTO := 1` set a target-specific variable that nothing checks (Makefile uses `ifdef PANOS`). All 4 `prod:` variable assignments were dead (target-specific variables don't affect `ifdef` at parse time).
**Fix:** Removed 4 dead lines. Added comment directing to `make prod-full`.
**Test:** Build unchanged.

---

## Pending Actions

| Action | Trigger | Owner |
|--------|---------|-------|
| Delete old JSON parser + `VIRP_JSON_DUAL_PARSE` | 48h clean dual-parse in lab with agentic loop | Nate |
| Pre-populate `~/.virp/known_hosts` for lab devices | Before switching to `make prod-full` posture | Nate |
| Integrate `fg_route_table_full.c` into library | When FortiGate route-command function is implemented | Nate |

---

## Test Inventory (added by this remediation)

| File | Tests | Items covered |
|------|-------|---------------|
| `tests/test_bridge_verify.py` | 3 | #1 |
| `tests/test_hmac_parity.py` | 4 | #3 |
| `tests/test_parse_message_bounds.py` | 5 | #9 |
| `tests/test_onode.c:test_batch_same_device_concurrent` | 1 | #5 |
| `tests/test_onode.c:test_v1_unframed_client_rejected` | 1 | #8.1 |
| `scripts/gen_constants.py` | (build-time) | #4 |
