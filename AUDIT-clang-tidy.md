# clang-tidy Audit Inventory

Generated: 2026-04-11
Tool: clang-tidy-14 (Ubuntu 14.0.0-1ubuntu1.1)
Config: `.clang-tidy` — cert-*, bugprone-*, clang-analyzer-security-*, clang-analyzer-core.*
Scope: src/*.c, src/drivers/driver_mock.c (core library only, optional drivers excluded)

## Summary by Check

| Count | Check ID | Severity | Notes |
|------:|----------|----------|-------|
| 189 | clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling | warning | memcpy/memset/snprintf flagged — suggests `*_s` variants. Low priority: all call sites are already bounds-checked. |
| 151 | cert-err33-c | warning | Unchecked return values (snprintf, fprintf, close, etc). Most are logging calls where failure is non-fatal. |
| 9 | clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling (driver_mock) | warning | Same as above, in mock driver. |
| 7 | clang-diagnostic-macro-redefined | warning | `_POSIX_C_SOURCE` redefined in multiple files. Harmless — each TU defines it before includes. |
| 4 | cert-err34-c | warning | Unchecked `atoi`/`strtol` return — in virp_tool.c CLI parsing. |
| 2 | bugprone-signal-handler | warning | fprintf in signal handler (virp_onode_main.c). Technically UB per POSIX but standard practice. |
| 2 | bugprone-implicit-widening-of-multiplication-result | warning | `i * 2` in hex loops — int multiplication used as ptrdiff_t. No overflow risk (i < 32). |
| 1 | bugprone-branch-clone | warning | Duplicate branches in virp_onode.c. Likely intentional (different semantic paths, same code). |
| 1 | cert-msc30-c | warning | `rand()` in driver_mock.c. Expected — mock driver, excluded from lint-rand. |

**Total: 366 findings across 13 files.**

## Summary by File

| File | Findings |
|------|------:|
| src/virp_chain.c | 94 |
| src/virp_onode.c | 82 |
| src/virp_message.c | 58 |
| src/virp_tool.c | 40 |
| src/virp_transcript.c | 18 |
| src/virp_handshake.c | 18 |
| src/virp_onode_json.c | 15 |
| src/virp_crypto.c | 10 |
| src/drivers/driver_mock.c | 9 |
| src/virp_onode_main.c | 8 |
| src/virp_session.c | 7 |
| src/virp_federation.c | 5 |
| src/virp_driver.c | 1 |

## Triage Notes

**High priority (actionable):**
- `bugprone-signal-handler` (2): Replace fprintf in signal handler with async-signal-safe write().
- `cert-err34-c` (4): Add return-value checks for strtol in virp_tool.c CLI parsing.

**Medium priority (defense-in-depth):**
- `cert-err33-c` on security-critical paths (RAND_bytes, HMAC, close on key files): add checks.
- `cert-err33-c` on logging (fprintf, snprintf for display): suppress — failure is non-fatal.

**Low priority / suppress:**
- `clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling`: All 189 are memcpy/memset/snprintf with correct bounds. The `*_s` (Annex K) functions are not portable and not available on Linux/glibc. Suppress.
- `bugprone-implicit-widening-of-multiplication-result`: Loop index `i` is always < 32. No risk.
- `bugprone-branch-clone`: Inspect but likely intentional.
- `clang-diagnostic-macro-redefined`: Consolidate `_POSIX_C_SOURCE` to a single project-wide header if desired.
