# Test #5 — Device-adversarial: making a real target misbehave at the execute boundary

**Date:** 2026-08-05 · **Host:** virp-lab · **Branch:** `test/adversarial-2026-08-03`
**Baseline:** `81ebcdb4`. Nothing pushed, nothing installed, production daemon and
production chain untouched. fi daemon rebuilt from this branch and run in the
foreground against a disposable spool at `/run/virp-fi/t05/`.

Everything before this transcript was unit suites, daemon-side fault injection, and
the witness canary. This is the first session in which a **real device was made to
misbehave during live execution**.

---

## 0. Blocker found before any test ran — the "sacrificial" targets are production

The brief names `clab-frr-ospf-frr1..4` as sacrificial. They are not isolated:

| Fact | Evidence |
|---|---|
| All four are production devices | present in `/run/virp/devices.json` |
| Prod daemon holds live SSH sessions to all four | `ss -tnp`: pid 788655 fds 7–10 → .2/.3/.4/.5 |
| Prod health-checks them every ~6 s | witness log: `cmd=uptime cmdsha=dd291cd6294bafef`, 34 in one 70-line window |
| `virp-autopilot.timer` executes against them **every 5 minutes** | `systemctl list-timers` |
| Those runs write into the **production chain** | journal: `[OK] clab-frr-ospf-frr1 vtysh -c "show ip ospf neighbor" … verified=VALID chain=obs:clab-frr-ospf-frr1:1785895502031887435`; `virp chain tail --db /var/lib/virp/chain.db` → session `autopilot:2026-08-05` seq 447 and climbing |

Making one of them hang or drop a connection — the entire point of this session —
would fail the autopilot's next battery and append error observations to
`/var/lib/virp/chain.db`, the file the brief declares untouchable. Per the standing
rule ("if a step would write prod state, stop and write it up instead"), the session
stopped here and the target was replaced rather than the rule bent.

**Resolution — a genuinely sacrificial fifth target.** `clab-frr-sacrifice`
(172.20.20.90): same `frr-ssh:10.2.1` image, same `clab` bridge, witness installed,
and **absent from the production device list**. The fi `devices.json` names it and
nothing else, asserted programmatically before every run
(`t05-device-abuse.sh: assert_isolated_target`), so fi-side abuse cannot reach a
prod-monitored device even by accident. Torn down at session end.

**Also found:** `/opt/virp/build-fi/virp-onode-prod` was stale (Aug 3; zero hits for
the retry-gating code). Task 1 run against it would have exercised the *old* blind-retry
path and "confirmed" a regression that no longer exists. Rebuilt from `81ebcdb4`;
freshness verified **behaviorally** (`outcome UNKNOWN` and `LEGACY_CHAIN` strings
present), never via `virp version`, which lags the build.

### Witness re-proved on the new target
Counting rule: **RECV lines per exact cmdsha; never DONE.** Benign GREEN canary
`vtysh -c "show ip ospf database"` through the full gate →

```
=== WITNESS RECV counts by cmdsha:
      1 a3fb7dd1b851dac1  vtysh -c "show ip ospf database"
```
Exactly one. Oracle trustworthy.

---

## 1. Headline finding — VIRP signs `success=true` for a command that never completed

**The chain over-claims against the witness. This is the invariant Task 3 declares
must never break, reached through Task 1.**

Method: a non-idempotent, countable side effect (`echo tick >> /tmp/virp-t05-ctr`,
counted with `wc -l`) wrapped in a device-side script that applies the side effect
and then destroys the connection before responding. Driven through the full
gate → propose → approve → apply path (bare shell is RED, so approval is mandatory).

### Results, all three sources

| Variant | side effect | witness | VIRP client | chain outcome |
|---|---|---|---|---|
| `t05-tick` (baseline) | 1 line | RECV 1, **DONE 1** | `TICK_OK`, exit 0 | `success=true` ✅ correct |
| `t05-tick-chankill` (exec channel dies after delivery) | 1 line | RECV 1, **DONE 0** | empty payload, exit 0 | `success=true` ❌ |
| `t05-tick-sshkill` (whole TCP session dies) | 1 line | RECV 1, **DONE 0** | empty payload, exit 0 | `success=true` ❌ |
| `t05-die-only` (no side effect at all) | **0 lines** | RECV 1, **DONE 0** | empty payload, exit 0 | `success=true` ❌ |

Nonce-level proof that the target never completed the operation — every `uptime`
health check has its matching DONE, only the command under test lacks one:

```
RECV a7cd00ea-80d0-438d-b317-1b07354dfd1b /usr/local/bin/t05-tick-chankill   <-- no DONE
RECV b9181ea3-243d-47a6-b073-c6709333840b uptime
DONE b9181ea3-243d-47a6-b073-c6709333840b
```

VIRP's account of that same operation:

```
[GATE] approval verified: proposal=cc118c… — executing
[GATE] outcome persisted: proposal=cc118c… seq=5 hash=7769a4ad23ecfacd success=true
```

The `t05-die-only` row is the purest form: the device did **literally nothing**
(0 side-effect lines, no output, no completion) and VIRP produced a signed
observation, `gate_decision=allowed`, client exit 0, and a persisted
`outcome … success=true`.

### Root cause

`src/drivers/driver_linux.c`:

```c
result->exit_code = libssh2_channel_get_exit_status(channel);
result->success   = (result->exit_code == 0);
```

`libssh2_channel_get_exit_status()` returns **0 when the peer never sent an
exit-status message** — precisely what happens when a channel dies abnormally. An
aborted command is therefore indistinguishable from "exited 0 with no output", and
the read loop's `break` on EOF/error is equally silent. The daemon then takes the
normal success path and signs a `DEVICE_OUTPUT` observation.

Timing note that sharpens it: the watchdog *did* notice the session died —
`[Linux] Disconnected` → `[Watchdog] Reconnecting` — but only **after** the outcome
had already been signed and persisted. VIRP held the evidence and committed first.

---

## 2. The retry/disposition machinery is unreachable on this driver after dispatch

Both the legacy blind-retry branch and the new `OUTCOME_UNKNOWN` branch
(`3dff0ef7`) are gated on `result.output_len == 0`:

```c
if (!result.success && result.output_len == 0 && result.no_dispatch)   /* retry */
if (!result.success && result.output_len == 0 && !result.no_dispatch)  /* UNKNOWN */
```

But the linux driver writes a `"<hostname>$ <command>\n"` prefix into the output
buffer **before** the read loop and never resets it:

```c
size_t prefix_len = snprintf(result->output, …, "%s$ %s\n", hostname, command);
total = prefix_len;          /* … */   result->output_len = total;
```

So once `libssh2_channel_exec()` has been called, `output_len > 0` **always**.
Neither branch can fire. Confirmed empirically: `grep -c 'outcome UNKNOWN|executed=unknown'`
over the whole session's daemon log = **0**, across every death variant above.

Two consequences, and the second is the more interesting one:

1. The Task 4 `OUTCOME_UNKNOWN` disposition never engages for the linux driver on a
   post-dispatch failure. The honest-disposition work does not cover this path.
2. **The P0 blind-retry double-execution is not reachable this way either** — under
   the *old* code the same `output_len == 0` guard was already false, so the blind
   retry would not have fired on connection death either. The P0 is masked by a
   worse bug: the operation is reported as a success rather than retried.

So "no double execution" tonight is a true result but must not be credited to the
retry-gating fix on this path — the fix was never reached. Every variant executed
exactly once (witness RECV == 1 in all cases), because the driver reported success.

### Where the fix *is* reachable, and it works

Killing the connection **before** dispatch exercises the `no_dispatch = true`
annotation on the linux driver's channel-open failure (added in `3dff0ef7`):

```
[GATE] approval verified: … — executing
[Linux] Disconnected: clab-frr-sacrifice
[O-Node] Connection dropped: clab-frr-sacrifice (backoff 5s)
[SSH-HK] Host key verified: 172.20.20.90:22
[Linux] Connected: root@172.20.20.90:22
[GATE] outcome persisted: … success=true
```
→ witness RECV **1**, side effect **1 line**, real response `TICK_OK`.

**The retry boundary is drawn in the right place.** Provable non-dispatch retries and
executes exactly once; unprovable dispatch is never retried. The defect is not
*where* the line is — it is that on this driver the post-dispatch side of the line
reports success instead of reaching the disposition logic at all.

---

## 3. Target-side read-path misbehavior

| Case | Target behavior | VIRP result |
|---|---|---|
| zero-length | exit 0, no output | RECV 1 / DONE 1, `success=true` — **correct**, the command genuinely succeeded |
| partial frame | ~6 KB emitted, then killed mid-stream | RECV 1 / **DONE 0**, partial bytes signed as `DEVICE_OUTPUT`, `success=true`, **no truncation indicator** |
| oversized | ~340 KB emitted | RECV 1 / DONE 1, `success=true`, silently truncated to the buffer; no crash, no misparse |
| hang | accepts command, never responds | **execute path wedged indefinitely** — see below |

No crash, no memory error, and no case where an attacker-controlled length was
treated as authoritative — the parser-bound hardening (`5bab16bd`) holds up under
live device I/O. The failures here are all **disposition honesty**, not memory safety:
a partial response is signed as though it were the device's complete output.

### Unbounded hang (availability)

`SSH_READ_TIMEOUT_MS` is 30 s, but it bounds only the read loop. After it the driver
returns to **blocking** mode and calls channel teardown with no timeout:

```c
libssh2_session_set_blocking(conn->session, 1);
libssh2_channel_send_eof(channel);
libssh2_channel_wait_eof(channel);      /* unbounded */
libssh2_channel_close(channel);
libssh2_channel_wait_closed(channel);   /* unbounded */
```

Observed: an `apply` against a device running `sleep 600` did not return after
**200 s** (vs. the 30 s the configured timeout implies). The daemon stayed alive and
its heartbeat thread kept ticking, but `obs` stopped advancing and a *new, unrelated*
GREEN read against that device timed out. It recovered the instant the device-side
process was killed.

**Blast radius is device-scoped, not daemon-wide** — the daemon is thread-per-connection
(`connection_worker`) with a per-device `exec_mutex`, so other devices remain
servable. Still: one unresponsive device removes itself from service indefinitely,
and the 30 s read timeout gives false assurance that the operation is bounded.

---

## 4. Not run

- **Task 4 (racing approvers against an in-flight execute)** — not reached; it was
  marked "only if time". The approval-attribution fix (`74ae4d2e`) remains covered
  only by its unit race test, not by live timing.
- **Task 3's second and third directions** (out-of-band execution; batch RECV-vs-outcome
  counting) — not run separately. The first direction (chain must not over-claim) was
  answered decisively in §1, in the negative.

---

## 5. Findings, for a later session to fix

Nothing was fixed tonight, per the brief. In priority order:

1. **`success` must not be inferred from `exit_code == 0` when no exit status was
   received.** libssh2 exposes this: `libssh2_channel_get_exit_signal()`, and the
   return of `wait_closed()`, distinguish "peer reported exit 0" from "peer never
   reported". Until then any abnormal channel termination is signed as a successful
   observation. **This is the chain-over-witness divergence and should be fixed first.**
2. **The `output_len == 0` gate is the wrong discriminator for "no response".** The
   linux driver's unconditional prefix write makes both the retry branch and the
   `OUTCOME_UNKNOWN` branch dead code post-dispatch. The disposition decision should
   key on whether a *response* was received, tracked explicitly by the driver, not on
   the size of a buffer the driver pre-seeded. This is the coupling to
   `EXECUTION_INTENT`/Part B flagged in `3dff0ef7`, now with a live reproduction.
3. **Bound channel teardown.** `wait_eof`/`wait_closed` need a deadline, or the
   channel needs to be torn down non-blocking, so a hung device cannot hold a device's
   execute path open indefinitely.
4. **Truncated responses need a truncation marker in the observation** so a consumer
   can tell a complete body from a prefix of one.

---

## 6. Reproduction

```
tests/adversarial/t05-device-abuse.sh <command-on-target> [label]
```
Asserts the isolated-target invariant and the `--dir` spool flag before every apply,
resets device-side evidence, then reports the target's record (witness + device
artifact) beside VIRP's (client, chain, daemon log). Device-side misbehavior scripts
(`/usr/local/bin/t05-*`) are listed in §1–§3 and live only on the sacrificial container.

**Teardown:** `docker rm -f clab-frr-sacrifice` (named `clab-frr-*` to satisfy the
witness installer's target guard). Production `devices.json`, daemon, and chain were
never modified; the four production FRR containers were never made to misbehave.
