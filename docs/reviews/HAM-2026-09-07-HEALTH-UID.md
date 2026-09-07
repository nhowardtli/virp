# HAM finding, 2026-09-07 — `health` bypasses the per-uid tier ceiling

## Morning summary

One defect, found live rather than by reading: the `health` action is not a
node-liveness ping on this daemon. It runs a client-chosen device through the
gate and, because of which wrapper it called, judged that device read under the
**node-wide** ceiling instead of the connecting uid's own, tighter one.

It surfaced through the `virp-sean` seat (uid 987) minutes after that seat was
deployed to `.211`, while proving the seat could not reach a device. It could.

Two changes exist. The **config mitigation** is deployed: `health` is gone from
uid 987's action allowlist on `.211`, and `health` now returns `-50` through
that seat for every device. The **code fix** is on
`fix/health-uid-passthrough`, commit `596ca16`, with the regression test
written first and proven to fail against the unfixed source. It is **not
deployed anywhere**.

Two things need you. `993` (netclaw) and `994` (broker) hold `health` on `.211`
under the same YELLOW node-wide ceiling and are therefore exposed the same way;
I did not touch them, per your instruction. And the code fix wants a deploy
decision of its own — it changes gate behaviour for every uid that holds
`health`, which on `.211` is four accounts.

---

## 1. Summary table

| # | item | branch | commit | status | test |
|---|---|---|---|---|---|
| 1 | config mitigation: drop `health` from uid 987 | `feat/virp-sean-seat` | `d657def` | **DEPLOYED** `.211` 15:57:50Z | live re-proof, §4 |
| 2 | code fix: HEALTH passes `client_uid` | `fix/health-uid-passthrough` | `596ca16` | DONE, undeployed | `test_health_uid_passthrough.py` |
| 3 | caller audit of the plain wrapper | `fix/health-uid-passthrough` | `596ca16` | DONE | `test_plain_wrapper_has_no_other_client_reachable_caller` |
| 4 | audit of uids 997 / 1001 | — | — | REPORTED, unchanged | §5 |

## 2. The defect

`ONODE_ACTION_HEALTH` requires a device and executes `show version` against it:

```c
case ONODE_ACTION_HEALTH:
    if (req.device[0] == '\0') { send_framed_error(client_fd, VIRP_ERR_NULL_PTR); break; }
    err = onode_execute_obs(state, req.device, "show version", ...);   /* BEFORE */
```

`onode_execute_obs()` and `onode_execute()` both forward to
`onode_execute_obs_ex(..., (uid_t)-1, ...)`. And the ceiling helper returns
early on that sentinel:

```c
static virp_trust_tier_t onode_effective_max_tier(const onode_state_t *state, uid_t client_uid)
{
    virp_trust_tier_t eff = state->gate_max_tier;
    if (client_uid == (uid_t)-1) return eff;      /* <- per-uid entry never consulted */
    ...
}
```

So on the health path the per-uid ceiling does not exist. Every other execute
path threads the real uid through `onode_execute_obs_ex()`.

## 3. Live proof

`.211` has `gate_max_tier: yellow`. uid 987 is pinned `green`. Requests issued
through the seat's own forwarded socket from the VM at 10.0.70.10, framed v2:

```
health device=cat3850-lab      97 bytes signed   payload~ not found
health device=virp-lab         94 bytes signed   payload~  found
health device=pbs-lab         390 bytes signed   'show version' on 'pbs-lab'   (tier=RED max=YELLOW)
health device=wazuh-lab       181 bytes signed   'show version' on 'wazuh-lab' (tier=RED max=YELLOW) proposal_id=ab1c298f37c860b1...
health device=librenms-lab    184 bytes signed   'show version' on 'librenms-lab' (tier=RED max=YELLOW) proposal_id=cc40cc9a83d85a...
```

`max=YELLOW` is the node-wide ceiling. The seat's own is GREEN.

Two consequences, both contradicting that row's policy note:

1. **Device read.** `show version` against any governed device, signed, judged
   at the node-wide ceiling. On a driver where `show version` grades GREEN it
   simply executes.
2. **Fleet oracle.** `not found` versus a real reply distinguishes real device
   names from absent ones, which partly defeats withholding `list_fleet`.

The tier escalation only bites where node-wide is looser than per-uid. On
`.211` (`yellow`) it bites. On `virp-onode-home` (`green`) it cannot.

## 4. Mitigation, deployed and re-proved

`d657def` removes `health` from uid 987. Installed and restarted on `.211` at
**15:57:50Z**; binary sha `c541fc72…` unchanged, so config-only. Re-proved
through the same socket:

```
health device=cat3850-lab    error_code=-50      health device=wazuh-lab     error_code=-50
health device=virp-lab       error_code=-50      health device=librenms-lab  error_code=-50
health device=pbs-lab        error_code=-50      health (no device)          error_code=-50

chain_verify session=node-config   166 bytes SIGNED REPLY     <- still works
chain_append evidence_item         340 bytes SIGNED REPLY     <- still works
execute                            error_code=-50
list_fleet                         error_code=-50
```

`chain_verify` covers liveness for this seat and is node-local, so nothing was
lost.

## 5. Audit: who else holds `health`

Asked for 997 and 1001; reporting the whole set, because the answer for those
two is "not exposed" and the exposure is elsewhere.

**`.211`** (`gate_max_tier: yellow`):

| uid | account | `health` | per-uid ceiling | exposed? |
|---|---|---|---|---|
| 999 | `virp` | yes | green | **yes** — node's own service account |
| 1000 | operator | yes | green | **yes** — but has `execute` and sudo anyway |
| **993** | `virp-netclaw` | **yes** | green | **YES — remote AI path, constrained by design** |
| **994** | `virp-broker` | **yes** | green | **YES — relay identity** |
| 997 | `virp-backup` | **no** | green | no — 2 actions only (`execute`, `chain_append`) |
| 995 | `virp-evidence` | **no** | green | no — same 2 actions |
| 1001 | — | — | — | **not allowlisted on this node at all** |
| 987 | `virp-sean` | **removed** | green | no, as of 15:57:50Z |

**`virp-onode-home` (313)** (`gate_max_tier: green`): allowlist is 999, 1000,
997, 1001; all four hold `health` with a green ceiling. Because the node-wide
ceiling is already GREEN, the fallback lands on the same tier and there is **no
tier escalation**. The device-read and fleet-oracle reach still applies.

**The finding you should weigh: 993 and 994.** uid 993 is the netclaw remote
requester, pinned GREEN precisely so the remote AI path is read-only-by-default
without lowering the node. `health` hands it YELLOW. That is the same class of
gap as the Finding A closed on 2026-08-09 by adding per-uid ceilings — this
path was simply never covered. **Not changed, per instruction.**

## 6. Caller audit of the plain wrapper

| caller | reachable by a client uid? |
|---|---|
| `case ONODE_ACTION_HEALTH` (`virp_onode.c`) | **yes** — fixed in `596ca16` |
| `onode_execute()` (`virp_onode.c:1477`) | no C caller anywhere in the tree |
| `onode_execute` in `api/server.py` | unrelated Python function, same name only |

After the fix, no request handler calls a wrapper that cannot apply a per-uid
ceiling, and `test_plain_wrapper_has_no_other_client_reachable_caller` fails if
one starts to.

## 7. On the test

The obvious test — *YELLOW-capped uid, `health` against a RED device, expect
`-50`* — **does not discriminate**. RED already exceeds YELLOW, so it is refused
with or without the fix and passes green against the broken code. A regression
test that cannot fail against the bug it names is worse than none.

The discriminating case is a uid capped **tighter** than the node, running a
command **between** the two ceilings: GREEN-capped uid, YELLOW node, YELLOW
command. Broken → effective YELLOW → executes. Fixed → effective GREEN → does
not. The suite also carries `test_a_red_command_does_not_discriminate`, which
pins that reasoning so the tests cannot later be simplified back into a
tautology.

Proven: **4 failed / 4 passed** against the unfixed source, **8 passed** against
the fix. `make prod` builds clean under `-Wall -Wextra -Werror`.

## 8. What is not done

- The code fix is **undeployed**. Deploying it changes gate behaviour for every
  uid holding `health` — four accounts on `.211`. It is a binary change, not
  config-only, so it does not ride a template restart.
- **993 and 994 are untouched.** They are the live exposure.
- Neither branch is merged. `feat/virp-sean-seat` carries the seat plus the
  config mitigation; `fix/health-uid-passthrough` carries the code fix.

---

## 9. Post-deploy verify (close-out run, 2026-09-07)

### 9.1 Mitigation extended to uids 993 and 994

Same config-only removal, deployed `.211` **16:17:37Z**, binary sha
`c541fc72…` **unchanged**, one restart, stop 91s. Template rollback point kept
at `/etc/virp/devices.template.json.bak-20260907T161603Z-pre993` and a
WAL-aware chain backup alongside it; neither was needed.

Measured as each uid over the real socket (SO_PEERCRED), before and after:

| probe | 993 before | 993 after |
|---|---|---|
| `health device=pbs-lab` | `390B signed — 'show version' … (tier=RED max=YELLOW)` | **`-50`** |
| `health device=virp-lab` | `94B signed — found` | **`-50`** |
| `list_fleet` | `2358B signed` | `2358B signed` |
| `chain_verify node-config` | `166B signed` | `166B signed` |
| `execute` GREEN pbs read | `223B signed — HTTP 200` | `223B signed — HTTP 200` |
| `list_devices` / `heartbeat` | `-50` | `-50` |
| `chain_append evidence_item` | `-50` | `-50` |
| `chain_append fed_observation` | `-27` | `-27` |

**Nothing that worked before stopped working**, so no rollback was taken.
`max=YELLOW` in the "before" column is this document's defect, observed on the
live remote-requester identity rather than inferred.

**uid 994 has no live reach at all, before or after.** Every probe returns
`Permission denied` at `connect()`: it is in `socket_allowed_uids` and carries
an action map, but holds **no ACL** on `/run/virp/onode.sock`. Its row has
never been exercised. Recorded because it is the second gate — the daemon
allowlist alone never admitted it, and a reader of the template would not
guess that.

Seat uid 987 re-proved after the same restart: `health` `-50`, `execute` `-50`,
`list_fleet` `-50`, `chain_verify` 166B signed, `chain_append evidence_item`
337B signed.

`broker/virp_broker.py` lost `health` from `ALLOWED_ACTIONS` in the same
commit, because `test_broker_matches_its_own_relay_allowlist` asserts the
relay's allowlist equals the template's row for that uid.

### 9.2 Chain verify — DID NOT COMPLETE, and that is the finding

Full-chain verify was run twice against the post-deploy chain (352,613
entries). **It did not finish either time.** Recorded as-is rather than
rounded up to a pass.

| | |
|---|---|
| sessions graded | **219** |
| failures | **0** (no FAIL, BROKEN or INVALID line in either run) |
| wall time | started 16:08:55Z, killed 16:38Z — **~29 min, still running** |
| last session graded | `gate-enforce:SW-3850` (18 entries) |
| large `gate-enforce:*` sessions | **NOT graded — never reached** |
| transcript | `/var/backups/virp/chainverify-postdeploy-partial.txt` on `.211` |

So the answer to "do the large gate-enforce sessions grade VALID" is: **unknown
— they were never reached.** The 219 sessions that were graded are all VALID.

The cost is not linear in session size, measured per session:

| session | entries | wall |
|---|---|---|
| `autopilot:2026-08-18` | 5,184 | **1 s** |
| `gate-enforce:clab-frr-ospf-frr4` | 15,200 | **TIMED OUT at 150 s** |

3× the entries, >150× the time. Four sessions of that class remain
(`pbs-lab` 29,905; `clab-frr-ospf-frr1/2/3` ~15,200 each), which is why a
whole-chain walk does not terminate in a useful window on this node.
**Caveat on the numbers:** these were taken while the full-chain run was
pegging a core, so they are contended and the absolute figures are pessimistic;
the *shape* is not explained by contention.

Worth its own branch. Two things to check first: whether the per-entry cost in
`virp_chain_verify()` is super-linear within a session, and whether the
`gate-enforce:*` sessions differ from `autopilot:*` in something other than
size (they carry gate decisions and proposals; the autopilot ones carry
observations).

**Consequence for deploy practice:** "chain_verify the full chain after
restart" is not currently an executable post-deploy step on `.211`. What *is*
executable, and what was done here, is per-session verification — including
`chain_verify session=node-config`, which every daemon start writes to and
which returned a signed result after every restart today.

An earlier note in this session that the verify had "stalled" or "hung" was
**wrong**: `stdout` is block-buffered when redirected, so the last flushed line
lagged far behind the real position. Re-run under `stdbuf -oL` it advanced
normally. The process was at 99.9% CPU in state R throughout — grinding, not
blocked.

### 9.3 Disconnect alarm — NOT CONFIRMED, and why

The test itself was clean. The Wazuh agent on the seat VM was stopped
**16:04:57Z** and restarted **16:21:45Z**, reconnecting at **16:21:33Z**
(`Connected to the server ([10.0.20.10]:1514/tcp)`, `status='connected'`,
`last_ack 16:21:58`). Outage **16 min 36 s**, comfortably past Wazuh's
10-minute `agents_disconnection_time` default — unlike the first attempt's
9 min 22 s, which was inside it and proved nothing.

**I could not read `alerts.json`, so I cannot say whether the alert fired.**
Absence of evidence, not evidence of absence. Three paths were tried:

1. **SSH to 10.0.20.10** — no shell. `nhoward`, `root`, `ubuntu`, `wazuh`
   against two keys: `Permission denied (publickey)` every time.
2. **`GET /manager/logs` through the gate** — refused, correctly:
   `(tier=RED max=GREEN)`, `proposal_id=6373ce50937834bf19f97bcb8474e49f`.
   Only `/manager/logs/summary` is GREEN, and it returns counts by daemon with
   no agent detail. **The proposal was left unapproved**: self-approving a RED
   read while the operator is away is his call, not mine.
3. **The Wazuh API does not serve `alerts.json` at all.** Alerts are written by
   `analysisd` and shipped to the Indexer; the manager API exposes
   `/manager/logs` (ossec.log) and never the alert stream. So even an approved
   RED read would not have answered the question.

What the manager *did* confirm, read GREEN through the gate as uid 1000
(`GET /agents?agents_list=012`): agent `012` `sean-agent`, `status: active`,
`lastKeepAlive 2026-09-07T16:22:33+00:00`, `dateAdd 2026-09-07T03:13:14+00:00`.

**To close this, one of:** shell on 10.0.20.10 and
`grep -iE 'disconnect|sean-agent' /var/ossec/logs/alerts/alerts.json` for
**Sep 7 12:04:57–12:21:33 EDT** (the dashboard renders UTC−4); or the same
window in the dashboard filtered on `agent.name: sean-agent`; or approve
proposal `6373ce50…` — though by (3) that still will not show alerts.
No rule was changed, and no rule was read, because the ruleset is not
reachable from here.
