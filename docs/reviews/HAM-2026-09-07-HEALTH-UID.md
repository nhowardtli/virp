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
