# Fleet UID registry

Every service and remote-client uid on both O-nodes, with what it means.
Created 2026-09-05 for the whole-estate visibility work.

Two nodes, two independently-grown uid spaces. They were never coordinated,
so the same number means different things on different boxes. That is
recorded here as debt. **Nothing is renumbered by this document.**

An entry is "gated" if the uid appears in that node's `socket_allowed_uids`
and can therefore speak to `/run/virp/onode.sock`. A uid can exist as a Unix
account without being gated (`virp-capture`, `virp-peer`) — those reach the
node by some other path, or not at all.

---

## 313 — 10.0.0.13, `virp-onode-home`, unit `virp-onode.service`

Governs the home segment. Node-wide `gate_default_mode=enforce`,
`gate_max_tier=green`.

| uid | gid | account | kind | gated | ceiling | actions |
|-----|-----|---------|------|-------|---------|---------|
| 999 | 988 | `virp` | daemon's own identity | yes | green | `chain_append` `chain_verify` `health` `heartbeat` `list_devices` `list_fleet` `execute` `sign_outcome` |
| 1000 | 1000 | `nhoward` | human operator | yes | green | `execute` `health` `list_fleet` `list_devices` `chain_append` `chain_verify` `approval_challenge` `approval_submit` |
| 1001 | 1001 | `virp-laptop` | remote client — laptop (approver + forward) | yes | green | `approval_challenge` `approval_submit` `list_fleet` `execute` `health` |
| 997 | 987 | `virp-spark` | remote client — Spark, 10.0.0.15 | yes | green | `execute` `list_fleet` `health` `chain_verify` |
| 995 | 986 | `virp-capture` | camera capture spool (chrooted sftp) | **no** | — | — |
| 992 | 985 | `virp-tacacs` | TACACS+ accounting receiver | yes | green | `chain_append` |

**Tracked-vs-live drift:** uid 992 is present in the live
`/etc/virp/devices.template.json` on 313 but is **absent from the tracked
`deploy/devices.home.template.json`** on `main` and on every other ref in
this repo. A re-render from the tracked template would silently drop the
TACACS receiver's gate access. Reconcile before any 313 restart.

## .211 — 10.0.10.211, `virp-lab`, unit `virp-onode.service`

Governs the colo. Node-wide `gate_default_mode=enforce`,
`gate_max_tier=yellow`.

| uid | gid | account | kind | gated | ceiling | actions |
|-----|-----|---------|------|-------|---------|---------|
| 999 | 986 | `virp` | daemon's own identity | yes | green¹ | 20 verbs (full service set, incl. `chain_append`) |
| 1000 | 1000 | `nhoward` | human operator | yes | green | 21 verbs (service set + `shutdown`) |
| 1001 | 1001 | `virp-peer` | peer node identity (from 10.0.10.212) | **no** | — | — |
| 997 | 985 | `virp-backup` | config-backup runbook identity | yes | green | `execute` `chain_append` |
| 995 | 984 | `virp-evidence` | compliance evidence collector | yes | green | `execute` `chain_append` |
| 994 | 983 | `virp-broker` | Stage 1 intent broker | yes | green¹ | `execute` `list_devices` `health` `heartbeat` `intent_store` `intent_get` `approval_challenge` `approval_submit` |
| 993 | 982 | `virp-netclaw` | remote client — netclaw, 10.0.30.30 | yes | green | `list_fleet` `health` `chain_verify` `chain_append` `execute` |

¹ The green ceilings on 999, 1000 and 994 are **committed but not deployed**.
They arrived with the SW-3850 merge (`b118236`) and exist only in
`deploy/devices.template.json`; the live node still has ceilings for 993, 997
and 995 only, so 999/1000/994 currently inherit the node-wide YELLOW.

---

## Collisions — recorded as debt, not fixed here

| uid | on .211 | on 313 | note |
|-----|---------|--------|------|
| 997 | `virp-backup` (service) | `virp-spark` (remote client) | worst of the set: a service account on one node, an external client on the other |
| 995 | `virp-evidence` (service) | `virp-capture` (service) | both local services, different jobs |
| 1001 | `virp-peer` (peer node) | `virp-laptop` (remote client) | neither is gated on .211; only 313's is |
| 992 | free | `virp-tacacs` | asymmetric; keep .211's 992 free so a future convergence is possible |
| 993 | `virp-netclaw` | free → allocated below | converges once 313's account is created |

Renumbering any of these is a separate, restart-bearing change on both
nodes at once. Not today.

---

## Allocations made by this session

| node | uid | gid | account | for | why this number |
|------|-----|-----|---------|-----|-----------------|
| 313 | 993 | 984 | `virp-netclaw` | netclaw / Nexus, 10.0.30.30 | 993 is free on 313 and already means exactly this on .211 — the one number that converges rather than adding debt |
| .211 | 988 | 981 | `virp-spark` | Spark, 10.0.0.15 | **997 is not free on .211** — it is `virp-backup`. 988 is free on *both* nodes, so it adds no new collision and leaves a future renumber of 313's `virp-spark` 997→988 available as the convergence path |

Both new uids, identically:

- **ceiling:** green
- **actions:** `list_fleet` `health` `execute` `chain_verify` — and nothing else
- **no `chain_append`**, therefore no `socket_uid_chain_append_types` entry
  is required and the boot invariant (an allowlisted uid must carry an
  action map; a uid with `chain_append` must carry a type policy) is
  satisfied by the action map alone.

Both are gated remote clients with no route to any device: the account is
`restrict,port-forwarding` with a `from=` pin, its only capability is a
streamlocal forward to the node's socket, and IP egress from the uid is
denied one layer down by nftables.

### Placeholder resolvers

The templates name uids as `${VIRP_*_UID}` and `render-devices.sh` resolves
each one with `pwd.getpwnam()`. A placeholder with no resolver renders empty
and the daemon refuses the config at load — this crash-looped .211 once
already (`${VIRP_BRIDGE_UID}`, fixed in `a904575`). Each new uid therefore
needs **both** halves, in the same change:

| node | placeholder | resolver account | also add to the required-vars tuple |
|------|-------------|------------------|--------------------------------------|
| .211 | `${VIRP_SPARK_UID}` | `virp-spark` | yes |
| 313 | `${VIRP_NETCLAW_UID}` | `virp-netclaw` | yes |

313's live template writes 992 as a bare literal rather than a placeholder;
either form works, but the two nodes are inconsistent about which they use.
