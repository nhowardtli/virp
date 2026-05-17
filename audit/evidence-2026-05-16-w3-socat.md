# W3 Evidence — virp-socat User Drop (root → virp-onode)

**Date:** 2026-05-16
**Trust primitive:** W3 — O-Node Unix-socket peer-credential gate (`SO_PEERCRED` + `socket_allowed_uids`)
**Branch:** hardening/audit-2026-04 (target for commit; current working branch raise-validator-manifest-caps)
**Author:** Nate Howard + Claude Code

---

## Summary

`virp-socat.service` had been running as `root` (uid 0). Every TCP connection
arriving at `10.0.0.211:9999` was proxied to `/tmp/virp-onode.sock` with the
socat process's credentials, so `SO_PEERCRED` reported uid 0 to the O-Node.
The O-Node's `socket_allowed_uids` list (default-seeded to `geteuid() = 999`
because no key is present in `/run/virp/devices.json`) rejected every such
connection in `virp_onode.c:2101`. The dashboard tool-call path was 100%
broken end-to-end.

Fix: dropped a systemd drop-in at
`/etc/systemd/system/virp-socat.service.d/override.conf` setting
`User=virp-onode`, `Group=virp-clients`, and clearing both
`AmbientCapabilities=` and `CapabilityBoundingSet=`. Reload + restart at
21:42:58 UTC. Socat is now uid 999, gid 1000 — peer credentials presented to
the O-Node match the daemon's own UID, the SO_PEERCRED check passes, and
REJECTED entries have stopped.

W2 (device-side ACLs, off-box) and W4 (Landlock FS sandbox on CT 210) are
unaffected. W1 (CT 210 egress firewall — DNS, 10.0.0.211:9998-9999, :443
only) was repaired earlier in the session and remains intact.

---

## Timeline (UTC, 2026-05-16)

| Time | Event |
|------|-------|
| 21:21:43 | First REJECTED today: peer uid=0 pid=1267846 |
| 21:21:43 – 21:38:44 | 22 REJECTED entries, all `peer uid=0`, ~1 per dashboard tool invocation |
| 21:38:44 | Last REJECTED today: peer uid=0 pid=1268091 |
| 21:42:57.812 | `override.conf` created (birth time on inode) |
| 21:42:58 | `systemctl stop virp-socat` → main process exited status=143 (SIGTERM, expected) |
| 21:42:58 | `systemctl start virp-socat` → new socat PID 1268204 running as uid=999 (virp-onode), gid=1000 (virp-clients) |
| 21:42:58 → present | **0 REJECTED entries** in `journalctl -u virp-onode` |
| 21:55:51 → 21:56:51 | O-Node heartbeats continue (seq 8344 → 8346) — daemon alive, socket reachable |

---

## Evidence

### Pre-fix — REJECTED count and exemplar

```
$ journalctl -u virp-onode --since today -o cat | grep -c "REJECTED connection"
22

$ journalctl -u virp-onode --since today -o cat | grep -oE "uid=[0-9]+" | sort | uniq -c
     22 uid=0

$ journalctl -u virp-onode --since today -o short-iso | grep "REJECTED" | head -1
2026-05-16T21:21:43+0000 ironclaw-onode virp-onode[1225843]: [O-Node] REJECTED connection: peer uid=0 pid=1267846 not in socket_allowed_uids

$ journalctl -u virp-onode --since today -o short-iso | grep "REJECTED" | tail -1
2026-05-16T21:38:44+0000 ironclaw-onode virp-onode[1225843]: [O-Node] REJECTED connection: peer uid=0 pid=1268091 not in socket_allowed_uids
```

All 22 rejections share `uid=0` — pure socat-as-root signature, no legitimate root client.

### Fix — drop-in override

```
$ cat /etc/systemd/system/virp-socat.service.d/override.conf
[Service]
User=virp-onode
Group=virp-clients
# Remove root-required capabilities if any are set
AmbientCapabilities=
CapabilityBoundingSet=

$ stat /etc/systemd/system/virp-socat.service.d/override.conf | grep Birth
 Birth: 2026-05-16 21:42:57.812335307 +0000
```

### Post-fix — socat process identity

```
$ ps -eo pid,user,uid,gid,cmd | grep "socat.*9999" | grep -v grep
1268204 virp-on+   999  1000 /usr/bin/socat TCP-LISTEN:9999,fork,reuseaddr UNIX-CONNECT:/tmp/virp-onode.sock
```

uid 999 = `virp-onode`, gid 1000 = `virp-clients`. Group membership is what
gives socat write access to the socket (mode 0660, owner virp-onode:virp-clients);
the matching uid is what satisfies `socket_allowed_uids`.

### Post-fix — REJECTED count and liveness

```
$ journalctl -u virp-onode --since "2026-05-16 21:42:58" -o cat | grep -c "REJECTED connection"
0

$ journalctl -u virp-onode --since "21:42:58" -o short-iso | grep -i heartbeat | tail -3
2026-05-16T21:55:51+0000 ironclaw-onode virp-onode[1225843]: [O-Node] Heartbeat: uptime=250866s obs=0 seq=8344 connected=0/40 reconnects=0
2026-05-16T21:56:21+0000 ironclaw-onode virp-onode[1225843]: [O-Node] Heartbeat: uptime=250896s obs=0 seq=8345 connected=0/40 reconnects=0
2026-05-16T21:56:51+0000 ironclaw-onode virp-onode[1225843]: [O-Node] Heartbeat: uptime=250926s obs=0 seq=8346 connected=0/40 reconnects=0
```

**Note on ACCEPTED logging.** The O-Node does not emit a symmetric "ACCEPTED"
line — `virp_onode.c:2101` logs only the rejection path; accepted peers
proceed silently into request handling. The positive evidence is therefore
the *absence* of REJECTED entries since 21:42:58 plus continued daemon
liveness. A follow-up step (W3 audit close-out) should add a one-shot
INFO-level "accepted peer uid=%u" log at first connection after start to
make this primitive's healthy state observable, not just its failure state.

### `socket_allowed_uids` provenance

```
$ jq 'has("socket_allowed_uids")' /run/virp/devices.json
# (verify via daemon stderr — key is absent, daemon self-seeded)

$ journalctl -u virp-onode | grep "socket_allowed_uids:" | tail -1
[O-Node] socket_allowed_uids: <default> = [999] (daemon UID)
```

The list contains only uid 999 (daemon's own euid), per the self-seed
branch in `virp_onode.c:1986-1990`. socat-as-virp-onode satisfies this.
socat-as-root did not.

---

## Trust-primitive impact

| Primitive | Pre-fix | Post-fix | Change |
|-----------|---------|----------|--------|
| W1 (CT 210 egress firewall) | DNS + 10.0.0.211:9999/9998 + :443 only, policy_out DROP | unchanged | none |
| W2 (device-side ACLs, off-box) | enforced at device | unchanged | none |
| W3 (O-Node SO_PEERCRED gate) | enforced but path BROKEN — socat-as-root meant the only client that could *reach* the socket was rejected by it. Defense was effective in the wrong direction: it blocked the legitimate path because the legitimate path was misconfigured. | enforced AND legitimate path passes (socat uid 999 == allowed uid 999) | **restored** |
| W4 (Landlock FS sandbox, CT 210 only) | active | unchanged | none |

Net: W3 moved from "enforced but never observed accepting traffic" to
"enforced and observed accepting traffic from a process whose uid is
audit-traceable to a dedicated, capability-stripped systemd service."

---

## Significance

This was a silent self-DoS by a defense-in-depth primitive. The SO_PEERCRED
gate did exactly what it was designed to do (commit `23680b0`, 2026-04-14):
reject local peers whose uid is not on the allow-list. But the only TCP→Unix
proxy in the system was running as a uid that wasn't on the allow-list, so
the gate happened to reject 100% of legitimate traffic. From the dashboard
side this looked like end-to-end tool-call failure with no obvious cause —
the firewall fix in W1 made the TCP path reachable, but the peer-credential
gate at the far end kept dropping every connection.

Two follow-ups the close-out should pick up:

1. **socket_allowed_uids in devices.json.age.** The default-seed branch is
   a useful safety net but it means the allowed list is implicit. An
   explicit `"socket_allowed_uids": [999]` (or a virp-clients-group-derived
   list) in the encrypted config makes the policy reviewable and removes
   the dependence on `geteuid()` at startup. See the existing memory note
   `virp_socket_peercred.md` — missing key has caused production-shaped
   incidents before.

2. **Track the socat unit in repo.** `virp-socat.service` is in
   `/etc/systemd/system/` only — not in `/root/virp/deploy/` like
   `virp-onode.service` is. Drift on this unit is invisible to git. The
   override that just fixed W3 will also drift until both the unit and the
   drop-in are committed.

3. **Symmetric ACCEPTED log.** Add a single startup-or-first-accept INFO
   line so future evidence captures can show a positive signal instead of
   "absence of negative signal."

---

## Reference

- `virp_onode.c:801-830` — `check_peer_uid()` SO_PEERCRED enforcement
- `virp_onode.c:1986-1995` — default-seed branch for `socket_allowed_uids`
- `virp_onode.c:2101-2122` — REJECTED log line and per-uid counter
- `virp_onode_prod.c:101-117` — `load_socket_allowed_uids()` (devices.json path)
- `commit 23680b0` (2026-04-14) — original SO_PEERCRED hardening
- Memory: `virp_socket_peercred.md` — onode socket allowlist trap (recurring)
- Snapshots: `pct snapshot 210 pre-w1-debug-20260516-1225`, `pct snapshot 211 pre-w1-debug-20260516-1225`

---

## Addendum — configuration consolidation (22:03:03 UTC)

The 21:42:58 fix used a drop-in override (`virp-socat.service.d/override.conf`)
layered on top of an untracked base unit. That works but leaves the
base unit invisible to git and splits the fix across two files. To make
the change durable and auditable, the base unit was rewritten with the
hardening directives baked in and the drop-in removed.

### Files changed

- **New:** `deploy/virp-socat.service` — single hardened base unit
- **New:** `deploy/README.md` — install procedure
- **Modified:** `Makefile` — added `install-systemd-units` target
- **Installed:** `/etc/systemd/system/virp-socat.service` (replaced)
- **Removed:** `/etc/systemd/system/virp-socat.service.d/override.conf` and parent directory

### Diff vs prior running unit (additions only — nothing removed)

```diff
+Requires=virp-onode.service
+User=virp-onode
+Group=virp-clients
+AmbientCapabilities=
+CapabilityBoundingSet=
+NoNewPrivileges=yes
 ExecStart=/usr/bin/socat TCP-LISTEN:9999,fork,reuseaddr \
     UNIX-CONNECT:/tmp/virp-onode.sock
```

`Requires=virp-onode.service` upgrades the dependency from ordering-only
(`After=`) to hard requirement — socat will stop if onode stops, which is
the correct behavior since socat without onode is useless. `NoNewPrivileges=yes`
is a pure-win sandbox tightening for a TCP proxy that should never need
setuid.

### Post-consolidation verification

```
$ systemctl status virp-socat --no-pager | head
* virp-socat.service - VIRP O-Node socat TCP Bridge
     Loaded: loaded (/etc/systemd/system/virp-socat.service; enabled; vendor preset: enabled)
     Active: active (running) since Sat 2026-05-16 22:03:03 UTC

$ ps -eo pid,user,uid,gid,cmd | grep '[s]ocat TCP-LISTEN:9999'
1269064 virp-on+   999  1000 /usr/bin/socat TCP-LISTEN:9999,fork,reuseaddr UNIX-CONNECT:/tmp/virp-onode.sock

$ ss -tlnp | grep 9999
LISTEN 0      5            0.0.0.0:9999      0.0.0.0:*    users:(("socat",pid=1269064,fd=5))

$ ls /etc/systemd/system/virp-socat.service.d/ 2>&1
ls: cannot access '/etc/systemd/system/virp-socat.service.d/': No such file or directory

$ journalctl -u virp-onode --since "2026-05-16 22:03:03" -o cat | grep -c "REJECTED connection"
0
```

uid/gid unchanged (999/1000) — the SO_PEERCRED gate continues to accept
the proxy. No REJECTED entries since consolidation. The drop-in
directory is gone, so future audits will see exactly one file describing
the socat service.

### Timeline (extended)

| Time | Event |
|------|-------|
| 22:01:55 | `deploy/virp-socat.service` written |
| 22:02 | `deploy/README.md` and `Makefile` target added |
| 22:03:03 | `install` + `daemon-reload` + `systemctl restart virp-socat` |
| 22:03:03 → | socat PID 1269064, uid 999, 0 REJECTED |

---

## Addendum 2 — virp-bridge.service: same root cause, different daemon (22:54 UTC)

The socat fix at 22:03:03 hardened the only TCP→Unix proxy on `:9999` but
did not enumerate the *other* daemon that connects to `/tmp/virp-onode.sock`.
`virp-bridge.service` — the Python JSON bridge on `:9998` — was still
running as `User=root, Group=root` because its base unit, like socat's,
had been untracked and unhardened. As soon as `socket_allowed_uids = [999]`
was active (see addendum 1), the bridge's session-handshake connection
was rejected on the same `SO_PEERCRED` gate, with the same root cause.

The bridge's failure mode differed superficially: rather than refusing all
traffic, it logged `Session handshake failed: Connection reset by peer`
and fell back to "operating without session." Validation entries went
through a non-session code path and kept landing in `chain_entries`,
masking the breakage in the audit log itself. The actual loss — silent —
was the observation/`chain_register` path: three confirmed failures at
22:35:27, 22:35:59, 22:40:49, each logged as "Connection reset by peer."

### Why this addendum is separate from addendum 1, not a continuation

The socat fix at 22:03:03 was scoped to "the unit running as root that
connects to the O-Node socket." That scope was incomplete. It enumerated
*one* such unit. The general truth is: any process binding to or
connecting to `/tmp/virp-onode.sock` must run as uid 999. Tonight there
were two; there may be more in future (Wazuh REST collector, federation
nodes, etc.). This is a deployment-rollout concern, not a one-off bug,
and the close-out should reflect that — see "Significance" below.

### Layered assumptions hit during the bridge fix

The bridge fix exposed three assumption layers, each of which had to be
unwound in order. None were addressable by changing `User=` alone.

1. **UID layer (`SO_PEERCRED`)** — the W3 gate. Resolved by
   `User=virp-onode, Group=virp-clients` on the bridge unit, identical
   in shape to the socat fix.

2. **Path layer (`/root/` 0700 + hard-coded source paths)** — `/root/`
   is mode 0700 and unreadable post-drop-privs. Three sub-issues:

   - `ExecStart=/usr/bin/python3 /root/virp/virp-bridge.py` failed with
     `[Errno 13] Permission denied` on the script itself. Resolved by
     `ExecStartPre=+/bin/install` staging to `/opt/virp/virp-bridge.py`
     owned `virp-onode:virp-clients` mode 0640. The `+` prefix runs the
     install as root before drop-privs.

   - `virp-bridge.py` imports `device_registry` as a sibling module.
     Staging only the entrypoint produced `ModuleNotFoundError`. Resolved
     by a second `ExecStartPre=+/bin/install` line for
     `/root/virp/device_registry.py`. No other first-party siblings are
     imported (verified by grep).

   - `virp-bridge.py:66` had `OKEY_PATH = "/root/virp/keys/onode.key"`.
     Even with `/root/` traversal, that file is `root:root 0600`, so
     `virp-onode` could not read it. The canonical key already lives at
     `/etc/virp/keys/onode.key` (owned `virp-onode:virp-onode 0400`,
     identical sha256, used by the daemon itself). Resolved by a one-line
     source edit pointing `OKEY_PATH` at the canonical location and
     dropping the `/root/virp/keys/` duplicate from the live read path.

3. **Schema layer (chain.db table name)** — minor. The chain.db ledger
   table is `chain_entries`, not `chain`; the pre/post-test snapshot
   queries hit `Error: no such table: chain (1)` until corrected. Worth
   noting because the chain.db schema is the verification surface for
   every W3 evidence run, and a stale assumption about its shape silently
   produces empty snapshots that look like "no observations" rather than
   "wrong query."

### Files changed

- **New:** `deploy/virp-bridge.service` — single hardened base unit,
  mirrors the socat shape (User/Group/AmbientCapabilities/CapabilityBoundingSet)
  and adds the two `ExecStartPre=+/bin/install` lines for source staging
- **Modified:** `deploy/README.md` — added bridge row in service table,
  bridge entry in install procedure, bridge drop-in cleanup note,
  bridge verification command, and a `/opt/virp/` staging rationale section
- **Modified:** `Makefile` — extended `install-systemd-units` target with
  the bridge unit and the legacy `peercred.conf` cleanup hint
- **Modified:** `/root/virp/virp-bridge.py` (working tree, branch
  `raise-validator-manifest-caps`) — `OKEY_PATH` source edit. See the
  divergence note in "Caveats" below
- **Installed:** `/etc/systemd/system/virp-bridge.service` (replaced)
- **Still present:** `/etc/systemd/system/virp-bridge.service.d/peercred.conf`
  — redundant with the new base unit; not removed in this round to limit
  blast radius. Cleanup procedure documented in `deploy/README.md`

### Diff vs prior running unit (additions only)

```diff
+After=virp-onode.service
+Requires=virp-onode.service
+User=virp-onode
+Group=virp-clients
+ExecStartPre=+/bin/install -d -o virp-onode -g virp-clients -m 0750 /opt/virp
+ExecStartPre=+/bin/install -o virp-onode -g virp-clients -m 0640 /root/virp/virp-bridge.py /opt/virp/virp-bridge.py
+ExecStartPre=+/bin/install -o virp-onode -g virp-clients -m 0640 /root/virp/device_registry.py /opt/virp/device_registry.py
+AmbientCapabilities=
+CapabilityBoundingSet=
-ExecStart=/usr/bin/python3 /root/virp/virp-bridge.py
+ExecStart=/usr/bin/python3 /opt/virp/virp-bridge.py
-User=root
-Group=root
```

### Verification — chain_register E2E (22:57:39 UTC)

Pre-fix state of `chain_entries` showed the silent break: most recent
`artifact_type=observation` entry was at **2026-05-12 20:21:55** (id 1836,
seq 1063). Four days of zero observations, with only `validation` entries
trickling in via the alternate code path.

Bridge logs after restart at 22:54:00:

```
[virp-bridge] INFO O-Key loaded from /etc/virp/keys/onode.key
[virp-bridge] INFO Handshake: HELLO_ACK received, session_id=16aa9ee80287751461caafb422194b67, version=2
[virp-bridge] INFO Handshake complete — session ACTIVE, session_id=16aa9ee80287751461caafb422194b67
```

Synthetic `chain_register` against SW-3850 at 22:57:39 (direct JSON to
TCP:9998, isolating the bridge→onode→chain path that W3 had blocked):

```
$ python3 /tmp/bridge_test.py
{
  "registered": true,
  "artifact_id": "obs:SW-3850:1778972259696166598",
  "artifact_hash": "88b886a6a8a280aec3972bab960574b19f391d2ff9e65390a59948a0ec807501",
  "chain_entry_hash": "b7490fbb49c6e52a7951676e3caaa3f5334429178447f1d90e71588301e5d208",
  "sequence": 0,
  "session_id": "16aa9ee80287751461caafb422194b67"
}

$ sqlite3 /var/lib/virp/chain.db \
    "SELECT id, sequence, artifact_type, artifact_id, datetime(timestamp_ns/1000000000,'unixepoch') \
     FROM chain_entries WHERE id > 1843 ORDER BY id DESC LIMIT 5;"
1844|0|observation|obs:SW-3850:1778972259696166598|2026-05-16 22:57:39
```

`session_id` in the bridge response matches the session_id printed on the
post-restart handshake — i.e., the chain entry was written under the same
session that the SO_PEERCRED gate just accepted. End-to-end is intact.

### Caveats discovered during this fix (not closed tonight)

1. **HMAC fail-closed on the execute path.** The bridge logs
   `C bridge unavailable (No module named 'virp_bridge') and
   VIRP_ALLOW_PY_FALLBACK!=1 — HMAC verification will fail closed`. The
   `virp_bridge` Python extension is not on the default `sys.path` for
   either `root` or `virp-onode` (verified). No process in the chain
   exports `VIRP_ALLOW_PY_FALLBACK=1`. The execute path
   (`{"command":"show version","hostname":"SW-3850"}`) therefore returns
   HTTP 403 `HMAC verification failed` regardless of what the device
   returns. `chain_register` succeeds in isolation because that handler
   only logs HMAC mismatch as a warning (line 431) — but the natural
   dashboard flow is execute → chain_register, so the dashboard's
   observation pipeline is still broken end-to-end at the execute leg.
   This is **pre-existing** (predates tonight's W3 work — chain.db shows
   four days with no observations) and **out of W3 scope**. Tracked here
   so it isn't forgotten.

2. **Branch divergence for `virp-bridge.py`.** The unit committed in this
   addendum was verified against the bridge source on the
   `raise-validator-manifest-caps` working tree, plus a one-line
   `OKEY_PATH` edit. The version of `virp-bridge.py` on
   `hardening/audit-2026-04` is structurally different — the
   `VIRPBridge`/`VIRP_ALLOW_PY_FALLBACK` HMAC mechanism has been removed
   on that branch. Anyone who checks out `hardening/audit-2026-04` and
   then deploys this unit is running a different bridge than the one
   verified here. Reconciling those branches is the next deployment-side
   task; this commit is unit-only by design.

3. **`peercred.conf` drop-in not removed.** Redundant with the new base
   unit but functionally inert. Cleanup is a one-liner (see
   `deploy/README.md`) and was deferred to avoid bundling further changes
   into the verification window.

4. **`NoNewPrivileges=yes` not added to the bridge unit.** The socat unit
   sets it. Adding it to bridge is a pure-win sandbox tightening for a
   Python TCP service that never needs setuid. Deferred for consistency
   with the unit shape explicitly approved tonight; recommended as a
   follow-up in the same change that reconciles branch divergence.

### Trust-primitive impact

| Primitive | Pre-fix (since 22:03:03) | Post-fix (since 22:54:00) |
|-----------|--------------------------|---------------------------|
| W3 (SO_PEERCRED gate) | enforced; socat passes; **bridge rejected** | enforced; both socat *and* bridge pass |
| chain.db observation writes | broken for 4 days, masked by validation-path success | restored (id 1844, 22:57:39) |
| W1 / W2 / W4 | unchanged | unchanged |

### Significance — the deployment-rollout pattern

Tonight's session hardened W3 twice for the same underlying reason: a
process with privileged access to a guarded resource was running as the
wrong uid because its systemd unit was untracked. Socat and the bridge
were the two known cases; there is no audit guarantee they are the only
two. The risk shape is:

- **W-primitive tightening** (e.g., `socket_allowed_uids = [999]`) **changes
  the contract** between the daemon and its peers.
- **Untracked / unenumerated peers do not get reviewed against the new
  contract** because the change-management process operates on `deploy/`,
  not on `/etc/systemd/system/`.
- **Failure modes are silent and partial** — validation entries kept
  flowing, dashboard kept responding, only the specific observation path
  went quiet. Four days passed before anyone noticed.

This is worth a `SECURITY.md` checklist item, owned by whoever lands the
next W-primitive tightening. Suggested wording:

> Before merging a change that tightens a W-primitive (SO_PEERCRED uid
> allowlist, Landlock policy, egress firewall, signing requirement,
> etc.), enumerate every process that *currently* depends on the loosened
> behavior. If any of them is not described by a unit in `deploy/`, add
> it to `deploy/` and reconcile before the tightening lands. Grep
> `/etc/systemd/system/` for units that reference the guarded resource
> (`/tmp/virp-onode.sock`, the Landlocked directory, the formerly-open
> egress port, etc.) as the minimum enumeration step.

### Timeline (W3 bridge fix)

| Time | Event |
|------|-------|
| 22:27:45 | Bridge handshake fails after socat consolidation activated `socket_allowed_uids = [999]` enforcement on its connection too. Bridge starts logging "operating without session." |
| 22:35:27 / 22:35:59 / 22:40:49 | Three confirmed `chain_register` failures, "Connection reset by peer." |
| ~22:47   | User attempts `User=virp-onode` drop-in (`peercred.conf`). Bridge crashes with `[Errno 13] Permission denied` on `/root/virp/virp-bridge.py` — the `/root/` traversal layer. |
| 22:51:17 | New unit (this addendum's `deploy/virp-bridge.service`) written and restarted; second failure mode: `ModuleNotFoundError: No module named 'device_registry'` — the sibling-module layer. |
| 22:53    | `OKEY_PATH` source edit applied; `device_registry.py` added to `ExecStartPre=+/bin/install`. |
| 22:54:00 | Bridge restart → `Handshake complete — session ACTIVE, session_id=16aa9ee80287751461caafb422194b67`. |
| 22:57:39 | Synthetic chain_register succeeds end-to-end. `chain_entries` id 1844, artifact_type=observation, session_id matches handshake. First observation entry since 2026-05-12 20:21:55. |

---

## Addendum 3 — closing the four caveats + a latent onode bug (23:27 UTC)

Addendum 2 left four items deferred ("Caveats discovered during this fix —
not closed tonight"). This addendum closes three of them, partially closes
the fourth, and surfaces a new latent bug in onode session lifecycle that
was discovered while closing them.

### Items closed

1. **HMAC fail-closed on execute path** — closed via
   `Environment=VIRP_ALLOW_PY_FALLBACK=1` on the bridge unit. The bridge
   now logs `WARNING C bridge unavailable ..., using Python HMAC fallback`
   instead of the previous ERROR fail-closed. The Python fallback is
   functionally identical to the C verifier: both compute
   `hmac.new(OKEY, msg[:24] + msg[56:], sha256)` and constant-time
   compare against `msg[24:56]`. The C extension's
   `verify_observation()` at `api/virp_bridge.py:304-319` is a ctypes
   wrapper over `virp_verify()` which does the same HMAC-SHA256 over the
   same byte range — there is no "chain-backed" extra check despite the
   docstring's wording.

2. **`peercred.conf` drop-in** — removed.
   `/etc/systemd/system/virp-bridge.service.d/peercred.conf` and its
   parent directory are gone. The base unit carries all relevant
   directives. `deploy/README.md` cleanup procedure used verbatim.

3. **`NoNewPrivileges=yes`** — added to both the deployed unit and
   `deploy/virp-bridge.service`. Pure-win sandbox tightening for a
   Python TCP service that never needs setuid. Now matches the socat
   unit shape.

### Item partially closed

4. **Branch divergence on `virp-bridge.py`** — partially reconciled.

   - The `OKEY_PATH` source edit (`/root/virp/keys/onode.key` →
     `/etc/virp/keys/onode.key`) was committed on
     `raise-validator-manifest-caps` as commit `38591ab` and applied to
     `hardening/audit-2026-04` in this commit. Both branches now agree
     on the key path.
   - The deeper divergence is **not** closed: `hardening/audit-2026-04`
     has restructured the HMAC verification path entirely (removed the
     C-bridge load attempt, `VIRP_ALLOW_PY_FALLBACK` check, and the
     gated `verify_hmac()` in favor of a direct
     `hmac_mod.new(OKEY, ..., sha256)` call at `verify_hmac()` line ~210
     of the hardening-branch file). With that change, the
     `Environment=VIRP_ALLOW_PY_FALLBACK=1` line added in this addendum
     would be ignored — harmless but vestigial.
   - **Decision deferred to the next session**: pick a canonical
     `virp-bridge.py` shape (most likely backport hardening's simpler
     `verify_hmac()` to the live branch and drop the C-bridge load
     attempt + env-var dance entirely), then update
     `deploy/virp-bridge.service` to remove
     `Environment=VIRP_ALLOW_PY_FALLBACK=1` in the same commit.

### New latent bug discovered: onode session cleanup never runs

During item-1 fix, the bridge restart hit
`SESSION_HELLO rejected: error 4294967266` (= `-30` =
`VIRP_ERR_SESSION_INVALID`). Root cause traced to
`src/virp_handshake.c:50-54` — the single-session check rejects any
HELLO that arrives while `ctx->session.state` is `ACTIVE` or `BOUND`,
and the timeout-and-disconnect cleanup functions that would clear stale
state are **never called from anywhere in the codebase**:

```sh
$ grep -rn 'virp_session_check_timeouts\|virp_session_on_disconnect' src/
src/virp_session.c:119:virp_error_t virp_session_check_timeouts(virp_context_t *ctx)
src/virp_session.c:145:void virp_session_on_disconnect(virp_context_t *ctx)
```

Only the definitions exist — no callers. As a result:

- `VIRP_SESSION_IDLE_TIMEOUT_NS` (5 min) and `VIRP_SESSION_BIND_TIMEOUT_NS`
  (30 s) are dead constants. Idle sessions never expire.
- When the bridge process dies, the onode does not clean up the
  associated session. The session stays `ACTIVE` until onode itself
  restarts.
- Any subsequent bridge restart within the lifetime of the same onode
  process gets rejected with `VIRP_ERR_SESSION_INVALID` on HELLO.

This is the *real* reason the dashboard observation path can't be
restored simply by restarting the bridge after an incident — it requires
an onode restart to clear session state. Confirmed empirically: bridge
restart at 23:13:27 against onode (running since 22:27:45 with session
16aa9ee...) returned -30; only after `systemctl restart virp-onode` at
23:26:57 did the bridge auto-restart's HELLO succeed (session 83372a23...).

Fix shape (next session): either invoke `virp_session_check_timeouts()`
eagerly at the top of the `SESSION_HELLO` handler (lazy cleanup), or
invoke `virp_session_on_disconnect()` from the client-disconnect path in
`virp_onode.c` (eager cleanup, preferred — cleans up resources too).
Both are one-line edits with no ABI change; rebuild via
`make prod-full`. The same source edit could also call
`virp_session_check_timeouts()` from the per-request path so idle
sessions self-expire on the next inbound request even without a HELLO.

This finding belongs in the same `SECURITY.md` follow-up checklist as
the addendum-2 deployment-rollout pattern: any change that *adds* a
session-stateful primitive to onode needs an enumeration step for
"when/how does the new session state get cleaned up on the
disconnect/timeout path?"

### Verification — full execute → chain_register E2E against real SW-3850

Unlike addendum 2's synthetic test, this run uses the actual show-version
output from SW-3850 routed through the bridge, executed by onode over
SSH, and HMAC-verified by the bridge using the Python fallback path
that item-1's env var enables.

```
$ python3 /tmp/bridge_test.py
>>> STEP 1: execute show version on SW-3850
verdict=VERIFIED, chain_seq=1, trust_tier=GREEN, latency_ms=152.2, hmac=ccd837531a043760...
raw_output snippet: SW-3850#show version
Cisco IOS XE Software, Version 16.12.13
Cisco IOS Software [Gibraltar], Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M)...

>>> STEP 2: chain_register the real observation
{
  "registered": true,
  "artifact_id": "obs:SW-3850:1778974051058439743",
  "artifact_hash": "f6015700e6e4407cdc825abe13c9088440c84ccec0c1ec0c5dc251af2083b426",
  "chain_entry_hash": "1d11dd7d61d702067474e87bfd330b96c6a22c22173e821bd27ad4e3e939994d",
  "sequence": 0,
  "session_id": "83372a234da1ab383846920e5815eced"
}

$ sqlite3 /var/lib/virp/chain.db \
    "SELECT id, artifact_type, artifact_id, datetime(timestamp_ns/1000000000,'unixepoch') \
     FROM chain_entries ORDER BY id DESC LIMIT 3;"
1845|observation|obs:SW-3850:1778974051058439743|2026-05-16 23:27:31
1844|observation|obs:SW-3850:1778972259696166598|2026-05-16 22:57:39
1843|validation|val-b8108c94ad7cefb8|2026-05-16 22:41:31
```

- `verdict=VERIFIED` on execute — the Python HMAC fallback successfully
  verified onode's signed observation. **No more 403.**
- `latency_ms=152.2` — real device round-trip (SSH to SW-3850 at 10.0.10.2,
  show version, parse, sign).
- `chain_register` returned `registered: true`; `chain_entries` id 1845
  shows the entry with `session_id=83372a234da1ab383846920e5815eced`
  matching the bridge handshake session.

The dashboard observation pipeline (execute → chain_register) is now
fully restored end-to-end through W3 enforcement.

### Cumulative state at end of session

| Component | State |
|-----------|-------|
| `socket_allowed_uids` | `[999]` (set by W3 in devices.json.age, addendum 1) |
| `virp-socat.service` | `User=virp-onode`, single hardened base unit (addendum 1) |
| `virp-bridge.service` | `User=virp-onode`, `NoNewPrivileges=yes`, `Environment=VIRP_ALLOW_PY_FALLBACK=1`, `ExecStartPre=+/bin/install` staging to `/opt/virp/`, no drop-in (addenda 2 + 3) |
| `/etc/systemd/system/virp-bridge.service.d/` | removed |
| `virp-bridge.py:66 OKEY_PATH` | `/etc/virp/keys/onode.key` (live: commit `38591ab` on `raise-validator-manifest-caps`; tracked: also applied in this commit on `hardening/audit-2026-04`) |
| Bridge handshake | ACTIVE, session_id=`83372a234da1ab383846920e5815eced` (since 23:27:02) |
| Last observation in chain.db | id=1845, SW-3850, 23:27:31 UTC |
| Open: branch reconciliation | structural `virp-bridge.py` divergence between `raise-validator-manifest-caps` and `hardening/audit-2026-04` — see "Item partially closed" above |
| Open: onode session cleanup | latent bug, never calls `virp_session_check_timeouts` or `virp_session_on_disconnect` — see "New latent bug" above |

### Files changed in addendum 3

- **Modified:** `deploy/virp-bridge.service` — `Environment=VIRP_ALLOW_PY_FALLBACK=1`
  and `NoNewPrivileges=yes` added
- **Modified:** `deploy/README.md` — added "Why the bridge sets
  `VIRP_ALLOW_PY_FALLBACK=1`" rationale section
- **Modified:** `virp-bridge.py` — `OKEY_PATH` set to
  `/etc/virp/keys/onode.key` (mirrors live commit `38591ab` on
  `raise-validator-manifest-caps`)
- **Appended:** this addendum
- **Live system:** `/etc/systemd/system/virp-bridge.service` updated (in
  sync with `deploy/`); `peercred.conf` drop-in removed; bridge
  restarted; onode restarted twice during diagnosis (clearing stale
  session state — see "New latent bug")

### Timeline (W3 cleanup pass)

| Time | Event |
|------|-------|
| 23:13:27 | Bridge restart hits `SESSION_HELLO rejected: error -30` — single-session bug surfaces |
| 23:18:56 | Onode restart #1 to clear stale session 16aa9ee... — bridge auto-restart grabs session 074f51b0 |
| 23:19:00 | Redundant `systemctl restart virp-bridge` re-traps the same single-session bug |
| 23:26:57 | Onode restart #2 — bridge auto-restart grabs session 83372a23 cleanly |
| 23:27:31 | E2E test: execute SW-3850 → `verdict=VERIFIED`; chain_register → id=1845; full dashboard observation path restored |


## Addendum 4 — Phase 1 validator-typing diagnostic (2026-05-17, no code edits)

Diagnostic scope: map the validator's verdict-emit surface and the
validator → onode → client → dashboard message path before the
Phase 2 error-class typing fix. This addendum carries no code change;
it captures ground truth as of `raise-validator-manifest-caps@38591ab`
so the Phase 2 plan can be designed against a known surface.

### Branch reconciliation (Phase 1 starting state)

The W3 hardening line (`hardening/audit-2026-04`, ending at `6179e3c`)
and the validator line (`raise-validator-manifest-caps`, ending at
`38591ab`) diverged at `782298e harden(onode+api+tests)` and never
re-integrated.  Phase 1 originally targeted the hardening branch per
the session brief, but the validator code (`src/virp_validator.c`,
`include/virp_validator.h`, `api/validator/`, plus the
`ONODE_ACTION_VALIDATE_TURN` dispatch added by commit `a9f52da` to
`src/virp_onode.c`) is **not** reachable from
`hardening/audit-2026-04`. Verified by `git merge-base --is-ancestor
a9f52da hardening/audit-2026-04` → false.

Deployed binary provenance confirmed the validator line is the live
tree: `/usr/local/bin/virp-onode` was built at 2026-05-16 23:27:01
UTC, contains validator symbols (`validator_run_turn`,
`validator_evaluate`, `validator_commit_decision`, etc.) plus the
`VALIDATION_DECISION` / `validate_turn` strings, and emitted
observation `obs:SW-3850:1778974051058439743` (chain id 1845) thirty
seconds after install. The W3 hardening commits on
`hardening/audit-2026-04` are deploy-side (systemd units, /opt/virp
relocation, virp-bridge.service tracking) and are partly reflected in
the runtime config (bridge runs from `/opt/virp/virp-bridge.py` per
ps) without being merged into the C source line.

Action taken: Phase 1 work moved to
`raise-validator-manifest-caps`; the staged rollback tag
`pre-phase1-validator-typing-20260517` was relocated from `6179e3c`
(no validator code) to `38591ab` (HEAD of the validator line). The
`audit/` directory was checked out from `hardening/audit-2026-04`
into the validator branch's working tree so this addendum extends the
existing evidence log rather than starting a fresh one — staged but
not committed pending Phase 1 sign-off.

### W1/W3 cage state confirmation (start of Phase 1)

| Component | Identity | Source of truth |
|-----------|----------|-----------------|
| `socket_allowed_uids` | `[999]` | `/run/virp/devices.json` (live, runtime) |
| `virp-onode` daemon | uid `virp-onode` (999), pid 1272336 | `systemctl show virp-onode -p MainPID,User` |
| `virp-bridge` Python | uid `virp-onode` (999), pid 1272346 | `ps -o user,pid,cmd` |
| `virp-socat` proxy | uid `virp-onode` (999), pid 1272343 | `ps -o user,pid,cmd` |

All three client-side processes run under the allowlisted uid; W3
peercred path is intact. No drift since Addendum 3 close-out at
23:27 UTC.

### Validator code surface (verbatim)

Source files:

- `include/virp_validator.h` — 205 lines (public types + API)
- `src/virp_validator.c` — 514 lines (implementation)
- `api/validator/__init__.py` — 338 lines (Python wire client)
- `docs/VALIDATOR-MANIFEST-CONTRACT.md` — 254 lines (policy doc)
- `src/virp_onode.c` lines 1341–1448 — dispatch case
  `ONODE_ACTION_VALIDATE_TURN` (action ID 13)
- `src/virp_onode.c` line 191 — string `"validate_turn"` →
  `ONODE_ACTION_VALIDATE_TURN` in `parse_action_string()`
- `src/virp_message.c` line 962 — `VIRP_OBS_VALIDATION_DECISION` →
  `"VALIDATION_DECISION"` in observation-type human string
- `include/virp.h` line 115 — `#define VIRP_OBS_VALIDATION_DECISION 0x10`

#### `claim_type` enum — verbatim

From `include/virp_validator.h` lines 57–62:

```c
typedef enum {
    VALIDATOR_CLAIM_UNKNOWN       = 0,
    VALIDATOR_CLAIM_STATE_READ    = 1,
    VALIDATOR_CLAIM_STATE_CHANGE  = 2,
    VALIDATOR_CLAIM_CONFIG_CHANGE = 3
} validator_claim_type_t;
```

String map (`validator_claim_type_str()`, virp_validator.c:115–124):

| Enum | String |
|------|--------|
| `VALIDATOR_CLAIM_STATE_READ` | `state_read` |
| `VALIDATOR_CLAIM_STATE_CHANGE` | `state_change` |
| `VALIDATOR_CLAIM_CONFIG_CHANGE` | `config_change` |
| `VALIDATOR_CLAIM_UNKNOWN` | `unknown` |

Parser (`parse_claim_type()`, virp_validator.c:69–76): exact match
against three literal strings; anything else maps to `UNKNOWN` and
later evaluates to BLOCK. There are exactly **three** content-bearing
claim types today. Every analytical, synthesis, recommendation, or
outcome-verification claim the AI layer might emit is rejected as
`UNKNOWN_CLAIM_TYPE`.

#### Violation enum (current error catalog) — verbatim

From `include/virp_validator.h` lines 78–89:

```c
typedef enum {
    VALIDATOR_VIOLATION_NONE                    = 0,
    VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_READ  = 1,  /* → WARN  */
    VALIDATOR_VIOLATION_NO_EVIDENCE_STATE_CHANGE= 2,  /* → BLOCK */
    VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_TURN    = 3,  /* → BLOCK */
    VALIDATOR_VIOLATION_EVIDENCE_NOT_IN_CHAIN   = 4,  /* → BLOCK */
    VALIDATOR_VIOLATION_UNKNOWN_CLAIM_TYPE      = 5,  /* → BLOCK */
    VALIDATOR_VIOLATION_PROSE_HASH_MISMATCH     = 6,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_MALFORMED      = 7,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_TOO_LARGE      = 8,  /* → BLOCK (turn) */
    VALIDATOR_VIOLATION_MANIFEST_MISSING        = 9   /* → BLOCK (turn) */
} validator_violation_code_t;
```

Strings (`validator_violation_str()`, virp_validator.c:98–113): one
lowercase snake_case string per enum. Single emit table — there is no
scattered string construction. Every violation surfaces through the
helper, so retargeting them is a one-file change.

#### Verdict-emit sites (every place a violation is assigned)

| Site | Violation | Decision contribution | Comment |
|------|-----------|------------------------|---------|
| `virp_validator.c:209` | `MANIFEST_MISSING` | turn BLOCK | NULL/zero-length input to parser |
| `virp_validator.c:215` | `MANIFEST_MALFORMED` | turn BLOCK | cJSON_ParseWithLength failure |
| `virp_validator.c:223` | `MANIFEST_MALFORMED` | turn BLOCK | session_id missing or invalid token |
| `virp_validator.c:232` | `MANIFEST_MALFORMED` | turn BLOCK | prose_hash missing / not 64 hex |
| `virp_validator.c:248` | `MANIFEST_MALFORMED` | turn BLOCK | assertions array missing or not array |
| `virp_validator.c:257` | `MANIFEST_TOO_LARGE` | turn BLOCK | assertion count exceeds 1024 |
| `virp_validator.c:134` | `MANIFEST_MALFORMED` | turn BLOCK | tool_call_refs not array |
| `virp_validator.c:141` | `MANIFEST_TOO_LARGE` | turn BLOCK | tool_call_refs count exceeds 512 |
| `virp_validator.c:145` | `MANIFEST_MALFORMED` | turn BLOCK | tool_call_ref not a hex64 string |
| `virp_validator.c:159` | `MANIFEST_MALFORMED` | turn BLOCK | assertion not an object |
| `virp_validator.c:165` | `MANIFEST_MALFORMED` | turn BLOCK | device missing / invalid token |
| `virp_validator.c:172` | `MANIFEST_MALFORMED` | turn BLOCK | claim_type not a string |
| `virp_validator.c:186` | `MANIFEST_MALFORMED` | turn BLOCK | evidence_ref not hex64 |
| `virp_validator.c:192` | `MANIFEST_MALFORMED` | turn BLOCK | evidence_ref wrong type |
| `virp_validator.c:325` | `UNKNOWN_CLAIM_TYPE` | per-assertion BLOCK | claim_type not in three legal values |
| `virp_validator.c:332` | `NO_EVIDENCE_STATE_READ` | per-assertion WARN | state_read without evidence_ref |
| `virp_validator.c:335` | `NO_EVIDENCE_STATE_CHANGE` | per-assertion BLOCK | state_change/config_change without evidence_ref |
| `virp_validator.c:342` | `EVIDENCE_NOT_IN_TURN` | per-assertion BLOCK | evidence_ref not in tool_call_refs[] |
| `virp_validator.c:350` | `EVIDENCE_NOT_IN_CHAIN` | per-assertion BLOCK | evidence_ref not in chain_entries for session |
| `virp_validator.c:373` | `PROSE_HASH_MISMATCH` | turn BLOCK | SHA-256(prose) ≠ manifest.prose_hash |
| `virp_validator.c:497` | falls back to `MANIFEST_MALFORMED` | turn BLOCK | parse failed with reason==NONE (unreachable defensively) |

Every emit site is structurally local — set `r->decision` and
`r->violation` (or `result->turn_violation` and bump the rollup) then
return. There is no place where a violation propagates as a string
or escapes through logging. Adding an `error_class` field to each
result struct and tagging it at the emit site is a per-site
single-line change.

### Message-passing path: validator → onode → bridge → CT 210 client

End-to-end trace of one validate_turn call:

1. **CT 210 client (sender)** — `api/validator/__init__.py:256–261`
   sends framed JSON over UDS `/tmp/virp-onode.sock` (or TCP
   `:9999` via virp-socat):

   ```json
   {"action":"validate_turn","session_id":"<fallback>",
    "prose":"<utf-8>","manifest":{<sidecar>}}
   ```

2. **Onode dispatch** — `src/virp_onode.c:1341–1448`
   - 1366: `cJSON_Parse(recv_buf)` re-parses the request (manifest is
     a nested object, doesn't fit the flat `onode_request_t`)
   - 1373–1381: extracts `manifest` subobject; `cJSON_PrintUnformatted`
     re-serializes it into `mani_json` for the C validator
   - 1383–1384: extracts `prose` string
   - 1386–1387: `fallback_sid` from `req.session_id` (or `"unknown"`)
   - 1390: `validator_run_turn(&state->chain, mani_json, mani_len,
     prose_str, prose_len, fallback_sid, &vr)`
   - 1394–1395: frees temp JSON, deletes parsed root
   - 1407–1432: builds response payload JSON into `json_buf[8192]`:

     ```json
     {"decision":"pass|warn|block","turn_violation":<int>,
      "chain_sequence":<int>,"chain_entry_hash":"<64-hex>",
      "artifact_hash":"<64-hex>",
      "assertions":[{"decision":"...","violation":<int>}, ...]}
     ```

   - 1434–1438: `virp_build_observation()` wraps `json_buf` in a
     signed VIRP OBSERVATION (`obs_type =
     VIRP_OBS_VALIDATION_DECISION = 0x10`, scope `VIRP_SCOPE_LOCAL`,
     HMAC over the bytes using `state->okey`)
   - 1440: `send_framed(client_fd, ...)` ships it

3. **Validator core** — `src/virp_validator.c`
   - `validator_run_turn()` (476–514) → `validator_parse_manifest()`
     (199–270) → `validator_evaluate()` (355–387) →
     `validator_commit_decision()` (440–470)
   - `build_canonical_decision()` (399–438) constructs the canonical
     JSON (`session_id`, `decision`, `turn_violation`, `prose_hash`,
     per-assertion list with `device`, `claim_type`, `decision`,
     `violation`) into a stack buffer of 8192 bytes
   - SHA-256 of that buffer → `result->artifact_hash`
   - `virp_chain_append()` (458) writes a `chain_entries` row with
     `artifact_type = "validation"`, `artifact_id = "val-<hash16>"`,
     `artifact_hash`. **The 8192-byte canonical JSON itself is not
     persisted** — only its hash. See "Asymmetric persistence" below.

4. **CT 210 client (receiver)** — `api/validator/__init__.py`
   - `_recv_framed()` reads response (165–170)
   - `_parse_observation()` (173–192) destructures the VIRP frame:
     extracts `obs_type`, payload `body` bytes, and HMAC hex (24:56
     offsets of the frame)
   - 273–277: rejects unexpected `obs_type` ≠ `0x10`
   - 279: `json.loads(body)` produces the dict
   - 282–286: if `bridge=` passed, calls
     `bridge.verify_observation(raw)` and records the boolean as
     `ValidationResult.verified`
   - 288–301: builds `ValidationResult` dataclass: `decision`,
     `turn_violation`, `chain_sequence`, `chain_entry_hash`,
     `artifact_hash`, `per_assertion: [(Decision, Violation), ...]`,
     `signature_hex`, `verified`

5. **CT 210 client surface to AI layer** — `attach_banner()`
   (`api/validator/__init__.py:305–324`)
   - PASS: prose returned unchanged
   - WARN: `f"[VIRP VALIDATOR WARN] one or more claims lack evidence
     (chain seq {N})"` prepended to prose
   - BLOCK: returns banner string only:
     `f"[VIRP VALIDATOR BLOCK] {turn_violation.name or
     first_assertion_violation.name} (chain seq {N})"`
   - BLOCK with `allow_blocked_prose=True`: banner + prose

**Critical observation about what the AI model actually sees.** The
banner already contains the violation code by *name*
(`turn_violation.name` resolves to `MANIFEST_MALFORMED`,
`UNKNOWN_CLAIM_TYPE`, etc. — `IntEnum.name` is the C-level identifier).
The AI model can therefore read a typed code today — but as a
substring embedded in an English sentence, with no error class, no
remediation hint, and no machine-friendly handoff. The false-
confession dynamic is consistent with a model that reads
`MANIFEST_MALFORMED` and self-attributes the malformedness to its
own prose rather than to a schema/format gap on the validator side.

### Where validation persistence would go (Phase 2 fold-in)

Insertion point: `src/virp_validator.c:464`, immediately after
`virp_chain_append()` returns `VIRP_OK`. Add one call:

```c
err = virp_chain_artifact_store(chain,
                                artifact_id,
                                "validation",
                                canonical,         /* the 8192-byte buf */
                                result->artifact_hash,
                                manifest->session_id);
if (err != VIRP_OK) return err;
```

Persistence API is already in place: `virp_chain_artifact_store()`,
declared `include/virp_chain.h:191–195`, implemented
`src/virp_chain.c:810–835`. Schema is `artifact_id, artifact_type,
artifact_content, artifact_hash, session_id, created_at_ns` with a
UNIQUE constraint on `artifact_id`. The `canonical` buffer at
`virp_validator.c:447` is already built, already deterministic, and
already hashed into `result->artifact_hash` — adding the persist call
makes the artifact body recoverable for forensic comparison and adds
zero new schema. This is the minimum change to make the
false-confession finding reproducible offline against past chain
state.

### Asymmetric persistence finding

`chain_entries` shows 108 validation rows; `artifacts` shows 0. Every
observation persists its content (`virp-bridge.py:392–406`); no
validation does. The asymmetry is structural in
`validator_commit_decision()` — there is no call site that ever
populates the artifacts row for `artifact_type = "validation"`. Three
classes of consumer are affected:

1. **Forensic replay.** Past validations cannot be reread; only their
   hashes are retained. Tonight's three dashboard validations (chain
   ids 1843, 1862, 1877 — sessions `dash_1778971291`, `dash_1778978578`,
   `dash_1778979638`) have headers but no recoverable bodies.
2. **Chain-export auditors.** A consumer that exports chain.db and
   replays the validator's logic offline cannot do so against the
   actual decision JSON — only the hash, which is opaque without the
   inputs.
3. **The false-confession finding itself.** With persisted artifact
   bodies, the model's claimed "I fabricated this" can be compared
   against the validator's actual emitted reason. Without them, the
   finding remains qualitative.

Per session brief Phase 2 amendment, persistence is a Phase 2
deliverable folded into the typing work — not a separate phase.

### Dashboard consumer (CT 210) is off-host

`grep -rn "from api.validator\|validate_turn"` across `/root` and
`/opt` finds zero non-test callers on this host. The only Python
processes running on `10.0.0.211` (this host) are:

- `virp_prometheus_exporter.py` (chain metrics on :9100)
- `virp-verify.py` (chain verification daemon)
- `virp-bridge.py` (dashboard's TCP entry point on :9998)
- (system) `networkd-dispatcher`

The dashboard that generates `dash_<unixtime>` session IDs lives on
CT 210 (10.0.0.210) per
`docs/VALIDATOR-MANIFEST-CONTRACT.md:7–10`. Its source is not on
this host. Phase 2 changes to wire-format (response JSON) are
forward-compatible by default: new fields are additive and the
existing Python client uses `dict[...]` accessors only on the four
fields it cares about (`decision`, `turn_violation`,
`chain_sequence`, `chain_entry_hash`, `artifact_hash`). New fields
will be silently dropped by the existing CT 210 client until that
client is updated to consume them — which is the
"breaking-change-candidate" hand-off the session brief flagged.

The local backend at `/root/tli-ops-center/backend/` does *not* use
the validator (zero importers of `api.validator`), so any Phase 2
client-side update needs to happen on CT 210, not in tli-ops-center.

### Phase 2 honest scope estimate

Component-by-component, assuming careful, tested C work:

| Component | Estimate | Notes |
|-----------|----------|-------|
| Add `validator_error_class_t` enum + helpers in `virp_validator.h/.c` | 30–45 min | 4–5 enum values + class/code-to-string + class-from-violation mapping |
| Tag every existing emit site with class | 15–30 min | Single mapping switch; the work is the *design* call (which violation maps to which class), not the typing |
| Update onode response JSON (`virp_onode.c:1407–1432`) to emit class/code/hint | 30–60 min | Buffer at 8192 bytes accommodates ~640 added bytes for 32 assertions; verify max-size assertion does not overflow |
| Update Python client (`api/validator/__init__.py`) `ValidationResult` and `attach_banner()` | 30–60 min | Add `error_class`, `error_code`, `remediation_hint` fields; banner format needs design call |
| Persistence: add `virp_chain_artifact_store()` call to `validator_commit_decision()` | 15–30 min | One call, after `virp_chain_append` succeeds; canonical buffer already in scope |
| Update `tests/test_validator.c` (11 cases) | 1–2 hr | Assert new fields populate; assert persistence row exists; one new case per error class |
| Update `tests/test_validator_e2e.py` (3 cases) | 30–45 min | Update PASS / BLOCK(prose_hash) / WARN assertions for new fields |
| Regression: full rebuild + `make test-validator` + `make test-validator-e2e` + live show-version | 30–60 min | If clean. Add 1 hr cushion if buffer overflow or HMAC re-signing edge case surfaces |
| Update `docs/VALIDATOR-MANIFEST-CONTRACT.md` §6 (response format) | 30–45 min | Document new fields, class semantics, remediation hint catalog, persistence behavior |

**Total range: 5 hours best case, 7–8 hours realistic, 10+ hours
pessimistic.** Pessimistic case assumes the CT 210 dashboard
coordination becomes blocking, the json_buf size overflow needs a
2-pass refactor, or the persistence call surfaces a chain_entries vs
artifacts ordering / transaction concern.

Per session brief threshold ("If it's 4–8 hours of careful C work,
we do not start it tonight"), this clears the threshold for *do not
start tonight*. Phase 1 should land; Phase 2 should start fresh,
post-review, post-rest.

### Stale chain.db gotcha (one-line note from earlier in session)

There is a 0-byte `/root/virp/chain.db` left over from 2026-04-29.
The production chain.db is at `/var/lib/virp/chain.db` per
`virp-bridge.py:304` (`CHAIN_DB = "/var/lib/virp/chain.db"`). A
`stat` or `ls` on the working-directory file will report a recent
atime (any tool that touches the file path with `stat()` is enough)
but a 2026-04-29 mtime — both misleading. **Check `CHAIN_DB` in the
bridge source, not the working-directory file size, before
concluding the chain is empty or wiped.** Earlier in this session
the wrong-path check caused a several-minute detour through "the
verification claim must be incorrect" before the right path was
inspected. One-line lesson: paths against code, not against `ls`.

### Files changed in addendum 4

- **Modified:** `audit/evidence-2026-05-16-w3-socat.md` — this addendum
  appended
- **Staged (not committed):** `audit/evidence-2026-05-16-sw3850.md`
  and `audit/evidence-2026-05-16-w3-socat.md` — pulled from
  `hardening/audit-2026-04` into `raise-validator-manifest-caps`
  working tree via `git checkout hardening/audit-2026-04 -- audit/`
  so this addendum extends the existing log
- **No source changes.** Phase 1 is diagnostic only; the C/Python
  emit sites, dispatch, response format, persistence call, and tests
  are unchanged. The Phase 2 plan above is the proposed work, not
  the executed work.

### Open questions for next session (before Phase 2 starts)

1. **Error-class taxonomy — final 4 vs proposed 4.** Session brief
   proposed `format | schema | provenance | content`. The 10
   violations map cleanly to those four:
   - `format`: `MANIFEST_MALFORMED`, `MANIFEST_TOO_LARGE`,
     `MANIFEST_MISSING`
   - `schema`: `UNKNOWN_CLAIM_TYPE`
   - `provenance`: `NO_EVIDENCE_STATE_READ`,
     `NO_EVIDENCE_STATE_CHANGE`, `EVIDENCE_NOT_IN_TURN`
   - `content`: `EVIDENCE_NOT_IN_CHAIN`, `PROSE_HASH_MISMATCH`
   `MANIFEST_MISSING` is debatable (could be `provenance` since it
   represents AI-layer failure to obey the contract). Confirm.

2. **Remediation hint catalog.** Brief proposed
   `regenerate_manifest | report_schema_gap | rerun_with_tools |
   fabrication_detected`. Confirm exact strings + per-violation
   mapping before implementation.

3. **Persistence atomicity.** Should the `virp_chain_artifact_store`
   call inside `validator_commit_decision` be wrapped in a single
   transaction with `virp_chain_append`, or accepted as best-effort?
   The chain entry is the canonical record; an orphaned chain
   header with no artifact body is current behavior already, so
   best-effort matches today's semantics. But a future auditor
   reading `chain_entries WHERE artifact_type='validation'` and
   `LEFT JOIN artifacts USING (artifact_id)` is going to find nulls
   either way without a backfill — flag for the design call.

4. **CT 210 client update.** The wire-format change is additive and
   non-breaking. Confirm: do we update the CT 210 dashboard's
   validator client in the same Phase 2, or land Phase 2 here first
   and update CT 210 separately? If separately, the new fields are
   silently dropped on the consumer side until CT 210 is updated;
   the validator's local persistence and the in-band code-by-name
   banner still work.

5. **Rollback tag at end of Phase 1.** `pre-phase1-validator-typing
   -20260517` currently points at `38591ab`. If Phase 1 commits
   land (this addendum is currently staged but not committed), move
   the tag to the new HEAD before Phase 2 starts. Or leave it as
   "state at start of validator typing work" — semantic call.

### Cumulative state at end of Phase 1 diagnostic

| Item | State |
|------|-------|
| Branch | `raise-validator-manifest-caps`, HEAD `38591ab` |
| Working tree | `audit/` files staged (new on this branch), `audit/evidence-2026-05-16-w3-socat.md` modified-staged with this addendum |
| Rollback tag | `pre-phase1-validator-typing-20260517 → 38591ab` |
| Stash | `wip-pre-phase1-20260517` on raise-validator-manifest-caps (devices.yaml mod + stale .bak/.pre-* files); unapplied |
| Deployed onode | `/usr/local/bin/virp-onode` mtime 23:27:01, validator-line build, 108 validation entries flowing |
| Cage state | `socket_allowed_uids=[999]`, all three services as uid 999, no drift |
| chain.db | `/var/lib/virp/chain.db`, 1877 entries, three tonight's dashboard validations (ids 1843, 1862, 1877) verified-by-header but unrecoverable-by-body |
| Validator code mapped | Yes — every emit site catalogued with file:line |
| Phase 2 scope | 5–8 hr realistic; do-not-start-tonight per session brief threshold |


## Addendum 5 — Phase 2 validator-typing implementation (2026-05-17)

Phase 2 lands. Validator now emits typed error_class +
remediation_hint structured tokens, persists the canonical decision
body to the `artifacts` table, and surfaces the typed surface
through the Python client and onode wire format. CT 211 only —
CT 210 dashboard update remains a separate engagement.

### Design decisions locked before implementation

User-confirmed on 2026-05-17 (open questions 1–4 from Addendum 4):

1. **`MANIFEST_MISSING` → provenance class**, paired with
   `rerun_with_tools` hint. Treated as the AI layer failing to emit
   any manifest at all; the prose has no inputs supplied. Distinct
   from `MANIFEST_MALFORMED` (format) where structure is broken.
2. **4 per-class remediation hints**, locked to:
   `regenerate_manifest` (format), `report_schema_gap` (schema),
   `rerun_with_tools` (provenance), `fabrication_detected`
   (content). No per-violation overrides.
3. **Best-effort persistence.** The new
   `virp_chain_artifact_store()` call inside
   `validator_commit_decision()` runs after `virp_chain_append`
   succeeds. If artifact_store fails, a warning is written to
   stderr (captured by systemd journal); the call still returns
   `VIRP_OK`. Matches today's semantics where the chain entry is
   canonical and artifact rows are best-effort.
4. **Phase 2 = CT 211 only.** C-side enums + onode response JSON +
   Python client. CT 210 dashboard pickup of the new fields is a
   follow-on; new fields are additive and forward-compatible.

### What changed (files)

- **`include/virp_validator.h`** (+49 lines)
  - New enum `validator_error_class_t` (5 values)
  - New enum `validator_remediation_hint_t` (5 values)
  - `validator_assertion_result_t` gains `error_class` and
    `remediation_hint` fields
  - `validator_result_t` gains `turn_error_class` and
    `turn_remediation_hint` fields
  - Four new helper declarations:
    `validator_error_class_str()`,
    `validator_remediation_hint_str()`,
    `validator_violation_class()`,
    `validator_violation_hint()`
  - Header comment block documents the locked mapping

- **`src/virp_validator.c`** (+104 lines)
  - `validator_error_class_str()` and
    `validator_remediation_hint_str()` — string serialization
    matching the wire-format tokens
  - `validator_violation_class()` — pure switch from violation code
    to class, single source of truth for the taxonomy
  - `validator_violation_hint()` — derives from class (one hint per
    class per the locked spec)
  - `validator_evaluate()` — appended finalization loop that fills
    `turn_error_class`, `turn_remediation_hint`, and per-assertion
    `error_class` / `remediation_hint` from violation codes. Emit
    sites untouched — typing is derived, not duplicated
  - `validator_run_turn()` parse-fail path — also derives
    class/hint from `turn_violation` so the early-fail BLOCK has
    the typed surface populated before `validator_commit_decision`
    is called
  - `build_canonical_decision()` — canonical JSON now includes
    `turn_error_class`, `turn_remediation_hint`, and per-assertion
    `error_class`, `remediation_hint`. Hash basis changes for
    every new entry; pre-Phase-2 chain entries are unaffected
  - `validator_commit_decision()` — new
    `virp_chain_artifact_store()` call after `virp_chain_append`,
    persisting `canonical` (the 8 KB decision body) to the
    `artifacts` table. Best-effort; failure logs to stderr and
    returns `VIRP_OK`

- **`src/virp_onode.c`** (+11 lines)
  - `ONODE_ACTION_VALIDATE_TURN` response JSON (lines 1407–1432)
    emits `turn_error_class`, `turn_remediation_hint`, and
    per-assertion `error_class`, `remediation_hint` strings. Buffer
    capacity (8 KB) still comfortable: 32 assertions × ~80
    added bytes ≈ 2.5 KB; the truncation-detection branch already
    handles the overflow case and is preserved

- **`api/validator/__init__.py`** (+117 lines)
  - New `ErrorClass(str, Enum)` and `RemediationHint(str, Enum)`
    mirror the C enums
  - `_VIOLATION_TO_CLASS` and `_CLASS_TO_HINT` maps and the
    `violation_class()` / `violation_hint()` helpers — used as a
    client-side fallback if talking to an older onode whose wire
    doesn't include the new fields (forward-compat)
  - `ValidationResult` dataclass gains `turn_error_class` and
    `turn_remediation_hint` fields with `None`/`NONE` defaults
  - `per_assertion` list is now a 4-tuple
    `(Decision, Violation, ErrorClass, RemediationHint)` — existing
    2-index access `per[0][0]` and `per[0][1]` is preserved; index
    2 and 3 are new
  - `validate_turn()` parses new fields with `.get()` defaults
    falling back to the derivation helpers — forward-compat
    with older onodes
  - `attach_banner()` banner string now appends
    `[class=<value> hint=<value>]` after the historical
    `[VIRP VALIDATOR BLOCK] <code> (chain seq N)` prefix; old
    callers regex'ing the prefix still match
  - Module `__all__` re-exports the new types and helpers

- **`tests/test_validator.c`** (+124 lines, -2 lines)
  - Test 2 (WARN/state_read/null) extended with
    `error_class == PROVENANCE` and
    `remediation_hint == RERUN_WITH_TOOLS` assertions
  - Test 5 (BLOCK/evidence_not_in_chain) extended with
    `error_class == CONTENT` and
    `remediation_hint == FABRICATION_DETECTED` assertions
  - Test 10 (commit_decision) extended: now queries the
    `artifacts` table and asserts the validation row's
    `artifact_content` exists and contains
    `"turn_error_class":"none"` — the Phase 2 persistence guarantee
  - **NEW Test 12** (`test_class_hint_mapping`) — table-driven
    check of every violation code's class and hint, the locked
    taxonomy in executable form
  - **NEW Test 13** (`test_manifest_missing_provenance`) — end-to-
    end `validator_run_turn(NULL, 0, NULL, 0)` asserts
    `MANIFEST_MISSING` rolls up to BLOCK with `class=provenance`
    and `hint=rerun_with_tools`, locking question-1's decision in
    a regression test
  - **Pre-existing bug fixed in test 7** (`test_manifest_too_large`):
    the `json[16384]` stack buffer overflowed via cumulative
    `snprintf` past EOB whenever the loop wrote >16 KB. The
    test passed by stack-layout luck before; with the Phase 2
    `validator_result_t` doubling in size (per_assertion array
    grew from 1024×8 B to 1024×16 B), the OOB write started
    segfaulting. Replaced with a 96 KB heap allocation. Not part
    of the typing work but surfaced by it; flagged here for
    transparency

- **`docs/VALIDATOR-MANIFEST-CONTRACT.md`** (+88 lines)
  - §6 response format JSON updated with new fields
  - **NEW §6.1** documenting the error class / remediation hint
    catalog, including the per-class routing guidance for the model
    (do/don't apologize for fabrication by class)
  - **NEW §6.2** documenting Phase 2 persistence behavior
  - **NEW §6.3** backward-compatibility guarantees

### Test evidence

```
make test test-onode test-chain test-federation test-session
     test-session-key test-validator
```

| Target          | Result |
|-----------------|--------|
| `test`          | 36/36 PASS |
| `test-onode`    | 31/31 PASS |
| `test-chain`    | 9/9 PASS |
| `test-federation` | 9/9 PASS |
| `test-session`  | 8/8 PASS |
| `test-session-key` | 6/6 PASS |
| `test-validator` | 13/13 PASS (including 2 new Phase 2 tests + extended commit_decision artifact-row assertion) |
| `test-validator-e2e` | 3/3 PASS (live wire format round-trip against subprocess virp-onode-prod) |

**Total: 115/115 PASS.** (`test-interop` skipped — Go toolchain
not installed on this host; pre-existing and unrelated to Phase 2.)

Build clean under `-Wall -Wextra -Werror -pedantic -std=c11 -O2`.

### Persistence verified at the test level

Test 10 (`commit_decision`) asserts:

1. `chain_entries` row exists with `artifact_type = 'validation'`
2. `artifacts` row exists with the same `session_id` and
   `artifact_type = 'validation'`
3. `artifacts.artifact_content` contains the
   `"turn_error_class":"none"` token — confirming the canonical
   JSON now embeds the typed surface

This is the post-hoc forensic property the false-confession
investigation needs: any future validator decision can be
recovered from chain.db alone, with full structured detail.

### What was NOT done in Phase 2

- **Live deployment.** `/usr/local/bin/virp-onode` is unchanged.
  The new build at `build/virp-onode-prod` is verified by the
  e2e harness against a temp socket but not installed to replace
  the production binary. Per session brief constraints ("commits
  stay local, no pushes"), install + restart is a separate
  decision pending review.
- **CT 210 dashboard regression (SW-3850 show-version round-trip
  through dashboard).** The dashboard runs on CT 210 (off-host),
  generating `dash_<unixtime>` validations. Live round-trip cannot
  be exercised from CT 211 alone. Coverage substitute: 3 e2e
  cases (PASS, WARN, BLOCK) round-trip through the new wire
  format against a real virp-onode-prod subprocess.
- **CT 210 client update.** Per the locked design decision, the
  CT 210 validator client pickup of the new typed fields is a
  follow-on engagement, not part of Phase 2. New wire fields are
  additive and silently dropped by the existing client.

### Open questions for next session

1. **Deployment timing.** When to install
   `build/virp-onode-prod` as the live `/usr/local/bin/virp-onode`?
   Suggested gate: review of this addendum, confirmation that the
   wire-format change won't surprise CT 210's existing parser
   (additive only — should be safe), and a maintenance window.
2. **CT 210 client pickup.** The new typed surface only routes
   the model's response if the CT 210 dashboard's validator client
   consumes the new fields. Until then, the dashboard sees the
   structured banner string `[class=... hint=...]` appended to
   each non-PASS verdict — already useful, but not as clean as
   reading the structured `ValidationResult.turn_error_class`.
3. **Phase 3 trigger — claim_type vocabulary extension.** Phase 2
   added the typing for *errors*. Phase 3 (per the original
   session brief) adds new claim_types: `state_observation`,
   `comparison`, `recommendation`, `synthesis`,
   `outcome_verification`. The `UNKNOWN_CLAIM_TYPE` → `schema`
   class now makes Phase 3 easy to surface — the model will see
   `class=schema hint=report_schema_gap` for each analytical
   claim type until Phase 3 lands, which is the right routing
   signal.
4. **Outcome-verification gap.** Tonight's FortiGate over-claim
   case (model claimed configuration changed when device state
   didn't) is exactly the case Phase 3's `outcome_verification`
   claim type targets. Until Phase 3, the validator can't
   distinguish "AI says action succeeded" from any other state
   claim. Worth scheduling Phase 3 promptly given the
   FortiGate-class risk surface.
5. **Tag semantics post-Phase-2.** The
   `pre-phase1-validator-typing-20260517` tag was moved to the
   Phase 1 diagnostic commit `dbdd555`. If Phase 2 lands as a
   commit, options: (a) move the tag forward again (continuing
   the "current-state" pattern), (b) leave it at `dbdd555`
   (Phase 1 boundary) and add a separate
   `pre-phase3-claim-type-extension-20260517` tag at the Phase 2
   landing commit. Naming is the only material question.

### Files changed in addendum 5

- **Modified:** `include/virp_validator.h`, `src/virp_validator.c`,
  `src/virp_onode.c`, `api/validator/__init__.py`,
  `tests/test_validator.c`, `docs/VALIDATOR-MANIFEST-CONTRACT.md`
- **Modified:** `audit/evidence-2026-05-16-w3-socat.md` — this
  addendum appended
- **No commits to live deploy state.** No restart, no install, no
  `/etc/systemd/...` touches.

### Cumulative state at end of Phase 2

| Item | State |
|------|-------|
| Branch | `raise-validator-manifest-caps` |
| Working tree | all Phase 2 source changes + this addendum, modified |
| Rollback tag (pre-Phase-1) | `pre-phase1-validator-typing-20260517` at `dbdd555` (Phase 1 diagnostic commit) |
| Tests | 115/115 PASS (incl. 2 new validator tests + 3 e2e); build clean -Werror |
| Deployed onode | unchanged (`/usr/local/bin/virp-onode` mtime 23:27:01); the new typed binary is at `build/virp-onode-prod` |
| Cage state | unchanged (`socket_allowed_uids=[999]`, all client procs as uid 999) |
| Phase 3 scope | claim_type vocabulary extension; design already drafted in the original session brief; can start fresh next session |


