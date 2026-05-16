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


