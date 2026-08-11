# VIRP Deployment Record — virp-lab

- **Role**: production reference instance

## Current live state (verified 2026-08-11 01:06 UTC)

**This block is authoritative for what is running right now.** Everything below
it is a chronological, append-only log: each section describes the state at the
time it was written and is deliberately *not* corrected in place. Where a fact
below disagrees with this block, this block wins. A copy of this file without
this block is stale — check the commit before relying on it.

- **Commit**: `569bff11517718e0347bdd48f82c9d3a2a7d6375` (short `569bff11`)
  — deployed 2026-08-11 01:00 UTC (consolidated main: branch consolidation +
  driver_linux AF_UNSPEC + installed virp-tool), superseding `5bda4deb`
  (2026-08-10 01:31 UTC); see the update log.
- **Branch**: `main` (consolidated 2026-08-10: `feat/cisco-config-scrub-netclaw-yellow` merged into main at `b446c3c2`; branch retired to `archive/feat/cisco-config-scrub-netclaw-yellow-2026-08-10`)
- **Daemon**: `/usr/local/lib/virp/virp-onode-prod`, unit `virp-onode.service`,
  socket `/run/virp/onode.sock`, chain `/var/lib/virp/chain.db`
  — binary sha256
  `27c0788354234cce2e19426b18f9eea70da680ab1c709ac7370516dd7b614bb5`
- **Client**: `/usr/local/lib/virp/virp-tool` (+ `virp` alias), sha256
  `8c4005a8628a62ca22ea9dd574357452b0da1df3302ccf00f085b4485028d0aa` —
  installed by `make install-prod` as the fourth artifact class; the
  autopilot shells out to this path. The build-tree copy is no longer a
  production dependency (the "Chain gap 2026-08-09" defect is closed).
- **Chain ingestion gate**: `chain_append` GATE 3 is LIVE as of this deploy.
  An `artifact_type=observation` submitted WITH a body must now carry a
  valid v1/v2/v3 signature or it is refused. Commitment-only (no body)
  appends remain accepted by design — see SECURITY.md.
- **Systemd unit: NOT updated in this deploy.** The installed unit is still
  the pre-`ef6cfa6c` one and still sets `VIRP_WAZUH_INSECURE=1`. That was a
  deliberate choice: the canonical unit drops that variable, no lab CA
  exists yet, and `wazuh-lab` is live. Wazuh collection verified working
  after the restart. Installing the new unit REQUIRES the Wazuh drop-in or
  a CA bundle first.
- **Gate**: `default=ENFORCE max_tier=YELLOW overrides=0` — pure ENFORCE.
  There is **no per-driver SHADOW override for any driver**, `linux` included.
  The FRR/vtysh classifier is **live**: `vtysh -c "show ..."` reads classify as
  GREEN and are allowed on their own tier, not waved through by a shadow mode.
  Journal evidence: `[GATE] mode=ENFORCE device=clab-frr-ospf-frr1 driver=linux
  tier=GREEN threshold=YELLOW decision=allow`.
- **Devices**: 43/43 loaded from `/run/virp/devices.json`
  (rendered at daemon start; sha256 of the rendered file
  `c6e5af7bec4d59f5e62891f1ea33bfa24f70a9df7b52b20ebc3050fcbd07d3f3`) —
  full fleet since the 2026-08-10 import; steady-state connected 38/43
  (pa-850, ASA-5525, srx-300 and two lab devices unreachable, watchdog
  cycling — unchanged from before this deploy).
- **Socket allowlist**: uids 999 (`virp`), 1000 (`nhoward`), 997
  (`virp-backup`), 995 (`virp-evidence`). **uid 0 is deliberately excluded** —
  a client running as root is rejected with
  `peer uid=0 not in socket_allowed_uids`.

### What this corrects
The 2026-07-29 deploy-time header (retained verbatim below) named commit
`0c9c7338` on branch `hardening/review-fixes-2026-07-29`, and the "Devices"
section stated a per-driver `linux=SHADOW` gate override held open "until the
FRR classification table is built". Both statements were true when written and
are now stale on two counts:

1. The shadow override was removed later the same day — see
   "Update 2026-07-29 — FRR/vtysh gate classifier, pure ENFORCE" — and the
   classifier it was waiting on has been live ever since.
2. The deployed commit has advanced through the update log below and is now
   `b6e9602c`, not `0c9c7338`.

## Update 2026-08-11 — deploy from consolidated main `569bff11`

- The repo was consolidated to a single branch: origin is `main` plus
  `archive/*` tags only. All branch content was merged, cherry-picked or
  archived; TODO.md carries the chain-recut re-land ticket as the first
  post-freeze item. Full battery ran twice, both exit 0; the second run
  covered test-api via `~/virp-api-venv` on PATH (system python3 lacks
  fastapi/httpx and the suite silently skips without it).
- New in this build vs `5bda4deb`:
  - `89905208` — driver_linux getaddrinfo `AF_UNSPEC` (IPv4-only connect
    blocked IPv6 device hosts; found live on the netclaw FRR testbed).
  - `e627ae90` — virp-tool installed to `/usr/local/lib/virp/` as the
    fourth artifact class; autopilot now uses the installed client.
    `PEER_CMD_CHAIN_HEAD` deliberately still names the build-tree path
    (exact-matched by the Linux gate on virp-node2) — see the Makefile.
- Installed 2026-08-11 00:58 UTC (`make install-prod` from clean main),
  restarted 01:00:17 UTC immediately after the 01:00 autopilot cycle.
  Nexus (uid 993) had zero polls in the preceding 8 hours, so no poll
  window was at risk.
- Rollback:
  `sudo make rollback-prod ROLLBACK_FROM=/var/backups/virp/20260811T005802Z`
- Verified after restart: 43/43 devices loaded, reconnect to the 38/43
  steady state in ~2 min, comparator pass at 01:02 (16 GREEN allows, no
  refusals), 01:05 battery `cycle complete: 18 observations, 6 alerts`
  (exit 1 = alerts present — identical to the pre-deploy cycle).

## Update 2026-08-10 — cisco config scrub, running-config GREEN, netclaw YELLOW ceiling

Deployed `ae016b0d` (branch `feat/cisco-config-scrub-netclaw-yellow`,
restart 01:09:46 UTC, 43/43 reconnected by 01:11:44, reconnects=0).

- `show running-config` on cisco_ios/iosxe reclassified YELLOW → GREEN.
  Safe only because cisco_execute now scrubs credential material
  (cisco_scrub_config, RANCID-style, fail-closed) out of the body BEFORE
  signing. startup-config/tech-support stay YELLOW but are scrubbed too.
  Suite: `make test-cisco-scrub` (9 tests). Verified live: chained R2
  observation carries `enable secret <removed>` — no hash material.
- uid 993 (virp-netclaw) ceiling raised GREEN → YELLOW in
  `/etc/virp/devices.template.json` (+ stage2 copy; .bak-20260810-netclaw-yellow).
  Re-proven after restart: RED `configure terminal` from uid 993 →
  decision=block, proposal `b32c0db0…` filed + chained (`approval:R1` seq=1),
  rejection persisted. YELLOW ping auto-executes.
- Known gap: `clear counters` (YELLOW) reaches the device but hangs at the
  IOS `[confirm]` prompt — driver returns a typed ERROR and the watchdog
  reconnects. Needs confirm-prompt handling in the cisco driver before it
  is usable.
- Rollback capture: `/var/backups/virp/20260810T010456Z`.

### Same night, second deploy (01:31 UTC): ASA scrub port — `5bda4deb`

- asa_scrub_config ported from the cisco scrub; wired into asa_execute
  the same way (scrub before the signer, fail-closed). ASA tiers
  UNCHANGED: running/startup-config stay YELLOW; the trigger also covers
  `more system:running-config` (RED) in case it is ever approved.
- Suites: test-asa-scrub 9/9, existing test-asa 157/157.
- Verified live against ASA-5525 as uid 993: 315-line config, 7
  redactions (enable password, 2 usernames, 4 tunnel-group
  pre-shared-keys), zero leak-pattern hits; commitment-only
  chain_append `netclaw-verify-asa-2b3bda…` — commitment hash matches
  the signed scrubbed bytes. Full-body append of the 12KB observation
  was correctly REJECTED by the ingestion gate (declared hash vs
  truncated 8192-byte artifact field), so large bodies register
  commitment-only, as the config-backup runbook already does.
- Rollback capture: `/var/backups/virp/20260810T013128Z`.

## Chain gap 2026-08-09 01:35–01:50 UTC — operator-caused, during deploy

**A reader of the chain will find a 15-minute hole here. It is not tamper
evidence and it is not data loss. No observation was minted and then
lost: the collector never ran, so those observations were never created.**

- **Last entry before the gap**: `2026-08-09 01:35:03 UTC`,
  `obs:virp-node2-peer:1786239303036276411`
- **First entry after the gap**: `2026-08-09 01:50:03 UTC`,
  `obs:clab-frr-ospf-frr1:1786240203080023488`
- **Duration**: 15.0 minutes — exactly two missed autopilot cycles
  (01:40 and 01:45; the timer fires every 5 minutes).
- **Chain continuity is intact.** The hash chain is unbroken across the
  gap; only the wall-clock spacing is wider than usual.

**Cause — operator error during the `8a2a6342 → 32dd710f` deploy.** The
first `make install-prod` failed to link: `/opt/virp/build/` still held
ASan/UBSan-instrumented objects from an interrupted `asan-test` on
2026-08-06, so the plain build hit `undefined reference to __asan_*`. The
documented remedy is a single `make clean`, which was run — and it also
deleted `/opt/virp/build/virp-tool`, which
`/usr/local/lib/virp/autopilot/virp_autopilot.py:60` invokes by absolute
path. `make install-prod` builds the `prod` target only, so it did not
rebuild the client. The next two autopilot cycles died at startup with
`FileNotFoundError: '/opt/virp/build/virp-tool'` before collecting
anything. Rebuilding the client at 01:47:11 restored collection on the
01:50 cycle.

**Not caused by the deploy payload.** GATE 3 refused nothing: zero
`chain_append REJECTED` lines across the whole window and since. The
daemon itself was healthy throughout — 7/7 devices connected immediately
after the 01:38:23 restart.

**Note on `autopilot` exit status.** `virp-autopilot.service` exits 1 on
any cycle that raises alerts, including the two `virp-node2-peer`
baseline deviations that predate this deploy. A `status=1/FAILURE` line
in the journal is therefore NOT evidence of a failed collection — check
for a `cycle complete: N observations` line, which is what distinguishes
the 01:40/01:45 crashes from the healthy 01:35 and 01:50 cycles.

**Structural defect this exposed, not yet fixed.** A production service
depends on a build artifact inside the source worktree
(`/opt/virp/build/virp-tool`), so an ordinary `make clean` in the
checkout can take out collection. `virp-tool` should be installed to
`/usr/local/lib/virp/` and the autopilot pointed there, making it a
fourth installed artifact class. Proposed, not implemented.

## Install procedure (written 2026-08-09, before the 8a2a6342 → HEAD deploy)

**Read this whole section before running anything.** It assumes no
knowledge of how the Aug-6 install was done, because that was done by
hand and left no script.

There are **four artifact classes**. A deploy that moves only the first
is incomplete, and the third can change behaviour with no code change at
all:

| class | what | installed by |
|---|---|---|
| 1. daemon binary + helper scripts + autopilot Python | `virp-onode-prod`, `render-devices.sh`, `config-backup-access.sh`, `evidence-access.sh`, `autopilot/*.py` | `make install-prod` |
| 2. **client** | `virp-tool` + its `virp` alias, at `/usr/local/lib/virp/` | `make install-prod` |
| 3. systemd unit | `/etc/systemd/system/virp-onode.service` | `make install-units` |
| 4. optional drop-ins | e.g. the Wazuh lab TLS drop-in | `make install-wazuh-lab-dropin` (never automatic) |

Class 2 was added 2026-08-09. `virp_autopilot.py` shells out to the
client every cycle and previously did so at `/opt/virp/build/virp-tool`,
inside the source worktree, so a `make clean` in the checkout took
collection down — see "Chain gap 2026-08-09" above. It is now installed
and captured like everything else.

**One build-tree reference remains, deliberately.**
`virp_autopilot.py`'s `PEER_CMD_CHAIN_HEAD` still names
`/opt/virp/build/virp-tool` because that command runs on **virp-node2**
and is exact-matched by the Linux gate allowlist
(`src/drivers/driver_linux.c`). Moving it requires node2 updated, the
gate row changed and `tests/test_driver_linux_gate.c` updated in the
same window, or the peer check classifies RED and is blocked. Deferred.

A `systemctl restart` on its own deploys **nothing** — it re-executes the
installed binary. Nothing is deployed until step 4/5 below.

### Before you start — configuration actions this payload requires

These come from two commits that change configuration expectations, not
code behaviour alone. Do them first; both can break a service on restart.

1. **Wazuh TLS (`ef6cfa6c`).** The canonical unit no longer sets
   `VIRP_WAZUH_INSECURE=1`; the driver now validates the manager's
   certificate by default. **The unit installed on virp-lab today still
   sets it, and `wazuh-lab` is a live device in `/run/virp/devices.json`.**
   So installing the new unit and restarting WILL break Wazuh collection
   unless you either:
   - point `VIRP_CA_BUNDLE` at the CA that signed the manager's cert
     (the real fix), or
   - `sudo make install-wazuh-lab-dropin` **before** restarting, which
     restores the insecure setting for this host only and is a
     deliberate, reversible act.
2. **API bind guard (`4062610e`).** `api/server.py` now REFUSES TO START
   on a non-loopback bind with no auth token, where it previously warned.
   The API is not a systemd service on virp-lab and is not running, so
   nothing breaks unattended — but anyone who starts it must now set a
   token, or bind to loopback, or it will exit instead of serving.

### The procedure

1. **Confirm what is live**, so the rollback target is known:
   ```sh
   systemctl is-active virp-onode
   ls -l --time-style=+%F\ %T /usr/local/lib/virp/
   sha256sum /usr/local/lib/virp/virp-onode-prod
   ```

2. **Sync and verify the source.** Install refuses a dirty tree, because
   what is deployed must be exactly what a commit hash names:
   ```sh
   cd /opt/virp && git status --porcelain     # must be empty
   git log --oneline -1                       # record this hash
   ```

3. **Build and test.** Do not install an untested tree:
   ```sh
   make clean && make -j4 && make all-tests
   ```

4. **Capture, then install classes 1.** `install-prod` depends on
   `deploy-capture`, so the snapshot happens automatically and cannot be
   forgotten. It writes `/var/backups/virp/<UTC timestamp>/` with every
   currently-installed artifact plus a `MANIFEST.sha256`, and points
   `/var/backups/virp/latest` at it:
   ```sh
   sudo make install-prod
   ```
   Note the capture path it prints. That is your rollback target.

5. **Install class 2 (the unit)** — separate because it needs
   `daemon-reload` and changes configuration:
   ```sh
   sudo make install-units
   ```
   This reloads systemd but does **not** restart. If this host needs the
   Wazuh drop-in (see above), install it now, before the restart.

6. **Restart, deliberately:**
   ```sh
   sudo systemctl restart virp-onode
   systemctl status virp-onode --no-pager
   ```

7. **Verify** — this payload makes chain ingestion fail-closed, so watch
   the thing most likely to break:
   ```sh
   journalctl -u virp-onode -n 50 --no-pager
   journalctl -u virp-onode -f | grep -i 'chain_append REJECTED'
   ```
   Registrations should continue at the normal cycle rate. A steady
   stream of `chain_append REJECTED ... signature verification` means
   observations are being refused and you should roll back.

8. **Record the deploy** in this file:
   ```sh
   make deploy-record        # emits the commit/sha256 stanza; paste it in
   ```

### Rollback

Rollback is a **copy-back of the captured bytes**, not a rebuild of an
older commit. It does not depend on the old source still building, on
the toolchain, or on anyone identifying which commit produced the
running binary:

```sh
sudo make rollback-prod ROLLBACK_FROM=/var/backups/virp/latest
sudo systemctl restart virp-onode
```

`rollback-prod` verifies the capture against its own `MANIFEST.sha256`
first and refuses a partial or corrupted capture rather than
half-restoring. It restores the binary, helper scripts, autopilot Python
and the unit, reloads systemd, and does not restart on its own.

To undo only the Wazuh drop-in:
```sh
sudo rm /etc/systemd/system/virp-onode.service.d/60-wazuh-lab.conf
sudo systemctl daemon-reload && sudo systemctl restart virp-onode
```

### What restarts do NOT deploy

Checked 2026-08-09 across every virp unit on virp-lab: no unit has an
`ExecStartPre` that builds or installs, and `make check-deploy-unit`
enforces that for `virp-onode.service`. One unit does execute from a
source worktree — **`virp-broker.service` runs
`/opt/virp/broker/virp_broker.py` and `ExecStartPre=+/opt/virp/broker/broker-access.sh`
(as root) directly out of the git checkout.** It does not rebuild, but a
`git pull` in `/opt/virp` followed by a broker restart changes what the
broker runs, with no install step. `broker/` is unchanged in this
payload, so this deploy does not move it — but it is the one path where
updating the checkout is itself a deploy.

## Deploy-time record (2026-07-29, historical)

- **Deployed**: 2026-07-29
- **Commit**: `0c9c73383d22c1909baf8f13b570176cfa9778c3`
- **Branch**: `hardening/review-fixes-2026-07-29` (HEAD; contains all of main @ 6eaacfc, branch not merged at deploy time)
- **Source**: git bundle from build host 10.0.0.211 (CT 210 session), cloned to /opt/virp
- **Deployed by**: nhoward (via Claude Code remediation follow-up session)

## Key material
All keys generated fresh on this host — no key material copied from any other machine.
- O-Key: /etc/virp/keys/onode.key
- Chain key: /etc/virp/keys/chain.key
- Approver keypair: /etc/virp/keys/approval.{key,pub} (Ed25519; secret key never readable by the daemon)
- Approver registry: /etc/virp/approvers.json

## Devices (as of 2026-07-29 — SUPERSEDED, see "Current live state")
> Stale on both counts: the device set has since grown to 7 (wazuh-lab,
> librenms-lab, pbs-lab were added) and the `linux=SHADOW` override was removed
> on 2026-07-29. Retained unedited as the record of what was true that day.

clab-frr-ospf-frr1..frr4 (containerlab FRR OSPF lab, 172.20.20.2–.5), linux driver.
Gate: default ENFORCE, max tier YELLOW; per-driver override linux=SHADOW until the
FRR classification table is built (linux driver has no route_command classifier yet).

## Deployment verification (2026-07-29)
- `make all-tests`: PASS (full suite, exit 0; required installing golang-go for the Go interop tests)
- Daemon: 4/4 devices loaded, SSH host keys verified (pre-seeded known_hosts, no TOFU), watchdog connected 4/4
- Approval mode: enabled, 1 enrolled key (key_id a88c58a65fc41b01de933ba6e803cf7a, ed25519, operator nhoward)
- Actual containerlab IP mapping (differs from naive ordering): frr1=172.20.20.5, frr2=.2, frr3=.4, frr4=.3
- Verification read: `vtysh -c "show ip ospf neighbor"` on clab-frr-ospf-frr1 — signed observation
  sha256 18151a4efd8248bbfd77a35d07ea49172b4d1fc6a73b777e5eb4e44ba9a2cba2, O-Key signature VALID,
  chain-registered as obs:clab-frr-ospf-frr1:1785351334661806485 (session virp-lab-deploy-2026-07-29)
- Gate behavior as expected: linux driver has no classifier → tier UNCLASSIFIED, allowed under the
  linux=SHADOW override ([GATE] decision=would-block logged). Next step: build the FRR classification
  table, then remove the shadow override so ENFORCE applies to the linux driver too.

## Update 2026-07-29 — FRR/vtysh gate classifier, pure ENFORCE
- **Commit**: `b5aab664c75e8adc5b2892bfc1fcdb621d5c0326` (same branch; adds linux driver
  FRR/vtysh classifier + route_reason hook + 45-test suite)
- `make all-tests` on this host: PASS (exit 0, includes new test-linux-gate 45/45)
- devices.json: `gate_modes {"linux": "shadow"}` override REMOVED — daemon now runs
  gate_default_mode=enforce for all drivers, max tier YELLOW

## Update 2026-07-29 — Autopilot monitoring layer
- **Commit**: `fbee0b7efbd261c39eb27aaf3e0aa2f3c08655ea` (same branch)
- `make all-tests` on this host: PASS (exit 0), including Go interop, test-librenms (19),
  test-autopilot (19 python), and 3 new exclusion tests in test_onode

### Devices (6 total)
FRR ring frr1–frr4 (linux) + **wazuh-lab** 10.0.20.10:55000 (wazuh) + **librenms-lab**
10.0.10.12:80 (librenms). Gate: pure ENFORCE, max tier YELLOW, no per-driver overrides.

### Hard exclusions (non-negotiable)
`virp_config_blocked_address()` in virp_onode.c refuses to load ANY config naming the two
blocked VLAN-10 addresses; wired into both loaders (prod + dev). Boundary-aware, so
10.0.10.12 and 10.0.10.100 load normally. Verified live: appending a blocked host to a copy
of the rendered config makes the daemon exit non-zero with
`FATAL: ... contains hard-excluded address ... — refusing to load`.

### Credentials
`/etc/virp/autopilot.env` (0600 root) is the only place device API credentials live. At each
virp-onode start, `ExecStartPre=+/opt/virp/deploy/render-devices.sh` renders
`/etc/virp/devices.template.json` (no secrets, git-tracked) into `/run/virp/devices.json`
(0640 root:virp, tmpfs). The old `/var/lib/virp/devices.json` was retired to
`devices.json.pre-autopilot.bak`. Verified: zero credential strings in the journal.
Wazuh TLS (updated 2026-08-07): the canonical unit no longer ships
`VIRP_WAZUH_INSECURE=1`. The driver validates the Wazuh cert by default;
disabling that for the self-signed lab manager is now a manual opt-in via
the `deploy/virp-onode-wazuh-lab.dropin.conf` drop-in (never in the
default install path; `make check-deploy-unit` fails if the flag returns
to the main unit). For a real Wazuh, set `VIRP_CA_BUNDLE` to its signing
CA and leave validation on.

### Classification (GREEN-only, everything else RED by absence)
- wazuh: `/agents`, `/agents/summary/status`, `/manager/stats/analysisd` — **EXACT** path
  match (closes the recorded `/agents_evil` prefix-creep gap). The pre-existing tables

## Update 2026-07-29 — LibreNMS baseline RESOLVED
- **Commit**: `d3e738f23246859a4c183d9c8f9ee8c3cd60a32f` (same branch)
- `librenms_devices` baseline corrected **5 → 6**. All six devices predate 2026-07-29;
  nothing was added and the loop was right all along.

### Root cause: the 5 was an availability figure, not an inventory figure
Measured through this daemon (all GREEN, all verified):

| query                        | count | devices |
|------------------------------|-------|---------|
| `/api/v0/devices`            | 6     | what the loop uses — unfiltered inventory |
| `/api/v0/devices?type=all`   | 6     | identical to unfiltered |
| `/api/v0/devices?type=up`    | 5     | **where the 5 came from** |
| `/api/v0/devices?type=down`  | 1     | **proxmox01** |

So `?type=all` was NOT the source of the 5 — it returns 6, the same as the unfiltered
query. The single device accounting for the 6-vs-5 gap is **proxmox01**, which LibreNMS
currently reports as **down**. Also worth knowing: `?type=network` and `?type=server` both
return 6 here, i.e. LibreNMS does not filter on those values the way the names suggest —
another reason to copy the battery's query verbatim rather than reason about it.

### Rule now recorded in autopilot/virp_autopilot.py
Every baseline MUST be measured with the exact path AND query string the battery issues. A
baseline taken with a different query form is a number about a different question and shows
up as a permanent false deviation that trains people to ignore the alert. A unit test
(`test_device_baseline_is_measured_by_the_query_the_loop_issues`) pins the device baseline
to the unfiltered query so the two cannot drift apart again.

### Still open, deliberately: LibreNMS availability is not baselined
proxmox01 being down is a real signal that was hiding inside the baseline discrepancy. An
availability baseline was NOT added, because 6-up would alert immediately and 5-up would
bake a current outage into the definition of healthy. That intent is a human decision;
noted in place next to BASELINES.

### Verification (2026-07-29 21:52Z)
Manual and timer-driven cycles both: **12/12 observations GREEN, signature VALID,
chain-registered, 0 alerts**, `ExecMainStatus=0 Result=success`. No failed virp units;
all three timers active and waiting.

## Update 2026-07-29 — second node (virp-node2) + cross-node comparator
- **Commit**: `17d14aeb3876903dfb8799b43d40806a368ccb17` (same branch). virp-node2 runs the
  SAME commit; its record is /opt/virp/DEPLOYED.md on that host.
- `make all-tests`: **PASS, exit 0** here and on virp-node2.

### New on this node
- **Peer device** `virp-node2-peer` (10.0.10.212, linux driver) — the mirror of node2's
  `virp-lab-peer`. Device count here is now 7. Exact-match GREEN peer rows only:
  `systemctl is-active virp-onode`, `virp-tool chain tail -n 1 --db /var/lib/virp/chain.db`,
  `cat /var/lib/virp/autopilot/published.json`. `systemctl stop/restart virp-onode`, other
  `-n` values, other `--db` paths and any other `cat` target stay RED by absence.
- **`virp-peer` probe account**: no sudo, group `virp` (reads chain.db), password auth
  enabled only for that user and only from 10.0.10.212 via
  /etc/ssh/sshd_config.d/60-virp-peer.conf. Needed because the linux driver authenticates
  with a password. PEER_USER/PEER_PASS added to this node's autopilot.env; the passwords
  were generated on their own hosts and piped host-to-host, never rendered.
- **Comparator timer** `virp-autopilot-comparator.timer` (every 10 min at :2) — diffs this
  node's published observations against the peer's for LibreNMS device count, Wazuh
  active/total, and peer liveness. Any disagreement alerts; one-sided missing values count
  as disagreement, because silence between two observers is not consensus.
- Node identity: /etc/virp/autopilot-node.json (4 FRR nodes, peer = virp-node2).
- Battery is now 14 observations (8 FRR + 4 REST + 2 peer).

### Fixes this session (both nodes)
- **Internal probes moved inside the GREEN set.** wazuh_health_check probed
  `/manager/status` and LibreNMS probed `/api/v0/system` — endpoints their own classifiers
  call RED. On virp-node2's tighter credential /manager/status returns HTTP 403, so the
  watchdog health-checked → failed → dropped → reconnected in a loop. Both probes now use
  a GREEN read the battery already performs. Zero health-check failures since restart.
- **render-devices.sh** now substitutes PEER_USER/PEER_PASS and fails loudly on ANY
  unsubstituted placeholder (the peer device was authenticating as the literal
  `${PEER_USER}`, which read like a bad credential rather than a bad render).
- **Baselines scoped to what a node observes**: the FRR adjacency check no longer fires on
  a node with no FRR devices.
- **Unit test de-coupled from deployed state**: the battery-composition test read the
  ambient BATTERY, which on a deployed node includes peer rows — it passed on the build
  host and failed on both real nodes. Now built from explicit configs.

### Cross-node verification is honest-v1, by design
Federation in the repo is an Ed25519 keypair library used by the approval flow; there is no
peer transport, no peer public-key registry, no foreign-chain import, and observations are
HMAC-signed under each node's own O-Key with no `sig_alg` field on the wire. A peer's
signature therefore cannot be verified here. The comparator signs, under THIS node's
O-Key, an observation of what the peer reported, cross-referencing both chain heads. The
claim is *"node A observed and signed that node B reported head X at T"*, never *"node A
verified node B's signature"*.

### Peer outage drill (verified)
With virp-node2's daemon stopped ~75 s: this node's next cycle alerted
`peer_daemon_liveness expected=active observed=inactive`, and the comparator alerted
`peer_daemon_not_active` with `peer_live=False`, `peer_head=-`, and still appended its
signed verdict. After restart: `peer_live=True`, chain head readable, cycle back to 0
alerts. Note that while a peer daemon is stopped, a read-only client cannot recover the
SQLite WAL, so the chain-head probe returns "attempt to write a readonly database" — the
comparator records no peer head rather than inventing one.

### Known limitation
`virp chain tail` prints entry hashes truncated to 16 hex chars, so the peer chain-head
cross-reference stores a 16-char prefix, not the full 64-char hash.

### OPEN (carried on virp-node2): node2 cannot observe Wazuh agents
node2's `virp-ro2` credential is denied in both Wazuh shapes — a real 403 on
/manager/stats/analysisd, and HTTP 200 with an all-zero connection block on
/agents/summary/status (resource-level RBAC filtering). So the two nodes legitimately
disagree about Wazuh and the comparator reports it every run. Grant `virp-ro2` agent read
to make node2 a genuine independent Wazuh observer, or drop Wazuh from its battery.

## Update 2026-07-30 — gate-reason retention + consolidation
- **Commit**: `75b135fe1aa140c77faff6d57f018f5b69feab65`, now on **main** as well as
  `hardening/review-fixes-2026-07-29` (both pushed; the branch fast-forwarded into main and
  every commit named earlier in this file is reachable from main).
- `make all-tests`: **PASS, exit 0** on both colo nodes.

### Gate-reason retention (Part 1)
A `gate_rejection` entry used to store `sha256(reason)` and **no body**, so a report could
prove a block happened and commit to its reason but could not show it — the text lived only
in the daemon journal. The entry now stores a structured body, schema `gate_rejection/1`:
`device, driver, command, classified_tier, gate_max_tier, matched_rule, message,
executed:false`. The commitment is unchanged in kind (`artifact_hash = sha256(body)`, covered
by the entry's chain HMAC); what changed is that the body is now retained, so the reason is
recoverable from the chain alone. `message` is the same text the O-Key-signed ERROR
observation carries, so chain and observation agree by construction. Built with cJSON so
arbitrary command text is escaped; if the body cannot be built or stored the entry still
records the commitment (a rejection is never lost) and says so in the journal.

Verified live on virp-lab: a blocked `vtysh -c "configure terminal"` produced entry
`gate-enforce:clab-frr-ospf-frr1` seq 15 whose stored body recovers
`matched_rule: "configuration change — use propose/approve/apply"` and whose
`sha256(body)` equals the entry commitment exactly.

**Retention sensitivity (asked and answered).** A classification reason is metadata — tiers,
rule names, device and driver names — and carries no credential. The one caller-supplied
field is `command`, and a blocked *write* attempt can legitimately contain a secret the
caller typed. That text is **not newly exposed**: it already went to the journal, is already
the payload of the signed ERROR observation returned to the caller, and was already hashed
into this entry. What changes is **durability and reach** — chain.db is permanent where the
journal rotates, and it is group-readable under /var/lib/virp (0750 virp:virp), so group
`virp` members can read attempted command text. Retained deliberately: an audit record of a
refused command that omits the command is not an audit record. A deployment that cannot
accept that should scrub at the caller, never in the daemon, where scrubbing would break the
observation/chain agreement above.

### Report section 5.1
Now renders the reason from the chain body plus a per-row binding verdict, with the
command on a sub-line. The "not recoverable" caveat is scoped to entries that predate the
change (20 of 21 on virp-lab at time of writing) instead of being asserted for all. Also
added `esc()` — section 5.2 already rendered unescaped command text into reportlab markup,
which a command containing `<` or `&` would corrupt. The report generator and its 32 tests
were untracked on virp-lab; they are now in the repo so both nodes get them and a checkout
cannot clobber the Makefile wiring.

### Socket allowlist policy — DELIBERATE, and aligned
**uid 0 is EXCLUDED.** The allowlist is the daemon's own uid (rendered from `${VIRP_UID}`,
which differs per host) plus **1000**, the interactive operator — exactly what CT 211 has
always run. The autopilot runs as `User=virp`: nologin, no sudo, and no read access to
/etc/virp/autopilot.env, so it holds no device credentials.

A separate least-privilege account (`virp-ops` + a `virp-keyread` group) was implemented,
deployed, and **rejected by the daemon itself**: `virp_key_load_file` refuses a signing key
with group read — `insecure mode 0640 — refusing to load` — and both nodes crash-looped.
That check is right, and it makes the design impossible rather than merely awkward:
verifying an observation requires the O-Key because VIRP signs with **symmetric HMAC**, so a
second account could only verify by weakening key hygiene or by keeping a duplicate signing
key on disk. Running as the key's owner avoids both. **Verifier and signer are not separable
until the daemon exposes a verify action** so no client needs the key at all — that is the
real fix and it is not built.

Operator consequence: `sudo virp exec …` no longer works (uid 0 is refused with
`Error: short read`). Use `sudo -u virp virp …`, or run as the operator uid 1000 — which
cannot read the O-Key, so verification reports `SKIPPED` rather than pretending.

### Other consolidation
- **`virp exec` / `virp apply` now VERIFY** the response signature against the O-Key and
  print `signature=VALID|SKIPPED|INVALID`. A bad signature is a hard failure with "the
  payload above is NOT evidence" — the operator CLI is no longer the weakest verifier in the
  fleet. `--chain-register` registers a *verified* observation the bridge way
  (`artifact_hash = sha256(raw bytes)`, body `base64:…`), and refuses to register anything
  whose base64 body would exceed the daemon's 8192-byte limit rather than write an entry
  that cannot be verified. `--no-verify` and `--okey PATH` are explicit.
- **BLACK invariant test** pins the linux/FRR table to never return BLACK, with a comment at
  the apply site: BLACK is refused before any signature work, so a BLACK row would make its
  commands permanently unapprovable and dead-end the propose/approve/apply path the
  teaching reasons point operators at.
- **`all-tests` now skips loudly** instead of failing when Go or reportlab is absent
  (`test-interop`, `test-virp-report`). Three environments hit the Go case and reported a
  red battery for a missing optional toolchain, which trains people to read failures as
  noise. The skip states exactly what is not covered.

### Two retention gaps reported, NOT fixed (backlog decision pending)
1. **8192-byte `artifact_content` truncation.** `json_extract_string_cjson` uses `snprintf`,
   so an over-long body is silently truncated — the stored body then cannot reproduce the
   commitment. Live: **47 of 682 bodies on virp-lab, 20 of 160 on virp-node2 were exactly
   8191 bytes**, all of them `librenms-lab GET /api/v0/devices` observations, and it recurs
   every 5 minutes. Chain HMAC and entry linkage are unaffected (they cover the hash, not
   the body); the damage is confined to body recoverability. Related: `artifact_type[16]`
   also truncates, which is why the chain shows `comparator_verd` and `chainwalk_summa`.
2. **Commitment to an object the chain does not store.** comparator and chainwalk entries
   commit to `sha256(signed observation)` but store the *verdict/summary JSON* as the body,
   and the signed observation is never retained — so `sha256(body) != artifact_hash` by
   construction. Proven on virp-lab; **13 entries there, 10 on node2**, growing every 10
   minutes. Worse than (1) in one respect: it presents a body a reader may assume is the
   committed object.

## Config-backup-and-drift runbook (2026-07-30, branch runbook/config-backup-2026-07-30)

Hourly governed no-AI automation: virp-config-backup.timer → runs as
`virp-backup` (uid 997), a dedicated identity in no key/credential
group. Socket reach via ACL (virp-onode ExecStartPost drop-in
/etc/systemd/system/virp-onode.service.d/50-config-backup.conf) +
allowlist entry ${VIRP_BACKUP_UID} in the template. The script refuses
to start if it can read onode.key / chain.key / approval.key /
autopilot.env / rendered devices.json, or runs as root/virp.

Per FRR node: GREEN `show running-config` → timestamped backup +
chain-registered signed observation → diff vs baseline. Baselines only
via explicit `set-baseline` (chain entry baseline_set). Drift → diff
artifact + alert + RED revert submission, which the gate
refuses-and-proposes; proposal left for the human (approve/apply or
let expire). Proven live 2026-07-30: clean cycle (chain seq 8–15),
drift cycle on frr2 (seq 18–19, proposal 8756273c…, left to expire,
device untouched), virp-backup cannot approve (-43 not enrolled).
Requires the `acl` package (setfacl) — installed 2026-07-30.
Docs: docs/RUNBOOK-CONFIG-BACKUP.md.

## Compliance-evidence collector (2026-07-30, branch runbook/evidence-collector-2026-07-30)

Daily governed no-AI READ-ONLY automation: virp-evidence.timer → runs as
`virp-evidence` (uid 995), a dedicated identity in no key/credential
group and deliberately SEPARATE from `virp-backup` (each automation owns
its own identity and evidence tree). Socket reach via ACL (virp-onode
ExecStartPost drop-in
/etc/systemd/system/virp-onode.service.d/51-evidence.conf) + allowlist
entry ${VIRP_EVIDENCE_UID} in the template. Same refusal check as
virp-backup: refuses to start if it can read onode.key / chain.key /
approval.key / autopilot.env / rendered devices.json, or runs as
root / virp / virp-backup.

Per FRR node, per item: one GREEN `vtysh -c "show ..."` read → signed
observation chain-registered (obs:<device>:<ns>) + an evidence record
chain-registered (evidence:<device>:<item>:<ns>, schema
evidence_item/1) carrying item, device, ts, the exact command, the
control ref, the honest caveats, collection status, and the path +
sha256 of both data files. Item set (deploy/evidence-items.json) and
control mapping (deploy/controls.json, PLACEHOLDER ids) are DATA in
/etc/virp — editing them never touches code. Unmapped items are
collected, flagged and reported, never dropped.

Read-only structurally: because the item list is operator-editable, the
collector re-derives driver_linux.c's GREEN row locally and refuses to
submit anything that is not exactly `vtysh -c "show <rest>"` with rest
in [a-z0-9 ./-]; validation happens at load, so a bad edit fails the
run rather than being found mid-collection. Non-GREEN returned tiers
alert and are never stored as evidence.

Report: report/virp-evidence-report renders BY CONTROL, reusing
report/verify.py + chain_read.py so every hash/link/signature is
recomputed at render time. Runs as a KEY HOLDER — the deliberate split
from the keyless collector.

Proven live 2026-07-30: full cycle over frr1–4 × 5 items = 20 results,
0 alerts, exit 0; chain session `evidence:2026-07-30` seq 0–39 (20
observations + 20 evidence records); report re-verified all 40 entries
PASS (entry hash, links, chain HMAC, artifact binding) and all 20
observation HMACs PASS, 5 controls, 1 declared evidence gap.

Honest gaps recorded, not papered over:
  - time_sync (AU-8) is UNEVIDENCED: FRR has no NTP subsystem — `show
    ntp status`, `show ntp associations`, `show clock` are all unknown
    commands (verified live on frr1). Needs a host-level collector that
    does not exist yet.
  - access_accounts / management_services cannot see host OS accounts,
    SSH keys, PAM, or listening ports — no GREEN vtysh row reaches them.
  - /var/lib/virp/chain.db is 0644, so virp-evidence could read it
    outside its unit; the unit masks it via InaccessiblePaths, and the
    chain holds no key material. Identical to virp-backup's position.
  - FRR answers unknown commands on stdout and exits 0, so the gate
    signs them. The collector detects the `%` diagnostic and flags
    collection_status=device_rejected_command rather than letting
    "% Unknown command" render as a satisfied control.

Docs: docs/RUNBOOK-EVIDENCE.md.

## Update 2026-07-31 — PBS typed-operation driver + deploy-path fix

First non-network domain through the gate, and the reference implementation of
typed operations (`docs/DRIVER-TYPED-OPS.md`).

- **Commit**: `aafd61064f069027feeb7901b7cdb641c34eb8ed`
  (branch `feature/driver-pbs-typed-2026-07-31`)
- **Tree at install**: clean — `make install-prod` REFUSES a dirty tree, so
  what is deployed is exactly what a commit hash names.
- **Installed binary**: `/usr/local/lib/virp/virp-onode-prod`
  sha256 `ce0bb73a918d14c3d532cdbb101f4efdf69a8ba45ee5c9262b1bb4b1f6af9374`
- Installed scripts (sha256):
  - `render-devices.sh` `dd67a55b96fce325505ec738e3f9ba6adc07064fd13247dded59eca57a1b5f0e`
  - `config-backup-access.sh` `358aa3aa978a0f220636c444336141f65d62f57136653f0e020fd370219fe022`
  - `evidence-access.sh` `bcf299794a84b63b0b14b3e9c98dab2009912b8d2fa180493f33834e28a67219`
  - `autopilot/virp_autopilot.py` `d465d377565d704cff5db466cabbe9047f4a0532ae7b687aab1467d19afa1e34`
  - `autopilot/virp_config_backup.py` `6dfc726d5ee0fa9b2b34a16ba31584be5ba5668d2a6277101aeffa3ef183c7b1`
  - `autopilot/virp_evidence.py` `f6deaf33eb1e020d523c9bc90658ec9fc952e585029da4ebfa8729453572528c`

**Snapshots confirmed by operator: VM 211 `pre-pbs-2026-07-31`, VM 212
(virp-node2) `pre-pbs-2026-07-31`, 2026-07-31.** Taken before the deploy; the
deploy was gated on this attestation because this session has no pve1 access
by design (same exclusion as the autopilot).

### Deployment is now an act, not a side effect of a restart

Every path the units executed used to live inside the live `/opt/virp`
checkout — the binary (`/opt/virp/build/virp-onode-prod`), all three deploy
scripts, and the autopilot Python. Any `make` or file edit in the worktree
armed the next restart, and `Restart=always` meant a crash or reboot shipped
it. It had already drifted: the installed binary was built from `75b135f`
while the worktree was twelve commits ahead at `9444ff0` (benign only by luck
— no `.c`/`.h` file differed).

Everything now runs from `/usr/local/lib/virp`, outside any worktree.
`make check-deploy-unit` fails if any shipped unit executes a path under
`/opt/virp`, `/root`, `/home` or a `build/` directory, if any `Exec*` line
invokes make/gcc/cc, or if `ExecStart` is not the documented install path. It
globs `deploy/*.service` and `deploy/*.dropin.conf` rather than a
hand-maintained list — the list-based first attempt missed six autopilot
units, which is how the wider fix was found.

Verified live after deploy: a full `make` inside `/opt/virp` left the running
daemon untouched (same PID, same start time, same binary sha256).

### PBS device

`pbs-lab` = 10.0.20.199:8007, vendor `pbs`, token `virp-ro@pbs!virp`,
datastore allowlist `colo-backups`. PBS 3.4 (release 8).

TLS identity is PINNED to the leaf certificate's SHA-256 fingerprint
(`0E:5A:25:…:F1:E7`), mandatory: the driver refuses to connect without one and
the daemon refuses to LOAD the device without one. There is no insecure mode —
`make check-pbs-pin` fails the build if the driver disables curl verification,
reads any environment variable, drops the verify callback, or follows
redirects.

**Pinning does not subsume hostname verification.** libcurl performs the name
check separately from the certificate-verify callback, so a *correct* pin
failed live with `CURLcode=60 … no alternative certificate subject name
matches target host name '10.0.20.199'` — the PBS self-signed certificate
covers `localhost`, `pbs`, `pbs.thirdlevelit.local`, not the management IP.
The fix is `tls_servername` + `CURLOPT_RESOLVE`, so hostname verification
stays ON and genuinely passes, NOT a lowered `VERIFYHOST`. Certificate
rotation on the PBS side is therefore a config change here.

PBS-side ACL required BOTH grants, because token privilege separation makes
effective rights the intersection of user and token ACLs:

    proxmox-backup-manager acl update /datastore/colo-backups DatastoreAudit --auth-id 'virp-ro@pbs!virp'
    proxmox-backup-manager acl update /datastore/colo-backups DatastoreAudit --auth-id 'virp-ro@pbs'

### Live verification (2026-07-31)

- `make clean && make all-tests`: **exit 0 on virp-lab AND virp-node2**.
  New suites: `test-pbs` 88/88, `test-pbs-gate` 74/74. Both clean under
  ASan+UBSan (`make asan-drivers`).
- Devices: **7/7 loaded** (was 6/6); all six pre-existing connects unchanged;
  `[Watchdog] Connected: pbs-lab` added. 12 drivers registered.
- Autopilot cycle: the four PBS reads all `[OK] tier=GREEN verified=VALID`.
  Alert profile per cycle is UNCHANGED from before the deploy (5 alerts, all
  pre-existing: the peer device is absent from `devices.json`, and
  `wazuh_active` is 4 vs a baseline of 5). No new alert kinds; zero PBS alerts.
- Adversarial corpus: **33 cases, 0 mismatches**, including one row per PBS
  refusal class replayed against the LIVE gate.
- Hard exclusions still FATAL: a config naming `10.0.10.1` makes the daemon
  exit 1 with `contains hard-excluded address … refusing to load`; the real
  config still loads 7/7.
- Token grep sweep: **0 hits** in the journal, `chain.db`, `/usr/local/lib/virp`,
  `/opt/virp`, `/root/virp-dev`, `/etc/virp/devices.template.json`,
  `/var/lib/virp`, `/home/nhoward`, `/tmp`. The only copy is
  `/run/virp/devices.json` (0640 root:virp, tmpfs) — by design, the render target.

### Chain-registered proofs

Session `virp-cli:pbs-lab`, all `signature=VALID`:

| seq | artifact_id | artifact sha256 (head) | what |
|---|---|---|---|
| 3 | `obs:pbs-lab:1785539354086878860` | `91934e649ea109b1` | GREEN `backup.version.read` → HTTP 200 |
| 4 | `obs:pbs-lab:1785539354289969384` | `3242b06585040d26` | GREEN `backup.verify.tasks` → HTTP 200 |
| 5 | `obs:pbs-lab:1785539354323436161` | `d2569bee5ca72db2` | **RED** `backup.verify.run` → `obs_type=0x0f`, gate blocked, nothing executed |

The RED proof's payload carries the teaching reason in full ("unknown operation
id — the PBS operation table is closed and RED by absence; no write operation
exists at any tier in v1…") and files a proposal, so the refusal stays
approvable through propose/approve/apply.

### OPEN: two of the four reads cannot be chain-registered

`backup.datastore.usage` (27,841 bytes) and `backup.snapshots.list` exceed the
daemon's **8192-byte artifact limit**. The client REFUSES to register them
rather than store a truncated, unverifiable artifact, and says so loudly:

    chain-register: observation is 27841 bytes; its base64 body (37131)
    exceeds the daemon's 8192-byte artifact limit and would be stored
    truncated (unverifiable). Not registered.

That refusal is correct — but it means two of the four v1 PBS operations
produce signed, verified GREEN observations that are NOT in the chain. In the
autopilot cycle they show `chain=-` and do NOT alert, which is quiet. The
evidence collector's pattern (store the artifact out of band, chain-register
its path + sha256) is the likely answer. Not designed yet.

### Superseded chain entries (recorded, not rewritten)

`virp-cli:pbs-lab` seq 0 and seq 1 share `artifact_id obs:pbs-lab:1785538992`.
`virp-tool` built CLI artifact ids from `time(NULL)` — SECONDS — while
`artifacts` has `UNIQUE(artifact_id)`, so two observations for one device
inside the same second collided and only one content row survived. seq 0
records `artifact_hash 5f109f05…` while the stored content under that id is
seq 1's observation (`1b5550cb…`): an entry that can never be verified against
its own artifact. Found by running four PBS reads ~200 ms apart.

Fixed in `74f0550` (nanosecond ids, matching what `virp_autopilot.py` always
did). The two bad entries are LEFT IN PLACE — the chain is append-only and
rewriting it to hide a defect would be worse than the defect. Proofs above are
the post-fix entries (seq 3–5).

## Disclosure decision — 2026-08-01

`github.com/nhowardtli/virp` is a **PUBLIC** repository, and
`feature/driver-pbs-typed-2026-07-31` was pushed to it on 2026-08-01
(remote `efb7eb5`).

That push published this file and `docs/RUNBOOK-{EVIDENCE,CONFIG-BACKUP}.md`
for the first time — none of them were tracked on `main` (`75b135f`). The
pre-push sweep checked "is this already published?" against `9444ff0`, the
branch's LOCAL base, which had never been on the remote; the correct
reference was `main`. The conclusion drawn from it ("consistent with existing
repo conventions") was therefore wrong, and the wider disclosure was not
identified until after the push.

**Operator reviewed and ACCEPTED the disclosure on 2026-08-01.** Recorded so
it is a decision rather than an oversight, and so nobody re-opens it.

What is public as a result:
  - 9 RFC1918 addresses, incl. 10.0.10.1 (edge firewall) and 10.0.20.10
    (Wazuh manager), both of which are also the daemon's hard exclusions
  - the internal FQDN `pbs.thirdlevelit.local`
  - service account names: `virp-ro`, `virp-ro2`, `virp-backup`,
    `virp-evidence`, `virp-ro@pbs!virp`
  - approver key_id `a88c58a6…`, chain artifact ids, installed-binary sha256s
  - the security-posture narrative: which drivers carry no classifier, that
    `VIRP_WAZUH_INSECURE=1` is live on the deployed unit, and the open items
    <br>*(2026-08-07: this records the 2026-08-01 disclosure state. Since
    then the canonical unit no longer ships `VIRP_WAZUH_INSECURE` and the
    Wazuh driver does carry a classifier — see the dated corrections in
    SECURITY.md. The RUNNING deployed unit still carries the flag until a
    redeploy, which is a separate act.)*

What is NOT public: no passwords, API tokens, or private key material. The
one credential in the tree — the FRR lab container password in
`deploy/devices.template.json` — was already on `main` before this branch.

**For future pushes:** compare against the REMOTE ref (`origin/main`), never
a local base commit. A local base can be arbitrarily far ahead of what was
ever published, which is exactly what happened here.

## Update 2026-08-01 — canonicalization hardening (FIX 1–4)

Four divergences between the object that gets classified/hashed/recorded and
the object submitted/transmitted, from a fresh-context external review of the
typed-op branch.

- **Commit**: `cc2133512dffe31ec5124297852fe510f7708bd9`
  (branch `feature/pbs-canon-hardening-2026-08-01`)
- **Tree at install**: clean
- **Installed binary**: `/usr/local/lib/virp/virp-onode-prod`
  sha256 `db5ae063ec01810266eb1b84a9f752f55ff367fd6a3bf18cb786e791f2f4ba90`
  (previous: `ce0bb73a…`)
- **Deployed**: 2026-08-01 03:04:39 UTC

### PROTOCOL-VISIBLE: typed-profile command hashes changed value

FIX 1 replaces the canonicalizing command hash with an exact-octet one for
any driver declaring a `typed_profile` (`"pbs/1"`). Every PBS command hash
therefore has a different value after this deploy. Noted for draft-07
(-06 was filed 2026-08-01 without typed profiles; its §17.7 scopes
them as future work).

Checked before deploying: **no signed approval existed for `pbs-lab`**, so
nothing in force was invalidated. 120 gate-rejection *proposals* do exist for
PBS commands, carrying old-derivation hashes; those are now UNAPPROVABLE —
`virp_approval_verify_consume` recomputes under the new derivation and
returns `VIRP_ERR_APPROVAL_HASH_MISMATCH`. That is fail-closed and correct: a
stale proposal cannot be approved into an execution. Deploying this while no
approvable non-GREEN PBS row exists is precisely why it was safe now and
would not have been later.

### Verification (2026-08-01)

- `make clean && make all-tests`: **exit 0 on virp-lab AND virp-node2** at
  `cc21335`. New suites `test-typed-hash` 19/19, `test-ingress-nul` 17/17;
  `test-pbs` 88 to 107. All clean under ASan+UBSan.
- Connect counts **unchanged**: 12 drivers, 7/7 devices, 7 driver connects,
  7 watchdog connects — identical to the pre-deploy baseline.
- Autopilot cycle: 18 observations, 5 alerts — the same five pre-existing
  ones (peer device absent from devices.json; `wazuh_active` 4 vs baseline 5).
  No new alert kinds.
- Adversarial corpus: **33 cases, 0 mismatches**.
- FIX 2 proven live over the raw socket, not just in unit tests: a clean
  request returns an observation (223 B) while an encoded-NUL smuggle, a
  MALFORMED three-digit unicode escape, and a batch-item smuggle each return
  the 4-byte framed error. Clean batch control returns an observation (231 B).
- FIX 3 proven live: `store=.` and `store=..` classify RED, gate-blocked,
  nothing executed, teaching reason intact.
- FIX 4 proven live: all four v1 ops still classify GREEN via their declared
  `.tier`, signatures VALID.

### Rollback (code-only change — no snapshot needed)

    cd /opt/virp && sudo git checkout -B feature/driver-pbs-typed-2026-07-31 8e554d7 \
      && sudo make install-prod && sudo systemctl restart virp-onode

The 2026-07-31 pve1 snapshots (`pre-pbs-2026-07-31`, VM 211 and VM 212) still
exist, but rolling back to them would also undo the PBS deploy. For this
change the git-based reinstall above is the correct, narrower rollback.

### Still open after this deploy

- No on-wire test asserts the exact request line, so `CURLOPT_PATH_AS_IS` is
  proven only by the setopt return check and by dot segments being refused
  three layers earlier. A local HTTP listener test is the only thing that
  would close it. TODO at the site.
- The typed-op interface is still `(const char *)`; FIX 2 closes the live
  divergence at the ingress boundary but does not make the interface
  length-aware. TODO at the site.
- Registry version-binding, classify-before-connect + disposition split, and
  table-only transport for the connect/health probes remain undesigned, each
  with a TODO at its site.

## Key hygiene — the ct211 credential, 2026-08-01

Recorded here because the artifacts live outside this repo (`~/.ssh` and the
containerlab lab directories), so the repo is the only durable record.

### What was found

Two distinct ed25519 keys both labelled `claude-code@ct211`, from the retired
CT 211 build host:

| fingerprint | private half | where it was trusted |
|---|---|---|
| `SHA256:rA3gTRbK…` | **UNLOCATED** | `nhoward@` on virp-lab AND node2 |
| `SHA256:jVrtKaNz…` | `~/.ssh/virp-lab` on virp-lab | nowhere (inert) |

The dangerous one is `rA3gTRbK…`: it granted `nhoward` on both hosts and its
private half has never been located. On virp-lab it sat in `authorized_keys`
with NO comment, which is why it read as "an unknown key" until node2's copy —
which carries the `claude-code@ct211` comment — identified it.

node2's `authorized_keys` also held four unparseable lines: three bare base64
key bodies with no `ssh-ed25519` type prefix, and one 32-hex string
`<REDACTED-32-HEX>`. All inert to sshd, evidence of a botched
append.

### What was removed

- virp-lab `~/.ssh/authorized_keys` — `rA3gTRbK…` removed (operator).
- node2 `~/.ssh/authorized_keys` — `rA3gTRbK…` plus the four malformed lines
  removed (operator, 01:48). 7 raw lines to 2. Backup
  `authorized_keys.bak-2026-08-01`.
- virp-lab containerlab files — BOTH ct211 entries removed:
  `frr-ospf-lab/clab-frr-ospf/authorized_keys` and
  `frr-spine-leaf-lab/clab-frr-clos/authorized_keys`, each 3 keys to 1
  (the laptop key). Backups `.bak-2026-08-01`, 0600.

Verified by fingerprint AND by raw grep at every step — a malformed copy of a
key body does not parse under `ssh-keygen -lf` but still sits in the file, so
fingerprint-only checking would have missed exactly the lines that were there.
Access proven on both hops after each change; FRR devices reconnect 4/4
(they authenticate by password, not key).

### Where the containerlab files come from — the removal is only half durable

The clab `authorized_keys` files are NOT declared in either topology (the only
`binds` are `daemons` and `frr.conf`). **containerlab 0.77.0 generates them**,
harvesting the invoking user's SSH material. The old contents map exactly onto
the sources at generation time:

    jVrtKaNz…  <- ~/.ssh/virp-lab.pub          (a .pub file in ~/.ssh)
    85OdOtNl…  <- ~/.ssh/authorized_keys        (laptop)
    rA3gTRbK…  <- ~/.ssh/authorized_keys        (as it was then)

Corroborated by timeline (lab file written 2026-07-29 18:17:52, four minutes
after virp-lab.pub appeared at 18:13:08; claude-code-virp-lab.pub did not
exist until 07-31 21:04 and is correctly absent) and by the absence of any
ssh-agent (`SSH_AUTH_SOCK` unset).

Consequence, split:

- **`rA3gTRbK…` will NOT return.** Its only source was `~/.ssh/authorized_keys`,
  now cleaned. A `clab deploy` regenerates without it.
- **`jVrtKaNz…` WILL return on the next `clab deploy`**, because
  `~/.ssh/virp-lab.pub` still exists and clab re-harvests it.

Deleting the clab file is therefore treating the symptom. The durable fix is
to remove the seed — `~/.ssh/virp-lab{,.pub}`, an orphaned keypair trusted
nowhere — which has NOT been done pending an operator decision.

### OPEN — do not treat as resolved

1. **`rA3gTRbK…`'s private half is still unlocated.** It is now trusted
   nowhere reachable on this pair, but nobody has established where it lives
   or whether anything outside these two hosts trusts it. "Removed from the
   hosts we can see" is not "revoked".
2. **IDENTIFIED, AND IT IS A LIVE CREDENTIAL.** The 32-hex string in node2's
   `authorized_keys` was assumed to be an approver `key_id` because it has
   that shape. It is not. It is the **LibreNMS API token** — the exact value
   of `LIBRENMS_TOKEN` in `/etc/virp/autopilot.env`.

   It is deliberately NOT reproduced in this file. It was caught by the
   pre-push secret sweep while this very section was being committed toward a
   PUBLIC repository; the commit was discarded and the object store gc'd
   before any push. That is the second time the "compare against the remote,
   sweep for secret VALUES" gate has earned itself.

   Exposure: it sat in `node2:~/.ssh/authorized_keys` (0600 nhoward:nhoward)
   from an unknown date until 01:48 on 2026-08-01, and now sits in
   `node2:~/.ssh/authorized_keys.bak-2026-08-01` with the same mode. Readable
   by `nhoward` and by root on node2. It never reached this repo.

   **The token should be rotated in LibreNMS and `autopilot.env` updated**, on
   the standard principle that a credential found outside its store is
   compromised regardless of who is believed to have read it. Until then the
   backup file is a plaintext copy of a live credential in a world where the
   store is supposed to be `autopilot.env` alone.
3. **`~/.ssh/virp-lab.pub` re-seeds `jVrtKaNz…` into clab files** on every lab
   deploy.

## Update 2026-08-01 — oversized-response fail-closed fix deployed

Closes an attestation-integrity bug: oversized HTTP responses were silently
truncated and then signed as if verbatim.

- **Commit**: `ebe6678d02eaa879df72961ccbe863083a4bfd01`
  (branch `fix/pbs-truncation-failclosed-2026-08-01`)
- **Tree at install**: clean
- **Installed binary**: `/usr/local/lib/virp/virp-onode-prod`
  sha256 `fb728199bf1587890856e98e3390a73fbaf1b43255a17821c3459de082c27b56`
  (previous `db5ae063…`)
- **Deployed**: 2026-08-01 04:45:32 UTC, PID 421334 (was 403188)
- **DEPLOYED BUT UNMERGED** — the branch sits on top of
  `feature/pbs-canon-hardening-2026-08-01`; no merge to main has happened.

### What was wrong

`pbs_write_cb` copied only what fit its fixed buffer and returned the FULL
incoming byte count to libcurl, so libcurl believed the whole body had been
consumed and the driver received no overflow signal. `pbs_execute` then set
`output_len` from snprintf's would-have-written value, unclamped, and could
mark the operation successful on HTTP status alone. The daemon's length clamp
prevented an out-of-bounds read but signed the truncated observation anyway,
with no truncation marker. A valid signature over incomplete evidence.

Now fails closed at BOTH truncation points (capture buffer and observation
formatter), returning a signed typed ERROR carrying "response exceeded
evidence limit" instead of a truncated success. `output_len` is the bytes
actually stored, and on the failure path the payload buffer is wiped and
`output_len` set to 0 — which is what makes the daemon emit a signed ERROR
rather than signing partial bytes as DEVICE_OUTPUT.

### Verified live post-deploy

- Connect/health probe against the real PBS: **clean**. `/api2/json/version`
  is 92 bytes against the 1024-byte probe buffer (~11x headroom), so the
  probe's new fail-closed behaviour does not affect normal connect.
- Connect counts **unchanged**: 12 drivers, 7/7 devices, 7 driver + 7
  watchdog connects.
- Three real GREEN ops end-to-end, all `signature=VALID`, `tier=GREEN`,
  `gate_decision=allowed`, HTTP 200:
  `backup.version.read`, `backup.datastore.usage` (27,841 B — the largest
  real response, exercising the capture path well inside limits),
  `backup.snapshots.list store=colo-backups` (19,622 B).
- Chain linkage verified: every `virp-cli:pbs-lab` entry's
  `previous_entry_hash` equals its predecessor's `chain_entry_hash`.
- The separate 8192-byte artifact limit behaves EXACTLY as before —
  `backup.datastore.usage` (27,841 B) and `backup.snapshots.list` (19,622 B)
  still sign and still report `chain=-`, refused by the artifact limit with
  the same message, NOT by the new evidence-limit path. This fix did not
  touch that path.
- Zero "evidence buffer" refusals in the journal: nothing overflowed, which
  is expected — no real response comes close to the limits.
- Autopilot cycle: 18 observations, 5 alerts (the same five pre-existing).
  Adversarial corpus: 33 cases, 0 mismatches.

### NOT proven live — pending a TLS listener fixture

The oversized path itself was **not** exercised against a real server.
Forcing a >65 KB response requires a TLS listener presenting the pinned PBS
certificate, whose private key lives on the PBS host. The largest real
response available is 27,841 bytes, comfortably inside both buffers. The
oversized path is covered by 26 unit tests (both buffer boundaries at
just-below / exactly-at / just-above, plus the execute-level contract), and
deployment was accepted on that evidence.

**One fixture closes two gaps.** The same TLS listener would also close the
`CURLOPT_PATH_AS_IS` on-wire test, which today is proven only by the checked
setopt return and by dot segments being refused three layers earlier. Build
the listener once:

  - oversized-response live proof (this fix)
  - PATH_AS_IS exact-request-line assertion (FIX 3, 2026-07-31)

### Rollback

    cd /opt/virp && sudo git checkout -B feature/pbs-canon-hardening-2026-08-01 cc21335 \
      && sudo make install-prod && sudo systemctl restart virp-onode

Restores binary sha256 `db5ae063ec01810266eb1b84a9f752f55ff367fd6a3bf18cb786e791f2f4ba90`.

### Behaviour change worth knowing

The connect and health probes use 1 KB buffers and now fail closed too. At 92
bytes the current `/api2/json/version` response has ~11x headroom, but if it
ever grew past 1 KB, connect would refuse rather than silently truncate.
Correct, and better than the alternative, but it is a new way for connect to
fail.

## Deploy 2026-08-09 04:11 UTC — per-uid GREEN ceiling for netclaw (commit 5841ec71)

Resolves Finding A. Built + installed via `make install-prod` (binary
sha256 3a440881…, new code; check-deploy-unit PASS, tree clean at
5841ec71), ceiling template staged to /etc/virp, restarted 04:11:58→59
UTC (onode then broker). Startup logged:
`per-uid tier ceilings: 993=GREEN (node-wide ceiling = YELLOW)`.

Verified live from netclaw through the tunnel (SO_PEERCRED uid 993 on
.211) AND via the full Nexus spawn path (sudo -u nexus → sudo -u
virp-bridge → MCP exec_device_command):
- GREEN `show ip ospf neighbor` → threshold=GREEN decision=allow → executed.
- YELLOW `clear ip ospf neighbor` → threshold=GREEN decision=block →
  proposal filed (proposal-only; unappliable, netclaw holds no approver key).
- RED `configure terminal` → threshold=GREEN decision=block.
- Local operator uid 1000: same YELLOW → threshold=YELLOW decision=allow.
  The ceiling tightens uid 993 ONLY; the node-wide YELLOW is unchanged.

Two-domain isolation re-confirmed: nexus observations landed on THIS
node's chain (sessions ncfed-nexus-*), netclaw's local chain unchanged.
frr1 OSPF re-formed to 2 Full after the operational clears.

### Finding A — RESOLVED
Mechanism: socket_uid_tier_ceilings config → onode_effective_max_tier()
= min(gate_max_tier, per-uid), consulted in onode_execute_obs_ex on the
single AND batch paths; connecting uid is SO_PEERCRED, threaded
explicitly (not thread-local, because batch fans out child threads).
Test: test_per_uid_ceiling_caps_yellow_but_not_uncapped (test-onode
101/101; approval 23/0; drivers 26/26).

### Nexus path now live (netclaw side, no .211 change)
- /etc/sudoers.d/nexus-virp-bridge: nexus may run ONLY the exact
  `env VIRP_ONODE_SOCKET=/run/virp-remote/onode.sock python3 -u
  /usr/local/lib/virp/virp-bridge-mcp.py` as virp-bridge. Deny checks
  pass: arbitrary cmd + different-socket both refused.
- virp-bridge-remote registered in /home/nexus/.openclaw/openclaw.json
  (mcp.servers) — nexus-live only; deliberately NOT in the repo config
  or catalog (reconcile-mcp.py PASS). Nexus isolation 8-check clean: the
  grant adds ONLY the spawn capability; config/key/socket all still denied.

### Finding B — still OPEN (not deployed; separate from this work)
Bridge `intent`/`outcome` chain appends still rejected by GATE 1
(-4 INVALID_TYPE); only `observation` lands. Attribution is therefore
observation-only. Fix would reconcile the bridge's artifact types with
the daemon's external-allowed set — a bridge/daemon contract change,
deferred pending a decision.

## Deploy 2026-08-09 03:14 UTC — netclaw remote requester allowlist (commit 886c41a2)

Config-only restart of virp-onode (binary sha256 unchanged `07b8eec4…`,
same as the 32dd710f deploy — the commit touches only deploy/ + Makefile).
Restarted 03:14:09→03:14:12 UTC, virp-broker immediately after. Added uids
993 (`virp-netclaw`, remote requester) and 994 (`virp-broker`) to
socket_allowed_uids; installed deploy/netclaw-access.sh + 52-netclaw.conf.

- **No chain gap.** The autopilot 03:10 cycle completed pre-restart; the
  03:15 cycle ran post-restart and minted entries (seq 2–36). No cycle was
  missed, so — unlike the 2026-08-01 01:35–01:50 gap — there is nothing to
  record as un-minted. chain.db persisted (not truncated); per-process seq
  reset to low numbers at restart is expected and does not break the
  hash-linked chain.
- **Pre-existing, NOT caused by this deploy:** virp-autopilot.service has
  been exiting non-zero since ~00:00 UTC because the battery raises alerts
  (device `virp-node2-peer` not found + baseline deviations) and returns
  the alert count as its exit status. Observations are still minted and
  chained each cycle; only the unit's exit result is "failed". Flagged for
  separate follow-up; it is orthogonal to the allowlist change.

### Finding A — remote client tier ceiling is YELLOW-executes, not GREEN-only
The gate ceiling is the GLOBAL `gate_max_tier=yellow`; there is no per-uid
ceiling (confirmed in src: gate_tier_blocks compares against the one
state->gate_max_tier). Verified end-to-end from netclaw through the tunnel
(all as uid 993 via SO_PEERCRED):
- GREEN `show ip ospf neighbor` → decision=allow → EXECUTED_CONFIRMED.
- RED `configure terminal` / `ping …` → decision=block → proposal filed +
  rejection persisted (proposal-only; approvable, but netclaw holds no
  approver key so it can never apply). Correct.
- YELLOW `clear ip ospf neighbor` → **decision=allow → EXECUTED_CONFIRMED.**
  YELLOW is NOT proposal-only: with max_tier=yellow it auto-executes for
  every allowlisted uid, netclaw included. (frr1 OSPF adjacencies cleared
  and re-formed to 2 Full within the test window.)
This contradicts the "YELLOW is proposal-only for the remote client"
expectation. A true GREEN-only (or YELLOW-proposal-only) ceiling for uid
993 needs per-uid tier support in the daemon — a code change, deferred
pending a decision. RED is the tier that is currently proposal-only.

### Finding B — bridge provenance/outcome chain entries rejected (pre-existing)
The federation bridge's attribution entries do NOT land: `intent` →
"unknown artifact_type" and `outcome` → "daemon-generated … may not be
submitted" (both err=-4 INVALID_TYPE), from GATE 1 (adversarial audit
2026-08-06). Only the `observation` entry lands (verified on this chain,
session ncfed-netclaw-*). This is a bridge/daemon contract mismatch
independent of transport and of this deploy — the same -4 occurs for a
local diag append (session=diag:phase4) — so the bridge's
federated_request/federated_outcome wrapper is degraded to
observation-only on this daemon build regardless of how it is reached.

### sshd transport deviation from the Phase 1 design (recorded intentionally)
Phase 1 specified `AllowTcpForwarding no` + `PermitOpen none` for
virp-netclaw. On this OpenSSH (9.6p1) BOTH also block the streamlocal
(Unix-socket) forward the account exists for: sshd checks direct-streamlocal
opens against the same local-perms list and logs "connect to path … request
was denied" without ever calling connect(). The Match block therefore now
sets `AllowTcpForwarding yes`, and TCP-forward denial is enforced one layer
down by an nft rule (uid 993 may not originate IP connections; established
inbound ssh exempt via ct state). Re-proven after
the change: streamlocal to onode.sock works; TCP forward → "Connection
refused" (nft counter incremented); shell/PTY → "account not available".
The authorized_keys entry keeps `restrict,port-forwarding,from="10.0.30.30"`.

**Correction 2026-08-09 — what was actually enforcing this, and since when.**
The sentence above credited `virp-netclaw-egress.service` with enforcing the
denial. The RULE was in force; the SERVICE was not what put it there. Found
during the installed-vs-tracked unit audit:

- the unit was `enabled` but `ActiveState=inactive`, with **no journal
  entries at any point** — systemd had never executed it;
- the nft table was nonetheless loaded in the kernel, with a live counter;
- unit and ruleset were both dated 2026-08-09 03:26 against 11 days of
  uptime, i.e. applied by hand with `nft -f` after the last boot;
- neither file was tracked in the repo, so a rebuild would have restored
  the sshd `AllowTcpForwarding yes` half of this arrangement and not the
  compensating half.

The control was real and simultaneously unowned. The claim was true of the
kernel and false of the mechanism, which is the same shape as the
`VIRP_WAZUH_INSECURE` drift found in the same audit: an assertion about a
file that was not in charge.

Resolved the same day. Both files are now tracked (`deploy/virp-netclaw-egress.service`,
`deploy/nftables-virp-netclaw-egress.nft`) and covered by
`deploy/unit-manifest.txt`, so `make check-deploy-unit` diffs them against
the host. The unit was then EXERCISED rather than assumed: the hand-applied
table was deleted, `systemctl start virp-netclaw-egress` was run, and the
resulting kernel ruleset compared against the saved original —
`Result=success`, and byte-identical apart from the counter reset
(`packets 1 bytes 60` → `packets 0 bytes 0`). That start is the first entry
this unit has ever written to the journal. systemd now genuinely owns the
rule, and the reboot path has been executed once instead of trusted.

Known limitation, unresolved: `deploy/nftables-virp-netclaw-egress.nft`
hardcodes uid 993. Everything else about this account is resolved by name at
render time (`${VIRP_NETCLAW_UID}` via `deploy/render-devices.sh`), so on a
node where `virp-netclaw` lands on a different uid this ruleset silently
protects the wrong account — it would load without error and deny nothing.

## Incident 2026-08-01 — daemon down 05:19–07:09 UTC (malformed autopilot.env)

**Duration:** 1h 50m. **Successful starts in the window: 0** — this was a
full outage, not flapping. 1265 restart attempts.

**Cause.** During the LibreNMS token rotation, line 5 of
`/etc/virp/autopilot.env` ended up holding TWO 32-character tokens
separated by a space:

    LIBRENMS_TOKEN=<tokenA> <tokenB>

`sh` parses `VAR=value word` as "run `word` with `VAR=value` in its
environment", so `LIBRENMS_TOKEN` was set only for that one (failed)
command and was EMPTY afterwards. Every start logged

    /etc/virp/autopilot.env: line 5: <tokenB>: command not found
    [render-devices] FATAL: LIBRENMS_TOKEN not set in autopilot.env

and `render-devices.sh` refused to render, so `ExecStartPre` failed and
the daemon never started. `Restart=always` retried every 5s for 110
minutes.

**The fail-closed design worked exactly as intended.** The render refused
to produce a devices.json rather than emit one with an empty credential,
and the daemon refused to run without it. The alternative — starting with
a blank LibreNMS token — would have meant a running daemon quietly
failing every LibreNMS read, which is far worse than a loud stop. This
incident is evidence FOR the loud-failure choice recorded on 2026-07-31,
not against it.

**What it cost anyway:** 110 minutes with no observations collected from
any of the 7 devices, and no chain entries written in that window. Any
audit of 05:19–07:09 will show a gap; the gap is explained here.

**Recovery.** Repairing line 5 to a single `LIBRENMS_TOKEN=<value>` was
sufficient; the next scheduled restart (07:09:46) rendered cleanly and
came up 7/7 devices, 7 driver + 7 watchdog connects, all four PBS ops
reachable. No code change, no redeploy.

**Detection gap — the honest part.** Nothing alerted. The autopilot could
not alert because the autopilot runs against the daemon that was down.
The outage was found incidentally, ~110 minutes in, because an unrelated
command sourced autopilot.env and printed the shell error. Nothing in the
system watches "is virp-onode actually up", and the one component that
would notice is the one that dies with it.

FOLLOW-UP (queued, not done): an external liveness check that does not
depend on the daemon — a systemd `OnFailure=` unit on virp-onode, or a
node2-side probe of the peer, either of which would have caught this in
minutes rather than hours.

**Second-order finding.** The token rotation that triggered this was also
incomplete: new tokens were created but the compromised one
(`b6bfb7a2…`, the value found in node2's `authorized_keys`) was left
live for a further ~2 hours and only revoked at the end of the session,
confirmed HTTP 401. At one point four tokens were valid simultaneously.
A rotation is not complete until the old credential is verified dead.

## Update 2026-08-07 — API server refuses unsafe network binds at startup

`api/server.py` now enforces a bind-safety guard at startup (and again in
`__main__`): binding to a non-loopback address (0.0.0.0 or any routable
IP) with no `VIRP_API_TOKEN` set is REFUSED — that configuration would
serve every mutating route unauthenticated to the network. The three
cases:

- loopback (127.0.0.1 / ::1) + no token → allowed, logs a `DEV MODE` line;
- non-loopback + no token → **refuses to start** (`UnsafeBindError`),
  naming the fix (set `VIRP_API_TOKEN`, or bind loopback behind an
  authenticated gateway);
- token set (any bind) → allowed.

Only a literal loopback IP counts as loopback; a hostname such as
`localhost`, `0.0.0.0`, `::`, or any routable address is treated as
non-loopback (fail closed). The guard runs at module import too, so
`uvicorn server:app --host 0.0.0.0` cannot bypass it via a runner that
never executes `__main__`; the runner's `--host` / `-b`/`--bind` argv is
also parsed.

**KNOWN GAP (do not assume coverage we do not have).** The guard sees
`VIRP_BIND_HOST` and common `--host`/`--bind` command-line forms. A bind
declared ONLY in a server config file/module (e.g. a gunicorn config
module) or a server-specific environment variable is NOT detected — an
operator using those must set `VIRP_API_TOKEN`. This is a config-sanity
guard, not per-request auth (`check_auth` is unchanged). Covered by
`api/test_bind_guard.py`, run via `make test-api`.

## Deploy 2026-08-09 17:49 UTC — case-exact classifiers, no-eval witness, v2-aware report, federation provenance types (commit 6a1bd278)

Four merges deployed as one event after a full green battery on merged
main (exit 0; only the two standing items — the Jul 31 virp-cli:pbs-lab
binding failure and the api-suite skip):

- **Commit**: `6a1bd27854ea401e457a16dffac281d826b74a49`
- **Branch**: `main`
- **Tree at install**: clean (`git status --porcelain` empty)
- **Installed binary**: `/usr/local/lib/virp/virp-onode-prod`
- **sha256**: `c8e266bfab7985b1b6af1d6f2bd58dfa1ded314ca6c6882e5c4a20c026f50ab2`
- Pre-deploy state captured: `/var/backups/virp/20260809T174944Z`
  (`sudo make rollback-prod ROLLBACK_FROM=` that path restores it)
- Restarted 17:49:54 UTC; startup clean: chain enabled, approvals
  loaded (keys=1), socket_allowed_uids 999 1000 997 995 993 994,
  per-uid ceiling 993=GREEN, all 7 devices reconnected, autopilot
  resumed GREEN cycles immediately.

Post-deploy smoke, all via the netclaw bridge over the tunnel and
verified from THIS node (chain/journal, never the bridge output):
- `VTYSH -C "SHOW IP OSPF"` (the 2026-08-09 classified≠executed repro)
  → RED by absence, SIGNED v1 refusal, executed=false, proposal filed.
- `vtysh -c "show ip ospf neighbor"` → GREEN, chained observation wire
  version byte 1, O-Key HMAC PASS, sha256 matches the bridge receipt.
- Federation provenance now lands: fed_request → observation →
  fed_outcome all chained for both smoke sessions; zero
  `chain_append REJECTED` lines.
- Live trust report: 59,672 entries, hashes/links/chain-HMAC all pass,
  observation HMAC fail=0, the 5 legacy v2 frames in the V2-SESSION
  category with journal corroboration pass=5, FAILED ENTRIES: 1 (the
  standing Jul 31 binding item).

Bridge side (netclaw, same event window): obs_version rolled back to 1
via unit drop-in 50-obs-version.conf — code default stays 2; returning
to v2 is deleting the drop-in once dual-signing lands.

### Known-open, deliberately not fixed in this deploy
- `virp_session_check_timeouts` has ZERO callers: an ACTIVE v2 session
  never expires.
- One shared session context: any allowlisted uid's HELLO races
  another's session (fail-closed, but racy). Both belong with the
  dual-signing design.
