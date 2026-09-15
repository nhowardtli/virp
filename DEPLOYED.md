# VIRP deployment — virp-node2 (10.0.10.212, VM 212)

## Current live state — 2026-09-15 16:18 UTC

Runtime source: nhowardtli/virp main @ 42fe1fec5c0b12e097265b8ca5fdd8ab13f71ced.
This branch adds a deployment record only; runtime identity remains the pinned source SHA.
Execution host for build/install/preflight: virp-node2; orchestration: nhoward-ThinkPad-E16-Gen-2.
Service uses /usr/local/lib/virp/virp-onode-prod; active, PID 17275 at initial proof.
Preflight: actual target daemon ran for 10 seconds with scratch database/socket/approval directory,
existing node-local keys, and a private network namespace. Graceful timeout exit124 was expected.
First preflight failed because scratch renderer output was root:root0640; changed scratch ownership
to root:virp0640 and reran successfully. No environment values or template rows changed.
No production keys or databases exported. Completed legacy archive was not reopened or reverified.
Configured gate default ENFORCE/YELLOW, evidence_required=true; no explicit per-uid tier overrides.
Startup records uid999 actions21/types4, uid1000 actions22/types7, allowed uids999/1000, Ready.
check-deploy-unit passed. Four pre-existing autopilot service paths were aligned to installed scripts;
no timer was enabled. Existing Wazuh lab TLS posture preserved in its supported drop-in.
No full isolated battery run under Nate's POC scope. No independent review or certification claimed.

### Generated install record

- **Commit**: `42fe1fec5c0b12e097265b8ca5fdd8ab13f71ced`
- **Branch**: `HEAD`
- **Tree at install**: clean (`git status --porcelain` exited 0 and printed nothing; see scripts/require-clean-tree.sh)
- **Installed binary**: `/usr/local/lib/virp/virp-onode-prod`
- **sha256**: `0c73de380bf149757c30d23957a7baad8a728dca88e5312fa8095b07cf80de5f`
- **sha256** `/usr/local/lib/virp/virp-tool`: `77c7d336adcce1d63b6836e3c0454c783eadc34ad2c51b368c189bd556ebdd33`
- **sha256** `/usr/local/lib/virp/render-devices.sh`: `f10a443ab0c37e8a361cf2fc7051c60ab1d80b193d41ea7ec7848b7c1bfd6f9a`
- **sha256** `/usr/local/lib/virp/config-backup-access.sh`: `358aa3aa978a0f220636c444336141f65d62f57136653f0e020fd370219fe022`
- **sha256** `/usr/local/lib/virp/evidence-access.sh`: `bcf299794a84b63b0b14b3e9c98dab2009912b8d2fa180493f33834e28a67219`
- **sha256** `/usr/local/lib/virp/netclaw-access.sh`: `a36999889421177fa437bf0d5d1fa680cfc92b37a7b761e7298839bfdd3fa8ca`
- **sha256** `/usr/local/lib/virp/sean-access.sh`: `1dc60c076f631db9cee8b5f549c2d3c2959462776ebaf1c9a20cee7b30698b0e`
- **sha256** `/usr/local/lib/virp/autopilot/virp_autopilot.py`: `f087541f8ca8c24915f505d77a8f25e78d9175d4cf4e2693c058fed938fb16c4`
- **sha256** `/usr/local/lib/virp/autopilot/virp_config_backup.py`: `6dfc726d5ee0fa9b2b34a16ba31584be5ba5668d2a6277101aeffa3ef183c7b1`
- **sha256** `/usr/local/lib/virp/autopilot/virp_evidence.py`: `b596b6de5859e8ee980410cf63e371780cbd3eed5a2f3b1bdd2ac4a7f978e504`

### Runtime binary identity

```text
0c73de380bf149757c30d23957a7baad8a728dca88e5312fa8095b07cf80de5f  /usr/local/lib/virp/virp-onode-prod
77c7d336adcce1d63b6836e3c0454c783eadc34ad2c51b368c189bd556ebdd33  /usr/local/lib/virp/virp-tool
0c73de380bf149757c30d23957a7baad8a728dca88e5312fa8095b07cf80de5f  /proc/17275/exe
```

## Legacy chain archived

Completed legacy archive (prior preserved evidence, NOT touched this run):
/var/lib/virp/archive/chain-legacy-75b135f-20260915.db
SHA256 582cb7b7e8b6f7d07fb0b09f7a5fffd0705671d487c5d508be2b7e35e3326920; 91751 entries / 131 sessions.
Target7c2e1d7 keyless verifier exit1; bytes unchanged in that prior run.
Its legacy path returns before hash/link checking: tier=hash+link text does NOT establish those checks ran.
This does not authenticate legacy history or establish its corruption.

Current cutover archive (stopped original database after rollback resumed it):
```text
70a09eee46d798e7009f292b00065b9a137de8ec835d810708443971dd186c16  /var/lib/virp/archive/chain-failed-attempt-20260915T161736Z.db
```
Count: 91783 entries / 131 sessions. Contrary to the prompt's zero-entry assumption, the old database
had been restored and was growing; all those bytes are now retained. No sidecars were present after stop.
Earlier failed target database remains /var/lib/virp/archive/chain-target-7c2e1d7-failed-20260915.db
(0 entries,0 heads); stopped original from that attempt remains chain-live-75b135f-20260915.db.
Approval directory and consumption records were not reset or replaced. This POC does not prove
cross-epoch replay resistance or the abandoned epoch-transition qualification requirements.

### Prior keyless verdict, verbatim (from preserved capture)

```text
[VIRP] Warning: coredump_filter=0x33 includes anonymous pages — if PR_SET_DUMPABLE is ever re-enabled, a core dump could contain the loaded key. PR_SET_DUMPABLE=0 is being set now as a hard mitigation.
[Chain] verifier: LEGACY_CHAIN shape (no chain_heads) — sessions will report COMPLETENESS_UNPROVABLE; database left untouched
[Chain] verifier: legacy artifacts shape (UNIQUE(artifact_id)) — left untouched
[Chain] Verifier open (read-only): db=/var/lib/virp/archive/chain-legacy-75b135f-20260915.db  tiers=keyless  sig_cols=no
approval:librenms-lab            BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
approval:wazuh-lab               BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-07-30   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-07-31   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-01   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-02   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-03   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-04   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-05   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-06   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-07   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-08   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-09   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-10   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-11   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-12   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-13   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-14   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-15   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-16   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-17   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-18   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-19   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-20   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-21   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-22   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-23   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-24   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-25   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-26   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-27   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-28   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-29   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-30   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-08-31   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-09-01   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-09-02   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-09-03   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-09-04   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-09-05   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-09-06   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-09-14   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-chainwalk:2026-09-15   BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-07-29  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-07-30  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-07-31  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-01  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-02  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-03  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-04  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-05  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-06  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-07  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-08  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-09  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-10  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-11  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-12  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-13  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-14  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-15  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-16  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-17  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-18  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-19  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-20  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-21  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-22  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-23  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-24  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-25  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-26  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-27  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-28  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-29  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-30  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-08-31  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-01  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-02  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-03  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-04  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-05  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-06  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-07  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-14  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot-comparator:2026-09-15  BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-07-29             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-07-30             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-07-31             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-01             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-02             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-03             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-04             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-05             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-06             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-07             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-08             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-09             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-10             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-11             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-12             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-13             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-14             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-15             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-16             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-17             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-18             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-19             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-20             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-21             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-22             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-23             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-24             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-25             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-26             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:[Chain] Destroyed
2026-08-27             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-28             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-29             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-30             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-08-31             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-01             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-02             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-03             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-04             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-05             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-06             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-07             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-14             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
autopilot:2026-09-15             BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
gate-enforce:librenms-lab        BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
gate-enforce:wazuh-lab           BROKEN         entries=0 to_seq=0 tier=hash+link  (LEGACY_CHAIN: no chain_heads table; chain length unauthenticated — COMPLETENESS_UNPROVABLE)
sessions=131 broken=131 unclean=0
```

### First new head

Session `node-config:00000001`, sequence0, hash `3a2a02c67917b0d662c5c04e9be6f6d7ee0290584995e3a6dbf40398442594f3`.
`show chain 3` establishes its one-entry session verifies through the gate. This shell does not display
head hashes, so the full hash above is attributed to supplemental read-only chain_heads inspection,
not to shell output. Head uses existing HMAC chain key; no Ed25519 chain signing was configured.

## Gate proofs, uid1000

Invoked the pinned tools/virp-shell.py via python3 as nhoward (uid1000); no shell service account added.
The shell's response HMAC is present but unverified by this client, as its output explicitly states.

### show-node

```text
node_id 0x00000001  seq 1  tier GREEN  type heartbeat  scope -  at 2026-09-15T16:18:25Z
hmac a08409a8..b39eb0c2
field                value
-------------------  --------------
node_id              0x00000001
uptime               0d 00h 00m 23s
onode_ok             yes
rnode_ok             yes
active_observations  0
active_proposals     0
HMAC present, not verified by this client (no O-Key at uid 1000)
% note: running as uid 1000, not 988 (virp-shell) or 985 (virp-shell-admin); the gate judges the PEER uid, so this session is not a virp-shell seat
```

### show-devices

```text
node_id 0x00000001  seq 2  tier GREEN  type resource_state  scope local  at 2026-09-15T16:18:25Z
hmac 29bcc9a3..9aae4b33
VIRP fleet: 3 devices
name           vendor    status
-------------  --------  -----------
wazuh-lab      wazuh     connected
librenms-lab   librenms  unconnected
virp-lab-peer  linux     connected
HMAC present, not verified by this client (no O-Key at uid 1000)
% note: running as uid 1000, not 988 (virp-shell) or 985 (virp-shell-admin); the gate judges the PEER uid, so this session is not a virp-shell seat
```

### show-chain-3

```text
node_id 0x00000001  seq 3  tier GREEN  type resource_state  scope local  at 2026-09-15T16:18:26Z
hmac c4011a99..e11edb62
chain sessions: 1 listed of the most recent 3; 0 broken
session               entries  range  valid  checked  first_broken  exec_open  last_write
--------------------  -------  -----  -----  -------  ------------  ---------  ----------
node-config:00000001  1        0-0    yes    1        -             0          23s
HMAC present, not verified by this client (no O-Key at uid 1000)
% note: running as uid 1000, not 988 (virp-shell) or 985 (virp-shell-admin); the gate judges the PEER uid, so this session is not a virp-shell seat
```

## Comparator — scheduled16:22UTC cycle, read-only211

Node2 cutover succeeded; comparator proof did NOT. The unchanged211 gate has no device named
virp-node2-peer, so it refuses the probe before contacting node2. This cannot be corrected under
node2-only write authorization. No restart or configuration change was made on211.
Node2 remains active; this is not a failed-start rollback condition. LibreNMS's pre-existing401
also remains unresolved; its fleet entry is unconnected.

```text
Sep 15 16:12:00 virp-lab systemd[1]: virp-autopilot-comparator.service: Main process exited, code=exited, status=1/FAILURE
Sep 15 16:12:00 virp-lab systemd[1]: virp-autopilot-comparator.service: Failed with result 'exit-code'.
Sep 15 16:12:00 virp-lab systemd[1]: Failed to start virp-autopilot-comparator.service - VIRP Autopilot — cross-node comparator (diffs this node's view against the peer's).
Sep 15 16:22:00 virp-lab systemd[1]: Starting virp-autopilot-comparator.service - VIRP Autopilot — cross-node comparator (diffs this node's view against the peer's)...
Sep 15 16:22:00 virp-lab python3[47188]: [ALERT] comparator_probe_not_green_verified: {'cmd': 'systemctl is-active virp-onode', 'tier': 'UNCLASSIFIED', 'obs_type': 15, 'verified': True, 'payload_head': "ERROR: device 'virp-node2-peer' not found"}
Sep 15 16:22:00 virp-lab python3[47188]: [ALERT] comparator_probe_not_green_verified: {'cmd': '/opt/virp/build/virp-tool chain tail -n 1 --db /var/lib/virp/chain.db', 'tier': 'UNCLASSIFIED', 'obs_type': 15, 'verified': True, 'payload_head': "ERROR: device 'virp-node2-peer' not found"}
Sep 15 16:22:00 virp-lab python3[47188]: [ALERT] comparator_probe_not_green_verified: {'cmd': 'cat /var/lib/virp/autopilot/published.json', 'tier': 'UNCLASSIFIED', 'obs_type': 15, 'verified': True, 'payload_head': "ERROR: device 'virp-node2-peer' not found"}
Sep 15 16:22:00 virp-lab python3[47188]: [ALERT] peer_daemon_not_active: {'peer': 'virp-node2', 'observed': '(unreachable / refused)'}
Sep 15 16:22:00 virp-lab python3[47188]: [ALERT] comparator_peer_summary_unreadable: {'check': 'peer_summary_unreadable', 'detail': 'no parseable peer summary'}
Sep 15 16:22:00 virp-lab python3[47188]:   [ALERT] peer_liveness    tier=UNCLASSIFIED obs=0x0f verified=VALID chain=obs:virp-node2-peer:1789489320196338276
Sep 15 16:22:00 virp-lab python3[47188]:   [ALERT] peer_chain_head  tier=UNCLASSIFIED obs=0x0f verified=VALID chain=obs:virp-node2-peer:1789489320204928050
Sep 15 16:22:00 virp-lab python3[47188]:   [ALERT] peer_published   tier=UNCLASSIFIED obs=0x0f verified=VALID chain=obs:virp-node2-peer:1789489320212795715
Sep 15 16:22:00 virp-lab python3[47188]:   peer_live=False
Sep 15 16:22:00 virp-lab python3[47188]:   local_head={"session": "autopilot-comparator:2026-09-15", "seq": 390, "entry_hash": "36287bc754cde57dc3ffa548a49daf6178d920ffb0ca7ee0726cdf9200ef488f"}
Sep 15 16:22:00 virp-lab python3[47188]:   peer_head =-
Sep 15 16:22:00 virp-lab python3[47188]:   signed verdict appended (obs sha256 a212301e597949dd...)
Sep 15 16:22:00 virp-lab python3[47188]: comparator complete: 1 disagreements, 5 alerts
Sep 15 16:22:00 virp-lab systemd[1]: virp-autopilot-comparator.service: Main process exited, code=exited, status=1/FAILURE
Sep 15 16:22:00 virp-lab systemd[1]: virp-autopilot-comparator.service: Failed with result 'exit-code'.
Sep 15 16:22:00 virp-lab systemd[1]: Failed to start virp-autopilot-comparator.service - VIRP Autopilot — cross-node comparator (diffs this node's view against the peer's).
```

## Recovery and evidence

/var/backups/virp/node2-42fe1fe-20260915/ contains previous binary/tool/unit/template, prior deployment
record, all build/install logs, exact initial preflight failure, successful retry, startup journal,
unit checks, shell proofs, generated deploy-record, first-head capture and archive hashes/counts.
Rollback if needed: stop node2; move current database plus any sidecars to a new archive name;
restore previous-daemon/previous-tool and previous-unit plus saved service/template files;
copy the stopped cutover archive (and any sidecars) to the live paths without removing archives;
restore75b135f worktree where the old unit executes; remove new drop-in by moving it to recovery custody;
daemon-reload/start; verify prior binary identity and device list. Never run rollback-prod alone:
the original service used a worktree executable, which the default install capture does not cover.
