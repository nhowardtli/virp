# VIRP Deployment Record — virp-lab

- **Role**: production reference instance
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

## Devices
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
Wazuh uses `VIRP_WAZUH_INSECURE=1` (self-signed lab cert) — replace with VIRP_CA_BUNDLE
when the lab CA exists.

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
therefore has a different value after this deploy. Noted for draft-06.

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
