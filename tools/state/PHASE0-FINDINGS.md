# Phase 0 — deployed-state facts, 2026-09-02

Read-only survey of the two live O-Nodes against `origin/main`
(`7cda0191171e56c7349b5b937420aa57c78d761c`). Nothing was changed on either
box. Every divergence below is REPORTED, not fixed.

Collection method for each fact is named, because "how we know" is the part
that decides whether the reporter can sign it or only print it (see §4).

---

## 1. The two nodes

| | virp-lab (".211") | virp-onode-home ("313") |
|---|---|---|
| reached as | `ssh virp-lab` → 10.0.10.211 | `ssh nhoward@10.0.0.13` |
| deploy tree | `/opt/virp` | `/home/nhoward/virp` |
| unit | `virp-onode.service` | `virp-onode.service` |
| node_id | `0x00000001` | `0x0000000D` |
| device config | `/run/virp/devices.json`, rendered at start | `/etc/virp/devices.json`, static |
| daemon uid | `virp` (999) | `virp` (999) |

Note the ssh alias trap named in the brief is real and already documented in
`~/.ssh/config`: `ct211` / `ironclaw-onode` still point at the **dead**
10.0.0.211. The live node is 10.0.10.211 via the `virp-lab` alias, no jump
host. Both aliases exist simultaneously and only a comment distinguishes them.

---

## 2. Fact table

### virp-lab (.211)

| fact | value | how read |
|---|---|---|
| deploy-tree rev | `f269455c6aeb8d0a3a8ba485015e9f492d17630d` | `git -C /opt/virp rev-parse HEAD` |
| `git describe` | `v0.2.0-8-gf269455c` | `git describe --tags --always --dirty` |
| branch | `main` | `git rev-parse --abbrev-ref HEAD` |
| dirty | **no** (`git status --porcelain` empty) | `git status --porcelain` |
| on a pushed ref | **yes** — ancestor of `origin/main`, 1 behind | `git merge-base --is-ancestor` |
| installed daemon sha256 | `54dc9d481dc6b210a265b84bdff68c0586b88e1491dc2078900d167777da9513` | `sha256sum /usr/local/lib/virp/virp-onode-prod` |
| running daemon sha256 | `54dc9d481dc6b210a265b84bdff68c0586b88e1491dc2078900d167777da9513` | `sha256sum /proc/2067392/exe` |
| running == installed | **yes** | comparison |
| daemon self-reported build | `v0.2.0-8-gf269455c` | daemon's own `node_config/1` chain entry |
| process start | 2026-09-02 12:24:38 UTC | `ps -o lstart=` |
| unit sha256 | `3a57030ac66c6bd8928325fa65b1ebd57a46b30569930bda8ab57a76363cb440` | `sha256sum` of `/etc/systemd/system/virp-onode.service` |
| drop-ins | 4, all byte-identical to tracked | `sha256sum` |
| installed template sha256 | `2c0bbd4cdd6d7799f809198122849a09629af6d277154fc1ab80c97b89bb9ce7` | `sha256sum /etc/virp/devices.template.json` |
| rendered config sha256 | `33aad43ba2f7669d8fceae75ab7e252d89a4bd4e157f6af7303e071e7012dc6a` | `sha256sum /run/virp/devices.json` |
| device count | **43** | parsed from rendered config |
| gate | `ENFORCE` / max tier `YELLOW` | rendered config **and** daemon `node_config/1` |
| `evidence_required` | `true` | rendered config **and** daemon `node_config/1` |
| socket allowlist | 999 `virp`, 1000 `nhoward`, 997 `virp-backup`, 995 `virp-evidence`, 993 `virp-netclaw`, 994 `virp-broker` | rendered config |
| per-uid ceilings | 993/997/995 → GREEN | rendered config **and** daemon `node_config/1` |
| enrolled approver key_ids | `a88c58a65fc41b01de933ba6e803cf7a` (nhoward, enabled) | `/etc/virp/approvers.json` |

### virp-onode-home (313)

| fact | value | how read |
|---|---|---|
| deploy-tree rev | `de95f805e9acb5394d29f0b6e51cbf97f2d68de7` | `git -C ~/virp rev-parse HEAD` |
| `git describe` | `archive/feat/cisco-config-scrub-netclaw-yellow-2026-08-10-167-gde95f80` | `git describe --tags --always --dirty` |
| branch | `main` | `git rev-parse --abbrev-ref HEAD` |
| dirty | **no** | `git status --porcelain` |
| on a pushed ref | **yes** — ancestor of `origin/main`, **22 behind** | `git merge-base --is-ancestor` |
| installed daemon sha256 | `87cb2cd78a22f3937ecefc77577af9ef183bbbba35a198426672fb9e2c919747` | `sha256sum` |
| running daemon sha256 | `87cb2cd78a22f3937ecefc77577af9ef183bbbba35a198426672fb9e2c919747` | `sha256sum /proc/9412/exe` |
| running == installed | **yes** | comparison |
| daemon self-reported build | **UNAVAILABLE** — binary predates both `--version` and `node_config/1` | attempted, refused |
| installed `virp-tool` build id | `f1bb8f5` — **not** the tree's `de95f80` | `virp-tool version` |
| process start | 2026-09-02 07:00:12 UTC | `ps -o lstart=` |
| unit sha256 | `17064a0307c258d40ad519cdde8d9e703b821250e2f04cbe6df1364ed14a1e32` | `sha256sum` |
| drop-ins | 1 (`60-wazuh-lab.conf`), byte-identical to tracked | `sha256sum` |
| template | **none** — no template, no render step | unit has no `ExecStartPre` |
| device config sha256 | `334735488045542468943a5956fb05fe5e7ef985bc9fe1d88d459baaccc346dc` | `sha256sum /etc/virp/devices.json` |
| device count | **38** | parsed |
| gate | `enforce` / max tier `green` | on-disk config only |
| `evidence_required` | key absent | on-disk config only |
| socket allowlist | 999 `virp`, 1000 `nhoward`, 997 `virp-spark`, 1001 `virp-laptop` | on-disk config |
| per-uid ceilings | 997/999/1000/1001 → green | on-disk config |
| enrolled approver key_ids | `ead98d807804c85e9e43c446d90dcec0` (**disabled**, orphaned), `155a9b963b4e1a293f009ff63134d686` (nhoward-laptop, enabled) | `/etc/virp/approvers.json` |

---

## 3. Divergences

Ranked by what would actually hurt. **Nothing here was fixed.**

| # | node | divergence | evidence | why it matters |
|---|---|---|---|---|
| D1 | 313 | Device config is **untracked**. `/etc/virp/devices.json` (38 devices, 9902 B) has no source in the repo — no template, no render step, no `unit-manifest.txt` row. It is hand-edited in place; 11 `.bak-*` copies sit beside it. | `sha256 334735…`; unit `ExecStartPre` count = 0 | This is the 43-device failure again, one node over and worse: on .211 the fleet at least now HAS a tracked template. On 313 the entire fleet exists only on the box. A rebuild loses it silently. |
| D2 | 313 | The **unit file is untracked**. `17064a03…` matches no file in `deploy/`, and `unit-manifest.txt` maps only the single `virp-lab` unit. `scripts/check-unit-drift.sh` cannot see this node at all. | manifest has 1 core-daemon row | The drift checker built specifically to catch untracked units reports green here because 313 is outside its map. |
| D3 | 313 | Unit runs **without any systemd hardening**. No `ProtectSystem`, `NoNewPrivileges`, `PrivateTmp`, `StateDirectory`; `RuntimeDirectoryMode=0755` where .211 uses `0750`. | full unit read | Divergence in security posture that no check compares, because of D2. |
| D4 | 313 | **`socket_uid_action_allow` covers only uids 997 and 1001.** Uids 999 and 1000 are allowlisted with **no action map**, i.e. unrestricted — `shutdown` included. | on-disk config | On `origin/main` this is a **boot failure** by design (Sep 1 review, Task 2: an allowlisted uid without an action map is fatal). 313 is 22 commits behind, so it boots. **Upgrading 313 to origin/main will fail to start until this config is written.** |
| D5 | 313 | `socket_uid_chain_append_types` **absent entirely**. | on-disk config | Same shape as D4: the v0.2.1 boot invariant requires a types entry for every allowlisted uid that may `chain_append`. Second blocker on the same upgrade. |
| D6 | 313 | Installed `virp-tool` reports build `f1bb8f5`, the deploy tree is at `de95f80`. Both are ancestors of `origin/main`, but they are **different commits**. | `virp-tool version` vs `rev-parse HEAD` | Binary-vs-tree skew: the tree does not describe the binary. This is exactly the state the reporter's running-vs-installed comparison is for, one level up — the tree moved after the build. |
| D7 | 313 | `/usr/local/lib/virp/render-devices.sh` is installed (`c4663a08…`, Aug 23) and **stale** vs tracked (`4990ede6…`), but nothing invokes it. | `sha256sum` + unit | Dead installed artifact. Harmless today; a future unit change that starts calling it renders with old logic. |
| D8 | 313 | Daemon emits **no `node_config/1`** — 0 such entries in the whole chain. | `SELECT count(*) … WHERE artifact_type='node_config'` → 0 | The daemon cannot attest its own build/gate posture here. On 313 every gate fact is an **unattested file read**. This is the single biggest constraint on Phase 1 (see §4). |
| D9 | both | `.211` is 1 commit behind `origin/main` (docs only); `313` is **22 behind**. | `rev-list --count` | Not drift, but the gap 313 must cross is where D4/D5 detonate. |
| D10 | .211 | 6 of 9 `virp-*` services are in `failed` state: `virp-autopilot`, `-comparator`, `-corpus`, `virp-config-backup`, `virp-evidence`. Only `virp-onode` and `virp-netclaw-egress` are healthy. | `systemctl list-units` | Out of this session's scope, but the timers that produce the chain's other evidence are not running. Recorded so it is not discovered by accident a fourth time. |
| D11 | .211 | Two entries in `~/.ssh/config` (`ct211`, `ironclaw-onode`) still resolve to the decommissioned 10.0.0.211, alongside the live `virp-lab` → 10.0.10.211. | ssh config | This is the stale-alias failure named in the brief. It has not been pruned. |

### What is NOT divergent (checked, clean)

- **.211 unit** is byte-identical to `deploy/virp-onode.service`.
- **.211 all four drop-ins** are byte-identical to their tracked sources.
- **.211 installed template** is byte-identical to `deploy/devices.template.json`, and both carry **43** devices. The "tracked template has been nine devices since August" gap was closed by `6598b47` on `origin/main` earlier today; the box and the repo now agree.
- **.211 `render-devices.sh`** is byte-identical to tracked.
- **Running == installed binary on both nodes.** No rollback is being hidden right now.
- **Both deploy trees are clean and both HEADs are ancestors of `origin/main`.** No local-only commits on either box.

---

## 4. What a GREEN command can already read — and what it cannot

The brief asks which of these facts a GREEN-classified command can read through
the existing gate, because that decides what the reporter can sign versus only
print. The answer splits along a line that is worth stating precisely, because
it is not the line the question assumes.

### 4.1 Through the gate's `execute` path: essentially none

The `linux` driver's GREEN surface for a bare shell is three exact strings:

    df -h        uptime        uname -a

plus three exact peer-probe strings:

    systemctl is-active virp-onode
    /opt/virp/build/virp-tool chain tail -n 1 --db /var/lib/virp/chain.db
    cat /var/lib/virp/autopilot/published.json

That is the whole list (`src/drivers/driver_linux.c`, `LINUX_HOST_GREEN_EXACT`
and `LINUX_PEER_GREEN_EXACT`). **Not one** of the facts in §2 is obtainable
from it: no `git rev-parse`, no `sha256sum`, no `systemctl cat`, no
`cat /etc/virp/…`. `cat` as a general verb is deliberately RED.

And the table above those rows carries an explicit, argued **hold**:

> THE LIST IS NOT GROWING. A DELIBERATE HOLD (2026-08-13) … Adding generic
> host shell changes the job description. `cat <path>` means the gate must
> decide which of a filesystem's paths are reads worth signing … That is no
> longer "know the Proxmox API"; it is "police arbitrary Linux".

So the honest reading of item 4 is: **every fact in §2 would need a new
classifier row, and the driver argues at length against granting them.**

### 4.2 But the reporter does not need that path

The classifier governs commands the O-Node runs **against a device**. The
reporter is a local script on the node reading its own filesystem, and its
submission path is `chain_append`, which is governed by
`socket_uid_action_allow` + `socket_uid_chain_append_types` — a different
authorisation surface entirely. `chain_append` never enters the driver
classifier.

**Conclusion: the reporter needs no new classifier row, and none should be
added.** That satisfies the brief's "no new classifier row that is not
read-only" by needing none at all, and it leaves the 2026-08-13 hold intact.

### 4.3 What can therefore be signed, and what can only be printed

Three distinct grades, and the reporter must not blur them.

**(a) Daemon-attested — the daemon signed these about itself.**
On .211 only: `build_id`, `gate_default_mode`, `gate_max_tier`,
`evidence_required`, `uid_ceilings`, all carried in the daemon's own
`node_config/1` chain entry, minted at startup under a reserved artifact type
a socket client may not forge (GATE 1). Latest on .211 is
`nodeconfig-f2cf840aee3a03aa`, seq 2, 2026-09-02 12:24:38 UTC.
The state document should **cite this entry's hash** rather than restate the
values as its own claim.
**On 313 this grade is empty (D8).**

**(b) Chained and hash-bound, but self-reported.**
Everything else in §2 — git rev, dirty flag, binary hashes, unit hash,
template hash and device count, approver key_ids, allowlist uids. The reporter
reads them locally and submits the document via `chain_append`. GATE 2 binds
the body to its declared hash, and the chain entry itself carries the node's
`K_chain` HMAC and its position in the hash chain. That proves **the daemon
received these exact bytes at this position at this time**. It does not prove
the bytes are true.

**(c) Not signable at all, only printable.** Nothing, given (b) — but the
distinction inside (b) is the thing Phase 4 has to say plainly.

### 4.4 The artifact type

`artifact_type="observation"` **with a body** requires a v1/v2/v3 signature
under a key the reporter will not hold (GATE 3: v1 is HMAC under the O-Key,
which is `virp`-owned; uid 1000 has no signing key). Two consequences:

- Submitting as `observation` would force **commitment-only** (no body), which
  every reader correctly grades UNVERIFIABLE — the document would not be on
  the chain, only its hash.
- The externally-allowed type list (`virp_chain_type_is_external_allowed`,
  `src/virp_chain.c:593`) is a fixed C array. A new `deployed_state` type is a
  C change plus a rebuild plus a deploy on both nodes — far past "build a
  reporter".

`evidence_item` is already externally allowed, already in uid 1000's
`socket_uid_chain_append_types` on .211, carries a plain-JSON body with no
signature requirement, and is semantically honest: a state document is
evidence. **Recommendation: submit as `evidence_item` with a
`deployed_state/1` schema tag in the body.** Document count is ~2 KB, well
inside the 8192-byte `artifact_content` limit, so it lands as a real body and
not a commitment.

**On 313 this needs uid 1000 to gain an `evidence_item` type entry** — which
does not exist there at all (D5), so today 313's uid 1000 is unrestricted and
the append would be accepted. After the D4/D5 config work that upgrade
requires, the entry must be written deliberately.

---

## 5. Open questions this raises for Phase 1

1. **313 has no attested grade at all.** The reporter will emit a document
   whose gate facts are unattested file reads. Options: emit it with an
   explicit `attested: false` marker per field, or refuse. Recommend the
   former — a marked-unattested fact is more useful than no document.
2. **D4/D5 are a live upgrade blocker on 313**, discovered here rather than at
   restart. Fixing them is config work on a box, which this session's rules
   forbid. Recorded, not touched.
3. **313 is outside `unit-manifest.txt` entirely** (D2). Whether the reporter
   should also grow a manifest row for it is a Phase 2 question, not Phase 1.
