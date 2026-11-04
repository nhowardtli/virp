# feat/autopilot-nondaemon-uid — the autopilot off the daemon's uid, FRR reads into the catalog

Branch opened 2026-11-04 at Nate's direction (Gate 0 of the Seat A build, step 3 option A). **Not built, not deployed in the session that wrote it.** The C change has not been compiled; the Python suites were run on the laptop (`python3 tests/test_autopilot.py`, `python3 tests/test_template_uid_policy.py`). Run `make test-black-policy test-autopilot test-template-uid-policy test-render-devices` before any install.

## Why

Since the owner policy went live on virp-lab (2026-10-26, `-P /etc/virp/owner-policy.json -J /var/lib/virp/policy.db`) three things stopped the collectors:

1. `virp_policy_load` refuses a policy that names the daemon's own uid (999) as a principal or trusted appender. The autopilot units ran as `virp` (999), so every `execute` they sent was refused `BLACK-13` before dispatch: 5,649 refusals in 24 h on 2026-11-04, 18 alerts per 5-minute cycle, exit 1 since 2026-10-26 01:32Z.
2. `virp_policy_classify` admits a closed catalog (`uptime`, `hostname`, `uname -sr`, `qm/pct status N`, `show version`, `show clock`, ...) and its grammar refuses quotes. The evidence collector (uid 995) and the config-backup collector (uid 997) send `vtysh -c "show ..."`, so they were refused too (20 and 96 refusals in the same 24 h).
3. The autopilot verified observations with `virp-tool inspect ... onode.key okey`: it needed the O-Key, which only uid 999 may read, so it could not simply move to another uid.

## What the branch changes

**Commit 1, `src/virp_policy.c`**: a new operation `frr.read` (effect 0, resource `host`) admitting exactly four byte strings for the Linux vendor, before `normalize()` runs:

    vtysh -c "show running-config"
    vtysh -c "show logging"
    vtysh -c "show zebra"
    vtysh -c "show daemons"

Whitespace canonicalizes as everywhere else; every other byte must match. No other `show`, abbreviation, second `-c`, environment prefix, redirection, separator or quoting is admitted; the same bytes on any other vendor stay refused; a `system.read` rule does not grant `frr.read` and vice versa. `frr.read` joins the read list in `virp_policy_reserve` so an UNKNOWN one does not quarantine mutation. `tests/test_policy.c` `frr_tests()` pins the four accepted forms, 30 near-miss rejections, seven other vendors, rule-scope separation, the operation vocabulary and the UNKNOWN-read behaviour. `docs/BLACK-POLICY.md` carries the catalog row.

The autopilot battery's own FRR rows (`show ip ospf neighbor`, `show ip route ospf`), `df -h`, `uname -a`, the Wazuh/LibreNMS/PBS typed reads and the peer probes are NOT added. They remain outside the catalog by this branch's scope (Nate: the exact forms evidence and config-backup send). The cycle will therefore still alert on those rows after deploy until a separate catalog decision.

**Commit 2, the autopilot identity**:

- `autopilot/virp_autopilot.py` holds no secret path. `OKEY_PATH` is gone; `OBS_PUB_PATH=/etc/virp/keys/chain-sign.pub`. `execute` requests `obs_version: 3`; the reply is parsed (`parse_observation_v3`: 88-byte header, XO1 profile, subheader, body) and verified with the public key only (`verify_observation`: Ed25519 over header || payload || HMAC, mirroring `virp_verify_observation_ed25519` and `report/verify.py`). `load_obs_pub` refuses a 64-byte file.
- `sign_outcome` and `chain_verify_session` replies are HMAC-only v1 frames with no public-key form. They are now transport-attested (`attest_control_frame`: SO_PEERCRED uid equals the socket owner's uid) and printed as `attested=PEERCRED`, never as `VALID`. Anything appended from them is re-verified by the daemon's GATE 3. A daemon-side `verify` action would make this cryptographic; that is a follow-up, named here, not hidden.
- Execute v3 needs a bound session: `open_session()` does `session_hello` (versions 2,1; HMAC-SHA256) and `session_bind`; `main()` opens it for `cycle`, `corpus`, `comparator` and closes it afterwards. The daemon's session context is shared, so a cycle resets any other client's session on that node (today nothing else on virp-lab holds one; uid 993 netclaw is locked).
- `chain.db` is opened `mode=ro&immutable=1`: this uid has, and must have, no write on `-shm`.
- Units: `User=virp-autopilot Group=virp-autopilot` on all four. `deploy/autopilot-access.sh` (installed by `make install-prod`, listed in `VIRP_INSTALL_SCRIPTS`) grants traversal of `/run/virp` and `/var/lib/virp`, rw on the socket, and ownership of `/var/lib/virp/autopilot`; it fails loud if the user is missing, is not uid 971, or is in any other group. `deploy/virp-onode-autopilot.dropin.conf` runs it from the daemon's `ExecStartPost` as `54-autopilot.conf` (`deploy/unit-manifest.txt`).
- `deploy/devices.template.json`: literal uid 971 with ceiling GREEN, actions `execute chain_append chain_verify_session sign_outcome session_hello session_bind session_close`, append types `observation comparator_verd chainwalk_summa`, and a note. `tests/test_template_uid_policy.py` derives the send set from the source and pins the row. `docs/UID-REGISTRY.md` records 971 (and the already-live 973 that never got a row).

## What deploying it will need (not done here)

1. Daemon flags: `-S /etc/virp/keys/chain-sign.key` (Gate 0 runbook step 4c adds it) **and `-3`** on `virp-onode.service`'s ExecStart, or execute v3 returns `VIRP_ERR_KEY_NOT_LOADED`. `-3` loads the chain-signing key as the observation key; `/etc/virp/keys/chain-sign.pub` is what this client verifies with.
2. `useradd --system --uid 971 --shell /usr/sbin/nologin --home-dir /nonexistent --no-create-home virp-autopilot` on virp-lab (check 313 first when it is reachable; the registry marks 971 unverified there).
3. Owner policy, `/etc/virp/owner-policy.json`: add principal `{"uid":971,"profile":"observe","expires":...,"rules":[...]}` with `system.read` rules for the devices the battery reads (same shape as uid 997's 59 rules) and `frr.read` rules for the four `clab-frr-ospf-frr*` device ids (vendor 3, port 2222); add a principal for 995 (observe) with `frr.read` rules for the same four devices (995 stays a `trusted_appender`? No: the loader refuses a uid that is both; move 995 from `trusted_appenders` to `principals` only if its `evidence_item` appends are covered another way, or leave 995 as appender and accept that its reads stay refused. Decide before editing.); add `frr.read` rules for the same four devices to uid 997. The daemon re-reads the policy only at start.
4. `make install-prod` (binary + `autopilot-access.sh` + Python modules), `make install-units` for the four autopilot units and the daemon drop-in, `make install-devices-template` after reconciling the live template with git (787-line drift on 2026-11-04), then the daemon restart. `/var/lib/virp/autopilot` is chowned by the access script on first start.
5. Acceptance: one `virp-autopilot.service` run with zero `BLACK-13 uid=971` lines, `verified=VALID` on the catalog rows and new `autopilot:<date>` entries; one `virp-evidence.service` run with `ok` equal to `expected`; one `virp-config-backup.service` run with no `gate_error` for the four FRR devices. Gate 0 row 3 stays FAIL until those three pass.

## Limits

- Control frames are attested, not verified, by this client (above).
- The C change is uncompiled in the authoring session.
- Point 3 above exposes a design knot for 995: it is a trusted appender, and the loader forbids an appender from also being a principal. Its reads cannot be granted without either a second identity for its reads or a loader change. This branch does not decide that.
