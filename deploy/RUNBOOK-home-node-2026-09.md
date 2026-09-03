# Runbook — bringing virp-onode-home onto tracked config

Order set by the operator 2026-09-03. Nothing below has been run.
Every step names what it changes and what proves it worked.

**The order is not cosmetic.** Step 1 must precede any binary upgrade:
uids 999 and 1000 are allowlisted on this node with no action map, which
the *running* binary treats as unrestricted and `origin/main` treats as
a **boot failure** (Sep 1 review, Task 2). Upgrading first leaves a
daemon that refuses to start. See `tools/state/PHASE0-FINDINGS.md`
D4/D5.

**Nothing on virp-lab until the home node has run the reporter for a
day.** The reporter and its timer are new code touching a live daemon's
socket; the node with 38 lab devices is the right place to find out it
misbehaves, not the one with 43 and a netclaw bridge.

---

## Step 1 — credentials, then the socket policy

The template names four credentials and `render-devices.sh` is FATAL on
any it cannot resolve, so this file must exist before the template is
installed or the daemon will not start.

    # on virp-onode-home, as root
    umask 077
    cat > /etc/virp/autopilot.env <<'EOF'
    VIRP_PVE_PASSWORD=...
    VIRP_LABNET_PASSWORD=...
    VIRP_WAZUH_HOME_PASSWORD=...
    VIRP_FORTIGATE_HOME_PASSWORD=...
    EOF
    chmod 0600 /etc/virp/autopilot.env

The four values are the ones currently inline in
`/etc/virp/devices.json` — pve-lab's root password, the `aiops-svc`
password shared by all 35 GNS3 routers, `virp-ro` on wazuh-home, and
`virp-gate` on fortigate-home. Confirmed by hashing every credential in
the live config and its eleven backups: there is no fifth.

    make install-devices-template \
        VIRP_DEVICES_TEMPLATE_SRC=deploy/devices.home.template.json

Refuses on a dirty tree by design. Installs to the canonical
`/etc/virp/devices.template.json`.

**Do not restart yet** — the unit still reads `/etc/virp/devices.json`
and has no render step. The template is inert until step 2.

## Step 2 — the unit drop-in, and the first restart

    make install-prod            # render-devices.sh must be the current one
    install -d -m 0755 /etc/systemd/system/virp-onode.service.d
    install -m 0644 deploy/virp-onode.service \
        /etc/systemd/system/virp-onode.service
    install -m 0644 deploy/virp-onode-home.dropin.conf \
        /etc/systemd/system/virp-onode.service.d/40-home.conf
    systemctl daemon-reload
    systemctl restart virp-onode

This restart does four things at once, so read the failure modes before
running it:

1. **Renders the fleet from the template.** If a credential is missing
   the render is FATAL and the daemon does not start. Fix the env file
   and restart; nothing is half-applied.
2. **Applies the socket policy.** uid 999 loses the `shutdown` it
   implicitly held. Check the journal for
   `uid 999 action allowlist` and `uid 999 chain_append types`.
3. **Adopts the base unit's hardening** — `NoNewPrivileges`,
   `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
   `RestrictAddressFamilies`, `RuntimeDirectoryMode` 0755 → 0750. The
   hand-written unit had none of it. This is the finding D3 fix and it
   is the most likely source of an unexpected failure: if the daemon
   dies on a path it can no longer reach, the journal names the path.
4. **Moves the device config to tmpfs.** `/etc/virp/devices.json` stops
   being read. Leave the file in place until step 3 confirms.

**PREREQUISITE, or every device fails.** `ProtectHome=yes` hides `/home`
from the service. If the `virp` account's home is under `/home`, the SSH
driver cannot read `~/.virp/known_hosts` and every ssh device fails host
key verification — observed on this node, connected 2/38 -> 0/38. Do
this BEFORE the restart (both services run as `virp`, so both must stop
for `usermod`):

    systemctl stop virp-onode virp-witness-tunnel
    cp -a /home/virp/.virp /home/virp/.ssh /var/lib/virp/
    chmod 0700 /var/lib/virp/.virp
    chmod 0600 /var/lib/virp/.virp/known_hosts*      # they were 0664
    usermod -d /var/lib/virp virp
    systemctl start virp-onode virp-witness-tunnel

Done on virp-onode-home 2026-09-03. virp-lab already had it.

Verify:

    systemctl is-active virp-onode
    virp-tool chain tail -n 3 --db /var/lib/virp/chain.db
    # 38/38 devices reconnected, and the gate line unchanged:
    #   default=ENFORCE max_tier=GREEN

Rollback: `rm /etc/systemd/system/virp-onode.service.d/40-home.conf`,
restore the previous unit, `daemon-reload`, `restart`. The old
`/etc/virp/devices.json` is still there and still correct.

## Step 3 — retire the hand-edited config

Only after step 2 has held. The rendered file is authoritative from
here; the on-disk one is a stale copy that will drift.

    mv /etc/virp/devices.json /etc/virp/devices.json.superseded-20260903
    # confirm the daemon does not care:
    systemctl restart virp-onode && systemctl is-active virp-onode

Delete `.superseded-*` once a restart has survived it. Its scrubbed
equivalent is `deploy/devices.home.template.json`; the eleven earlier
backups are already in `deploy/history/virp-onode-home/` and were
removed from the box 2026-09-03.

## Step 4 — the binary

Now, and not before, the node can move off `de95f80` (22 commits
behind). The socket policy from step 1 is what makes this safe.

    git fetch && git checkout main && git pull
    sudo git config --global --add safe.directory <tree>   # or the
        # dirty-tree guard in install-prod sees an empty status under
        # sudo (dubious ownership) and passes without checking anything
    make prod && sudo make install-prod

**`install-prod` OVERWRITES `render-devices.sh` from the tree.** It is in
`VIRP_INSTALL_SCRIPTS`, so installing from a ref that does not carry the
home node's four credential names (`VIRP_PVE_PASSWORD`,
`VIRP_LABNET_PASSWORD`, `VIRP_WAZUH_HOME_PASSWORD`,
`VIRP_FORTIGATE_HOME_PASSWORD`) or the `[A-Z0-9_]+` placeholder fix
silently reverts both. The next render then fails and the daemon does
not start. Observed 2026-09-03: install-prod from `origin/main` replaced
`47abe98f…` with `4990ede6…`.

Until this branch is merged, re-install it and re-render BEFORE
restarting:

    install -m 0755 deploy/render-devices.sh \
        /usr/local/lib/virp/render-devices.sh
    VIRP_RENDER_OUT=/tmp/probe.json /usr/local/lib/virp/render-devices.sh
    rm -f /tmp/probe.json

    systemctl restart virp-onode

Verify the daemon now attests itself — this node has never emitted a
`node_config/1` entry, and after this it should:

    sqlite3 -readonly /var/lib/virp/chain.db \
      "SELECT count(*) FROM chain_entries WHERE artifact_type='node_config'"

A non-zero count means `tools/state/drift-check.sh` will start reporting
this node's gate facts as `attested` rather than as unattested file
reads.

## Step 5 — the state reporter, home node only

    install -m 0755 tools/state/deployed-state.sh \
        /usr/local/lib/virp/deployed-state.sh
    install -m 0644 deploy/virp-deployed-state.service \
        /etc/systemd/system/virp-deployed-state.service
    install -m 0644 deploy/virp-deployed-state.timer \
        /etc/systemd/system/virp-deployed-state.timer
    systemctl daemon-reload
    systemctl start virp-deployed-state          # once, by hand, first
    systemctl enable --now virp-deployed-state.timer

The template row granting `${VIRP_UID}` the `evidence_item` append type
is already in `deploy/devices.home.template.json` from step 1, so the
submit half will be accepted. If it is not, the error names the two
config keys to check.

    drift-check.sh --state /var/lib/virp/state/deployed-state.json

Expect `CLEAN` or `INCOMPLETE`, not `DRIFT`.

## Step 6 — virp-lab, after a full day

Not before. The colo node needs the same `evidence_item` row, which is
already in `deploy/devices.template.json` and lands with
`make install-devices-template` plus a restart. The reporter and timer
install identically.

virp-lab needs no socket-policy work: its action maps and append-type
policy are already complete.

---

## Read this before touching any other node

Two traps this deploy walked into. Both are silent — nothing logs a
warning, and in one case the daemon simply never starts.

### 1. Check the daemon version before adding a uid action map

On a **pre-v0.2.1** daemon, any uid that appears in
`socket_uid_action_allow` is inferred to be a restricted federated
principal and its `chain_append` is narrowed to `fed_request` /
`fed_observation` / `fed_outcome` **and nothing else**. `observation` and
`evidence_item` are refused with `err=-50`.

So on such a node, **adding an action map silently kills that uid's
ability to append anything**. Giving uid 999 a map to take away its
`shutdown` also takes away the autopilot's and the reporter's writes, and
the only sign is a refusal at submit time. v0.2.1 replaced the inference
with the explicit `socket_uid_chain_append_types` policy, so on v0.2.1+
the two are separable — but only there.

Check first:

    strings /usr/local/lib/virp/virp-onode-prod       | grep -c socket_uid_chain_append_types      # 0 = pre-v0.2.1

**This applies to virp-lab too.** Confirm its binary before changing its
action maps.

Related, same era: `ONODE_MAX_UID_ACTIONS` is **8** before `13ec426` and
**32** after. A longer list overflows and `virp_onode_prod.c` fails closed
by installing DENY-ALL for that uid. The cap raise and the boot invariant
landed in the same commit, so config and binary are coupled.

### 2. `install-prod` overwrites `render-devices.sh`

It is in `VIRP_INSTALL_SCRIPTS`. Installing from **any ref that predates
this merge** reverts both the home node's four credential names and the
`[A-Z0-9_]+` placeholder fix. The next render then fails and **the daemon
does not start**. Observed 2026-09-03: `47abe98f…` replaced by
`4990ede6…`.

Anyone installing on virp-onode-home from an older ref must re-install
that script and re-render before restarting:

    install -m 0755 deploy/render-devices.sh         /usr/local/lib/virp/render-devices.sh
    VIRP_RENDER_OUT=/tmp/probe.json /usr/local/lib/virp/render-devices.sh
    rm -f /tmp/probe.json

---

## Not in this runbook

- **Producer key `008353cf`**, whose private half is on two machines.
  2537 chain records are signed under it and no key rotation changes
  what those records bind. Decision outstanding; see
  `deploy/keys/registry.json`.
- **Producer key `4727a5b9`**: 32 records on this node's chain and its
  public half is not pinned there, so they cannot be verified on the
  node that stores them. Copying its `producer.pub` across closes it.
- **The stale ssh aliases.** `ct211` and `ironclaw-onode` still resolve
  to the decommissioned 10.0.0.211.
- **`install-prod`'s dirty-tree guard**, which is a no-op on a
  user-owned tree. Deliberately left unfixed and tracked as TODO.md
  section 3 — it is a fail-open guard and deserves a test, not a patch
  at the end of a deploy.
- **Five failed timers on virp-lab** — autopilot, comparator, corpus,
  config-backup, evidence. Unrelated to this work and unaddressed.
