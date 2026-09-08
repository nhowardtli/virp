# Deploy runbook: VM 313 (virp-onode-home, node_id 0x0000000D)

Host `10.0.0.13`. Unit `virp-onode.service`. Install prefix
`/usr/local/lib/virp`. Chain `/var/lib/virp/chain.db`.

## Rule 1: deploy via `make install-prod` only, never a manual copy

Build and install with the make target. Do not `scp` a binary out of
`build/` and `install` it by hand, even when the build looks current.

`install-prod` depends on `prod`, and `prod` recurses with the driver
flags:

    prod:
        $(MAKE) CISCO=1 FORTIGATE=1 PANOS=1 ASA=1 LINUX=1 WAZUH=1 \
                JUNIPER=1 LIBRENMS=1 PBS=1 ZAMMAD=1 $(ONODE_PROD)

Every driver is behind `#ifdef VIRP_DRIVER_*`, so a build without those
flags produces a binary that starts cleanly, signs correctly, and
registers zero drivers. `make` cannot tell the two object sets apart by
timestamp: they have the same file names and differ only in `-D` flags.
Any flagless build in the same `build/` directory silently replaces the
driver-enabled objects, and `make all-tests` is exactly such a build.
Depending on `prod` is what rebuilds them.

**What this cost, 2026-09-07.** A binary built with `make prod`, then
followed by `make all-tests` in the same tree, then copied by hand, ran
on 313 from 16:42:18Z to 17:03:13Z. For those 21 minutes:

* All 39 devices were unreachable. `virp_driver_lookup()` returned NULL
  for every vendor, so the watchdog logged "connecting 39 enabled
  devices" and then made no connection at all.
* Both autopilot ticks alerted, each with two
  `ERROR: no driver for 'wazuh-home'` observations, signed and honest,
  exit 1.
* One real TACACS accounting record from 10.0.0.10 was lost in the
  restart window (see `docs/BACKLOG.md`).

Nothing was silently wrong: the failure was visible in the first tick.
It was also entirely avoidable, and `make install-prod` would have
avoided it.

## Rule 2: check the driver count in the startup log

The daemon logs `[O-Node] Registered N driver(s)` at startup. On this
node N is 13. A restart that logs a different number is a bad build, no
matter what the version string says. Roll back before waiting for a
tick to tell you.

## Post-restart gate

Within 30 seconds of `systemctl restart virp-onode`:

* `systemctl is-active virp-onode` reports `active`.
* The journal carries
  `[Chain] Detached Ed25519 chain signing ENABLED (scheme
  ed25519-detached-v1, key_id c1104805e1044d63a0c531eb7a025e68)`.
  A restart that comes up without this line is signing nothing, and
  every entry it writes lands in the unsigned era. This happened on
  2026-08-23 for 2 minutes 21 seconds and put 15 entries beyond the
  reach of the signature (`docs/notes/SIGNING-WINDOW-2026-08-23.md`).
* `[O-Node] Registered 13 driver(s)`.
* `[O-Node] node_config recorded: build=<version>` names the build you
  intended to install.

Then one autopilot tick (`*:0/5`) must report
`cycle complete: 2 observations, 0 alerts` and exit 0.

Note that `virp_autopilot.py cycle` runs neither `chainwalk` nor
`comparator`. Neither has a timer on this node, and `comparator` is a
no-op here in any case: `/etc/virp/autopilot-node.json` sets
`"peer_device": null` deliberately, because 313 has no peer O-Node. Do
not gate a deploy on a `comparator_verd` record appearing on this node.

## Verifier baseline of record

    virp-tool chain verify --db <snapshot> \
        --key /etc/virp/keys/chain.key \
        --pubkey /etc/virp/keys/chain-sign.pub

    sessions=87 broken=1 unclean=46      exit 1

The single BROKEN session is `autopilot:2026-08-23`, which transitions
signed to unsigned to signed and is BROKEN by design. The 46 unclean
sessions are the UNSIGNED_ERA and SIGNED_FROM_N sessions that predate,
or straddle, the 2026-08-23 signing cutover. Exit 1 here is the expected
result, not a regression.

Take the snapshot with `sudo cp` of `chain.db`, `chain.db-wal` and
`chain.db-shm` into a temp dir, then checkpoint the copy. Never run
sqlite3 against the live database and never checkpoint the live WAL.
