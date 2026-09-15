# VIRP service uid registry

Every service identity that can reach an O-Node socket, across the three
nodes that run one, and what the number means on each. The O-Node gates by
**SO_PEERCRED uid**, so a number is the identity; the same number meaning
two different things on two nodes is drift, and it is recorded here rather
than hidden.

Sources (2026-09-14): `getent passwd` on virp-lab (10.0.10.211) and
virp-onode-home (10.0.0.13); `deploy/devices.template.json` (colo) and
`deploy/devices.home.template.json` (home); netclaw (10.0.30.30) was **not
reachable** when this was written — its column is from the templates and
the 2026-08 notes, marked unverified.

## Rule

- A uid is allocated **once, estate-wide**, even when only one node creates
  the account. Reserve before you create.
- Templates carry service uids as **literals** (not `${...}` placeholders)
  unless `deploy/render-devices.sh` already resolves the name: the render
  FATALs on an unknown placeholder, and that script only ships with
  `make install-prod`.
- uid 0 is never allowlisted. 1000 is the interactive operator on every node.
- Off-limits for VIRP: **986** (is `virp`'s *gid*, not a uid), **991**
  (systemd-resolve), and the distro's own 989/990/996/998.

## Registry

| uid | virp-lab (.211, colo) | virp-onode-home (313) | netclaw (10.0.30.30) | Notes |
|----:|---|---|---|---|
| 999 | `virp` — daemon service account | `virp` — same | `virp` (unverified) | Full wire vocabulary except `shutdown` |
| 998 | systemd-network | systemd-network | — | distro |
| 997 | `virp-backup` — config-backup collector (`execute`, `chain_append`) | `virp-spark` — Spark camera/detection relay | — | **DRIFT: same number, two identities** |
| 996 | systemd-timesync | systemd-timesync | — | distro |
| 995 | `virp-evidence` — compliance-evidence collector | `virp-capture` — chrooted sftp camera capture | — | **DRIFT: same number, two identities** |
| 994 | `virp-broker` — Stage-1 intent broker relay | *free* | — | .211 only |
| 993 | `virp-netclaw` — remote requester for netclaw's bridge | `virp-netclaw` — same role | local O-Node's requester (unverified) | consistent |
| 992 | **reserved** for `virp-tacacs` (not created) | `virp-tacacs` — TACACS+ accounting receiver | — | 313 only today; do not reuse |
| 991 | systemd-resolve | systemd-resolve | — | distro — never allocate |
| 990 | fwupd-refresh | fwupd-refresh | — | distro |
| 989 | polkitd | polkitd | — | distro |
| 988 | **`virp-shell`** — operator REPL seat (`list_fleet list_sessions health heartbeat chain_verify execute`, GREEN — config mode proposes, never applies; `list_sessions` only once the daemon on `feat/onode-list-sessions` is deployed) | *free — reserved for the same identity* | — | new 2026-09-14; the older "reserved for Spark" note in the colo template was wrong (Spark is 997 on 313) and is corrected there |
| 985 | **`virp-shell-admin`** — the shell's `enable` seat (same verbs as 988, ceiling **YELLOW**: YELLOW changes apply, RED still proposals; reached only via the sudo PASSWD rule in `deploy/sudoers-virp-shell`) | *free — reserved for the same identity* | — | new 2026-09-15 |
| 987 | `virp-sean` — Sean's agent-VM requester (`chain_verify`, `chain_append`→`evidence_item`) | *free — reserved for the same identity* | — | .211 only |
| 1000 | operator (nhoward) | operator | operator | full vocabulary incl. `shutdown` |
| 1001 | — | `virp-laptop` — forward-only approver identity (laptop → 313 socket) | — | 313 only |

## Known drift (do not "fix" by renumbering without a ruling)

1. **987 and 994 exist on .211 only.** Expected: sean-agent and the broker
   are colo services. 313 keeps those numbers free for them.
2. **992 exists on 313 only** (`virp-tacacs`). .211 reserves it; the colo
   TACACS receiver, when it lands, must use 992.
3. **997 and 995 collide**: `virp-backup`/`virp-evidence` on .211 versus
   `virp-spark`/`virp-capture` on 313. Each node's template is internally
   right, so nothing is mis-gated today — but a template copied between
   nodes would silently hand the backup collector's verbs to the Spark
   relay. Any future shared template must renumber one side first.
4. **netclaw's own O-Node is stale** (27c07883, ~183 commits behind .211)
   and its account table was not verified for this document.

## How a new identity is added

1. Pick the next free number in **both** columns above and add the row here
   (same commit as the template change).
2. `useradd --system --uid N -g virp --shell /usr/sbin/nologin NAME` on the
   node(s) that run it. Group `virp` gives socket reach through the socket's
   group bits; identities outside the group need an `*-access.sh`
   ExecStartPost ACL grant (see `deploy/sean-access.sh`).
3. Template: `socket_allowed_uids` + `socket_uid_tier_ceilings` +
   `socket_uid_action_allow` (+ `socket_uid_chain_append_types` if it may
   append) — all in one commit, or the daemon refuses to start.
4. A test that pins the verbs the client actually sends
   (`tests/test_template_uid_policy.py`, or a client-specific one such as
   `tests/test_virp_shell.py`).
