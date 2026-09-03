# TODO — post-consolidation follow-ups

## 1. Re-land chain_append verify-before-append on main — DONE

Landed as fresh, reviewed changes on main (the archive tags
`archive/harden-chain-recut-2026-08-07-2026-08-10` and
`archive/feature/frr-driver-2026-08-10` were reference material only and
were not merged):

- sha256 == artifact_hash verification of submitted bodies — DONE
  (GATE 2 in src/virp_onode.c, constant-time, fail-closed on a body
  that does not decode).
- O-Key HMAC verify of observation bodies — DONE (GATE 3: v1 O-Key
  HMAC, v2 session-HMAC, v3 Ed25519; explicit version dispatch,
  unknown versions refused).
- replay rejection via virp_chain_hash_exists — SUPERSEDED, not
  implemented, by design: re-applying replay rejection on the append
  path would refuse the very message being registered (see the GATE 3
  design note in src/virp_onode.c). The federation duplicate case is
  covered by GATE 5 instead: an id reused with different bytes is
  refused, a byte-identical retry succeeds.

Aug 7 review findings:

- **F2**: fail-open on non-parsing body — CLOSED (GATE 2/GATE 3 refuse
  undecodable and unverifiable bodies; fed_outcome citation scanning is
  fail-closed).
- **F3**: checks keyed on client-supplied artifact_type — CLOSED
  (GATE 1 reserves every daemon semantic type; fed_observation is held
  to the identical signature standard as observation).
- **F4**: TOCTOU — the fix belongs inside the append transaction —
  CLOSED on branch fix/concurrency-evidence-path (2026-08-17): the
  GATE 5 conflict query now runs inside chain_append_locked's own
  BEGIN IMMEDIATE instead of as a pre-append probe, with a
  deterministic concurrency regression test
  (test_chain_fed_id_conflict_check_is_inside_append_txn). Not yet
  running in the installed daemon until the next restart window.

## 2. Tracked-template errors found by the v0.2.1 deploy (2026-09-02)

Both were found by deploying `f269455c` to the reference node and
comparing the tracked template against what the node actually runs.
Neither is fixed; both are recorded in `deploy/devices.template.json`
next to the field they concern.

### 2a. uid 993 (netclaw) — the tracked verb set was never the deployed one

The tracked template proposed
`{session_hello, session_bind, execute, chain_append}` for
`${VIRP_NETCLAW_UID}`, on the stated premise that this is what the
installed `virp-bridge-mcp.py` sends. The node runs
`{list_fleet, health, chain_verify, chain_append, execute}`.

The two sets are **disjoint in four verbs**. The proposal drops
`list_fleet`/`health`/`chain_verify` and grants
`session_hello`/`session_bind`, a grant the bridge has never held. So
this was never a tightening of the deployed set that could be shipped
quietly — it changes a live remote client's reach in both directions.
The deploy therefore kept the node's set and the template now tracks it.

To close: decide the set from what `virp-bridge-mcp.py` on netclaw
actually sends, test the bridge against it, and change the template,
`tests/test_template_uid_policy.py`
(`test_netclaw_matches_the_deployed_verb_set`) and the bridge in one
window. The chain_append TYPE policy is independent and already
correct — 30 days of the node's own chain show 993 appending only
`fed_request`/`fed_observation`/`fed_outcome` since 2026-08-11, when it
entered `socket_uid_action_allow`.

### 2b. wazuh-lab `protected_agents` named the HOME manager's agent ids

The tracked template carried `"protected_agents": ["004","313"]` on
`wazuh-lab`, which is the **colo** manager at 10.0.20.10. Those ids are
the home Wazuh's. Read back from the colo manager through the gate as a
GREEN `GET /agents` on 2026-09-02, it has seven agents and neither id is
among them:

| id | agent |
|-----|-------|
| 000 | wazuh (the manager itself) |
| 001 | pve1 |
| 006 | librenms |
| 007 | pbs |
| 008 | thirdlevel-ai-web |
| 009 | ironclaw-onode |
| 011 | netclaw |

A BLACK never-class list of ids that do not exist protects nothing while
reading as protection, which is worse than an honest omission — so the
deploy kept the node's omission rather than installing the wrong ids.

To close: decide which of the seven real ids belong on the never-class
list and set them. Note the driver compares ids numerically, so `"004"`
and `4` are one agent; the ids above are the colo manager's own
spellings.

### 2c. `make all-tests` no longer completes on the reference node

Not a template error, found in the same window. `tests/test_virp_report.py`
carries a `TestAgainstLiveChain` tier gated on
`os.path.exists("/var/lib/virp/chain.db")`, so it runs by design on a
deployed node. The chain is now 426 MB / 277k entries and the tier burned
30 minutes at 100% CPU without finishing. The suite is therefore
unrunnable as a deploy gate on the one host where it matters most, and it
competes with the daemon for CPU.

Separately, `tests/test_approval.c`'s
`1.1(item3): cache write fails after intent` induces its failure with
`chmod(DIR, 0500)`, which does not constrain uid 0. It FAILS when the
suite is run under `sudo` — the way the install procedure implies — and
PASSES as a normal user. Either bound the test to non-root or induce the
write failure by a means root cannot bypass.

## 3. `install-prod`'s dirty-tree guard is a no-op on a user-owned tree (2026-09-03)

**Deliberately NOT fixed in the deployed-state merge.** It is the same
fail-open shape as any guard that reads empty output as a safe state, and
it deserves a test rather than a patch written at the end of a deploy.
Its own branch.

`install-prod` refuses to install from a dirty tree:

    @st=$$(git status --porcelain 2>/dev/null); \
     if [ -n "$$st" ]; then ... exit 1; fi

On virp-lab the deploy tree is `/opt/virp`, root-owned, and `sudo make
install-prod` runs git as its owner, so the guard works. On
virp-onode-home the tree is `/home/nhoward/virp`, owned by a normal user.
Under `sudo`, git refuses the repository for dubious ownership, writes
its complaint to **stderr**, and exits non-zero with **empty stdout**.
`2>/dev/null` discards the complaint, `$$st` is empty, and the guard
concludes the tree is clean.

So on any node whose deploy tree is not owned by the installing user, the
check that exists to guarantee "what gets deployed is exactly what a
commit hash names" passes unconditionally — including when the tree is
genuinely dirty. It reads as a strong check and is a no-op precisely
where a non-`/opt` layout puts it.

Worked around during the 2026-09-03 home-node upgrade with

    sudo git config --global --add safe.directory /home/nhoward/virp

which makes the guard real again on that node, and is a per-host
mitigation, not the fix.

**To close.** The guard must distinguish "git said nothing because the
tree is clean" from "git said nothing because it failed". Capture the
exit status, not only the output; a non-zero git is a hard failure, not
a clean tree. The same pattern appears anywhere else `$(git ... 2>/dev/null)`
is tested for emptiness — audit for it rather than fixing this one site.
And it needs a **test**: a fixture with a deliberately dirty tree owned
by another uid, asserting install-prod refuses. A guard that has never
been observed to fail is indistinguishable from one that cannot, which is
the argument this repo already makes for every other checker's
`--selftest`.
