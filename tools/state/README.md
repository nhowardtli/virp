# Deployed state, as an observation

What is running on a node used to live in `DEPLOYED.md` prose and in an
operator's head. That was wrong three times, and every time it was found
by accident:

- a stale ssh alias made a session declare the colo unreachable — the
  live node is `10.0.10.211`, and `ct211` / `ironclaw-onode` still point
  at the decommissioned `10.0.0.211` in the same config file;
- a 43-device fleet existed only on the box and never in the repo;
- the tracked template said nine devices, for a month, while the box ran
  forty-three.

None of those were caught by a check. They were caught by someone
tripping over them. These three files are the attempt to make that class
of surprise into scheduled, signed evidence instead.

    tools/state/deployed-state.sh    observes  — runs on a node, reads it,
                                                lands what it saw on the chain
    tools/state/drift-check.sh       judges    — reads documents and git,
                                                never touches a node
    deploy/keys/registry.json        remembers — every key, id derived from
                                                its own bytes
    scripts/check-key-registry.sh    enforces  — that the ids are derived

This is a reporter, not a config-management system. Nothing here
converges anything, and nothing here has an opinion about what a node
*should* be running that it did not read out of git.

---

## What the reporter observes

`deployed-state.sh --collect` emits one `deployed_state/1` JSON document:

| | |
|---|---|
| node | hostname, node_id |
| unit | path, sha256, every drop-in's name and sha256 |
| daemon | installed sha256, **running** sha256 from `/proc/<pid>/exe`, the comparison stated outright, pid, start time |
| client | `virp-tool` path, sha256, self-reported build id |
| deploy tree | path, rev, describe, branch, dirty flag and count, which locally-known remote refs contain HEAD, when those refs were last fetched |
| device config | path, sha256, rendered-or-static, template path and sha256, **device count** |
| gate | mode, max tier, `evidence_required`, per-uid ceilings, and whether the daemon attested them |
| identities | socket allowlist uids, enrolled approver key_ids |

Every path it reports is derived from the unit, never hardcoded. The two
live nodes already disagree about where the device config lives —
rendered at `/run/virp/devices.json` on the colo node, static at
`/etc/virp/devices.json` on the home node — and a reporter that assumed
one shape would have reported the other node confidently and wrongly,
which is the failure being fixed.

### Two grades, marked per fact

The document does not present everything it knows as equally trustworthy.

**`attested`** — the daemon minted these about *itself*. `build_id`,
gate mode, max tier, `evidence_required` and the per-uid ceilings all
appear in the daemon's own `node_config/1` chain entry, written at
startup under a reserved artifact type that GATE 1 forbids any socket
client from submitting. Where such an entry exists the document **cites
it by hash** instead of restating the values as its own claim.

**`reported`** — everything else. Read off the node's filesystem by a
shell script. `GATE 2` binds the submitted body to its declared hash and
the chain entry carries the node's `K_chain` HMAC and its position in
the hash chain. That proves the daemon received *these exact bytes at
this position at this time*. It proves nothing about whether they are
true.

On the colo node the gate block is attested. On the home node it is not:
that daemon predates `node_config/1` entirely, so `gate.attested` is
`false`, the reason is spelled out in the document, and every gate value
there is labelled as an unattested file read.

### What it refuses to read

Hashes and identifiers only. It counts the devices without reading one —
the count is `len(devices)` and the list is dropped before any code that
could emit an entry. It reads `approvers.json` for key_ids and never
emits key bytes. It never opens `/etc/virp/autopilot.env`, and the unit
sets `InaccessiblePaths` on it so that is structural rather than merely
true of the code as written.

### Why collect and submit are separate invocations

They need different identities and neither can do the other's job.

**Collection needs root.** The daemon sets `PR_SET_DUMPABLE=0` as a
key-exposure mitigation, which makes `/proc/<pid>/exe` unreadable to
every uid but root — the daemon's *own* uid included; uid 999 gets
`EACCES` on its own process. The running-binary hash, the single fact
that exposes a rollback hiding behind a current binary on disk, is
root-only as a direct consequence of a mitigation we want.

**Submission must not be root.** uid 0 is deliberately excluded from
`socket_allowed_uids`; a root client is refused at the peercred gate.

So the unit runs collection under systemd's `+` prefix and submission as
the service user — the idiom `virp-onode.service` already uses for its
`ExecStartPre` render step. Both halves refuse the wrong identity with a
message that says which one they wanted and why.

### Why no new gate classifier row was added

None was needed, and none should be. The driver classifier governs
commands the O-Node runs against a **device**. This reads its own node
locally and submits over `chain_append`, authorised by
`socket_uid_action_allow` / `socket_uid_chain_append_types`, which never
enters the classifier at all.

That matters because the `linux` driver's GREEN surface carries an
argued hold (2026-08-13): *"THE LIST IS NOT GROWING… Adding generic host
shell changes the job description… That is no longer 'know the Proxmox
API'; it is 'police arbitrary Linux'."* Not one fact in the document is
reachable through that surface — `cat` as a general verb is deliberately
RED — so the version of this tool that worked through the gate would
have required exactly the rows that hold says not to add. It works
around the outside instead, and the hold stays intact.

### Why `evidence_item` and not `observation`

`artifact_type="observation"` **with a body** must carry a v1/v2/v3
signature (GATE 3). v1 is HMAC under the O-Key, which is the daemon's
and not the reporter's, so an `observation` submission could only be
*commitment-only* — the document would not be on the chain, only its
hash, and every reader would correctly grade it UNVERIFIABLE.

A purpose-built `deployed_state` type would mean editing the fixed C
array in `virp_chain_type_is_external_allowed()`, rebuilding, and
redeploying the daemon on every node — far past "build a reporter".

`evidence_item` is already externally allowed, takes a plain-JSON body
with no signature requirement, and is honest: a state document is
evidence. The `schema` field inside the body is what makes it findable
as a deployed-state document. This requires `evidence_item` in the
daemon uid's `socket_uid_chain_append_types` — added to
`deploy/devices.template.json` with the reasoning beside the key, **not
yet on any box**.

---

## What the checker judges

`drift-check.sh --state DOC [--previous DOC] [--ref REF]` reads a
document and git objects. It has no ssh, no socket, no node.

That separation is load-bearing rather than tidy. A checker that must
reach a box can only run where the box is reachable, and it inherits the
box's availability, its credentials, and its ability to lie to whoever
asks. This one runs on a laptop, in CI, or later against a bundle — and
against a document from a node that has since been rebuilt or destroyed.

It reads git **objects**, never a working tree, including
`unit-manifest.txt` as of the ref, so the tracked-to-installed mapping
does not shift with whatever branch happens to be checked out.

**It never fetches.** A judgement that silently mutates the repo it
judges from is not a judgement. The ref is read as the clone already
knows it, and the ref's own sha and fetch time print with every verdict
so staleness is visible instead of assumed.

### Exit codes

| | |
|---|---|
| `0` | every comparison ran, nothing drifted |
| `1` | **drift** — running binary ≠ installed, dirty deploy tree, or the device count moved (against the tracked template, or against the previous document) |
| `2` | usage, or an input that could not be read |
| `4` | **incomplete** — nothing drifted, but a comparison could not be made |

Exit 1 is reserved for the three conditions that have actually bitten
this system. Everything else prints as INFO and does not change the exit
code: being 22 commits behind `origin/main` is a normal state for a
node, and an alarm that fires on normal states stops being read.

Exit 2 is deliberately distinct from 1, because a CI gate has to tell
"the node moved" from "you handed me the wrong file".

**Exit 4 exists because "clean" and "I could not check" must never print
the same thing.** This repo has already run a unit-drift check that
passed green for eight days while the installed unit said the opposite
of the tracked one, because the check read only the file in git. The
home node trips exit 4 today: its device config has no tracked template,
so its fleet size cannot be compared against anything, and the checker
says so rather than reporting clean.

The checker also re-derives `running_matches_installed` instead of
trusting the flag, so a document whose flag disagrees with its own
hashes is caught as its own finding.

---

## What the registry remembers

`deploy/keys/registry.json` holds every asymmetric key the system trusts
or has trusted, with `key_id = SHA-256(raw public key)[0:16]` **derived
from the bytes in the file**, never copied from a declaration.
`scripts/check-key-registry.sh` (via `make check-key-registry`) fails if
any id does not derive, if an id appears twice, or if an entry is
missing a field — and self-tests against seven mutations of the real
file first, because a check that cannot fail is indistinguishable from a
clean file.

It is **append-only**. A receipt, approval or chain head signed under a
retired key must stay verifiable; a verifier that cannot find the key it
needs reports UNVERIFIABLE rather than "signed by nobody". Retiring is a
status change plus an appended note, never a deletion.

The motivating case is in it: two distinct Ed25519 keys both commented
`claude-code@ct211`, from a build host that no longer exists, now
`d74c7e02` and `bc3f27db` and no longer confusable.

---

## What none of this can see

This is the part worth being blunt about.

### A signed state document proves what the box reported about itself

It does not prove the box is honest.

An attacker with root on the node can hand `deployed-state.sh` whatever
they like — patch the script, `LD_PRELOAD` its `sha256sum`, mount
something else over `/proc`, or simply write the JSON by hand and
submit it. The chain will accept those bytes, hash-bind them, HMAC them
under `K_chain`, and place them in an unbroken hash chain. The result is
a **faithfully and verifiably chained lie**, and it will look exactly
like a true document to every reader.

The `attested` grade narrows this a little and does not close it. The
daemon's `node_config/1` entry is minted by the daemon, under a reserved
type a socket client cannot forge, so a client-side liar cannot fabricate
one — but root on the node owns the daemon too.

**This closes the accident case, not the adversary case.** The
accidents were real, repeated, and expensive, and a scheduled signed
report ends them. Saying that plainly is the point: a tool that hints at
tamper-evidence it does not have is worse than one that has none,
because the next person will rely on it.

The one thing the chain genuinely adds against an adversary is that
lying **consistently over time** is harder than lying once. Each
document is chained in sequence, the witness holds heads off-box, and a
retroactively edited history has to survive comparison against both.
That is a real property. It is much weaker than "the box is honest", and
it is not a substitute for it.

### Other blind spots, named

- **The document is not verified to be the one on the chain.** The
  checker judges a *file*; whether that file is the one the daemon
  committed to is a separate lookup. `drift-check.sh` prints the
  document's sha256 and its `depstate-<first16>` artifact id so a reader
  can do it — and does not do it itself, because that would mean reading
  a chain, which means reaching a node.
- **`matches_known_remote_ref` is a local answer.** It says HEAD is
  contained in a ref this node has fetched at some point, not that it
  matches `origin` right now. The fetch timestamp travels with the claim
  precisely so nobody reads it as the stronger statement.
- **The rendered device config is compared as a whole hash.** Nothing
  checks that rendering the tracked template with the node's own
  credentials reproduces that hash. A template edit that changes only a
  credential is invisible here, by design — checking it would mean
  reading the credential store.
- **A node role sharing an installed path reads as drift.**
  `unit-manifest.txt` maps one tracked file per installed path, so the
  home node's differently-roled unit reports as differing from tracked,
  and the checker cannot distinguish that from a genuine drift. The
  finding text says so where it appears.
- **The registry cannot check its own completeness.** Nothing inside a
  file can know about a key nobody wrote down. That is the failure mode
  the registry *reduces*; it is not one it can detect from the inside.
  Completeness is re-earned by sweeping the hosts.
- **Symmetric keys are absent from the registry** and named as absent.
  `onode.key` and `chain.key` have no public half; an id for them under
  this scheme would be a hash of a live secret sitting in git.
- **Nothing here watches the watchers.** If the timer stops firing, the
  gap in the document series is the only signal, and only if somebody
  looks. `Persistent=true` means a node that was down reports on next
  boot, so a gap should mean "the node was down" rather than "the timer
  shrugged" — but no alarm fires on a missing document.

---

## Running it

    # on a node — root, because /proc/<pid>/exe is
    deployed-state.sh --collect --out /var/lib/virp/state/deployed-state.json

    # on a node — as the service user, because uid 0 cannot reach the socket
    deployed-state.sh --submit  --in  /var/lib/virp/state/deployed-state.json

    # anywhere with the repo and the documents
    drift-check.sh --state today.json --previous yesterday.json
    drift-check.sh --state today.json --ref origin/main --json

    make check-key-registry

`deploy/virp-deployed-state.{service,timer}` run the first two daily.
They are tracked and listed in `unit-manifest.txt`, and **installed on
no node**. They were listed before being deployed on purpose: "the unit
exists only on the host" is the condition that hid the netclaw egress
ruleset, and a manifest that only learns about a unit when someone
remembers to add it is the same check that passed green for eight days.

`PHASE0-FINDINGS.md` beside this file is the read-only survey these
tools were built from — eleven divergences between the two live nodes
and `origin/main` as of 2026-09-02, including three that are still open.
