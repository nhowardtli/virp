# Where VIRP's binding starts and stops

For someone building an authorization layer above VIRP. This says exactly which
bytes are covered by a hash or a signature, and which facts the daemon knew at
that moment and did not cover. Read only; every claim carries file:line. Where
two paths disagree, both are named.

## 1. The objects

**Chain entry.** `build_canonical_json` (`src/virp_chain.c:1133-1160`) emits
twelve fields, alphabetical, compact: `artifact_hash`, `artifact_hash_alg`,
`artifact_id`, `artifact_schema_version`, `artifact_type`, `monotonic_ns`,
`previous_entry_hash`, `sequence`, `session_id`, `signer_node_id`,
`signer_org_id`, `timestamp_ns`. Over exactly those bytes:
`chain_entry_hash = sha256(canonical)` (`:2007`),
`chain_hmac = HMAC-SHA256(K_chain, canonical)` (`:2013-2018`), and with `-S` a
detached Ed25519 signature under tag `VIRP-CHAIN-ENTRY-SIG-v1`
(`:2029-2038`), stored beside the entry and never inside it.

Outside those bytes, and known to the daemon at append time: the artifact body
itself (only its `artifact_hash` is covered), `chain_sig` and
`chain_sig_key_id`, the connecting uid, the classified tier, the driver, and
the device hostname. The body is bound only through `artifact_hash`, which is
why the body-side gates below matter.

**Proposal** (`include/virp_approval.h:72-83`): `proposal_id`, `session_id`,
`device`, `device_node_id`, `command`, `command_hash`, `proposer`,
`timestamp_ns`, `tier`, `chain_entry_hash`. The record is a file; what binds
downstream is `command_hash`.

**Approval.** The approver signs a 72-byte canonical payload
(`src/virp_approval.c:184-199`): 4-byte magic, `proposal_id` (16),
`command_hash` (32), `device_node_id` (8), `approved_at_ns` (8),
`ttl_seconds` (4). Nothing else. `device` (the hostname string),
`approver_key_id`, `operator` and `session_id` are all outside the signature
(`include/virp_approval.h:85-96`).

**gate_intent/1** (`src/virp_onode.c:1243-1285`): `schema`, `device`,
`driver`, `command`, `classified_tier`, `gate_max_tier`, `effective_max_tier`,
`ceiling_source`, `gate_mode`, `decision`, `uid`, `session`, `proposal_id`,
`approval_entry_hash`, `proposal_entry_hash`. This body is the one place the
tier decision and its ceiling source are recorded. It is covered by
`artifact_hash` like any other body.

**Outcome** (`src/virp_onode.c:850-861`): `proposal_id`,
`proposal_entry_hash`, `approval_entry_hash`, `device`, `command_hash`,
`success`, `intent_entry_hash`.

**Observations.** `obs_version` selects the path
(`include/virp_onode.h:642-666`). v1 is a v1 wire message under the static
master O-Key. v2 is an 88-byte header plus payload plus 32-byte signature
under an HKDF-derived session key; the header binds `session_id`, `device_id`,
`seq_num`, `timestamp` and `sha256(canonical command)`. v3 is Ed25519
(`src/virp_obskey.c`), and the daemon's only use of that key is verification
(`include/virp_onode.h:187`). One gap stated in source: error observations
(device not found, connect failure, tier-gate rejection) are still emitted as
v1 even when the caller asked for v2 (`include/virp_onode.h:660-665`).

**fed_request, fed_observation, fed_error, fed_outcome.** These bodies are
built by the bridge, not this tree. To the daemon they are `artifact_content`
plus a declared `artifact_type`; the chain binds them exactly as it binds any
other body, through `artifact_hash`. `fed_error` is a commitment type
carrying no signature and claiming none.

## 2. The exclusions

**Device hostname.** The approval signature covers `device_node_id`, not the
`device` string, and verification compares the unsigned string
(`SECURITY.md:143-149`). `device_node_id` was degenerate when first audited,
5 of 7 lab devices loading `node_id == 0` (`SECURITY.md:1546-1549`); that is
narrowed now, but the signature still does not say what the comments in
`src/virp_approval.c` claim. Widening it needs the canonical-format window
(`docs/DRAFT07-NOTES.md`). Still open.

**Timestamps.** Three different clocks, and only the first is in the chain's
own canonical bytes. `timestamp_ns` and `monotonic_ns` are the daemon's
(`src/virp_chain.c:1143,1145`). `approved_at_ns` is the approver's, inside the
72-byte payload, so it is signed by the approver and not by the daemon.
Device-asserted time is not carried at all at this layer.

**Raw body versus its hash.** `artifact_content` is `char[8192]`
(`src/virp_onode.c:77`); a body at or past that is refused rather than stored
truncated (`include/virp_chain.h:29`). Two consequences. First, GATE 2 and
GATE 3 are both inside `if (req.artifact_content[0] != '\0')`
(`src/virp_onode.c:4089`), so a commitment-only append skips both: GATE 3 is
skipped as a side effect rather than by decision, and a client can cite any
64-hex string as an unsigned observation. Second, the indirect types
`comparator_verdict` and `chainwalk_summary` commit to a signed observation
the chain does not retain, so `sha256(body) != artifact_hash` by design and
the entry cannot be bound from inside the chain
(`src/virp_chain.c:628-636`, `include/virp_chain.h:170-181`). The truncated
spellings in that list (`comparator_verd`, `chainwalk_summa`) exist because
`artifact_type` is `char[16]` (`include/virp_chain.h:46`). The documented fix
is an explicit `commitment_mode` field inside the canonical object, deferred
to the same format window.

**Approver identity.** `approver_key_id` and `operator` are outside the signed
72 bytes. You can tell which key verified an approval only from the unsigned
record beside it.

**Session identity.** The bridge derives `ncfed-<user>-<host>` from
`SUDO_USER` and the hostname. The daemon applies per-uid policy but does not
derive or sign the session owner: the `SO_PEERCRED` plumbing exists
(`include/virp_onode.h:284,705,737`) and `client_uid` reaches the gate, but no
signed owner field exists, so uid 993 can assert any `session_id`.
`bridge_instance` is a body field only.

**Tier decision and policy provenance.** The decision is recorded, in the
`gate_intent` body above. The policy that produced it is not: there is no
policy, registry or device-template digest anywhere in the signed bytes
(grep for `policy_digest|registry_digest|template_sha` returns nothing). Two
runs under different `devices.json` are indistinguishable from the chain.

## 3. One approved RED action, end to end

`command_hash` is the spine. The proposal records it; the approver signs it
inside the 72 bytes together with `proposal_id`, `device_node_id`,
`approved_at_ns` and `ttl_seconds`; the `gate_intent` cites
`approval_entry_hash` and `proposal_entry_hash` (`src/virp_onode.c:1282-1294`)
and is the record that consumes the approval, with `approval_entry_hash` as
the apply-time replay key (`include/virp_chain.h:574`); the outcome then cites
`intent_entry_hash`, `approval_entry_hash`, `proposal_entry_hash` and
`command_hash` again.

An attacker changing the payload after approval must produce a different
command with the same SHA-256. Changing the target device is cheaper: the
hostname string is unsigned, so the binding it must defeat is only
`device_node_id`.

Not prevented. A compromised O-node holds `K_chain` and, with `-S`, the
chain-signing key, so it can mint entries at will; the detached signature
proves the node signed, not that the node was honest. And uid 993 can forge
`session_id`, because nothing derives it from the socket peer.

## 4. The seam for an upstream authorizer

VIRP takes nothing from an agent-layer receipt today. Identity arrives as
`SUDO_USER` on the bridge and reaches the daemon only as a `session_id` string
the caller chose. There is no slot inside any signed canonical form for an
upstream authorization decision; the nearest carriers are unsigned or
body-level: the `gate_intent` body's `session` and `uid` fields, and the
federated body fields. What VIRP will never take from the model is identity
itself: the Sep 3 fix removed `peer` and `request_id` from the MCP tool schema
after `gpt-oss:120b` invented the session `ncfed-user-session-req-001` and the
bridge signed it onto the chain (`nhowardtli/netclaw-virp-bridge` `31ffbd05`,
with `TestBridgeInstance` and the identity tests pinning it). Any receipt you
pass must land in a field the model cannot write, and no such field is signed
yet.

## 5. The BLACK backstop

Three drivers return BLACK from the classifier, so the O-Node gate refuses
before any connection: PAN-OS (`src/driver_panos.c:268`), ASA
(`src/drivers/driver_asa.c:147-151`, `:190`) and JunOS
(`src/drivers/driver_juniper.c:107-112`, `:175`). Two top out at RED in the
classifier and rely on a driver-local backstop at execute time: Cisco
(`src/drivers/driver_cisco.c:528`, `:693`, backstop `:1154`) and FortiGate
(`src/drivers/driver_fortigate.c:775`, backstop `:797`).

The difference is what the chain shows. A classifier BLACK is refused at the
gate (`src/virp_onode.c:1583` refuses to file a proposal at all, `:2188`
refuses the execute), so the record is a gate refusal and no device was
touched. An execute-time BLACK classifies RED, which is proposable and
approvable, so the chain can show a proposal, an approval and a `gate_intent`
for a command the driver then refuses locally. Same outcome for the device,
different evidence.

**Two paths disagree here.** `SECURITY.md:1550-1553` says SHADOW does not
honour BLACK because "both blocking branches are gated on ENFORCE". The BLACK
branch at `src/virp_onode.c:2188` is not gated on mode; the `ENFORCE` test is
the next branch (`:2196`), and the comment above it says BLACK is "refused
under SHADOW rather than leaving that to be inferred from an absence". The
code is the stricter of the two. Treat SECURITY.md §4.7 as stale for the BLACK
branch specifically.
