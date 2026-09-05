# TACACS+ accounting as a VIRP observation source

**Status:** design + lab-only implementation. NOT deployed to
`virp-onode-home` (313) or `virp-lab` (.211), and nothing in this
document changes either node.

**Scope of v1: ACCOUNTING ONLY.** VIRP listens as a TACACS+ server
(RFC 8907) and serves the accounting session type. It does **not**
serve authentication and does **not** serve authorization. A device
pointed at VIRP for `aaa authentication` or `aaa authorization` will be
refused at the packet type, not partially handled — see
[Refusal of non-accounting types](#refusal-of-non-accounting-types).
This matters operationally: an accounting server that fails does not
block commands, whereas an authorization server that fails can lock an
operator out of a device. v1 deliberately takes only the job whose
failure mode is "evidence is missing", never "the network is down".

**v2 adds authorization, and this paragraph is why it applies to the
GATE's identities only.** `virp-ro` and `virp-rw` fail closed when the
TACACS+ server is unreachable; humans never do, because the reasoning
above still holds for them. See §9.1 for the resolution and §9.3 for the
measurement that rules out a network break-glass path.

---

## 1. What this source is, and the boundary on the report face

A device configured to send command accounting to VIRP delivers one
TACACS+ accounting packet per command event. Each received packet
becomes one chain-signed `tacacs_accounting/1` record containing
exactly what arrived.

Every report face that renders these records carries this sentence, and
the record carries the fields that back it:

> Received on the configured AAA relationship for device X and signed
> at receipt. The shared secret obfuscates the body and authenticates
> possession of the secret; it does not prove physical origin.

That is the whole claim. Spelled out, because the gap between it and
what a reader wants it to say is where this kind of evidence gets
oversold:

| What a receipt DOES establish | What it does NOT |
|---|---|
| These bytes arrived at this VIRP node, from this source address and port, at this receive time | That they were emitted by the physical device that owns that address |
| The sender held the shared secret configured for that AAA relationship | That only that device holds it — a secret is a bearer credential, copyable, and typically identical across a device group |
| The body decoded under RFC 8907 §4.5 obfuscation with that secret | That the body was *encrypted*. It was not. RFC 8907 §10.1 is explicit that the MD5 pad is obfuscation, cryptographically weak, and not a substitute for a secure transport |
| VIRP signed the record at receipt, so it is unaltered since | Anything about the interval between the operator's keystroke and the packet leaving the device |
| The record's `client_identity` is the label VIRP was configured to use for that source | That the label is correct. It is configuration, restated — see below |

**`client_identity` is a configured label, never a measurement.** VIRP
maps a source address to a device name from its own config. The record
carries `client_identity_source` naming how the mapping was made, and
the vocabulary is closed:

| value | meaning |
|---|---|
| `configured_by_source_address` | matched a configured relationship on source IP |
| `unconfigured_source` | no relationship configured for this source; `client_identity` is `null` |

An `unconfigured_source` packet is **still recorded**, and this is
deliberate. A device that appears on the wire and was never enrolled is
exactly the fact an operator needs; dropping it because it is unknown
would destroy the only evidence that it happened. What VIRP will not do
is *guess* a name for it.

**No reverse DNS, ever.** A PTR lookup would make the record depend on
a name service that is not under evidentiary control and can change
between receipt and reading. The address is the fact.

### What replay protection there is (little)

TACACS+ carries no timestamp inside the accounting body that VIRP can
authenticate, and no nonce. Within one TCP connection the `session_id`
and `seq_no` order packets, and VIRP records both. Across connections,
a party holding the secret can replay a captured packet and VIRP will
produce a valid receipt of that replay. The receipt would be a truthful
record of what arrived — VIRP's own `recv_utc_ns` would show the replay
time — but the record cannot, alone, distinguish a replay from a fresh
event. Stated here rather than implied away.

### Refusal of non-accounting types

The TACACS+ header's `type` byte names the session type:
`TAC_PLUS_AUTHEN` (0x01), `TAC_PLUS_AUTHOR` (0x02), `TAC_PLUS_ACCT`
(0x03). v1 serves 0x03 only.

An `AUTHEN` or `AUTHOR` packet is **refused at the type byte, before
the body is decoded**, and the connection is closed. VIRP does not
reply with a partial or a permissive status, because either would be a
lie about a service it does not implement — and a permissive
authorization reply from a server that implements no authorization is
the worst possible failure in this whole design.

The refusal is itself recorded: an operator who has mistakenly pointed
`aaa authentication` at VIRP needs to see that, and the device's own
behaviour (falling through to the next method) will otherwise mask it.
The record is a `tacacs_accounting/1` with `parse: MALFORMED`? **No** —
that would abuse a vocabulary that means something else. It is a
separate counter in the receiver's ledger, reported with the run, and
carried into the reconciliation record's coverage section. A wrong
session type is a configuration fact, not a malformed packet, and the
two are not merged.

An unknown type byte (anything but 0x01/0x02/0x03) is counted
separately again, as `unknown_session_type`.

---

## 2. `tacacs_accounting/1` — the receipt

**Rule: exactly what arrived, nothing else.** The receipt is a
transcription. It performs no normalization, resolves no names, applies
no policy, and reaches no conclusion. Everything interpretive lives in
`tacacs_reconciliation/1` (§3), which is written later, by a different
component, and never touches the receipt.

### Field set

```json
{
  "schema": "tacacs_accounting/1",

  "receiver_node": "virp-tacacs-lab",
  "receiver_local_addr": "192.168.122.1",
  "receiver_local_port": 49,

  "source_addr": "192.168.122.50",
  "source_port": 51314,

  "recv_utc_ns": 1757030400123456789,
  "recv_monotonic_ns": 884412339006112,

  "client_identity": "R1",
  "client_identity_source": "configured_by_source_address",

  "tacacs_version_major": 12,
  "tacacs_version_minor": 0,
  "tacacs_seq_no": 1,
  "tacacs_session_id": 305419896,
  "tacacs_flags_raw": 0,
  "tacacs_unencrypted": false,
  "tacacs_single_connect": false,

  "acct_flags_raw": 2,
  "acct_flags": ["START"],

  "authen_method_raw": 6,
  "authen_method": "TACACSPLUS",
  "priv_lvl": 15,
  "authen_type_raw": 1,
  "authen_type": "ASCII",
  "authen_service_raw": 1,
  "authen_service": "LOGIN",

  "user": "aiops-svc",
  "port": "tty2",
  "rem_addr": "192.168.122.1",

  "arg_cnt": 6,
  "args": [
    "task_id=7",
    "timezone=UTC",
    "service=shell",
    "priv-lvl=15",
    "cmd=show",
    "cmd-arg=version"
  ],
  "args_index": {
    "task_id": "7",
    "service": "shell",
    "lookup_rule": "first_occurrence_verbatim",
    "duplicates": []
  },

  "raw_body_len": 118,
  "raw_body_sha256": "9f2c…",

  "decode": "OBFUSCATED_MD5",
  "parse": "COMPLETE",

  "producer_sig": "…"
}
```

### Three clocks, never collapsed

The same discipline the camera driver applies (`camera/README.md`):

- `recv_utc_ns` — the VIRP receiver's wall clock at receipt. **This is
  the only time VIRP measured.**
- `recv_monotonic_ns` — the receiver's monotonic clock at the same
  instant. Present because wall clock can step; ordering between two
  receipts on one receiver run is answerable from this even when
  `recv_utc_ns` is not.
- Any time inside `args` (`start_time=`, `stop_time=`, `elapsed_time=`)
  — **the DEVICE's clock**, carried verbatim inside `args` and
  deliberately *not* promoted to a top-level field. A device with a
  wrong clock, or no NTP, writes a wrong `start_time`, and the receipt
  must not launder that into something that looks like VIRP's
  measurement.

### `args` is verbatim, and that is load-bearing

`args` is the ordered list of argument strings as they arrived, byte
for byte: no case folding, no `=`/`*` separator interpretation, no
unescaping, no de-duplication, no reordering. Cisco splits a command
across `cmd=` and repeated `cmd-arg=` arguments; reassembling those into
one command string is an *interpretation*, and it belongs to the
reconciler, not the receipt.

`args_index` is a **convenience lookup into `args`, not a second source
of truth.** Its values are byte-identical to the arg they came from,
selected by first occurrence. If an argument name appears more than
once, every occurrence is listed in `duplicates` and the reader is
expected to go to `args`. It exists so a reconciler can find `task_id`
without re-implementing the split; it never carries a value `args` does
not.

### `decode` and `parse` — closed vocabularies, never omitted

Both fields are always present. A record that omitted them would let a
verifier testing `if "decode" in body` read a failure as a success —
the same trap `camera/README.md` documents for `sensor_signature`.

| `decode` | meaning |
|---|---|
| `OBFUSCATED_MD5` | body was obfuscated per RFC 8907 §4.5 and the pad was applied with the configured secret |
| `CLEARTEXT` | the header's `TAC_PLUS_UNENCRYPTED_FLAG` was set; the body arrived unobfuscated. Recorded as the fact it is — this is a device misconfiguration worth seeing, not an error to swallow |
| `NO_SECRET_CONFIGURED` | packet from a source with no configured secret; body retained raw and hashed, not decoded |

| `parse` | meaning |
|---|---|
| `COMPLETE` | header and accounting body parsed, all declared lengths consistent with the received byte count |
| `MALFORMED` | lengths did not reconcile, or the body was short. **The record still ships**, with every field that did parse, `args` truncated to what was recoverable, and `raw_body_sha256` over what arrived |
| `NOT_ATTEMPTED` | pairs with `decode: NO_SECRET_CONFIGURED` — the body was never decoded, so no parse was tried. Deliberately **not** `MALFORMED`: the body is not known to be broken, it was never read, and accusing a possibly well-formed packet of being malformed is the vocabulary abuse this design refuses everywhere else |

**A packet that cannot be decoded or parsed is still recorded.** Aug 28
ruling #1, applied here: a prerequisite that could not be established is
reported, never omitted and never upgraded. A receiver that dropped
undecodable packets would be destroying the evidence of a wrong secret
or a hostile sender — precisely the events worth keeping.

`raw_body_sha256` is over the **raw decrypted body** — the accounting
body after the obfuscation pad is removed, before any parsing — so a
reader can confirm the parse was over these bytes and no others. When
`decode` is `NO_SECRET_CONFIGURED` it is over the bytes as they arrived,
and the field pairs with `decode` to say which.

### Size boundary — refuse, never truncate

The daemon's `artifact_content` field is 8191 bytes
(`VIRP_CHAIN_ARTIFACT_CONTENT_MAX`). A body at or past that limit is
**refused at submission and never truncated**, because a truncated body
does not hash to its own `artifact_hash` and would be permanently
unverifiable. A refused packet is counted and reported by the receiver
as a receive-side gap, on the same footing as a dropped packet — it is
never silently discarded. Real command-accounting packets are well
under 1 KB; the guard is for a pathological or hostile `args` list.

---

## 3. `tacacs_reconciliation/1` — the claim, written later

A separate reconciler reads receipts and `gate_execution` records and
states **what the receipts appear to correspond to**.

**The reconciler never modifies, re-signs, supersedes, or annotates a
receipt.** A receipt is final at receipt. Reconciliation is a new record
that *cites* receipts by chain sequence, and a receipt is entirely
readable without it. Running the reconciler twice produces two
reconciliation records over the same receipts and changes no receipt.

Citation is by `(session_id, sequence)` on the VIRP chain plus the
receipt's `raw_body_sha256`, so a cited receipt can be located and
confirmed to be the one that was reconciled.

### Verdict vocabulary — closed

| verdict | meaning |
|---|---|
| `MATCHED` | receipt and a `gate_execution` correspond on device, command bytes, and time window |
| `START_WITHOUT_STOP` | a START receipt with no STOP for its `task_id` |
| `STOP_WITHOUT_START` | a STOP receipt with no START for its `task_id` |
| `UNGOVERNED` | accounting exists, no gate record — the device executed a command VIRP did not govern |
| `UNREPORTED` | gate record exists, no accounting — VIRP governed a command the device did not report |
| `AMBIGUOUS` | more than one candidate satisfied the match rule; every candidate is listed and none is chosen |

`AMBIGUOUS` is a real outcome, not a defect. Two identical commands to
one device inside one match window are indistinguishable on the stated
criteria, and picking one would be a fabrication. The record names the
candidates and stops.

### The match rule is stated in the record

Because the rule is a judgement, every reconciliation record carries the
parameters it ran under — `match_window_ms`, the command comparison
mode, the reassembly rule — so a reader can see what "MATCHED" meant on
this run rather than trusting a constant compiled in somewhere.

Command comparison is over **bytes**. Cisco delivers `cmd=show` +
`cmd-arg=version` + `cmd-arg=<cr>`; the reconciler's reassembly (join
`cmd` and successive `cmd-arg` values with single spaces, drop a
trailing `<cr>`) is *named in the record* as
`command_reassembly: "cisco_cmd_cmdarg_space_join_drop_cr"`. That name
is the honest handle on an interpretation. A different vendor gets a
different named rule, and an unrecognized shape gets
`command_reassembly: "UNRECOGNIZED"` with the verdict falling to
`AMBIGUOUS` or `UNGOVERNED` rather than to a guessed join.

### Receiver coverage is a separate axis from the verdict

When the VIRP listener is down, a device's accounting for that window
never arrives. The resulting receipts show a START with no STOP.

**That grades `START_WITHOUT_STOP` and the verdict is not softened.**
A separate field records what was known about the receiver in that
window, and the two never borrow each other's vocabulary — the same
rule that keeps camera identity failures out of `INVALID`:

| `coverage` | meaning |
|---|---|
| `RECEIVER_UP` | the receiver's own uptime ledger covers the whole match window |
| `RECEIVER_DOWN` | the ledger shows the receiver was not listening for part or all of the window |
| `RECEIVER_UNKNOWN` | no ledger covers that window |

`RECEIVER_DOWN` explains a gap. It does not excuse it, does not upgrade
the verdict, and does not remove the pair from the counts. A reader sees
"START_WITHOUT_STOP, coverage RECEIVER_DOWN" — a gap with a known
cause, which is still a gap. The receiver writes its own start/stop
ledger so this field is answerable from evidence rather than from
memory.

---

## 4. How these records ride the chain

Both types follow the **established externally-produced record pattern**
(`autopilot/virp_evidence.py`, `camera/virp_camera.py`):

- Submitted as `artifact_type=evidence_item` via `chain_append`.
  `evidence_item` is on the daemon's external-allowed list
  (`virp_chain_type_is_external_allowed`); the real type
  (`tacacs_accounting/1`) is the `schema` INSIDE the body.
- **This is not a workaround, it is the required shape.** The wire's
  `artifact_type` field is `char[16]` — 15 usable characters. A literal
  `tacacs_accounting` (17) and `tacacs_reconciliation` (21) would both
  be silently truncated, exactly the defect that forced the
  `comparator_verd` / `chainwalk_summa` aliases. Riding under
  `evidence_item` with the schema in the body avoids inventing two more
  truncated aliases, and matches what every other external producer
  already does.
- The body is single-line canonical JSON (sorted keys, no whitespace),
  serialized **once**; `artifact_hash` is sha256 over exactly those
  stored bytes, and the daemon's GATE 2 re-derives it and refuses a
  mismatch.
- Each body carries `producer_sig`, Ed25519 over the canonical body
  minus `producer_sig`, verified out of band against a pinned public
  key. As with the camera producer, **Docket does not verify
  `producer_sig` and reaches its verdicts without it.**

### Key custody

The receiver holds **no VIRP key**: not the chain key, not the O-Key. It
holds its own producer keypair and the TACACS+ shared secrets. Chain
entries are signed by the O-node at ingest.

**The producer signature binds a key, not a host** — the limit stated at
length in `camera/virp_camera.py`, and it applies identically here. A
new producer key is minted for the TACACS receiver and recorded in
`deploy/keys/registry.json` with role `producer`, so it is not
conflated with the camera's `008353cf` (which is already known to live
on two machines).

### Secret handling

TACACS+ shared secrets are read from a 0600 file or the environment and
**never appear in a body, a log line, or a report** — the same rule the
camera driver applies to RTSP credentials. Note that `src/virp_scrub.c`
already redacts first-token `key <string>` lines in the tacacs/radius
server-block shape, so a device config captured elsewhere in VIRP does
not leak the secret either.

### Daemon config this requires

The receiver runs as its own uid. Per the v0.2.1 per-uid policy, that
uid needs:

- an entry in `socket_allowed_uids`
- an entry in `socket_uid_action_allow` — exactly `["chain_append"]`
- an entry in `socket_uid_chain_append_types` — exactly
  `["evidence_item"]`

All three are mandatory: the daemon **refuses to start** naming the uid
if an allowlisted uid is missing from the action or type map. A
forgotten entry is a boot failure, never a silent grant. In the lab this
is a rendered lab config; no production template is edited by this work.

---

## 5. Verifier and Docket

### virp-verify

The new types need **no new grading logic**. `report/verify.py` grades a
chain entry on `entry_hash`, `link`, `chain_hmac`, and `artifact_bind`,
none of which is schema-aware; the bodies are direct commitments
(sha256(body) == artifact_hash), so they are not on the
`INDIRECT_COMMITMENT_TYPES` list and bind normally. Under the existing
artifact rules a receipt is graded **carried, hashed, signed** exactly
as a `camera_segment` body is.

That is the intended outcome and it is worth stating plainly: a new
observation source that needed the verifier changed in order to pass
would be a source that had negotiated its own grading.

### The Docket presentation rule

Reconciliation is a **producer claim** and is rendered **beside** the
cryptographic verdict ladder, **never inside it** — the same separation
the camera's `sensor_signature` object is held to.

The reason is not cosmetic. The verdict ladder answers "are these bytes
what was signed, and is the chain intact". Reconciliation answers "does
this receipt appear to correspond to a governed command". A `MATCHED`
reconciliation over a chain that FAILs `entry_hash` must not read as
reassurance, and an `UNGOVERNED` verdict must not read as a
cryptographic failure. Collapsing them would let an interpretation
borrow the authority of a signature.

Concretely: `MATCHED` / `UNGOVERNED` / `UNREPORTED` never appear in the
PASS / FAIL / UNCHECKED / UNVERIFIABLE column.

### Docket schema entry

Docket is a separate tree (`docket-bundle/`) and **is not edited in this
session**. If rendering these records requires a Docket schema entry,
the work stops and reports the field set rather than reaching into
Docket — per the instruction governing this task. See
[§8](#8-docket-field-set-if-an-entry-is-needed).

---

## 6. Vendor capability: duplicate delivery

The requirement is that VIRP receives a *copy* of accounting the
existing AAA server also receives — VIRP must not become a single point
of failure for the customer's real accounting, and must not be fed a
different stream than the system of record.

**The trap:** on Cisco IOS/XE, multiple servers *inside one server
group* are a **failover list**, not a fan-out. The second server is
tried only when the first fails. Pointing `aaa accounting` at one group
containing both ISE and VIRP means VIRP receives **nothing** as long as
ISE is healthy — and the misconfiguration is invisible, because
everything looks fine at ISE.

Duplicate delivery on IOS/XE therefore requires **two server groups**
and the **`broadcast`** keyword on the accounting line. `broadcast`
sends to the first server in *each* named group.

| Platform | Duplicate accounting delivery | Status |
|---|---|---|
| Cisco IOS / IOS-XE | Two `aaa group server tacacs+` groups + `broadcast` on the `aaa accounting` line | **VALIDATED IN LAB** on 15.2(4)M7 — 38 TCP sessions to each of two distinct servers from one `broadcast` line, by packet capture (§7.4) |
| Arista EOS | Believed to support multiple TACACS+ groups; fan-out semantics not confirmed | **UNVALIDATED** |
| Juniper Junos | Junos TACACS+ accounting server list semantics (failover vs. fan-out) not confirmed | **UNVALIDATED** |
| Fortinet FortiOS | Multiple TACACS+ servers configurable; duplicate-delivery behaviour not confirmed | **UNVALIDATED** |

**`UNVALIDATED` is a positive statement**, on the same principle as the
camera's `UNSIGNED`: it means *we have not proven this in a lab*, not
*this does not work* and not *this works*. No row is upgraded from
vendor documentation alone. A row moves to `VALIDATED IN LAB` when a
lab run shows the same command producing a receipt on VIRP **and** on
the second server, and the run is cited here.

---

## 6a. Transport table — what else could carry device evidence

TACACS+ accounting is one transport. Others are possible and are NOT
built; naming them here with their boundary difference keeps a reader
from assuming this design generalises for free.

| transport | record | status | boundary difference from `tacacs_accounting/1` |
|---|---|---|---|
| TACACS+ accounting (RFC 8907) | `tacacs_accounting/1` | **BUILT** (lab) | TCP; body obfuscated under a shared secret, so receipt authenticates possession of that secret; the record is a PROTOCOL EXCHANGE the device initiated for the purpose of being accounted |
| Syslog | `syslog_event/1` | **UNBUILT** | **UDP** — no connection, no delivery signal, no ordering; a lost message is indistinguishable from one never sent. **Unauthenticated unless RFC 5425 TLS is configured**, so with plain syslog a receipt authenticates *nothing* — anyone who can reach the port can write any message claiming any source. And the content is a **device LOG ENTRY, not a protocol exchange**: it is whatever the device chose to write for human reading, subject to logging level, rate limiting and message-format changes between releases, rather than a structured record the device emitted specifically to be accounted |

**Why `syslog_event/1` is not simply the same design with a different
parser.** Three of its properties break assumptions this design relies
on, and each would need answering before a record type could be honest:

- **No secret, no possession claim.** `tacacs_accounting/1` says the
  sender held the configured secret. A plain-syslog record could not say
  even that, and its `client_identity_source` would need a value weaker
  than `configured_by_source_address` — the source address of a UDP
  datagram is trivially forged.
- **Loss is silent and unbounded.** The `coverage` axis here can say
  `INTERRUPTED` because the receiver knows when it was listening and TCP
  tells the device when delivery failed. Over UDP neither end knows, so a
  gap has no cause the record can evidence.
- **No START/STOP pairing.** Reconciliation's pair vocabulary
  (`START_WITHOUT_STOP`, `STOP_WITHOUT_START`) has no syslog equivalent;
  a log line is a point, not an interval.

`UNBUILT` is a positive statement, on the same principle as `UNSIGNED`
in the camera driver: it means *we considered this and have not built
it*, not that it is impossible and not that it is coming.

---

## 6b. Lab rule: isolated bridge only

**Rule: a VIRP lab is bridged to a host-only segment and NEVER to a
physical NIC.** In this repo that means `virbr0` (192.168.122.0/24). Not
`enp0s31f6`, not `wlp0s20f3`, not a USB adapter — not even
"temporarily", and not when the isolated path would need one more
privileged command than is already granted.

### What happened on 2026-09-05 when it wasn't

An earlier attempt at this same proof bridged three GNS3 c7200s to the
laptop's physical NIC, because the isolated option needed one `ip link
set virbr0 up` and that felt like the bigger obstacle. It was not. What
followed, in order:

1. **Duplicate addresses on a production segment.** A second, unrelated
   GNS3 project (35 routers) was started on the same carrier, using the
   same 10.0.0.50-.52 the lab routers had. Two live R1s, two R2s, two R3s
   answered ARP on the house LAN.
2. **ARP flux took out the receiver's own address.** The host was
   multi-homed on one subnet (wifi held the receiver address; the wired
   NIC was the bridge carrier). With `arp_ignore=0` the kernel answers ARP
   for any local address on ANY interface, so the wired NIC began
   answering for the receiver's address with its own MAC. Replies then
   left via the physical switch instead of the bridge, and reached
   nothing. Accounting delivery went to zero with every component
   apparently healthy.
3. **The house network went down.** Two GNS3 clouds bridging two switch
   fabrics onto one physical NIC, with 38 emulated routers between them.
   The operator lost internet and pulled the ethernet link to stop it.

Nothing in that sequence was a TACACS+ problem, a VIRP problem, or a
Cisco problem. All of it came from one decision: putting a lab on a real
network.

### Why the isolated bridge is not merely safer, but more correct

It also removes a whole class of evidence defect. On `virbr0` the host
has exactly ONE interface on the lab subnet, so the ARP ambiguity in (2)
cannot arise, and lab traffic cannot be perturbed by — or perturb —
anything outside. A missing accounting record on an isolated segment is
therefore attributable; on a shared one it is not, and this design's
entire value is in the difference between "the gap has a cause we can
evidence" and "something, somewhere, dropped it."

**If the isolated path needs a privileged step that is not already
granted, that is a blocker to report, not an obstacle to route around.**
The physical bridge was the cheaper-looking route and cost an evening
and the household's connectivity.

---

## 7. Lab proof

Three GNS3 routers, a stub standing in for ISE's role as the second
accounting target, and VIRP as the second group. Full run, exact config
and IOS version: **recorded in §7.4 once executed.**

### 7.1 What the run must show

1. Every accounted command produces a receipt on the VIRP chain, and the
   same event reaches BOTH configured server groups (proved by packet
   capture, not by inference).
2. The gated commands reconcile `MATCHED` to their `gate_execution`.
3. The console commands reconcile `UNGOVERNED`.
4. With the VIRP listener killed for one command, that command's record
   is missing, and the gap is **graded** — `coverage: INTERRUPTED`, with
   the ledger boundary cited as evidence — not hidden and not excused.
5. A bundle exports and `virp-verify` grades the new record types under
   the existing artifact rules, with reconciliation shown beside the
   ladder.

> **Requirement 1 was written expecting a START *and* a STOP per
> command. The platform does not do that**, and the requirement is
> restated above rather than quietly failed. On IOS 15.2(4)M7 command
> accounting emits a **single STOP record per command** even under
> `start-stop`; `start-stop` governs EXEC/session accounting, where a
> START and STOP pair genuinely do appear. The run therefore configures
> BOTH `aaa accounting commands 15` and `aaa accounting exec`, so the
> pair vocabulary is exercised on real session records while command
> records are counted as the complete single-STOP records they are. See
> `record_class()` in `tacacs/virp_tacacs_reconcile.py`.

### 7.2 Lab topology

A **duplicate** of the `Tie in to AI OPs` GNS3 project
(`TACACS-VIRBR0-LAB`), so the original is untouched. Cloud1's
`ports_mapping` binds **`virbr0` only** — no physical NIC, per §6b.

```
R1 192.168.122.11 (Gi0/0) ─┐
R2 192.168.122.12 (Gi1/0) ─┼─ Switch1 ─ Cloud1(virbr0) ─ host 192.168.122.1
R3 192.168.122.13 (Gi1/0) ─┘
                                    VIRP receiver  192.168.122.1:4949
                                    stub-ISE       172.17.0.1:4950
```

**Why the stub is on 172.17.0.1.** IOS refuses two TACACS+ servers at the
same address (§7.3, finding 2), and the host has exactly one address on
the lab segment. `172.17.0.1` is the host's `docker0` address, reachable
from the lab via its own gateway (`ip route 172.17.0.0 255.255.0.0
192.168.122.1`) and delivered locally because it is a host address. That
gives IOS the two distinct server addresses it requires **without adding
one** — which would have needed privileged host configuration this run
was not permitted to make.

### 7.3 Exact Cisco configuration

Platform: **Cisco 7206VXR (NPE400), IOS 15.2(4)M7**, `C7200-ADVENTERPRISEK9-M`,
under GNS3 2.2.59 / dynamips 0.2.23. Applied to R1, R2 and R3.

```
aaa new-model
!
tacacs server VIRP
 address ipv4 192.168.122.1
 port 4949
 key LabKeyVirp
!
tacacs server STUB-ISE
 address ipv4 172.17.0.1
 port 4950
 key LabKeyStub
!
aaa group server tacacs+ GRP-VIRP
 server name VIRP
!
aaa group server tacacs+ GRP-STUB
 server name STUB-ISE
!
aaa authentication login default local
aaa authentication login CONSOLE local
aaa authorization exec default local
aaa accounting commands 15 default start-stop broadcast group GRP-STUB group GRP-VIRP
!
line con 0
 login authentication CONSOLE
line vty 0 4
 login authentication default
 transport input ssh
```

#### Three constraints this platform imposed, each measured

These cost real time in the lab and are the practical content of the Cisco
row above. None is guessable from the vendor documentation's happy path.

**1. `tacacs server <name>` does not exist until `aaa new-model` is set.**
Before `aaa new-model`, every line of the named-server block is rejected:

```
R1(config)#tacacs server PROBE
                        ^
% Invalid input detected at '^' marker.
```

So the AAA model must be enabled first, which on a production device is
itself the change that puts authentication under AAA. Ordering matters:
enable `aaa new-model` and the console-protecting authentication list in the
same change, or a session can be lost on the next login.

**2. IOS keys TACACS+ servers by ADDRESS ALONE — a second server at the same
IP is refused even on a different port.** This is the constraint with real
deployment consequences, and it is not documented as a restriction:

```
R1(config-server-tacacs)#port 4949
%TAC-3-SERVCONF: Server config failure: A server already exists
```

and, via the legacy syntax against an existing named server:

```
%TAC-3-SERVCONF: Server config failure: New type server exists with same address
```

The address is silently dropped and `show tacacs` then reports
`Server address: UNKNOWN` — a state that looks configured in `show
running-config` but can never send a packet. **Always confirm with `show
tacacs`, not with `show running-config`.**

Consequence for deployment: **VIRP cannot be co-located with the incumbent
AAA server on one host by port.** It needs its own address. A migration plan
that assumed "point it at the same collector on a different port" does not
work on IOS.

**3. A console line authenticating with `none` produces NO command
accounting.** With `aaa authentication login CONSOLE none` on `line con 0`,
`debug aaa accounting` shows nothing whatever for a privilege-15 command —
there is no authenticated AAA user to attribute the command to, so no
accounting record is generated. The console must authenticate (`local` here)
before console commands appear in accounting at all.

This matters well beyond the lab: **an operator at an unauthenticated console
is invisible to command accounting**, on every device configured that way.
That is a governance gap in the device, not in VIRP, and VIRP's honest
reading of it is `UNREPORTED` — the device did not report — rather than
silence.

#### A related trap: `commands 15` means level-15 commands, not a level-15 user

`aaa accounting commands 15` accounts commands whose own privilege level is
15. `show clock` is a level-1 command and produces nothing under
`commands 15`, even when run by a privilege-15 user. Catching everything
requires `aaa accounting commands 1` alongside it. A deployment that
configures only `commands 15` and concludes "we have command accounting" has
accounting for `configure terminal` and `show running-config`, and none for
the bulk of what operators actually type.

### 7.4 Run record — 2026-09-05

Executed 06:00-06:05 UTC. `virp-onode-prod` build `v0.2.0-57-g1dab856`,
chain signing ENABLED (`ed25519-detached-v1`, key_id
`aec58669fa9c5d4726d12a4e8570a6f8`).

**Emulator honesty controls.** Idle-PC applied on all three routers
(`0x6062dd4c`, `idlemax=500`) before the run. Host load average
**89.18 before / 86.49 after** — high, because an unrelated 35-router
project was running and was deliberately not touched. Load alone would
make "missing record" ambiguous, so it was measured rather than assumed:
a 200-packet probe to each router immediately before the run returned
**0% loss on all three**, and the second accounting target received
**every** record VIRP did except the one deliberately withheld. Emulator
loss is therefore excluded by evidence, not by hope.

**Idle baseline.** 90 s with no commands issued produced **3** receipts,
not 0 — the gate's three persistent SSH sessions each emitting an EXEC
session START. Explained, not waved away; it is why counts below are
given per record class.

#### Delivery to both server groups (requirement: duplicate delivery)

From `dumpcap` on `virbr0`, 752 frames:

| | VIRP `192.168.122.1:4949` | stub-ISE `172.17.0.1:4950` |
|---|---|---|
| TCP sessions opened (SYN) | **38** | **38** |
| accounting payload frames | **37** | **38** |

Equal session counts to two distinct servers, one per accounting event,
from one `broadcast` accounting line. **The Cisco row in §6 moves to
VALIDATED.** The single payload difference is the deliberate outage
below, and is itself the proof it is meant to be.

#### Counts, by record class

Command-class records (one STOP each, §7.1):

| phase | MATCHED | UNGOVERNED | AMBIGUOUS |
|---|---|---|---|
| A — 15 gated + 15 console | **15** | **15** | **0** |
| C — deliberate mismatch | 1 | 1 | 0 |

Run totals across all classes: `MATCHED 16, UNGOVERNED 17,
START_WITHOUT_STOP 6, STOP_WITHOUT_START 0, UNREPORTED 1, AMBIGUOUS 0`;
coverage `RECEIVER_UP 33, INTERRUPTED 7, RECEIVER_DOWN 0,
RECEIVER_UNKNOWN 0`. The 6 `START_WITHOUT_STOP` are EXEC **session**
records still open when the reconciler ran — sessions that had not
ended, correctly reported as unclosed rather than as complete.

#### The withheld record (requirement: a graded gap)

The VIRP listener was killed with SIGTERM, `show file systems` was run
on R1 through the gate, and the listener was restored.

```
LISTEN_STOP   1788588250183687267
stub receives 1788588257545435918   <- inside VIRP's outage
LISTEN_START  1788588265688471864
```

- VIRP receipts mentioning `file systems`: **0**
- stub-ISE receipts for it: **1**, carrying `cmd=show file systems <cr>`
- reconciler: `UNREPORTED`, `coverage: INTERRUPTED`, evidence
  `[{"event":"LISTEN_START","utc_ns":1788588265688471864}]`

**The cause is evidenced, not inferred.** The second server holds the
record VIRP lacks, at a timestamp inside VIRP's own recorded outage. That
distinguishes a receiver outage from emulator or device loss by
independent evidence — which is the entire point of keeping `coverage`
on its own axis, apart from the verdict.

#### The deliberate mismatch (requirement: side-by-side)

The gate authorised `show ip bgp summary` on R1; `clear ip bgp *` was
then run at the console, ungoverned.

| record | verdict | why |
|---|---|---|
| `show ip bgp summary` | **MATCHED** | accounting corresponds to a `gate_execution` on device, command bytes and time window |
| `clear ip bgp *` | **UNGOVERNED** | accounting exists; no gate record does |

Both appear in the same reconciliation, side by side, neither inferred
from the other's absence.

#### Bundle and verification

`tools/bundle/virp_export_bundle.py` → 6 sessions, 79 entries, 79
carried artifact bodies. `virp-verify` **exit 0**, every session
`CRYPTOGRAPHICALLY-VERIFIED`, including both new types:

```
session tacacs:virp-tacacs-lab  (40 entries)
  entry_hashes        VERIFIED   40 entries recomputed (SHA-256 over canonical bytes)
  links               VERIFIED   39 links checked against recomputed hashes
  entry_signatures    VERIFIED   40 entries, ed25519-detached-v1
  artifact_binding    VERIFIED   40/40 entries have carried bodies
  signer_trust        PINNED
  verdict: CRYPTOGRAPHICALLY-VERIFIED

session tacacs-reconcile  (4 entries)
  artifact_binding    VERIFIED   4/4 entries have carried bodies
  entry_signatures    VERIFIED   4 entries, ed25519-detached-v1
  verdict: CRYPTOGRAPHICALLY-VERIFIED
```

That is **carried, hashed, signed** under the existing artifact rules,
with no verifier change — the intended outcome, since a record type that
needed the verifier altered to pass would have negotiated its own
grading.

**Reconciliation did not fit one record and was SPLIT, not trimmed.** The
full run is 23,835 bytes against the daemon's 8,191-byte artifact field.
It was refused (never truncated), then re-submitted as 4 chunks of
7,471 / 7,358 / 7,446 / 5,304 bytes, each naming `run_id`, `index`, `of`
and carrying the run-wide tally beside its own. No item was dropped:
dropping findings to fit would be an evidence tool deciding which
findings survive.

---

## 8. Docket field set — an entry IS needed

**Docket was not edited.** This section states the field set and stops,
per the rule governing the run that produced it.

### What works today with no Docket change

`virp-verify 0.1.0` grades both new types fully — `entry_hashes`,
`contiguity`, `genesis`, `links`, `head_commitment`, `entry_hmacs`,
`head_signature`, `session_key_binding`, `entry_signatures`,
`artifact_binding` — and reaches `CRYPTOGRAPHICALLY-VERIFIED`. Nothing
below is required for that.

### What is missing, exactly

Two things, both observed in the run:

```
producer_signature   ABSENT          no camera_segment records among the carried bodies;
                                     there is no producer signature to check
producer_trust       UNESTABLISHED   none — no producer key was available for this session
```

The producer-signature check is **keyed on `camera_segment`**. A
`tacacs_accounting/1` body carries a `producer_sig` over its canonical
form minus that field, under a producer key with its own `key_id`, and
Docket has no way to know it should check it. `--producer-key` was
supplied and correctly reported as unused.

Second, `tacacs_reconciliation/1` is graded as an opaque artifact. Its
verdicts are not rendered. Per §5 they must appear **beside** the verdict
ladder, never inside it — the same treatment `sensor_signature` and the
witness result already get.

### Field set for a `tacacs_accounting/1` Docket entry

Producer-signature verification needs only:

| field | type | meaning |
|---|---|---|
| `schema` | string | `"tacacs_accounting/1"` — the dispatch key |
| `producer_sig` | 128 hex | Ed25519 over `canonical_json(body minus producer_sig)`; **no domain-tag prefix** (unlike chain entry/head signatures) |
| `producer_key_id` | 32 hex | **NOT PRESENT TODAY — see below** |

**One producer change is required first, and it is not cosmetic.** The
camera record carries `producer_key_id`; `tacacs_accounting/1` does
**not**. Docket resolves which `--producer-key` to check against by that
id, so without it a bundle with two producer keys cannot say which key a
record claims. Adding `producer_key_id` is a `tacacs_accounting/2`
schema bump, because existing `/1` records must stay readable and must
never be re-signed. Until then, producer verification is possible only
when exactly one producer key is supplied, and Docket should report
`UNVERIFIABLE` rather than guess.

### Field set for a `tacacs_reconciliation/1` Docket entry

Rendered as a **claim panel beside the ladder**:

| field | type | meaning |
|---|---|---|
| `schema` | string | `"tacacs_reconciliation/1"` |
| `reconciled_utc_ns` | u64 | when the reconciler ran (not when anything was observed) |
| `match_rule.match_window_ms` | int | window the run used |
| `match_rule.command_comparison` | string | `"exact_bytes"` |
| `match_rule.join_key` | string | how receipts were grouped |
| `match_rule.known_reassembly_rules` | [string] | named interpretations available |
| `tally` | {verdict: int} | closed set: MATCHED, START_WITHOUT_STOP, STOP_WITHOUT_START, UNGOVERNED, UNREPORTED, AMBIGUOUS |
| `coverage_tally` | {coverage: int} | closed set: RECEIVER_UP, RECEIVER_DOWN, INTERRUPTED, RECEIVER_UNKNOWN |
| `items[]` | array | one claim per group |
| `items[].verdict` | string | from the closed verdict set |
| `items[].record_class` | string | `"command"` \| `"session"` \| null |
| `items[].coverage` | string | from the closed coverage set |
| `items[].coverage_evidence` | array | ledger boundaries justifying `coverage` |
| `items[].coverage_span_ns` | [u64, u64] | interval the coverage answer covers |
| `items[].device` | string | configured label, never a measurement |
| `items[].command` | string\|null | reassembled under the NAMED rule |
| `items[].command_reassembly` | string | which rule produced it |
| `items[].receipt_cites[]` | array | `{session_id, sequence, raw_body_sha256, acct_flags}` |
| `items[].gate_cite` | object\|array\|null | cited `gate_execution`; an ARRAY when AMBIGUOUS |
| `items[].detail` | string | free text; never load-bearing |
| `chunk` | object\|absent | `{run_id, index, of}` when a run is split |
| `run_tally` | {verdict: int}\|absent | run-wide tally carried in every chunk |
| `presentation` | string | states the beside-the-ladder rule in the record itself |

**Two things a renderer must not do.** It must not sum `tally` across
chunks of one `run_id` — every chunk already carries `run_tally`, and
adding the parts would double-count. And it must not show `verdict`
without `coverage`: `START_WITHOUT_STOP` with `RECEIVER_UP` and the same
verdict with `INTERRUPTED` are different claims, and collapsing them
re-introduces exactly the ambiguity the coverage axis exists to remove.

---

## 8a. Docket additions for AUTHORIZATION (v2 scope)

**Docket was not edited.** These are the field sets, reported.

### The scope change itself, stated plainly

v1's scope paragraph says VIRP serves accounting only, because "an
authorization server that fails can lock an operator out of a device"
and v1 "deliberately takes only the job whose failure mode is 'evidence
is missing', never 'the network is down'."

**Authorization deliberately reverses that trade.** An authorization
server that fails open is not a control, so the rw method list has NO
fallback (`group GRP-VIRPAZ` and nothing else) and an unreachable server
denies every command on the vty. The consequence is real and is the
biggest change in the design: VIRP moves from "cannot break the network"
to "can deny every command on every router it governs".

Two things keep that survivable, and both are load-bearing rather than
decorative:

- **The console is exempt** (`aaa authorization commands 15 CONSOLE
  none`). An authorization outage leaves console access working, which
  is the documented break-glass path. On real hardware that is a
  deliberate, stated hole: anyone with console access bypasses command
  authorization entirely.
- **Accounting stays a separate process on a separate address.** An
  authorization outage cannot lose evidence and an accounting outage
  cannot deny commands. Merging them would couple exactly the two
  failure modes v1 separated.

### `tacacs_authorization/1` — the decision record

One per AUTHOR request, chained BEFORE the reply is sent. A decision the
router acted on that no record describes is the hole this exists to
close, so a chain-append failure downgrades the decision to `ERROR`,
which denies.

| field | type | meaning |
|---|---|---|
| `schema` | string | `"tacacs_authorization/1"` |
| `recv_utc_ns`, `recv_monotonic_ns` | u64 | receiver clocks, same discipline as §2 |
| `client_identity`, `client_identity_source` | string | configured label, never a measurement |
| `user` | string | `virp-ro` \| `virp-rw` — the identity the ROUTER authenticated |
| `port`, `rem_addr`, `priv_lvl` | string/int | as sent |
| `args` | [string] | verbatim, same rule as the accounting receipt |
| `command` | string\|null | reassembled under a NAMED rule |
| `command_reassembly` | string | which rule produced it |
| `decision` | string | closed set: `PASS_ADD`, `PASS_REPL`, `FAIL`, `ERROR` |
| `decision_reason` | string | operator-visible; denials carry the `VIRP-DENY: ` prefix |
| `grant_id` | string\|null | the grant spent, or null |
| `policy_sha256` | 64 hex | the policy in force AT THE MOMENT OF THE DECISION |
| `raw_body_sha256` | 64 hex | over the decrypted AUTHOR body |
| `parse` | string | `COMPLETE` \| `MALFORMED` |

`policy_sha256` is the field that makes the record auditable: it binds a
decision to the exact policy bytes it was judged against.

### `tacacs_authz_policy_rendered/1` — what the router would have accepted

| field | type | meaning |
|---|---|---|
| `schema` | string | `"tacacs_authz_policy_rendered/1"` |
| `device` | string | device, or a comma list for a multi-device render |
| `rendered_utc_ns` | u64 | when the compiler ran |
| `policy_sha256`, `policy_bytes_len` | 64 hex / int | commitment to the rendered bytes |
| `grant_count` | int | grants in force |
| `approval_ids` | [string] | which approvals are represented |
| `refusals[]` | array | `{approval_id, reason}` for every approval NOT rendered |
| `daemon_load_confirmed` | bool\|null | whether the daemon's own ledger confirmed the load |
| `presentation` | string | the beside-the-ladder rule, in the record |

**`refusals` is not optional.** An approval that silently failed to
render is a silent denial of approved work and looks identical to an
attack; the record must show what did not make it in.

**A renderer must show `daemon_load_confirmed`.** A policy that was
written but never loaded describes a router that was never governed by
it. `false` and `null` are different: `false` means the daemon was asked
and did not confirm; `null` means nobody checked.

### The grant shape a reader needs

Grants inside the policy carry `accepted_spellings` and `spelling_rule`.
That is deliberate and must be rendered: IOS does not authorize the
command the operator typed (§8b), so "what was approved" and "what the
router will be allowed to say" are different strings, and only the second
governs. A UI that showed the approved text alone would be showing the
wrong string.

`derived: "config_mode_prerequisite"` marks a grant the COMPILER minted,
not one a human approved. It must never be displayed as an approval.

### The gap this session could not close: identity

The `outcome` record (src/virp_onode.c) carries `proposal_id`,
`proposal_entry_hash`, `approval_entry_hash`, `device`, `command_hash`,
`success` and `intent_entry_hash` — and **no identity field**. So "which
identity executed this" is not answerable from the chain. The
authorization record knows (`user`), and the outcome record does not, and
nothing binds the two.

**Recommended field for `outcome`:** `executed_as` (string, the AAA
username the gate authenticated with). It is a schema bump on a
daemon-reserved type and therefore not made here.

### Recommendation: `producer_key_id` from day one — argued

The accounting report left `producer_key_id` open for
`tacacs_accounting/1`, where adding it means a `/2` bump because `/1`
records exist and must never be re-signed.

**The two new types above have produced nothing real yet. They should
carry `producer_key_id` from their first record, and the argument is not
symmetry — it is that the cost curve is entirely one-sided.**

Adding it now costs one field in a record no auditor has yet read.
Adding it later costs a schema bump, a period where two versions are
live, a verifier that must handle both forever, and a body of `/1`
records that can never be upgraded because re-signing evidence is exactly
what this system refuses to do. The accounting type is already paying
that price; there is no reason to buy it twice.

The counter-argument — "wait until Docket actually verifies producer
signatures, in case the field set changes" — fails on its own terms. If
Docket later wants something different, a type with `producer_key_id`
can add a field; a type WITHOUT it cannot retroactively acquire the one
field that says which key to check, because the records are already
signed. The asymmetry is the whole argument: the field is cheap before
first use and permanently unavailable after.

**So: `tacacs_authorization/1` and `tacacs_authz_policy_rendered/1` carry
`producer_key_id` before any of their records is treated as evidence.**
This is recorded as a decision, not implemented in this session, because
the records already written during the lab run would then be `/1` bodies
without the field — which is the exact trap being described. The clean
move is to add the field and DISCARD the lab chain, not to bump a type
that is three hours old.

---

## 8b. FortiOS: a design sketch, and where the Cisco model does not reach

**No FortiGate was touched.** This is design only, written from the
platform model, and every row is `UNVALIDATED` until a lab proves it.

### What maps cleanly

| Cisco element | FortiOS equivalent | note |
|---|---|---|
| two AAA identities (`virp-ro`, `virp-rw`) | two admin accounts, each bound to its own `accprofile` | direct |
| the read allowlist | an `accprofile` with read-only scopes | coarser: FortiOS grants by FEATURE AREA, not by command |
| source restriction | `trusthost` on the admin account | **stronger than Cisco.** `trusthost` pins the source prefixes an admin may log in from at all, which Cisco's command authorization does not do |
| command accounting | TACACS+ accounting, `config log tacacs+accounting` | the accounting half of this design should port |

### What does NOT map, and it is the important half

**FortiOS has no per-command TACACS+ authorization.** Cisco asks the
TACACS+ server about every command; FortiOS decides locally from the
admin's `accprofile`. There is no AUTHOR exchange per command to
intercept, so there is nothing for a policy compiler to answer.

That breaks the central mechanism of this design. "One approval, one
command, one device" has no expression on FortiOS: the finest grain
available is a feature-area permission (`fwgrp`, `sysgrp`, `netgrp` and
so on, each none/read/read-write). An approval for *one command* would
have to be rendered as a profile granting *every command in that feature
area* — which is not the same claim, and quietly widens the blast radius
from one command to a category.

Three shapes are possible, and none is equivalent:

1. **Dynamic profile rewrite.** On approval, rewrite the `virp-rw`
   account's `accprofile` to open the needed feature area, and close it
   on outcome or TTL. Honest description: *time-boxed feature-area
   access*, not per-command authorization. The window is narrow in TIME
   but wide in SCOPE, and a report must say so rather than reusing the
   Cisco wording.
2. **Approval-gated credential release.** Keep `virp-rw` permanently
   disabled and enable it only inside an approved window. Same scope
   problem, plus the account is a bearer credential while enabled.
3. **Proxy the CLI.** Put VIRP in the command path rather than beside
   it, so it can refuse per command. This restores the granularity and
   loses the property that makes the Cisco design worth having: the
   router refuses *regardless of what the gate sends*. A proxy that is
   also the gate is back to trusting the gate.

**The recommendation is to say so plainly rather than ship option 1 under
the Cisco vocabulary.** On Cisco, `UNGOVERNED` means the device executed
something VIRP did not authorize. On FortiOS under option 1 the device
would be executing things VIRP never saw, inside a window VIRP opened —
which is a materially weaker statement and needs its own verdict name,
not a borrowed one.

| FortiOS capability | status |
|---|---|
| per-command TACACS+ authorization | **NOT AVAILABLE** — architectural, not a config gap |
| time-boxed feature-area access via profile rewrite | **UNVALIDATED** |
| `trusthost` source pinning | **UNVALIDATED** |
| TACACS+ command accounting | **UNVALIDATED** |

---

## 9. Scope of authorization, and what this source still does not prove

### 9.1 The resolution: authorization applies to the GATE's identities only

§1 and §8a were in tension. §1 says VIRP takes only the job whose failure
mode is "evidence is missing, never the network is down". §8a introduced
an authorization control whose whole point is to deny. Both cannot be
true of the same identities.

**They are true of different identities, and that is the resolution.**

| identity | authorization | if the TACACS+ server is unreachable |
|---|---|---|
| `virp-ro` (gate steady state) | TACACS+ per-command, `group` only | **can do nothing** |
| `virp-rw` (gate, approved actions) | TACACS+ per-command, `group` only | **can do nothing** |
| humans, via the console | exempt (`CONSOLE` list, method `none`) | **unaffected** |
| `breakglass` (local account, console path) | exempt with the console | **unaffected** |

**The original §1 argument is not withdrawn — it is the reason humans are
exempt.** An authorization server that can lock an operator out of a
device is exactly the failure v1 refused to build, so no human depends on
one. What changed is that the GATE is now fenced: VIRP's own automated
identities fail closed, because an automated actor that keeps acting when
its control plane is unreachable is not governed at all.

So the failure mode is still "evidence is missing, never the network is
down" **for humans**, and is deliberately "the gate stops" for the gate.

### 9.2 Break-glass use is an event, graded RED

The exemption has a price and it is paid in visibility. `breakglass` is
the one identity that can act without the gate, so its use is:

- **recorded** — a locally-authenticated console session emits TACACS+
  accounting (EXEC START plus a command STOP per command,
  `user=breakglass`). Measured 2026-09-05.
- **graded `RED`** by the reconciler, under its own verdict
  `BREAKGLASS_USED`, on a grade axis separate from the verdict.
- **never folded into `UNGOVERNED`.** A break-glass command has no gate
  record by definition, so `UNGOVERNED` is where it would land by
  default — and that is a counting bucket. Burying an alarm in a
  counting bucket is how alarms get ignored.

The break-glass account list is **configured, never inferred**. With none
configured the reconciler reports `NOT_GRADED`, which is not the same
claim as "no break-glass happened".

### 9.3 Why there is no network break-glass path

Measured on IOS 15.2(4)M7, 2026-09-05, with the authorization server
down:

| shape | `virp-rw` | `breakglass` |
|---|---|---|
| `commands N VIRPRW group GRP-VIRPAZ` | login OK, **every command DENIED** | login OK, **every command DENIED** |
| `commands N VIRPRW group GRP-VIRPAZ local` | login OK, **`configure terminal` EXECUTED** | everything EXECUTED |
| separate vty on its own SSH port, list `local` | port 22 **DENIED**; **port 2222 EXECUTED** | port 2222 EXECUTED |

**IOS cannot scope `local` fallback to specific users.** A method list
binds to a LINE and authorizes whoever reaches it. The gate must hold a
local account in order to authenticate at all, so any line offering a
`local` fallback offers it to the gate too — including a dedicated
break-glass port, which the gate simply connects to.

A network break-glass therefore requires `access-class` source
separation, and is only a control where the gate host and the operator's
jump host are different sources. **Without one it is a gate
self-escalation route**, and is not shipped in the template for that
reason.

### 9.4 The limit: both servers down

Measured, and this is the honest edge of the design.

| what is down | break-glass visible to VIRP? |
|---|---|
| authorization server only | **YES** — accounting is a separate process on a separate address, so receipts still arrive |
| authorization **and** accounting | **NO** — zero receipts |

That accounting survives an authorization outage is not luck; it is the
separation §1 spent a paragraph on, doing its job.

With both down, what survives is the router's own local buffer, and only
if it was configured for it:

- `%SEC_LOGIN-5-LOGIN_SUCCESS: [user: breakglass]` (needs
  `login on-success log`)
- `%SYS-6-LOGOUT: User breakglass has exited`
- `%PARSER-5-CFGLOG_LOGGEDCMD: User:breakglass logged command:<cmd>` for
  every config command (needs `archive` / `log config`)

Without those, a break-glass **`show`** command during a full outage
leaves **no trace anywhere**. Even with them, the buffer is volatile,
unauthenticated, lost on reload, and under the control of the device
being investigated. It is a lead, not evidence.

Shipping a durable answer means getting those events off the box while
the collectors are down — which is the `syslog_event/1` transport in
§6a, still `UNBUILT`, and which has its own boundary problems.

---

### 9.5 What this whole source still does not prove

Collected in one place, because a reader who skips everything else
should still find this.

- **Not physical origin.** Possession of a shared secret, from an
  address. Nothing more. See §1.
- **Not a complete record of what ran.** A device that does not send
  accounting produces nothing, and its silence is indistinguishable
  from a device that ran nothing — which is exactly why `UNREPORTED`
  exists as a verdict rather than as an absence.
- **Not a record of what was REFUSED.** A denied command never executes,
  so it produces no accounting record at all. Measured: 5 of 16 distinct
  denied command strings appeared nowhere in accounting. Only the
  `tacacs_authorization/1` record evidences a refusal.
- **Not tamper-proof against the device.** A compromised device
  controls what it reports. VIRP records what it was told, signed at
  receipt. Tamper-**evident downstream of receipt**, not upstream.
- **Not a control over humans.** Authorization governs the gate's
  identities. Anyone at a console is outside it by design (§9.1), and
  the compensating control is a RED record, not a refusal.
- **Not authenticated transport.** RFC 8907 obfuscation is not TLS. An
  observer on-path with the secret reads everything; an observer
  without it sees packet sizes, timing, and the header in clear.

---

Copyright 2026 Third Level IT LLC — Apache 2.0
