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
| Cisco IOS / IOS-XE | Two `aaa group server tacacs+` groups + `broadcast` on the `aaa accounting` line | **CONFIG VALIDATED IN LAB** on 15.2(4)M7 — `broadcast` confirmed active by `debug aaa accounting` (`Broadcast osr 2`). Delivery to both targets: see §7.4 |
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

1. Every command produces START and STOP receipts on the VIRP chain.
2. The gated commands reconcile `MATCHED` to their `gate_execution`.
3. The console commands reconcile `UNGOVERNED`.
4. With the VIRP listener killed for one command, the device's next STOP
   is missing, and the gap is **graded** (`START_WITHOUT_STOP`,
   `coverage: RECEIVER_DOWN`) — not hidden, not excused.
5. A bundle exports and `virp-verify` grades the new record types under
   the existing artifact rules, with reconciliation shown beside the
   ladder.

### 7.2 Lab topology

The `Tie in to AI OPs` GNS3 project (R1/R2/R3, c7200, one switch, one
cloud bridge) is the right shape. Its cloud bridge points at a USB NIC
that currently has no carrier, so the proof runs on a **copy** of the
project bridged to a host-local segment; the original project is left
untouched.

### 7.3 Exact Cisco configuration

Platform: **Cisco 7206VXR (NPE400), IOS 15.2(4)M7**, `C7200-ADVENTERPRISEK9-M`,
under GNS3 2.2.59 / dynamips 0.2.23. Applied to R1, R2 and R3.

```
aaa new-model
!
tacacs server VIRP
 address ipv4 10.0.0.36
 port 4949
 key LabKeyVirp
!
tacacs server STUB-ISE
 address ipv4 10.0.0.21
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

### 7.4 Run record

*(populated by the lab run)*

---

## 8. Docket field set, if an entry is needed

*(populated once the record shapes are exercised end to end)*

---

## 9. What this whole source does not prove

Collected in one place, because a reader who skips everything else
should still find this.

- **Not physical origin.** Possession of a shared secret, from an
  address. Nothing more. See §1.
- **Not a complete record of what ran.** A device that does not send
  accounting produces nothing, and its silence is indistinguishable
  from a device that ran nothing — which is exactly why `UNREPORTED`
  exists as a verdict rather than as an absence.
- **Not tamper-proof against the device.** A compromised device
  controls what it reports. VIRP records what it was told, signed at
  receipt. Tamper-**evident downstream of receipt**, not upstream.
- **Not a security control.** v1 serves accounting only. It authorizes
  nothing and denies nothing. A command already ran by the time its
  accounting arrives.
- **Not authenticated transport.** RFC 8907 obfuscation is not TLS. An
  observer on-path with the secret reads everything; an observer
  without it sees packet sizes, timing, and the header in clear.

---

Copyright 2026 Third Level IT LLC — Apache 2.0
