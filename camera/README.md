# virp_camera.py — the camera driver

Turns closed video segments into producer-signed `camera_segment/N`
records on the O-node trust chain. Full mechanics are in the module
docstring; this file documents one thing the docstring is the wrong
place for, because it is what a reader of a *record* needs.

## Sensor trust states

A signing camera (Axis signed video) makes claims about its own output
that this producer cannot make on the camera's behalf. Records at
`camera_segment/3` and later carry a `sensor_signature` object holding
those claims and — separately — what we were able to establish about
them.

**Three clocks, never collapsed.** `capture_end_utc_ns` is the capture
host's clock when ffmpeg finalized the segment. The chain entry's own
timestamp is the O-node's receipt. `asserted_first_frame` /
`asserted_last_frame` are the CAMERA's clock, from the SEI. These are
three different facts about three different machines. The M3085-V used
to build this feature spent its first weeks stamping `2024-08-15` onto
2026 footage; the record was correct throughout, because it never
claimed the camera's word for the time was ours.

### `verdict` — what the validator said about the bitstream

| state | meaning |
|---|---|
| `VALID` | the validator verified every signed GOP in this segment |
| `INVALID` | the validator checked and the signatures do not hold |
| `UNSIGNED` | this camera does not sign its video at all (Tapo, Reolink) |
| `UNVERIFIED` | the question could not be answered — see below |

The vocabulary is closed and the object is never omitted. A record that
simply left `sensor_signature` out would let a verifier testing
`if "sensor_signature" in body` read "the check failed" as "the check
passed", which is the failure this whole design exists to prevent.

`UNSIGNED` is a positive statement, not an absence: it says *we asked,
and this camera does not sign*. `vendor` is `null` there.

### Why a record reads `UNVERIFIED`

Aug 28 ruling #1: a prerequisite that could not be established is
reported, never omitted and never upgraded — **and the record still
ships**. A producer that dropped footage because a validator was missing
would be destroying evidence to protect a verdict.

| cause | recorded as |
|---|---|
| validator binary missing | `verdict UNVERIFIED` |
| validator crashed or timed out | `verdict UNVERIFIED` |
| output present but unparseable | `verdict UNVERIFIED`, raw bytes still kept and hashed |
| clip too short for one complete GOP | `verdict UNVERIFIED` (`NO COMPLETE GOPS FOUND!`) |
| public key could not be validated, video otherwise valid | `verdict UNVERIFIED`, `public_key COULD_NOT_BE_VALIDATED` |
| pinned key file missing or not a PEM | `verdict UNVERIFIED`, `public_key_pin PIN_UNREADABLE` |
| segment signed by a key that is not the pinned one | `verdict UNVERIFIED`, `public_key_pin MISMATCH` |
| a key is pinned but the stream carries none | `verdict UNVERIFIED`, `public_key_pin NO_KEY_IN_STREAM` |
| chain does not reach the pinned anchor | `verdict UNVERIFIED`, `device_chain.chain_to_anchor_verified false` |
| chain reaches the anchor but the leaf is another device | `verdict UNVERIFIED`, `device_chain.leaf_serial_matches_device false` |

**Identity failures are never `INVALID`.** The last four rows are
questions about *which device this is*, not about whether the bytes were
altered. Authentic footage from a camera we did not pin looks exactly
like a pin mismatch. Reporting that as `INVALID` would accuse a device
of tampering with video it signed honestly. Tampering is the validator's
word; identity is ours, and the two never borrow each other's
vocabulary.

A related trap on the other side: `VIDEO IS VALID, BUT HAS MISSING
FRAMES!` is a real validator branch. It maps to `VALID` with
`gops_valid_with_missing` non-zero — never to a bare `VALID` with the
count dropped, which would launder a lossy stream into a clean one.

### What each trust layer actually proves

Three independent statements. A record carries all three; none stands in
for another.

| layer | field | proves | does not prove |
|---|---|---|---|
| **TOFU leaf key** | `sensor_key_sha256`, `public_key_pin` absent | the segment carried *a* signing key, and we recorded which | nothing about whether that key is the right one |
| **pinned leaf key** | `public_key_pin: MATCH` | the segment was signed by the exact key we hold for this camera, and the validator verified against *our* key rather than one it lifted from the stream | nothing after a legitimate key rotation, which reads `MISMATCH` and needs a human |
| **anchored chain** | `device_chain.chain_to_anchor_verified` + `leaf_serial_matches_device` | the leaf certificate was issued by the CA we pinned, and its subject `serialNumber` is this device — so it survives leaf rotation within that CA, and detects a leaf from any other CA | that the CA itself is genuine, because the anchor was taken from the camera's own stream |

That last cell is the honest limit of the current setup, and
`device_chain.anchor` states it in the record: it reads
`intermediate_pinned`, and will read `root` only when a root delivered
out of band is pinned instead.

**Why it is not a root today.** Axis does not publish the Edge Vault
Attestation root. Their PKI repository
(`axis.com/support/public-key-infrastructure-repository`) carries only
the Device ID hierarchy; that root is a different CA and the chain fails
against it at depth 1. Axis's own Product PKI Certificate Policy names
`Axis Edge Vault Root CA` as a separate CA, and commits to publishing
new CA certificates — but it is not in the repository. Until it is, an
anchored chain is the strongest honest claim available, and calling it
anything else would be the collapse this document exists to prevent.

**The anchor is a key, not a certificate.** Axis has issued at least two
certificates for `Axis Edge Vault Attestation CA ECC 1` — identical
subject, identical public key, different serial numbers and different
`notAfter`. Both are legitimate. Verification is therefore the leaf's
signature under the anchor's public key; `anchor_sha256` records which
file an operator actually installed, which is its own separate fact.

### Reading a record

`verdict` alone is not the whole answer. `VALID` with `public_key_pin`
absent means the validator was satisfied by a key that came from the
same stream it was judging. `VALID` with `public_key_pin: MATCH` and
`chain_to_anchor_verified: true` is a much stronger record, and the
difference is visible only by reading the fields rather than the
headline. Docket renders the whole object as a *producer claim*, held
deliberately apart from its own cryptographic verdict ladder, for the
same reason.

## Deployed

Where this driver is installed, and what is running there. The capture side
runs from a working tree on the laptop; the O-node side is an installed copy,
and `submit-spool` uses THAT one — so a capture host at `/6` shipping to an
O-node at `/5` is refused at the schema gate, correctly and unhelpfully. Keep
this table current or the next bump repeats that.

| host | path | purpose |
|---|---|---|
| laptop | working tree `camera/virp_camera.py` | `live` capture, `verify-segment` |
| 313 `virp-onode-home` (10.0.0.13) | `/usr/local/lib/virp-camera/virp_camera.py` | `submit-spool`, `audit` |

### 313, current

- **Commit** `e3a16c75c6310e59adf0ec2f8d238cba14b354f3` (short `e3a16c7`),
  deployed 2026-09-04 21:49 UTC
- **sha256** `95fc356c39939503b9a28b4950a6e60034d8a5aac6bd56bbeba863efdeeaae43`
- **Emits / accepts**: `SCHEMA = camera_segment/6`; reads `/1` through `/6`
- **Cites**: `segment_sha256`,
  `sensor_signature.validator_output_sha256`,
  `sensor_signature.device_chain.leaf_sha256`
- **Payload grades**: VERIFIED, ABSENT, INACCESSIBLE, FAILED
- **Supersedes**: `/5` at sha256 `f5d5088…`, kept as
  `virp_camera.py.bak-v5-20260904` beside it
- **Why this one mattered**: the previous copy's `submit-spool` moved only
  `(segment, body, marker)` out of `incoming/`, so every cited sidecar the
  capture host shipped stayed behind and `audit --artifact-dir` on 313 graded
  SEGMENT PAYLOAD ABSENT forever. This copy moves the whole job.

Verify what is installed, without changing anything:

```sh
ssh nhoward@10.0.0.13 '
  D=/usr/local/lib/virp-camera/virp_camera.py
  sha256sum $D; grep "^SCHEMA = " $D
  sudo -u virp python3 $D submit-spool --sock /run/virp/onode.sock \
    --db /var/lib/virp/chain.db --incoming /var/spool/virp-capture/incoming --once'
```

An empty `incoming/` makes that a no-op — `0 job(s) appended this run`, exit 0
— which is the safe way to confirm the installed copy runs at all.
