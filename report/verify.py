#!/usr/bin/env python3
"""
Re-verification of VIRP chain evidence, in pure Python.

This module recomputes, from the chain database alone, every cryptographic
claim the report makes. Nothing here trusts a stored value because it is
stored; each is recomputed and compared.

What is checked, per chain entry:

  entry_hash    chain_entry_hash == sha256(canonical_json(entry))
                Detects any mutation of the entry's own fields. No key needed.

  link          previous_entry_hash == the preceding entry's chain_entry_hash
                within the same session, or sha256("VIRP_CHAIN_GENESIS:" +
                session_id) at sequence 0. The chain is linked PER SESSION,
                not globally; sequence restarts at 0 for each session. No key
                needed.

  chain_hmac    chain_hmac == HMAC-SHA256(K_chain, canonical_json(entry))
                Detects forgery by anyone lacking the chain key. Requires
                /etc/virp/keys/chain.key. Skipped (reported as UNCHECKED, not
                as a pass) when the key is unavailable.

  artifact_bind sha256(artifact bytes) == entry.artifact_hash
                Binds the stored artifact body to the chain entry. This is
                what makes the chain entry evidence *about* the artifact
                rather than an unrelated row. No key needed.

  obs_hmac      For observations: HMAC-SHA256(O-Key, header[0:24] || payload)
                == header[24:56], i.e. the signature the O-Node applied when
                it signed the measurement. Requires /etc/virp/keys/onode.key.

Canonical JSON must match the C producer (src/virp_chain.c
build_canonical_json) BYTE FOR BYTE, since its sha256 is the entry hash.
Note the C version interpolates strings with snprintf and performs no JSON
escaping; this implementation reproduces that behaviour exactly rather than
"correcting" it, because the goal is to recompute what the C code computed.

Pure stdlib. No network.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import base64
import hashlib
import hmac
import struct

VIRP_HEADER_SIZE = 56
VIRP_KEY_SIZE = 32
VIRP_HMAC_SIZE = 32

CHAIN_GENESIS_PREFIX = "VIRP_CHAIN_GENESIS:"

TIER_NAMES = {
    0x00: "UNCLASSIFIED",
    0x01: "GREEN",
    0x02: "YELLOW",
    0x03: "RED",
    0xFF: "BLACK",
}

MSG_TYPE_NAMES = {
    0x01: "OBSERVATION",
    0x02: "HELLO",
    0x10: "PROPOSAL",
    0x11: "APPROVAL",
    0x20: "INTENT_ADV",
    0x21: "INTENT_WD",
    0x30: "HEARTBEAT",
    0x40: "SESSION_HELLO",
    0x41: "SESSION_HELLO_ACK",
    0x42: "SESSION_BIND",
    0x43: "SESSION_CLOSE",
    0x4F: "SESSION_ERROR",
    0xF0: "TEARDOWN",
}

CHANNEL_NAMES = {0x01: "OC", 0x02: "IC"}

# Verification verdicts. Three distinct not-a-pass states, deliberately kept
# apart — collapsing them would either hide tampering or cry wolf about a
# healthy chain:
#
#   PASS         recomputed and matched.
#   FAIL         recomputed and did NOT match. This is a tampering signal.
#   UNCHECKED    the check did not run because an input the operator controls
#                was missing — almost always a key we were not given. Rerun
#                with the key and it becomes PASS or FAIL.
#   UNVERIFIABLE the check CANNOT run from this chain, ever, because the
#                evidence it needs was never retained. No key or rerun fixes
#                it. See RETENTION_* below for the structural causes.
#   N/A          the check does not apply to this entry at all (e.g. the
#                observation-signature check on a proposal row).
PASS = "PASS"
FAIL = "FAIL"
UNCHECKED = "UNCHECKED"
UNVERIFIABLE = "UNVERIFIABLE"
NOT_APPLICABLE = "N/A"

# ── Structural retention limits of the chain format ────────────────────────
# These are properties of how the daemon and autopilot write evidence, not
# defects in a particular chain. Each one makes some check impossible, and
# each is discovered by inspection of the producer, not guessed:
#
# 1. virp_onode.c declares `char artifact_content[8192]`, so any artifact body
#    is stored truncated to 8191 bytes while the chain entry's artifact_hash
#    commits to the FULL message. Bodies at exactly the limit cannot be bound
#    to their entry, and their O-Key signature cannot be recomputed, because
#    the bytes that were signed are not all present.
ARTIFACT_CONTENT_MAX = 8191

# 2. The autopilot's comparator verdicts and chainwalk summaries register
#    artifact_hash = sha256(signed observation) but store artifact_content =
#    the plain human-readable JSON. The signed observation itself is never
#    written to the chain (verified: no stored body hashes to that
#    commitment). So the stored body is NOT cryptographically bound to its
#    entry from within the chain. See autopilot/virp_autopilot.py, the
#    "sign_outcome" then "chain_append" pairs.
INDIRECT_COMMITMENT_TYPES = frozenset((
    "comparator_verdict", "comparator_verd",
    "chainwalk_summary", "chainwalk_summa",
))

# 3. LEGACY ONLY as of 2026-07-30. Gate rejections used to register only
#    sha256(reason text) with no body, so the reason lived solely in the
#    daemon journal. The daemon now stores a structured reason body (schema
#    gate_rejection/1) under the entry's artifact_id, committed to by
#    artifact_hash — those entries verify PASS like any other body-bearing
#    entry with no special-casing here. This set therefore applies only to
#    entries written BEFORE reason retention, which legitimately have no body
#    and must not be reported as tampering.
NO_BODY_TYPES = frozenset(("gate_rejection",))

RETENTION_TRUNCATED = (
    "artifact body was truncated at the daemon's %d-byte storage limit; the "
    "entry commits to the full message, only a prefix was retained"
    % ARTIFACT_CONTENT_MAX)
RETENTION_INDIRECT = (
    "entry commits to sha256 of a signed observation that the chain does not "
    "retain; the stored body is the plain verdict JSON and is not "
    "cryptographically bound to this entry from within the chain")
RETENTION_NO_BODY = (
    "entry predates gate-reason retention (2026-07-30): no artifact body was "
    "stored for it; the chain retains only "
    "the hash commitment, the reason text goes to the daemon journal")

# Chain entry columns, in the order the report reads them.
ENTRY_COLUMNS = (
    "session_id", "sequence", "chain_entry_hash", "previous_entry_hash",
    "timestamp_ns", "monotonic_ns", "artifact_type", "artifact_id",
    "artifact_hash", "artifact_hash_alg", "artifact_schema_version",
    "signer_node_id", "signer_org_id", "chain_hmac",
)


def genesis_hash(session_id):
    """sha256("VIRP_CHAIN_GENESIS:" + session_id) — the prev-hash at seq 0."""
    return hashlib.sha256(
        (CHAIN_GENESIS_PREFIX + session_id).encode()).hexdigest()


def canonical_json(entry):
    """Rebuild the exact byte string the C code hashes and HMACs.

    Keys alphabetically sorted, compact separators, chain_entry_hash and
    chain_hmac excluded (they are derived from this). Must match
    src/virp_chain.c:build_canonical_json byte for byte.
    """
    return (
        '{"artifact_hash":"%s",'
        '"artifact_hash_alg":"%s",'
        '"artifact_id":"%s",'
        '"artifact_schema_version":"%s",'
        '"artifact_type":"%s",'
        '"monotonic_ns":%d,'
        '"previous_entry_hash":"%s",'
        '"sequence":%d,'
        '"session_id":"%s",'
        '"signer_node_id":%d,'
        '"signer_org_id":"%s",'
        '"timestamp_ns":%d}'
    ) % (
        entry["artifact_hash"],
        entry["artifact_hash_alg"],
        entry["artifact_id"],
        entry["artifact_schema_version"],
        entry["artifact_type"],
        entry["monotonic_ns"],
        entry["previous_entry_hash"],
        entry["sequence"],
        entry["session_id"],
        entry["signer_node_id"],
        entry["signer_org_id"],
        entry["timestamp_ns"],
    )


def load_key(path):
    """Load a 32-byte raw VIRP signing key. Returns bytes, or raises."""
    with open(path, "rb") as fh:
        key = fh.read()
    if len(key) != VIRP_KEY_SIZE:
        raise ValueError(
            "%s: expected %d-byte key, got %d bytes"
            % (path, VIRP_KEY_SIZE, len(key)))
    return key


def key_fingerprint(key):
    """SHA-256 of the raw key bytes — matches compute_fingerprint() in
    src/virp_crypto.c. Identifies a key without revealing it."""
    return hashlib.sha256(key).hexdigest()


def decode_artifact(content):
    """Artifact bodies are stored either as 'base64:<b64>' (signed wire
    messages) or as literal text/JSON. Returns the bytes that artifact_hash
    is computed over."""
    if content is None:
        return None
    if content.startswith("base64:"):
        try:
            return base64.b64decode(content[7:], validate=True)
        except Exception:
            return None
    return content.encode()


def parse_message_header(raw):
    """Parse a VIRP wire header. Returns a dict, or None if too short.

    Layout (packed, big-endian on the wire — see include/virp.h virp_header_t
    and the network-order unpack in tests/test_hmac_parity.py):
        0  u8   version        8  u8   channel      16 u64 timestamp_ns
        1  u8   type           9  u8   tier         24 [32]u8 hmac
        2  u16  length        10  u16  reserved
        4  u32  node_id       12  u32  seq_num
    """
    if raw is None or len(raw) < VIRP_HEADER_SIZE:
        return None
    version, mtype, length, node_id, channel, tier, reserved, seq_num, ts = \
        struct.unpack_from("!BBHIBBHIQ", raw, 0)
    return {
        "version": version,
        "type": mtype,
        "type_name": MSG_TYPE_NAMES.get(mtype, "0x%02x" % mtype),
        "length": length,
        "node_id": node_id,
        # node_id is an IPv4 address packed big-endian; render it as one.
        "node_ip": "%d.%d.%d.%d" % (
            (node_id >> 24) & 0xFF, (node_id >> 16) & 0xFF,
            (node_id >> 8) & 0xFF, node_id & 0xFF),
        "channel": channel,
        "channel_name": CHANNEL_NAMES.get(channel, "0x%02x" % channel),
        "tier": tier,
        "tier_name": TIER_NAMES.get(tier, "0x%02x" % tier),
        "reserved": reserved,
        "seq_num": seq_num,
        "timestamp_ns": ts,
        "hmac": raw[24:56],
    }


def verify_observation_hmac(raw, okey):
    """Recompute the O-Key HMAC over a signed VIRP message.

    Signed region is header-without-HMAC (bytes 0..24) concatenated with the
    payload (bytes 56..56+payload_len), where payload_len derives from the
    header's declared length. Mirrors virp_verify() in the C library and the
    pure-Python parity check in tests/test_hmac_parity.py.

    Returns (verdict, detail).
    """
    if okey is None:
        return UNCHECKED, "no O-Key available"
    if raw is None or len(raw) < VIRP_HEADER_SIZE:
        return FAIL, "message shorter than %d-byte header" % VIRP_HEADER_SIZE

    length = struct.unpack_from("!H", raw, 2)[0]
    if length < VIRP_HEADER_SIZE:
        return FAIL, "declared length %d < header size" % length
    payload_len = length - VIRP_HEADER_SIZE
    if len(raw) < VIRP_HEADER_SIZE + payload_len:
        return FAIL, ("declared length %d exceeds stored bytes %d"
                      % (length, len(raw)))

    received = raw[24:56]
    signed = raw[0:24] + raw[VIRP_HEADER_SIZE:VIRP_HEADER_SIZE + payload_len]
    computed = hmac.new(okey, signed, hashlib.sha256).digest()
    if hmac.compare_digest(computed, received):
        return PASS, ""
    return FAIL, ("HMAC mismatch: computed %s, stored %s"
                  % (computed.hex()[:16], received.hex()[:16]))


def parse_observation_payload(raw):
    """Extract the observation body from a signed message.

    Payload begins with virp_observation_t {u8 obs_type, u8 obs_scope,
    u16 obs_length} followed by obs_length bytes of data. The data for device
    observations is text of the form "<device>$ <command>\\n<output>".
    """
    if raw is None or len(raw) < VIRP_HEADER_SIZE + 4:
        return None
    obs_type, obs_scope, obs_length = struct.unpack_from(
        "!BBH", raw, VIRP_HEADER_SIZE)
    start = VIRP_HEADER_SIZE + 4
    data = raw[start:start + obs_length]
    text = data.decode("utf-8", errors="replace")
    command = ""
    output = text
    if "\n" in text:
        first, rest = text.split("\n", 1)
        if "$ " in first or first.endswith("$"):
            command = first.split("$ ", 1)[-1] if "$ " in first else ""
            output = rest
        elif ">" in first:
            # REST-style: "<device>>/path [HTTP 200]"
            command = first.split(">", 1)[-1]
            output = rest
    return {
        "obs_type": obs_type,
        "obs_scope": obs_scope,
        "obs_length": obs_length,
        "text": text,
        "command": command.strip(),
        "output": output,
    }


def device_from_artifact_id(artifact_id):
    """Observation artifact ids are 'obs:<device>:<nanos>'. Return <device>."""
    if artifact_id and artifact_id.startswith("obs:"):
        rest = artifact_id[4:]
        idx = rest.rfind(":")
        if idx > 0:
            return rest[:idx]
    return ""


class EntryVerification:
    """Per-entry verification results. Every field is a verdict constant."""

    __slots__ = ("entry", "entry_hash", "entry_hash_detail", "link",
                 "link_detail", "chain_hmac", "chain_hmac_detail",
                 "artifact_bind", "artifact_bind_detail", "obs_hmac",
                 "obs_hmac_detail", "header", "payload", "artifact_raw",
                 "artifact_content", "device")

    def __init__(self, entry):
        self.entry = entry
        self.entry_hash = UNCHECKED
        self.entry_hash_detail = ""
        self.link = UNCHECKED
        self.link_detail = ""
        self.chain_hmac = UNCHECKED
        self.chain_hmac_detail = ""
        self.artifact_bind = UNCHECKED
        self.artifact_bind_detail = ""
        # Only observations carry an O-Key signature; every other row is N/A
        # rather than "unchecked", so the counter cannot be misread as work
        # left undone.
        self.obs_hmac = NOT_APPLICABLE
        self.obs_hmac_detail = ""
        self.header = None
        self.payload = None
        self.artifact_raw = None
        self.artifact_content = None
        self.device = ""

    @property
    def ok(self):
        """True only if nothing that ran came back FAIL."""
        return FAIL not in (self.entry_hash, self.link, self.chain_hmac,
                            self.artifact_bind, self.obs_hmac)

    @property
    def failures(self):
        """List of (check_name, detail) for every FAIL on this entry."""
        out = []
        for name, verdict, detail in (
                ("entry_hash", self.entry_hash, self.entry_hash_detail),
                ("link", self.link, self.link_detail),
                ("chain_hmac", self.chain_hmac, self.chain_hmac_detail),
                ("artifact_bind", self.artifact_bind,
                 self.artifact_bind_detail),
                ("observation_hmac", self.obs_hmac, self.obs_hmac_detail)):
            if verdict == FAIL:
                out.append((name, detail))
        return out


def verify_entry(entry, artifact_content, okey, chain_key, expected_prev):
    """Run every available check against one chain entry."""
    v = EntryVerification(entry)

    canonical = canonical_json(entry)

    # 1. entry hash — no key required
    computed = hashlib.sha256(canonical.encode()).hexdigest()
    if computed == entry["chain_entry_hash"]:
        v.entry_hash = PASS
    else:
        v.entry_hash = FAIL
        v.entry_hash_detail = ("recomputed %s, stored %s"
                               % (computed[:16], entry["chain_entry_hash"][:16]))

    # 2. link continuity — no key required
    if expected_prev is None:
        v.link = UNCHECKED
        v.link_detail = "no predecessor available in the selected range"
    elif entry["previous_entry_hash"] == expected_prev:
        v.link = PASS
    else:
        v.link = FAIL
        v.link_detail = ("previous_entry_hash %s does not match predecessor %s"
                         % (entry["previous_entry_hash"][:16],
                            expected_prev[:16]))

    # 3. chain HMAC under K_chain
    if chain_key is None:
        v.chain_hmac = UNCHECKED
        v.chain_hmac_detail = "no chain key available"
    else:
        mac = hmac.new(chain_key, canonical.encode(), hashlib.sha256).hexdigest()
        if hmac.compare_digest(mac, entry["chain_hmac"]):
            v.chain_hmac = PASS
        else:
            v.chain_hmac = FAIL
            v.chain_hmac_detail = ("recomputed %s, stored %s"
                                   % (mac[:16], entry["chain_hmac"][:16]))

    # 4. artifact binding + 5. observation HMAC
    #
    # A mismatch here is only a tampering signal when the chain actually
    # retained the bytes the entry commits to. Where the format guarantees it
    # did not, the honest verdict is UNVERIFIABLE with the structural reason —
    # reporting those as FAIL would mark a healthy chain as compromised.
    v.artifact_content = artifact_content
    raw = decode_artifact(artifact_content)
    v.artifact_raw = raw
    atype = entry["artifact_type"]
    truncated = (artifact_content is not None
                 and len(artifact_content) >= ARTIFACT_CONTENT_MAX)

    if artifact_content is None:
        v.artifact_bind = UNVERIFIABLE
        v.artifact_bind_detail = (
            RETENTION_NO_BODY if atype in NO_BODY_TYPES
            else "no artifact body is stored for this entry")
    elif raw is None:
        v.artifact_bind = FAIL
        v.artifact_bind_detail = "artifact body is not decodable base64"
    else:
        digest = hashlib.sha256(raw).hexdigest()
        if digest == entry["artifact_hash"]:
            v.artifact_bind = PASS
        elif truncated:
            v.artifact_bind = UNVERIFIABLE
            v.artifact_bind_detail = RETENTION_TRUNCATED
        elif atype in INDIRECT_COMMITMENT_TYPES:
            v.artifact_bind = UNVERIFIABLE
            v.artifact_bind_detail = RETENTION_INDIRECT
        else:
            v.artifact_bind = FAIL
            v.artifact_bind_detail = (
                "sha256(artifact) %s does not match entry artifact_hash %s"
                % (digest[:16], entry["artifact_hash"][:16]))

    v.device = device_from_artifact_id(entry["artifact_id"])

    if atype == "observation":
        if raw is None:
            v.obs_hmac = UNVERIFIABLE
            v.obs_hmac_detail = "no signed message body is stored"
        elif truncated:
            # The signed region is incomplete, so the HMAC cannot be
            # recomputed at all. Not a failure of the signature — a failure
            # of retention.
            v.header = parse_message_header(raw)
            v.obs_hmac = UNVERIFIABLE
            v.obs_hmac_detail = RETENTION_TRUNCATED
        else:
            v.header = parse_message_header(raw)
            v.payload = parse_observation_payload(raw)
            v.obs_hmac, v.obs_hmac_detail = verify_observation_hmac(raw, okey)

    return v


def verify_chain(entries, artifacts, okey=None, chain_key=None,
                 heads=None, selection_complete=False):
    """Verify a list of chain entries (dicts) in session/sequence order.

    `artifacts` maps artifact_id -> artifact_content (or is missing the key).

    `heads` maps session_id -> head row dict (last_sequence,
    last_entry_hash, head_hmac) from the chain_heads table, or is None when
    the table was absent (pre-2026-08-01 database) or not loaded. The head
    record is the SIGNED commitment to chain length: without it, link
    continuity proves only that the rows present are consistent, not that
    the tail was retained — deleting the last K entries of a session leaves
    every per-entry check passing.

    Link continuity is evaluated per session. Where the selected range does
    not start at sequence 0, the first entry of that session has no in-range
    predecessor and its link is UNCHECKED rather than assumed good — a
    filtered report must not claim continuity it did not observe.

    Returns (verifications, summary dict). summary["heads"] holds the
    per-session head verdicts and their tally.
    """
    by_session = {}
    for e in entries:
        by_session.setdefault(e["session_id"], []).append(e)

    verifications = []
    for session_id in sorted(by_session):
        rows = sorted(by_session[session_id], key=lambda r: r["sequence"])
        prev_hash = None
        prev_seq = None
        for e in rows:
            if e["sequence"] == 0:
                expected = genesis_hash(session_id)
            elif prev_seq is not None and e["sequence"] == prev_seq + 1:
                expected = prev_hash
            elif prev_seq is not None:
                # A gap inside the session: sequences are not contiguous.
                expected = None
            else:
                # First row we have for this session, and it is not seq 0.
                expected = None
            v = verify_entry(e, artifacts.get(e["artifact_id"]),
                             okey, chain_key, expected)
            if expected is None and prev_seq is not None:
                v.link = FAIL
                v.link_detail = (
                    "sequence gap: previous entry in this session was %d, "
                    "this is %d" % (prev_seq, e["sequence"]))
            verifications.append(v)
            prev_hash = e["chain_entry_hash"]
            prev_seq = e["sequence"]

    head_results = verify_heads(by_session, heads, chain_key,
                                selection_complete)

    summary = summarize(verifications)
    summary["heads"] = head_results
    # Fold head FAILs into failed_entries so every consumer of the summary
    # — the PDF failure table, the printed tally, the process exit code —
    # fails when a session's length claim fails. Adversarial audit
    # 2026-08-06 (Finding B): these verdicts used to be computed and then
    # read by nobody, so a tail+head-deleted chain reported clean.
    for sid in sorted(head_results["per_session"]):
        verdict, detail = head_results["per_session"][sid]
        if verdict == FAIL:
            last_seq = max(e["sequence"] for e in by_session[sid])
            summary["failed_entries"].append(
                HeadFailure(sid, last_seq, detail))
    return verifications, summary


# Canonical form for the head HMAC — must match src/virp_chain.c
# head_canonical() BYTE FOR BYTE (alphabetical keys, compact separators,
# no escaping, version-tagged), for the same reason canonical_json above
# reproduces the C producer exactly.
def head_canonical(session_id, last_sequence, last_entry_hash):
    return ('{"last_entry_hash":"%s",'
            '"last_sequence":%d,'
            '"session_id":"%s",'
            '"v":"VIRP-CHAIN-HEAD-v1"}'
            % (last_entry_hash, last_sequence, session_id))


class HeadFailure:
    """A per-session head FAIL, shaped like a failed entry so it rides the
    same failed_entries plumbing as per-entry failures (renderers read
    .entry["session_id"], .entry["sequence"], .ok and .failures)."""

    is_head = True

    def __init__(self, session_id, last_visible_sequence, detail):
        self.entry = {"session_id": session_id,
                      "sequence": last_visible_sequence,
                      "artifact_type": "(session head)"}
        self.ok = False
        self.failures = [("session head", detail)]


def verify_heads(by_session, heads, chain_key, selection_complete=False):
    """Check each selected session against its signed head record.

    Verdicts per session:

      FAIL       head missing while the table exists (tail-plus-head
                 deletion is exactly the attack the record exists to catch);
                 or visible entries extend BEYOND the head (a head can never
                 lag — it commits in the same transaction as every append);
                 or the head names the visible final entry but the hash or
                 HMAC does not match.
      UNCHECKED  the selection ends before the head's committed tail AND
                 selection_complete is False (a time-filtered report
                 legitimately excludes the tail; the unselected remainder is
                 simply not verified HERE — with selection_complete=True the
                 same condition is a FAIL: truncation); or the structural
                 checks pass but no chain key was provided to authenticate
                 the head itself.
      UNVERIFIABLE  heads is None: pre-2026-08-01 database or export
                 without a chain_heads table. Chain LENGTH is then not
                 authenticated by anything — the honest structural verdict.
      PASS       head authenticated, and the selection's final entry is
                 exactly the one the head commits to.

    Returns {"per_session": {sid: (verdict, detail)}, "tally": {...}}.
    """
    per_session = {}
    for sid in sorted(by_session):
        rows = sorted(by_session[sid], key=lambda r: r["sequence"])
        max_seq = rows[-1]["sequence"]
        max_hash = rows[-1]["chain_entry_hash"]

        if heads is None:
            per_session[sid] = (
                UNVERIFIABLE,
                "no chain_heads table (pre-2026-08-01 database): chain "
                "length is not authenticated; tail deletion would be "
                "undetectable")
            continue

        head = heads.get(sid)
        if head is None:
            per_session[sid] = (
                FAIL,
                "no head record for a session with entries; chain length "
                "cannot be authenticated (consistent with tail+head "
                "deletion)")
            continue

        h_seq = int(head["last_sequence"])
        h_hash = head["last_entry_hash"]
        h_mac = head["head_hmac"]

        if max_seq > h_seq:
            per_session[sid] = (
                FAIL,
                "entries visible beyond the head (head=%d, visible=%d); "
                "the head updates transactionally with every append and "
                "can never lag" % (h_seq, max_seq))
            continue

        if max_seq < h_seq:
            # Whether this is damning depends on what the caller selected.
            # selection_complete=True asserts the caller loaded the WHOLE
            # session, so an entry the head commits to but the selection
            # lacks is a truncation. With a time-filtered selection the
            # missing tail may simply be outside the window — UNCHECKED,
            # because a filtered report must not cry wolf about a healthy
            # chain (same principle as the link-continuity UNCHECKED).
            if selection_complete:
                per_session[sid] = (
                    FAIL,
                    "chain truncated: head commits to sequence %d but the "
                    "session ends at %d" % (h_seq, max_seq))
            else:
                per_session[sid] = (
                    UNCHECKED,
                    "selection ends at %d; head commits to %d — the tail "
                    "beyond this selection is not verified here (rerun "
                    "unfiltered to verify the whole session)"
                    % (max_seq, h_seq))
            continue

        # max_seq == h_seq: the head names our final entry
        if max_hash != h_hash:
            per_session[sid] = (
                FAIL,
                "head last_entry_hash %s does not match final entry %s"
                % (h_hash[:16], max_hash[:16]))
            continue

        if chain_key is None:
            per_session[sid] = (
                UNCHECKED,
                "head structurally consistent but unauthenticated: no "
                "chain key available to verify head_hmac")
            continue

        canonical = head_canonical(sid, h_seq, h_hash)
        mac = hmac.new(chain_key, canonical.encode(),
                       hashlib.sha256).hexdigest()
        if hmac.compare_digest(mac, h_mac):
            per_session[sid] = (PASS, None)
        else:
            per_session[sid] = (
                FAIL,
                "head_hmac mismatch: recomputed %s, stored %s"
                % (mac[:16], h_mac[:16]))

    tally = {PASS: 0, FAIL: 0, UNCHECKED: 0, UNVERIFIABLE: 0}
    for verdict, _ in per_session.values():
        tally[verdict] += 1
    return {"per_session": per_session, "tally": tally}


def _tally(verifications, attr):
    counts = {PASS: 0, FAIL: 0, UNCHECKED: 0, UNVERIFIABLE: 0,
              NOT_APPLICABLE: 0}
    for v in verifications:
        counts[getattr(v, attr)] += 1
    return counts


def retention_reasons(verifications):
    """Count entries per structural reason a check could not be run.

    The integrity summary prints this so an UNVERIFIABLE count is never a
    bare number the reader has to take on faith.
    """
    reasons = {}
    for v in verifications:
        for verdict, detail in ((v.artifact_bind, v.artifact_bind_detail),
                                (v.obs_hmac, v.obs_hmac_detail)):
            if verdict == UNVERIFIABLE and detail:
                reasons[detail] = reasons.get(detail, 0) + 1
    return reasons


def summarize(verifications):
    """Aggregate counters plus the first broken link, if any."""
    first_broken = None
    for v in sorted(verifications,
                    key=lambda x: (x.entry["session_id"], x.entry["sequence"])):
        if v.link == FAIL:
            first_broken = v
            break

    return {
        "entries": len(verifications),
        "entry_hash": _tally(verifications, "entry_hash"),
        "link": _tally(verifications, "link"),
        "chain_hmac": _tally(verifications, "chain_hmac"),
        "artifact_bind": _tally(verifications, "artifact_bind"),
        "obs_hmac": _tally(verifications, "obs_hmac"),
        "observations": sum(1 for v in verifications
                            if v.entry["artifact_type"] == "observation"),
        "failed_entries": [v for v in verifications if not v.ok],
        "first_broken_link": first_broken,
        "sessions": len({v.entry["session_id"] for v in verifications}),
        "retention_reasons": retention_reasons(verifications),
    }
