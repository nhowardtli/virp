#!/usr/bin/env python3
"""
virp_tacacs_policy.py — compile VIRP approvals into TACACS+ authorization
policy, and render the router-side AAA config. LAB ONLY.

The compiler is a CHAIN CONSUMER. It reads approvals through the same
read path the accounting reconciler uses and writes exactly one kind of
record back: `tacacs_authz_policy_rendered/1`, committing to the sha256
of the policy it rendered and the approval ids inside it. That record is
what lets an auditor answer "what would this router have accepted at
14:03?" without trusting the compiler.

Refusal is the default. An approval is rendered only when it is
signature-VERIFIED, unexpired, names a device in the lab inventory, and
carries a command that canonicalises. Anything else is refused with a
reason and the refusal is reported, never dropped -- an approval that
silently failed to render is a silent denial of an approved action, which
looks identical to an attack.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import hashlib
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from virp_tacacs_authz import (canonical_command, command_spellings,
                               ios_canonical, is_do_command, SPELLING_RULE,
                               GATE_IDENTITIES, GATE_IDENTITY_RW)

# 2c: the compiler and the reconciler call the SAME function. If these
# two ever diverge, a command is authorized under one spelling and
# reconciled under another, and both records look correct in isolation.
canonical_for_policy = ios_canonical

SCHEMA = "tacacs_authz_policy/1"
RENDERED_SCHEMA = "tacacs_authz_policy_rendered/1"
RENDER_REFUSED_SCHEMA = "tacacs_authz_policy_render_refused/1"

# Text IOS will silently rewrite before it ever reaches authorization.
# An approval containing any of these means the approver believes they
# authorized something the router will never be asked about, so it is
# refused rather than rendered under a different meaning.
UNRENDERABLE = (
    (";", "IOS TRUNCATES at ';' -- everything after it is discarded "
          "before authorization and before execution"),
    ("|", "IOS STRIPS the output filter after '|' -- it never reaches "
          "the authorization or accounting record"),
    ("\n", "a newline is more than one command; one approval grants one "
            "command"),
    ("\r", "a carriage return is more than one command; one approval "
            "grants one command"),
)


def unrenderable_reason(command):
    """Why this approval text cannot be rendered, or None."""
    for ch, why in UNRENDERABLE:
        if ch in (command or ""):
            return ("approval text contains %r, which IOS would rewrite "
                    "before authorizing: %s. Rendering it would grant a "
                    "different command than the one approved. Re-approve "
                    "the command actually intended." % (ch, why))
    return None

# The authorization server's own AAA identifiers on the router.
AUTHZ_SERVER_NAME = "VIRPAZ"
AUTHZ_GROUP = "GRP-VIRPAZ"
RW_LIST = "VIRPRW"
RO_LIST = "VIRPRO"
CONSOLE_LIST = "CONSOLE"

DEFAULT_TTL_NS = 300 * 1_000_000_000

# Commands that only exist inside configuration mode. An approval for one
# of these is unusable unless the session can also run `configure
# terminal`, which no approval covers -- so the compiler emits that as a
# DERIVED grant, marked as such, sharing the approval's window and spent
# once. Safe because `aaa authorization config-commands` is on: the
# session reaches config mode and can still run only the approved line.
CONFIG_MODE_PREFIXES = (
    "interface ", "router ", "ip route ", "no ", "hostname ",
    "username ", "aaa ", "line ", "access-list ", "snmp-server ",
    "description ", "shutdown", "ip address ", "banner ", "crypto ",
    "logging ", "ntp ", "vlan ", "spanning-tree ", "tacacs ",
)
CONFIG_ENTRY_COMMAND = "configure terminal"

# Never a real password in a committed template. The lab substitutes a
# value at apply time; production substitutes from a vault.
BREAKGLASS_SECRET_PLACEHOLDER = "${BREAKGLASS_SECRET}"
BREAKGLASS_USER = "breakglass"


def is_config_mode_command(cmd):
    c = canonical_command(cmd) or ""
    return any(c == p.strip() or c.startswith(p)
               for p in CONFIG_MODE_PREFIXES)


# ── the approver signature, verified by THIS compiler ──────────────────
#
# HAM review 2026-09-06, item 6. -07 requires the party issuing temporary
# write authority to verify the approver's signature itself rather than
# trusting the gate's word for it. Until now this compiler could not:
# the chained approval body carried approver_key_id but no signature, and
# `approval_trusted` was built from binding correctness, which is a real
# check and is not a signature.
#
# The daemon now writes the signature into the approval body
# (body_version 2, src/virp_approval.c). This compiler RECONSTRUCTS the
# 72-byte canonical payload from the body's own fields and verifies the
# signature against ITS OWN pinned registry. Two consequences worth
# stating:
#
#   - reconstructing, rather than reading a carried payload, is what
#     makes the signature bind the fields. A payload travelling beside
#     the body could verify while the body said something else.
#   - the ALGORITHM comes from the pinned registry entry, never from the
#     body. A body-declared scheme would be attacker material deciding
#     how the body gets checked.
#
# Layout from include/virp_approval.h:
#   off  0  magic "VAP1"          off 52  device_node_id  (8, big-endian)
#   off  4  proposal_id  (16)     off 60  approved_at_ns  (8, big-endian)
#   off 20  command_hash (32)     off 68  ttl_seconds     (4, big-endian)
APPROVAL_CANON_MAGIC = b"VAP1"
APPROVAL_CANON_SIZE = 72


def build_approval_canonical(proposal_id_hex, command_hash_hex,
                             device_node_id, approved_at_ns, ttl_seconds):
    """The exact bytes virp_approval_build_canonical() produces."""
    pid = bytes.fromhex(proposal_id_hex)
    ch = bytes.fromhex(command_hash_hex)
    if len(pid) != 16:
        raise ValueError("proposal_id is %d bytes, not 16" % len(pid))
    if len(ch) != 32:
        raise ValueError("command_hash is %d bytes, not 32" % len(ch))
    out = (APPROVAL_CANON_MAGIC + pid + ch
           + int(device_node_id).to_bytes(8, "big")
           + int(approved_at_ns).to_bytes(8, "big")
           + int(ttl_seconds).to_bytes(4, "big"))
    assert len(out) == APPROVAL_CANON_SIZE
    return out


class ApproverRegistry:
    """The COMPILER's pinned approver public keys.

    Deliberately its own file, under the compiler's control, in the same
    shape as the daemon's /etc/virp/approvers.json. It is NOT read from
    the gate and NOT read from the chain: a registry the checked party
    supplies is not an independent check."""

    def __init__(self, entries):
        self.entries = {}
        for e in entries or []:
            kid = e.get("key_id")
            if kid and kid not in self.entries:
                self.entries[kid] = e

    @classmethod
    def load(cls, path):
        with open(path) as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError("%s is not a JSON array of approver entries"
                             % path)
        return cls(data)

    def find(self, key_id):
        return self.entries.get(key_id)


def _load_pubkey(entry):
    """Raw verifying key from a base64 SPKI, cross-checked against the
    entry's declared key_id exactly as the C loader does. An entry whose
    declared key_id does not match its own public key is a
    misconfiguration and is refused, never trusted."""
    import base64
    import hashlib as _h
    from cryptography.hazmat.primitives import serialization
    spki = base64.b64decode(entry["public_key"])
    pub = serialization.load_der_public_key(spki)
    alg = (entry.get("algorithm") or "").lower()
    if alg == "ed25519":
        from cryptography.hazmat.primitives.asymmetric import ed25519
        if not isinstance(pub, ed25519.Ed25519PublicKey):
            raise ValueError("entry declares ed25519 but the key is not")
        raw = pub.public_bytes_raw()
    elif alg == "ecdsa-p256":
        from cryptography.hazmat.primitives.asymmetric import ec
        if not isinstance(pub, ec.EllipticCurvePublicKey):
            raise ValueError("entry declares ecdsa-p256 but the key is not")
        raw = pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint)
    else:
        raise ValueError("unknown algorithm %r" % entry.get("algorithm"))
    if _h.sha256(raw).hexdigest()[:32] != entry.get("key_id"):
        raise ValueError("entry key_id does not match its own public key")
    return alg, pub


def verify_approver_signature(approval, registry):
    """(verified, reason). Never raises for hostile input.

    `verified` is True only when a key THIS compiler pinned, and which is
    enabled, signed the 72-byte payload reconstructed from this body's
    own fields."""
    if registry is None:
        return False, ("no approver registry is pinned; this compiler can "
                       "verify nothing and therefore renders nothing")
    sig_hex = approval.get("approver_signature")
    if not sig_hex:
        return False, ("approval body carries no approver_signature "
                       "(body_version %r); pre-2026-09-06 bodies cannot be "
                       "verified by any consumer and are not upgraded by "
                       "silence" % approval.get("body_version"))
    kid = approval.get("approver_key_id")
    entry = registry.find(kid)
    if entry is None:
        return False, ("approver_key_id %r is not in this compiler's pinned "
                       "registry" % kid)
    if entry.get("enabled") is not True:
        return False, "approver_key_id %r is pinned but disabled" % kid
    try:
        alg, pub = _load_pubkey(entry)
        canon = build_approval_canonical(
            approval.get("proposal_id"), approval.get("command_hash"),
            int(approval.get("device_node_id") or 0),
            int(approval.get("approved_at_ns") or 0),
            int(approval.get("ttl_seconds") or 0))
        sig = bytes.fromhex(sig_hex)
    except (ValueError, TypeError, KeyError) as e:
        return False, "approval could not be reconstructed for verification: %s" % e
    try:
        if alg == "ed25519":
            pub.verify(sig, canon)
        else:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.asymmetric import ec, utils
            if len(sig) != 64:
                return False, "ecdsa-p256 signature is not 64 raw bytes"
            r = int.from_bytes(sig[:32], "big")
            sv = int.from_bytes(sig[32:], "big")
            pub.verify(utils.encode_dss_signature(r, sv), canon,
                       ec.ECDSA(hashes.SHA256()))
    except Exception as e:                      # noqa: BLE001 - any failure is a failure
        return False, ("approver signature did not verify under pinned key "
                       "%s: %s" % (kid, type(e).__name__))
    return True, "approver signature verified under pinned key %s" % kid


def command_hash(command):
    """sha256 over VIRP's canonical command form.

    Mirrors command_hash_hex() in src/virp_approval.c for the non-typed
    path: virp_canonicalize_command() then sha256 of the result. The
    compiler recomputes this rather than trusting the hash in either
    record, because a hash copied from the thing being checked proves
    nothing."""
    return hashlib.sha256(
        canonical_command(command).encode("utf-8")).hexdigest()


def approval_from_chain(proposal, approval, registry=None):
    """Join a chained proposal to its approval and state, honestly, what
    was verified.

    `trust_basis` lists the checks that ran and passed;
    `trust_not_established` lists the checks that could not run at all.
    Nothing is ever upgraded by silence.

    HISTORY, kept because it explains the shape: until 2026-09-06 the
    chained approval body carried `approver_key_id` but NOT the
    approver's signature, so a chain-only consumer could not verify it
    and "approver_signature" sat permanently in the second list. The
    daemon now writes the signature into the body (body_version 2) and
    this function verifies it against the caller's OWN pinned registry.
    A body without one still lands in the second list, exactly as before:
    a legacy record is not made trustworthy by being old.

    `registry` is required for `approval_trusted` to be True. Absent, the
    compiler can verify nothing and says so, which renders nothing.
    """
    basis, missing = [], []
    sig_ok, sig_detail = verify_approver_signature(approval, registry)
    if sig_ok:
        basis.append("approver_signature_verified")
    else:
        missing.append("approver_signature")

    p_hash = proposal.get("command_hash")
    a_hash = approval.get("command_hash")
    if p_hash and a_hash and p_hash == a_hash:
        basis.append("command_hash_binding")

    recomputed = command_hash(proposal.get("command") or "")
    if a_hash and recomputed == a_hash:
        basis.append("command_hash_recomputed")

    if proposal.get("device") and proposal.get("device") == approval.get("device"):
        basis.append("device_agreement")

    # The signature is a REQUIREMENT, not a bonus. Binding correctness
    # says the proposal and the approval agree; only the signature says a
    # human this compiler pinned actually approved it.
    trusted = (sig_ok
               and "command_hash_binding" in basis
               and "command_hash_recomputed" in basis
               and "device_agreement" in basis)

    ttl_s = int(approval.get("ttl_seconds") or 0)
    return {
        "approval_id": approval.get("proposal_id"),
        "device": approval.get("device"),
        "command": proposal.get("command"),
        "command_hash": a_hash,
        "issued_utc_ns": int(float(approval.get("approved_at_ns") or 0)),
        "ttl_ns": ttl_s * 1_000_000_000,
        "repeat_count": approval.get("repeat_count"),
        "approver_key_id": approval.get("approver_key_id"),
        "operator": approval.get("operator"),
        "approval_entry_hash": approval.get("_entry_hash"),
        "approval_trusted": trusted,
        "trust_basis": basis,
        "trust_not_established": missing,
        "approver_signature_detail": sig_detail,
    }


def compile_grants(approvals, now_ns, default_uses=1,
                   compiled_approval_ids=()):
    """(grants, refusals).

    One approval, one command, one device, one grant. No approval ever
    produces two grants and no grant ever covers two commands: the whole
    point is that the blast radius of a compromised approval is exactly
    what a human approved.

    `compiled_approval_ids` is the set of approval ids this compiler has
    already rendered, read from its own prior policy_rendered records.
    One approval, one compilation: a second render of the same approval
    is a REPLAY, refused with its own reason rather than quietly minting
    another use of authority a human granted once.
    """
    already = set(compiled_approval_ids or ())
    grants, refusals = [], []
    for a in approvals:
        aid = a.get("approval_id")

        if aid in already:
            refusals.append({
                "approval_id": aid,
                "reason": "approval was already compiled into a policy "
                          "(policy_rendered record on chain); a second "
                          "render is a replay"})
            continue

        # Absence of the flag is NEVER treated as verified. An approval
        # whose signature was not checked is indistinguishable, to this
        # compiler, from one that failed -- and rendering either would let
        # an unsigned record open a router.
        # Accepts either gate: the chain reader sets approval_trusted
        # after recomputing the bindings; synthetic callers set
        # signature_verified. Absence of BOTH is refused exactly as a
        # failure -- absence is never read as verified.
        trusted = a.get("approval_trusted")
        if trusted is None:
            trusted = a.get("signature_verified")
        if trusted is not True:
            refusals.append({
                "approval_id": aid,
                "reason": "approval not verified (approval_trusted=%r, "
                          "signature_verified=%r); basis=%r; "
                          "approver_signature: %s"
                          % (a.get("approval_trusted"),
                             a.get("signature_verified"),
                             a.get("trust_basis"),
                             a.get("approver_signature_detail")
                             or "not checked by this caller")})
            continue

        raw = a.get("command")
        if is_do_command(raw):
            refusals.append({
                "approval_id": aid,
                "reason": "approval text is a 'do' command, which runs an "
                          "EXEC command from config mode. Gate identities "
                          "are never granted 'do': it would turn one "
                          "approved command into a way to run others."})
            continue
        bad = unrenderable_reason(raw)
        if bad:
            refusals.append({"approval_id": aid, "reason": bad})
            continue

        cmd = canonical_command(raw)
        if not cmd:
            refusals.append({"approval_id": aid,
                             "reason": "approval carries no command"})
            continue

        device = a.get("device")
        if not device:
            refusals.append({"approval_id": aid,
                             "reason": "approval names no device"})
            continue

        # A dynamic grant is ISSUED to a gate identity only (HAM item 2).
        # An approval naming any other principal is refused here rather
        # than rendered under the gate's name, which would put an
        # operator's approval behind an identity they never named.
        # Absent means "the gate's write identity", the only subject this
        # compiler has ever rendered for; anything else present must be
        # a gate identity or it is refused.
        principal = a.get("user") or GATE_IDENTITY_RW
        if principal not in GATE_IDENTITIES:
            refusals.append({
                "approval_id": aid,
                "reason": "approval names principal %r, which is not a "
                          "gate identity (%s); dynamic grants are issued "
                          "to the gate only"
                          % (principal, ", ".join(GATE_IDENTITIES))})
            continue

        issued = int(a.get("issued_utc_ns") or 0)
        ttl = int(a.get("ttl_ns") or DEFAULT_TTL_NS)
        not_after = issued + ttl
        if not_after <= now_ns:
            refusals.append({
                "approval_id": aid,
                "reason": "approval already expired (not_after %d <= now %d)"
                          % (not_after, now_ns)})
            continue

        # `or default_uses` would silently CLAMP repeat_count 0 to 1,
        # turning an approval that grants nothing into one that grants a
        # use. An explicit None check refuses it instead.
        rc_raw = a.get("repeat_count")
        uses = default_uses if rc_raw is None else int(rc_raw)
        if uses < 1:
            refusals.append({"approval_id": aid,
                             "reason": "repeat_count %r is below 1" % uses})
            continue

        grants.append({
            "grant_id": "g-%s" % aid,
            "device": device,
            "user": GATE_IDENTITY_RW,
            "command": cmd,
            "approval_id": aid,
            "approval_entry_hash": a.get("approval_entry_hash"),
            "not_before_ns": issued,
            "not_after_ns": not_after,
            "uses_remaining": uses,
            # Written into the grant so an auditor reads exactly what the
            # router will be allowed to say, rather than trusting a
            # matcher's behaviour.
            "accepted_spellings": command_spellings(cmd),
            "spelling_rule": SPELLING_RULE,
            "derived": None,
        })

    # One prerequisite PER DEVICE, spanning that device's config grants.
    #
    # Taking the window from a single arbitrary grant (the first draft
    # used the oldest) gave a freshly approved change a nearly-expired
    # prerequisite, so `configure terminal` was denied and the approved
    # line never ran. Emitting one globally bound it to whichever device
    # sorted first, leaving the other unable to enter config mode. Both
    # denied approved work, which is the failure direction that erodes
    # trust in a control fastest.
    #
    # One use per config grant: each approved line may be applied in its
    # own session, and a session that cannot enter config mode cannot
    # apply the line it was approved for.
    by_device = {}
    for g in grants:
        if is_config_mode_command(g["command"]):
            by_device.setdefault(g["device"], []).append(g)
    for device, cgs in sorted(by_device.items()):
        anchor = min(cgs, key=lambda g: g["not_before_ns"])
        grants.append({
            "grant_id": "g-configentry-%s" % device,
            "device": device,
            "user": GATE_IDENTITY_RW,
            "command": CONFIG_ENTRY_COMMAND,
            "approval_id": anchor["approval_id"],
            "approval_entry_hash": anchor.get("approval_entry_hash"),
            "not_before_ns": min(g["not_before_ns"] for g in cgs),
            "not_after_ns": max(g["not_after_ns"] for g in cgs),
            # One entry into config mode per USE, not per grant: a
            # repeat_count 3 change needs to enter config mode 3 times,
            # and counting grants would leave it stranded after the first.
            "uses_remaining": sum(int(g["uses_remaining"]) for g in cgs),
            "accepted_spellings": command_spellings(CONFIG_ENTRY_COMMAND),
            "spelling_rule": SPELLING_RULE,
            # Never presented as something a human approved.
            "derived": "config_mode_prerequisite",
        })
    return grants, refusals


def build_policy(device, grants, now_ns):
    return {
        "schema": SCHEMA,
        "device": device,
        "rendered_utc_ns": now_ns,
        "grants": [g for g in grants if g.get("device") == device],
    }


def policy_bytes(policy):
    return json.dumps(policy, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def policy_sha256(policy):
    return hashlib.sha256(policy_bytes(policy)).hexdigest()


def render_router_config(device, authz_addr="172.17.0.1", authz_port=4950,
                         authz_key="LabKeyAuthz"):
    """The router-side AAA for per-command authorization.

    Two things here are safety-critical and are asserted by test:

    1. The rw list is `group <tacacs group>` and NOTHING ELSE. No
       `local`, no `if-authenticated`, no `none`. A fallback would make
       the control stop controlling at exactly the moment it matters --
       when the authorization server is unreachable, which is also what a
       determined attacker would arrange. Deny on unreachable is the
       whole point.

    2. The CONSOLE line is EXEMPT from command authorization. Without
       this, an authorization-server outage locks every operator out of
       every router with no recovery path but a password reset. The
       console is physical-access-equivalent in this lab (a GNS3 console
       socket); on real hardware the same exemption is the documented
       break-glass path and it is a deliberate, stated hole.
    """
    return "\n".join([
        "! VIRP per-command authorization — device %s" % device,
        "!",
        "! BREAK-GLASS (design doc §9). Humans are never subject to",
        "! VIRP-driven authorization. This account's PATH is the CONSOLE,",
        "! which is exempt below. There is deliberately NO network",
        "! break-glass path: a separate vty on its own SSH port was",
        "! measured on 2026-09-05 and it does NOT fence the gate --",
        "! virp-rw reached that port and took local privilege 15,",
        "! because a method list authorizes whoever reaches the LINE and",
        "! the gate must hold a local account in order to authenticate.",
        "! A network break-glass needs `access-class` source separation;",
        "! without one it is a gate self-escalation route.",
        "username %s privilege 15 secret 0 %s"
        % (BREAKGLASS_USER, BREAKGLASS_SECRET_PLACEHOLDER),
        "!",
        "! With BOTH servers down the router's own buffer is the only",
        "! evidence that survives. Measured: without these, a break-glass",
        "! `show` leaves no trace at all.",
        "login on-success log",
        "login on-failure log",
        "archive",
        " log config",
        "  logging enable",
        "  notify syslog",
        "  hidekeys",
        "  exit",
        " exit",
        "tacacs server %s" % AUTHZ_SERVER_NAME,
        " address ipv4 %s" % authz_addr,
        " port %d" % authz_port,
        " key %s" % authz_key,
        " exit",
        "aaa group server tacacs+ %s" % AUTHZ_GROUP,
        " server name %s" % AUTHZ_SERVER_NAME,
        " exit",
        "! Without this, commands typed INSIDE config mode are not",
        "! authorized at all -- the whole control defeated by one",
        "! `configure terminal`. MEASURED on IOS 15.2(4)M7.",
        "aaa authorization config-commands",
        "! rw: tacacs+ only. No local, no if-authenticated, no none.",
        "aaa authorization commands 15 %s group %s" % (RW_LIST, AUTHZ_GROUP),
        "aaa authorization commands 1 %s group %s" % (RW_LIST, AUTHZ_GROUP),
        "! console break-glass: exempt, deliberately and visibly.",
        "aaa authorization commands 15 %s none" % CONSOLE_LIST,
        "aaa authorization commands 1 %s none" % CONSOLE_LIST,
        "line con 0",
        " authorization commands 15 %s" % CONSOLE_LIST,
        " authorization commands 1 %s" % CONSOLE_LIST,
        " exit",
        "! EVERY vty line, not just 0-4. Found by diffing running configs:",
        "! a router with vty 5-15 left those lines with NO command",
        "! authorization, so a session overflowing past vty 4 ran",
        "! unpoliced. A line the template does not mention is a line the",
        "! control does not cover.",
        "line vty 0 15",
        " authorization commands 15 %s" % RW_LIST,
        " authorization commands 1 %s" % RW_LIST,
        " transport input ssh",
        " exit",
    ])


def wait_for_policy_load(ledger_path, sha, timeout_s=10.0, poll_s=0.25):
    """True only when the authorization daemon's OWN ledger says it
    loaded this exact policy sha.

    A render that was written but never loaded is a silent deny of an
    approved action and is indistinguishable from an attack, so the
    compiler must never report success on the strength of having written
    a file. A missing or unreadable ledger returns False: absence of
    evidence that it loaded is not evidence that it did.
    """
    deadline = time.time() + timeout_s
    while True:
        try:
            with open(ledger_path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if (rec.get("event") == "POLICY_LOADED"
                            and rec.get("policy_sha256") == sha):
                        return True
        except OSError:
            pass
        if time.time() >= deadline:
            return False
        time.sleep(poll_s)


def build_rendered_record(device, policy, refusals, policy_path):
    """The one record this compiler writes. It commits to the policy bytes
    a router would have been judged against, so an auditor can bind a
    decision to a policy rather than to the compiler's word."""
    return {
        "schema": RENDERED_SCHEMA,
        "device": device,
        "rendered_utc_ns": policy["rendered_utc_ns"],
        "policy_sha256": policy_sha256(policy),
        "policy_bytes_len": len(policy_bytes(policy)),
        "policy_path": policy_path,
        "grant_count": len(policy["grants"]),
        "approval_ids": sorted(g["approval_id"] for g in policy["grants"]),
        "refusals": refusals,
        "presentation": (
            "CLAIM about what the authorization server was configured to "
            "accept. Render beside the verdict ladder, never inside it. "
            "It does not assert any command was run."),
    }


# ── CLI: chain -> policy -> verified load -> policy_rendered record ────

def compile_from_chain(db_path, now_ns, registry=None):
    """(approvals, refusals_from_join). Reads through the reconciler's
    shared reader, joins approval to proposal by proposal_id, and refuses
    any approval whose proposal is absent -- command text must never
    enter the policy from an unbound source.

    `registry` is this compiler's own pinned approver keys. Without it
    nothing verifies and nothing renders."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import virp_tacacs_reconcile as rc

    rows = rc.read_entries(db_path, artifact_types=("proposal", "approval"))
    proposals, approvals = {}, []
    for r in rows:
        b = r["body"]
        if r["artifact_type"] == "proposal":
            proposals[b.get("proposal_id")] = b
        else:
            b = dict(b)
            b["_entry_hash"] = r["chain_entry_hash"]
            approvals.append(b)

    joined, refusals = [], []
    for a in approvals:
        pid = a.get("proposal_id")
        pr = proposals.get(pid)
        if pr is None:
            refusals.append({
                "approval_id": pid,
                "reason": "no proposal on chain for this approval; the "
                          "command text is unbound and will not be rendered"})
            continue
        joined.append(approval_from_chain(pr, a, registry=registry))
    return joined, refusals


def compiled_approval_ids_from_chain(db_path):
    """Approval ids this compiler has already rendered, read from its own
    prior `tacacs_authz_policy_rendered/1` records on the chain.

    The compiler's replay check is answered from the chain rather than
    from a local file, because a local file is exactly the thing an
    attacker who can re-run the compiler would delete."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import virp_tacacs_reconcile as rc
    out = set()
    for r in rc.read_entries(db_path, artifact_types=("evidence_item",)):
        b = r["body"]
        if b.get("schema") != RENDERED_SCHEMA:
            continue
        for aid in (b.get("approval_ids") or []):
            out.add(aid)
    return out


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        description="Compile VIRP approvals into TACACS+ authorization "
                    "policy (lab only)")
    ap.add_argument("--db", required=True)
    ap.add_argument("--out", required=True, help="policy JSON the daemon reads")
    ap.add_argument("--device", action="append", default=None,
                    help="restrict to these devices (repeatable)")
    ap.add_argument("--authz-ledger", help="daemon ledger, to confirm the load")
    ap.add_argument("--load-timeout", type=float, default=15.0)
    ap.add_argument("--submit", action="store_true",
                    help="append the policy_rendered record")
    ap.add_argument("--producer-key")
    ap.add_argument("--onode-socket")
    ap.add_argument("--chain-session", default="tacacs-authz-policy")
    ap.add_argument("--approver-registry", required=True,
                    help="THIS compiler's pinned approver public keys "
                         "(approvers.json shape). Required: an issuer of "
                         "write authority that cannot verify the approval "
                         "signature itself is taking the gate's word for "
                         "it, which -07 does not allow.")
    ap.add_argument("--allow-recompile", action="store_true",
                    help="render an approval that a prior policy_rendered "
                         "record already compiled. Off by default: one "
                         "approval, one compilation.")
    a = ap.parse_args(argv)

    registry = ApproverRegistry.load(a.approver_registry)
    now = time.time_ns()
    joined, join_refusals = compile_from_chain(a.db, now, registry=registry)
    already = (set() if a.allow_recompile
               else compiled_approval_ids_from_chain(a.db))
    grants, refusals = compile_grants(joined, now_ns=now,
                                      compiled_approval_ids=already)
    refusals = join_refusals + refusals

    devices = a.device or sorted({g["device"] for g in grants}) or ["R1"]
    all_grants = [g for g in grants if g["device"] in devices]

    combined = {"schema": SCHEMA, "device": ",".join(devices),
                "rendered_utc_ns": now, "grants": all_grants}
    tmp = a.out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(combined, f, indent=1, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, a.out)

    sha = policy_sha256(combined)
    print("grants: %d   refusals: %d   policy_sha256: %s"
          % (len(all_grants), len(refusals), sha))
    for r in refusals:
        print("  REFUSED %s: %s" % (r.get("approval_id"), r.get("reason")))
    for g in all_grants:
        print("  GRANT %s %s %r uses=%d until=%d"
              % (g["grant_id"], g["device"], g["command"],
                 g["uses_remaining"], g["not_after_ns"]))

    loaded = None
    if a.authz_ledger:
        loaded = wait_for_policy_load(a.authz_ledger, sha,
                                      timeout_s=a.load_timeout)
        print("daemon loaded this policy: %s" % ("YES" if loaded else "NO"))
        if not loaded:
            # A render that was written but not loaded is a silent deny.
            print("REFUSING to report success: the daemon has not "
                  "confirmed this policy", file=sys.stderr)

    if a.submit:
        if not a.producer_key:
            raise SystemExit("--submit needs --producer-key")
        from virp_tacacs_recv import (producer_load_sk, producer_sign,
                                      chain_append_evidence)
        rec = build_rendered_record(combined["device"], combined, refusals,
                                    a.out)
        rec["daemon_load_confirmed"] = loaded
        sk = producer_load_sk(a.producer_key)
        body_bytes, _ = producer_sign(sk, rec)
        aid = "authzpolicy:%d:%s" % (now, sha[:16])
        ok, detail = chain_append_evidence(a.chain_session, aid, body_bytes,
                                           a.onode_socket)
        if not ok:
            raise SystemExit("policy_rendered NOT chained: %s" % detail)
        print("chained %s (%d bytes)" % (aid, len(body_bytes)))

    return 0 if (loaded is not False) else 3


if __name__ == "__main__":
    sys.exit(main())


def build_render_refused_record(device, refusals):
    """The record that says what did NOT make it into the policy.

    An approval that silently failed to render is a silent denial of
    approved work and is indistinguishable, from the router's side, from
    an attack. This makes the absence explicit and auditable."""
    return {
        "schema": RENDER_REFUSED_SCHEMA,
        "device": device,
        "refused_utc_ns": time.time_ns(),
        "refused_count": len(refusals),
        "refusals": refusals,
        "presentation": (
            "CLAIM about approvals NOT rendered. Render beside the "
            "verdict ladder, never inside it. A refusal here is not a "
            "cryptographic failure; it is the compiler declining to "
            "grant a command different from the one approved."),
    }
