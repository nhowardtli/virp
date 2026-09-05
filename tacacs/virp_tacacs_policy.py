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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from virp_tacacs_authz import canonical_command

SCHEMA = "tacacs_authz_policy/1"
RENDERED_SCHEMA = "tacacs_authz_policy_rendered/1"

# The authorization server's own AAA identifiers on the router.
AUTHZ_SERVER_NAME = "VIRPAZ"
AUTHZ_GROUP = "GRP-VIRPAZ"
RW_LIST = "VIRPRW"
RO_LIST = "VIRPRO"
CONSOLE_LIST = "CONSOLE"

DEFAULT_TTL_NS = 300 * 1_000_000_000


def compile_grants(approvals, now_ns, default_uses=1):
    """(grants, refusals).

    One approval, one command, one device, one grant. No approval ever
    produces two grants and no grant ever covers two commands: the whole
    point is that the blast radius of a compromised approval is exactly
    what a human approved.
    """
    grants, refusals = [], []
    for a in approvals:
        aid = a.get("approval_id")

        # Absence of the flag is NEVER treated as verified. An approval
        # whose signature was not checked is indistinguishable, to this
        # compiler, from one that failed -- and rendering either would let
        # an unsigned record open a router.
        if a.get("signature_verified") is not True:
            refusals.append({
                "approval_id": aid,
                "reason": "approval signature not verified (flag is %r)"
                          % a.get("signature_verified")})
            continue

        cmd = canonical_command(a.get("command"))
        if not cmd:
            refusals.append({"approval_id": aid,
                             "reason": "approval carries no command"})
            continue

        device = a.get("device")
        if not device:
            refusals.append({"approval_id": aid,
                             "reason": "approval names no device"})
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

        uses = int(a.get("repeat_count") or default_uses)
        if uses < 1:
            refusals.append({"approval_id": aid,
                             "reason": "repeat_count %r is below 1" % uses})
            continue

        grants.append({
            "grant_id": "g-%s" % aid,
            "device": device,
            "user": "virp-rw",
            "command": cmd,
            "approval_id": aid,
            "approval_entry_hash": a.get("approval_entry_hash"),
            "not_before_ns": issued,
            "not_after_ns": not_after,
            "uses_remaining": uses,
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


def render_router_config(device, authz_addr="172.17.0.1", authz_port=4951,
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
        "tacacs server %s" % AUTHZ_SERVER_NAME,
        " address ipv4 %s" % authz_addr,
        " port %d" % authz_port,
        " key %s" % authz_key,
        " exit",
        "aaa group server tacacs+ %s" % AUTHZ_GROUP,
        " server name %s" % AUTHZ_SERVER_NAME,
        " exit",
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
        "line vty 0 4",
        " authorization commands 15 %s" % RW_LIST,
        " authorization commands 1 %s" % RW_LIST,
        " exit",
    ])


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
