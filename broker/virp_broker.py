#!/usr/bin/env python3
"""
virp_broker.py — network intent-broker for the VIRP O-Node (Stage 1).

An agentless, credential-less relay: accepts ONE JSON request per TCP
connection on 127.0.0.1, allowlists the action, forwards the validated
request to the local daemon socket with the exact framing the autopilot
uses, and returns the daemon's signed response bytes unchanged.

The broker holds NO device credentials and NO keys. It never
classifies, never constructs commands, never adds or modifies fields:
pure allowlist + forward. The daemon parser/classifier/signer stays
authoritative — the broker only fails early and keeps daemon-internal
actions off the socket entirely.

Stage 1 binds 127.0.0.1 ONLY. The VLAN bind, mTLS, and the firewall
pinhole are separate, later, operator steps.

Copyright (c) 2026 Third Level IT LLC. All rights reserved.
"""

import argparse
import grp
import json
import os
import socket
import struct
import sys
import time

ONODE_SOCKET = "/run/virp/onode.sock"
DEVICES_JSON = "/run/virp/devices.json"
BIND_HOST = "127.0.0.1"          # localhost ONLY — never the VLAN IP
DEFAULT_PORT = 7420
MAX_REQUEST_SIZE = 24576         # ONODE_MAX_REQUEST_SIZE (include/virp_onode.h)
CLIENT_TIMEOUT = 15

# Actions a remote agent may submit. Everything else — daemon-internal
# and operator actions (shutdown, chain_append, sign_intent,
# sign_outcome, chain_verify, chain_verify_session, batch_execute,
# validate_turn, session_hello, session_bind, session_close) and any
# unknown action — is rejected here and never reaches the socket.
ALLOWED_ACTIONS = frozenset({
    "execute", "list_devices", "health", "heartbeat",
    "intent_store", "intent_get", "approval_challenge", "approval_submit",
})


def log(peer, action, verdict, reason=""):
    # Action name only — never the payload (a forwarded field could in
    # principle carry something secret; the broker must not echo it).
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = "%s %s action=%s %s" % (ts, peer, action or "-", verdict)
    if reason:
        line += " reason=%s" % reason
    print(line, flush=True)


# ── O-Node socket client — onode_send() copied VERBATIM from ───────────
# ── autopilot/virp_autopilot.py: the broker must frame exactly as ──────
# ── the autopilot does. ────────────────────────────────────────────────

def onode_send(request, sock_path=ONODE_SOCKET, timeout=60):
    """v2 framing: send [4B len][0x02][JSON], receive [4B len][payload]."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(sock_path)
        payload = json.dumps(request).encode()
        s.sendall(struct.pack(">I", 1 + len(payload)) + b"\x02" + payload)
        hdr = b""
        while len(hdr) < 4:
            c = s.recv(4 - len(hdr))
            if not c:
                raise IOError("short read on frame length")
            hdr += c
        n = struct.unpack(">I", hdr)[0]
        buf = b""
        while len(buf) < n:
            c = s.recv(n - len(buf))
            if not c:
                raise IOError("short read on frame body")
            buf += c
        return buf
    finally:
        s.close()


# ── Validation (defence in depth; the daemon parser is authoritative) ──

def contains_nul(value):
    """True if any string anywhere in the parsed JSON carries U+0000."""
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, dict):
        return any(contains_nul(k) or contains_nul(v)
                   for k, v in value.items())
    if isinstance(value, list):
        return any(contains_nul(v) for v in value)
    return False


def validate(raw):
    """Return (request, action, None) on accept, (None, action, reason)
    on reject. Rejected requests are never forwarded."""
    if len(raw) > MAX_REQUEST_SIZE:
        return None, None, "oversized (%d > %d bytes)" % (len(raw),
                                                          MAX_REQUEST_SIZE)
    if b"\x00" in raw:
        return None, None, "raw NUL byte in payload"
    try:
        req = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None, None, "payload is not valid JSON"
    if not isinstance(req, dict):
        return None, None, "root is not a JSON object"
    if contains_nul(req):
        return None, None, "encoded NUL (\\u0000) in payload"
    action = req.get("action")
    if not isinstance(action, str) or not action:
        return None, None, "missing or non-string action"
    if action not in ALLOWED_ACTIONS:
        return None, action, "action not in allowlist"
    return req, action, None


# ── Per-connection handling: one request, one response, close ──────────

def read_request(conn):
    """Read until client EOF (client half-closes after sending), capped
    just past the limit so oversize is detected without buffering it."""
    chunks, total = [], 0
    while total <= MAX_REQUEST_SIZE:
        chunk = conn.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def handle(conn, peer):
    conn.settimeout(CLIENT_TIMEOUT)
    try:
        raw = read_request(conn)
    except (socket.timeout, OSError) as e:
        log(peer, None, "REJECT", "read failed: %s" % e)
        return
    req, action, reason = validate(raw)
    if req is None:
        log(peer, action, "REJECT", reason)
        reply = json.dumps({"broker_error": reason}).encode()
    else:
        try:
            reply = onode_send(req)          # daemon bytes, unchanged
            log(peer, action, "FORWARD", "daemon replied %d bytes" % len(reply))
        except (OSError, IOError) as e:
            log(peer, action, "ERROR", "daemon unreachable: %s" % e)
            reply = json.dumps({"broker_error": "daemon unreachable"}).encode()
    try:
        conn.sendall(reply)
        conn.shutdown(socket.SHUT_WR)
    except OSError:
        pass


# ── Identity guard (production): refuse over-privileged identities ─────

def assert_unprivileged():
    """Fail loud, same spirit as broker-access.sh: the broker identity
    must be credential-less. Root, supplementary groups, or a readable
    devices.json all mean the wrong identity — refuse to serve."""
    if os.getuid() == 0:
        sys.exit("[virp-broker] FATAL: refusing to run as root")
    gids = [g for g in os.getgroups() if g != os.getgid()]
    if gids:
        names = ", ".join(grp.getgrgid(g).gr_name for g in gids)
        sys.exit("[virp-broker] FATAL: supplementary groups: %s" % names)
    if os.access(DEVICES_JSON, os.R_OK):
        sys.exit("[virp-broker] FATAL: %s is readable — this identity "
                 "can see device credentials" % DEVICES_JSON)


def main():
    ap = argparse.ArgumentParser(description="VIRP intent-broker (Stage 1)")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--require-unprivileged", action="store_true",
                    help="refuse to start unless credential-less "
                         "(set in the systemd unit)")
    args = ap.parse_args()

    if args.require_unprivileged:
        assert_unprivileged()
    elif os.access(DEVICES_JSON, os.R_OK):
        print("[virp-broker] WARNING: running as an identity that can "
              "read %s — test use only" % DEVICES_JSON, flush=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND_HOST, args.port))     # 127.0.0.1 only, by construction
    srv.listen(8)
    print("[virp-broker] listening on %s:%d, allowlist: %s"
          % (BIND_HOST, args.port, ", ".join(sorted(ALLOWED_ACTIONS))),
          flush=True)
    while True:
        conn, addr = srv.accept()
        try:
            handle(conn, "%s:%d" % addr)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
