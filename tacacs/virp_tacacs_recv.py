#!/usr/bin/env python3
"""
virp_tacacs_recv.py — TACACS+ ACCOUNTING receiver. LAB ONLY.

Listens as a TACACS+ server (RFC 8907) and serves the ACCOUNTING
session type only. Each received accounting packet becomes one
chain-signed `tacacs_accounting/1` record containing exactly what
arrived. Design, boundaries and field set: docs/TACACS-ACCOUNTING.md.

NOT DEPLOYED. This runs against the GNS3 lab from a working tree. It
does not touch virp-onode-home (313) or virp-lab (.211).

Three rules this module exists to keep:

  1. THE RECEIPT IS A TRANSCRIPTION. No normalization, no name
     resolution, no policy, no conclusion. Interpretation belongs to
     virp_tacacs_reconcile.py, which runs later and never touches a
     receipt.

  2. NOTHING IS DROPPED FOR BEING WRONG. A packet that fails to decode,
     fails to parse, arrives from an unconfigured source, or is the
     wrong session type is COUNTED and — where it is an accounting
     packet at all — RECORDED, with the failure named in a closed
     vocabulary. A receiver that discarded what it could not understand
     would be destroying exactly the evidence worth keeping.

  3. WHAT DID NOT LAND IS SAID SO. A chain append that fails does not
     silently vanish: it is counted, written to the ledger, and
     reported. The listener's own up/down ledger is what later lets a
     reconciler answer RECEIVER_UP / RECEIVER_DOWN / RECEIVER_UNKNOWN
     for a window instead of guessing.

Key custody: this receiver holds NO VIRP key — not the chain key, not
the O-Key. It holds its own Ed25519 PRODUCER key and the TACACS+ shared
secrets. Chain entries are signed by the O-node at ingest. As with the
camera producer, a producer signature binds A KEY, NOT A HOST.

Shared secrets are read from a 0600 config and never appear in a body,
a log line, or a report.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import argparse
import hashlib
import json
import os
import signal
import socket
import socketserver
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import virp_tacacs_codec as tp

SCHEMA = "tacacs_accounting/1"

# The wire's artifact_type is char[16] (15 usable), so "tacacs_accounting"
# would be truncated. Externally-produced records ride as evidence_item
# with the real type in the body `schema` — the same convention as
# camera_segment and the autopilot's evidence items.
ARTIFACT_TYPE = "evidence_item"

# Daemon artifact_content[8192]: at or past this a body would be stored
# truncated and could never hash to its own artifact_hash. Refused, never
# truncated.
ARTIFACT_LIMIT = 8192

ONODE_SOCKET = "/run/virp/onode.sock"


# ── canonical form, producer key: identical to camera/virp_camera.py ───

def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def _ed25519():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519


def producer_key_id(pk_raw):
    return hashlib.sha256(pk_raw).hexdigest()[:32]


def producer_keygen(sk_path, pk_path):
    """Refuses to overwrite. An existing key is an identity; a new key
    is a NEW producer identity and does not re-sign old records."""
    ed = _ed25519()
    sk = ed.Ed25519PrivateKey.generate()
    fd = os.open(sk_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(sk.private_bytes_raw())
    pk_raw = sk.public_key().public_bytes_raw()
    fd = os.open(pk_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(pk_raw)
    return producer_key_id(pk_raw)


def producer_load_sk(sk_path):
    st = os.stat(sk_path)
    if st.st_mode & 0o077:
        raise SystemExit("producer key %s is group/world-accessible "
                         "(mode %o) — refusing to use it"
                         % (sk_path, st.st_mode & 0o777))
    with open(sk_path, "rb") as f:
        raw = f.read()
    if len(raw) != 32:
        raise SystemExit("producer key %s is not a 32-byte raw Ed25519 "
                         "seed" % sk_path)
    return _ed25519().Ed25519PrivateKey.from_private_bytes(raw)


def producer_sign(sk, body_without_sig):
    payload = canonical_bytes(body_without_sig)
    sig = sk.sign(payload)
    body = dict(body_without_sig)
    body["producer_sig"] = sig.hex()
    return canonical_bytes(body), body


# ── O-node client: v2 framing, vocabulary is chain_append only ─────────

def onode_send(request, sock_path, timeout=30):
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


def chain_append_evidence(session_id, artifact_id, body_bytes, sock_path):
    """Append one evidence_item committing to body_bytes.
    Returns (ok, receipt_or_error). A refusal means the record did NOT
    land — the caller must count it as a loss, never assume it stored."""
    if len(body_bytes) >= ARTIFACT_LIMIT:
        return False, ("body is %d bytes, at/past the daemon's %d-byte "
                       "artifact field — would be stored truncated "
                       "(unverifiable); not submitted"
                       % (len(body_bytes), ARTIFACT_LIMIT))
    req = {
        "action": "chain_append",
        "session_id": session_id,
        "artifact_type": ARTIFACT_TYPE,
        "artifact_id": artifact_id,
        "artifact_hash": hashlib.sha256(body_bytes).hexdigest(),
        "artifact_content": body_bytes.decode("ascii"),
    }
    try:
        resp = onode_send(req, sock_path)
    except Exception as e:
        return False, "O-Node unreachable: %s" % e
    if len(resp) == 4:
        return False, "O-Node error %d" % struct.unpack(">i", resp)[0]
    return True, resp


# ── the listener's own up/down ledger ──────────────────────────────────

def _fsync_dir(dirpath):
    fd = os.open(dirpath or ".", os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Ledger:
    """Append-only JSONL of what the LISTENER did, distinct from what it
    received. This is what makes `coverage` answerable from evidence: a
    window with no LISTEN_START..LISTEN_STOP covering it is
    RECEIVER_UNKNOWN, and a window inside a stop is RECEIVER_DOWN.

    fsynced on every write. A ledger that lost its last line on a crash
    would report coverage it cannot support."""

    def __init__(self, path):
        self.path = path
        self._lock = threading.Lock()

    def write(self, event, **fields):
        rec = dict(fields)
        rec["event"] = event
        rec["utc_ns"] = time.time_ns()
        rec["monotonic_ns"] = time.monotonic_ns()
        line = json.dumps(rec, sort_keys=True) + "\n"
        with self._lock:
            with open(self.path, "a") as f:
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
        return rec


# ── configuration ──────────────────────────────────────────────────────

def load_config(path):
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise SystemExit("config %s holds TACACS+ shared secrets and is "
                         "group/world-accessible (mode %o) — refusing"
                         % (path, st.st_mode & 0o777))
    with open(path) as f:
        cfg = json.load(f)
    for required in ("receiver_node", "relationships", "producer_key",
                     "ledger"):
        if required not in cfg:
            raise SystemExit("config %s is missing %r" % (path, required))
    by_addr = {}
    for rel in cfg["relationships"]:
        by_addr[rel["source_addr"]] = {
            "client_identity": rel["client_identity"],
            "secret": rel["secret"].encode("latin-1"),
        }
    cfg["_by_addr"] = by_addr
    return cfg


# ── the receipt ────────────────────────────────────────────────────────

def build_receipt(cfg, peer, local, hdr, raw_body, recv_utc_ns,
                  recv_mono_ns):
    """Everything that arrived, and nothing else.

    Returns (body_without_sig, artifact_id). Never raises for a bad
    packet: decode/parse state is recorded in the closed vocabularies
    `decode` and `parse`, and the record still ships.
    """
    rel = cfg["_by_addr"].get(peer[0])
    if rel is None:
        identity, identity_source, secret = None, "unconfigured_source", None
    else:
        identity = rel["client_identity"]
        identity_source = "configured_by_source_address"
        secret = rel["secret"]

    if hdr["unencrypted"]:
        # The device set TAC_PLUS_UNENCRYPTED_FLAG. The body is in the
        # clear. Recorded as the fact it is — a misconfiguration worth
        # seeing, not an error to swallow.
        plain, decode = raw_body, "CLEARTEXT"
    elif secret is None:
        plain, decode = raw_body, "NO_SECRET_CONFIGURED"
    else:
        plain = tp.xor_body(raw_body, hdr["session_id"], secret,
                            hdr["version"], hdr["seq_no"])
        decode = "OBFUSCATED_MD5"

    if decode == "NO_SECRET_CONFIGURED":
        # Nothing was decoded, so nothing may be claimed to have parsed.
        # NOT_ATTEMPTED, never MALFORMED: the body is not known to be
        # malformed, it was never read. Borrowing MALFORMED here would
        # accuse a possibly well-formed packet of being broken, which is
        # the same vocabulary abuse this design refuses everywhere else.
        fields = tp.parse_acct_request(b"")[0]
        parse = "NOT_ATTEMPTED"
    else:
        fields, parse = tp.parse_acct_request(plain)

    body = {
        "schema": SCHEMA,

        "receiver_node": cfg["receiver_node"],
        "receiver_local_addr": local[0],
        "receiver_local_port": local[1],

        "source_addr": peer[0],
        "source_port": peer[1],

        "recv_utc_ns": recv_utc_ns,
        "recv_monotonic_ns": recv_mono_ns,

        "client_identity": identity,
        "client_identity_source": identity_source,

        "tacacs_version_major": hdr["version_major"],
        "tacacs_version_minor": hdr["version_minor"],
        "tacacs_seq_no": hdr["seq_no"],
        "tacacs_session_id": hdr["session_id"],
        "tacacs_flags_raw": hdr["flags"],
        "tacacs_unencrypted": hdr["unencrypted"],
        "tacacs_single_connect": hdr["single_connect"],

        "acct_flags_raw": fields["acct_flags_raw"],
        "acct_flags": fields["acct_flags"],

        "authen_method_raw": fields["authen_method_raw"],
        "authen_method": fields["authen_method"],
        "priv_lvl": fields["priv_lvl"],
        "authen_type_raw": fields["authen_type_raw"],
        "authen_type": fields["authen_type"],
        "authen_service_raw": fields["authen_service_raw"],
        "authen_service": fields["authen_service"],

        "user": fields["user"],
        "port": fields["port"],
        "rem_addr": fields["rem_addr"],

        "arg_cnt": fields["arg_cnt"],
        "args": fields["args"],
        "args_index": tp.args_index(fields["args"]),

        # sha256 over the RAW DECRYPTED body — after the pad is removed,
        # before any parsing — so a reader can confirm the parse was over
        # these bytes and no others. When decode is NO_SECRET_CONFIGURED
        # it is over the bytes as they arrived, and `decode` says which.
        "raw_body_len": len(plain),
        "raw_body_sha256": hashlib.sha256(plain).hexdigest(),

        "decode": decode,
        "parse": parse,
    }
    artifact_id = "tacacs:%s:%d:%d:%s" % (
        peer[0], hdr["session_id"], hdr["seq_no"],
        body["raw_body_sha256"][:16])
    return body, artifact_id


# ── the server ─────────────────────────────────────────────────────────

class Counters:
    """What the listener saw, including everything it could not use.
    Reported at shutdown and written to the ledger, because a count of
    refusals that only exists in memory is a count nobody can audit."""

    _NAMES = ("accepted", "recorded", "append_failed", "oversize",
              "malformed", "cleartext", "unconfigured_source",
              "refused_authen", "refused_author", "unknown_session_type",
              "short_read")

    def __init__(self):
        self._lock = threading.Lock()
        for n in self._NAMES:
            setattr(self, n, 0)

    def bump(self, name, n=1):
        with self._lock:
            setattr(self, name, getattr(self, name) + n)

    def snapshot(self):
        with self._lock:
            return {n: getattr(self, n) for n in self._NAMES}


class AcctHandler(socketserver.BaseRequestHandler):

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            c = self.request.recv(n - len(buf))
            if not c:
                return None
            buf += c
        return buf

    def handle(self):
        cfg = self.server.cfg
        counters = self.server.counters
        ledger = self.server.ledger
        local = self.request.getsockname()
        peer = self.client_address

        # A device may reuse one TCP connection for many sessions when
        # single-connect is negotiated; loop until the peer closes.
        while True:
            raw_hdr = self._recv_exact(tp.HEADER_LEN)
            if raw_hdr is None:
                return
            recv_utc_ns = time.time_ns()
            recv_mono_ns = time.monotonic_ns()
            try:
                hdr = tp.parse_header(raw_hdr)
            except tp.TacacsMalformed:
                counters.bump("short_read")
                return

            if hdr["length"] > ARTIFACT_LIMIT * 4:
                # Refuse an absurd declared length rather than allocate
                # to it. Counted, not silently closed.
                counters.bump("oversize")
                ledger.write("OVERSIZE_DECLARED", source_addr=peer[0],
                             declared_len=hdr["length"])
                return

            raw_body = self._recv_exact(hdr["length"]) if hdr["length"] else b""
            if raw_body is None:
                counters.bump("short_read")
                return

            # v1 serves ACCOUNTING only. AUTHEN/AUTHOR are refused at the
            # type byte, before the body is decoded, and the connection
            # is closed. No partial and no permissive reply is ever sent:
            # a permissive authorization reply from a server that
            # implements no authorization is the worst failure available
            # to this design. The refusal is counted and ledgered,
            # because a device wrongly pointed here will otherwise just
            # fall through to its next method and mask the mistake.
            if hdr["type"] != tp.TAC_PLUS_ACCT:
                if hdr["type"] == tp.TAC_PLUS_AUTHEN:
                    counters.bump("refused_authen")
                    what = "AUTHEN"
                elif hdr["type"] == tp.TAC_PLUS_AUTHOR:
                    counters.bump("refused_author")
                    what = "AUTHOR"
                else:
                    counters.bump("unknown_session_type")
                    what = "type_0x%02x" % hdr["type"]
                ledger.write("REFUSED_SESSION_TYPE", source_addr=peer[0],
                             session_type=what)
                return

            counters.bump("accepted")
            body_nosig, artifact_id = build_receipt(
                cfg, peer, local, hdr, raw_body, recv_utc_ns, recv_mono_ns)

            if body_nosig["parse"] == "MALFORMED":
                counters.bump("malformed")
            if body_nosig["decode"] == "CLEARTEXT":
                counters.bump("cleartext")
            if body_nosig["client_identity_source"] == "unconfigured_source":
                counters.bump("unconfigured_source")

            body_bytes, _body = producer_sign(self.server.sk, body_nosig)
            ok, detail = chain_append_evidence(
                cfg.get("chain_session", "tacacs:%s" % cfg["receiver_node"]),
                artifact_id, body_bytes, self.server.onode_socket)

            if ok:
                counters.bump("recorded")
            else:
                # The record did NOT land. Say so, durably, with enough
                # to reconstruct what was lost.
                counters.bump("append_failed")
                if "at/past the daemon" in str(detail):
                    counters.bump("oversize")
                ledger.write("APPEND_FAILED", source_addr=peer[0],
                             artifact_id=artifact_id,
                             body_sha256=hashlib.sha256(
                                 body_bytes).hexdigest(),
                             detail=str(detail))

            # Reply SUCCESS. Accounting is advisory: a device whose
            # accounting server errors does not stop executing commands,
            # and v1 must never appear to be a control. The reply says
            # "received", which is exactly what happened at this layer —
            # it is NOT a claim that the record chained. Whether it
            # chained is in the ledger and the counters, which is where a
            # reader can actually check it.
            reply = tp.build_acct_reply(tp.TAC_PLUS_ACCT_STATUS_SUCCESS)
            if not hdr["unencrypted"]:
                rel = cfg["_by_addr"].get(peer[0])
                if rel is not None:
                    reply = tp.xor_body(reply, hdr["session_id"],
                                        rel["secret"], hdr["version"],
                                        hdr["seq_no"] + 1)
            out = tp.build_header(hdr["version"], tp.TAC_PLUS_ACCT,
                                  hdr["seq_no"] + 1, hdr["flags"],
                                  hdr["session_id"], len(reply)) + reply
            try:
                self.request.sendall(out)
            except OSError:
                return

            if not hdr["single_connect"]:
                return


class AcctServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def cmd_serve(args):
    cfg = load_config(args.config)
    sk = producer_load_sk(cfg["producer_key"])
    ledger = Ledger(cfg["ledger"])
    counters = Counters()

    addr = (args.listen_addr or cfg.get("listen_addr", "0.0.0.0"),
            args.listen_port or cfg.get("listen_port", 49))
    srv = AcctServer(addr, AcctHandler)
    srv.cfg = cfg
    srv.sk = sk
    srv.ledger = ledger
    srv.counters = counters
    srv.onode_socket = args.onode_socket or cfg.get("onode_socket",
                                                    ONODE_SOCKET)

    ledger.write("LISTEN_START", listen_addr=addr[0], listen_port=addr[1],
                 receiver_node=cfg["receiver_node"], pid=os.getpid())

    # A listener killed by SIGTERM must still close its window. Without
    # this the ledger shows an open window that never ended, and coverage
    # cannot distinguish "restarted" from "up the whole time" -- which is
    # exactly the distinction INTERRUPTED exists to make. The handler
    # raises through to the same shutdown path as Ctrl-C rather than
    # writing from inside the signal context.
    def _term(_sig, _frm):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term)
    print("listening on %s:%d — ACCOUNTING only (RFC 8907)"
          % (addr[0], addr[1]), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        snap = counters.snapshot()
        ledger.write("LISTEN_STOP", counters=snap)
        srv.server_close()
        print("counters: %s" % json.dumps(snap, sort_keys=True), flush=True)
    return 0


def cmd_keygen(args):
    kid = producer_keygen(args.sk, args.pk)
    print("producer key_id %s" % kid)
    print("  secret: %s (0600)" % args.sk)
    print("  public: %s (0644)" % args.pk)
    print("Record it in deploy/keys/registry.json with role 'producer'.")
    return 0


def cmd_selftest(args):
    """Round-trip the codec without a lab: build the packet a router
    would send, obfuscate it, decode it back, and show the receipt.
    Proves the codec against itself only — the LAB run is what proves it
    against a real IOS."""
    secret = b"labsecret"
    sid = 0x12345678
    version = 0xC0
    seq = 1
    body = tp.build_acct_request(
        tp.TAC_PLUS_ACCT_FLAG_START, 0x06, 15, 0x01, 0x01,
        "aiops-svc", "tty2", "192.168.122.1",
        ["task_id=7", "timezone=UTC", "service=shell", "priv-lvl=15",
         "cmd=show", "cmd-arg=version", "cmd-arg=<cr>"])
    ob = tp.xor_body(body, sid, secret, version, seq)
    assert ob != body, "obfuscation was a no-op"
    back = tp.xor_body(ob, sid, secret, version, seq)
    assert back == body, "XOR round-trip failed"
    fields, state = tp.parse_acct_request(back)
    print("round-trip: OK   parse: %s" % state)
    print("args: %s" % json.dumps(fields["args"]))
    print("index: %s" % json.dumps(tp.args_index(fields["args"]),
                                   sort_keys=True))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        description="VIRP TACACS+ ACCOUNTING receiver (lab only)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve")
    s.add_argument("--config", required=True)
    s.add_argument("--listen-addr")
    s.add_argument("--listen-port", type=int)
    s.add_argument("--onode-socket")
    s.set_defaults(fn=cmd_serve)

    k = sub.add_parser("keygen")
    k.add_argument("--sk", required=True)
    k.add_argument("--pk", required=True)
    k.set_defaults(fn=cmd_keygen)

    t = sub.add_parser("selftest")
    t.set_defaults(fn=cmd_selftest)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
