#!/usr/bin/env python3
"""
virp_tacacs_authzd.py — TACACS+ AUTHORIZATION server. LAB ONLY.

Serves TAC_PLUS_AUTHOR and refuses everything else. Separate process,
separate port and separate identity from the accounting receiver, so an
authorization outage cannot lose evidence and an accounting outage cannot
deny commands.

Every decision is chained as `tacacs_authorization/1` BEFORE the reply is
sent. That ordering is deliberate: a decision the router acted on but
which no record describes is exactly the hole this whole system exists to
close. If the chain append fails, the decision becomes ERROR and the
router denies -- a control that cannot record what it did must not
pretend to be a control.

Policy is reloaded from disk when the file changes, per request, so a
newly compiled grant takes effect without restarting the listener and
without dropping in-flight sessions.

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
import virp_tacacs_authz as az
from virp_tacacs_recv import (Ledger, canonical_bytes, chain_append_evidence,
                              producer_load_sk, producer_sign)
import virp_tacacs_reconcile as rc

SCHEMA = "tacacs_authorization/1"

STATUS_WIRE = {
    az.PASS_ADD: tp.TAC_PLUS_AUTHOR_STATUS_PASS_ADD,
    az.PASS_REPL: tp.TAC_PLUS_AUTHOR_STATUS_PASS_REPL,
    az.FAIL: tp.TAC_PLUS_AUTHOR_STATUS_FAIL,
    az.ERROR: tp.TAC_PLUS_AUTHOR_STATUS_ERROR,
}


class PolicyStore:
    """Policy on disk, reloaded when it changes, consumption persisted.

    Reload is by (mtime, size) per request rather than by signal: a
    compiler that wrote a policy the server never loaded is a SILENT DENY
    of an approved action, and it looks exactly like an attack. Checking
    per request makes the window zero instead of "until someone sends a
    HUP"."""

    def __init__(self, path, ledger=None):
        self.path = path
        self.ledger = ledger
        self._lock = threading.Lock()
        self._stamp = None
        self._policy = {"schema": "tacacs_authz_policy/1", "grants": []}
        self.load(force=True)

    def _stat(self):
        try:
            st = os.stat(self.path)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def load(self, force=False):
        changed = False
        with self._lock:
            stamp = self._stat()
            if not force and stamp == self._stamp:
                return False
            if stamp is None:
                # No policy file is an EMPTY policy, never an open one.
                self._policy = {"schema": "tacacs_authz_policy/1",
                                "grants": []}
            else:
                try:
                    with open(self.path) as f:
                        self._policy = json.load(f)
                except (ValueError, OSError):
                    # An unreadable policy denies everything. Failing
                    # closed on a corrupt file is the only safe reading.
                    self._policy = {"schema": "tacacs_authz_policy/1",
                                    "grants": [], "_load_error": True}
            self._stamp = stamp
            changed = True
            loaded_sha = hashlib.sha256(json.dumps(
                self._policy, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()
            loaded_grants = len(self._policy.get("grants", []))
        if changed and self.ledger is not None:
            # Written outside the lock (the ledger fsyncs), using values
            # captured while the lock was held.
            self.ledger.write("POLICY_LOADED",
                              policy_path=self.path,
                              policy_sha256=loaded_sha,
                              grants=loaded_grants)
        return changed

    def snapshot(self):
        with self._lock:
            return json.loads(json.dumps(self._policy))

    def sha256(self):
        with self._lock:
            return hashlib.sha256(json.dumps(
                self._policy, sort_keys=True,
                separators=(",", ":")).encode()).hexdigest()

    def consume(self, grant_id):
        """Spend a use and persist atomically."""
        with self._lock:
            n = az.consume(self._policy, grant_id)
            if n is None:
                return None
            tmp = self.path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._policy, f, indent=1, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self.path)
            self._stamp = self._stat()
            return n


class Counters:
    _NAMES = ("author_requests", "pass_add", "fail", "error",
              "refused_acct", "refused_authen", "unknown_session_type",
              "chain_failed", "short_read", "malformed")

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


class AuthorHandler(socketserver.BaseRequestHandler):

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            c = self.request.recv(n - len(buf))
            if not c:
                return None
            buf += c
        return buf

    def handle(self):
        srv = self.server
        peer = self.client_address
        local = self.request.getsockname()

        while True:
            raw_hdr = self._recv_exact(tp.HEADER_LEN)
            if raw_hdr is None:
                return
            recv_utc_ns = time.time_ns()
            recv_mono_ns = time.monotonic_ns()
            try:
                hdr = tp.parse_header(raw_hdr)
            except tp.TacacsMalformed:
                srv.counters.bump("short_read")
                return

            raw_body = (self._recv_exact(hdr["length"])
                        if hdr["length"] else b"")
            if raw_body is None:
                srv.counters.bump("short_read")
                return

            # This server serves AUTHORIZATION only. Accounting is a
            # different process on a different address, and answering for
            # it here would recreate the coupling that separation exists
            # to prevent.
            if hdr["type"] != tp.TAC_PLUS_AUTHOR:
                if hdr["type"] == tp.TAC_PLUS_ACCT:
                    srv.counters.bump("refused_acct")
                elif hdr["type"] == tp.TAC_PLUS_AUTHEN:
                    srv.counters.bump("refused_authen")
                else:
                    srv.counters.bump("unknown_session_type")
                srv.ledger.write("REFUSED_SESSION_TYPE",
                                 source_addr=peer[0],
                                 session_type="0x%02x" % hdr["type"])
                return

            rel = srv.cfg["_by_addr"].get(peer[0])
            secret = rel["secret"] if rel else None
            device = rel["client_identity"] if rel else None

            if hdr["unencrypted"] or secret is None:
                plain = raw_body
            else:
                plain = tp.xor_body(raw_body, hdr["session_id"], secret,
                                    hdr["version"], hdr["seq_no"])

            fields, parse = tp.parse_author_request(plain)
            srv.counters.bump("author_requests")
            if parse == "MALFORMED":
                srv.counters.bump("malformed")

            command, rule = rc.reassemble_command(fields.get("args") or [])
            user = fields.get("user")

            srv.policy.load()
            policy = srv.policy.snapshot()

            if device is None:
                status, reason, gid = (az.ERROR,
                                       az.DENY_PREFIX + "source %s is not a "
                                       "configured device" % peer[0], None)
            elif parse == "MALFORMED":
                status, reason, gid = (az.ERROR,
                                       az.DENY_PREFIX + "authorization "
                                       "request did not parse", None)
            elif command is None:
                # No cmd= argument: this is a service authorization
                # (EXEC/shell), not a command. Out of scope for v1 and
                # denied rather than guessed at.
                status, reason, gid = (az.FAIL,
                                       az.DENY_PREFIX + "no cmd argument "
                                       "(service authorization is not "
                                       "served)", None)
            else:
                status, reason, gid = az.authorize(
                    policy, device=device, user=user, command=command,
                    now_ns=recv_utc_ns)

            body = {
                "schema": SCHEMA,
                "receiver_node": srv.cfg["receiver_node"],
                "receiver_local_addr": local[0],
                "receiver_local_port": local[1],
                "source_addr": peer[0],
                "source_port": peer[1],
                "recv_utc_ns": recv_utc_ns,
                "recv_monotonic_ns": recv_mono_ns,
                "client_identity": device,
                "client_identity_source": ("configured_by_source_address"
                                           if device else
                                           "unconfigured_source"),
                "user": user,
                "port": fields.get("port"),
                "rem_addr": fields.get("rem_addr"),
                "priv_lvl": fields.get("priv_lvl"),
                "authen_method": fields.get("authen_method"),
                "authen_service": fields.get("authen_service"),
                "arg_cnt": fields.get("arg_cnt"),
                "args": fields.get("args"),
                "command": command,
                "command_reassembly": rule,
                "decision": status,
                "decision_reason": reason,
                "grant_id": gid,
                "policy_sha256": srv.policy.sha256(),
                "tacacs_session_id": hdr["session_id"],
                "tacacs_seq_no": hdr["seq_no"],
                "raw_body_len": len(plain),
                "raw_body_sha256": hashlib.sha256(plain).hexdigest(),
                "parse": parse,
            }

            # Chain BEFORE replying. A decision the router acted on that
            # no record describes is the hole this system exists to close.
            body_bytes, _ = producer_sign(srv.sk, body)
            aid = "tacacsaz:%s:%d:%d:%s" % (
                peer[0], hdr["session_id"], hdr["seq_no"],
                body["raw_body_sha256"][:16])
            ok, detail = chain_append_evidence(
                srv.cfg.get("chain_session",
                            "tacacs-authz:%s" % srv.cfg["receiver_node"]),
                aid, body_bytes, srv.onode_socket)
            if not ok:
                # Cannot record => cannot authorize. Downgrade to ERROR,
                # which the router treats as a denial under a method list
                # with no fallback.
                srv.counters.bump("chain_failed")
                srv.ledger.write("CHAIN_APPEND_FAILED", artifact_id=aid,
                                 detail=str(detail), decision=status)
                status, reason = (az.ERROR,
                                  az.DENY_PREFIX + "decision could not be "
                                                   "recorded")

            if status == az.PASS_ADD and gid:
                srv.policy.consume(gid)

            srv.counters.bump({"PASS_ADD": "pass_add", "FAIL": "fail",
                               "ERROR": "error",
                               "PASS_REPL": "pass_add"}.get(status, "error"))

            reply_args = az.reply_args_for(status)
            reply = tp.build_author_response(
                STATUS_WIRE.get(status, tp.TAC_PLUS_AUTHOR_STATUS_ERROR),
                args=reply_args,
                server_msg=(reason or "")[:200].encode("latin-1", "replace"))
            if not hdr["unencrypted"] and secret is not None:
                reply = tp.xor_body(reply, hdr["session_id"], secret,
                                    hdr["version"], hdr["seq_no"] + 1)
            out = tp.build_header(hdr["version"], tp.TAC_PLUS_AUTHOR,
                                  hdr["seq_no"] + 1, hdr["flags"],
                                  hdr["session_id"], len(reply)) + reply
            try:
                self.request.sendall(out)
            except OSError:
                return

            print("[AUTHZ] %-3s %-8s %-40s -> %s (%s)"
                  % (device, user, (command or "-")[:40], status, reason),
                  flush=True)

            if not hdr["single_connect"]:
                return


class AuthorServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def load_config(path):
    st = os.stat(path)
    if st.st_mode & 0o077:
        raise SystemExit("config %s holds shared secrets and is "
                         "group/world-accessible (mode %o) — refusing"
                         % (path, st.st_mode & 0o777))
    with open(path) as f:
        cfg = json.load(f)
    cfg["_by_addr"] = {
        r["source_addr"]: {"client_identity": r["client_identity"],
                           "secret": r["secret"].encode("latin-1")}
        for r in cfg["relationships"]}
    return cfg


def main(argv=None):
    p = argparse.ArgumentParser(
        description="VIRP TACACS+ authorization server (lab only)")
    p.add_argument("--config", required=True)
    p.add_argument("--policy", required=True)
    p.add_argument("--listen-addr")
    p.add_argument("--listen-port", type=int)
    p.add_argument("--onode-socket")
    args = p.parse_args(argv)

    cfg = load_config(args.config)
    srv = AuthorServer((args.listen_addr or cfg.get("listen_addr", "0.0.0.0"),
                        args.listen_port or cfg.get("listen_port", 4951)),
                       AuthorHandler)
    srv.cfg = cfg
    srv.sk = producer_load_sk(cfg["producer_key"])
    srv.ledger = Ledger(cfg["ledger"])
    srv.counters = Counters()
    srv.policy = PolicyStore(args.policy, ledger=srv.ledger)
    srv.onode_socket = args.onode_socket or cfg.get("onode_socket")

    srv.ledger.write("AUTHZ_LISTEN_START", policy=args.policy,
                     policy_sha256=srv.policy.sha256(), pid=os.getpid())

    def _term(_s, _f):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, _term)

    print("authorization server on %s:%d — AUTHOR only (RFC 8907)"
          % srv.server_address, flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        snap = srv.counters.snapshot()
        srv.ledger.write("AUTHZ_LISTEN_STOP", counters=snap)
        srv.server_close()
        print("counters: %s" % json.dumps(snap, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
