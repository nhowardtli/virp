#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
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
        self._reserved = {}
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
            # A reservation names a grant. A policy that no longer carries
            # that grant cannot have it released back, so the bookkeeping
            # goes with it.
            live = {g.get("grant_id") for g in self._policy.get("grants", [])}
            self._reserved = {k: v for k, v in
                              getattr(self, "_reserved", {}).items()
                              if k in live}
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

    def _sha256_locked(self):
        return hashlib.sha256(json.dumps(
            self._policy, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest()

    def sha256(self):
        with self._lock:
            return self._sha256_locked()

    def _persist_locked(self):
        """Write the policy back. Caller holds self._lock.

        Restamps afterwards so our own write is not read back as an
        external change on the next request."""
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(self._policy, f, indent=1, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)
        self._stamp = self._stat()

    def consume(self, grant_id):
        """Spend a use and persist atomically.

        Kept for callers that already hold a decision. The request path
        does NOT use this: see authorize_and_reserve()."""
        with self._lock:
            n = az.consume(self._policy, grant_id)
            if n is None:
                return None
            self._persist_locked()
            return n

    # ── grant lifecycle ────────────────────────────────────────────────
    #
    # HAM review 2026-09-06, item 1. The reviewed request path snapshotted
    # the policy, authorized against the SNAPSHOT, and consumed under a
    # second, later acquisition of this lock. N threads that reached the
    # decision together all read uses_remaining=1, all returned PASS_ADD,
    # and one human approval became N authorized commands (measured: 16 of
    # 16 threads passed on a uses=1 grant).
    #
    # The fix is that deciding and reserving are ONE operation under ONE
    # lock. A grant is:
    #
    #   AVAILABLE  uses_remaining > 0 and nobody is holding it
    #   RESERVED   a request has taken it; the decrement is already on
    #              disk, so a crash here cannot resurrect it
    #   SPENT      the reply has been serialized to the wire
    #
    # RESERVED and SPENT are indistinguishable to a competing request:
    # both see uses_remaining at 0 and are refused. The only path back to
    # AVAILABLE is release(), which the caller may use ONLY when it can
    # prove nothing left the box. That is the same retry asymmetry the
    # execution path follows.
    GRANT_AVAILABLE = "AVAILABLE"
    GRANT_RESERVED = "RESERVED"
    GRANT_SPENT = "SPENT"

    def authorize_and_reserve(self, device, user, command, now_ns):
        """Decide and, on PASS, reserve the grant. One atomic step.

        Returns (status, reason, grant_id, policy_sha256). The sha is of
        the policy AS DECIDED AGAINST, taken inside the same lock and
        BEFORE the reservation changes it, so the chained record names
        the policy that produced the decision rather than the one this
        decision left behind.

        On PASS_ADD with a grant, that grant is already decremented and
        persisted when this returns, so no second request can be given
        the same use."""
        self.load()
        with self._lock:
            sha = self._sha256_locked()
            status, reason, gid = az.authorize(
                self._policy, device=device, user=user, command=command,
                now_ns=now_ns)
            if status == az.PASS_ADD and gid:
                if az.consume(self._policy, gid) is None:
                    # The grant vanished between the decision and the
                    # reservation, which under this lock cannot happen;
                    # refuse rather than pass on an unreserved grant.
                    return (az.FAIL,
                            az.DENY_PREFIX + "grant %s could not be "
                                             "reserved" % gid, None, sha)
                self._reserved[gid] = self.GRANT_RESERVED
                self._persist_locked()
            return status, reason, gid, sha

    def spend(self, grant_id):
        """RESERVED -> SPENT. The reply is on the wire.

        The decrement is already durable; this only closes the in-memory
        reservation so release() can no longer return it."""
        if not grant_id:
            return
        with self._lock:
            self._reserved[grant_id] = self.GRANT_SPENT

    def release(self, grant_id):
        """RESERVED -> AVAILABLE. Returns the use to the grant.

        Legitimate ONLY when the caller can prove nothing reached the
        router: the decision could not be recorded, so no reply was ever
        built. A reservation already SPENT is never returned."""
        if not grant_id:
            return False
        with self._lock:
            if self._reserved.get(grant_id) != self.GRANT_RESERVED:
                return False
            for g in self._policy.get("grants", []):
                if g.get("grant_id") == grant_id:
                    g["uses_remaining"] = int(g.get("uses_remaining", 0)) + 1
                    self._reserved.pop(grant_id, None)
                    self._persist_locked()
                    return True
            return False

    def grant_state(self, grant_id):
        with self._lock:
            return self._reserved.get(grant_id, self.GRANT_AVAILABLE)


class Counters:
    _NAMES = ("author_requests", "pass_add", "fail", "error",
              "refused_acct", "refused_authen", "unknown_session_type",
              "chain_failed", "short_read", "malformed",
              "grant_consumed_unsent", "cleartext_rejected")

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

            # THE ASYMMETRY WITH THE ACCOUNTING RECEIVER, DELIBERATE.
            #
            # HAM review 2026-09-06, item 3. virp_tacacs_recv.py accepts a
            # packet that sets TAC_PLUS_UNENCRYPTED_FLAG and records
            # decode=CLEARTEXT. That is right for accounting: the receipt
            # is evidence, the misconfiguration is part of what happened,
            # and refusing it would DESTROY the record of a device talking
            # in the clear.
            #
            # It is wrong here. This listener does not record what a
            # device did, it decides what a device MAY do, and honouring
            # the flag lets the client choose whether the shared secret
            # applies and still reach PASS_ADD. Measured before the fix: a
            # cleartext request from a source with a configured secret
            # returned PASS_ADD and spent the grant.
            #
            # So: the body is still decoded-as-received and still
            # recorded, because the record must say what arrived. The
            # DECISION is a hard FAIL, taken below before any policy is
            # consulted.
            cleartext_refused = bool(hdr["unencrypted"]) and secret is not None
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

            policy_sha = srv.policy.sha256()
            if cleartext_refused:
                # First, and before any policy evaluation: the packet
                # asked us not to use the secret we hold for it.
                srv.counters.bump("cleartext_rejected")
                srv.ledger.write("CLEARTEXT_REJECTED",
                                 source_addr=peer[0],
                                 client_identity=device,
                                 tacacs_session_id=hdr["session_id"],
                                 user=user, command=command)
                status, reason, gid = (
                    az.FAIL,
                    az.DENY_PREFIX + "request set the TACACS+ cleartext "
                                     "flag from a source that has a "
                                     "configured shared secret; an "
                                     "authorization decision is never made "
                                     "on a body the client chose not to "
                                     "obfuscate", None)
            elif device is None:
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
                # Deciding and reserving are ONE atomic step (HAM item 1).
                # A PASS returned here has already spent the grant's use,
                # durably, so a racing request cannot be given the same
                # one.
                status, reason, gid, policy_sha = \
                    srv.policy.authorize_and_reserve(
                        device=device, user=user, command=command,
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
                "policy_sha256": policy_sha,
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
                # Nothing has been built for the wire yet, so this is the
                # one case where we can PROVE nothing reached the router.
                # Only here does a reservation go back.
                if srv.policy.release(gid):
                    srv.ledger.write("GRANT_RESERVATION_RELEASED",
                                     grant_id=gid, artifact_id=aid,
                                     reason="chain append failed before any "
                                            "reply was built")

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
                # The reservation stays consumed. We cannot prove the
                # router did not see this PASS, and resurrecting the
                # grant on an unprovable failure is how one approval
                # becomes two commands.
                if status == az.PASS_ADD and gid:
                    srv.policy.spend(gid)
                    srv.counters.bump("grant_consumed_unsent")
                    srv.ledger.write("GRANT_CONSUMED_UNSENT", grant_id=gid,
                                     artifact_id=aid, user=user,
                                     device=device, command=command)
                return
            if status == az.PASS_ADD and gid:
                srv.policy.spend(gid)

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
