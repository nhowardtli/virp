#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
HAM review, 2026-09-06 — regressions for the TACACS+ authorization
boundary.

Each class names the review item it pins. These are written to FAIL
against the code as reviewed and to pass only against the fix, so a
later refactor that reopens the hole is a test failure and not a
re-review.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import json
import os
import socket
import socketserver
import struct
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tacacs"))

import virp_tacacs_authz as az
import virp_tacacs_authzd as azd
import virp_tacacs_codec as tp

NOW = 1_757_002_000_000_000_000
SEC = 1_000_000_000


def grant(device="R1", command="interface Loopback99", uses=1,
          user="virp-rw", not_before=NOW - 10 * SEC,
          not_after=NOW + 300 * SEC, approval_id="appr-1"):
    return {
        "grant_id": "g-" + approval_id,
        "device": device,
        "user": user,
        "command": command,
        "approval_id": approval_id,
        "approval_entry_hash": "a" * 64,
        "not_before_ns": not_before,
        "not_after_ns": not_after,
        "uses_remaining": uses,
    }


def policy(grants=None, device="R1"):
    return {
        "schema": "tacacs_authz_policy/1",
        "device": device,
        "rendered_utc_ns": NOW,
        "grants": list(grants or []),
    }


def live_grant(**kw):
    """A grant valid at the REAL clock, for tests that drive the daemon
    (which reads time.time_ns() and cannot be handed a fixed NOW)."""
    import time
    now = time.time_ns()
    kw.setdefault("not_before", now - 10 * SEC)
    kw.setdefault("not_after", now + 3600 * SEC)
    return grant(**kw)


def write_policy(path, grants):
    with open(path, "w") as f:
        json.dump(policy(grants), f)


class TestItem1SingleUseUnderConcurrency(unittest.TestCase):
    """HAM item 1: a single-use grant must authorize at most once, even
    when N requests reach the decision at the same instant.

    The reviewed code snapshots the policy, authorizes against the
    snapshot, and consumes under a SEPARATE lock acquisition. Two racing
    requests both read uses_remaining=1, both PASS, and one approval
    becomes two authorized commands."""

    N_THREADS = 16
    ITERATIONS = 40

    def _store(self, tmpdir, uses=1):
        path = os.path.join(tmpdir, "policy.json")
        write_policy(path, [grant(uses=uses)])
        return azd.PolicyStore(path)

    def test_one_pass_across_racing_threads(self):
        for it in range(self.ITERATIONS):
            with tempfile.TemporaryDirectory() as d:
                store = self._store(d)
                barrier = threading.Barrier(self.N_THREADS)
                results = []
                rlock = threading.Lock()

                def worker():
                    barrier.wait()
                    st, reason, gid, _sha = store.authorize_and_reserve(
                        device="R1", user="virp-rw",
                        command="interface Loopback99", now_ns=NOW)
                    with rlock:
                        results.append((st, gid))

                threads = [threading.Thread(target=worker)
                           for _ in range(self.N_THREADS)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                passes = [r for r in results if r[0] == az.PASS_ADD]
                self.assertEqual(
                    len(passes), 1,
                    "iteration %d: a uses=1 grant authorized %d times"
                    % (it, len(passes)))

    def test_uses_three_authorizes_exactly_three_times(self):
        """The reservation must not over-deny either: a repeat_count of 3
        grants exactly three, no matter how the requests interleave."""
        for it in range(10):
            with tempfile.TemporaryDirectory() as d:
                store = self._store(d, uses=3)
                barrier = threading.Barrier(self.N_THREADS)
                results = []
                rlock = threading.Lock()

                def worker():
                    barrier.wait()
                    st, _r, _g, _sha = store.authorize_and_reserve(
                        device="R1", user="virp-rw",
                        command="interface Loopback99", now_ns=NOW)
                    with rlock:
                        results.append(st)

                threads = [threading.Thread(target=worker)
                           for _ in range(self.N_THREADS)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                self.assertEqual(results.count(az.PASS_ADD), 3,
                                 "iteration %d: got %d passes, wanted 3"
                                 % (it, results.count(az.PASS_ADD)))

    def test_reservation_is_durable_across_reload(self):
        """A daemon that dies between the reservation and its next policy
        read must not resurrect the grant. The reservation is persisted
        inside the same critical section that took it."""
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "policy.json")
            write_policy(path, [grant(uses=1)])
            store = azd.PolicyStore(path)
            st, _r, gid, _sha = store.authorize_and_reserve(
                device="R1", user="virp-rw",
                command="interface Loopback99", now_ns=NOW)
            self.assertEqual(st, az.PASS_ADD)
            self.assertIsNotNone(gid)

            # A brand new process reading the same file on disk.
            reloaded = azd.PolicyStore(path)
            st2, reason, _g, _sha = reloaded.authorize_and_reserve(
                device="R1", user="virp-rw",
                command="interface Loopback99", now_ns=NOW)
            self.assertEqual(st2, az.FAIL,
                             "a consumed grant survived a reload")
            self.assertIn("spent", reason.lower())

    def test_second_request_sees_reserved_and_fails(self):
        """Sequentially: the second request must be refused while the
        first is still only RESERVED (its reply not yet sent)."""
        with tempfile.TemporaryDirectory() as d:
            store = self._store(d)
            st1, _r1, gid1, _sha = store.authorize_and_reserve(
                device="R1", user="virp-rw",
                command="interface Loopback99", now_ns=NOW)
            self.assertEqual(st1, az.PASS_ADD)
            st2, _r2, _g2, _sha = store.authorize_and_reserve(
                device="R1", user="virp-rw",
                command="interface Loopback99", now_ns=NOW)
            self.assertEqual(st2, az.FAIL)
            # Only now is the reply serialized and the reservation
            # confirmed.
            store.spend(gid1)
            st3, _r3, _g3, _sha = store.authorize_and_reserve(
                device="R1", user="virp-rw",
                command="interface Loopback99", now_ns=NOW)
            self.assertEqual(st3, az.FAIL)

    def test_request_path_never_decides_outside_the_reservation(self):
        """The reviewed hole was reachable only because the handler could
        authorize against a SNAPSHOT. Pinned at the source so a later
        edit cannot quietly reintroduce the two-step sequence.

        az.authorize() itself stays public: it is a pure function and the
        compiler and the tests call it. What must not come back is the
        request path calling it, or calling snapshot(), on its own."""
        import inspect
        src = inspect.getsource(azd.AuthorHandler)
        self.assertNotIn("az.authorize(", src,
                         "the request path decides outside the reservation")
        self.assertNotIn(".snapshot()", src,
                         "the request path decides against a snapshot")
        self.assertIn("authorize_and_reserve(", src)

    def test_release_returns_an_unsent_reservation(self):
        """A reservation released because NOTHING left the box (the chain
        append failed before any reply was built) returns to AVAILABLE.
        This is the only rollback there is."""
        with tempfile.TemporaryDirectory() as d:
            store = self._store(d)
            st1, _r, gid, _sha = store.authorize_and_reserve(
                device="R1", user="virp-rw",
                command="interface Loopback99", now_ns=NOW)
            self.assertEqual(st1, az.PASS_ADD)
            store.release(gid)
            st2, _r2, _g, _sha = store.authorize_and_reserve(
                device="R1", user="virp-rw",
                command="interface Loopback99", now_ns=NOW)
            self.assertEqual(st2, az.PASS_ADD,
                             "a reservation nothing acted on must return")


# ── a stub O-Node, so the authorization daemon can be driven end to end ──
#
# The daemon chains its decision BEFORE it replies, and a chain append
# that fails downgrades the reply to ERROR. A test that ran without a
# chain would therefore see ERROR for every request and could not tell a
# refusal from an outage, which is precisely the confusion the daemon
# exists to avoid. This accepts the append and returns a receipt so the
# reply under test is the DECISION.

class _StubONodeHandler(socketserver.BaseRequestHandler):
    def handle(self):
        hdr = self.request.recv(4)
        if len(hdr) < 4:
            return
        n = struct.unpack(">I", hdr)[0]
        buf = b""
        while len(buf) < n:
            c = self.request.recv(n - len(buf))
            if not c:
                return
            buf += c
        self.server.appends.append(json.loads(buf[1:].decode()))
        body = b'{"status":"ok"}'
        self.request.sendall(struct.pack(">I", len(body)) + body)


class _StubONodeServer(socketserver.ThreadingUnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True


class AuthzDaemonHarness:
    """The real AuthorServer on a loopback port, with a real config, a
    real producer key and a real ledger. Nothing is mocked but the
    O-Node."""

    def __init__(self, tmpdir, grants=(), secret=b"labsecret",
                 configured=True):
        self.dir = tmpdir
        self.policy_path = os.path.join(tmpdir, "policy.json")
        write_policy(self.policy_path, list(grants))

        sk_path = os.path.join(tmpdir, "producer.key")
        pk_path = os.path.join(tmpdir, "producer.pub")
        from virp_tacacs_recv import producer_keygen
        self.producer_key_id = producer_keygen(sk_path, pk_path)

        self.sock_path = os.path.join(tmpdir, "onode.sock")
        self.onode = _StubONodeServer(self.sock_path, _StubONodeHandler)
        self.onode.appends = []
        self._ot = threading.Thread(target=self.onode.serve_forever,
                                    daemon=True)
        self._ot.start()

        self.ledger_path = os.path.join(tmpdir, "ledger.jsonl")
        cfg = {
            "receiver_node": "ham-test",
            "producer_key": sk_path,
            "ledger": self.ledger_path,
            "onode_socket": self.sock_path,
            "chain_session": "tacacs-authz:ham-test",
            "relationships": ([{"source_addr": "127.0.0.1",
                                "client_identity": "R1",
                                "secret": secret.decode("latin-1")}]
                              if configured else []),
        }
        self.cfg_path = os.path.join(tmpdir, "authzd.json")
        fd = os.open(self.cfg_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                     0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)
        self.secret = secret

        from virp_tacacs_recv import producer_load_sk
        self.srv = azd.AuthorServer(("127.0.0.1", 0), azd.AuthorHandler)
        self.srv.cfg = azd.load_config(self.cfg_path)
        self.srv.sk = producer_load_sk(sk_path)
        from virp_tacacs_recv import Ledger
        self.srv.ledger = Ledger(self.ledger_path)
        self.srv.counters = azd.Counters()
        self.srv.policy = azd.PolicyStore(self.policy_path,
                                          ledger=self.srv.ledger)
        self.srv.onode_socket = self.sock_path
        self.addr = self.srv.server_address
        self._t = threading.Thread(target=self.srv.serve_forever,
                                   daemon=True)
        self._t.start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        self.onode.shutdown()
        self.onode.server_close()

    def request(self, command, user="virp-rw", unencrypted=False,
                session_id=0x11223344, seq_no=1):
        body = tp.build_author_request(
            authen_method=6, priv_lvl=15, authen_type=1, authen_service=1,
            user=user, port="tty0", rem_addr="10.0.0.9",
            args=["service=shell", "cmd=%s" % command.split()[0],
                  "cmd-arg=%s" % " ".join(command.split()[1:]),
                  "cmd-arg=<cr>"])
        flags = tp.TAC_PLUS_UNENCRYPTED_FLAG if unencrypted else 0
        wire = body if unencrypted else tp.xor_body(
            body, session_id, self.secret, 0xc0, seq_no)
        pkt = tp.build_header(0xc0, tp.TAC_PLUS_AUTHOR, seq_no, flags,
                              session_id, len(wire)) + wire
        s = socket.create_connection(self.addr, timeout=10)
        try:
            s.sendall(pkt)
            hdr = b""
            while len(hdr) < tp.HEADER_LEN:
                c = s.recv(tp.HEADER_LEN - len(hdr))
                if not c:
                    raise AssertionError("daemon closed without replying")
                hdr += c
            h = tp.parse_header(hdr)
            rb = b""
            while len(rb) < h["length"]:
                c = s.recv(h["length"] - len(rb))
                if not c:
                    raise AssertionError("short reply body")
                rb += c
        finally:
            s.close()
        plain = rb if h["unencrypted"] else tp.xor_body(
            rb, session_id, self.secret, h["version"], h["seq_no"])
        return tp.parse_author_response(plain)

    def ledger_events(self):
        out = []
        with open(self.ledger_path) as f:
            for line in f:
                out.append(json.loads(line))
        return out


class TestItem3CleartextOnTheAuthorizationListener(unittest.TestCase):
    """HAM item 3: the authorization listener must not let a client opt
    out of the shared secret.

    The reviewed decode was `if packet.unencrypted or secret is None:
    plain = body`. On the ACCOUNTING receiver that is right: record the
    ugly truth, and say in the record that it arrived in the clear. On an
    AUTHORIZATION service it means the client chooses whether the secret
    applies, and still reaches PASS_ADD."""

    def test_cleartext_from_a_configured_source_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            h = AuthzDaemonHarness(d, grants=[live_grant()])
            try:
                r = h.request("interface Loopback99", unencrypted=True)
                self.assertEqual(r["status_name"], "FAIL", r["server_msg"])
                self.assertIn("cleartext", r["server_msg"].lower())
                events = [e["event"] for e in h.ledger_events()]
                self.assertIn("CLEARTEXT_REJECTED", events)
            finally:
                h.close()

    def test_the_same_request_obfuscated_is_authorized(self):
        """The control must be the CLEARTEXT FLAG and nothing else. Same
        grant, same command, same identity, secret applied: PASS."""
        with tempfile.TemporaryDirectory() as d:
            h = AuthzDaemonHarness(d, grants=[live_grant()])
            try:
                r = h.request("interface Loopback99", unencrypted=False)
                self.assertEqual(r["status_name"], "PASS_ADD",
                                 r["server_msg"])
            finally:
                h.close()

    def test_an_unconfigured_source_is_refused(self):
        """A source with no configured secret is an unknown source. It was
        already refused, by a different route (device is None -> ERROR);
        this pins that it stays refused and never reaches policy."""
        with tempfile.TemporaryDirectory() as d:
            h = AuthzDaemonHarness(d, grants=[live_grant()], configured=False)
            try:
                r = h.request("interface Loopback99", unencrypted=True)
                self.assertIn(r["status_name"], ("FAIL", "ERROR"),
                              r["server_msg"])
            finally:
                h.close()

    def test_a_refused_cleartext_request_never_reserves_a_grant(self):
        with tempfile.TemporaryDirectory() as d:
            h = AuthzDaemonHarness(d, grants=[live_grant(uses=1)])
            try:
                h.request("interface Loopback99", unencrypted=True)
                r = h.request("interface Loopback99", unencrypted=False,
                              session_id=0x55667788)
                self.assertEqual(r["status_name"], "PASS_ADD",
                                 "the cleartext refusal spent the grant")
            finally:
                h.close()

    def test_the_accounting_receiver_stays_permissive(self):
        """The asymmetry is deliberate and must not be 'fixed' later by
        someone tidying the two decoders into one. The receiver records
        CLEARTEXT as a fact; the authorizer refuses it."""
        import virp_tacacs_recv as rcv
        import inspect
        src = inspect.getsource(rcv.build_receipt)
        self.assertIn('"CLEARTEXT"', src)


class TestItem2GrantBindsThePrincipal(unittest.TestCase):
    """HAM item 2: a grant names a user, and that name is part of the key.

    The reviewed _grant_matches() compared device and command only, and
    authorize() special-cased virp-ro and routed EVERY other username
    through write-grant matching. A grant issued for virp-rw therefore
    passed for nate, for breakglass, for anyone the router authenticated
    under any name at all."""

    CMD = "interface Loopback99"

    def test_only_the_named_principal_passes(self):
        p = policy([grant(user="virp-rw")])
        for user, want in (("virp-rw", az.PASS_ADD),
                           ("nate", az.FAIL),
                           ("eviluser", az.FAIL),
                           ("breakglass", az.FAIL),
                           ("virp-ro", az.FAIL)):
            st, reason, _g = az.authorize(p, device="R1", user=user,
                                          command=self.CMD, now_ns=NOW)
            self.assertEqual(st, want,
                             "user %r: got %s (%s)" % (user, st, reason))

    def test_unknown_principal_is_refused_before_any_grant_is_read(self):
        """Fail closed on the identity, not on the absence of a grant.
        The reason must name the identity, so an operator reading a denial
        can tell 'you are not a gate identity' from 'nothing is approved'."""
        st, reason, gid = az.authorize(policy([grant(user="virp-rw")]),
                                       device="R1", user="nate",
                                       command=self.CMD, now_ns=NOW)
        self.assertEqual(st, az.FAIL)
        self.assertIsNone(gid)
        self.assertIn("gate identity", reason.lower())

    def test_a_missing_username_is_refused(self):
        for user in (None, ""):
            st, _r, _g = az.authorize(policy([grant(user="virp-rw")]),
                                      device="R1", user=user,
                                      command=self.CMD, now_ns=NOW)
            self.assertEqual(st, az.FAIL, "user %r must fail closed" % user)

    def test_a_grant_issued_for_ro_does_not_pass_for_rw(self):
        """The grant's own user field is load-bearing, not decoration."""
        st, _r, _g = az.authorize(policy([grant(user="virp-ro")]),
                                  device="R1", user="virp-rw",
                                  command=self.CMD, now_ns=NOW)
        self.assertEqual(st, az.FAIL)

    def test_gate_identities_have_exactly_one_definition(self):
        """The allowlist is derived from the same place the gate
        identities are defined, not typed out again per module."""
        import virp_tacacs_policy as pol
        self.assertEqual(tuple(az.GATE_IDENTITIES),
                         (az.GATE_IDENTITY_RO, az.GATE_IDENTITY_RW))
        self.assertIs(pol.GATE_IDENTITY_RW, az.GATE_IDENTITY_RW)
        with open(os.path.join(ROOT, "tacacs",
                               "virp_tacacs_policy.py")) as f:
            src = f.read()
        self.assertNotIn('"virp-rw"', src,
                         "policy compiler re-types the gate identity")

    def test_compiler_refuses_a_grant_for_a_non_gate_principal(self):
        """The daemon must not ISSUE one either. An approval naming an
        operator outside the gate identity set is refused with a reason,
        never rendered into a grant."""
        import virp_tacacs_policy as pol
        appr = {"approval_id": "appr-x", "signature_verified": True,
                "command": "interface Loopback99", "device": "R1",
                "issued_utc_ns": NOW, "ttl_ns": 300 * SEC,
                "repeat_count": 1, "user": "nate"}
        grants, refusals = pol.compile_grants([appr], now_ns=NOW)
        self.assertEqual(grants, [])
        self.assertEqual(len(refusals), 1)
        self.assertIn("gate identity", refusals[0]["reason"].lower())


class TestItem5dIdentityFollowsTheOperation(unittest.TestCase):
    """HAM item 5d: the authorization decision names the principal it
    decisioned, so authorization, execution and accounting all carry the
    same identity through.

    tacacs_authorization/1 already carries `user`. What was never pinned
    is that the field holds the principal the DECISION was made for, and
    that a refusal carries it too. A break in that line must downgrade
    the evidence, never disappear."""

    def _chained(self, h):
        bodies = []
        for a in h.onode.appends:
            bodies.append(json.loads(a["artifact_content"]))
        return bodies

    def test_a_pass_records_the_principal_it_decisioned(self):
        with tempfile.TemporaryDirectory() as d:
            h = AuthzDaemonHarness(d, grants=[live_grant()])
            try:
                r = h.request("interface Loopback99", user="virp-rw")
                self.assertEqual(r["status_name"], "PASS_ADD")
                bodies = self._chained(h)
                self.assertEqual(len(bodies), 1)
                self.assertEqual(bodies[0]["user"], "virp-rw")
                self.assertEqual(bodies[0]["decision"], "PASS_ADD")
                self.assertEqual(bodies[0]["schema"],
                                 "tacacs_authorization/1")
            finally:
                h.close()

    def test_a_denial_records_the_principal_too(self):
        """A denial for the wrong principal must say WHICH principal was
        denied. A record that only said FAIL would lose the identity at
        exactly the moment it matters."""
        with tempfile.TemporaryDirectory() as d:
            h = AuthzDaemonHarness(d, grants=[live_grant()])
            try:
                r = h.request("interface Loopback99", user="eviluser")
                self.assertEqual(r["status_name"], "FAIL")
                bodies = self._chained(h)
                self.assertEqual(bodies[-1]["user"], "eviluser")
                self.assertEqual(bodies[-1]["decision"], "FAIL")
                self.assertIn("gate identity",
                              bodies[-1]["decision_reason"].lower())
            finally:
                h.close()

    def test_a_cleartext_refusal_still_records_the_principal(self):
        with tempfile.TemporaryDirectory() as d:
            h = AuthzDaemonHarness(d, grants=[live_grant()])
            try:
                h.request("interface Loopback99", user="virp-rw",
                          unencrypted=True)
                bodies = self._chained(h)
                self.assertEqual(bodies[-1]["decision"], "FAIL")
                self.assertIn("cleartext",
                              bodies[-1]["decision_reason"].lower())
            finally:
                h.close()


# ── item 6 fixtures: a real approver key and a real signed approval ─────

def _ed25519():
    from cryptography.hazmat.primitives.asymmetric import ed25519
    return ed25519


def approver_keypair():
    """A THROWAWAY approver key, generated per test. Nothing in the repo
    is a key and nothing here is reused."""
    import base64
    import hashlib
    from cryptography.hazmat.primitives import serialization
    sk = _ed25519().Ed25519PrivateKey.generate()
    pk = sk.public_key()
    raw = pk.public_bytes_raw()
    spki = pk.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)
    key_id = hashlib.sha256(raw).hexdigest()[:32]
    entry = {"key_id": key_id, "algorithm": "ed25519",
             "public_key": base64.b64encode(spki).decode(),
             "operator": "ham-test", "enabled": True}
    return sk, entry


def signed_approval(sk, entry, command="interface Loopback99", device="R1",
                    device_node_id=0x0badf00d, proposal_id=None,
                    approved_at_ns=None, ttl_seconds=300):
    """The pair of chained bodies the compiler joins: a proposal and an
    approval whose approver_signature is real."""
    import hashlib
    import virp_tacacs_policy as pol
    pid = proposal_id or ("a" * 32)
    approved_at_ns = approved_at_ns if approved_at_ns is not None else NOW
    chash = hashlib.sha256(
        az.canonical_command(command).encode("utf-8")).hexdigest()
    canon = pol.build_approval_canonical(pid, chash, device_node_id,
                                         approved_at_ns, ttl_seconds)
    sig = sk.sign(canon)
    proposal = {"proposal_id": pid, "device": device, "command": command,
                "command_hash": chash, "device_node_id": device_node_id}
    approval = {"proposal_id": pid, "command_hash": chash, "device": device,
                "device_node_id": device_node_id,
                "approved_at_ns": str(approved_at_ns),
                "ttl_seconds": ttl_seconds,
                "approver_key_id": entry["key_id"], "operator": "ham-test",
                "body_version": 2, "approver_signature": sig.hex(),
                "_entry_hash": "e" * 64}
    return proposal, approval


class TestItem6CompilerVerifiesTheApproverSignature(unittest.TestCase):
    """HAM item 6: the party issuing temporary write authority verifies
    the human approval signature ITSELF.

    The reviewed compiler built `approval_trusted` from binding
    correctness alone: proposal and approval agree about the command
    hash, the hash recomputes from the proposal text, and the devices
    match. Those are real checks and none of them is a signature. The
    chained approval body did not even carry one, so the compiler could
    not have checked it, and `trust_not_established` listed
    "approver_signature" permanently.

    -07 does not accept that. A grant is temporary write authority on a
    real device, and the issuer must verify the approver's signature
    against ITS OWN pinned registry, not the gate's word."""

    def setUp(self):
        import virp_tacacs_policy as pol
        self.pol = pol
        self.sk, self.entry = approver_keypair()
        self.registry = pol.ApproverRegistry([self.entry])

    def _compile(self, proposal, approval, registry=None, compiled=()):
        a = self.pol.approval_from_chain(
            proposal, approval,
            registry=self.registry if registry is None else registry)
        grants, refusals = self.pol.compile_grants(
            [a], now_ns=NOW, compiled_approval_ids=compiled)
        # The derived `configure terminal` prerequisite is not something a
        # human approved and is counted separately.
        return [g for g in grants if not g.get("derived")], refusals

    def test_a_verified_approval_becomes_a_grant(self):
        pr, ap = signed_approval(self.sk, self.entry)
        grants, refusals = self._compile(pr, ap)
        self.assertEqual(len(grants), 1, refusals)
        self.assertEqual(grants[0]["device"], "R1")

    def test_the_trust_basis_names_the_signature(self):
        pr, ap = signed_approval(self.sk, self.entry)
        a = self.pol.approval_from_chain(pr, ap, registry=self.registry)
        self.assertIn("approver_signature_verified", a["trust_basis"])
        self.assertEqual(a["trust_not_established"], [])
        self.assertIs(a["approval_trusted"], True)

    def test_a_signature_by_an_unpinned_key_yields_no_grant(self):
        """The fail-first case. The bindings are perfect; the key is not
        one this compiler pinned. Nothing may be rendered."""
        other_sk, other_entry = approver_keypair()
        pr, ap = signed_approval(other_sk, other_entry)
        grants, refusals = self._compile(pr, ap)
        self.assertEqual(grants, [])
        self.assertEqual(len(refusals), 1)
        self.assertIn("approver_signature", str(refusals[0]))

    def test_a_key_pinned_but_disabled_yields_no_grant(self):
        entry = dict(self.entry)
        entry["enabled"] = False
        reg = self.pol.ApproverRegistry([entry])
        pr, ap = signed_approval(self.sk, self.entry)
        a = self.pol.approval_from_chain(pr, ap, registry=reg)
        self.assertIs(a["approval_trusted"], False)
        self.assertIn("approver_signature", a["trust_not_established"])

    def test_a_tampered_command_digest_yields_no_grant(self):
        pr, ap = signed_approval(self.sk, self.entry)
        ap = dict(ap)
        ap["command_hash"] = "b" * 64
        pr = dict(pr)
        pr["command_hash"] = "b" * 64
        grants, refusals = self._compile(pr, ap)
        self.assertEqual(grants, [])

    def test_a_tampered_ttl_yields_no_grant(self):
        """Every field the 72-byte payload covers is bound, not just the
        command. Extending the TTL after the fact must break it."""
        pr, ap = signed_approval(self.sk, self.entry)
        ap = dict(ap)
        ap["ttl_seconds"] = 86400
        grants, refusals = self._compile(pr, ap)
        self.assertEqual(grants, [])

    def test_a_replayed_approval_yields_no_grant(self):
        """One approval, one compilation. A second render of the same
        approval id is a replay and is refused with its own reason."""
        pr, ap = signed_approval(self.sk, self.entry)
        grants, _r = self._compile(pr, ap)
        self.assertEqual(len(grants), 1)
        grants2, refusals2 = self._compile(pr, ap,
                                           compiled=(ap["proposal_id"],))
        self.assertEqual(grants2, [])
        self.assertIn("already", str(refusals2).lower())

    def test_no_registry_at_all_renders_nothing(self):
        """Fail closed on the absence of the registry, never open. A
        compiler with nothing pinned can verify nothing."""
        pr, ap = signed_approval(self.sk, self.entry)
        a = self.pol.approval_from_chain(pr, ap, registry=None)
        self.assertIs(a["approval_trusted"], False)
        grants, refusals = self.pol.compile_grants([a], now_ns=NOW)
        self.assertEqual(grants, [])

    def test_a_body_with_no_signature_is_legacy_and_untrusted(self):
        """The pre-change approval bodies carry no signature at all. They
        are not upgraded by silence: they read as trust-not-established,
        exactly as they did before, and render nothing."""
        pr, ap = signed_approval(self.sk, self.entry)
        ap = dict(ap)
        ap.pop("approver_signature")
        ap.pop("body_version")
        a = self.pol.approval_from_chain(pr, ap, registry=self.registry)
        self.assertIs(a["approval_trusted"], False)
        self.assertIn("approver_signature", a["trust_not_established"])

    def test_canonical_payload_matches_the_c_layout(self):
        """The Python reconstruction is the C daemon's 72 bytes or it is
        nothing. Layout from include/virp_approval.h."""
        canon = self.pol.build_approval_canonical(
            "0" * 30 + "ff", "1" * 64, 0x0badf00d, 1788722800424766173, 300)
        self.assertEqual(len(canon), 72)
        self.assertEqual(canon[:4], b"VAP1")
        self.assertEqual(canon[4:20], bytes.fromhex("0" * 30 + "ff"))
        self.assertEqual(canon[20:52], bytes.fromhex("1" * 64))
        self.assertEqual(int.from_bytes(canon[52:60], "big"), 0x0badf00d)
        self.assertEqual(int.from_bytes(canon[60:68], "big"),
                         1788722800424766173)
        self.assertEqual(int.from_bytes(canon[68:72], "big"), 300)


if __name__ == "__main__":
    unittest.main(verbosity=2)
