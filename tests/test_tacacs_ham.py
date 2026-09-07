#!/usr/bin/env python3
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
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tacacs"))

import virp_tacacs_authz as az
import virp_tacacs_authzd as azd

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
