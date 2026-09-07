#!/usr/bin/env python3
"""
HAM review, 2026-09-06 — regressions for TACACS+ evidence strength.

Items 4 (producer signature is part of a trust decision), 5 (the
device-side principal is part of the reconciliation key) and 15 (a
cleartext receipt does not grade like an authenticated one).

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

import hashlib
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tacacs"))

import virp_tacacs_recv as rcv
import virp_tacacs_reconcile as rc
import virp_tacacs_codec as tp

NOW = 1_788_722_800_000_000_000
SEC = 1_000_000_000


def producer_key():
    """A THROWAWAY producer key, generated per test."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    sk = ed25519.Ed25519PrivateKey.generate()
    raw_pk = sk.public_key().public_bytes_raw()
    return sk, raw_pk, rcv.producer_key_id(raw_pk)


def acct_body(device="R1", command="show running-config", user="nhoward",
              t_ns=NOW, task_id="7", decode="OBFUSCATED_MD5",
              parse="COMPLETE", flags=("STOP",)):
    args = ["service=shell", "task_id=%s" % task_id,
            "cmd=%s" % command.split()[0],
            "cmd-arg=%s" % " ".join(command.split()[1:]), "cmd-arg=<cr>"]
    return {
        "schema": rcv.SCHEMA,
        "receiver_node": "ham",
        "client_identity": device,
        "client_identity_source": ("configured_by_source_address"
                                   if decode != "NO_SECRET_CONFIGURED"
                                   else "unconfigured_source"),
        "source_addr": "10.0.0.1",
        "recv_utc_ns": t_ns,
        "user": user,
        "port": "tty0",
        "args": args,
        "args_index": tp.args_index(args),
        "acct_flags": list(flags),
        "raw_body_sha256": hashlib.sha256(
            ("%s%s%s" % (device, task_id, command)).encode()).hexdigest(),
        "decode": decode,
        "parse": parse,
    }


def receipt(body, seq=0):
    return {"session_id": "tacacs:ham", "sequence": seq,
            "artifact_id": "tacacs:%d" % seq,
            "timestamp_ns": body["recv_utc_ns"], "body": body}


def gate(device="R1", command="show running-config", t_ns=NOW,
         device_principal=None, seq=0):
    b = {"schema": "gate_execution/1", "device": device, "command": command,
         "decision": "auto-execute"}
    if device_principal is not None:
        b["device_principal"] = device_principal
        b["body_version"] = 2
    return {"session_id": "gate-enforce:%s" % device, "sequence": seq,
            "artifact_id": "gateexec-%d" % seq, "timestamp_ns": t_ns,
            "body": b}


def run(receipts, gates, **kw):
    return rc.reconcile(receipts, gates, windows=(), match_window_ms=15000,
                        **kw)


class TestItem5ReconciliationBindsThePrincipal(unittest.TestCase):
    """HAM item 5: the reconciliation key is device + PRINCIPAL + command
    + temporal context.

    The reviewed matcher used device + command + time. -07 names the
    principal, and the gate record did not carry one, so a human running
    the same command one second after the gate CORROBORATED the gate's
    execution: the accountability the record claims to establish, handed
    to whoever typed next."""

    def test_the_one_second_human_does_not_match_the_gate(self):
        """19:00:00 the gate runs `show running-config` as virp-ro.
        19:00:01 a human runs the same command as nhoward. Same device.
        These are two events and must never be graded as one."""
        g = gate(t_ns=NOW, device_principal="virp-ro")
        r = receipt(acct_body(user="nhoward", t_ns=NOW + 1 * SEC))
        items = run([r], [g])
        verdicts = sorted(i["verdict"] for i in items)
        self.assertNotIn("MATCHED", verdicts)
        self.assertNotIn("MATCHED_LEGACY_NO_PRINCIPAL", verdicts)
        self.assertEqual(verdicts, ["UNGOVERNED", "UNREPORTED"])

    def test_the_same_principal_one_second_apart_does_match(self):
        """The control is the PRINCIPAL and nothing else. Same window,
        same command, same identity: one event."""
        g = gate(t_ns=NOW, device_principal="virp-ro")
        r = receipt(acct_body(user="virp-ro", t_ns=NOW + 1 * SEC))
        items = run([r], [g])
        self.assertEqual([i["verdict"] for i in items], ["MATCHED"])
        self.assertEqual(items[0]["acct_principal"], "virp-ro")
        self.assertEqual(items[0]["gate_principal"], "virp-ro")

    def test_a_legacy_gate_record_grades_separately(self):
        """A gate_execution written before device_principal existed is
        matched, and SAID to be the weaker thing it is. Never promoted."""
        g = gate(t_ns=NOW)
        r = receipt(acct_body(user="virp-ro", t_ns=NOW + 1 * SEC))
        items = run([r], [g])
        self.assertEqual([i["verdict"] for i in items],
                         ["MATCHED_LEGACY_NO_PRINCIPAL"])
        self.assertIsNone(items[0]["gate_principal"])

    def test_a_bound_gate_record_is_preferred_over_a_legacy_one(self):
        """With both available, the one that proves the identity wins and
        the run does not silently fall back to the weaker grade."""
        bound = gate(t_ns=NOW, device_principal="virp-ro", seq=0)
        legacy = gate(t_ns=NOW, seq=1)
        r = receipt(acct_body(user="virp-ro", t_ns=NOW))
        items = run([r], [bound, legacy])
        matched = [i for i in items if i["verdict"] == "MATCHED"]
        self.assertEqual(len(matched), 1)
        self.assertEqual(matched[0]["gate_principal"], "virp-ro")

    def test_the_verdict_vocabulary_carries_the_new_grade(self):
        self.assertIn("MATCHED_LEGACY_NO_PRINCIPAL", rc.VERDICTS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
