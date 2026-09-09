#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
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


class TestItem4ProducerSignatureIsATrustDecision(unittest.TestCase):
    """HAM item 4: a producer signature nobody checks proves nothing.

    /1 bodies carry `producer_sig` and no consumer has ever verified it,
    and /1 carries no producer key id, so no consumer could pick a key to
    try. What /1 proves is that the chain committed to these bytes. What
    it does not prove is that the bytes came from the receiver."""

    def setUp(self):
        self.sk, self.pk, self.kid = producer_key()

    def _signed(self, **kw):
        _bytes, body = rcv.producer_sign_v2(self.sk, self.kid,
                                            acct_body(**kw))
        return body

    def test_a_good_v2_body_verifies(self):
        body = self._signed()
        self.assertEqual(body["schema"], "tacacs_accounting/2")
        self.assertEqual(body["producer_key_id"], self.kid)
        self.assertEqual(body["producer_signature_scheme"], "ed25519")
        status, detail = rcv.producer_verify(body, self.pk, self.kid)
        self.assertEqual(status, "VERIFIED", detail)

    def test_a_tampered_body_fails(self):
        body = self._signed()
        body["user"] = "eviluser"
        status, _d = rcv.producer_verify(body, self.pk, self.kid)
        self.assertEqual(status, "FAILED")

    def test_a_tampered_key_id_fails(self):
        """The key id is INSIDE the signed bytes. Re-labelling a record
        onto another key breaks the signature, it does not move it."""
        body = self._signed()
        body["producer_key_id"] = "0" * 32
        status, _d = rcv.producer_verify(body, self.pk, None)
        self.assertEqual(status, "FAILED")

    def test_the_wrong_pinned_key_fails(self):
        body = self._signed()
        _sk2, pk2, kid2 = producer_key()
        status, _d = rcv.producer_verify(body, pk2, kid2)
        self.assertEqual(status, "FAILED")

    def test_a_v1_body_is_absent_not_failed(self):
        """Every record on 313 and .211 today is /1. Grading the existing
        corpus as tampered would be a lie about what happened."""
        body = acct_body()
        _b, signed = rcv.producer_sign(self.sk, body)
        status, detail = rcv.producer_verify(signed, self.pk, self.kid)
        self.assertEqual(status, "ABSENT", detail)

    def test_a_v2_body_with_no_pinned_key_is_failed_not_absent(self):
        """A /2 body a verifier cannot check is not the same thing as a
        /1 body that carries nothing to check."""
        body = self._signed()
        status, _d = rcv.producer_verify(body, None, None)
        self.assertEqual(status, "FAILED")

    def test_the_canonical_string_excludes_only_the_signature_fields(self):
        body = self._signed()
        canon = rcv.producer_canonical_bytes(body)
        obj = json.loads(canon.decode("ascii"))
        self.assertNotIn("producer_signature", obj)
        self.assertNotIn("producer_sig", obj)
        self.assertNotIn("producer_signature_scheme", obj)
        self.assertIn("producer_key_id", obj)
        self.assertEqual(obj["schema"], "tacacs_accounting/2")
        # Deterministic: sorted keys, compact separators, ascii only.
        self.assertEqual(canon, json.dumps(
            obj, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("ascii"))

    def test_the_documented_test_vector_reproduces(self):
        """docs/TACACS-ACCOUNTING.md carries a worked vector. If the
        canonical string ever drifts from the document, this fails."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        seed = bytes(range(32))
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        raw_pk = sk.public_key().public_bytes_raw()
        kid = rcv.producer_key_id(raw_pk)
        body = {"schema": "tacacs_accounting/1", "receiver_node": "vector",
                "user": "virp-ro", "decode": "OBFUSCATED_MD5",
                "parse": "COMPLETE", "recv_utc_ns": 1788722800424766173}
        _b, signed = rcv.producer_sign_v2(sk, kid, body)
        doc = open(os.path.join(ROOT, "docs",
                                "TACACS-ACCOUNTING.md")).read()
        self.assertIn(raw_pk.hex(), doc, "documented pubkey drifted")
        self.assertIn(kid, doc, "documented key_id drifted")
        self.assertIn(signed["producer_signature"], doc,
                      "documented signature drifted")
        self.assertIn(
            rcv.producer_canonical_bytes(signed).decode("ascii"), doc,
            "documented canonical string drifted")

    def test_reconciliation_reads_both_schemas(self):
        v2 = self._signed(user="virp-ro")
        items = run([receipt(v2)],
                    [gate(device_principal="virp-ro")],
                    producer_pubkey=self.pk, producer_key_id=self.kid)
        self.assertEqual(items[0]["verdict"], "MATCHED")
        self.assertEqual(items[0]["tacacs_producer_signature"], "VERIFIED")

    def test_only_a_verified_record_may_be_called_corroboration(self):
        v2 = self._signed(user="virp-ro")
        strong = run([receipt(v2)], [gate(device_principal="virp-ro")],
                     producer_pubkey=self.pk, producer_key_id=self.kid)
        self.assertEqual(strong[0]["corroboration"],
                         rc.CORROBORATION_STRONG)

        v1 = acct_body(user="virp-ro")
        weak = run([receipt(v1)], [gate(device_principal="virp-ro")],
                   producer_pubkey=self.pk, producer_key_id=self.kid)
        self.assertEqual(weak[0]["verdict"], "MATCHED")
        self.assertEqual(weak[0]["tacacs_producer_signature"], "ABSENT")
        self.assertEqual(weak[0]["corroboration"], rc.CORROBORATION_WEAK)

    def test_a_tampered_v2_record_still_correlates_but_never_corroborates(self):
        v2 = self._signed(user="virp-ro")
        v2["receiver_node"] = "somewhere-else"
        items = run([receipt(v2)], [gate(device_principal="virp-ro")],
                    producer_pubkey=self.pk, producer_key_id=self.kid)
        self.assertEqual(items[0]["tacacs_producer_signature"], "FAILED")
        self.assertEqual(items[0]["corroboration"], rc.CORROBORATION_WEAK)


class TestItem15SourceStrength(unittest.TestCase):
    """HAM item 15: a cleartext or unconfigured-source receipt does not
    grade like a shared-secret-decoded one.

    Correlation is shown for all of them. Only the strong end may be
    called corroboration: anyone who can reach the accounting port can
    write a cleartext receipt."""

    def setUp(self):
        self.sk, self.pk, self.kid = producer_key()

    def _strength(self, **kw):
        return rc.source_strength(acct_body(**kw))

    def test_every_strength_value(self):
        self.assertEqual(self._strength(decode="OBFUSCATED_MD5"),
                         "SHARED_SECRET_DECODED")
        self.assertEqual(self._strength(decode="CLEARTEXT"), "CLEARTEXT")
        self.assertEqual(self._strength(decode="NO_SECRET_CONFIGURED",
                                        parse="NOT_ATTEMPTED"),
                         "UNCONFIGURED_SOURCE")
        self.assertEqual(self._strength(decode="OBFUSCATED_MD5",
                                        parse="MALFORMED"), "MALFORMED")
        b = acct_body()
        b["tacacs_tls"] = True
        self.assertEqual(rc.source_strength(b), "TLS_AUTHENTICATED")

    def test_the_vocabulary_is_closed(self):
        for decode in ("OBFUSCATED_MD5", "CLEARTEXT", "NO_SECRET_CONFIGURED",
                       "SOMETHING_NEW", None):
            self.assertIn(self._strength(decode=decode),
                          rc.SOURCE_STRENGTHS)

    def test_a_cleartext_receipt_correlates_but_does_not_corroborate(self):
        _b, body = rcv.producer_sign_v2(
            self.sk, self.kid, acct_body(user="virp-ro", decode="CLEARTEXT"))
        items = run([receipt(body)], [gate(device_principal="virp-ro")],
                    producer_pubkey=self.pk, producer_key_id=self.kid)
        self.assertEqual(items[0]["verdict"], "MATCHED")
        self.assertEqual(items[0]["source_strength"], "CLEARTEXT")
        self.assertEqual(items[0]["tacacs_producer_signature"], "VERIFIED")
        self.assertEqual(items[0]["corroboration"], rc.CORROBORATION_WEAK,
                         "a cleartext receipt graded as corroboration")

    def test_an_unconfigured_source_correlates_but_does_not_corroborate(self):
        body = acct_body(user="virp-ro", decode="NO_SECRET_CONFIGURED",
                         parse="NOT_ATTEMPTED")
        items = run([receipt(body)], [gate(device_principal="virp-ro")])
        self.assertEqual(items[0]["source_strength"], "UNCONFIGURED_SOURCE")
        self.assertEqual(items[0]["corroboration"], rc.CORROBORATION_WEAK)

    def test_the_claim_sentence_is_unchanged(self):
        """The reconciliation record still says, verbatim, that it is a
        CLAIM and not a cryptographic verdict. These two new axes are
        properties beside that sentence, never a promotion of it."""
        rec = rc.build_record([], 15000, "/nonexistent", None, ())
        self.assertEqual(
            rec["presentation"],
            "CLAIM, not a cryptographic verdict. Render beside the "
            "PASS/FAIL/UNCHECKED/UNVERIFIABLE ladder, never inside it. "
            "This record cites receipts and never modifies them.")


class TestItem4dThePublicVerifierAgrees(unittest.TestCase):
    """HAM item 4d: report/verify.py grades the same property, and grades
    it identically.

    verify.py reimplements the canonical string rather than importing the
    producer's. A verifier that runs the signer's own code is checking
    nothing, so the two implementations are held byte-identical by test
    instead of by shared import."""

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "report"))
        import verify
        self.verify = verify
        self.sk, self.pk, self.kid = producer_key()

    def _signed(self, **kw):
        _b, body = rcv.producer_sign_v2(self.sk, self.kid, acct_body(**kw))
        return body

    def test_the_two_canonical_strings_are_byte_identical(self):
        body = self._signed()
        self.assertEqual(rcv.producer_canonical_bytes(body),
                         self.verify.tacacs_producer_canonical(body))

    def test_the_two_key_ids_agree(self):
        self.assertEqual(self.verify.tacacs_producer_key_id(self.pk),
                         self.kid)

    def test_good_signature_verifies(self):
        status, detail = self.verify.verify_tacacs_producer_signature(
            self._signed(), self.pk, self.kid)
        self.assertEqual(status, "VERIFIED", detail)

    def test_tampered_body_fails(self):
        body = self._signed()
        body["command_seen"] = "reload"
        status, _d = self.verify.verify_tacacs_producer_signature(
            body, self.pk, self.kid)
        self.assertEqual(status, "FAILED")

    def test_v1_body_is_absent(self):
        _b, body = rcv.producer_sign(self.sk, acct_body())
        status, _d = self.verify.verify_tacacs_producer_signature(
            body, self.pk, self.kid)
        self.assertEqual(status, "ABSENT")

    def test_wrong_key_fails(self):
        _sk2, pk2, kid2 = producer_key()
        status, _d = self.verify.verify_tacacs_producer_signature(
            self._signed(), pk2, kid2)
        self.assertEqual(status, "FAILED")

    def test_a_non_accounting_body_is_not_this_property_s_business(self):
        status, _d = self.verify.verify_tacacs_producer_signature(
            {"schema": "gate_execution/1"}, self.pk, self.kid)
        self.assertIsNone(status)

    def test_the_selection_grader_tallies_and_never_touches_the_rollup(self):
        class FakeV:
            def __init__(self, body, seq):
                self.artifact_raw = json.dumps(body).encode()
                self.entry = {"session_id": "tacacs:ham", "sequence": seq,
                              "artifact_id": "tacacs:%d" % seq}

        good = self._signed()
        bad = self._signed()
        bad["user"] = "eviluser"
        v1 = rcv.producer_sign(self.sk, acct_body())[1]
        other = {"schema": "gate_execution/1", "device": "R1"}
        rows, tally = self.verify.verify_tacacs_producer_signatures(
            [FakeV(good, 0), FakeV(bad, 1), FakeV(v1, 2), FakeV(other, 3)],
            self.pk, self.kid)
        self.assertEqual(tally, {"VERIFIED": 1, "FAILED": 1, "ABSENT": 1})
        self.assertEqual(len(rows), 3, "a non-accounting entry was counted")

    def test_the_report_cli_exposes_the_flag(self):
        src = open(os.path.join(ROOT, "report", "virp_report.py")).read()
        self.assertIn("--tacacs-producer-pubkey", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
