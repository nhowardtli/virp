"""Decision submitter: parsing, and the source-refusal tag it derives.

The tag is the part worth testing hardest. tac_plus-ng emits a real,
distinct token for an authentication refused by the source acl
(AUTHC-FAIL-ACL, measured 2026-09-06), but on the AUTHORIZATION path it
emits only generic AUTHZ-FAIL with no reason vocabulary. So for authz
the submitter RECOMPUTES the source test and records the verdict as
derived. These tests pin the difference between observed and derived,
because a reader who mistakes one for the other is being told the server
said something it did not.

Crypto-dependent tests skip when `cryptography` is absent rather than
erroring, so the suite is honest in a checkout without it.
"""

import importlib.util
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tacacs"))
import virp_tacacs_submit as sub

HAVE_CRYPTO = importlib.util.find_spec("cryptography") is not None

AUTHZ = ("2026-09-06 20:02:38 +0000 10.0.0.10\tvirp-ro\ttty1\t10.0.0.13\t"
         "virp_ro_profile\tpermit\tshell\tshow clock <cr>\tAUTHZ-PASS")
AUTHZ_DENY_BADSRC = ("2026-09-06 20:02:38 +0000 10.0.0.10\tnhoward\ttty0\t"
                     "10.0.0.99\toperator_profile\tdeny\tshell\t"
                     "show version <cr>\tAUTHZ-FAIL")
AUTHZ_DENY_GOODSRC = ("2026-09-06 20:02:38 +0000 10.0.0.10\tvirp-ro\ttty1\t"
                      "10.0.0.13\tvirp_ro_profile\tdeny\tshell\t"
                      "configure terminal <cr>\tAUTHZ-FAIL")
ACCESS_ACL = ("2026-09-06 20:00:26 +0000 127.0.0.1\tnhoward\ttty0\t"
              "10.0.0.99\tascii login denied by ACL\tAUTHC-FAIL-ACL")

ALLOWED = {"10.0.0.45", "10.0.0.13"}


class TestParsing(unittest.TestCase):

    def test_head_splits_timestamp_from_device(self):
        """Field 0 is 'timestamp nas' -- the timestamp prefix is NOT
        tab-separated from the device address, so a naive split puts the
        device in with the clock."""
        ts, nas, rest = sub.split_line(AUTHZ)
        self.assertEqual(nas, "10.0.0.10")
        self.assertEqual(ts, "2026-09-06 20:02:38 +0000")
        self.assertEqual(rest[0], "virp-ro")

    def test_authz_fields_map_in_order(self):
        r = sub.parse_line(AUTHZ, "authz")
        self.assertEqual(r["user"], "virp-ro")
        self.assertEqual(r["client"], "10.0.0.13")
        self.assertEqual(r["profile"], "virp_ro_profile")
        self.assertEqual(r["result"], "permit")
        self.assertEqual(r["cmd"], "show clock <cr>")
        self.assertEqual(r["msgid"], "AUTHZ-PASS")

    def test_access_has_no_cmd_and_shorter_shape(self):
        r = sub.parse_line(ACCESS_ACL, "access")
        self.assertEqual(r["user"], "nhoward")
        self.assertEqual(r["client"], "10.0.0.99")
        self.assertEqual(r["msgid"], "AUTHC-FAIL-ACL")
        self.assertNotIn("cmd", r)

    def test_unparseable_line_returns_none_not_garbage(self):
        self.assertIsNone(sub.parse_line("not a log line", "authz"))
        self.assertIsNone(sub.parse_line("", "authz"))


class TestSourceRefusalTag(unittest.TestCase):

    def test_acl_denial_is_reported_as_observed_not_derived(self):
        """AUTHC-FAIL-ACL is something tac_plus-ng actually said. The
        basis must name the server, never 'derived' -- the whole point
        of the field is to keep those apart."""
        refused, basis = sub.classify_refusal(
            sub.parse_line(ACCESS_ACL, "access"), ALLOWED)
        self.assertTrue(refused)
        self.assertEqual(basis, "tac_plus-ng")

    def test_authz_deny_from_disallowed_source_is_derived_true(self):
        refused, basis = sub.classify_refusal(
            sub.parse_line(AUTHZ_DENY_BADSRC, "authz"), ALLOWED)
        self.assertTrue(refused)
        self.assertEqual(basis, "derived")

    def test_authz_deny_from_allowed_source_is_a_command_refusal(self):
        """The case the raw log cannot distinguish: a real deny from a
        permitted source is a COMMAND refusal and must not be mislabelled
        as a source refusal."""
        refused, basis = sub.classify_refusal(
            sub.parse_line(AUTHZ_DENY_GOODSRC, "authz"), ALLOWED)
        self.assertFalse(refused)
        self.assertEqual(basis, "derived")

    def test_permit_is_never_a_refusal(self):
        refused, basis = sub.classify_refusal(
            sub.parse_line(AUTHZ, "authz"), ALLOWED)
        self.assertFalse(refused)
        self.assertEqual(basis, "n/a")


class TestBody(unittest.TestCase):

    def body(self, line, kind):
        return sub.build_body(sub.parse_line(line, kind), kind,
                              "virp-tacacs-home", "deadbeef" * 4, ALLOWED)

    def test_producer_key_id_is_present(self):
        """tacacs_accounting/1 carries producer_sig with NO key id. This
        schema is a SECOND producer on the same chain, so a record that
        cannot name its signing key would be ambiguous from day one."""
        b = self.body(AUTHZ, "authz")
        self.assertEqual(b["producer_key_id"], "deadbeef" * 4)
        self.assertEqual(b["schema"], "tacacs_decision/1")

    def test_derived_field_is_named_so_it_cannot_be_mistaken(self):
        b = self.body(AUTHZ_DENY_BADSRC, "authz")
        self.assertIn("source_refused_derived", b)
        self.assertIn("source_refused_basis", b)
        self.assertTrue(b["source_refused_derived"])

    def test_original_fields_survive_into_the_body(self):
        b = self.body(AUTHZ, "authz")
        self.assertEqual(b["device_addr"], "10.0.0.10")
        self.assertEqual(b["cmd"], "show clock <cr>")

    @unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
    def test_signed_body_is_canonical_and_carries_sig(self):
        import tempfile
        from virp_tacacs_recv import producer_keygen, canonical_bytes
        d = tempfile.mkdtemp()
        sk_p, pk_p = os.path.join(d, "k"), os.path.join(d, "k.pub")
        kid = producer_keygen(sk_p, pk_p)
        sk = sub.producer_load_sk(sk_p)
        raw, body = sub.producer_sign(sk, self.body(AUTHZ, "authz"))
        self.assertIn("producer_sig", body)
        self.assertEqual(raw, canonical_bytes(body))
        self.assertEqual(len(kid), 32)


if __name__ == "__main__":
    unittest.main(verbosity=2)
