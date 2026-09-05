"""Every TACACS+ relationship must name a real fleet device.

virp_tacacs_reconcile.py groups receipts by (client_identity or
source_addr) and then looks for gate records with the same device name:

    key = (b.get("client_identity") or b.get("source_addr"), ...)   # :320
    if gb.get("device") != device: continue                          # :375

So client_identity is a JOIN KEY against the VIRP device hostname, not a
label of convenience. A client_identity that does not name a fleet
device produces no error anywhere: the receiver records receipts
happily, the reconciler matches zero gate records for that switch, and
the operator sees unmatched receipts forever without being told why.

This suite makes that a load-time fact about the tracked configs
instead. It reads no production path and writes none.
"""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TEMPLATES = [
    ROOT / "deploy" / "devices.template.json",
    ROOT / "deploy" / "devices.home.template.json",
    ROOT / "deploy" / "devices.node2.template.json",
]

RECEIVER_CONFIGS = [
    ROOT / "docs" / "tacacs-receiver.example.json",
]

PLACEHOLDER = re.compile(r"^\$\{[A-Z0-9_]+\}$")


def load_template(path):
    """Templates carry ${VAR} placeholders; neutralise them to parse."""
    text = re.sub(r"\$\{[A-Z0-9_]+\}", "X", path.read_text())
    return json.loads(text)


def fleet_devices():
    """hostname -> (template name, host address), across every template."""
    out = {}
    for t in TEMPLATES:
        if not t.exists():
            continue
        for dev in load_template(t).get("devices", []):
            hn = dev.get("hostname")
            if hn:
                out.setdefault(hn, (t.name, dev.get("host")))
    return out


class TestRelationshipIdentities(unittest.TestCase):
    def setUp(self):
        self.fleet = fleet_devices()
        self.assertTrue(self.fleet, "no devices parsed from any template")

    def test_every_client_identity_names_a_fleet_device(self):
        for cfg_path in RECEIVER_CONFIGS:
            cfg = json.loads(cfg_path.read_text())
            for rel in cfg.get("relationships", []):
                ident = rel.get("client_identity")
                self.assertIsNotNone(
                    ident, "%s: a relationship has no client_identity" % cfg_path.name)
                self.assertIn(
                    ident, self.fleet,
                    "%s: client_identity %r is not a hostname in any tracked "
                    "device template. Reconciliation would join on it and "
                    "match nothing, silently." % (cfg_path.name, ident))

    def test_source_addr_is_present_and_not_a_placeholder(self):
        for cfg_path in RECEIVER_CONFIGS:
            cfg = json.loads(cfg_path.read_text())
            for rel in cfg.get("relationships", []):
                addr = rel.get("source_addr")
                self.assertTrue(addr, "%s: relationship without source_addr"
                                % cfg_path.name)
                self.assertFalse(
                    PLACEHOLDER.match(addr),
                    "%s: source_addr %r is a ${...} placeholder. load_config "
                    "does no substitution, so this would be matched "
                    "literally against the peer address and never hit."
                    % (cfg_path.name, addr))

    def test_no_real_secret_is_tracked(self):
        """A tracked config is 0644. Its secrets must be obvious blanks."""
        for cfg_path in RECEIVER_CONFIGS:
            cfg = json.loads(cfg_path.read_text())
            for rel in cfg.get("relationships", []):
                secret = rel.get("secret")
                self.assertEqual(
                    secret, "REPLACE_ME",
                    "%s: relationship for %r carries %r as its secret. A "
                    "tracked example must not hold anything that could be a "
                    "real TACACS+ key, and must not hold a ${...} placeholder "
                    "either — load_config does no substitution and would use "
                    "it verbatim."
                    % (cfg_path.name, rel.get("client_identity"), secret))

    def test_sw3850_is_enrolled_and_agrees_with_the_fleet_entry(self):
        """The device this enrollment exists for, pinned by name."""
        cfg = json.loads(
            (ROOT / "docs" / "tacacs-receiver.example.json").read_text())
        rels = {r["client_identity"]: r for r in cfg["relationships"]}
        self.assertIn("SW-3850", rels,
                      "SW-3850 is not enrolled in the example receiver config")
        self.assertIn("SW-3850", self.fleet,
                      "SW-3850 is not in any tracked device template")

        template_name, fleet_host = self.fleet["SW-3850"]
        source_addr = rels["SW-3850"]["source_addr"]
        # These CAN legitimately differ — `ip tacacs source-interface`
        # makes the sourcing address other than the management one — so
        # a mismatch is not a failure. It is a fact worth stating, and
        # the config comment says to confirm it with `show tacacs`.
        self.assertTrue(
            fleet_host,
            "SW-3850 in %s has no host address to compare" % template_name)
        if source_addr != fleet_host:
            self.skipTest(
                "SW-3850 sources accounting from %s but is managed at %s "
                "(%s) — legitimate under `ip tacacs source-interface`, "
                "confirm with `show tacacs`."
                % (source_addr, fleet_host, template_name))


if __name__ == "__main__":
    unittest.main(verbosity=2)
