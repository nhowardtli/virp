"""Pure-render checks; never installs rules or sends packets."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('demo_network', ROOT / 'deploy/demo/network.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class DemoNetwork(unittest.TestCase):
    def test_caddy_access_is_uid_scoped_and_private_egress_stays_denied(self):
        rules = m.render('eth0', 'br-demo', ['10.0.20.1'], ['10.0.20.1'], True, 995)
        self.assertIn('meta nfproto ipv4 iifname "eth0" tcp dport 443', rules)
        self.assertIn('meta skuid 995 tcp dport 443', rules)
        self.assertIn('172.16.0.0/12', rules)
        with self.assertRaises(ValueError):
            m.render('eth0', 'br-demo', ['10.0.20.1'], ['10.0.20.1'], True, 0)

    def test_rejects_interface_injection(self):
        for value in ['eth0"; accept', 'eth0\n', '*', 'x' * 16]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                m.render(value, 'clab-demo', ['10.0.20.1'], ['10.0.20.1'])

    def test_no_private_service_exceptions(self):
        for ip in ['10.0.10.211', '10.0.50.102', '10.0.0.211', '1.1.1.1', '127.0.0.1', '172.31.219.11', '::1']:
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                m.endpoints([ip])

    def test_policy_separates_internal_fleet_from_management(self):
        rules = m.render('ens19', 'clab-demo', ['10.0.20.1'], ['10.0.20.1'])
        self.assertNotIn('flush ruleset', rules)
        self.assertEqual(rules.count('policy drop'), 3)
        self.assertIn('meta nfproto ipv4 iifname "ens19" tcp dport 22', rules)
        self.assertIn('oifname "clab-demo" ip daddr 172.31.219.0/24 counter accept', rules)
        self.assertLess(rules.index('ip daddr { 10.0.10.0/24'),
                        rules.index('ct state established,related', rules.index('chain output')))
        self.assertNotIn('8096', rules)  # Phase B is not enabled.
        self.assertNotIn('tcp dport { 80', rules)

    def test_no_shared_interface(self):
        with self.assertRaises(ValueError):
            m.render('eth0', 'eth0', ['10.0.20.1'], ['10.0.20.1'])


if __name__ == '__main__':
    unittest.main()
