"""Demo login correlation uses the real wire encoder and fake UNIX gate."""
import hashlib
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
from test_virp_shell import FakeGate, observation, error_frame, vs


class DemoSession(unittest.TestCase):
    def answer(self, req):
        if req['action'] == 'chain_append':
            body = req['artifact_content'].encode()
            self.assertEqual(hashlib.sha256(body).hexdigest(), req['artifact_hash'])
            self.assertEqual(req['artifact_type'], 'evidence_item')
            return observation(1, '{"sequence":1}')
        return observation(7, 'O 192.0.2.0/24 via 192.0.2.1')

    def test_distinct_sessions_record_before_and_after_execute(self):
        with patch.dict(os.environ, {'VIRP_SHELL_DEMO_SESSION': '1'}):
            gate = FakeGate(self.answer)
            try:
                first = vs.VirpShell(sock_path=gate.path, stdout=io.StringIO())
                second = vs.VirpShell(sock_path=gate.path, stdout=io.StringIO())
                self.assertNotEqual(first.demo_session, second.demo_session)
                req = {'action': 'execute', 'device': 'frr1', 'command': 'show ip route'}
                first._reply(req)
                self.assertEqual([r['action'] for r in gate.requests],
                                 ['chain_append', 'execute', 'chain_append'])
                before = json.loads(gate.requests[0]['artifact_content'])
                after = json.loads(gate.requests[2]['artifact_content'])
                self.assertEqual(before['session_id'], first.demo_session)
                self.assertEqual(before['detail'], req)
                self.assertEqual(after['event'], 'reply')
                self.assertEqual(after['detail']['observation_sha256'],
                                 hashlib.sha256(observation(7, 'O 192.0.2.0/24 via 192.0.2.1')).hexdigest())
            finally:
                gate.close()

    def test_refused_record_prevents_device_request(self):
        with patch.dict(os.environ, {'VIRP_SHELL_DEMO_SESSION': '1'}):
            gate = FakeGate(lambda req: error_frame(-50))
            try:
                sh = vs.VirpShell(sock_path=gate.path, stdout=io.StringIO())
                with self.assertRaises(vs.GateError):
                    sh._reply({'action': 'execute', 'device': 'frr1', 'command': 'show ip route'})
                self.assertEqual([r['action'] for r in gate.requests], ['chain_append'])
            finally:
                gate.close()

    def test_production_does_not_gain_append(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(vs.VirpShell(stdout=io.StringIO()).demo_session)
            with self.assertRaises(vs.GateError):
                vs.gate({'action': 'chain_append'}, '/nonexistent')

    def test_demo_policy_matches_shell_without_approval_actions(self):
        p = json.loads((Path(__file__).resolve().parents[1] / 'deploy/devices.demo.template.json').read_text())
        self.assertEqual(set(p['socket_uid_action_allow']['988']),
                         set(vs.COMMAND_ACTIONS.values()) | {'chain_append'})
        self.assertEqual(p['socket_uid_chain_append_types']['988'], ['evidence_item'])
        self.assertEqual(p['socket_uid_tier_ceilings']['988'], 'green')
        self.assertEqual(p['gate_max_tier'], 'yellow')
        self.assertNotIn(1500, p['socket_allowed_uids'])
        self.assertEqual(len(p['devices']), 6)


if __name__ == '__main__':
    unittest.main()
