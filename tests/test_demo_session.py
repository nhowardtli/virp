"""Demo login correlation uses the real wire encoder and fake UNIX gate."""
import base64
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
                                 ['chain_append', 'execute', 'chain_append', 'chain_append'])
                before = json.loads(gate.requests[0]['artifact_content'])
                after = json.loads(gate.requests[2]['artifact_content'])
                self.assertEqual(before['session_id'], first.demo_session)
                self.assertEqual(before['detail'], dict(req, typed='show ip route'))
                part = json.loads(gate.requests[3]['artifact_content'])
                self.assertEqual(part['event'], 'reply_part')
                self.assertEqual(base64.b64decode(part['detail']['data']), observation(7, 'O 192.0.2.0/24 via 192.0.2.1'))
                self.assertEqual(after['event'], 'reply')
                self.assertEqual(after['detail']['observation_sha256'],
                                 hashlib.sha256(observation(7, 'O 192.0.2.0/24 via 192.0.2.1')).hexdigest())
            finally:
                gate.close()

    def test_large_reply_is_preserved_in_bounded_parts(self):
        raw = observation(7, 'route ' * 2000)
        def answer(req):
            return self.answer(req) if req['action'] == 'chain_append' else raw
        with patch.dict(os.environ, {'VIRP_SHELL_DEMO_SESSION': '1'}):
            gate = FakeGate(answer)
            try:
                sh = vs.VirpShell(sock_path=gate.path, stdout=io.StringIO())
                sh._reply({'action':'execute','device':'frr1','command':'show ip route'})
                records = [json.loads(r['artifact_content']) for r in gate.requests if r['action']=='chain_append']
                parts = [r['detail'] for r in records if r['event']=='reply_part']
                self.assertGreater(len(parts), 1)
                self.assertEqual(b''.join(base64.b64decode(p['data']) for p in parts), raw)
                self.assertEqual([p['index'] for p in parts], list(range(len(parts))))
                self.assertTrue(all(p['count']==len(parts) for p in parts))
                self.assertTrue(all(len(r['artifact_content'].encode()) < 8191 for r in gate.requests if r['action']=='chain_append'))
            finally:
                gate.close()

    def test_demo_reload_is_recorded_and_never_submitted(self):
        with patch.dict(os.environ, {'VIRP_SHELL_DEMO_SESSION':'1'}):
            gate=FakeGate(self.answer)
            try:
                sh=vs.VirpShell(sock_path=gate.path,stdout=io.StringIO())
                with self.assertRaisesRegex(vs.GateError,'reload is refused'):
                    sh._reply({'action':'execute','device':'frr1','command':'reload'})
                self.assertEqual([r['action'] for r in gate.requests],['chain_append','chain_append'])
                reply=json.loads(gate.requests[-1]['artifact_content'])['detail']
                self.assertTrue(reply['demo_refusal'])
                self.assertEqual(reply['reply_kind'],'local_refusal')
                self.assertNotIn('reply_tier',reply)
                self.assertEqual(reply['proposal_ids'],[])
            finally:gate.close()
        with patch.dict(os.environ,{},clear=True), patch.object(vs,'gate',return_value=observation(7,'answer')) as call:
            vs.VirpShell(stdout=io.StringIO())._reply({'action':'execute','device':'frr1','command':'reload'})
            call.assert_called_once()

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

    def test_chain_content_limit_rejects_8191_bytes(self):
        with patch.dict(os.environ, {'VIRP_SHELL_DEMO_SESSION': '1'}):
            sh = vs.VirpShell(stdout=io.StringIO())
            for size in (8191, 8192):
                with self.subTest(size=size), patch.object(vs.json, 'dumps', return_value='x' * size), patch.object(vs, 'gate') as call:
                    with self.assertRaises(vs.GateError):
                        sh._demo_record('request', {})
                    call.assert_not_called()
            with patch.object(vs.json, 'dumps', return_value='x' * 8190), patch.object(vs, 'gate', return_value=observation(1, '{"sequence":0}')) as call:
                sh._demo_record('request', {})
                call.assert_called_once()

    def test_reply_record_refusal_preserves_signed_output_before_warning(self):
        calls = []
        def answer(req):
            calls.append(req['action'])
            if len(calls) == 3:
                return error_frame(-50)
            return self.answer(req)
        with patch.dict(os.environ, {'VIRP_SHELL_DEMO_SESSION': '1'}):
            gate = FakeGate(answer)
            try:
                out = io.StringIO()
                sh = vs.VirpShell(sock_path=gate.path, stdout=out)
                info = sh._reply({'action': 'execute', 'device': 'frr1', 'command': 'show ip route'})
                sh._print_signed(info, [info['text']])
                text = out.getvalue()
                self.assertIn('O 192.0.2.0/24 via 192.0.2.1', text)
                self.assertLess(text.index(vs.trailer()), text.index('% WARNING:'))
                self.assertIn('do not retry automatically', text)
                self.assertEqual(calls, ['chain_append', 'execute', 'chain_append'])
            finally:
                gate.close()

    def test_own_session_verifies_full_acknowledged_range_outside_recent_window(self):
        sequence = -1
        def answer(req):
            nonlocal sequence
            if req['action'] == 'chain_append':
                sequence += 1
                return observation(1, json.dumps({'sequence': sequence}))
            if req['action'] == 'list_sessions':
                return observation(1, '{"sessions":[],"count":0}')
            return observation(1, '{"valid":true,"entries_checked":4}')
        with patch.dict(os.environ, {'VIRP_SHELL_DEMO_SESSION': '1'}):
            gate = FakeGate(answer)
            try:
                sh = vs.VirpShell(sock_path=gate.path, stdout=io.StringIO())
                for _ in range(3):
                    sh._demo_record('request', {})
                sh.cmd_show_chain(['1'])
                checks = [r for r in gate.requests if r['action'] == 'chain_verify']
                self.assertEqual(len(checks), 1)
                self.assertEqual((checks[0]['from_sequence'], checks[0]['to_sequence']), (0, 3))
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
