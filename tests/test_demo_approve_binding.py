"""Real C signer and framed fake gate: mismatches never submit approval."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from test_virp_shell import FakeGate, observation
ROOT=Path(__file__).resolve().parents[1]
TOOL=ROOT/'build/virp-tool'
PID='a'*32
COMMAND='interface eth1 description hello-from-binding'
class Binding(unittest.TestCase):
    def attempt(self, change):
        chash=hashlib.sha256(COMMAND.encode()).digest()
        node=0xde002101
        if change=='hash':chash=b'X'*32
        if change=='node':node=0xde002102
        canon=b'VAP1'+bytes.fromhex(PID)+chash+struct.pack('>QQI',node,1,300)
        challenge={'canonical':canon.hex(),'device':'frr2' if change=='device' else 'frr1','command':COMMAND+'x' if change=='command' else COMMAND,'command_hash':chash.hex(),'tier':'RED'}
        gate=FakeGate(lambda r:observation(1,json.dumps(challenge if r['action']=='approval_challenge' else {})))
        try:
            with tempfile.TemporaryDirectory() as td:
                key=Path(td)/'approval'
                subprocess.run([str(TOOL),'keygen','approval',str(key)],check=True,capture_output=True)
                r=subprocess.run([str(TOOL),'approve',PID,'--socket',gate.path,'--key',str(key)+'.key','--expect-device','frr1','--expect-command',COMMAND,'--expect-node-id','0xde002101'],capture_output=True,text=True)
                actions=[r['action'] for r in gate.requests]
                return r,actions
        finally:gate.close()
    def test_matching_challenge_submits(self):
        r,actions=self.attempt(None)
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(actions,['approval_challenge','approval_submit'])
    def test_mismatches_refuse_before_signing_or_submission(self):
        for field in ('device','command','hash','node'):
            with self.subTest(field=field):
                r,actions=self.attempt(field)
                self.assertNotEqual(r.returncode,0)
                self.assertIn('nothing signed or submitted',r.stderr)
                self.assertEqual(actions,['approval_challenge'])
if __name__=='__main__':unittest.main()
