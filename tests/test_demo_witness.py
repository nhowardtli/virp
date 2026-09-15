#!/usr/bin/env python3
"""No network: demo egress restriction and registry refusal latch."""
import importlib.util
import importlib.machinery
from pathlib import Path
import sqlite3
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec=importlib.util.spec_from_file_location(name,path,loader=importlib.machinery.SourceFileLoader(name,str(path)))
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
network=load('demo_network',ROOT/'deploy/demo/network.py')
shim=load('demo_submit',ROOT/'deploy/demo/virp-witness-submit')

class DemoWitness(unittest.TestCase):
    def test_only_authorized_egress_is_added(self):
        args=('eth0','br-demo',['10.0.20.1'],['10.0.20.1'])
        before=network.render(*args)
        after=network.render(*args,witness_ssh=True)
        rule='  oifname "eth0" ip daddr 18.217.153.230 tcp dport 22 counter accept\n'
        self.assertEqual(after.replace(rule,''),before)
        self.assertEqual(after.count(rule),1)

    def test_existing_registry_latch_prevents_database_and_network(self):
        with patch.object(shim.os.path,'exists',return_value=True), patch.object(shim.sqlite3,'connect') as connect, patch.object(shim.subprocess,'run') as run:
            self.assertEqual(shim.main(),1)
            connect.assert_not_called()
            run.assert_not_called()

    def test_403_latches_and_stops_after_one_submission(self):
        with tempfile.TemporaryDirectory() as d:
            db=Path(d)/'chain.db'
            c=sqlite3.connect(db)
            c.execute('CREATE TABLE chain_heads(session_id,last_sequence,last_entry_hash,head_sig_key_id,head_sig,updated_at_ns)')
            for i in range(2):
                c.execute('INSERT INTO chain_heads VALUES(?,?,?,?,?,?)',('demo-'+str(i)*32,0,'a'*64,'0572220fff65745d5f4685431ad063f5','b'*128,i))
            c.commit();c.close()
            failure=subprocess.CompletedProcess([],1,'','HTTP403 registry refused')
            with patch.object(shim,'CHAIN_DB',str(db)), patch.object(shim,'HEADS',d), patch.object(shim,'receipt_gap',return_value='no receipt'), patch.object(shim,'write_head') as write, patch.object(shim.subprocess,'run',return_value=failure) as run:
                self.assertEqual(shim.main(),1)
                self.assertEqual(run.call_count,1)
                self.assertEqual(write.call_args_list[-1].args[0],'/var/lib/virp/witness/STOP-403')

if __name__=='__main__':
    unittest.main()
