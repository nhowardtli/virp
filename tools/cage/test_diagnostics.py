import unittest,ast
from expand_diagnostics import READS,operations,replace_ops,endpoint,runner
class FixedDiagnostics(unittest.TestCase):
 def test_only_fixed_target_reads(self):
  for name,(device,host,command) in READS.items():
   self.assertTrue(name.startswith('sw_'));self.assertEqual((device,host),('SW-3850','10.0.10.2'))
   self.assertTrue(command.startswith('show interfaces '));self.assertFalse(any(c in command for c in ';|\n\r'))
 def test_unrecognized_endpoint_refused(self):
  with self.assertRaisesRegex(ValueError,'baseline_changed'):endpoint(b'OPS={}\n')
 def test_preserve_existing_operations(self):
  source='OPS={"existing": ("node", "host", "approved fixed command")}\nSENTINEL=42\n'
  old=operations(source)[1];new=replace_ops(source,old|READS)
  self.assertEqual(operations(new)[1]['existing'],old['existing']);self.assertIn('SENTINEL=42',new)
 def test_runner_adds_no_write_operation(self):
  result=runner(b"OPS=['sw_apply_description']\n")
  self.assertEqual(operations(result)[1],['sw_apply_description']+list(READS))
 def test_runner_double_upgrade_refused(self):
  with self.assertRaises(ValueError):runner(runner(b"OPS=[]\n").encode())
 def test_duplicate_registry_refused(self):
  with self.assertRaises(ValueError):operations('OPS={}\nOPS={}\n')
