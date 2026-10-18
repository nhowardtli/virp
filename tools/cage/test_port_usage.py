import unittest
from port_model import summarize_usage

class UsageTests(unittest.TestCase):
 def test_counts_details_without_double_counting(self):
  u=summarize_usage([{'model':'gpt-6-astra','usage':{'input_tokens':100,'output_tokens':30,'total_tokens':130,'input_tokens_details':{'cached_tokens':40},'output_tokens_details':{'reasoning_tokens':20}}}]*2)
  self.assertEqual((u['input_tokens'],u['output_tokens'],u['total_tokens'],u['cached_input_tokens'],u['reasoning_output_tokens']),(200,60,260,80,40))
  self.assertTrue(u['complete']);self.assertEqual(u['models'],['gpt-6-astra'])
 def test_missing_usage_is_not_zero_cost(self):
  u=summarize_usage([{}]);self.assertFalse(u['complete']);self.assertEqual(u['missing_or_invalid_responses'],1)
 def test_malformed_counts_are_untrusted(self):
  for usage in ({'input_tokens':True,'output_tokens':2,'total_tokens':3},{'input_tokens':-1,'output_tokens':2,'total_tokens':1},{'input_tokens':1,'output_tokens':2,'total_tokens':4}):
   self.assertFalse(summarize_usage([{'usage':usage}])['complete'])
 def test_detail_absence_explicit(self):
  u=summarize_usage([{'usage':{'input_tokens':1,'output_tokens':2,'total_tokens':3}}]);self.assertTrue(u['complete']);self.assertFalse(u['details_complete'])
if __name__=='__main__':unittest.main()
