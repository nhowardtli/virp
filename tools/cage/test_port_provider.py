import io,json,unittest,urllib.error
from port_provider import ResponsesProvider,ProviderRefused,NoRedirect,ENDPOINT

class Response(io.BytesIO):
 status=200
 def geturl(self):return ENDPOINT

class ProviderTests(unittest.TestCase):
 def setUp(self):self.requests=[]
 def open(self,request,timeout):
  self.requests.append((request,timeout));return Response(b'{"status":"completed","output":[]}')
 def test_strict_finite_payload_and_preserved_model(self):
  provider=ResponsesProvider('gpt-4.1-mini-2025-04-14','unit-test-key',open_request=self.open)
  provider([{'role':'user','content':'qualify canary'}],('port_preflight',))
  request,timeout=self.requests[0];body=json.loads(request.data)
  self.assertEqual(request.full_url,ENDPOINT);self.assertEqual(timeout,45)
  self.assertEqual(body['model'],'gpt-4.1-mini-2025-04-14');self.assertFalse(body['store']);self.assertFalse(body['parallel_tool_calls'])
  tool=body['tools'][0];self.assertTrue(tool['strict']);self.assertEqual(tool['parameters']['properties']['operation']['enum'],['port_preflight'])
  self.assertFalse(tool['parameters']['additionalProperties']);self.assertEqual(set(tool['parameters']['required']),{'operation','rationale'})
  self.assertNotIn(b'unit-test-key',request.data)
 def test_astra_low_reasoning(self):
  ResponsesProvider('gpt-6-astra','unit-test-key',open_request=self.open)([],('port_preflight',))
  self.assertEqual(json.loads(self.requests[0][0].data)['reasoning'],{'effort':'low'})
 def test_unknown_operation_refuses_before_network(self):
  provider=ResponsesProvider('model','unit-test-key',open_request=self.open)
  with self.assertRaises(ProviderRefused):provider([],('reload',))
  self.assertEqual(self.requests,[])
 def test_redirects_never_forward_auth(self):
  with self.assertRaises(ProviderRefused):NoRedirect().redirect_request(None,None,302,'moved',{},'https://example.invalid')
 def test_http_error_body_not_exposed_or_retried(self):
  calls=[]
  def fail(request,timeout):
   calls.append(request);raise urllib.error.HTTPError(ENDPOINT,429,'private detail',{},io.BytesIO(b'private body'))
  with self.assertRaisesRegex(ProviderRefused,'provider_http_429'):ResponsesProvider('model','unit-test-key',open_request=fail)([],('port_apply',))
  self.assertEqual(len(calls),1)
 def test_oversized_and_duplicate_key_replies_refuse(self):
  for raw in (b'x'*131073,b'{"output":[],"output":[]}'):
   with self.assertRaises(ProviderRefused):ResponsesProvider('model','unit-test-key',open_request=lambda req,timeout:Response(raw))([],('port_apply',))
 def test_guard_runs_before_request(self):
  def guard():raise ProviderRefused('profile_changed')
  with self.assertRaisesRegex(ProviderRefused,'profile_changed'):ResponsesProvider('model','unit-test-key',open_request=self.open,guard=guard)([],('port_apply',))
  self.assertEqual(self.requests,[])

if __name__=='__main__':unittest.main()
