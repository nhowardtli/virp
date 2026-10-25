import hashlib,struct,unittest
from port_challenge import validate
class Challenges(unittest.TestCase):
 def setUp(self):
  self.now=1000000000000;self.command='interface Ethernet0/1 switchport mode access';self.node=0xc0a8ff0a
  self.q={'device':'kestrel-ios','command':self.command,'proposal_id':'12'*16,'device_node_id':self.node,'tier':'RED','ttl_seconds':300}
  self.q['canonical']=struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(self.q['proposal_id']),hashlib.sha256(self.command.encode()).digest(),self.node,self.now,300).hex()
 def check(self,q=None,**kw):
  args=dict(device='kestrel-ios',command=self.command,node_id=self.node,now_ns=self.now,tier='RED');args.update(kw);return validate(q or self.q,**args)
 def test_exact_command_device_and_freshness(self):self.assertEqual(self.check(),bytes.fromhex(self.q['canonical']))
 def test_json_scope_mismatch(self):
  for k,v in [('device','SW-3850'),('command',self.command+' extra'),('proposal_id','ab'*16),('device_node_id',1),('tier','YELLOW'),('ttl_seconds',600)]:
   with self.subTest(k=k),self.assertRaises(ValueError):self.check({**self.q,k:v})
 def test_canonical_fields_mismatch(self):
  for pos in [0,5,22,55,60,71]:
   b=bytearray.fromhex(self.q['canonical']);b[pos]^=1
   with self.subTest(pos=pos),self.assertRaises(ValueError):self.check({**self.q,'canonical':b.hex()})
 def test_expired_future_and_wrong_pin(self):
  for args in [dict(now_ns=self.now+300000000000),dict(now_ns=self.now-1),dict(node_id=1)]:
   with self.assertRaises(ValueError):self.check(**args)
 def test_invalid_lengths_and_types(self):
  for value in ['',123,'z'*152,self.q['canonical']+'00']:
   with self.assertRaises(ValueError):self.check({**self.q,'canonical':value})
if __name__=='__main__':unittest.main()
