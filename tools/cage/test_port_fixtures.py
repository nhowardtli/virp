"""Synthetic proposal references for unit tests; never live approval evidence."""
import hashlib
import uuid

def proposal_inventory():
 def ref():
  pid=uuid.uuid4().hex
  return {'proposal_id':pid,'artifact_hash':hashlib.sha256(('artifact:'+pid).encode()).hexdigest(),
          'chain_entry_hash':hashlib.sha256(('entry:'+pid).encode()).hexdigest()}
 return {'forward':ref(),'restore':ref(),'preflight':ref(),'verify':[ref() for _ in range(8)]}
