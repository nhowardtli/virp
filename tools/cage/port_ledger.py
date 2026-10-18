"""Idempotent transaction outbox adapter for the existing native signed chain.

Invoke under Transactions.flush's serialized writer lock. The root-owned state
and chain paths and the external public pin must come from trusted deployment
configuration, never cage input. No chain signature format is introduced here.
"""
import re
import sqlite3
from pathlib import Path
from recovery import Ledger,verify_entry_signature
from port_transaction import canonical

class EventLedger:
 def __init__(self,db,transport,public_key,session,append_transport=None):
  if not isinstance(session,str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}',session):
   raise ValueError('invalid_transaction_chain_session')
  self.session=session
  self.native=Ledger(db,transport,public_key,append_transport)
 def __call__(self,event):
  if (event.get('schema')!='kestrel-port-event/1'
      or not re.fullmatch('[a-f0-9]{32}',str(event.get('event_id','')))
      or not re.fullmatch('[a-f0-9]{32}',str(event.get('transaction_id','')))):
   raise ValueError('invalid_transaction_event')
  raw=canonical(event);aid=event['event_id']
  # Distinguish absent from corrupt. Never catch a failed verification and
  # append a replacement: that could hide an altered or ambiguous prior entry.
  with sqlite3.connect('file:'+str(Path(self.native.db).resolve())+'?mode=ro',uri=True) as db:
   entries=db.execute('SELECT COUNT(*) FROM chain_entries WHERE session_id=? AND artifact_id=?',(self.session,aid)).fetchone()[0]
   artifacts=db.execute('SELECT COUNT(*) FROM artifacts WHERE artifact_id=?',(aid,)).fetchone()[0]
  if entries:
   if entries!=1:raise ValueError('transaction_event_not_unique')
   return self.native.verify(raw,self.session,aid)
  if artifacts:raise ValueError('transaction_orphan_artifact_requires_reconciliation')
  return self.native.append(raw,self.session,aid)

 def proof(self,event):
  """Read an existing verified entry for the independent owner; never append."""
  raw=canonical(event);aid=event['event_id']
  receipt=self.native.verify(raw,self.session,aid)
  with sqlite3.connect('file:'+str(Path(self.native.db).resolve())+'?mode=ro',uri=True) as db:
   db.row_factory=sqlite3.Row
   rows=db.execute('SELECT * FROM chain_entries WHERE session_id=? AND artifact_id=?',(self.session,aid)).fetchall()
  if len(rows)!=1:raise ValueError('transaction_event_not_unique')
  entry=dict(rows[0]);verify_entry_signature(entry,self.native.public_key)
  if entry['chain_entry_hash']!=receipt['chain_entry_hash']:raise ValueError('transaction_entry_changed')
  return entry
