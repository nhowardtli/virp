"""Validate native VAP1 bytes against an independently approved fixed command.

This parser grants no authority and signs nothing. Expected command, device and
node pin must be derived from the approved plan and protected target registry.
JSON timestamps are deliberately not authority: C's JSON number loses integer
nanosecond precision; the exact integer inside canonical bytes is authoritative.
"""
import hashlib
import struct

def validate(value,*,device,command,node_id,now_ns,tier):
 try:
  if value['device']!=device or value['command']!=command or value['tier']!=tier or value['ttl_seconds']!=300:raise ValueError()
  raw=bytes.fromhex(value['canonical'])
  magic,pid,chash,node,issued,ttl=struct.unpack('!4s16s32sQQI',raw)
  if magic!=b'VAP1' or pid.hex()!=value['proposal_id']:raise ValueError()
  if chash!=hashlib.sha256(command.encode('ascii')).digest():raise ValueError()
  if type(node_id)is not int or not node_id or type(value['device_node_id'])is not int or node!=node_id or node!=value['device_node_id']:raise ValueError()
  if ttl!=300 or not issued<=now_ns<issued+ttl*1000000000:raise ValueError()
 except (KeyError,TypeError,ValueError,struct.error,UnicodeError):
  raise ValueError('native_challenge_binding_invalid') from None
 return raw
