"""Machine-side port comparison and post-apply observation ordering.

Inputs to compare must be outputs returned by capture_after, keyed by the exact
expected commands in trusted adapter code. Model text is never verification.
This is the initial config/switchport comparator, not complete VLAN/log coverage.
"""
import re
import struct
from port_plan import verify,config_lines
from port_evidence import verified_capture,one_field,preconditions

def capture_after(*,not_before_ns,min_chain_sequence,**bindings):
 result=verified_capture(**bindings)
 timestamp=struct.unpack_from('!Q',bindings['raw'],12)[0]
 receipt=result['receipt']
 if timestamp<not_before_ns:raise ValueError('observation_predates_transaction_action')
 if receipt.get('session_id')!=bindings['chain_session'] or type(receipt.get('sequence'))is not int or receipt['sequence']<=min_chain_sequence:raise ValueError('observation_chain_order_invalid')
 return result

def compare(p,outputs,*,restore=False):
 if set(outputs)!={'config','switchport'} or any(not isinstance(x,str) for x in outputs.values()):return 'unknown'
 try:
  sw=outputs['switchport'];port=p['port'];short={'Ethernet0/1':'Et0/1','GigabitEthernet1/0/22':'Gi1/0/22'}[port]
  name=one_field(sw,'Name');enabled=one_field(sw,'Switchport');mode=one_field(sw,'Administrative Mode');oper=one_field(sw,'Operational Mode');vlan=one_field(sw,'Access Mode VLAN')
  if not re.fullmatch(r'[1-9][0-9]{0,3} \([^\n]+\)',vlan):return 'unknown'
  expected=p['before' if restore else 'expected']
  explicit_vlan=[int(x.split()[-1]) for x in expected if x.startswith(' switchport access vlan ')]
  target_vlan=explicit_vlan[0] if explicit_vlan else 1
  target_mode='static access' if ' switchport mode access' in expected else 'dynamic auto'
  if not verify(p,outputs['config'],restore):return 'mismatch'
  if name not in (port,short) or enabled!='Enabled' or oper!='down' or mode!=target_mode or int(vlan.split()[0])!=target_vlan:return 'mismatch'
  return 'matches'
 except (ValueError,KeyError,TypeError):return 'unknown'


def compare_preflight(body,outputs,*,protected_ports):
 try:
  p=body['plan'];port=body['target']['port']
  if config_lines(outputs['config'],port)!=p['before']:return 'mismatch'
  current=preconditions(outputs,port,p['operation'],protected_ports=protected_ports)
  if any(current[k]!=p[k] for k in ('before','forward','rollback','expected','operation','tier')):return 'mismatch'
  return 'matches'
 except (ValueError,KeyError,TypeError):return 'unknown'
