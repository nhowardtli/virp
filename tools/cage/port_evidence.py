"""Strict IOS port prerequisites. Pure parsers do not authenticate observations.

Call verified_capture for every record before passing its output to preconditions.
Unknown output formats fail closed. The initial channel parser deliberately only
supports a device with zero channel groups; a populated production summary needs
its own captured-format qualification before this path can be enabled there.
"""
import re
from helper import decode
from port_plan import PORTS,plan

def commands(port):
 if port not in PORTS:raise ValueError('unsupported_port')
 return {'config':'show running-config interface '+port,
         'switchport':'show interfaces '+port+' switchport',
         'mac':'show mac address-table interface '+port,
         'cdp':'show cdp neighbors '+port+' detail',
         'lldp':'show lldp neighbors '+port+' detail',
         'channel':'show etherchannel summary','vlans':'show vlan brief'}

def verified_capture(raw,*,public_key,session_id,node_id,device_id,command,
                     after_sequence,now_ns,ledger,chain_session,artifact_id):
 result=decode(raw,public_key=public_key,session_id=session_id,node_id=node_id,
               device_id=device_id,command=command,after_sequence=after_sequence,now_ns=now_ns)
 if result['subtype']!=7:raise ValueError('prerequisite_read_not_successful')
 receipt=ledger.verify(raw,chain_session,artifact_id)
 output=result['output'].replace('\r\n','\n')
 lines=output.splitlines()
 if not lines or not re.fullmatch(r'[A-Za-z0-9_.-]+#'+re.escape(command),lines[0]):raise ValueError('missing_or_wrong_command_echo')
 body='\n'.join(lines[1:]).strip('\n')
 if not body or '\x1b' in body or '--More--' in body or re.search(r'(?m)^\s*(?:%|ERROR:)',body):raise ValueError('error_or_incomplete_prerequisite_read')
 return {'output':body,'frame_sha256':result['frame_sha256'],'receipt':receipt}

def compact(text):return [' '.join(x.split()) for x in text.splitlines() if x.strip()]
def one_field(text,label):
 values=re.findall(r'^'+re.escape(label)+r':\s*(.*?)\s*$',text,re.M)
 if len(values)!=1:raise ValueError('missing_or_ambiguous_'+label)
 return values[0]
def vlan_ids(text):
 rows=compact(text)
 if len(rows)<3 or rows[0]!='VLAN Name Status Ports' or not re.fullmatch(r'-+ -+ -+ -+',rows[1]):raise ValueError('vlan_table_incomplete')
 seen=set();active=set()
 for row in rows[2:]:
  m=re.fullmatch(r'([1-9][0-9]{0,3}) (\S+) (active|suspended|act/unsup)(?: (.*))?',row)
  if not m:raise ValueError('unsupported_vlan_row')
  n=int(m[1])
  if n>4094 or n in seen:raise ValueError('duplicate_or_invalid_vlan')
  seen.add(n)
  if m[3]=='active':active.add(n)
 return active

def preconditions(outputs,port,operation,*,protected_ports):
 if port not in PORTS or port in protected_ports:raise ValueError('protected_or_unsupported_port')
 if set(outputs)!=set(commands(port)) or any(not isinstance(v,str) for v in outputs.values()):raise ValueError('incomplete_prerequisite_set')
 for value in outputs.values():
  if re.search(r'(?m)^\s*(?:%|ERROR:)',value) or '\x1b' in value or '--More--' in value:raise ValueError('prerequisite_cli_error')
 sw=outputs['switchport'];short={'Ethernet0/1':'Et0/1','GigabitEthernet1/0/22':'Gi1/0/22'}[port]
 if one_field(sw,'Name') not in (port,short) or one_field(sw,'Switchport')!='Enabled' or one_field(sw,'Operational Mode')!='down':raise ValueError('port_not_isolated_down_switchport')
 mode=one_field(sw,'Administrative Mode')
 if mode!='static access' and not (operation=='mode_access' and mode=='dynamic auto'):raise ValueError('not_access_port')
 vlan=one_field(sw,'Access Mode VLAN')
 if not re.fullmatch(r'[1-9][0-9]{0,3} \([^\n]+\)',vlan) or int(vlan.split()[0])>4094:raise ValueError('invalid_access_vlan')
 mac=compact(outputs['mac'])
 if len(mac)!=4 or mac[0]!='Mac Address Table' or not re.fullmatch('-+',mac[1]) or mac[2]!='Vlan Mac Address Type Ports' or not re.fullmatch('-+ -+ -+ -+',mac[3]):raise ValueError('mac_present_or_unproven_absence')
 if compact(outputs['cdp'])!=['Total cdp entries displayed : 0']:raise ValueError('cdp_neighbor_or_unproven_absence')
 if compact(outputs['lldp'])!=['Total entries displayed: 0']:raise ValueError('lldp_neighbor_or_unproven_absence')
 channel=outputs['channel']
 if one_field(channel,'Number of channel-groups in use')!='0' or one_field(channel,'Number of aggregators')!='0':raise ValueError('channel_summary_requires_qualification')
 if re.search(r'(?m)^\s*\d+\s+Po\d+',channel):raise ValueError('inconsistent_channel_summary')
 active=vlan_ids(outputs['vlans'])
 p=plan(outputs['config'],port,operation,active_vlans=active)
 configured=[x.split()[-1] for x in p['before'] if x.startswith(' switchport access vlan ')]
 if int(vlan.split()[0])!=int(configured[0] if configured else 1):raise ValueError('config_switchport_vlan_disagree')
 if mode=='static access' and ' switchport mode access' not in p['before']:raise ValueError('config_switchport_mode_disagree')
 return p
