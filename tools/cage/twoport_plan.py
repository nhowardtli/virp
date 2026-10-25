"""Owner's two-port production qualification grammar, not a general executor."""
import re
PORTS=('GigabitEthernet1/0/22','GigabitEthernet1/0/23')
GLOBALS=('show vlan brief','show etherchannel summary','show interfaces trunk','show interfaces status','show clock')
LINES=('switchport mode access','switchport mode trunk','switchport nonegotiate','no switchport nonegotiate','spanning-tree portfast','no spanning-tree portfast','spanning-tree bpduguard enable','no spanning-tree bpduguard enable','switchport port-security','no switchport port-security','switchport port-security violation restrict','no switchport port-security violation','speed auto','duplex auto','shutdown','no shutdown','no description','no switchport access vlan','no switchport trunk allowed vlan','no switchport mode','no switchport port-security maximum')
def plan(command):
 if not isinstance(command,str) or not 1<=len(command)<=300 or any(ord(c)<32 or ord(c)>126 for c in command):raise ValueError('invalid_twoport_command')
 if command in GLOBALS:return [command]
 for port in PORTS:
  reads=(f'show interfaces {port}',f'show interfaces {port} switchport',f'show interfaces {port} counters errors',f'show running-config interface {port}',f'show mac address-table interface {port}',f'show cdp neighbors {port} detail',f'show lldp neighbors {port} detail',f'show spanning-tree interface {port} detail',f'show port-security interface {port}')
  if command in reads:return [command]
  prefix='interface '+port+' '
  if not command.startswith(prefix):continue
  line=command[len(prefix):];valid=line in LINES or bool(re.fullmatch(r'description KESTREL-[A-Za-z0-9_-]{1,80}',line)) or bool(re.fullmatch(r'switchport port-security maximum [1-4]',line))
  for kw in ('switchport access vlan ','switchport trunk allowed vlan '):
   if line.startswith(kw):
    vals=line[len(kw):].split(',')
    valid=(1<=len(vals)<=8 and all(re.fullmatch('[1-9][0-9]{0,3}',v) and int(v)<=4094 for v in vals) and (len(vals)==1 or kw.endswith('allowed vlan ')))
  if valid:return ['configure terminal','interface '+port,line,'end']
 raise ValueError('outside_twoport_scope')
