"""Pure bounded port renderer/verifier; inputs must come from verified root-held observations.

This module neither grants approval nor accepts model-provided evidence. Production
activation additionally requires protected-target, neighbor, MAC and VLAN checks.
"""
import hashlib
import json
import re

PORTS = ('Ethernet0/1', 'GigabitEthernet1/0/22')
OPS = {
 'mode_access': ('switchport mode', 'switchport mode access'),
 'vlan_10': ('switchport access vlan', 'switchport access vlan 10'),
 'portfast': ('spanning-tree portfast', 'spanning-tree portfast'),
 'security_enable': ('switchport port-security', 'switchport port-security'),
 'security_maximum_2': ('switchport port-security maximum', 'switchport port-security maximum 2'),
 'security_violation_restrict': ('switchport port-security violation', 'switchport port-security violation restrict'),
}

def config_lines(text, port):
 if port not in PORTS or not isinstance(text,str):raise ValueError('target_or_capture_invalid')
 lines=text.replace('\r\n','\n').splitlines()
 start='interface '+port
 if [x for x in lines if x.startswith('interface ')]!=[start] or not lines or lines[-1]!='end':raise ValueError('incomplete_or_wrong_interface')
 body=lines[lines.index(start)+1:-1]
 if not body or any(not x.startswith(' ') or x.startswith('  ') or '\t' in x for x in body):raise ValueError('ambiguous_configuration')
 if len(set(body))!=len(body) or ' shutdown' not in body or ' no shutdown' in body:raise ValueError('not_shutdown_or_duplicate')
 return sorted(body)

def family(line, prefix):
 s=line.strip()
 if prefix=='switchport port-security':return s==prefix
 return s==prefix or s.startswith(prefix+' ')

def plan(text, port, operation, *, active_vlans=None):
 before=config_lines(text,port)
 if operation not in OPS:raise ValueError('operation_not_supported')
 if operation=='vlan_10' and (active_vlans is None or 10 not in active_vlans):raise ValueError('vlan_not_active')
 if any(x.startswith((' channel-group ', ' switchport mode trunk', ' no switchport')) for x in before):raise ValueError('protected_port_mode')
 prefix,forward=OPS[operation]
 if operation.startswith('security_') and ' switchport mode access' not in before:raise ValueError('security_requires_access')
 old=[x.strip() for x in before if family(x,prefix)]
 if len(old)>1:raise ValueError('ambiguous_prior_setting')
 # Refuse a baseline the same finite native grammar cannot restore.
 if old:
  allowed={'switchport mode':r'switchport mode (access|dynamic auto)',
           'switchport access vlan':r'switchport access vlan ([1-9][0-9]{0,3})',
           'spanning-tree portfast':r'spanning-tree portfast',
           'switchport port-security':r'switchport port-security',
           'switchport port-security maximum':r'switchport port-security maximum ([1-9][0-9]{0,3})',
           'switchport port-security violation':r'switchport port-security violation (restrict|shutdown)'}
  if not re.fullmatch(allowed[prefix],old[0]):raise ValueError('unsupported_restore')
  if prefix=='switchport access vlan' and int(old[0].split()[-1])>4094:raise ValueError('unsupported_restore')
  if prefix=='switchport port-security maximum' and int(old[0].split()[-1])>1024:raise ValueError('unsupported_restore')
 if old==[forward]:raise ValueError('no_change')
 expected=sorted([x for x in before if not family(x,prefix)]+[' '+forward])
 body={'schema':'kestrel-port-plan/1','port':port,'operation':operation,'tier':'RED' if operation.startswith('security_') else 'YELLOW',
       'before':before,'expected':expected,'pre_config_sha256':hashlib.sha256(text.encode()).hexdigest(),
       'forward':'interface '+port+' '+forward,'rollback':'interface '+port+' '+(old[0] if old else 'no '+prefix),
       'save':False}
 body['bundle_sha256']=hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 return body

def verify(p, observed, restore=False):
 try:
  body={k:v for k,v in p.items() if k!='bundle_sha256'}
  if hashlib.sha256(json.dumps(body,sort_keys=True,separators=(',',':')).encode()).hexdigest()!=p['bundle_sha256']:return False
  return config_lines(observed,p['port'])==p['before' if restore else 'expected']
 except (ValueError,KeyError):return False
