#!/usr/bin/env python3
"""VM219-only network guard. Rendering and tests need no privilege/network."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess

FORBIDDEN = ('10.0.10.0/24', '10.0.50.0/24', '10.0.0.0/24')
FLEET = ipaddress.ip_network('172.31.219.0/24')
IDENTITY = Path('/etc/virp-demo/identity.json')


def require_demo_vm():
    if os.geteuid() != 0:
        raise RuntimeError('apply requires root ON VM219')
    st = IDENTITY.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError('demo identity must be root-owned and not writable by others')
    identity = json.loads(IDENTITY.read_text())
    actual_uuid = Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
    if (identity.get('vmid') != 219 or identity.get('hostname') != 'virp-demo'
            or socket.gethostname().split('.')[0] != 'virp-demo'
            or identity.get('dmi_uuid', '').lower() != actual_uuid):
        raise RuntimeError('not the specifically enrolled VM219; refusing')


def interface(value):
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', value):
        raise ValueError('invalid interface name')
    return value


def endpoints(values):
    result = []
    for value in values:
        addr = ipaddress.IPv4Address(value)
        if str(addr) != '10.0.20.1':
            raise ValueError('Phase A permits DNS/NTP only at 10.0.20.1')
        result.append(str(addr))
    if not result:
        raise ValueError('at least one explicit endpoint required')
    return ', '.join(sorted(set(result)))


def render(management, bridge, dns, ntp, witness_ssh=False):
    management, bridge = interface(management), interface(bridge)
    if management == bridge:
        raise ValueError('management and fake-fleet interfaces must differ')
    blocked = ', '.join(FORBIDDEN)
    witness_rule = (f'  oifname "{management}" ip daddr 18.217.153.230 tcp dport 22 counter accept\n' if witness_ssh else '')
    # Own table only. Conntrack has already run by priority -50; replies to
    # admitted SSH are allowed without granting new arbitrary egress.
    return f'''add table inet virp_demo
flush table inet virp_demo
table inet virp_demo {{
 chain input {{
  type filter hook input priority -50; policy drop;
  iifname "lo" accept
  ip saddr {{ {blocked} }} counter drop
  ct state invalid drop
  ct state established,related accept
  iifname "{bridge}" ip saddr {FLEET} accept
  meta nfproto ipv4 iifname "{management}" tcp dport 22 counter accept
 }}
 chain output {{
  type filter hook output priority -50; policy drop;
  oifname "lo" accept
  ip daddr {{ {blocked} }} counter reject
  ct state invalid drop
  ct state established,related accept
  oifname "{management}" ip daddr {{ {endpoints(dns)} }} udp dport 53 counter accept
  oifname "{management}" ip daddr {{ {endpoints(dns)} }} tcp dport 53 counter accept
  oifname "{management}" ip daddr {{ {endpoints(ntp)} }} udp dport 123 counter accept
{witness_rule}  oifname "{bridge}" ip daddr {FLEET} counter accept
 }}
 chain forward {{
  type filter hook forward priority -50; policy drop;
  ip daddr {{ {blocked} }} counter drop
  ip saddr {{ {blocked} }} counter drop
  iifname "{bridge}" oifname "{bridge}" ip saddr {FLEET} ip daddr {FLEET} accept
 }}
}}
'''


def apply(rules, management):
    require_demo_vm()
    addresses = json.loads(subprocess.check_output(['ip', '-j', '-4', 'addr', 'show', 'dev', management]))
    if not any(ipaddress.IPv4Address(a['local']) in ipaddress.ip_network('10.0.20.0/24')
               for dev in addresses for a in dev.get('addr_info', [])):
        raise RuntimeError('management interface lacks a VLAN20 IPv4 address')
    policy = json.loads(subprocess.check_output(['ip', '-j', '-4', 'rule']))
    if any(r.get('table') not in ('local', 'main', 'default', 255, 254, 253) for r in policy):
        raise RuntimeError('unexpected policy routing; review before applying')
    routes = json.loads(subprocess.check_output(['ip', '-j', '-4', 'route']))
    if any(r.get('protocol') == 'dhcp' for r in routes):
        raise RuntimeError('static management addressing is required; DHCP egress is not admitted')
    subprocess.run(['nft', '-c', '-f', '-'], input=rules, text=True, check=True)
    # Install the packet boundary first, so any later route failure remains
    # fail-closed. No default route or upstream device configuration changes.
    subprocess.run(['nft', '-f', '-'], input=rules, text=True, check=True)
    for prefix in FORBIDDEN:
        subprocess.run(['ip', '-4', 'route', 'replace', 'prohibit', prefix], check=True)
    for prefix in FORBIDDEN:
        target = str(next(ipaddress.ip_network(prefix).hosts()))
        r = subprocess.run(['ip', '-4', 'route', 'get', target], capture_output=True)
        if r.returncode == 0:
            raise RuntimeError('forbidden network still has a usable route: ' + prefix)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--management-interface', required=True)
    p.add_argument('--container-bridge', default='clab-demo')
    p.add_argument('--dns', action='append', required=True)
    p.add_argument('--ntp', action='append', required=True)
    p.add_argument('--apply', action='store_true', help='VM219 only; otherwise render to stdout')
    p.add_argument('--demo-witness-ssh', action='store_true', help='Owner-authorized EC2 tcp/22 only')
    a = p.parse_args()
    rules = render(a.management_interface, a.container_bridge, a.dns, a.ntp, a.demo_witness_ssh)
    if a.apply:
        apply(rules, a.management_interface)
    else:
        print(rules, end='')


if __name__ == '__main__':
    main()
