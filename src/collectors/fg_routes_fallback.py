"""
fg_routes_full.py — Complete FortiGate fallback routing table

This replaces the _FALLBACK_ROUTES list in virp_bridge.py.
Must stay in sync with fg_route_table_full.c.

~120 routes covering every useful FortiGate REST API endpoint.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

# (command_prefix, api_endpoint, api_params, tier)

FALLBACK_ROUTES = [

    # ═══════════════════════════════════════════════════════════════
    # GREEN — Read-only monitoring, auto-execute
    # ═══════════════════════════════════════════════════════════════

    # Firewall Sessions
    ("show firewall session",              "firewall/session",                  "count=100",                             "green"),
    ("get firewall session",               "firewall/session",                  "count=100",                             "green"),
    ("show firewall session top",          "firewall/session/top",              "count=20&sort_by=bytes",                "green"),

    # Firewall Policies (runtime)
    ("show firewall policy",               "firewall/policy",                   None,                                    "green"),
    ("get firewall policy",                "firewall/policy",                   None,                                    "green"),
    ("show firewall consolidated-policy",  "firewall/consolidated-policy",      None,                                    "green"),
    ("show firewall policy hit-count",     "firewall/policy",                   "counters=true",                         "green"),

    # Interfaces
    ("show system interface",              "system/interface",                  "include_vlan=true&include_aggregate=true", "green"),
    ("get system interface",               "system/interface",                  "include_vlan=true&include_aggregate=true", "green"),
    ("show system available-interfaces",   "system/available-interfaces",       None,                                    "green"),
    ("show interface bandwidth",           "system/interface",                  "include_vlan=true",                     "green"),

    # Routing
    ("show ip route",                      "router/ipv4",                       None,                                    "green"),
    ("get router info routing-table",      "router/ipv4",                       None,                                    "green"),
    ("show ipv6 route",                    "router/ipv6",                       None,                                    "green"),
    ("get router info6 routing-table",     "router/ipv6",                       None,                                    "green"),
    ("show router bgp summary",            "router/bgp/summary",               None,                                    "green"),
    ("get router info bgp summary",        "router/bgp/summary",               None,                                    "green"),
    ("show router bgp neighbors",          "router/bgp/neighbors",             None,                                    "green"),
    ("show router bgp paths",             "router/bgp/paths",                  None,                                    "green"),
    ("show router ospf neighbor",          "router/ospf/neighbors",            None,                                    "green"),
    ("show router ospf interface",         "router/ospf/interfaces",           None,                                    "green"),
    ("show router policy",                 "router/policy",                     None,                                    "green"),

    # VPN
    ("show vpn ipsec",                     "vpn/ipsec",                         None,                                    "green"),
    ("get vpn ipsec tunnel summary",       "vpn/ipsec",                         None,                                    "green"),
    ("show vpn ipsec tunnel details",      "vpn/ipsec",                         "tunnel=all",                            "green"),
    ("show vpn ssl",                       "vpn/ssl",                           None,                                    "green"),
    ("show vpn ssl stats",                 "vpn/ssl/stats",                     None,                                    "green"),
    ("get vpn ssl monitor",                "vpn/ssl",                           None,                                    "green"),

    # System Status / Health
    ("get system status",                  "system/status",                     None,                                    "green"),
    ("get system performance status",      "system/resource/usage",             None,                                    "green"),
    ("show system resource",               "system/resource/usage",             None,                                    "green"),
    ("show system performance",            "system/performance/status",         None,                                    "green"),
    ("get system performance top",         "system/performance/top",            "count=20",                              "green"),

    # High Availability
    ("show system ha",                     "system/ha-peer",                    None,                                    "green"),
    ("get system ha status",               "system/ha-peer",                    None,                                    "green"),
    ("show ha statistics",                 "system/ha-statistics",              None,                                    "green"),
    ("show ha checksums",                  "system/ha-checksums",              None,                                    "green"),

    # ARP
    ("get system arp",                     "system/proxy-arp",                  None,                                    "green"),
    ("show arp table",                     "system/proxy-arp",                  None,                                    "green"),

    # DHCP
    ("show dhcp lease",                    "system/dhcp",                       None,                                    "green"),
    ("get system dhcp status",             "system/dhcp",                       None,                                    "green"),

    # SD-WAN
    ("show sdwan health",                  "virtual-wan/health-check",          None,                                    "green"),
    ("get virtual-wan health-check",       "virtual-wan/health-check",          None,                                    "green"),
    ("show sdwan members",                 "virtual-wan/members",               None,                                    "green"),
    ("get virtual-wan members",            "virtual-wan/members",               None,                                    "green"),
    ("show sdwan interface log",           "virtual-wan/interface-log",         None,                                    "green"),
    ("show sdwan status",                  "virtual-wan/sla-log",              None,                                    "green"),

    # Link Monitor
    ("show link-monitor",                  "system/link-monitor",               None,                                    "green"),
    ("get system link-monitor",            "system/link-monitor",               None,                                    "green"),

    # Firmware / License
    ("get system firmware",                "system/firmware",                   None,                                    "green"),
    ("show system firmware",               "system/firmware",                   None,                                    "green"),
    ("get system license",                 "license/status",                    None,                                    "green"),
    ("show license status",                "license/status",                    None,                                    "green"),
    ("show fortiguard status",             "system/fortiguard/server-info",     None,                                    "green"),

    # LLDP Neighbors
    ("show lldp neighbor",                 "network/lldp/neighbors",            None,                                    "green"),
    ("get network lldp",                   "network/lldp/neighbors",            None,                                    "green"),

    # Connected Users / Devices
    ("show user detected-device",          "user/detected-device",              None,                                    "green"),
    ("get user detected-device",           "user/detected-device",              None,                                    "green"),
    ("show user auth-list",                "user/firewall",                     None,                                    "green"),
    ("get user firewall",                  "user/firewall",                     None,                                    "green"),

    # FortiToken
    ("show user fortitoken",               "user/fortitoken",                   None,                                    "green"),

    # WiFi
    ("show wifi client",                   "wifi/client",                       None,                                    "green"),
    ("get wifi client",                    "wifi/client",                       None,                                    "green"),
    ("show wifi managed-ap",               "wifi/managed_ap",                   None,                                    "green"),
    ("show wifi rogue-ap",                 "wifi/rogue_ap",                     None,                                    "green"),

    # Switch Controller
    ("show switch-controller managed-switch", "switch-controller/managed-switch", None,                                  "green"),
    ("get switch-controller managed-switch",  "switch-controller/managed-switch", None,                                  "green"),

    # Endpoint Control
    ("show endpoint-control ems",          "endpoint-control/ems/status",       None,                                    "green"),
    ("get endpoint-control summary",       "endpoint-control/summary",          None,                                    "green"),

    # Security Fabric
    ("show security-fabric",               "system/csf",                        None,                                    "green"),
    ("get system csf",                     "system/csf",                        None,                                    "green"),

    # SDN Connector
    ("show sdn-connector",                 "system/sdn-connector/status",       None,                                    "green"),

    # FortiManager / FortiAnalyzer
    ("show fortimanager status",           "system/fortimanager/status",        None,                                    "green"),
    ("show fortianalyzer status",          "log/fortianalyzer/status",          None,                                    "green"),

    # Logs
    ("show log event",                     "log/event",                         "rows=50",                               "green"),
    ("show log traffic",                   "log/traffic/forward",               "rows=50",                               "green"),
    ("show log threat",                    "log/threat",                        "rows=50",                               "green"),
    ("show log anomaly",                   "log/anomaly",                       "rows=50",                               "green"),
    ("show log dns",                       "log/dns",                           "rows=50",                               "green"),
    ("show log virus",                     "log/virus",                         "rows=50",                               "green"),
    ("show log webfilter",                 "log/webfilter",                     "rows=50",                               "green"),
    ("show log ips",                       "log/ips",                           "rows=50",                               "green"),
    ("show log app-ctrl",                  "log/app-ctrl",                      "rows=50",                               "green"),

    # NTP / DNS Status
    ("show ntp status",                    "system/ntp/status",                 None,                                    "green"),
    ("get system ntp",                     "system/ntp/status",                 None,                                    "green"),

    # Current Admins
    ("show current-admins",                "system/current-admins/select",      None,                                    "green"),
    ("get system current-admins",          "system/current-admins/select",      None,                                    "green"),

    # Certificates (monitoring)
    ("show certificate status",            "system/certificate/download",       None,                                    "green"),

    # Config Revision
    ("show config revision",               "system/config-revision",            None,                                    "green"),

    # Automation
    ("show automation-stitch status",      "system/automation-stitch/stats",    None,                                    "green"),

    # Botnet
    ("show botnet status",                 "system/botnet",                     None,                                    "green"),

    # FQDN
    ("show firewall fqdn",                "firewall/address-fqdns",            None,                                    "green"),


    # ═══════════════════════════════════════════════════════════════
    # YELLOW — Config reads, advanced diagnostics
    # ═══════════════════════════════════════════════════════════════

    # Address Objects / Groups
    ("show firewall address",              "firewall/address",                  None,                                    "yellow"),
    ("show firewall addrgrp",              "firewall/addrgrp",                  None,                                    "yellow"),
    ("show firewall address6",             "firewall/address6",                 None,                                    "yellow"),
    ("show firewall addrgrp6",             "firewall/addrgrp6",                None,                                    "yellow"),

    # Service Objects / Groups
    ("show firewall service custom",       "firewall.service/custom",           None,                                    "yellow"),
    ("show firewall service group",        "firewall.service/group",            None,                                    "yellow"),

    # NAT / VIP
    ("show firewall vip",                  "firewall/vip",                      None,                                    "yellow"),
    ("show firewall ippool",               "firewall/ippool",                   None,                                    "yellow"),

    # Traffic Shaping
    ("show firewall shaper",               "firewall.shaper/traffic-shaper",    None,                                    "yellow"),
    ("show firewall shaper per-ip",        "firewall.shaper/per-ip-shaper",    None,                                    "yellow"),
    ("show firewall shaping-policy",       "firewall/shaping-policy",           None,                                    "yellow"),

    # Security Profiles
    ("show webfilter profile",             "webfilter/profile",                 None,                                    "yellow"),
    ("show antivirus profile",             "antivirus/profile",                 None,                                    "yellow"),
    ("show ips sensor",                    "ips/sensor",                        None,                                    "yellow"),
    ("show application list",              "application/list",                  None,                                    "yellow"),
    ("show dlp sensor",                    "dlp/sensor",                        None,                                    "yellow"),
    ("show emailfilter profile",           "emailfilter/profile",               None,                                    "yellow"),
    ("show ssl-ssh profile",               "firewall/ssl-ssh-profile",          None,                                    "yellow"),

    # VPN Config
    ("show vpn ipsec phase1",              "vpn.ipsec/phase1-interface",        None,                                    "yellow"),
    ("show vpn ipsec phase2",              "vpn.ipsec/phase2-interface",        None,                                    "yellow"),
    ("show vpn ssl settings",              "vpn.ssl/settings",                  None,                                    "yellow"),

    # Routing Config
    ("show router static",                 "router/static",                     None,                                    "yellow"),
    ("show router bgp config",             "router/bgp",                       None,                                    "yellow"),
    ("show router ospf config",            "router/ospf",                      None,                                    "yellow"),
    ("show router policy config",          "router/policy",                    None,                                    "yellow"),

    # SD-WAN Config
    ("show sdwan service",                 "system.sdwan/service",              None,                                    "yellow"),
    ("show sdwan zone",                    "system.sdwan/zone",                 None,                                    "yellow"),
    ("show sdwan health-check config",     "system.sdwan/health-check",         None,                                    "yellow"),

    # User / Auth Config
    ("show user group",                    "user/group",                        None,                                    "yellow"),
    ("show user local",                    "user/local",                        None,                                    "yellow"),
    ("show authentication policy",         "authentication/rule",               None,                                    "yellow"),

    # Proxy Policies
    ("show firewall proxy-policy",         "firewall/proxy-policy",             None,                                    "yellow"),

    # System Config (non-sensitive)
    ("show system global",                 "system/global",                     None,                                    "yellow"),
    ("show system settings",               "system/settings",                   None,                                    "yellow"),
    ("show system dns config",             "system/dns",                        None,                                    "yellow"),
    ("show system ntp config",             "system/ntp",                        None,                                    "yellow"),
    ("show system zone",                   "system/zone",                       None,                                    "yellow"),
    ("show system interface config",       "system/interface",                  None,                                    "yellow"),
    ("show system vdom",                   "system/vdom",                       None,                                    "yellow"),

    # Log Settings
    ("show log setting",                   "log/setting",                       None,                                    "yellow"),

    # SNMP
    ("show system snmp community",         "system.snmp/community",             None,                                    "yellow"),
    ("show system snmp sysinfo",           "system.snmp/sysinfo",              None,                                    "yellow"),

    # HA Config
    ("show system ha config",              "system/ha",                         None,                                    "yellow"),

    # Automation Config
    ("show automation-trigger",            "system/automation-trigger",          None,                                    "yellow"),
    ("show automation-action",             "system/automation-action",           None,                                    "yellow"),
    ("show automation-stitch config",      "system/automation-stitch",           None,                                    "yellow"),

    # External Resources
    ("show external-resource",             "system/external-resource",           None,                                    "yellow"),

    # Internet Service DB
    ("show firewall internet-service",     "firewall/internet-service-name",    None,                                    "yellow"),

    # Certificates Config
    ("show certificate local",             "certificate/local",                 None,                                    "yellow"),
    ("show certificate ca",                "certificate/ca",                    None,                                    "yellow"),
    ("show certificate remote",            "certificate/remote",                None,                                    "yellow"),

    # Admin Profiles
    ("show system accprofile",             "system/accprofile",                 None,                                    "yellow"),

    # Replacement Messages
    ("show system replacemsg",             "system/replacemsg-group",           None,                                    "yellow"),


    # ═══════════════════════════════════════════════════════════════
    # RED — Security-sensitive, human approval required
    # ═══════════════════════════════════════════════════════════════

    ("show system admin",                  "system/admin",                      None,                                    "red"),
    ("show system api-user",               "system/api-user",                   None,                                    "red"),
    ("show user radius",                   "user/radius",                       None,                                    "red"),
    ("show user ldap",                     "user/ldap",                         None,                                    "red"),
    ("show user tacacs",                   "user/tacacs+",                      None,                                    "red"),
    ("show user saml",                     "user/saml",                         None,                                    "red"),
    ("show full-configuration",            "system/config",                     None,                                    "red"),
    ("get system config backup",           "system/config/backup",              "scope=global",                          "red"),
]
