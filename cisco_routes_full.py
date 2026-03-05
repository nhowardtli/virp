"""
cisco_routes_full.py — Complete Cisco IOS/IOS-XE fallback routing table

Mirrors cisco_route_table_full.c for Python fallback mode.
~170 routes covering every useful Cisco IOS/IOS-XE command.

RESTCONF paths are included for IOS-XE devices.
For classic IOS devices, all commands fall through to SSH
but still get correct trust tier classification.

Copyright 2026 Third Level IT LLC — Apache 2.0
"""

# (command_prefix, restconf_path, yang_module, tier)
# restconf_path=None means SSH-only (no RESTCONF equivalent)

CISCO_FALLBACK_ROUTES = [

    # ═══════════════════════════════════════════════════════════════
    # GREEN — Read-only operational state, auto-execute
    # ═══════════════════════════════════════════════════════════════

    # Interfaces
    ("show interfaces",                     "ietf-interfaces:interfaces",                                      "ietf-interfaces",                   "green"),
    ("show ip interface brief",             "Cisco-IOS-XE-native:native/interface",                            "Cisco-IOS-XE-native",               "green"),
    ("show ip interface",                   "ietf-interfaces:interfaces",                                      "ietf-interfaces",                   "green"),
    ("show interfaces status",              "Cisco-IOS-XE-interfaces-oper:interfaces/interface",               "Cisco-IOS-XE-interfaces-oper",      "green"),
    ("show interfaces description",         "Cisco-IOS-XE-interfaces-oper:interfaces",                         "Cisco-IOS-XE-interfaces-oper",      "green"),
    ("show interfaces counters",            "Cisco-IOS-XE-interfaces-oper:interfaces",                         "Cisco-IOS-XE-interfaces-oper",      "green"),
    ("show interfaces trunk",              "Cisco-IOS-XE-interfaces-oper:interfaces",                         "Cisco-IOS-XE-interfaces-oper",      "green"),
    ("show interfaces switchport",          None,                                                               None,                                "green"),
    ("show etherchannel summary",           "Cisco-IOS-XE-lag-oper:lag-oper-data",                             "Cisco-IOS-XE-lag-oper",             "green"),
    ("show etherchannel detail",            "Cisco-IOS-XE-lag-oper:lag-oper-data",                             "Cisco-IOS-XE-lag-oper",             "green"),

    # IP Routing
    ("show ip route",                       "ietf-routing:routing/routing-instance=default/ribs/rib=ipv4-default/routes", "ietf-routing",             "green"),
    ("show ip route summary",               "Cisco-IOS-XE-ip-oper:ip-route-oper-data",                        "Cisco-IOS-XE-ip-oper",              "green"),
    ("show ip route static",                None,                                                               None,                                "green"),
    ("show ip route connected",             None,                                                               None,                                "green"),
    ("show ip route ospf",                  None,                                                               None,                                "green"),
    ("show ip route bgp",                   None,                                                               None,                                "green"),
    ("show ip route eigrp",                 None,                                                               None,                                "green"),
    ("show ipv6 route",                     "ietf-routing:routing/routing-instance=default/ribs/rib=ipv6-default/routes", "ietf-routing",             "green"),

    # BGP
    ("show ip bgp summary",                 "Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors",                 "Cisco-IOS-XE-bgp-oper",             "green"),
    ("show ip bgp neighbors",               "Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors",                 "Cisco-IOS-XE-bgp-oper",             "green"),
    ("show ip bgp",                         "Cisco-IOS-XE-bgp-oper:bgp-state-data",                           "Cisco-IOS-XE-bgp-oper",             "green"),
    ("show bgp ipv4 unicast summary",       "Cisco-IOS-XE-bgp-oper:bgp-state-data/address-families",          "Cisco-IOS-XE-bgp-oper",             "green"),
    ("show bgp ipv6 unicast summary",       "Cisco-IOS-XE-bgp-oper:bgp-state-data/address-families",          "Cisco-IOS-XE-bgp-oper",             "green"),

    # OSPF
    ("show ip ospf",                        "Cisco-IOS-XE-ospf-oper:ospf-oper-data",                          "Cisco-IOS-XE-ospf-oper",            "green"),
    ("show ip ospf neighbor",               "Cisco-IOS-XE-ospf-oper:ospf-oper-data/ospf-state/ospf-instance", "Cisco-IOS-XE-ospf-oper",            "green"),
    ("show ip ospf interface",              "Cisco-IOS-XE-ospf-oper:ospf-oper-data",                          "Cisco-IOS-XE-ospf-oper",            "green"),
    ("show ip ospf database",               "Cisco-IOS-XE-ospf-oper:ospf-oper-data",                          "Cisco-IOS-XE-ospf-oper",            "green"),
    ("show ip ospf border-routers",         None,                                                               None,                                "green"),

    # EIGRP
    ("show ip eigrp neighbors",             None,                                                               None,                                "green"),
    ("show ip eigrp topology",              None,                                                               None,                                "green"),
    ("show ip eigrp interfaces",            None,                                                               None,                                "green"),

    # FHRP
    ("show standby",                        "Cisco-IOS-XE-hsrp-oper:hsrp-oper-data",                          "Cisco-IOS-XE-hsrp-oper",            "green"),
    ("show standby brief",                  "Cisco-IOS-XE-hsrp-oper:hsrp-oper-data",                          "Cisco-IOS-XE-hsrp-oper",            "green"),
    ("show vrrp",                           None,                                                               None,                                "green"),
    ("show vrrp brief",                     None,                                                               None,                                "green"),
    ("show glbp",                           None,                                                               None,                                "green"),

    # ARP / MAC
    ("show arp",                            "Cisco-IOS-XE-arp-oper:arp-data/arp-vrf",                          "Cisco-IOS-XE-arp-oper",             "green"),
    ("show ip arp",                         "Cisco-IOS-XE-arp-oper:arp-data/arp-vrf",                          "Cisco-IOS-XE-arp-oper",             "green"),
    ("show mac address-table",              "Cisco-IOS-XE-matm-oper:matm-oper-data/matm-table",               "Cisco-IOS-XE-matm-oper",            "green"),
    ("show mac address-table dynamic",      "Cisco-IOS-XE-matm-oper:matm-oper-data/matm-table",               "Cisco-IOS-XE-matm-oper",            "green"),
    ("show mac address-table count",        None,                                                               None,                                "green"),

    # VLANs
    ("show vlan",                           "Cisco-IOS-XE-vlan-oper:vlans/vlan",                               "Cisco-IOS-XE-vlan-oper",            "green"),
    ("show vlan brief",                     "Cisco-IOS-XE-vlan-oper:vlans/vlan",                               "Cisco-IOS-XE-vlan-oper",            "green"),
    ("show vlan summary",                   None,                                                               None,                                "green"),

    # Spanning Tree
    ("show spanning-tree",                  "Cisco-IOS-XE-spanning-tree-oper:stp-details",                     "Cisco-IOS-XE-spanning-tree-oper",   "green"),
    ("show spanning-tree summary",          "Cisco-IOS-XE-spanning-tree-oper:stp-details",                     "Cisco-IOS-XE-spanning-tree-oper",   "green"),
    ("show spanning-tree root",             None,                                                               None,                                "green"),
    ("show spanning-tree blockedports",     None,                                                               None,                                "green"),

    # CDP / LLDP
    ("show cdp neighbors",                  "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details",                      "Cisco-IOS-XE-cdp-oper",             "green"),
    ("show cdp neighbors detail",           "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details",                      "Cisco-IOS-XE-cdp-oper",             "green"),
    ("show lldp neighbors",                 "Cisco-IOS-XE-lldp-oper:lldp-entries",                             "Cisco-IOS-XE-lldp-oper",            "green"),
    ("show lldp neighbors detail",          "Cisco-IOS-XE-lldp-oper:lldp-entries",                             "Cisco-IOS-XE-lldp-oper",            "green"),

    # System / Platform
    ("show version",                        "Cisco-IOS-XE-native:native/version",                              "Cisco-IOS-XE-native",               "green"),
    ("show inventory",                      "Cisco-IOS-XE-platform-oper:components/component",                 "Cisco-IOS-XE-platform-oper",        "green"),
    ("show platform",                       "Cisco-IOS-XE-platform-oper:components",                           "Cisco-IOS-XE-platform-oper",        "green"),
    ("show processes cpu",                  "Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization",         "Cisco-IOS-XE-process-cpu-oper",     "green"),
    ("show processes cpu sorted",           "Cisco-IOS-XE-process-cpu-oper:cpu-usage",                         "Cisco-IOS-XE-process-cpu-oper",     "green"),
    ("show processes cpu history",          None,                                                               None,                                "green"),
    ("show processes memory",               "Cisco-IOS-XE-process-memory-oper:memory-usage-processes",         "Cisco-IOS-XE-process-memory-oper",  "green"),
    ("show processes memory sorted",        "Cisco-IOS-XE-process-memory-oper:memory-usage-processes",         "Cisco-IOS-XE-process-memory-oper",  "green"),
    ("show memory statistics",              "Cisco-IOS-XE-memory-oper:memory-statistics",                      "Cisco-IOS-XE-memory-oper",          "green"),
    ("show clock",                          "Cisco-IOS-XE-native:native/clock",                                "Cisco-IOS-XE-native",               "green"),
    ("show uptime",                         None,                                                               None,                                "green"),
    ("show reload",                         None,                                                               None,                                "green"),
    ("show boot",                           "Cisco-IOS-XE-native:native/boot",                                 "Cisco-IOS-XE-native",               "green"),
    ("show environment",                    "Cisco-IOS-XE-environment-oper:environment-sensors",                "Cisco-IOS-XE-environment-oper",     "green"),
    ("show environment power",              "Cisco-IOS-XE-environment-oper:environment-sensors",                "Cisco-IOS-XE-environment-oper",     "green"),
    ("show environment temperature",        "Cisco-IOS-XE-environment-oper:environment-sensors",                "Cisco-IOS-XE-environment-oper",     "green"),

    # Stacking
    ("show switch",                         "Cisco-IOS-XE-switch-oper:switch-oper-data",                       "Cisco-IOS-XE-switch-oper",          "green"),
    ("show switch detail",                  "Cisco-IOS-XE-switch-oper:switch-oper-data",                       "Cisco-IOS-XE-switch-oper",          "green"),
    ("show switch stack-ports",             None,                                                               None,                                "green"),

    # PoE
    ("show power inline",                   "Cisco-IOS-XE-poe-oper:poe-oper-data",                            "Cisco-IOS-XE-poe-oper",             "green"),
    ("show power inline detail",            "Cisco-IOS-XE-poe-oper:poe-oper-data",                            "Cisco-IOS-XE-poe-oper",             "green"),

    # DHCP
    ("show ip dhcp binding",                "Cisco-IOS-XE-dhcp-oper:dhcp-oper-data",                          "Cisco-IOS-XE-dhcp-oper",            "green"),
    ("show ip dhcp pool",                   None,                                                               None,                                "green"),
    ("show ip dhcp server statistics",      None,                                                               None,                                "green"),
    ("show ip dhcp snooping",               None,                                                               None,                                "green"),
    ("show ip dhcp snooping binding",       None,                                                               None,                                "green"),

    # ACLs (hit counts)
    ("show access-lists",                   "Cisco-IOS-XE-acl-oper:access-lists",                              "Cisco-IOS-XE-acl-oper",             "green"),
    ("show ip access-lists",                "Cisco-IOS-XE-acl-oper:access-lists",                              "Cisco-IOS-XE-acl-oper",             "green"),

    # NAT
    ("show ip nat translations",            "Cisco-IOS-XE-nat-oper:nat-data/ip-nat-translation",              "Cisco-IOS-XE-nat-oper",             "green"),
    ("show ip nat statistics",              "Cisco-IOS-XE-nat-oper:nat-data/ip-nat-statistics",               "Cisco-IOS-XE-nat-oper",             "green"),

    # VPN / Crypto
    ("show crypto ipsec sa",                None,                                                               None,                                "green"),
    ("show crypto ipsec sa summary",        None,                                                               None,                                "green"),
    ("show crypto isakmp sa",               None,                                                               None,                                "green"),
    ("show crypto session",                 None,                                                               None,                                "green"),
    ("show crypto session detail",          None,                                                               None,                                "green"),

    # DMVPN / Tunnels
    ("show dmvpn",                          None,                                                               None,                                "green"),
    ("show tunnel interface",               None,                                                               None,                                "green"),
    ("show interfaces tunnel",              None,                                                               None,                                "green"),

    # QoS
    ("show policy-map interface",           None,                                                               None,                                "green"),
    ("show policy-map",                     None,                                                               None,                                "green"),
    ("show class-map",                      None,                                                               None,                                "green"),

    # NTP
    ("show ntp status",                     "Cisco-IOS-XE-ntp-oper:ntp-oper-data",                            "Cisco-IOS-XE-ntp-oper",             "green"),
    ("show ntp associations",               "Cisco-IOS-XE-ntp-oper:ntp-oper-data",                            "Cisco-IOS-XE-ntp-oper",             "green"),

    # Logging
    ("show logging",                        "Cisco-IOS-XE-logging-oper:logging",                               "Cisco-IOS-XE-logging-oper",         "green"),
    ("show logging history",                None,                                                               None,                                "green"),

    # IP SLA
    ("show ip sla statistics",              "Cisco-IOS-XE-ip-sla-oper:ip-sla-stats",                          "Cisco-IOS-XE-ip-sla-oper",          "green"),
    ("show ip sla summary",                 "Cisco-IOS-XE-ip-sla-oper:ip-sla-stats",                          "Cisco-IOS-XE-ip-sla-oper",          "green"),

    # NetFlow
    ("show flow monitor",                   "Cisco-IOS-XE-flow-monitor-oper:flow-monitors",                   "Cisco-IOS-XE-flow-monitor-oper",    "green"),
    ("show flow exporter",                  None,                                                               None,                                "green"),
    ("show flow record",                    None,                                                               None,                                "green"),

    # 802.1X
    ("show authentication sessions",        None,                                                               None,                                "green"),
    ("show dot1x all",                      None,                                                               None,                                "green"),
    ("show dot1x interface",                None,                                                               None,                                "green"),

    # Multicast
    ("show ip mroute",                      None,                                                               None,                                "green"),
    ("show ip pim neighbor",                None,                                                               None,                                "green"),
    ("show ip igmp groups",                 None,                                                               None,                                "green"),
    ("show ip igmp snooping",               None,                                                               None,                                "green"),

    # MPLS
    ("show mpls forwarding-table",          "Cisco-IOS-XE-mpls-fwd-oper:mpls-forwarding-table",               "Cisco-IOS-XE-mpls-fwd-oper",        "green"),
    ("show mpls ldp neighbor",              "Cisco-IOS-XE-mpls-ldp-oper:mpls-ldp-oper-data",                  "Cisco-IOS-XE-mpls-ldp-oper",        "green"),
    ("show mpls interfaces",                None,                                                               None,                                "green"),

    # VRF
    ("show vrf",                            "Cisco-IOS-XE-native:native/vrf",                                  "Cisco-IOS-XE-native",               "green"),
    ("show ip vrf",                         "Cisco-IOS-XE-native:native/vrf",                                  "Cisco-IOS-XE-native",               "green"),
    ("show vrf detail",                     None,                                                               None,                                "green"),

    # TCP/IP
    ("show tcp brief",                      None,                                                               None,                                "green"),
    ("show ip sockets",                     None,                                                               None,                                "green"),
    ("show ip traffic",                     None,                                                               None,                                "green"),

    # CEF
    ("show ip cef",                         "Cisco-IOS-XE-cef-oper:cef-oper-data",                            "Cisco-IOS-XE-cef-oper",             "green"),
    ("show ip cef summary",                 None,                                                               None,                                "green"),

    # Flash / Filesystem
    ("show flash",                          None,                                                               None,                                "green"),
    ("dir flash",                           None,                                                               None,                                "green"),
    ("show file systems",                   None,                                                               None,                                "green"),

    # License
    ("show license",                        "Cisco-IOS-XE-platform-oper:license",                              "Cisco-IOS-XE-platform-oper",        "green"),
    ("show license status",                 None,                                                               None,                                "green"),
    ("show license usage",                  None,                                                               None,                                "green"),
    ("show license summary",                None,                                                               None,                                "green"),

    # SNMP (operational)
    ("show snmp",                           None,                                                               None,                                "green"),
    ("show snmp engineID",                  None,                                                               None,                                "green"),
    ("show snmp group",                     None,                                                               None,                                "green"),

    # Security Features
    ("show ip arp inspection",              None,                                                               None,                                "green"),
    ("show ip arp inspection statistics",   None,                                                               None,                                "green"),
    ("show ip verify source",               None,                                                               None,                                "green"),
    ("show storm-control",                  None,                                                               None,                                "green"),
    ("show port-security",                  None,                                                               None,                                "green"),
    ("show port-security address",          None,                                                               None,                                "green"),

    # EEM
    ("show event manager policy",           None,                                                               None,                                "green"),
    ("show event manager history",          None,                                                               None,                                "green"),

    # Wireless (3850)
    ("show wireless client summary",        "Cisco-IOS-XE-wireless-client-oper:client-oper-data",              "Cisco-IOS-XE-wireless-client-oper", "green"),
    ("show wireless ap summary",            "Cisco-IOS-XE-wireless-ap-oper:ap-oper-data",                      "Cisco-IOS-XE-wireless-ap-oper",     "green"),
    ("show wireless wlan summary",          "Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-data",                    "Cisco-IOS-XE-wireless-wlan-cfg",    "green"),
    ("show ap summary",                     "Cisco-IOS-XE-wireless-ap-oper:ap-oper-data",                      "Cisco-IOS-XE-wireless-ap-oper",     "green"),
    ("show wireless statistics",            None,                                                               None,                                "green"),


    # ═══════════════════════════════════════════════════════════════
    # YELLOW — Config reads, advanced diagnostics
    # ═══════════════════════════════════════════════════════════════

    # Running Config Sections
    ("show running-config interface",       "Cisco-IOS-XE-native:native/interface",                            "Cisco-IOS-XE-native",               "yellow"),
    ("show running-config router",          None,                                                               None,                                "yellow"),
    ("show running-config access-list",     "Cisco-IOS-XE-native:native/ip/access-list",                      "Cisco-IOS-XE-native",               "yellow"),
    ("show running-config vlan",            "Cisco-IOS-XE-native:native/vlan",                                 "Cisco-IOS-XE-native",               "yellow"),
    ("show running-config ntp",             "Cisco-IOS-XE-native:native/ntp",                                  "Cisco-IOS-XE-native",               "yellow"),
    ("show running-config logging",         "Cisco-IOS-XE-native:native/logging",                              "Cisco-IOS-XE-native",               "yellow"),
    ("show running-config snmp",            "Cisco-IOS-XE-native:native/snmp-server",                          "Cisco-IOS-XE-native",               "yellow"),
    ("show running-config spanning-tree",   None,                                                               None,                                "yellow"),
    ("show running-config policy-map",      None,                                                               None,                                "yellow"),
    ("show running-config class-map",       None,                                                               None,                                "yellow"),
    ("show running-config dhcp",            None,                                                               None,                                "yellow"),
    ("show running-config monitor",         None,                                                               None,                                "yellow"),
    ("show running-config ip sla",          None,                                                               None,                                "yellow"),

    # Startup Config
    ("show startup-config",                 None,                                                               None,                                "yellow"),

    # ACL Config
    ("show ip access-lists config",         "Cisco-IOS-XE-native:native/ip/access-list",                      "Cisco-IOS-XE-native",               "yellow"),

    # Route Map / Prefix List
    ("show route-map",                      None,                                                               None,                                "yellow"),
    ("show ip prefix-list",                 None,                                                               None,                                "yellow"),
    ("show ip protocols",                   None,                                                               None,                                "yellow"),

    # Archive
    ("show archive",                        None,                                                               None,                                "yellow"),
    ("show archive log config",             None,                                                               None,                                "yellow"),

    # Crypto (public keys only)
    ("show crypto key mypubkey",            None,                                                               None,                                "yellow"),

    # Smart Call Home
    ("show call-home",                      None,                                                               None,                                "yellow"),

    # Track Objects
    ("show track",                          None,                                                               None,                                "yellow"),

    # HTTP Server Status
    ("show ip http server status",          None,                                                               None,                                "yellow"),


    # ═══════════════════════════════════════════════════════════════
    # RED — Security-sensitive, human approval required
    # ═══════════════════════════════════════════════════════════════

    ("show running-config",                 "Cisco-IOS-XE-native:native",                                      "Cisco-IOS-XE-native",               "red"),
    ("show running-config line",            "Cisco-IOS-XE-native:native/line",                                 "Cisco-IOS-XE-native",               "red"),
    ("show running-config aaa",             "Cisco-IOS-XE-native:native/aaa",                                  "Cisco-IOS-XE-native",               "red"),
    ("show aaa servers",                    None,                                                               None,                                "red"),
    ("show aaa sessions",                   None,                                                               None,                                "red"),
    ("show running-config username",        "Cisco-IOS-XE-native:native/username",                             "Cisco-IOS-XE-native",               "red"),
    ("show running-config radius",          None,                                                               None,                                "red"),
    ("show running-config tacacs",          None,                                                               None,                                "red"),
    ("show radius server-group",            None,                                                               None,                                "red"),
    ("show tacacs server-group",            None,                                                               None,                                "red"),
    ("show crypto key",                     None,                                                               None,                                "red"),
    ("show snmp community",                 None,                                                               None,                                "red"),
    ("show snmp user",                      None,                                                               None,                                "red"),
    ("show running-config enable",          None,                                                               None,                                "red"),
    ("show running-config crypto",          None,                                                               None,                                "red"),
]
