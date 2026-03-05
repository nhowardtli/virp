/*
 * cisco_route_table_full.c — Comprehensive Cisco IOS/IOS-XE routing table
 *
 * Maps ~180 CLI commands to RESTCONF endpoints (YANG models) or SSH.
 *
 * RESTCONF base: https://{host}:443/restconf/data/
 * YANG modules:
 *   Cisco-IOS-XE-*        — Cisco native models
 *   ietf-interfaces        — Standard interface model
 *   ietf-routing           — Standard routing model
 *   openconfig-*           — OpenConfig models (if enabled)
 *
 * For IOS (non-XE) devices, all commands fall through to SSH.
 * The routing table still classifies trust tiers correctly.
 *
 * Trust tiers:
 *   GREEN  — show commands (read-only state), auto-execute
 *   YELLOW — config reads, debug setup, flag operator
 *   RED    — credential exposure, human approval required
 *   BLACK  — not in table (reload, erase startup-config)
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

const cisco_command_route_t CISCO_ROUTE_TABLE[] = {

    /* ═══════════════════════════════════════════════════════════════
     * GREEN TIER — Read-only operational state, auto-execute
     * ═══════════════════════════════════════════════════════════════ */

    /* ── Interface Status ──────────────────────────────────────── */
    { "show interfaces",
      "ietf-interfaces:interfaces",
      "ietf-interfaces",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip interface brief",
      "Cisco-IOS-XE-native:native/interface",
      "Cisco-IOS-XE-native",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip interface",
      "ietf-interfaces:interfaces",
      "ietf-interfaces",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show interfaces status",
      "Cisco-IOS-XE-interfaces-oper:interfaces/interface",
      "Cisco-IOS-XE-interfaces-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show interfaces description",
      "Cisco-IOS-XE-interfaces-oper:interfaces",
      "Cisco-IOS-XE-interfaces-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show interfaces counters",
      "Cisco-IOS-XE-interfaces-oper:interfaces",
      "Cisco-IOS-XE-interfaces-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show interfaces trunk",
      "Cisco-IOS-XE-interfaces-oper:interfaces",
      "Cisco-IOS-XE-interfaces-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show interfaces switchport",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show etherchannel summary",
      "Cisco-IOS-XE-lag-oper:lag-oper-data",
      "Cisco-IOS-XE-lag-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show etherchannel detail",
      "Cisco-IOS-XE-lag-oper:lag-oper-data",
      "Cisco-IOS-XE-lag-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── IP Routing ────────────────────────────────────────────── */
    { "show ip route",
      "ietf-routing:routing/routing-instance=default/ribs/rib=ipv4-default/routes",
      "ietf-routing",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip route summary",
      "Cisco-IOS-XE-ip-oper:ip-route-oper-data",
      "Cisco-IOS-XE-ip-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip route static",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip route connected",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip route ospf",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip route bgp",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip route eigrp",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ipv6 route",
      "ietf-routing:routing/routing-instance=default/ribs/rib=ipv6-default/routes",
      "ietf-routing",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── BGP ───────────────────────────────────────────────────── */
    { "show ip bgp summary",
      "Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors",
      "Cisco-IOS-XE-bgp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip bgp neighbors",
      "Cisco-IOS-XE-bgp-oper:bgp-state-data/neighbors",
      "Cisco-IOS-XE-bgp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip bgp",
      "Cisco-IOS-XE-bgp-oper:bgp-state-data",
      "Cisco-IOS-XE-bgp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show bgp ipv4 unicast summary",
      "Cisco-IOS-XE-bgp-oper:bgp-state-data/address-families",
      "Cisco-IOS-XE-bgp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show bgp ipv6 unicast summary",
      "Cisco-IOS-XE-bgp-oper:bgp-state-data/address-families",
      "Cisco-IOS-XE-bgp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── OSPF ──────────────────────────────────────────────────── */
    { "show ip ospf",
      "Cisco-IOS-XE-ospf-oper:ospf-oper-data",
      "Cisco-IOS-XE-ospf-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip ospf neighbor",
      "Cisco-IOS-XE-ospf-oper:ospf-oper-data/ospf-state/ospf-instance",
      "Cisco-IOS-XE-ospf-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip ospf interface",
      "Cisco-IOS-XE-ospf-oper:ospf-oper-data",
      "Cisco-IOS-XE-ospf-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip ospf database",
      "Cisco-IOS-XE-ospf-oper:ospf-oper-data",
      "Cisco-IOS-XE-ospf-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip ospf border-routers",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── EIGRP ─────────────────────────────────────────────────── */
    { "show ip eigrp neighbors",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip eigrp topology",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip eigrp interfaces",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── VRRP / HSRP / GLBP ───────────────────────────────────── */
    { "show standby",
      "Cisco-IOS-XE-hsrp-oper:hsrp-oper-data",
      "Cisco-IOS-XE-hsrp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show standby brief",
      "Cisco-IOS-XE-hsrp-oper:hsrp-oper-data",
      "Cisco-IOS-XE-hsrp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show vrrp",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show vrrp brief",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show glbp",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── ARP / MAC Tables ──────────────────────────────────────── */
    { "show arp",
      "Cisco-IOS-XE-arp-oper:arp-data/arp-vrf",
      "Cisco-IOS-XE-arp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip arp",
      "Cisco-IOS-XE-arp-oper:arp-data/arp-vrf",
      "Cisco-IOS-XE-arp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show mac address-table",
      "Cisco-IOS-XE-matm-oper:matm-oper-data/matm-table",
      "Cisco-IOS-XE-matm-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show mac address-table dynamic",
      "Cisco-IOS-XE-matm-oper:matm-oper-data/matm-table",
      "Cisco-IOS-XE-matm-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show mac address-table count",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── VLANs ─────────────────────────────────────────────────── */
    { "show vlan",
      "Cisco-IOS-XE-vlan-oper:vlans/vlan",
      "Cisco-IOS-XE-vlan-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show vlan brief",
      "Cisco-IOS-XE-vlan-oper:vlans/vlan",
      "Cisco-IOS-XE-vlan-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show vlan summary",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Spanning Tree ─────────────────────────────────────────── */
    { "show spanning-tree",
      "Cisco-IOS-XE-spanning-tree-oper:stp-details",
      "Cisco-IOS-XE-spanning-tree-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show spanning-tree summary",
      "Cisco-IOS-XE-spanning-tree-oper:stp-details",
      "Cisco-IOS-XE-spanning-tree-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show spanning-tree root",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show spanning-tree blockedports",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── CDP / LLDP Neighbors ──────────────────────────────────── */
    { "show cdp neighbors",
      "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details",
      "Cisco-IOS-XE-cdp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show cdp neighbors detail",
      "Cisco-IOS-XE-cdp-oper:cdp-neighbor-details",
      "Cisco-IOS-XE-cdp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show lldp neighbors",
      "Cisco-IOS-XE-lldp-oper:lldp-entries",
      "Cisco-IOS-XE-lldp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show lldp neighbors detail",
      "Cisco-IOS-XE-lldp-oper:lldp-entries",
      "Cisco-IOS-XE-lldp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── System / Platform ─────────────────────────────────────── */
    { "show version",
      "Cisco-IOS-XE-native:native/version",
      "Cisco-IOS-XE-native",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show inventory",
      "Cisco-IOS-XE-platform-oper:components/component",
      "Cisco-IOS-XE-platform-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show platform",
      "Cisco-IOS-XE-platform-oper:components",
      "Cisco-IOS-XE-platform-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show processes cpu",
      "Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization",
      "Cisco-IOS-XE-process-cpu-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show processes cpu sorted",
      "Cisco-IOS-XE-process-cpu-oper:cpu-usage",
      "Cisco-IOS-XE-process-cpu-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show processes cpu history",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show processes memory",
      "Cisco-IOS-XE-process-memory-oper:memory-usage-processes",
      "Cisco-IOS-XE-process-memory-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show processes memory sorted",
      "Cisco-IOS-XE-process-memory-oper:memory-usage-processes",
      "Cisco-IOS-XE-process-memory-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show memory statistics",
      "Cisco-IOS-XE-memory-oper:memory-statistics",
      "Cisco-IOS-XE-memory-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show clock",
      "Cisco-IOS-XE-native:native/clock",
      "Cisco-IOS-XE-native",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show uptime",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show reload",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show boot",
      "Cisco-IOS-XE-native:native/boot",
      "Cisco-IOS-XE-native",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show environment",
      "Cisco-IOS-XE-environment-oper:environment-sensors",
      "Cisco-IOS-XE-environment-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show environment power",
      "Cisco-IOS-XE-environment-oper:environment-sensors",
      "Cisco-IOS-XE-environment-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show environment temperature",
      "Cisco-IOS-XE-environment-oper:environment-sensors",
      "Cisco-IOS-XE-environment-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Stacking ──────────────────────────────────────────────── */
    { "show switch",
      "Cisco-IOS-XE-switch-oper:switch-oper-data",
      "Cisco-IOS-XE-switch-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show switch detail",
      "Cisco-IOS-XE-switch-oper:switch-oper-data",
      "Cisco-IOS-XE-switch-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show switch stack-ports",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Power over Ethernet ───────────────────────────────────── */
    { "show power inline",
      "Cisco-IOS-XE-poe-oper:poe-oper-data",
      "Cisco-IOS-XE-poe-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show power inline detail",
      "Cisco-IOS-XE-poe-oper:poe-oper-data",
      "Cisco-IOS-XE-poe-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── DHCP ──────────────────────────────────────────────────── */
    { "show ip dhcp binding",
      "Cisco-IOS-XE-dhcp-oper:dhcp-oper-data",
      "Cisco-IOS-XE-dhcp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip dhcp pool",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip dhcp server statistics",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip dhcp snooping",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip dhcp snooping binding",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── ACLs (runtime hit counts) ─────────────────────────────── */
    { "show access-lists",
      "Cisco-IOS-XE-acl-oper:access-lists",
      "Cisco-IOS-XE-acl-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip access-lists",
      "Cisco-IOS-XE-acl-oper:access-lists",
      "Cisco-IOS-XE-acl-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── NAT ───────────────────────────────────────────────────── */
    { "show ip nat translations",
      "Cisco-IOS-XE-nat-oper:nat-data/ip-nat-translation",
      "Cisco-IOS-XE-nat-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip nat statistics",
      "Cisco-IOS-XE-nat-oper:nat-data/ip-nat-statistics",
      "Cisco-IOS-XE-nat-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── VPN / Crypto ──────────────────────────────────────────── */
    { "show crypto ipsec sa",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show crypto ipsec sa summary",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show crypto isakmp sa",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show crypto session",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show crypto session detail",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── DMVPN / Tunnel ────────────────────────────────────────── */
    { "show dmvpn",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show tunnel interface",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── GRE ───────────────────────────────────────────────────── */
    { "show interfaces tunnel",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── QoS ───────────────────────────────────────────────────── */
    { "show policy-map interface",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show policy-map",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show class-map",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── NTP ───────────────────────────────────────────────────── */
    { "show ntp status",
      "Cisco-IOS-XE-ntp-oper:ntp-oper-data",
      "Cisco-IOS-XE-ntp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ntp associations",
      "Cisco-IOS-XE-ntp-oper:ntp-oper-data",
      "Cisco-IOS-XE-ntp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Logging ───────────────────────────────────────────────── */
    { "show logging",
      "Cisco-IOS-XE-logging-oper:logging",
      "Cisco-IOS-XE-logging-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show logging history",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── IP SLA ────────────────────────────────────────────────── */
    { "show ip sla statistics",
      "Cisco-IOS-XE-ip-sla-oper:ip-sla-stats",
      "Cisco-IOS-XE-ip-sla-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip sla summary",
      "Cisco-IOS-XE-ip-sla-oper:ip-sla-stats",
      "Cisco-IOS-XE-ip-sla-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── NetFlow / Flexible NetFlow ────────────────────────────── */
    { "show flow monitor",
      "Cisco-IOS-XE-flow-monitor-oper:flow-monitors",
      "Cisco-IOS-XE-flow-monitor-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show flow exporter",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show flow record",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── 802.1X / Authentication ───────────────────────────────── */
    { "show authentication sessions",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show dot1x all",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show dot1x interface",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── IP Multicast ──────────────────────────────────────────── */
    { "show ip mroute",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip pim neighbor",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip igmp groups",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip igmp snooping",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── MPLS (if applicable) ──────────────────────────────────── */
    { "show mpls forwarding-table",
      "Cisco-IOS-XE-mpls-fwd-oper:mpls-forwarding-table",
      "Cisco-IOS-XE-mpls-fwd-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show mpls ldp neighbor",
      "Cisco-IOS-XE-mpls-ldp-oper:mpls-ldp-oper-data",
      "Cisco-IOS-XE-mpls-ldp-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show mpls interfaces",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── VRF ───────────────────────────────────────────────────── */
    { "show vrf",
      "Cisco-IOS-XE-native:native/vrf",
      "Cisco-IOS-XE-native",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip vrf",
      "Cisco-IOS-XE-native:native/vrf",
      "Cisco-IOS-XE-native",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show vrf detail",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── TCP/IP / Sockets ──────────────────────────────────────── */
    { "show tcp brief",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip sockets",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip traffic",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── CEF ───────────────────────────────────────────────────── */
    { "show ip cef",
      "Cisco-IOS-XE-cef-oper:cef-oper-data",
      "Cisco-IOS-XE-cef-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip cef summary",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Flash / Filesystem ────────────────────────────────────── */
    { "show flash",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "dir flash",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show file systems",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── License ───────────────────────────────────────────────── */
    { "show license",
      "Cisco-IOS-XE-platform-oper:license",
      "Cisco-IOS-XE-platform-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show license status",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show license usage",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show license summary",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── SNMP ──────────────────────────────────────────────────── */
    { "show snmp",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show snmp engineID",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show snmp group",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Dynamic ARP Inspection ────────────────────────────────── */
    { "show ip arp inspection",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ip arp inspection statistics",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── IP Source Guard ───────────────────────────────────────── */
    { "show ip verify source",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Storm Control ─────────────────────────────────────────── */
    { "show storm-control",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Port Security ─────────────────────────────────────────── */
    { "show port-security",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show port-security address",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── EEM ───────────────────────────────────────────────────── */
    { "show event manager policy",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show event manager history",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    /* ── Wireless (3850 specific) ──────────────────────────────── */
    { "show wireless client summary",
      "Cisco-IOS-XE-wireless-client-oper:client-oper-data",
      "Cisco-IOS-XE-wireless-client-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show wireless ap summary",
      "Cisco-IOS-XE-wireless-ap-oper:ap-oper-data",
      "Cisco-IOS-XE-wireless-ap-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show wireless wlan summary",
      "Cisco-IOS-XE-wireless-wlan-cfg:wlan-cfg-data",
      "Cisco-IOS-XE-wireless-wlan-cfg",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show ap summary",
      "Cisco-IOS-XE-wireless-ap-oper:ap-oper-data",
      "Cisco-IOS-XE-wireless-ap-oper",
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },

    { "show wireless statistics",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_GREEN },


    /* ═══════════════════════════════════════════════════════════════
     * YELLOW TIER — Config reads, advanced diagnostics
     * ═══════════════════════════════════════════════════════════════ */

    /* ── Running Config Sections ───────────────────────────────── */
    { "show running-config interface",
      "Cisco-IOS-XE-native:native/interface",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config router",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config access-list",
      "Cisco-IOS-XE-native:native/ip/access-list",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config vlan",
      "Cisco-IOS-XE-native:native/vlan",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config ntp",
      "Cisco-IOS-XE-native:native/ntp",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config logging",
      "Cisco-IOS-XE-native:native/logging",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config snmp",
      "Cisco-IOS-XE-native:native/snmp-server",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config spanning-tree",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config policy-map",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config class-map",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config dhcp",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config monitor",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    { "show running-config ip sla",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    /* ── Startup Config ────────────────────────────────────────── */
    { "show startup-config",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    /* ── ACL Configuration ─────────────────────────────────────── */
    { "show ip access-lists config",
      "Cisco-IOS-XE-native:native/ip/access-list",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_YELLOW },

    /* ── Route Map ─────────────────────────────────────────────── */
    { "show route-map",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },

    /* ── Prefix List ───────────────────────────────────────────── */
    { "show ip prefix-list",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },

    /* ── IP Protocols ──────────────────────────────────────────── */
    { "show ip protocols",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },

    /* ── Archive / Config Changes ──────────────────────────────── */
    { "show archive",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },

    { "show archive log config",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },

    /* ── Crypto Config ─────────────────────────────────────────── */
    { "show crypto key mypubkey",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },

    /* ── Smart Call Home ───────────────────────────────────────── */
    { "show call-home",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },

    /* ── Track Objects ─────────────────────────────────────────── */
    { "show track",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },

    /* ── IP HTTP Server Status ─────────────────────────────────── */
    { "show ip http server status",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_YELLOW },


    /* ═══════════════════════════════════════════════════════════════
     * RED TIER — Security-sensitive, human approval required
     * ═══════════════════════════════════════════════════════════════ */

    /* ── Full Running Config (contains passwords) ──────────────── */
    { "show running-config",
      "Cisco-IOS-XE-native:native",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_RED },

    /* ── Running Config with line/vty (contains passwords) ─────── */
    { "show running-config line",
      "Cisco-IOS-XE-native:native/line",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_RED },

    /* ── AAA / Authentication Config ───────────────────────────── */
    { "show running-config aaa",
      "Cisco-IOS-XE-native:native/aaa",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_RED },

    { "show aaa servers",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_RED },

    { "show aaa sessions",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_RED },

    /* ── Local User Database ───────────────────────────────────── */
    { "show running-config username",
      "Cisco-IOS-XE-native:native/username",
      "Cisco-IOS-XE-native",
      CISCO_DS_RUNNING, VIRP_TIER_RED },

    /* ── RADIUS / TACACS Config ────────────────────────────────── */
    { "show running-config radius",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_RED },

    { "show running-config tacacs",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_RED },

    { "show radius server-group",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_RED },

    { "show tacacs server-group",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_RED },

    /* ── Crypto Keys (private key exposure) ────────────────────── */
    { "show crypto key",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_RED },

    /* ── SNMP Community Strings ────────────────────────────────── */
    { "show snmp community",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_RED },

    { "show snmp user",
      NULL, NULL,
      CISCO_DS_OPERATIONAL, VIRP_TIER_RED },

    /* ── Enable Secret ─────────────────────────────────────────── */
    { "show running-config enable",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_RED },

    /* ── VPN Pre-Shared Keys ───────────────────────────────────── */
    { "show running-config crypto",
      NULL, NULL,
      CISCO_DS_RUNNING, VIRP_TIER_RED },
};

const size_t CISCO_ROUTE_TABLE_SIZE =
    sizeof(CISCO_ROUTE_TABLE) / sizeof(CISCO_ROUTE_TABLE[0]);


/*
 * ═══════════════════════════════════════════════════════════════════
 * COMMANDS THAT REMAIN SSH-ONLY (not in routing table)
 *
 * These fall to SSH transport at YELLOW tier automatically:
 *
 *   show tech-support              — Massive dump, SSH only
 *   show diagnostic                — Hardware diagnostics
 *   show controllers               — Low-level interface info
 *   debug ip packet                — Live packet debugging
 *   debug ip routing               — Routing process debug
 *   debug spanning-tree            — STP debug
 *   debug crypto ipsec             — VPN debug
 *   test aaa                       — Auth testing
 *   ping                           — ICMP ping
 *   traceroute                     — Traceroute
 *   telnet                         — Telnet test
 *   ssh                            — SSH test from device
 *
 * NEVER auto-execute (handled by approval queue):
 *   reload                         — Reboot
 *   write erase                    — Erase startup-config
 *   erase startup-config           — Same
 *   delete flash:                  — Delete files
 *   squeeze flash:                 — Reclaim space
 *   copy running-config startup    — Save config
 *   configure terminal             — Enter config mode
 *
 * These are not in the routing table because they don't exist
 * as read operations. The VIRP approval queue handles them
 * at a higher level.
 * ═══════════════════════════════════════════════════════════════════
 */
