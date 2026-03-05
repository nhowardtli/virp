/*
 * fg_route_table_full.c — Comprehensive FortiGate command routing table
 *
 * This replaces the FG_ROUTE_TABLE[] array in driver_fortigate.c
 * Maps ~120 CLI-style commands to FortiGate REST API endpoints.
 *
 * Organization:
 *   GREEN  — Read-only runtime monitoring, auto-execute
 *   YELLOW — Config reads, advanced diagnostics, flag operator
 *   RED    — Security-sensitive reads, human approval required
 *   BLACK  — Not in table (structurally impossible)
 *
 * Commands not in this table → SSH transport, YELLOW tier.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

const fg_command_route_t FG_ROUTE_TABLE[] = {

    /* ═══════════════════════════════════════════════════════════════
     * GREEN TIER — Read-only monitoring, auto-execute
     *
     * Everything you'd check during a normal shift.
     * No config exposure, no security risk, just operational state.
     * ═══════════════════════════════════════════════════════════════ */

    /* ── Firewall Sessions ─────────────────────────────────────── */
    { "show firewall session",
      "firewall/session", "count=100",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get firewall session",
      "firewall/session", "count=100",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show firewall session top",
      "firewall/session/top", "count=20&sort_by=bytes",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Firewall Policies (runtime state) ─────────────────────── */
    { "show firewall policy",
      "firewall/policy", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get firewall policy",
      "firewall/policy", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show firewall consolidated-policy",
      "firewall/consolidated-policy", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show firewall policy hit-count",
      "firewall/policy", "counters=true",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Interfaces ────────────────────────────────────────────── */
    { "show system interface",
      "system/interface", "include_vlan=true&include_aggregate=true",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system interface",
      "system/interface", "include_vlan=true&include_aggregate=true",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show system available-interfaces",
      "system/available-interfaces", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show interface bandwidth",
      "system/interface", "include_vlan=true",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Routing ───────────────────────────────────────────────── */
    { "show ip route",
      "router/ipv4", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get router info routing-table",
      "router/ipv4", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show ipv6 route",
      "router/ipv6", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get router info6 routing-table",
      "router/ipv6", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show router bgp summary",
      "router/bgp/summary", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get router info bgp summary",
      "router/bgp/summary", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show router bgp neighbors",
      "router/bgp/neighbors", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show router bgp paths",
      "router/bgp/paths", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show router ospf neighbor",
      "router/ospf/neighbors", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show router ospf interface",
      "router/ospf/interfaces", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show router policy",
      "router/policy", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── VPN ───────────────────────────────────────────────────── */
    { "show vpn ipsec",
      "vpn/ipsec", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get vpn ipsec tunnel summary",
      "vpn/ipsec", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show vpn ipsec tunnel details",
      "vpn/ipsec", "tunnel=all",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show vpn ssl",
      "vpn/ssl", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show vpn ssl stats",
      "vpn/ssl/stats", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get vpn ssl monitor",
      "vpn/ssl", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── System Status / Health ────────────────────────────────── */
    { "get system status",
      "system/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system performance status",
      "system/resource/usage", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show system resource",
      "system/resource/usage", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show system performance",
      "system/performance/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system performance top",
      "system/performance/top", "count=20",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── High Availability ─────────────────────────────────────── */
    { "show system ha",
      "system/ha-peer", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system ha status",
      "system/ha-peer", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show ha statistics",
      "system/ha-statistics", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show ha checksums",
      "system/ha-checksums", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── ARP / Neighbor Table ──────────────────────────────────── */
    { "get system arp",
      "system/proxy-arp", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show arp table",
      "system/proxy-arp", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── DHCP ──────────────────────────────────────────────────── */
    { "show dhcp lease",
      "system/dhcp", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system dhcp status",
      "system/dhcp", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── SD-WAN ────────────────────────────────────────────────── */
    { "show sdwan health",
      "virtual-wan/health-check", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get virtual-wan health-check",
      "virtual-wan/health-check", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show sdwan members",
      "virtual-wan/members", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get virtual-wan members",
      "virtual-wan/members", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show sdwan interface log",
      "virtual-wan/interface-log", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show sdwan status",
      "virtual-wan/sla-log", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Link Monitor ──────────────────────────────────────────── */
    { "show link-monitor",
      "system/link-monitor", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system link-monitor",
      "system/link-monitor", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Firmware / License ────────────────────────────────────── */
    { "get system firmware",
      "system/firmware", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show system firmware",
      "system/firmware", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system license",
      "license/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show license status",
      "license/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show fortiguard status",
      "system/fortiguard/server-info", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Network Discovery / Neighbors ─────────────────────────── */
    { "show lldp neighbor",
      "network/lldp/neighbors", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get network lldp",
      "network/lldp/neighbors", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Connected Users / Devices ─────────────────────────────── */
    { "show user detected-device",
      "user/detected-device", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get user detected-device",
      "user/detected-device", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show user auth-list",
      "user/firewall", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get user firewall",
      "user/firewall", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── FortiToken ────────────────────────────────────────────── */
    { "show user fortitoken",
      "user/fortitoken", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── WiFi ──────────────────────────────────────────────────── */
    { "show wifi client",
      "wifi/client", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get wifi client",
      "wifi/client", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show wifi managed-ap",
      "wifi/managed_ap", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show wifi rogue-ap",
      "wifi/rogue_ap", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Switch Controller ─────────────────────────────────────── */
    { "show switch-controller managed-switch",
      "switch-controller/managed-switch", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get switch-controller managed-switch",
      "switch-controller/managed-switch", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Endpoint Control ──────────────────────────────────────── */
    { "show endpoint-control ems",
      "endpoint-control/ems/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get endpoint-control summary",
      "endpoint-control/summary", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Security Fabric ───────────────────────────────────────── */
    { "show security-fabric",
      "system/csf", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system csf",
      "system/csf", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── SDN Connector ─────────────────────────────────────────── */
    { "show sdn-connector",
      "system/sdn-connector/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── FortiManager Integration ──────────────────────────────── */
    { "show fortimanager status",
      "system/fortimanager/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── FortiAnalyzer Integration ─────────────────────────────── */
    { "show fortianalyzer status",
      "log/fortianalyzer/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Logging / Alerts ──────────────────────────────────────── */
    { "show log event",
      "log/event", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show log traffic",
      "log/traffic/forward", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show log threat",
      "log/threat", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show log anomaly",
      "log/anomaly", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show log dns",
      "log/dns", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show log virus",
      "log/virus", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show log webfilter",
      "log/webfilter", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show log ips",
      "log/ips", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "show log app-ctrl",
      "log/app-ctrl", "rows=50",
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── NTP / DNS Status ──────────────────────────────────────── */
    { "show ntp status",
      "system/ntp/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system ntp",
      "system/ntp/status", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Currently Logged In Admins ────────────────────────────── */
    { "show current-admins",
      "system/current-admins/select", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    { "get system current-admins",
      "system/current-admins/select", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Certificates (monitoring) ─────────────────────────────── */
    { "show certificate status",
      "system/certificate/download", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Config Revision History ───────────────────────────────── */
    { "show config revision",
      "system/config-revision", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Automation Stitch Status ──────────────────────────────── */
    { "show automation-stitch status",
      "system/automation-stitch/stats", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Botnet Detection ──────────────────────────────────────── */
    { "show botnet status",
      "system/botnet", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── FQDN Address Resolution ───────────────────────────────── */
    { "show firewall fqdn",
      "firewall/address-fqdns", NULL,
      FG_API_MONITOR, VIRP_TIER_GREEN },


    /* ═══════════════════════════════════════════════════════════════
     * YELLOW TIER — Config reads, advanced diagnostics
     *
     * Object definitions, security profiles, non-sensitive config.
     * Operator gets flagged but execution proceeds.
     * ═══════════════════════════════════════════════════════════════ */

    /* ── Address Objects / Groups ──────────────────────────────── */
    { "show firewall address",
      "firewall/address", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show firewall addrgrp",
      "firewall/addrgrp", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show firewall address6",
      "firewall/address6", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show firewall addrgrp6",
      "firewall/addrgrp6", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Service Objects / Groups ──────────────────────────────── */
    { "show firewall service custom",
      "firewall.service/custom", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show firewall service group",
      "firewall.service/group", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── NAT / VIP ─────────────────────────────────────────────── */
    { "show firewall vip",
      "firewall/vip", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show firewall ippool",
      "firewall/ippool", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Traffic Shaping ───────────────────────────────────────── */
    { "show firewall shaper",
      "firewall.shaper/traffic-shaper", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show firewall shaper per-ip",
      "firewall.shaper/per-ip-shaper", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show firewall shaping-policy",
      "firewall/shaping-policy", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Security Profiles ─────────────────────────────────────── */
    { "show webfilter profile",
      "webfilter/profile", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show antivirus profile",
      "antivirus/profile", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show ips sensor",
      "ips/sensor", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show application list",
      "application/list", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show dlp sensor",
      "dlp/sensor", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show emailfilter profile",
      "emailfilter/profile", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show ssl-ssh profile",
      "firewall/ssl-ssh-profile", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── VPN Configuration ─────────────────────────────────────── */
    { "show vpn ipsec phase1",
      "vpn.ipsec/phase1-interface", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show vpn ipsec phase2",
      "vpn.ipsec/phase2-interface", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show vpn ssl settings",
      "vpn.ssl/settings", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Routing Configuration ─────────────────────────────────── */
    { "show router static",
      "router/static", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show router bgp config",
      "router/bgp", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show router ospf config",
      "router/ospf", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show router policy config",
      "router/policy", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── SD-WAN Configuration ──────────────────────────────────── */
    { "show sdwan service",
      "system.sdwan/service", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show sdwan zone",
      "system.sdwan/zone", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show sdwan health-check config",
      "system.sdwan/health-check", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── User / Auth Configuration ─────────────────────────────── */
    { "show user group",
      "user/group", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show user local",
      "user/local", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show authentication policy",
      "authentication/rule", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Proxy Policies ────────────────────────────────────────── */
    { "show firewall proxy-policy",
      "firewall/proxy-policy", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── System Configuration (non-sensitive) ──────────────────── */
    { "show system global",
      "system/global", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show system settings",
      "system/settings", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show system dns config",
      "system/dns", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show system ntp config",
      "system/ntp", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show system zone",
      "system/zone", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show system interface config",
      "system/interface", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show system vdom",
      "system/vdom", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Log Settings ──────────────────────────────────────────── */
    { "show log setting",
      "log/setting", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── SNMP Configuration ────────────────────────────────────── */
    { "show system snmp community",
      "system.snmp/community", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show system snmp sysinfo",
      "system.snmp/sysinfo", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── HA Configuration ──────────────────────────────────────── */
    { "show system ha config",
      "system/ha", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Automation ────────────────────────────────────────────── */
    { "show automation-trigger",
      "system/automation-trigger", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show automation-action",
      "system/automation-action", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show automation-stitch config",
      "system/automation-stitch", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── External Resources ────────────────────────────────────── */
    { "show external-resource",
      "system/external-resource", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Internet Service Database ─────────────────────────────── */
    { "show firewall internet-service",
      "firewall/internet-service-name", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Certificate Config ────────────────────────────────────── */
    { "show certificate local",
      "certificate/local", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show certificate ca",
      "certificate/ca", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    { "show certificate remote",
      "certificate/remote", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Admin Access Profiles ─────────────────────────────────── */
    { "show system accprofile",
      "system/accprofile", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Replacement Messages ──────────────────────────────────── */
    { "show system replacemsg",
      "system/replacemsg-group", NULL,
      FG_API_CMDB, VIRP_TIER_YELLOW },


    /* ═══════════════════════════════════════════════════════════════
     * RED TIER — Security-sensitive reads, human approval required
     *
     * Credential exposure, auth configs, admin access.
     * These NEVER execute without operator sign-off.
     * ═══════════════════════════════════════════════════════════════ */

    /* ── Admin Users ───────────────────────────────────────────── */
    { "show system admin",
      "system/admin", NULL,
      FG_API_CMDB, VIRP_TIER_RED },

    /* ── API Keys / Tokens ─────────────────────────────────────── */
    { "show system api-user",
      "system/api-user", NULL,
      FG_API_CMDB, VIRP_TIER_RED },

    /* ── RADIUS Server Config (contains shared secrets) ────────── */
    { "show user radius",
      "user/radius", NULL,
      FG_API_CMDB, VIRP_TIER_RED },

    /* ── LDAP Server Config (contains bind credentials) ────────── */
    { "show user ldap",
      "user/ldap", NULL,
      FG_API_CMDB, VIRP_TIER_RED },

    /* ── TACACS+ Config ────────────────────────────────────────── */
    { "show user tacacs",
      "user/tacacs+", NULL,
      FG_API_CMDB, VIRP_TIER_RED },

    /* ── SAML Config ───────────────────────────────────────────── */
    { "show user saml",
      "user/saml", NULL,
      FG_API_CMDB, VIRP_TIER_RED },

    /* ── Full System Backup ────────────────────────────────────── */
    { "show full-configuration",
      "system/config", NULL,
      FG_API_MONITOR, VIRP_TIER_RED },

    { "get system config backup",
      "system/config/backup", "scope=global",
      FG_API_MONITOR, VIRP_TIER_RED },
};

const size_t FG_ROUTE_TABLE_SIZE =
    sizeof(FG_ROUTE_TABLE) / sizeof(FG_ROUTE_TABLE[0]);


/*
 * ═══════════════════════════════════════════════════════════════════
 * COMMANDS THAT REMAIN SSH-ONLY (not in routing table)
 *
 * These have no REST API equivalent and will automatically
 * fall through to SSH transport at YELLOW tier:
 *
 *   diagnose debug flow          — Packet flow tracing
 *   diagnose debug enable        — Debug output toggle
 *   diagnose debug disable       — Debug output toggle
 *   diagnose sniffer packet      — Packet capture
 *   diagnose sys top             — Process list (like top)
 *   diagnose sys session         — Session diagnostics
 *   diagnose ip address list     — IP address diagnostics
 *   diagnose hardware deviceinfo — Hardware details
 *   diagnose autoupdate status   — FortiGuard update status
 *   diagnose firewall iprope     — IP property lookups
 *   execute ping                 — ICMP ping
 *   execute traceroute           — Traceroute
 *   execute telnet               — Telnet test
 *   execute ssh                  — SSH test
 *   execute backup               — Config backup to USB/TFTP
 *   execute restore              — Config restore from backup
 *   execute reboot               — Reboot (NEVER auto-execute)
 *   execute shutdown             — Shutdown (NEVER auto-execute)
 *   execute factoryreset         — Factory reset (NEVER expose)
 *   fnsysctl ls                  — Hidden Linux shell
 *   fnsysctl cat                 — Hidden Linux shell
 *   fnsysctl ifconfig            — Hidden Linux shell
 *
 * The SSH fallback at YELLOW tier is intentional.
 * Dangerous execute commands (reboot, shutdown, factoryreset)
 * should be handled by the VIRP approval queue at a higher
 * level, not by the routing table.
 * ═══════════════════════════════════════════════════════════════════ */
