/*
 * driver_fortigate.c — FortiGate device driver implementation
 *
 * Ported to VIRP appliance type system (fixed buffers, virp_driver.h).
 * Original from tli-ops-center/virp/src/driver_fortigate.c.
 *
 * Implements the five virp_driver_t functions:
 *   connect     — Establish REST API + optional SSH connections
 *   execute     — Route command to REST or SSH, return output
 *   disconnect  — Tear down both transports
 *   detect      — Probe device to confirm it's a FortiGate
 *   health_check — Verify device is responsive and healthy
 *
 * Key design decisions:
 *   - REST API is primary transport. Structured JSON > CLI parsing.
 *   - SSH is fallback for diagnose/execute commands only.
 *   - Command routing table maps CLI-style strings to API endpoints.
 *   - Commands not in routing table default to SSH + YELLOW tier.
 *   - 429 rate limiting is handled with exponential backoff.
 *   - VDOM scoping is per-connection (default: root).
 *   - API token auth via Bearer header (not query param).
 *
 * Dependencies:
 *   - libcurl (REST API calls)
 *   - libssh2 (SSH fallback)
 *   - libssl  (TLS, already a VIRP dependency)
 *
 * Build:  make CISCO=1 FORTIGATE=1
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <curl/curl.h>
#include <libssh2.h>

#include "virp_driver.h"
#include "virp_driver_fortigate.h"


/* ══════════════════════════════════════════════════════════════════
 * CONNECTION STATE
 *
 * Appliance pattern: each driver defines its own 'struct virp_conn'.
 * The O-Node sees only an opaque pointer.
 * ══════════════════════════════════════════════════════════════════ */

struct virp_conn {
    virp_device_t       device;         /* Copy of device config */

    /* REST API transport */
    CURL               *curl_handle;
    char               *api_token;
    char               *base_url;       /* https://host:port */
    int                 api_port;
    bool                verify_tls;
    char               *vdom;

    /* SSH transport */
    LIBSSH2_SESSION    *ssh_session;
    int                 ssh_socket;
    int                 ssh_port;

    /* State */
    fg_transport_t      preferred;
    bool                rest_connected;
    bool                ssh_connected;
};


/* ══════════════════════════════════════════════════════════════════
 * COMMAND ROUTING TABLE
 *
 * Maps CLI-style commands to FortiGate REST API endpoints.
 * Prefix match: "show firewall session list" matches
 * "show firewall session" in the table.
 *
 * Trust tiers follow VIRP convention:
 *   GREEN  — read-only monitoring, auto-execute
 *   YELLOW — advanced diagnostics, flag operator
 *   RED    — configuration reads, human approval
 *   BLACK  — structurally impossible (not in table)
 *
 * Commands not in this table → SSH transport, YELLOW tier.
 * ══════════════════════════════════════════════════════════════════ */
const fg_command_route_t FG_ROUTE_TABLE[] = {

    /* ═══════════════════════════════════════════════════════════════
     * GREEN TIER — Read-only runtime monitoring
     * ═══════════════════════════════════════════════════════════════ */

    /* ── System health & identity ──────────────────────────────── */
    { "get system status",           "system/status",             NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show system status",          "system/status",             NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system performance",      "system/resource/usage",     NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show system resource",        "system/resource/usage",     NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system time",             "system/time",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show system time",            "system/time",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system firmware",         "system/firmware",            NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show system firmware",        "system/firmware",            NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system ntp status",       "system/ntp/status",         NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show system ntp status",      "system/ntp/status",         NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "diagnose sys ntp status",     "system/ntp/status",         NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system fortiguard",       "system/fortiguard/server-info", NULL,         FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show system fortiguard",      "system/fortiguard/server-info", NULL,         FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Interfaces & network ──────────────────────────────────── */
    { "show system interface",       "system/interface",          "include_vlan=true", FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system interface",        "system/interface",          "include_vlan=true", FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show system available-interface", "system/available-interfaces", "select",    FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system arp",              "network/arp",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show arp",                    "network/arp",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system dns",              "network/dns/latency",       NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show network lldp",           "network/lldp/neighbors",    NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get network lldp",            "network/lldp/neighbors",    NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Routing ───────────────────────────────────────────────── */
    { "show ip route",               "router/ipv4",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get router info routing-table", "router/ipv4",             NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show ipv6 route",             "router/ipv6",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get router info6 routing-table", "router/ipv6",            NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get router info kernel",      "router/statistics",         NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show router statistics",      "router/statistics",         NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Firewall runtime state ────────────────────────────────── */
    /* BUG FIX: was "firewall/policy" — corrected to "firewall/session" */
    { "show firewall session",       "firewall/session",          "count=100",      FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get firewall session",        "firewall/session",          "count=100",      FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show firewall policy",        "firewall/policy",           NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get firewall policy",         "firewall/policy",           NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show firewall security-policy", "firewall/security-policy", NULL,            FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show firewall multicast-policy", "firewall/multicast-policy", NULL,          FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show firewall address-fqdns", "firewall/address-fqdns",    NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── VPN runtime state ─────────────────────────────────────── */
    { "show vpn ipsec",              "vpn/ipsec",                 NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get vpn ipsec tunnel",        "vpn/ipsec",                 NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show vpn ssl",                "vpn/ssl",                   NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get vpn ssl",                 "vpn/ssl",                   NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show vpn ssl stats",          "vpn/ssl/stats",             NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get vpn ssl stats",           "vpn/ssl/stats",             NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── DHCP, licensing, logging ──────────────────────────────── */
    { "show dhcp lease",             "system/dhcp",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get system dhcp",             "system/dhcp",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show license status",         "license/status",            NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get license status",          "license/status",            NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show log disk",               "log/current-disk-usage",    NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get log disk",                "log/current-disk-usage",    NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show log device state",       "log/device/state",          NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── WiFi & endpoint monitoring ────────────────────────────── */
    { "show wifi managed_ap",        "wifi/managed_ap",           NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get wifi managed_ap",         "wifi/managed_ap",           NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show wifi client",            "wifi/client",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get wifi client",             "wifi/client",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Security monitoring ───────────────────────────────────── */
    { "show user banned",            "user/banned",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get user banned",             "user/banned",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show utm antivirus stats",    "utm/antivirus/stats",       NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get utm antivirus stats",     "utm/antivirus/stats",       NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show ips anomaly",            "ips/anomaly",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "get ips anomaly",             "ips/anomaly",               NULL,             FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show webfilter categories",   "webfilter/fortiguard-categories", NULL,       FG_API_MONITOR, VIRP_TIER_GREEN },

    /* ── Automation & SDN ──────────────────────────────────────── */
    { "show system automation stats", "system/automation-stitch/stats", NULL,       FG_API_MONITOR, VIRP_TIER_GREEN },
    { "show system sdn-connector status", "system/sdn-connector/status", NULL,     FG_API_MONITOR, VIRP_TIER_GREEN },


    /* ═══════════════════════════════════════════════════════════════
     * YELLOW TIER — Configuration object reads
     * ═══════════════════════════════════════════════════════════════ */

    /* ── Firewall objects ──────────────────────────────────────── */
    { "show firewall address",       "firewall/address",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get firewall address",        "firewall/address",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall addrgrp",       "firewall/addrgrp",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get firewall addrgrp",        "firewall/addrgrp",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall service custom", "firewall.service/custom",  NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall service group", "firewall.service/group",    NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall vip",           "firewall/vip",              NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get firewall vip",            "firewall/vip",              NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall ippool",        "firewall/ippool",           NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get firewall ippool",         "firewall/ippool",           NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall central-snat",  "firewall/central-snat-map", NULL,            FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall shaper",        "firewall.shaper/traffic-shaper", NULL,        FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall per-ip-shaper", "firewall.shaper/per-ip-shaper", NULL,        FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall internet-service", "firewall/internet-service-name", NULL,    FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall schedule",      "firewall.schedule/recurring", NULL,           FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall local-in-policy", "firewall/local-in-policy", NULL,           FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall DoS-policy",    "firewall/DoS-policy",       NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall sniffer",       "firewall/sniffer",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show firewall proxy-policy",  "firewall/proxy-policy",     NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── System configuration ──────────────────────────────────── */
    { "show system zone",            "system/zone",               NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get system zone",             "system/zone",               NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system dns",             "system/dns",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system ntp",             "system/ntp",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system global",          "system/global",             NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get system global",           "system/global",             NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system settings",        "system/settings",           NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get system settings",         "system/settings",           NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system ha",              "system/ha",                 NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get system ha",               "system/ha",                 NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system accprofile",      "system/accprofile",         NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system dhcp server",     "system/dhcp/server",        NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system link-monitor",    "system/link-monitor",       NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system sdwan",           "system/sdwan/zone",         NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system sdn-connector",   "system/sdn-connector",     NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system automation-stitch", "system/automation-stitch", NULL,            FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system automation-trigger", "system/automation-trigger", NULL,          FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show system automation-action", "system/automation-action", NULL,            FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Routing configuration ─────────────────────────────────── */
    { "show router static",          "router/static",             NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get router static",           "router/static",             NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show router policy",          "router/policy",             NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show router ospf",            "router/ospf",               NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get router ospf",             "router/ospf",               NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show router bgp",             "router/bgp",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get router bgp",              "router/bgp",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show router prefix-list",     "router/prefix-list",        NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show router route-map",       "router/route-map",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show router access-list",     "router/access-list",        NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show router community-list",  "router/community-list",     NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── VPN configuration ─────────────────────────────────────── */
    { "show vpn ipsec phase1",       "vpn.ipsec/phase1-interface", NULL,            FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get vpn ipsec phase1",        "vpn.ipsec/phase1-interface", NULL,            FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show vpn ipsec phase2",       "vpn.ipsec/phase2-interface", NULL,            FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get vpn ipsec phase2",        "vpn.ipsec/phase2-interface", NULL,            FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show vpn ssl settings",       "vpn.ssl/settings",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get vpn ssl settings",        "vpn.ssl/settings",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── User & auth configuration ─────────────────────────────── */
    { "show user group",             "user/group",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "get user group",              "user/group",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show user ldap",              "user/ldap",                 NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show user radius",            "user/radius",               NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show user local",             "user/local",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show user fsso",              "user/fsso",                 NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show user fortitoken",        "user/fortitoken",           NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Security profiles ─────────────────────────────────────── */
    { "show antivirus profile",      "antivirus/profile",         NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show ips sensor",             "ips/sensor",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show ips global",             "ips/global",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show webfilter profile",      "webfilter/profile",         NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show webfilter urlfilter",    "webfilter/urlfilter",       NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show application list",       "application/list",          NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show dnsfilter profile",      "dnsfilter/profile",         NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show dlp sensor",             "dlp/sensor",                NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show voip profile",           "voip/profile",              NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Logging configuration ─────────────────────────────────── */
    { "show log syslogd setting",    "log.syslogd/setting",       NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show log syslogd filter",     "log.syslogd/filter",        NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show log fortianalyzer",      "log.fortianalyzer/setting", NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show log setting",            "log/setting",               NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },

    /* ── Infrastructure config ─────────────────────────────────── */
    { "show switch-controller managed-switch", "switch-controller/managed-switch", NULL, FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show wireless-controller wtp", "wireless-controller/wtp",  NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show wireless-controller wtp-profile", "wireless-controller/wtp-profile", NULL, FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show wireless-controller vap", "wireless-controller/vap",  NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },
    { "show endpoint-control fctems", "endpoint-control/fctems",  NULL,             FG_API_CMDB, VIRP_TIER_YELLOW },


    /* ═══════════════════════════════════════════════════════════════
     * RED TIER — Security-sensitive reads
     * ═══════════════════════════════════════════════════════════════ */

    { "show system admin",           "system/admin",              NULL,             FG_API_CMDB, VIRP_TIER_RED },
    { "get system admin",            "system/admin",              NULL,             FG_API_CMDB, VIRP_TIER_RED },
    { "show system api-user",        "system/api-user",           NULL,             FG_API_CMDB, VIRP_TIER_RED },
    { "get system api-user",         "system/api-user",           NULL,             FG_API_CMDB, VIRP_TIER_RED },
    { "show certificate local",      "certificate/local",         NULL,             FG_API_CMDB, VIRP_TIER_RED },
    { "show certificate remote",     "certificate/remote",        NULL,             FG_API_CMDB, VIRP_TIER_RED },
    { "show certificate ca",         "certificate/ca",            NULL,             FG_API_CMDB, VIRP_TIER_RED },
    { "show user peer",              "user/peer",                 NULL,             FG_API_CMDB, VIRP_TIER_RED },
    { "show alertemail setting",     "alertemail/setting",        NULL,             FG_API_CMDB, VIRP_TIER_RED },
};

const size_t FG_ROUTE_TABLE_SIZE =
    sizeof(FG_ROUTE_TABLE) / sizeof(FG_ROUTE_TABLE[0]);


/* ══════════════════════════════════════════════════════════════════
 * CURL WRITE CALLBACK
 * ══════════════════════════════════════════════════════════════════ */
typedef struct {
    char   *data;
    size_t  size;
    size_t  capacity;
} curl_buffer_t;

static size_t curl_write_cb(char *ptr, size_t size, size_t nmemb,
                            void *userdata)
{
    curl_buffer_t *buf = (curl_buffer_t *)userdata;
    size_t bytes = size * nmemb;

    while (buf->size + bytes + 1 > buf->capacity) {
        size_t new_cap = buf->capacity ? buf->capacity * 2 : 4096;
        char *new_data = realloc(buf->data, new_cap);
        if (!new_data) return 0;
        buf->data = new_data;
        buf->capacity = new_cap;
    }

    memcpy(buf->data + buf->size, ptr, bytes);
    buf->size += bytes;
    buf->data[buf->size] = '\0';
    return bytes;
}

static void curl_buffer_init(curl_buffer_t *buf)
{
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}

static void curl_buffer_free(curl_buffer_t *buf)
{
    free(buf->data);
    buf->data = NULL;
    buf->size = 0;
    buf->capacity = 0;
}


/* ══════════════════════════════════════════════════════════════════
 * COMMAND ROUTING
 * ══════════════════════════════════════════════════════════════════ */
virp_error_t fg_route_command(const char *command,
                              fg_transport_t *transport,
                              virp_trust_tier_t *tier,
                              const char **endpoint,
                              const char **params)
{
    return fg_route_command_ns(command, transport, tier, endpoint, params, NULL);
}

virp_error_t fg_route_command_ns(const char *command,
                                 fg_transport_t *transport,
                                 virp_trust_tier_t *tier,
                                 const char **endpoint,
                                 const char **params,
                                 fg_api_namespace_t *ns)
{
    if (!command || !transport || !tier)
        return VIRP_ERR_NULL_PTR;

    /* Normalize: skip leading whitespace */
    while (*command == ' ' || *command == '\t') command++;

    /* Search routing table — prefix match */
    for (size_t i = 0; i < FG_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(FG_ROUTE_TABLE[i].command_pattern);
        if (strncasecmp(command, FG_ROUTE_TABLE[i].command_pattern,
                        plen) == 0) {
            *transport = FG_TRANSPORT_REST;
            *tier      = FG_ROUTE_TABLE[i].tier;
            if (endpoint) *endpoint = FG_ROUTE_TABLE[i].api_endpoint;
            if (params)   *params   = FG_ROUTE_TABLE[i].api_params;
            if (ns)       *ns       = FG_ROUTE_TABLE[i].ns;
            return VIRP_OK;
        }
    }

    /* No match — fall through to SSH, YELLOW tier */
    *transport = FG_TRANSPORT_SSH;
    *tier      = VIRP_TIER_YELLOW;
    if (endpoint) *endpoint = NULL;
    if (params)   *params   = NULL;
    if (ns)       *ns       = FG_API_MONITOR;
    return VIRP_OK;
}


/* ══════════════════════════════════════════════════════════════════
 * REST API CALL
 * ══════════════════════════════════════════════════════════════════ */
static virp_error_t fg_api_call_internal(struct virp_conn *conn,
                                         const char *endpoint,
                                         fg_api_namespace_t ns,
                                         const char *params,
                                         fg_api_response_t *response)
{
    if (!conn || !endpoint || !response)
        return VIRP_ERR_NULL_PTR;

    memset(response, 0, sizeof(*response));

    CURL *curl = conn->curl_handle;
    if (!curl) return FG_ERR_NOT_CONNECTED;

    /* Build URL */
    const char *ns_path = (ns == FG_API_MONITOR)
                          ? "/api/v2/monitor/"
                          : "/api/v2/cmdb/";

    char url[2048];
    int written;

    if (params && conn->vdom) {
        written = snprintf(url, sizeof(url), "%s%s%s?%s&vdom=%s",
                          conn->base_url, ns_path, endpoint,
                          params, conn->vdom);
    } else if (params) {
        written = snprintf(url, sizeof(url), "%s%s%s?%s",
                          conn->base_url, ns_path, endpoint, params);
    } else if (conn->vdom) {
        written = snprintf(url, sizeof(url), "%s%s%s?vdom=%s",
                          conn->base_url, ns_path, endpoint,
                          conn->vdom);
    } else {
        written = snprintf(url, sizeof(url), "%s%s%s",
                          conn->base_url, ns_path, endpoint);
    }

    if (written < 0 || (size_t)written >= sizeof(url))
        return VIRP_ERR_BUFFER_TOO_SMALL;

    /* Set up auth header */
    char auth_header[512];
    snprintf(auth_header, sizeof(auth_header),
             "Authorization: Bearer %s", conn->api_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Response buffer */
    curl_buffer_t buf;
    curl_buffer_init(&buf);

    /* Configure request */
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);

    if (!conn->verify_tls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    /* Execute with retry on 429 */
    CURLcode res;
    long http_code = 0;
    int max_retries = 3;

    for (int attempt = 0; attempt <= max_retries; attempt++) {
        if (attempt > 0) {
            unsigned int delay = 1u << (attempt - 1);
            fprintf(stderr, "[virp-fg] 429 rate limited, "
                    "retry %d/%d in %us\n",
                    attempt, max_retries, delay);
            sleep(delay);

            curl_buffer_free(&buf);
            curl_buffer_init(&buf);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buf);
        }

        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            response->success = false;
            response->error_msg = strdup(curl_easy_strerror(res));
            curl_slist_free_all(headers);
            curl_buffer_free(&buf);
            return FG_ERR_TRANSPORT;
        }

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        if (http_code != 429) break;
    }

    curl_slist_free_all(headers);

    /* Populate response */
    response->http_status = (int)http_code;
    response->body = buf.data;       /* Transfer ownership */
    response->body_len = buf.size;

    if (http_code == 200) {
        response->success = true;
    } else if (http_code == 429) {
        response->success = false;
        response->error_msg = strdup("Rate limited after retries");
        return FG_ERR_RATE_LIMITED;
    } else if (http_code == 401 || http_code == 403) {
        response->success = false;
        response->error_msg = strdup("Authentication failed");
        return FG_ERR_AUTH;
    } else if (http_code == 404) {
        response->success = false;
        response->error_msg = strdup("Endpoint not found");
        return FG_ERR_NOT_FOUND;
    } else {
        response->success = false;
        char errbuf[128];
        snprintf(errbuf, sizeof(errbuf), "HTTP %d", (int)http_code);
        response->error_msg = strdup(errbuf);
        return FG_ERR_TRANSPORT;
    }

    return VIRP_OK;
}

static void fg_api_response_free(fg_api_response_t *response)
{
    if (!response) return;
    free(response->body);
    free(response->results_json);
    free(response->error_msg);
    memset(response, 0, sizeof(*response));
}


/* ══════════════════════════════════════════════════════════════════
 * SSH HELPERS
 * ══════════════════════════════════════════════════════════════════ */

#define FG_SSH_READ_TIMEOUT_MS  15000
#define FG_SSH_BUFFER_SIZE      65536

static int fg_ssh_connect(struct virp_conn *conn)
{
    struct sockaddr_in sin;
    int sock;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(conn->ssh_port);

    if (inet_pton(AF_INET, conn->device.host, &sin.sin_addr) <= 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        close(sock);
        return -1;
    }

    conn->ssh_socket = sock;

    LIBSSH2_SESSION *session = libssh2_session_init();
    if (!session) {
        close(sock);
        return -1;
    }

    libssh2_session_set_timeout(session, 30000);

    if (libssh2_session_handshake(session, sock) != 0) {
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    if (libssh2_userauth_password(session,
                                  conn->device.username,
                                  conn->device.password) != 0) {
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    conn->ssh_session = session;
    conn->ssh_connected = true;

    return 0;
}

static virp_error_t fg_ssh_execute(struct virp_conn *conn,
                                   const char *command,
                                   virp_exec_result_t *result)
{
    if (!conn->ssh_session || !conn->ssh_connected)
        return FG_ERR_NOT_CONNECTED;

    LIBSSH2_SESSION *session = conn->ssh_session;
    LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
    if (!channel)
        return FG_ERR_TRANSPORT;

    if (libssh2_channel_request_pty(channel, "xterm") != 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return FG_ERR_TRANSPORT;
    }

    if (libssh2_channel_shell(channel) != 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return FG_ERR_TRANSPORT;
    }

    /* Drain initial prompt/banner before sending command */
    libssh2_session_set_blocking(session, 0);
    {
        char drain[4096];
        int drain_idle = 0;
        while (drain_idle < 15) {
            ssize_t n = libssh2_channel_read(channel, drain, sizeof(drain) - 1);
            if (n > 0) {
                drain_idle = 0;
            } else if (n == LIBSSH2_ERROR_EAGAIN) {
                drain_idle++;
                usleep(100000);
            } else {
                break;
            }
        }
    }
    libssh2_session_set_blocking(session, 1);

    /* Send command */
    char cmd_buf[4096];
    int cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "%s\n", command);
    libssh2_channel_write(channel, cmd_buf, cmd_len);

    /* Read output into temp buffer */
    char *raw = calloc(FG_SSH_BUFFER_SIZE, 1);
    if (!raw) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "out of memory for SSH read buffer");
        result->success = false;
        return VIRP_OK;
    }

    size_t total = 0;
    int idle_cycles = 0;
    libssh2_session_set_blocking(session, 0);

    while (total < FG_SSH_BUFFER_SIZE - 1 && idle_cycles < 30) {
        ssize_t n = libssh2_channel_read(channel,
                                         raw + total,
                                         FG_SSH_BUFFER_SIZE - total - 1);
        if (n > 0) {
            total += n;
            idle_cycles = 0;

            if (total > 3 && raw[total - 1] == ' '
                          && raw[total - 2] == '#') {
                break;
            }
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            idle_cycles++;
            usleep(100000);
        } else {
            break;
        }
    }

    libssh2_session_set_blocking(session, 1);
    raw[total] = '\0';

    /* Strip command echo and trailing prompt */
    char *start = strstr(raw, "\n");
    if (start) start++;
    else start = raw;

    char *end = raw + total;
    while (end > start && (end[-1] == ' ' || end[-1] == '#'
                           || end[-1] == '\r' || end[-1] == '\n'))
        end--;
    char *prompt_line = end;
    while (prompt_line > start && prompt_line[-1] != '\n')
        prompt_line--;

    size_t payload_len = (size_t)(prompt_line - start);
    if (payload_len > 0 && start[payload_len - 1] == '\r')
        payload_len--;

    /* Copy into fixed-size result buffer */
    if (payload_len >= VIRP_OUTPUT_MAX)
        payload_len = VIRP_OUTPUT_MAX - 1;

    memcpy(result->output, start, payload_len);
    result->output[payload_len] = '\0';
    result->output_len = payload_len;
    result->success = true;
    result->exit_code = 0;

    free(raw);
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);

    return VIRP_OK;
}


/* ══════════════════════════════════════════════════════════════════
 * DRIVER INTERFACE IMPLEMENTATION
 * ══════════════════════════════════════════════════════════════════ */

/* ── connect ────────────────────────────────────────────────────── */
static virp_conn_t *fg_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    /* Copy device config */
    memcpy(&conn->device, device, sizeof(*device));

    /* FortiGate config from extended device fields */
    conn->api_port = device->api_port ? device->api_port : 443;
    conn->ssh_port = device->port ? device->port : 22;
    conn->verify_tls = device->verify_tls;
    conn->preferred = FG_TRANSPORT_AUTO;

    /* VDOM — default to "root" if not specified */
    if (device->vdom[0] != '\0')
        conn->vdom = strdup(device->vdom);
    else
        conn->vdom = strdup("root");

    /* API token */
    if (device->api_token[0] != '\0')
        conn->api_token = strdup(device->api_token);

    /* Build base URL */
    char base[512];
    snprintf(base, sizeof(base), "https://%s:%d",
             device->host, conn->api_port);
    conn->base_url = strdup(base);

    /* Initialize REST API transport */
    conn->curl_handle = curl_easy_init();
    if (conn->curl_handle && conn->api_token) {
        fg_api_response_t test_resp;
        virp_error_t err = fg_api_call_internal(conn, "system/status",
                                                FG_API_MONITOR, NULL,
                                                &test_resp);
        if (err == VIRP_OK && test_resp.success) {
            conn->rest_connected = true;
        }
        fg_api_response_free(&test_resp);
    }

    /* Initialize SSH if REST not available or AUTO mode */
    if (conn->preferred != FG_TRANSPORT_REST || !conn->rest_connected) {
        if (device->username[0] != '\0' && device->password[0] != '\0') {
            fg_ssh_connect(conn);
        }
    }

    /* At least one transport must be up */
    if (!conn->rest_connected && !conn->ssh_connected) {
        free(conn->api_token);
        free(conn->base_url);
        free(conn->vdom);
        if (conn->curl_handle)
            curl_easy_cleanup(conn->curl_handle);
        free(conn);
        return NULL;
    }

    return (virp_conn_t *)conn;
}


/* ── execute ────────────────────────────────────────────────────── */
static virp_error_t fg_execute(virp_conn_t *base_conn,
                               const char *command,
                               virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    /* Route command to appropriate transport */
    fg_transport_t transport;
    virp_trust_tier_t tier;
    fg_api_namespace_t ns = FG_API_MONITOR;
    const char *endpoint = NULL;
    const char *params = NULL;

    virp_error_t err = fg_route_command_ns(command, &transport,
                                           &tier, &endpoint, &params, &ns);
    if (err != VIRP_OK) return err;

    /* Execute via selected transport */
    if (transport == FG_TRANSPORT_REST && conn->rest_connected) {
        /* REST API path — use namespace from route table */
        fg_api_response_t api_resp;
        err = fg_api_call_internal(conn, endpoint, ns,
                         params, &api_resp);

        if (err == VIRP_OK && api_resp.success) {
            /* Copy JSON body into fixed-size output buffer */
            size_t copy_len = api_resp.body_len;
            if (copy_len >= VIRP_OUTPUT_MAX)
                copy_len = VIRP_OUTPUT_MAX - 1;
            memcpy(result->output, api_resp.body, copy_len);
            result->output[copy_len] = '\0';
            result->output_len = copy_len;
            result->success = true;
            result->exit_code = 0;
        } else if (err == FG_ERR_RATE_LIMITED) {
            fg_api_response_free(&api_resp);

            if (conn->ssh_connected) {
                fprintf(stderr, "[virp-fg] REST 429, falling back to SSH\n");
                return fg_ssh_execute(conn, command, result);
            }

            snprintf(result->output, VIRP_OUTPUT_MAX,
                     "ERROR: API rate limited (429)");
            result->output_len = strlen(result->output);
            result->success = false;
            result->exit_code = 429;
            return VIRP_OK;  /* Driver succeeded, command failed */
        } else {
            /* Copy error info if available */
            if (api_resp.error_msg) {
                snprintf(result->error_msg, sizeof(result->error_msg),
                         "%s", api_resp.error_msg);
            }
            result->success = false;
            fg_api_response_free(&api_resp);
            return VIRP_OK;  /* Driver succeeded, command failed */
        }
        fg_api_response_free(&api_resp);

    } else if (conn->ssh_connected) {
        err = fg_ssh_execute(conn, command, result);

    } else {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "No transport available");
        result->success = false;
        return VIRP_OK;
    }

    return err;
}


/* ── disconnect ─────────────────────────────────────────────────── */
static void fg_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    /* Tear down REST */
    if (conn->curl_handle) {
        curl_easy_cleanup(conn->curl_handle);
        conn->curl_handle = NULL;
    }
    conn->rest_connected = false;

    /* Tear down SSH */
    if (conn->ssh_session) {
        libssh2_session_disconnect(conn->ssh_session, "VIRP disconnect");
        libssh2_session_free(conn->ssh_session);
        conn->ssh_session = NULL;
    }
    if (conn->ssh_socket >= 0) {
        close(conn->ssh_socket);
        conn->ssh_socket = -1;
    }
    conn->ssh_connected = false;

    /* Free heap strings */
    free(conn->api_token);
    free(conn->base_url);
    free(conn->vdom);

    free(conn);
}


/* ── detect ─────────────────────────────────────────────────────── */
static bool fg_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->rest_connected) return false;

    fg_api_response_t resp;
    virp_error_t err = fg_api_call_internal(conn, "system/status",
                                            FG_API_MONITOR, NULL, &resp);

    bool is_fortigate = false;
    if (err == VIRP_OK && resp.success && resp.body) {
        is_fortigate = (strstr(resp.body, "\"serial\"") != NULL
                     && strstr(resp.body, "\"version\"") != NULL);
    }

    fg_api_response_free(&resp);
    return is_fortigate;
}


/* ── health_check ───────────────────────────────────────────────── */
static virp_error_t fg_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->rest_connected)
        return FG_ERR_NOT_CONNECTED;

    fg_api_response_t resp;
    virp_error_t err = fg_api_call_internal(conn, "system/status",
                                            FG_API_MONITOR, NULL, &resp);

    if (err != VIRP_OK || !resp.success) {
        fg_api_response_free(&resp);
        return err ? err : FG_ERR_TRANSPORT;
    }

    fg_api_response_free(&resp);
    return VIRP_OK;
}


/* ══════════════════════════════════════════════════════════════════
 * DRIVER REGISTRATION
 * ══════════════════════════════════════════════════════════════════ */

static const virp_driver_t fg_driver = {
    .name        = "fortigate",
    .vendor      = VIRP_VENDOR_FORTINET,
    .connect     = fg_connect,
    .execute     = fg_execute,
    .disconnect  = fg_disconnect,
    .detect      = fg_detect,
    .health_check = fg_health_check,
};

void virp_driver_fortinet_init(void)
{
    virp_driver_register(&fg_driver);
}
