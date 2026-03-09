/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco ASA Driver Unit Tests
 *
 * Tests parsers and command routing locally (no SSH).
 * Live device tests are in test_live.c.
 */

#include "virp.h"
#include "virp_driver.h"
#include "virp_driver_asa.h"
#include "parser_asa.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %s ... ", tests_run, name); \
} while(0)

#define PASS() do { \
    tests_passed++; \
    printf("PASS\n"); \
} while(0)

#define FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
} while(0)

/* =========================================================================
 * Prompt Parsing Tests
 * ========================================================================= */

static void test_prompt_parsing(void)
{
    printf("\n=== Prompt Parsing ===\n");

    TEST("user mode (ASA>)");
    assert(asa_parse_mode("ASA>") == ASA_MODE_USER);
    PASS();

    TEST("enable mode (ASA#)");
    assert(asa_parse_mode("ASA#") == ASA_MODE_ENABLE);
    PASS();

    TEST("config mode (ASA(config)#)");
    assert(asa_parse_mode("ASA(config)#") == ASA_MODE_CONFIG);
    PASS();

    TEST("config-if mode (ASA(config-if)#)");
    assert(asa_parse_mode("ASA(config-if)#") == ASA_MODE_CONFIG_SUB);
    PASS();

    TEST("config-subif mode (ASA(config-subif)#)");
    assert(asa_parse_mode("ASA(config-subif)#") == ASA_MODE_CONFIG_SUB);
    PASS();

    TEST("multi-context user (ASA/ctx1>)");
    assert(asa_parse_mode("ASA/ctx1>") == ASA_MODE_USER);
    PASS();

    TEST("multi-context enable (ASA/ctx1#)");
    assert(asa_parse_mode("ASA/ctx1#") == ASA_MODE_ENABLE);
    PASS();

    TEST("custom hostname (FW-PROD#)");
    assert(asa_parse_mode("FW-PROD#") == ASA_MODE_ENABLE);
    PASS();

    TEST("custom hostname user (FW-PROD>)");
    assert(asa_parse_mode("FW-PROD>") == ASA_MODE_USER);
    PASS();

    TEST("empty prompt");
    assert(asa_parse_mode("") == ASA_MODE_UNKNOWN);
    PASS();

    TEST("null prompt");
    assert(asa_parse_mode(NULL) == ASA_MODE_UNKNOWN);
    PASS();

    TEST("trailing space (ASA# )");
    assert(asa_parse_mode("ASA# ") == ASA_MODE_ENABLE);
    PASS();
}

/* =========================================================================
 * Command Routing Tests
 * ========================================================================= */

static void test_command_routing(void)
{
    printf("\n=== Command Routing ===\n");

    TEST("show version → GREEN");
    assert(asa_route_command("show version") == VIRP_TIER_GREEN);
    PASS();

    TEST("show interface ip brief → GREEN");
    assert(asa_route_command("show interface ip brief") == VIRP_TIER_GREEN);
    PASS();

    TEST("show route → GREEN");
    assert(asa_route_command("show route") == VIRP_TIER_GREEN);
    PASS();

    TEST("show firewall → GREEN");
    assert(asa_route_command("show firewall") == VIRP_TIER_GREEN);
    PASS();

    TEST("show failover → GREEN");
    assert(asa_route_command("show failover") == VIRP_TIER_GREEN);
    PASS();

    TEST("show conn count → GREEN");
    assert(asa_route_command("show conn count") == VIRP_TIER_GREEN);
    PASS();

    TEST("show cpu usage → GREEN");
    assert(asa_route_command("show cpu usage") == VIRP_TIER_GREEN);
    PASS();

    TEST("show access-list → YELLOW");
    assert(asa_route_command("show access-list") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show crypto isakmp sa → YELLOW");
    assert(asa_route_command("show crypto isakmp sa") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show logging → YELLOW");
    assert(asa_route_command("show logging") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show running-config → RED");
    assert(asa_route_command("show running-config") == VIRP_TIER_RED);
    PASS();

    TEST("show running-config access-list → YELLOW (longest match)");
    assert(asa_route_command("show running-config access-list") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show startup-config → RED");
    assert(asa_route_command("show startup-config") == VIRP_TIER_RED);
    PASS();

    TEST("erase → BLACK");
    assert(asa_route_command("erase startup-config") == VIRP_TIER_BLACK);
    PASS();

    TEST("reload → BLACK");
    assert(asa_route_command("reload") == VIRP_TIER_BLACK);
    PASS();

    TEST("delete → BLACK");
    assert(asa_route_command("delete disk0:/test") == VIRP_TIER_BLACK);
    PASS();

    TEST("write erase → BLACK");
    assert(asa_route_command("write erase") == VIRP_TIER_BLACK);
    PASS();

    TEST("unmapped command → YELLOW");
    assert(asa_route_command("show tech-support") == VIRP_TIER_YELLOW);
    PASS();

    TEST("null command → YELLOW");
    assert(asa_route_command(NULL) == VIRP_TIER_YELLOW);
    PASS();
}

/* =========================================================================
 * Parser: show version
 * ========================================================================= */

static void test_parse_version(void)
{
    printf("\n=== Parser: show version ===\n");

    const char *sample =
        "Cisco Adaptive Security Appliance Software Version 9.8(3)21\n"
        "Device Manager Version 7.2(2)1\n"
        "\n"
        "Compiled on Tue 29-Jan-19 13:09 PST by builders\n"
        "System image file is \"disk0:/asa983-21-smp-k8.bin\"\n"
        "\n"
        "Hardware:   ASA5525, 8192 MB RAM, CPU Lynnfield 2394 MHz, 1 CPU (4 cores)\n"
        "            Internal ATA Compact Flash, 8192MB\n"
        "Serial Number: FCH1234ABCD\n"
        "ASA up 45 days 12 hours\n";

    asa_version_t v;

    TEST("parse succeeds");
    assert(asa_parse_version(sample, &v) == 0);
    assert(v.parsed);
    PASS();

    TEST("version = 9.8(3)21");
    assert(strcmp(v.version, "9.8(3)21") == 0);
    PASS();

    TEST("model = ASA5525");
    assert(strcmp(v.model, "ASA5525") == 0);
    PASS();

    TEST("ram_mb = 8192");
    assert(v.ram_mb == 8192);
    PASS();

    TEST("cpu_cores = 4");
    assert(v.cpu_cores == 4);
    PASS();

    TEST("image = asa983-21-smp-k8.bin");
    assert(strcmp(v.image, "asa983-21-smp-k8.bin") == 0);
    PASS();

    TEST("serial = FCH1234ABCD");
    assert(strcmp(v.serial, "FCH1234ABCD") == 0);
    PASS();

    TEST("uptime_days = 45");
    assert(v.uptime_days == 45);
    PASS();

    TEST("null input");
    assert(asa_parse_version(NULL, &v) == -1);
    PASS();

    TEST("empty input");
    asa_version_t v2;
    assert(asa_parse_version("", &v2) == -1);
    assert(!v2.parsed);
    PASS();
}

/* =========================================================================
 * Parser: show interface ip brief
 * ========================================================================= */

static void test_parse_interfaces(void)
{
    printf("\n=== Parser: show interface ip brief ===\n");

    const char *sample =
        "Interface                  IP-Address      OK? Method Status                Protocol\n"
        "GigabitEthernet0/0         unassigned      YES unset  administratively down down\n"
        "GigabitEthernet0/1         unassigned      YES unset  administratively down down\n"
        "Management0/0              10.0.0.253      YES unset  up                    up\n";

    asa_interfaces_t ifaces;

    TEST("parse succeeds");
    assert(asa_parse_interfaces(sample, &ifaces) == 0);
    assert(ifaces.parsed);
    PASS();

    TEST("count = 3");
    assert(ifaces.count == 3);
    PASS();

    TEST("first interface name");
    assert(strcmp(ifaces.interfaces[0].name, "GigabitEthernet0/0") == 0);
    PASS();

    TEST("first interface IP = unassigned");
    assert(strcmp(ifaces.interfaces[0].ip_address, "unassigned") == 0);
    PASS();

    TEST("management IP = 10.0.0.253");
    assert(strcmp(ifaces.interfaces[2].ip_address, "10.0.0.253") == 0);
    PASS();

    TEST("management status = up");
    assert(strcmp(ifaces.interfaces[2].status, "up") == 0);
    PASS();

    TEST("management protocol = up");
    assert(strcmp(ifaces.interfaces[2].protocol, "up") == 0);
    PASS();

    TEST("null input");
    assert(asa_parse_interfaces(NULL, &ifaces) == -1);
    PASS();
}

/* =========================================================================
 * Parser: show route
 * ========================================================================= */

static void test_parse_routes(void)
{
    printf("\n=== Parser: show route ===\n");

    const char *sample =
        "Codes: L - local, C - connected, S - static, R - RIP, M - mobile, B - BGP\n"
        "       D - EIGRP, EX - EIGRP external, O - OSPF, IA - OSPF inter area\n"
        "\n"
        "Gateway of last resort is 10.0.0.1 to network 0.0.0.0\n"
        "\n"
        "S*    0.0.0.0 0.0.0.0 [1/0] via 10.0.0.1, management\n"
        "C     10.0.0.0 255.255.255.0 is directly connected, management\n"
        "L     10.0.0.253 255.255.255.255 is directly connected, management\n";

    asa_routes_t routes;

    TEST("parse succeeds");
    assert(asa_parse_routes(sample, &routes) == 0);
    assert(routes.parsed);
    PASS();

    TEST("count = 3");
    assert(routes.count == 3);
    PASS();

    TEST("gateway of last resort");
    assert(strstr(routes.gateway_of_last_resort, "10.0.0.1") != NULL);
    PASS();

    TEST("default route is S*");
    assert(routes.routes[0].code == 'S');
    assert(routes.routes[0].is_default);
    PASS();

    TEST("default route network = 0.0.0.0");
    assert(strcmp(routes.routes[0].network, "0.0.0.0") == 0);
    PASS();

    TEST("default route next_hop = 10.0.0.1");
    assert(strcmp(routes.routes[0].next_hop, "10.0.0.1") == 0);
    PASS();

    TEST("default route nameif = management");
    assert(strcmp(routes.routes[0].nameif, "management") == 0);
    PASS();

    TEST("default route AD = 1, metric = 0");
    assert(routes.routes[0].ad == 1);
    assert(routes.routes[0].metric == 0);
    PASS();

    TEST("connected route code = C");
    assert(routes.routes[1].code == 'C');
    assert(!routes.routes[1].is_default);
    PASS();

    TEST("connected route nameif = management");
    assert(strcmp(routes.routes[1].nameif, "management") == 0);
    PASS();

    TEST("null input");
    assert(asa_parse_routes(NULL, &routes) == -1);
    PASS();
}

/* =========================================================================
 * Parser: show conn count
 * ========================================================================= */

static void test_parse_conn_count(void)
{
    printf("\n=== Parser: show conn count ===\n");

    const char *sample = "12345 in use, 23456 most used\n";
    asa_conn_count_t cc;

    TEST("parse succeeds");
    assert(asa_parse_conn_count(sample, &cc) == 0);
    assert(cc.parsed);
    PASS();

    TEST("current = 12345");
    assert(cc.current == 12345);
    PASS();

    TEST("peak = 23456");
    assert(cc.peak == 23456);
    PASS();

    TEST("zero connections");
    asa_conn_count_t cc2;
    assert(asa_parse_conn_count("0 in use, 0 most used\n", &cc2) == 0);
    assert(cc2.current == 0);
    PASS();
}

/* =========================================================================
 * Parser: show failover
 * ========================================================================= */

static void test_parse_failover(void)
{
    printf("\n=== Parser: show failover ===\n");

    TEST("failover off");
    {
        asa_failover_t fo;
        assert(asa_parse_failover("Failover Off\n", &fo) == 0);
        assert(!fo.failover_on);
        assert(strcmp(fo.state, "Disabled") == 0);
    }
    PASS();

    TEST("failover on — active/standby");
    {
        const char *sample =
            "Failover On\n"
            "Failover unit Primary\n"
            "This host: Primary - Active\n"
            "  Interface management (10.0.0.253): Normal\n"
            "Other host: Secondary - Standby Ready\n"
            "  Interface management (10.0.0.254): Normal\n";

        asa_failover_t fo;
        assert(asa_parse_failover(sample, &fo) == 0);
        assert(fo.failover_on);
        assert(strcmp(fo.state, "Active") == 0);
        assert(strcmp(fo.peer_state, "Standby Ready") == 0);
    }
    PASS();
}

/* =========================================================================
 * Parser: show cpu usage
 * ========================================================================= */

static void test_parse_cpu(void)
{
    printf("\n=== Parser: show cpu usage ===\n");

    const char *sample =
        "CPU utilization for 5 seconds = 3%; 1 minute: 2%; 5 minutes: 1%\n";

    asa_cpu_t cpu;

    TEST("parse succeeds");
    assert(asa_parse_cpu(sample, &cpu) == 0);
    assert(cpu.parsed);
    PASS();

    TEST("five_sec = 3");
    assert(cpu.five_sec == 3);
    PASS();

    TEST("one_min = 2");
    assert(cpu.one_min == 2);
    PASS();

    TEST("five_min = 1");
    assert(cpu.five_min == 1);
    PASS();
}

/* =========================================================================
 * Parser: show memory
 * ========================================================================= */

static void test_parse_memory(void)
{
    printf("\n=== Parser: show memory ===\n");

    const char *sample =
        "Free memory:         1063498752 bytes (49%)\n"
        "Used memory:         1084067840 bytes (51%)\n"
        "Total memory:        2147566592 bytes (100%)\n";

    asa_memory_t mem;

    TEST("parse succeeds");
    assert(asa_parse_memory(sample, &mem) == 0);
    assert(mem.parsed);
    PASS();

    TEST("total = 2147566592");
    assert(mem.total == 2147566592ULL);
    PASS();

    TEST("used = 1084067840");
    assert(mem.used == 1084067840ULL);
    PASS();

    TEST("free = 1063498752");
    assert(mem.free == 1063498752ULL);
    PASS();
}

/* =========================================================================
 * Parser: show access-list
 * ========================================================================= */

static void test_parse_access_list(void)
{
    printf("\n=== Parser: show access-list ===\n");

    const char *sample =
        "access-list OUTSIDE_IN; 3 elements; name hash: 0x12345678\n"
        "access-list OUTSIDE_IN line 1 extended permit tcp any host 10.0.0.1 eq https (hitcnt=12345) 0xabcdef01\n"
        "access-list OUTSIDE_IN line 2 extended permit tcp any host 10.0.0.1 eq ssh (hitcnt=456) 0xabcdef02\n"
        "access-list OUTSIDE_IN line 3 extended deny ip any any (hitcnt=0) 0xabcdef03\n";

    asa_acl_t acl;

    TEST("parse succeeds");
    assert(asa_parse_access_list(sample, &acl) == 0);
    assert(acl.parsed);
    PASS();

    TEST("count = 3");
    assert(acl.count == 3);
    PASS();

    TEST("ACL name = OUTSIDE_IN");
    assert(strcmp(acl.entries[0].acl_name, "OUTSIDE_IN") == 0);
    PASS();

    TEST("first entry hitcnt = 12345");
    assert(acl.entries[0].hitcnt == 12345);
    PASS();

    TEST("third entry hitcnt = 0");
    assert(acl.entries[2].hitcnt == 0);
    PASS();

    TEST("entry text contains permit/deny");
    assert(strstr(acl.entries[0].line, "permit") != NULL);
    assert(strstr(acl.entries[2].line, "deny") != NULL);
    PASS();
}

/* =========================================================================
 * Driver Registration Test
 * ========================================================================= */

static void test_driver_registration(void)
{
    printf("\n=== Driver Registration ===\n");

    TEST("vendor enum CISCO_ASA = 8");
    assert(VIRP_VENDOR_CISCO_ASA == 8);
    PASS();

    TEST("driver name is cisco_asa");
    const virp_driver_t *drv = virp_driver_asa();
    assert(drv != NULL);
    assert(strcmp(drv->name, "cisco_asa") == 0);
    PASS();

    TEST("driver vendor matches");
    assert(drv->vendor == VIRP_VENDOR_CISCO_ASA);
    PASS();

    TEST("all function pointers non-NULL");
    assert(drv->connect != NULL);
    assert(drv->execute != NULL);
    assert(drv->disconnect != NULL);
    assert(drv->detect != NULL);
    assert(drv->health_check != NULL);
    PASS();

    TEST("disconnect(NULL) is no-op");
    drv->disconnect(NULL);
    PASS();

    TEST("register and lookup");
    virp_driver_mock_init();
    virp_driver_asa_init();
    const virp_driver_t *found = virp_driver_lookup(VIRP_VENDOR_CISCO_ASA);
    assert(found != NULL);
    assert(found->vendor == VIRP_VENDOR_CISCO_ASA);
    assert(strcmp(found->name, "cisco_asa") == 0);
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void)
{
    printf("VIRP Cisco ASA Driver — Unit Tests\n");
    printf("===================================\n");

    test_prompt_parsing();
    test_command_routing();
    test_parse_version();
    test_parse_interfaces();
    test_parse_routes();
    test_parse_conn_count();
    test_parse_failover();
    test_parse_cpu();
    test_parse_memory();
    test_parse_access_list();
    test_driver_registration();

    printf("\n===================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
