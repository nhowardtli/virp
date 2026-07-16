/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco IOS / IOS-XE gate-classifier unit tests (cisco_gate_tier).
 *
 * cisco_gate_tier() is the SHARED CORE table for both classic IOS and
 * IOS-XE. It is FAIL-CLOSED: anything not explicitly GREEN/YELLOW is RED.
 * Credential/security writes are asserted EXPLICITLY, one per command.
 */

#include "virp.h"
#include "virp_driver.h"
#include <stdio.h>
#include <assert.h>

/* cisco_gate_tier is declared in virp_driver_cisco.h, but that header embeds
 * an opaque virp_conn_t by value (the RESTCONF struct) and cannot be included
 * standalone. Forward-declare the one symbol under test, as test_driver_cisco.c
 * does for its own symbols. */
virp_trust_tier_t cisco_gate_tier(const char *command);

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

static void test_green(void)
{
    printf("\n=== GREEN — read-only status ===\n");
    TEST("show version -> GREEN");            assert(cisco_gate_tier("show version") == VIRP_TIER_GREEN); PASS();
    TEST("show ip interface brief -> GREEN"); assert(cisco_gate_tier("show ip interface brief") == VIRP_TIER_GREEN); PASS();
    TEST("show interfaces -> GREEN");         assert(cisco_gate_tier("show interfaces GigabitEthernet0/0") == VIRP_TIER_GREEN); PASS();
    TEST("show ip route -> GREEN");           assert(cisco_gate_tier("show ip route") == VIRP_TIER_GREEN); PASS();
    TEST("show cdp neighbors -> GREEN");      assert(cisco_gate_tier("show cdp neighbors detail") == VIRP_TIER_GREEN); PASS();
    TEST("show inventory -> GREEN");          assert(cisco_gate_tier("show inventory") == VIRP_TIER_GREEN); PASS();
    TEST("show clock -> GREEN");              assert(cisco_gate_tier("show clock") == VIRP_TIER_GREEN); PASS();
}

static void test_yellow(void)
{
    printf("\n=== YELLOW — config-visibility reads ===\n");
    TEST("show running-config -> YELLOW");       assert(cisco_gate_tier("show running-config") == VIRP_TIER_YELLOW); PASS();
    TEST("show startup-config -> YELLOW");       assert(cisco_gate_tier("show startup-config") == VIRP_TIER_YELLOW); PASS();
    TEST("show access-lists -> YELLOW");         assert(cisco_gate_tier("show access-lists") == VIRP_TIER_YELLOW); PASS();
    TEST("show ip nat translations -> YELLOW");  assert(cisco_gate_tier("show ip nat translations") == VIRP_TIER_YELLOW); PASS();
}

static void test_red_config_writes(void)
{
    printf("\n=== RED — config writes ===\n");
    TEST("configure terminal -> RED"); assert(cisco_gate_tier("configure terminal") == VIRP_TIER_RED); PASS();
    TEST("conf t -> RED");             assert(cisco_gate_tier("conf t") == VIRP_TIER_RED); PASS();
    TEST("interface -> RED");          assert(cisco_gate_tier("interface GigabitEthernet0/0") == VIRP_TIER_RED); PASS();
    TEST("ip route -> RED");           assert(cisco_gate_tier("ip route 0.0.0.0 0.0.0.0 10.0.0.1") == VIRP_TIER_RED); PASS();
    TEST("router bgp -> RED");         assert(cisco_gate_tier("router bgp 65000") == VIRP_TIER_RED); PASS();
    TEST("router ospf -> RED");        assert(cisco_gate_tier("router ospf 1") == VIRP_TIER_RED); PASS();
    TEST("router eigrp -> RED");       assert(cisco_gate_tier("router eigrp 100") == VIRP_TIER_RED); PASS();
    TEST("no shutdown -> RED");        assert(cisco_gate_tier("no shutdown") == VIRP_TIER_RED); PASS();
    TEST("hostname -> RED");           assert(cisco_gate_tier("hostname EVIL") == VIRP_TIER_RED); PASS();
}

static void test_red_credential_writes(void)
{
    printf("\n=== RED — credential/security writes (adversarial, explicit) ===\n");
    /* username variants — each explicit */
    TEST("username ... privilege 15 -> RED");
    assert(cisco_gate_tier("username attacker privilege 15 secret Str0ng") == VIRP_TIER_RED); PASS();
    TEST("username ... secret -> RED");
    assert(cisco_gate_tier("username attacker secret Str0ng") == VIRP_TIER_RED); PASS();
    TEST("username ... password -> RED");
    assert(cisco_gate_tier("username attacker password 0 Str0ng") == VIRP_TIER_RED); PASS();

    TEST("enable secret -> RED");        assert(cisco_gate_tier("enable secret 0 Str0ng") == VIRP_TIER_RED); PASS();
    TEST("enable password -> RED");      assert(cisco_gate_tier("enable password Str0ng") == VIRP_TIER_RED); PASS();
    TEST("aaa -> RED");                  assert(cisco_gate_tier("aaa authentication login default local") == VIRP_TIER_RED); PASS();
    TEST("tacacs-server -> RED");        assert(cisco_gate_tier("tacacs-server host 10.0.0.9 key SECRET") == VIRP_TIER_RED); PASS();
    TEST("tacacs server (IOS-XE) -> RED"); assert(cisco_gate_tier("tacacs server TS1") == VIRP_TIER_RED); PASS();
    TEST("radius-server -> RED");        assert(cisco_gate_tier("radius-server host 10.0.0.9 key SECRET") == VIRP_TIER_RED); PASS();
    TEST("radius server (IOS-XE) -> RED"); assert(cisco_gate_tier("radius server RS1") == VIRP_TIER_RED); PASS();
    TEST("snmp-server community -> RED"); assert(cisco_gate_tier("snmp-server community public RW") == VIRP_TIER_RED); PASS();
    TEST("crypto key -> RED");           assert(cisco_gate_tier("crypto key generate rsa") == VIRP_TIER_RED); PASS();
    TEST("crypto pki -> RED");           assert(cisco_gate_tier("crypto pki trustpoint TP") == VIRP_TIER_RED); PASS();
    TEST("key chain -> RED");            assert(cisco_gate_tier("key chain KC") == VIRP_TIER_RED); PASS();
    TEST("line vty (login/password) -> RED"); assert(cisco_gate_tier("line vty 0 4") == VIRP_TIER_RED); PASS();
    TEST("login -> RED");                assert(cisco_gate_tier("login local") == VIRP_TIER_RED); PASS();
    TEST("password -> RED");             assert(cisco_gate_tier("password 0 Str0ng") == VIRP_TIER_RED); PASS();
}

static void test_fail_closed(void)
{
    printf("\n=== Fail-closed default ===\n");
    TEST("unknown command -> RED (fail-closed default)");
    assert(cisco_gate_tier("frobnicate the widget") == VIRP_TIER_RED); PASS();
    TEST("unlisted show (show sessions) -> RED (fail-closed)");
    assert(cisco_gate_tier("show sessions") == VIRP_TIER_RED); PASS();
    TEST("null -> RED (fail-closed)");
    assert(cisco_gate_tier(NULL) == VIRP_TIER_RED); PASS();
    TEST("leading whitespace tolerated ( show version -> GREEN)");
    assert(cisco_gate_tier("   show version") == VIRP_TIER_GREEN); PASS();
}

int main(void)
{
    printf("VIRP Cisco IOS/IOS-XE Gate Classifier — Unit Tests\n");
    printf("==================================================\n");
    test_green();
    test_yellow();
    test_red_config_writes();
    test_red_credential_writes();
    test_fail_closed();
    printf("\n==================================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
