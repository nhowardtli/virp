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
#include <string.h>
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

/*
 * REGRESSION (2026-08-09): tier-table matching was case-insensitive
 * while the driver executes the caller's ORIGINAL bytes — the gate
 * could sign an execution of a byte string it never classified. Tier
 * rows now match case-sensitively: a case variant is an unlisted
 * spelling and falls through RED, like abbreviations always have.
 * (cisco_is_black_tier stays case-insensitive on purpose: a DENY list
 * over-matching is fail-closed, and BLACK never executes —
 * test_driver_cisco_black.c pins "RELOAD" == BLACK.)
 */
static void test_no_case_folding(void)
{
    printf("\n=== No case folding (classified == executed bytes) ===\n");
    TEST("SHOW VERSION -> RED");     assert(cisco_gate_tier("SHOW VERSION") == VIRP_TIER_RED); PASS();
    TEST("Show version -> RED");     assert(cisco_gate_tier("Show version") == VIRP_TIER_RED); PASS();
    TEST("sHoW iP rOuTe -> RED");    assert(cisco_gate_tier("sHoW iP rOuTe") == VIRP_TIER_RED); PASS();
    TEST("SHOW RUNNING-CONFIG -> RED (was YELLOW row)");
    assert(cisco_gate_tier("SHOW RUNNING-CONFIG") == VIRP_TIER_RED); PASS();
    TEST("show version (control, exact case) -> GREEN");
    assert(cisco_gate_tier("show version") == VIRP_TIER_GREEN); PASS();
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

static void test_promotions(void)
{
    printf("\n=== Shadow-evidence promotions ===\n");
    /* GREEN — routing adjacency + status */
    TEST("show ip ospf neighbor -> GREEN");     assert(cisco_gate_tier("show ip ospf neighbor") == VIRP_TIER_GREEN); PASS();
    TEST("show ip bgp summary -> GREEN");        assert(cisco_gate_tier("show ip bgp summary") == VIRP_TIER_GREEN); PASS();
    TEST("show ip eigrp neighbors -> GREEN");    assert(cisco_gate_tier("show ip eigrp neighbors") == VIRP_TIER_GREEN); PASS();
    TEST("show ip ssh -> GREEN");                assert(cisco_gate_tier("show ip ssh") == VIRP_TIER_GREEN); PASS();
    TEST("show arp -> GREEN");                   assert(cisco_gate_tier("show arp") == VIRP_TIER_GREEN); PASS();
    TEST("show etherchannel summary -> GREEN");  assert(cisco_gate_tier("show etherchannel summary") == VIRP_TIER_GREEN); PASS();
    TEST("show redundancy -> GREEN");            assert(cisco_gate_tier("show redundancy") == VIRP_TIER_GREEN); PASS();
    TEST("show platform -> GREEN");              assert(cisco_gate_tier("show platform resources") == VIRP_TIER_GREEN); PASS();
    TEST("show memory statistics -> GREEN");     assert(cisco_gate_tier("show memory statistics") == VIRP_TIER_GREEN); PASS();
    TEST("show ntp associations -> GREEN");      assert(cisco_gate_tier("show ntp associations") == VIRP_TIER_GREEN); PASS();
    TEST("show bootvar -> GREEN");               assert(cisco_gate_tier("show bootvar") == VIRP_TIER_GREEN); PASS();
    TEST("show boot -> GREEN");                  assert(cisco_gate_tier("show boot") == VIRP_TIER_GREEN); PASS();
    TEST("show file systems -> GREEN");          assert(cisco_gate_tier("show file systems") == VIRP_TIER_GREEN); PASS();
    /* YELLOW — config-visibility / security posture / session / diagnostics */
    TEST("show ip access-lists -> YELLOW");      assert(cisco_gate_tier("show ip access-lists") == VIRP_TIER_YELLOW); PASS();
    TEST("show crypto isakmp sa -> YELLOW");     assert(cisco_gate_tier("show crypto isakmp sa") == VIRP_TIER_YELLOW); PASS();
    TEST("show crypto ipsec sa -> YELLOW");      assert(cisco_gate_tier("show crypto ipsec sa") == VIRP_TIER_YELLOW); PASS();
    TEST("show logging -> YELLOW");              assert(cisco_gate_tier("show logging") == VIRP_TIER_YELLOW); PASS();
    TEST("show users -> YELLOW");                assert(cisco_gate_tier("show users") == VIRP_TIER_YELLOW); PASS();
    TEST("show port-security -> YELLOW");        assert(cisco_gate_tier("show port-security address") == VIRP_TIER_YELLOW); PASS();
    TEST("ping -> YELLOW");                      assert(cisco_gate_tier("ping 10.0.0.1") == VIRP_TIER_YELLOW); PASS();
    TEST("traceroute -> YELLOW");                assert(cisco_gate_tier("traceroute 10.0.0.1") == VIRP_TIER_YELLOW); PASS();
}

static void test_prefix_safety(void)
{
    printf("\n=== Longest-prefix safety (the class of gap that bit us before) ===\n");
    /* No broad "show ip" GREEN entry shadows the YELLOW config-reads:
     * the ip-routing reads are GREEN, yet show ip access-lists and the
     * full-config reads stay YELLOW. */
    TEST("show ip ospf -> GREEN while show ip access-lists -> YELLOW");
    assert(cisco_gate_tier("show ip ospf neighbor") == VIRP_TIER_GREEN);
    assert(cisco_gate_tier("show ip access-lists") == VIRP_TIER_YELLOW);
    PASS();
    TEST("show ip bgp -> GREEN while show running-config -> YELLOW");
    assert(cisco_gate_tier("show ip bgp summary") == VIRP_TIER_GREEN);
    assert(cisco_gate_tier("show running-config") == VIRP_TIER_YELLOW);
    PASS();
    TEST("show ip eigrp -> GREEN while show startup-config -> YELLOW");
    assert(cisco_gate_tier("show ip eigrp neighbors") == VIRP_TIER_GREEN);
    assert(cisco_gate_tier("show startup-config") == VIRP_TIER_YELLOW);
    PASS();

    /* The read entry "show crypto" (YELLOW) must NOT soften the bare
     * "crypto ..." config write (RED). */
    TEST("show crypto -> YELLOW but crypto key generate -> RED");
    assert(cisco_gate_tier("show crypto isakmp sa") == VIRP_TIER_YELLOW);
    assert(cisco_gate_tier("crypto key generate rsa") == VIRP_TIER_RED);
    PASS();
    TEST("show crypto -> YELLOW but crypto pki trustpoint -> RED");
    assert(cisco_gate_tier("show crypto ipsec sa") == VIRP_TIER_YELLOW);
    assert(cisco_gate_tier("crypto pki trustpoint TP") == VIRP_TIER_RED);
    PASS();

    /* ping/traceroute (YELLOW diagnostics) must not soften any write. */
    TEST("ping -> YELLOW but no shutdown -> RED (write unaffected)");
    assert(cisco_gate_tier("ping 10.0.0.1") == VIRP_TIER_YELLOW);
    assert(cisco_gate_tier("no shutdown") == VIRP_TIER_RED);
    PASS();
}

/*
 * Multi-command bypass reproduction (expected to FAIL pre-fix).
 *
 * cisco_gate_tier() prefix-matches from index 0 and its leading-
 * whitespace skip covers only ' ' and '\t' — not '\n'. So a string whose
 * FIRST line is GREEN classifies GREEN no matter what follows the
 * newline, while cisco_execute() sends the whole string to the device
 * where '\n' separates commands. Anything past the first newline reaches
 * the wire unclassified.
 */
static void test_multicommand_bypass(void)
{
    printf("\n=== Multi-command (embedded newline) must not classify GREEN ===\n");

    TEST("show version\\nreload -> not GREEN");
    assert(cisco_gate_tier("show version\nreload") != VIRP_TIER_GREEN);
    PASS();

    TEST("show version\\nconfigure terminal -> not GREEN");
    assert(cisco_gate_tier("show version\nconfigure terminal") != VIRP_TIER_GREEN);
    PASS();

    /* Semicolon and CR are the same class of separator. */
    TEST("show clock\\r\\nreload -> not GREEN");
    assert(cisco_gate_tier("show clock\r\nreload") != VIRP_TIER_GREEN);
    PASS();

    /* The BLACK list is anchored at index 0 too, so an embedded
     * destructive command is invisible to it. */
    TEST("show version\\nerase startup-config -> not GREEN");
    assert(cisco_gate_tier("show version\nerase startup-config") != VIRP_TIER_GREEN);
    PASS();
}

/*
 * Layer 2a — every separator class fails closed in the classifier
 * itself, independently of the daemon's layer-1 boundary rejection.
 */
static void test_separator_fails_closed(void)
{
    printf("\n=== Layer 2a — separators fail closed to RED ===\n");

    TEST("semicolon: show version;reload -> RED");
    assert(cisco_gate_tier("show version;reload") == VIRP_TIER_RED); PASS();

    TEST("pipe: show version|reload -> RED");
    assert(cisco_gate_tier("show version|reload") == VIRP_TIER_RED); PASS();

    TEST("ampersand: show version&reload -> RED");
    assert(cisco_gate_tier("show version&reload") == VIRP_TIER_RED); PASS();

    TEST("backtick: show version`reload` -> RED");
    assert(cisco_gate_tier("show version`reload`") == VIRP_TIER_RED); PASS();

    TEST("command subst: show version$(reload) -> RED");
    assert(cisco_gate_tier("show version$(reload)") == VIRP_TIER_RED); PASS();

    TEST("brace expansion: show version${x} -> RED");
    assert(cisco_gate_tier("show version${x}") == VIRP_TIER_RED); PASS();

    TEST("carriage return: show clock\\rreload -> RED");
    assert(cisco_gate_tier("show clock\rreload") == VIRP_TIER_RED); PASS();

    TEST("double ampersand: show version&&reload -> RED");
    assert(cisco_gate_tier("show version&&reload") == VIRP_TIER_RED); PASS();

    TEST("leading newline: \\nreload -> RED");
    assert(cisco_gate_tier("\nreload") == VIRP_TIER_RED); PASS();

    TEST("embedded tab: show version\\treload -> RED");
    assert(cisco_gate_tier("show version\treload") == VIRP_TIER_RED); PASS();

    TEST("trailing newline: show version\\n -> RED");
    assert(cisco_gate_tier("show version\n") == VIRP_TIER_RED); PASS();
}

/*
 * Layer 2b — a matched prefix must end on a token boundary, so a listed
 * entry can never stand in for a longer word. This is a distinct bug
 * class from the separator check: no separator is involved.
 */
static void test_token_boundary(void)
{
    printf("\n=== Layer 2b — matches must end on a token boundary ===\n");

    /* "show boot" is GREEN; a longer word starting with it must not
     * inherit that tier. */
    TEST("show bootleg -> not GREEN (show boot must not cover it)");
    assert(cisco_gate_tier("show bootleg") != VIRP_TIER_GREEN); PASS();

    TEST("show versionitis -> not GREEN");
    assert(cisco_gate_tier("show versionitis") != VIRP_TIER_GREEN); PASS();

    TEST("show clockwork -> not GREEN");
    assert(cisco_gate_tier("show clockwork") != VIRP_TIER_GREEN); PASS();

    TEST("pingu -> not YELLOW (ping must not cover it)");
    assert(cisco_gate_tier("pingu") != VIRP_TIER_YELLOW); PASS();

    /* Boundary rule must not break legitimate matches: exact match,
     * match followed by arguments, and self-terminated entries. */
    TEST("exact match still classifies: show version -> GREEN");
    assert(cisco_gate_tier("show version") == VIRP_TIER_GREEN); PASS();

    TEST("args still classify: show interfaces Gi0/0 -> GREEN");
    assert(cisco_gate_tier("show interfaces GigabitEthernet0/0")
           == VIRP_TIER_GREEN); PASS();

    TEST("self-terminated entry: no shutdown -> RED (via \"no \")");
    assert(cisco_gate_tier("no shutdown") == VIRP_TIER_RED); PASS();

    /* Longest-valid-match still wins once short matches are boundary-
     * rejected: "show bootvar" must beat "show boot". */
    TEST("longest valid match wins: show bootvar -> GREEN");
    assert(cisco_gate_tier("show bootvar") == VIRP_TIER_GREEN); PASS();
}

extern size_t cisco_gate_table_count(void);
extern const char *cisco_gate_table_entry(size_t i, virp_trust_tier_t *tier);

/* Tier name helper for the table-driven suite's labels. */
static const char *tier_name(virp_trust_tier_t t)
{
    switch (t) {
    case VIRP_TIER_GREEN:  return "GREEN";
    case VIRP_TIER_YELLOW: return "YELLOW";
    case VIRP_TIER_RED:    return "RED";
    case VIRP_TIER_BLACK:  return "BLACK";
    default:               return "UNCLASSIFIED";
    }
}

/* =========================================================================
 * Table-driven reachability + declared-tier suite
 *
 * Iterates Cisco IOS/IOS-XE's OWN classification table and asserts, for every
 * entry, that cisco_gate_tier(entry) returns the tier that entry declares.
 *
 * This is not tautological. It proves two things hand-written cases
 * cannot:
 *   1. REACHABILITY — an entry shadowed by a broader or earlier entry
 *      would silently never fire. A BLACK or RED entry shadowed by a
 *      GREEN one is a live vulnerability. This table is longest-match.
 *   2. The entry returns its declared tier through the REAL matching
 *      logic, including the separator and token-boundary rules.
 *
 * Any new entry is covered automatically the moment it is added.
 * ========================================================================= */

static void test_table_driven_all_entries(void)
{
    printf("\n=== Table-driven: every table entry reachable + correctly tiered ===\n");
    size_t total = cisco_gate_table_count();
    size_t skipped = 0;

    for (size_t i = 0; i < total; i++) {
        virp_trust_tier_t declared;
        const char *cmd = cisco_gate_table_entry(i, &declared);
        assert(cmd != NULL);

        char label[192];
        snprintf(label, sizeof(label), "entry[%zu] %s -> %s",
                 i, cmd, tier_name(declared));
        TEST(label);
        virp_trust_tier_t got = cisco_gate_tier(cmd);
        if (got != declared) {
            printf("\n    SHADOWED or MIS-TIERED: \"%s\" declares %s but "
                   "classifies %s\n", cmd, tier_name(declared), tier_name(got));
            assert(got == declared);
        }
        PASS();
    }

    printf("  (%zu entries checked, %zu known-dead skipped)\n",
           total - skipped, skipped);
}

int main(void)
{
    printf("VIRP Cisco IOS/IOS-XE Gate Classifier — Unit Tests\n");
    printf("==================================================\n");
    test_green();
    test_yellow();
    test_red_config_writes();
    test_red_credential_writes();
    test_no_case_folding();
    test_fail_closed();
    test_promotions();
    test_prefix_safety();
    test_multicommand_bypass();
    test_separator_fails_closed();
    test_token_boundary();
    test_table_driven_all_entries();
    printf("\n==================================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
