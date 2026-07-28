/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * PAN-OS Driver Unit Tests
 *
 * Tests command routing locally (no SSH). PAN-OS routing is FIRST-MATCH
 * with a word-boundary check (not longest-prefix), so these tests also
 * assert table ORDER — a broad entry must not shadow a more specific one.
 */

#include "virp.h"
#include "virp_driver.h"
#include "driver_panos.h"
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

/* =========================================================================
 * GREEN — passive monitoring reads
 * ========================================================================= */

static void test_green(void)
{
    printf("\n=== GREEN tier ===\n");

    TEST("show system info -> GREEN");
    assert(pa_route_command("show system info") == VIRP_TIER_GREEN);
    PASS();

    TEST("show interface all -> GREEN");
    assert(pa_route_command("show interface all") == VIRP_TIER_GREEN);
    PASS();

    TEST("show interface ethernet -> GREEN (bare, word boundary)");
    assert(pa_route_command("show interface ethernet") == VIRP_TIER_GREEN);
    PASS();

    TEST("show routing route -> GREEN");
    assert(pa_route_command("show routing route") == VIRP_TIER_GREEN);
    PASS();

    TEST("show session all -> GREEN");
    assert(pa_route_command("show session all") == VIRP_TIER_GREEN);
    PASS();

    TEST("show log traffic -> GREEN");
    assert(pa_route_command("show log traffic") == VIRP_TIER_GREEN);
    PASS();

    TEST("show vpn ipsec-sa -> GREEN");
    assert(pa_route_command("show vpn ipsec-sa") == VIRP_TIER_GREEN);
    PASS();
}

/* =========================================================================
 * YELLOW — config reads, active diagnostics
 * ========================================================================= */

static void test_yellow(void)
{
    printf("\n=== YELLOW tier ===\n");

    TEST("show config -> YELLOW");
    assert(pa_route_command("show config") == VIRP_TIER_YELLOW);
    PASS();

    /* Config-dump equivalent of show running-config / full-configuration.
     * Covered by the "show config" prefix — YELLOW, matching FortiGate/ASA. */
    TEST("show config running -> YELLOW (config-dump equivalent)");
    assert(pa_route_command("show config running") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show running -> YELLOW");
    assert(pa_route_command("show running") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show running security-policy -> YELLOW");
    assert(pa_route_command("show running security-policy") == VIRP_TIER_YELLOW);
    PASS();

    TEST("debug dataplane pool statistics -> YELLOW");
    assert(pa_route_command("debug dataplane pool statistics") == VIRP_TIER_YELLOW);
    PASS();

    TEST("ping host 1.1.1.1 -> YELLOW");
    assert(pa_route_command("ping host 1.1.1.1") == VIRP_TIER_YELLOW);
    PASS();

    /* Operational/topology reads — reclassified RED->YELLOW (not
     * credential-exposing; consistent with the config-read precedent). */
    TEST("show device-group -> YELLOW (operational/topology read)");
    assert(pa_route_command("show device-group") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show panorama-status -> YELLOW (reveals Panorama mgmt IP, not creds)");
    assert(pa_route_command("show panorama-status") == VIRP_TIER_YELLOW);
    PASS();
}

/* =========================================================================
 * RED — credential / sensitive reads
 * ========================================================================= */

static void test_red(void)
{
    printf("\n=== RED tier ===\n");

    TEST("show admins -> RED");
    assert(pa_route_command("show admins") == VIRP_TIER_RED);
    PASS();

    TEST("show user ip-user-mapping all -> RED");
    assert(pa_route_command("show user ip-user-mapping all") == VIRP_TIER_RED);
    PASS();

    TEST("show user group -> RED");
    assert(pa_route_command("show user group") == VIRP_TIER_RED);
    PASS();

    TEST("show user -> RED (bare, after specific show user * entries)");
    assert(pa_route_command("show user") == VIRP_TIER_RED);
    PASS();

    TEST("show certificate -> RED");
    assert(pa_route_command("show certificate") == VIRP_TIER_RED);
    PASS();

    TEST("request password-hash -> RED");
    assert(pa_route_command("request password-hash username admin") == VIRP_TIER_RED);
    PASS();
}

/* =========================================================================
 * Ordering (first-match) + word-boundary + default
 * ========================================================================= */

static void test_ordering_and_boundary(void)
{
    printf("\n=== Ordering / word-boundary / default ===\n");

    /* Specific-before-bare: bare entries must not shadow the specific ones
     * that precede them, and the bare entry must still match on its own. */
    TEST("show arp all -> GREEN (specific before bare 'show arp')");
    assert(pa_route_command("show arp all") == VIRP_TIER_GREEN);
    PASS();

    TEST("show arp -> GREEN (bare still matches)");
    assert(pa_route_command("show arp") == VIRP_TIER_GREEN);
    PASS();

    TEST("show vpn -> GREEN (bare after show vpn ipsec-sa/ike-sa/flow)");
    assert(pa_route_command("show vpn") == VIRP_TIER_GREEN);
    PASS();

    /* Cross-tier: no GREEN/YELLOW entry word-boundary-shadows a RED read. */
    TEST("show admins not shadowed by any earlier show* GREEN entry");
    assert(pa_route_command("show admins") == VIRP_TIER_RED);
    PASS();

    /* Word boundary: 'show system' alone is not a table entry; 'show system
     * info' is GREEN, but a non-boundary suffix must not false-match. */
    TEST("show systemfoo -> RED (no boundary, falls through to fail-closed default)");
    assert(pa_route_command("show systemfoo") == VIRP_TIER_RED);
    PASS();

    /* KNOWN word-boundary mis-tier: real PAN-OS interface syntax has no
     * space (ethernet1/1), so it does NOT match "show interface ethernet"
     * and falls to the YELLOW default. Fail-safe (over-restrictive, not
     * dangerous); documented here so the behavior is explicit. */
    /* RELIER on the old YELLOW default — NOT added to the table.
     * This is a legitimate command that was never listed; it executed
     * only because the no-match default cleared the gate. Now RED.
     * Listing it is a deliberate tier decision, not a bug fix. */
    TEST("show interface ethernet1/1 -> RED (word-boundary fall-through)");
    assert(pa_route_command("show interface ethernet1/1") == VIRP_TIER_RED);
    PASS();

    TEST("unmapped command -> RED (fail-closed default)");
    assert(pa_route_command("show blahblah") == VIRP_TIER_RED);
    PASS();

    TEST("null command -> RED (fail closed)");
    assert(pa_route_command(NULL) == VIRP_TIER_RED);   /* fail closed */
    PASS();
}


/* =========================================================================
 * Adversarial — separator injection (layer 3)
 *
 * The exploit shape: a benign prefix that is a REAL entry in this
 * driver's own table, followed by a separator and a command that was
 * never classified. The prefix match only ever sees the first command
 * while the driver hands the whole string to the device. Every case must
 * fail closed to RED — no benign tier may be inherited.
 *
 * PAN-OS previously accepted '\n' as a valid token boundary, which WAS
 * this driver's copy of the bypass: the GREEN entry matched and returned
 * its tier with a whole second command still attached.
 * ========================================================================= */

static void test_adversarial_separators(void)
{
    printf("\n=== Adversarial — separator injection fails closed ===\n");

    TEST("newline: show system info\\nrequest restart system -> RED");
    assert(pa_route_command("show system info\nrequest restart system") == VIRP_TIER_RED); PASS();

    TEST("carriage return: show system info\\rrequest restart system -> RED");
    assert(pa_route_command("show system info\rrequest restart system") == VIRP_TIER_RED); PASS();

    TEST("CRLF: show system info\\r\\nrequest restart system -> RED");
    assert(pa_route_command("show system info\r\nrequest restart system") == VIRP_TIER_RED); PASS();

    TEST("semicolon: show system info;request restart system -> RED");
    assert(pa_route_command("show system info;request restart system") == VIRP_TIER_RED); PASS();

    TEST("pipe: show system info|request restart system -> RED");
    assert(pa_route_command("show system info|request restart system") == VIRP_TIER_RED); PASS();

    TEST("ampersand: show system info&request restart system -> RED");
    assert(pa_route_command("show system info&request restart system") == VIRP_TIER_RED); PASS();

    TEST("double ampersand: show system info&&request restart system -> RED");
    assert(pa_route_command("show system info&&request restart system") == VIRP_TIER_RED); PASS();

    TEST("backtick: show system info`request restart system` -> RED");
    assert(pa_route_command("show system info`request restart system`") == VIRP_TIER_RED); PASS();

    TEST("command substitution: show system info$(request restart system) -> RED");
    assert(pa_route_command("show system info$(request restart system)") == VIRP_TIER_RED); PASS();

    TEST("brace expansion: show system info${x} -> RED");
    assert(pa_route_command("show system info${x}") == VIRP_TIER_RED); PASS();

    TEST("embedded tab: show system info\\trequest restart system -> RED");
    assert(pa_route_command("show system info\trequest restart system") == VIRP_TIER_RED); PASS();

    TEST("trailing newline alone: show system info\\n -> RED");
    assert(pa_route_command("show system info\n") == VIRP_TIER_RED); PASS();

    TEST("leading newline: \\nrequest restart system -> RED");
    assert(pa_route_command("\nrequest restart system") == VIRP_TIER_RED); PASS();
}

/* =========================================================================
 * Legitimate-match regressions (layer 3)
 *
 * The separator/boundary rules must not become over-broad. If a future
 * edit starts rejecting valid PAN-OS commands, these fail loudly here
 * rather than degrading the fleet quietly.
 * ========================================================================= */

static void test_legit_matches_unaffected(void)
{
    printf("\n=== Legitimate commands still classify ===\n");

    TEST("exact GREEN entry: show system info");
    assert(pa_route_command("show system info") == VIRP_TIER_GREEN); PASS();

    TEST("GREEN entry: show system resources");
    assert(pa_route_command("show system resources") == VIRP_TIER_GREEN); PASS();

    TEST("RED credential read: show admins");
    assert(pa_route_command("show admins") == VIRP_TIER_RED); PASS();

    TEST("YELLOW topology read: show device-group");
    assert(pa_route_command("show device-group") == VIRP_TIER_YELLOW); PASS();
}


/* =========================================================================
 * No-match default must FAIL CLOSED (P0)
 *
 * PAN-OS's classifier returned YELLOW when no table entry matched. The
 * default gate threshold is YELLOW, so an unlisted command CLEARED the
 * gate and executed. Only the Cisco classifier failed closed to RED.
 *
 * Each command below is plausible, unlisted, and state-changing or
 * sensitive — every one of them executed before this change.
 * ========================================================================= */

static void test_no_match_fails_closed(void)
{
    printf("\n=== No-match default fails closed to RED ===\n");

    TEST("unlisted: commit -> RED (applies the entire candidate configuration)");
    assert(pa_route_command("commit") == VIRP_TIER_RED); PASS();

    TEST("unlisted: delete rulebase security rules TRUST-ANY -> RED (deletes a firewall rule)");
    assert(pa_route_command("delete rulebase security rules TRUST-ANY") == VIRP_TIER_RED); PASS();

    TEST("unlisted: set deviceconfig system permitted-ip 0.0.0.0 -> RED (opens mgmt to the world)");
    assert(pa_route_command("set deviceconfig system permitted-ip 0.0.0.0") == VIRP_TIER_RED); PASS();

    TEST("unlisted: request restart system -> RED (reboots the firewall)");
    assert(pa_route_command("request restart system") == VIRP_TIER_RED); PASS();

    TEST("NULL command -> RED (fail closed)");
    assert(pa_route_command(NULL) == VIRP_TIER_RED); PASS();
}


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
 * Iterates PAN-OS's OWN classification table and asserts, for every
 * entry, that pa_route_command(entry) returns the tier that entry declares.
 *
 * This is not tautological. It proves two things hand-written cases
 * cannot:
 *   1. REACHABILITY — an entry shadowed by a broader or earlier entry
 *      would silently never fire. A BLACK or RED entry shadowed by a
 *      GREEN one is a live vulnerability. This table is FIRST-match, not longest-match, so ordering
 *      is load-bearing: a broad entry placed above a specific one
 *      would swallow it.
 *   2. The entry returns its declared tier through the REAL matching
 *      logic, including the separator and token-boundary rules.
 *
 * Any new entry is covered automatically the moment it is added.
 * ========================================================================= */

static void test_table_driven_all_entries(void)
{
    printf("\n=== Table-driven: every table entry reachable + correctly tiered ===\n");
    size_t total = PA_ROUTE_TABLE_SIZE;
    size_t skipped = 0;

    for (size_t i = 0; i < total; i++) {
        const char *cmd = PA_ROUTE_TABLE[i].command_pattern;
        virp_trust_tier_t declared = PA_ROUTE_TABLE[i].tier;

        char label[192];
        snprintf(label, sizeof(label), "entry[%zu] %s -> %s",
                 i, cmd, tier_name(declared));
        TEST(label);
        virp_trust_tier_t got = pa_route_command(cmd);
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
    printf("VIRP PAN-OS Driver — Unit Tests\n");
    printf("================================\n");

    test_green();
    test_yellow();
    test_red();
    test_ordering_and_boundary();

    test_adversarial_separators();
    test_legit_matches_unaffected();
    test_no_match_fails_closed();
    test_table_driven_all_entries();
    printf("\n================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
