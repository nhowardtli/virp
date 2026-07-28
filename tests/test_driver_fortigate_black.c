/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * FortiGate Driver — BLACK Tier Enforcement Tests
 *
 * Verifies that all destructive commands are blocked at the driver
 * level before any bytes hit the wire.
 */

#include "virp.h"
#include "virp_driver.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

/* BLACK-tier check plus the gate classifier — no SSH, no libssh2. */
extern bool fg_is_black_tier(const char *command);
extern virp_trust_tier_t fg_route_command(const char *command);

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
 * BLACK Tier: Commands That Must Be Blocked
 * ========================================================================= */

static void test_black_tier_blocked(void)
{
    printf("\n=== BLACK Tier — Must Be Blocked ===\n");

    TEST("execute factoryreset → BLACK");
    assert(fg_is_black_tier("execute factoryreset") == true);
    PASS();

    TEST("execute formatdisk → BLACK");
    assert(fg_is_black_tier("execute formatdisk") == true);
    PASS();

    TEST("execute reboot → BLACK");
    assert(fg_is_black_tier("execute reboot") == true);
    PASS();

    TEST("execute shutdown → BLACK");
    assert(fg_is_black_tier("execute shutdown") == true);
    PASS();

    TEST("fnsysctl ls → BLACK");
    assert(fg_is_black_tier("fnsysctl ls /") == true);
    PASS();

    TEST("fnsysctl cat → BLACK");
    assert(fg_is_black_tier("fnsysctl cat /etc/shadow") == true);
    PASS();

    TEST("fnsysctl ifconfig → BLACK");
    assert(fg_is_black_tier("fnsysctl ifconfig") == true);
    PASS();

    /* Case insensitivity */
    TEST("EXECUTE FACTORYRESET → BLACK (case insensitive)");
    assert(fg_is_black_tier("EXECUTE FACTORYRESET") == true);
    PASS();

    TEST("Execute Reboot → BLACK (case insensitive)");
    assert(fg_is_black_tier("Execute Reboot") == true);
    PASS();

    TEST("FNSYSCTL → BLACK (case insensitive)");
    assert(fg_is_black_tier("FNSYSCTL ls") == true);
    PASS();
}

/* =========================================================================
 * Non-BLACK: Commands That Must Pass Through
 * ========================================================================= */

static void test_non_black_passthrough(void)
{
    printf("\n=== Non-BLACK — Must Pass Through ===\n");

    TEST("get system status → not BLACK");
    assert(fg_is_black_tier("get system status") == false);
    PASS();

    TEST("get system interface → not BLACK");
    assert(fg_is_black_tier("get system interface") == false);
    PASS();

    TEST("execute ping → not BLACK");
    assert(fg_is_black_tier("execute ping 10.0.0.1") == false);
    PASS();

    TEST("execute traceroute → not BLACK");
    assert(fg_is_black_tier("execute traceroute 10.0.0.1") == false);
    PASS();

    TEST("execute ssh → not BLACK");
    assert(fg_is_black_tier("execute ssh admin@10.0.0.1") == false);
    PASS();

    TEST("diagnose sys session stat → not BLACK");
    assert(fg_is_black_tier("diagnose sys session stat") == false);
    PASS();

    TEST("diagnose sniffer packet → not BLACK");
    assert(fg_is_black_tier("diagnose sniffer packet any") == false);
    PASS();

    TEST("null → not BLACK");
    assert(fg_is_black_tier(NULL) == false);
    PASS();

    TEST("empty string → not BLACK");
    assert(fg_is_black_tier("") == false);
    PASS();

    /* 'execute' alone should NOT match */
    TEST("execute (bare) → not BLACK");
    assert(fg_is_black_tier("execute") == false);
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */


/* =========================================================================
 * Adversarial — separator injection (layer 3)
 *
 * The exploit shape: a benign prefix that is a REAL entry in this
 * driver's own table, followed by a separator and a command that was
 * never classified. The prefix match only ever sees the first command
 * while the driver hands the whole string to the device. Every case must
 * fail closed to RED — no benign tier may be inherited.
 *
 * "execute reboot" is a BLACK command here, so the injected half is
 * precisely what must never reach the wire.
 * ========================================================================= */

static void test_adversarial_separators(void)
{
    printf("\n=== Adversarial — separator injection fails closed ===\n");

    TEST("newline: get system status\\nexecute reboot -> RED");
    assert(fg_route_command("get system status\nexecute reboot") == VIRP_TIER_RED); PASS();

    TEST("carriage return: get system status\\rexecute reboot -> RED");
    assert(fg_route_command("get system status\rexecute reboot") == VIRP_TIER_RED); PASS();

    TEST("CRLF: get system status\\r\\nexecute reboot -> RED");
    assert(fg_route_command("get system status\r\nexecute reboot") == VIRP_TIER_RED); PASS();

    TEST("semicolon: get system status;execute reboot -> RED");
    assert(fg_route_command("get system status;execute reboot") == VIRP_TIER_RED); PASS();

    TEST("pipe: get system status|execute reboot -> RED");
    assert(fg_route_command("get system status|execute reboot") == VIRP_TIER_RED); PASS();

    TEST("ampersand: get system status&execute reboot -> RED");
    assert(fg_route_command("get system status&execute reboot") == VIRP_TIER_RED); PASS();

    TEST("double ampersand: get system status&&execute reboot -> RED");
    assert(fg_route_command("get system status&&execute reboot") == VIRP_TIER_RED); PASS();

    TEST("backtick: get system status`execute reboot` -> RED");
    assert(fg_route_command("get system status`execute reboot`") == VIRP_TIER_RED); PASS();

    TEST("command substitution: get system status$(execute reboot) -> RED");
    assert(fg_route_command("get system status$(execute reboot)") == VIRP_TIER_RED); PASS();

    TEST("brace expansion: get system status${x} -> RED");
    assert(fg_route_command("get system status${x}") == VIRP_TIER_RED); PASS();

    TEST("embedded tab: get system status\\texecute reboot -> RED");
    assert(fg_route_command("get system status\texecute reboot") == VIRP_TIER_RED); PASS();

    TEST("trailing newline alone: get system status\\n -> RED");
    assert(fg_route_command("get system status\n") == VIRP_TIER_RED); PASS();

    TEST("leading newline: \\nexecute reboot -> RED");
    assert(fg_route_command("\nexecute reboot") == VIRP_TIER_RED); PASS();
}

/* =========================================================================
 * Legitimate-match regressions (layer 3)
 *
 * The separator/boundary rules must not become over-broad. If a future
 * edit starts rejecting valid FortiGate commands, these fail loudly here
 * rather than degrading the fleet quietly.
 * ========================================================================= */

static void test_legit_matches_unaffected(void)
{
    printf("\n=== Legitimate commands still classify ===\n");

    TEST("exact GREEN entry: get system status");
    assert(fg_route_command("get system status") == VIRP_TIER_GREEN); PASS();

    TEST("longest match: get router info ...");
    assert(fg_route_command("get router info routing-table all") == VIRP_TIER_GREEN); PASS();

    TEST("YELLOW backup path: show full-configuration");
    assert(fg_route_command("show full-configuration") == VIRP_TIER_YELLOW); PASS();

    TEST("RED credential read: show system admin");
    assert(fg_route_command("show system admin") == VIRP_TIER_RED); PASS();

    TEST("RED config-mode change: config system admin");
    assert(fg_route_command("config system admin") == VIRP_TIER_RED); PASS();
}

int main(void)
{
    printf("VIRP FortiGate Driver — BLACK Tier Enforcement Tests\n");
    printf("====================================================\n");

    test_black_tier_blocked();
    test_non_black_passthrough();

    test_adversarial_separators();
    test_legit_matches_unaffected();
    printf("\n====================================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
