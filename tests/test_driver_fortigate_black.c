/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * FortiGate Driver — BLACK Tier Enforcement Tests
 *
 * Verifies that all destructive commands are blocked at the driver
 * level before any bytes hit the wire.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

/* We only need the black tier check — no SSH, no libssh2 */
extern bool fg_is_black_tier(const char *command);

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

int main(void)
{
    printf("VIRP FortiGate Driver — BLACK Tier Enforcement Tests\n");
    printf("====================================================\n");

    test_black_tier_blocked();
    test_non_black_passthrough();

    printf("\n====================================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
