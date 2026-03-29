/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco IOS Driver — BLACK Tier Enforcement Tests
 *
 * Verifies that all destructive commands are blocked at the driver
 * level before any bytes hit the wire.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

/* We only need the black tier check — no SSH, no libssh2 */
extern bool cisco_is_black_tier(const char *command);

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

    TEST("reload → BLACK");
    assert(cisco_is_black_tier("reload") == true);
    PASS();

    TEST("reload (with args) → BLACK");
    assert(cisco_is_black_tier("reload in 5") == true);
    PASS();

    TEST("write erase → BLACK");
    assert(cisco_is_black_tier("write erase") == true);
    PASS();

    TEST("erase startup-config → BLACK");
    assert(cisco_is_black_tier("erase startup-config") == true);
    PASS();

    TEST("erase startup → BLACK");
    assert(cisco_is_black_tier("erase startup") == true);
    PASS();

    TEST("delete flash: → BLACK");
    assert(cisco_is_black_tier("delete flash:vlan.dat") == true);
    PASS();

    TEST("delete bootflash: → BLACK");
    assert(cisco_is_black_tier("delete bootflash:old-image.bin") == true);
    PASS();

    TEST("delete nvram: → BLACK");
    assert(cisco_is_black_tier("delete nvram:startup-config") == true);
    PASS();

    TEST("squeeze flash: → BLACK");
    assert(cisco_is_black_tier("squeeze flash:") == true);
    PASS();

    TEST("format flash: → BLACK");
    assert(cisco_is_black_tier("format flash:") == true);
    PASS();

    TEST("format bootflash: → BLACK");
    assert(cisco_is_black_tier("format bootflash:") == true);
    PASS();

    /* Case insensitivity */
    TEST("RELOAD → BLACK (case insensitive)");
    assert(cisco_is_black_tier("RELOAD") == true);
    PASS();

    TEST("Write Erase → BLACK (case insensitive)");
    assert(cisco_is_black_tier("Write Erase") == true);
    PASS();
}

/* =========================================================================
 * Non-BLACK: Commands That Must Pass Through
 * ========================================================================= */

static void test_non_black_passthrough(void)
{
    printf("\n=== Non-BLACK — Must Pass Through ===\n");

    TEST("show version → not BLACK");
    assert(cisco_is_black_tier("show version") == false);
    PASS();

    TEST("show ip interface brief → not BLACK");
    assert(cisco_is_black_tier("show ip interface brief") == false);
    PASS();

    TEST("show running-config → not BLACK");
    assert(cisco_is_black_tier("show running-config") == false);
    PASS();

    TEST("show reload → not BLACK");
    assert(cisco_is_black_tier("show reload") == false);
    PASS();

    TEST("write memory → not BLACK");
    assert(cisco_is_black_tier("write memory") == false);
    PASS();

    TEST("write terminal → not BLACK");
    assert(cisco_is_black_tier("write terminal") == false);
    PASS();

    TEST("show ip bgp summary → not BLACK");
    assert(cisco_is_black_tier("show ip bgp summary") == false);
    PASS();

    TEST("null → not BLACK");
    assert(cisco_is_black_tier(NULL) == false);
    PASS();

    TEST("empty string → not BLACK");
    assert(cisco_is_black_tier("") == false);
    PASS();

    /* 'delete' without flash:/bootflash:/nvram: should NOT match */
    TEST("delete (bare) → not BLACK");
    assert(cisco_is_black_tier("delete") == false);
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void)
{
    printf("VIRP Cisco IOS Driver — BLACK Tier Enforcement Tests\n");
    printf("====================================================\n");

    test_black_tier_blocked();
    test_non_black_passthrough();

    printf("\n====================================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
