/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco Driver Unit Tests
 *
 * Tests the parts of the Cisco driver that can be exercised without an
 * actual SSH connection. Live device tests live in test_live.c.
 */

#include "virp.h"
#include "virp_driver.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/*
 * KEX-list accessor exposed by driver_cisco.c for issue #5. Returning
 * a const char * means the test can grep the string directly without
 * copying.
 */
extern const char *virp_cisco_kex_list(bool ssh_legacy);

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %s ... ", tests_run, name); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)

/* =========================================================================
 * KEX preference (issue #5)
 *
 * Pre-fix: the cisco driver advertised a single KEX list that omitted
 * diffie-hellman-group1-sha1, so pre-2014 IOS 12.x devices (Snowacki's
 * report) couldn't handshake.
 *
 * Post-fix: ssh_legacy=true extends the list with group1-sha1, but the
 * default path stays exactly as it was — these tests guard against
 * accidentally weakening the default for modern devices in the future.
 * ========================================================================= */

static void test_kex_default_is_unchanged(void)
{
    printf("\n=== KEX: default (ssh_legacy=false) ===\n");

    const char *kex = virp_cisco_kex_list(false);
    assert(kex != NULL);

    TEST("default KEX includes ecdh-sha2-nistp256");
    assert(strstr(kex, "ecdh-sha2-nistp256") != NULL);
    PASS();

    TEST("default KEX includes ecdh-sha2-nistp384");
    assert(strstr(kex, "ecdh-sha2-nistp384") != NULL);
    PASS();

    TEST("default KEX includes ecdh-sha2-nistp521");
    assert(strstr(kex, "ecdh-sha2-nistp521") != NULL);
    PASS();

    TEST("default KEX includes diffie-hellman-group14-sha256");
    assert(strstr(kex, "diffie-hellman-group14-sha256") != NULL);
    PASS();

    TEST("default KEX includes diffie-hellman-group14-sha1");
    assert(strstr(kex, "diffie-hellman-group14-sha1") != NULL);
    PASS();

    TEST("default KEX includes diffie-hellman-group-exchange-sha256");
    assert(strstr(kex, "diffie-hellman-group-exchange-sha256") != NULL);
    PASS();

    TEST("default KEX includes diffie-hellman-group-exchange-sha1");
    assert(strstr(kex, "diffie-hellman-group-exchange-sha1") != NULL);
    PASS();

    /* The whole point of leaving the default alone: legacy group1-sha1
     * must NOT leak into the modern-device path. */
    TEST("default KEX does NOT include diffie-hellman-group1-sha1");
    assert(strstr(kex, "diffie-hellman-group1-sha1") == NULL);
    PASS();

    /* Sanity: first offering is the strongest. libssh2 negotiates in
     * order, so an mis-ordered list would silently downgrade. */
    TEST("default KEX starts with ecdh-sha2-nistp256");
    assert(strncmp(kex, "ecdh-sha2-nistp256",
                   strlen("ecdh-sha2-nistp256")) == 0);
    PASS();
}

static void test_kex_legacy_adds_group1(void)
{
    printf("\n=== KEX: ssh_legacy=true ===\n");

    const char *kex = virp_cisco_kex_list(true);
    assert(kex != NULL);

    TEST("legacy KEX includes diffie-hellman-group1-sha1");
    assert(strstr(kex, "diffie-hellman-group1-sha1") != NULL);
    PASS();

    /* Legacy must remain a superset of the default — we don't want
     * ssh_legacy=true to silently disable modern algos. */
    TEST("legacy KEX still includes ecdh-sha2-nistp256");
    assert(strstr(kex, "ecdh-sha2-nistp256") != NULL);
    PASS();

    TEST("legacy KEX still includes diffie-hellman-group14-sha256");
    assert(strstr(kex, "diffie-hellman-group14-sha256") != NULL);
    PASS();

    TEST("legacy KEX still includes diffie-hellman-group14-sha1");
    assert(strstr(kex, "diffie-hellman-group14-sha1") != NULL);
    PASS();

    /* Negotiation ordering: weak algos must be offered last, so a
     * peer that supports anything stronger wins. */
    const char *modern_pos = strstr(kex, "ecdh-sha2-nistp256");
    const char *legacy_pos = strstr(kex, "diffie-hellman-group1-sha1");
    TEST("legacy KEX offers group1-sha1 last (after modern algos)");
    assert(modern_pos != NULL && legacy_pos != NULL);
    assert(modern_pos < legacy_pos);
    PASS();
}

static void test_kex_pointers_distinct(void)
{
    printf("\n=== KEX: accessor ===\n");

    TEST("default and legacy lists are different strings");
    assert(strcmp(virp_cisco_kex_list(false),
                  virp_cisco_kex_list(true)) != 0);
    PASS();

    TEST("repeated calls return stable pointers");
    const char *a = virp_cisco_kex_list(false);
    const char *b = virp_cisco_kex_list(false);
    assert(a == b);
    PASS();
}

int main(void)
{
    printf("==========================================\n");
    printf("VIRP Cisco Driver Tests\n");
    printf("==========================================\n");

    test_kex_default_is_unchanged();
    test_kex_legacy_adds_group1();
    test_kex_pointers_distinct();

    printf("\n==========================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);
    printf("==========================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}
