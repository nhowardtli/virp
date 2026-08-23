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
#include "virp_driver_cisco_modes.h"
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

/* =========================================================================
 * Prompt-mode classification (config-mode support)
 *
 * cisco_parse_mode / cisco_is_mode_changing are the pure halves of the
 * config-mode transition recovery in cisco_execute: a read that ends
 * without the learned prompt is accepted as a mode transition ONLY for
 * a mode-changing command AND only when the re-learned prompt parses
 * to a known mode. These pin both classifiers.
 * ========================================================================= */

static void test_parse_mode(void)
{
    printf("\n=== Prompt-mode parsing ===\n");

    TEST("R24# -> EXEC");
    assert(cisco_parse_mode("R24#") == CISCO_MODE_EXEC);
    PASS();

    TEST("R24> -> USER");
    assert(cisco_parse_mode("R24>") == CISCO_MODE_USER);
    PASS();

    TEST("R24(config)# -> CONFIG");
    assert(cisco_parse_mode("R24(config)#") == CISCO_MODE_CONFIG);
    PASS();

    TEST("R24(config-if)# -> CONFIG_SUB");
    assert(cisco_parse_mode("R24(config-if)#") == CISCO_MODE_CONFIG_SUB);
    PASS();

    TEST("R24(config-router)# -> CONFIG_SUB");
    assert(cisco_parse_mode("R24(config-router)#") == CISCO_MODE_CONFIG_SUB);
    PASS();

    TEST("R24(config-line)# -> CONFIG_SUB");
    assert(cisco_parse_mode("R24(config-line)#") == CISCO_MODE_CONFIG_SUB);
    PASS();

    TEST("trailing space tolerated: 'R24# '");
    assert(cisco_parse_mode("R24# ") == CISCO_MODE_EXEC);
    PASS();

    TEST("trailing CRLF tolerated: 'R24(config)#\\r\\n'");
    assert(cisco_parse_mode("R24(config)#\r\n") == CISCO_MODE_CONFIG);
    PASS();

    TEST("non-config parenthesized prompt -> UNKNOWN (fail closed)");
    assert(cisco_parse_mode("R24(tcl)#") == CISCO_MODE_UNKNOWN);
    PASS();

    TEST("no #/> terminator -> UNKNOWN");
    assert(cisco_parse_mode("R24") == CISCO_MODE_UNKNOWN);
    PASS();

    TEST("empty -> UNKNOWN");
    assert(cisco_parse_mode("") == CISCO_MODE_UNKNOWN);
    PASS();

    TEST("NULL -> UNKNOWN");
    assert(cisco_parse_mode(NULL) == CISCO_MODE_UNKNOWN);
    PASS();
}

static void test_mode_changing(void)
{
    printf("\n=== Mode-changing command classification ===\n");

    TEST("configure terminal from EXEC -> mode-changing");
    assert(cisco_is_mode_changing("configure terminal", CISCO_MODE_EXEC));
    PASS();

    TEST("conf t from EXEC -> mode-changing");
    assert(cisco_is_mode_changing("conf t", CISCO_MODE_EXEC));
    PASS();

    TEST("end from CONFIG_SUB -> mode-changing");
    assert(cisco_is_mode_changing("end", CISCO_MODE_CONFIG_SUB));
    PASS();

    TEST("exit from CONFIG -> mode-changing");
    assert(cisco_is_mode_changing("exit", CISCO_MODE_CONFIG));
    PASS();

    TEST("show version from EXEC -> NOT mode-changing (strict read)");
    assert(!cisco_is_mode_changing("show version", CISCO_MODE_EXEC));
    PASS();

    TEST("show ip bgp summary from EXEC -> NOT mode-changing");
    assert(!cisco_is_mode_changing("show ip bgp summary", CISCO_MODE_EXEC));
    PASS();

    TEST("router bgp 1000 from EXEC -> NOT mode-changing (invalid there)");
    assert(!cisco_is_mode_changing("router bgp 1000", CISCO_MODE_EXEC));
    PASS();

    TEST("any command in CONFIG -> mode-changing (sub-mode moves)");
    assert(cisco_is_mode_changing("interface Loopback0", CISCO_MODE_CONFIG));
    assert(cisco_is_mode_changing("router bgp 1000", CISCO_MODE_CONFIG));
    assert(cisco_is_mode_changing("no neighbor 10.2.5.2", CISCO_MODE_CONFIG));
    PASS();

    TEST("any command in CONFIG_SUB -> mode-changing");
    assert(cisco_is_mode_changing("ip address 24.24.24.24 255.255.255.255",
                                  CISCO_MODE_CONFIG_SUB));
    PASS();

    TEST("token boundary: 'configured' is NOT mode-changing");
    assert(!cisco_is_mode_changing("configured", CISCO_MODE_EXEC));
    PASS();

    TEST("token boundary: 'config' first token is NOT 'conf'");
    assert(!cisco_is_mode_changing("config something", CISCO_MODE_EXEC));
    PASS();

    TEST("token boundary: 'exited' is NOT mode-changing");
    assert(!cisco_is_mode_changing("exited", CISCO_MODE_EXEC));
    PASS();

    TEST("NULL / empty -> NOT mode-changing");
    assert(!cisco_is_mode_changing(NULL, CISCO_MODE_CONFIG));
    assert(!cisco_is_mode_changing("   ", CISCO_MODE_CONFIG));
    PASS();
}

/* The gate must keep every config-mode command approval-gated: nothing
 * the transition recovery applies to may ever ride GREEN/YELLOW. */
extern virp_trust_tier_t cisco_gate_tier(const char *command);

static void test_config_sequence_stays_red(void)
{
    printf("\n=== Config-mode sequence commands all classify RED ===\n");

    const char *seq[] = {
        "configure terminal",
        "conf t",
        "interface Loopback0",
        "ip address 24.24.24.24 255.255.255.255",
        "router bgp 1000",
        "bgp router-id 24.24.24.24",
        "no neighbor 10.2.5.2 remote-as 1100",
        "neighbor 25.25.25.25 remote-as 1000",
        "ip route 25.25.25.25 255.255.255.255 10.0.0.74",
        "end",
        "exit",
    };
    for (size_t i = 0; i < sizeof(seq) / sizeof(seq[0]); i++) {
        char label[128];
        snprintf(label, sizeof(label), "%s -> RED", seq[i]);
        TEST(label);
        assert(cisco_gate_tier(seq[i]) == VIRP_TIER_RED);
        PASS();
    }
}

int main(void)
{
    printf("==========================================\n");
    printf("VIRP Cisco Driver Tests\n");
    printf("==========================================\n");

    test_kex_default_is_unchanged();
    test_kex_legacy_adds_group1();
    test_kex_pointers_distinct();
    test_parse_mode();
    test_mode_changing();
    test_config_sequence_stays_red();

    printf("\n==========================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);
    printf("==========================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}
