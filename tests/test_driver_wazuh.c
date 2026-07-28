/*
 * test_driver_wazuh.c — Wazuh REST API driver tests
 *
 * Tests:
 *   1. Driver registration and lookup
 *   2. Command routing table (tier classification)
 *   3. Live JWT authentication against Wazuh Manager
 *   4. Live endpoint collection (all four collectors)
 *   5. VIRP observation signing of collected data
 *
 * Build:  make WAZUH=1 test-wazuh
 * Run:    ./build/test_driver_wazuh
 *
 * Requires: Wazuh Manager at 10.0.10.20:55000 with aiops-svc credentials.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_driver.h"
#include "virp_driver_wazuh.h"
#include "virp_crypto.h"
#include "virp_context.h"
#include "virp_message.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <curl/curl.h>

/* =========================================================================
 * Test counters
 * ========================================================================= */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

/*
 * Live-contact opt-in. Tests 3+ authenticate against a REAL Wazuh
 * manager over the network. They SKIP unless VIRP_LIVE_WAZUH=1, the
 * same shape as TestInterop_LiveCONode's VIRP_LIVE_INTEROP guard
 * (a2c01ef), so running this binary never touches a production host by
 * accident.
 */
static bool live_enabled(void)
{
    const char *v = getenv("VIRP_LIVE_WAZUH");
    return v && v[0] == '1' && v[1] == '\0';
}

#define REQUIRE_LIVE(name) do { \
    if (!live_enabled()) { \
        printf("  [SKIP] %s — set VIRP_LIVE_WAZUH=1 to enable "\
               "(contacts a real Wazuh manager)\n", name); \
        return; \
    } \
} while (0)

#define TEST_START(name) do { \
    tests_run++; \
    fprintf(stderr, "\n  [TEST %d] %s\n", tests_run, name); \
} while(0)

#define TEST_PASS() do { \
    tests_passed++; \
    fprintf(stderr, "  [PASS]\n"); \
} while(0)

#define TEST_FAIL(msg) do { \
    tests_failed++; \
    fprintf(stderr, "  [FAIL] %s\n", msg); \
} while(0)

/* =========================================================================
 * Test: Driver registration
 * ========================================================================= */

static void test_registration(void)
{
    TEST_START("Driver registration and lookup");

    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
    if (!drv) {
        TEST_FAIL("virp_driver_lookup(VIRP_VENDOR_WAZUH) returned NULL");
        return;
    }

    if (strcmp(drv->name, "wazuh") != 0) {
        TEST_FAIL("Driver name mismatch");
        return;
    }

    if (drv->vendor != VIRP_VENDOR_WAZUH) {
        TEST_FAIL("Driver vendor mismatch");
        return;
    }

    if (!drv->connect || !drv->execute || !drv->disconnect ||
        !drv->detect || !drv->health_check) {
        TEST_FAIL("One or more function pointers are NULL");
        return;
    }

    fprintf(stderr, "    Driver: name=%s vendor=%d\n", drv->name, drv->vendor);
    TEST_PASS();
}

/* =========================================================================
 * Test: Command routing table
 * ========================================================================= */

static void test_routing_table(void)
{
    TEST_START("Command routing table (tier classification)");

    struct {
        const char *endpoint;
        virp_trust_tier_t expected;
    } cases[] = {
        { "/agents?select=id,name,status,ip",       VIRP_TIER_GREEN  },
        { "/agents/summary/status",                  VIRP_TIER_GREEN  },
        { "/manager/status",                         VIRP_TIER_GREEN  },
        { "/manager/logs/summary",                   VIRP_TIER_GREEN  },
        { "/vulnerability/001/last_scan",            VIRP_TIER_YELLOW },
        { "/syscheck/001?limit=100",                 VIRP_TIER_YELLOW },
        { "/security/user/authenticate",             VIRP_TIER_BLACK  },
        { "/active-response",                        VIRP_TIER_BLACK  },
        { "/manager/restart",                        VIRP_TIER_BLACK  },
        /* Fail-closed: an unmapped endpoint is RED, not GREEN. The old
         * GREEN default was the most permissive tier there is. */
        { "/some/unknown/endpoint",                  VIRP_TIER_RED    },
        { "/manager/../../etc/passwd",               VIRP_TIER_RED    },
        { NULL, 0 },
    };

    int ok = 0, fail = 0;
    for (int i = 0; cases[i].endpoint; i++) {
        virp_trust_tier_t got = wz_route_endpoint(cases[i].endpoint);
        if (got == cases[i].expected) {
            ok++;
        } else {
            fail++;
            fprintf(stderr, "    MISMATCH: %s → got 0x%02x, expected 0x%02x\n",
                    cases[i].endpoint, got, cases[i].expected);
        }
    }

    fprintf(stderr, "    Routing: %d/%d passed\n", ok, ok + fail);

    if (fail > 0)
        TEST_FAIL("Routing table mismatches");
    else
        TEST_PASS();
}

/* =========================================================================
 * Test: Live JWT authentication
 * ========================================================================= */

static virp_conn_t *g_conn = NULL;  /* Shared across live tests */

static void test_live_auth(void)
{
    REQUIRE_LIVE("Live JWT authentication");
    TEST_START("Live JWT authentication (10.0.20.10:55000)");

    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
    if (!drv) {
        TEST_FAIL("Driver not registered");
        return;
    }

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    strncpy(dev.hostname, "wazuh-mgr", sizeof(dev.hostname) - 1);
    strncpy(dev.host, "10.0.20.10", sizeof(dev.host) - 1);
    dev.port = 55000;
    dev.api_port = 55000;
    strncpy(dev.username, "aiops-svc", sizeof(dev.username) - 1);
    strncpy(dev.password, "Lab2001-92!-Go-Run", sizeof(dev.password) - 1);
    dev.vendor = VIRP_VENDOR_WAZUH;
    dev.node_id = 0x24242424;
    dev.enabled = true;

    g_conn = drv->connect(&dev);
    if (!g_conn) {
        TEST_FAIL("connect() returned NULL — auth failed or host unreachable");
        return;
    }

    fprintf(stderr, "    JWT obtained, connection established\n");
    TEST_PASS();
}

/* =========================================================================
 * Test: Health check
 * ========================================================================= */

static void test_health_check(void)
{
    REQUIRE_LIVE("Health check");
    TEST_START("Health check (/manager/status)");

    if (!g_conn) {
        TEST_FAIL("No connection (auth test failed)");
        return;
    }

    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
    virp_error_t err = drv->health_check(g_conn);
    if (err != VIRP_OK) {
        char msg[128];
        snprintf(msg, sizeof(msg), "health_check returned %d", err);
        TEST_FAIL(msg);
        return;
    }

    fprintf(stderr, "    Health check passed\n");
    TEST_PASS();
}

/* =========================================================================
 * Test: Collector endpoints
 * ========================================================================= */

static void test_endpoint(const char *name, const char *endpoint)
{
    REQUIRE_LIVE(name);
    char test_name[256];
    snprintf(test_name, sizeof(test_name), "Collect: %s (%s)", name, endpoint);
    TEST_START(test_name);

    if (!g_conn) {
        TEST_FAIL("No connection (auth test failed)");
        return;
    }

    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
    virp_exec_result_t result;

    virp_error_t err = drv->execute(g_conn, endpoint, &result);
    if (err != VIRP_OK) {
        char msg[128];
        snprintf(msg, sizeof(msg), "execute() returned error %d", err);
        TEST_FAIL(msg);
        return;
    }

    if (!result.success) {
        char msg[512];
        snprintf(msg, sizeof(msg), "Command failed: %.200s (exit=%d)",
                 result.error_msg, result.exit_code);
        TEST_FAIL(msg);
        /* Still print output for debugging */
        if (result.output_len > 0) {
            fprintf(stderr, "    Output (first 500 chars):\n    %.500s\n",
                    result.output);
        }
        return;
    }

    fprintf(stderr, "    OK: %zu bytes, %lums\n",
            result.output_len, (unsigned long)result.exec_time_ms);

    /* Print first 300 chars of output */
    if (result.output_len > 0) {
        fprintf(stderr, "    Preview:\n    %.300s\n",
                result.output);
    }

    TEST_PASS();
}

/* =========================================================================
 * Test: VIRP observation signing of collected data
 * ========================================================================= */

static void test_virp_signing(void)
{
    REQUIRE_LIVE("VIRP signing over live collector output");
    TEST_START("VIRP observation signing of Wazuh data");

    if (!g_conn) {
        TEST_FAIL("No connection (auth test failed)");
        return;
    }

    /* Collect agents data */
    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
    virp_exec_result_t result;
    virp_error_t err = drv->execute(g_conn, WZ_EP_AGENTS, &result);

    if (err != VIRP_OK || !result.success) {
        TEST_FAIL("Failed to collect agent data for signing test");
        return;
    }

    /* Generate a test O-Key */
    virp_signing_key_t okey;
    err = virp_key_generate(&okey, VIRP_KEY_TYPE_OKEY);
    if (err != VIRP_OK) {
        TEST_FAIL("Failed to generate test O-Key");
        return;
    }

    /* Build a signed VIRP observation */
    uint8_t obs_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t obs_len = 0;
    uint16_t data_len = (result.output_len > 65530) ?
                         65530 : (uint16_t)result.output_len;

    err = virp_build_observation(obs_buf, sizeof(obs_buf), &obs_len,
                                 0x24242424,     /* node_id */
                                 1,              /* seq_num */
                                 VIRP_OBS_DEVICE_OUTPUT,
                                 VIRP_SCOPE_LOCAL,
                                 (const uint8_t *)result.output,
                                 data_len,
                                 &okey);

    if (err != VIRP_OK) {
        char msg[128];
        snprintf(msg, sizeof(msg),
                 "virp_build_observation failed: %d", err);
        TEST_FAIL(msg);
        virp_key_destroy(&okey);
        return;
    }

    fprintf(stderr, "    Observation built: %zu bytes (payload %u bytes)\n",
            obs_len, data_len);

    /* Verify the signature */
    err = virp_verify(NULL, obs_buf, obs_len, &okey);
    if (err != VIRP_OK) {
        char msg[128];
        snprintf(msg, sizeof(msg), "virp_verify failed: %d", err);
        TEST_FAIL(msg);
        virp_key_destroy(&okey);
        return;
    }

    fprintf(stderr, "    HMAC-SHA256 signature verified OK\n");

    /* Parse the observation back to verify structure */
    virp_header_t hdr;
    err = virp_header_deserialize(&hdr, obs_buf, obs_len);
    if (err != VIRP_OK) {
        TEST_FAIL("Failed to deserialize observation header");
        virp_key_destroy(&okey);
        return;
    }

    fprintf(stderr, "    Header: version=%u type=0x%02x channel=0x%02x "
                    "tier=0x%02x node_id=0x%08x seq=%u\n",
            hdr.version, hdr.type, hdr.channel,
            hdr.tier, hdr.node_id, hdr.seq_num);

    if (hdr.channel != VIRP_CHANNEL_OC) {
        TEST_FAIL("Observation not on OC channel");
        virp_key_destroy(&okey);
        return;
    }

    if (hdr.node_id != 0x24242424) {
        TEST_FAIL("Node ID mismatch in observation");
        virp_key_destroy(&okey);
        return;
    }

    virp_key_destroy(&okey);
    TEST_PASS();
}

/* =========================================================================
 * Test: BLACK tier rejection
 * ========================================================================= */

static void test_black_tier_rejection(void)
{
    REQUIRE_LIVE("BLACK tier rejection against the live manager");
    TEST_START("BLACK tier endpoint rejection");

    if (!g_conn) {
        TEST_FAIL("No connection (auth test failed)");
        return;
    }

    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
    virp_exec_result_t result;

    /* Try to call the auth endpoint via execute (should be blocked) */
    virp_error_t err = drv->execute(g_conn, "/security/user/authenticate", &result);
    if (err != VIRP_OK) {
        TEST_FAIL("execute() should return VIRP_OK even for blocked commands");
        return;
    }

    if (result.success) {
        TEST_FAIL("BLACK tier endpoint should have been rejected");
        return;
    }

    if (strstr(result.error_msg, "BLACK") == NULL) {
        char msg[512];
        snprintf(msg, sizeof(msg),
                 "Error msg should mention BLACK: '%.200s'", result.error_msg);
        TEST_FAIL(msg);
        return;
    }

    fprintf(stderr, "    Correctly rejected: %s\n", result.error_msg);
    TEST_PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

/*
 * KNOWN GAP — recorded here rather than in notes, deliberately skipped.
 *
 * wz_route_endpoint() prefix-matches with plain strncmp and has NO token
 * boundary rule: the layer-3 boundary work covered the five CLI drivers
 * and never reached this REST matcher. So "/agents_evil" prefix-matches
 * the GREEN "/agents" entry and inherits GREEN, exactly the class of bug
 * the boundary rule fixed elsewhere ("show boot" covering "show
 * bootleg").
 *
 * Not fixed here: this driver is wired to no route_command hook, and the
 * fix needs a boundary rule shaped for URL paths ('/' and '?' are
 * structural, not word separators), which is a design decision, not a
 * one-liner. Enable this test with the fix.
 */
static void test_known_gap_prefix_boundary(void)
{
    printf("  [SKIP] Endpoint prefix boundary — KNOWN GAP: "
           "\"/agents_evil\" matches \"/agents\" and inherits GREEN "
           "(wz_route_endpoint has no token-boundary rule)\n");
    if (0) {   /* enable with the fix */
        assert(wz_route_endpoint("/agents_evil") == VIRP_TIER_RED);
    }
}

int main(void)
{
    printf("\n");
    printf("================================================================\n");
    printf("  VIRP Wazuh Driver Tests\n");
    printf("================================================================\n");

    /* Global curl init */
    curl_global_init(CURL_GLOBAL_DEFAULT);

    /* Register all drivers */
    virp_driver_mock_init();
    virp_driver_wazuh_init();

    fprintf(stderr, "\n  Registered %d driver(s)\n", virp_driver_count());

    /* Unit tests (no network) */
    test_registration();
    test_routing_table();
    test_known_gap_prefix_boundary();

    /* Live tests (need Wazuh Manager) */
    test_live_auth();
    test_health_check();

    /* Four collector endpoints */
    test_endpoint("Agents",        WZ_EP_AGENTS);
    test_endpoint("Agent Summary", WZ_EP_AGENT_SUMMARY);
    test_endpoint("Logs Summary",  WZ_EP_LOGS_SUMMARY);
    test_endpoint("Syscheck/FIM",  WZ_EP_SYSCHECK);

    /* VIRP integration */
    test_virp_signing();
    test_black_tier_rejection();

    /* Disconnect */
    if (g_conn) {
        const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
        drv->disconnect(g_conn);
        g_conn = NULL;
    }

    curl_global_cleanup();

    /* Summary */
    printf("\n");
    printf("================================================================\n");
    printf("  Results: %d total, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    printf("================================================================\n\n");

    return tests_failed > 0 ? 1 : 0;
}
