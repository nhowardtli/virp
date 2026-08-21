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
        /* The autopilot GREEN read set — exact paths, query allowed. */
        { "/agents?select=id,name,status,ip",        VIRP_TIER_GREEN  },
        { "/agents",                                 VIRP_TIER_GREEN  },
        { "/agents/summary/status",                  VIRP_TIER_GREEN  },
        { "/manager/stats/analysisd",                VIRP_TIER_GREEN  },
        /* No YELLOW rows, no write endpoints classified: everything
         * unlisted — including every row the old SHADOW-only table
         * carried — is RED by absence. */
        /* Governance read set added 2026-08-19 — now GREEN. */
        { "/manager/status",                         VIRP_TIER_GREEN  },
        { "/manager/info",                           VIRP_TIER_GREEN  },
        { "/manager/stats",                          VIRP_TIER_GREEN  },
        { "/manager/stats/remoted",                  VIRP_TIER_GREEN  },
        { "/manager/logs/summary",                   VIRP_TIER_GREEN  },
        { "/agents/summary/os",                      VIRP_TIER_GREEN  },
        { "/rules",                                  VIRP_TIER_GREEN  },
        { "/rules/groups",                           VIRP_TIER_GREEN  },
        { "/decoders",                               VIRP_TIER_GREEN  },
        { "/rules?limit=10&pretty=true",             VIRP_TIER_GREEN  },
        /* Still RED: manager config, and the full log body as opposed
         * to its summary. */
        { "/manager/configuration",                  VIRP_TIER_RED    },
        { "/manager/logs",                           VIRP_TIER_RED    },
        { "/vulnerability/001/last_scan",            VIRP_TIER_RED    },
        { "/syscheck/001?limit=100",                 VIRP_TIER_RED    },
        { "/security/users",                         VIRP_TIER_RED    },
        { "/security/user/authenticate",             VIRP_TIER_RED    },
        { "/active-response",                        VIRP_TIER_RED    },
        { "/manager/restart",                        VIRP_TIER_RED    },
        { "/agents/restart",                         VIRP_TIER_RED    },
        /* Exact match kills prefix creep in BOTH directions. */
        { "/agents/001",                             VIRP_TIER_RED    },
        { "/agents/summary/status/extra",            VIRP_TIER_RED    },
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
 * Test: protected_agents registry parsing
 *
 * Contract mirrors linux_gate_set_protected_vmids(): a list that does
 * not parse registers NOTHING, so a half-parsed list can never leave a
 * partial protection in force while the loader believes it succeeded.
 * ========================================================================= */

static void test_protected_agent_parsing(void)
{
    TEST_START("protected_agents parsing and registration");

    wazuh_gate_clear_protected_agents();
    assert(wazuh_gate_protected_agent_count() == 0);

    /* Empty / NULL are a no-op success, not an error: a device that
     * declares no protected agents is a legal configuration. */
    assert(wazuh_gate_set_protected_agents(NULL) == 0);
    assert(wazuh_gate_set_protected_agents("") == 0);
    assert(wazuh_gate_protected_agent_count() == 0);

    /* Zero-padded and bare spellings are the SAME agent. */
    assert(wazuh_gate_set_protected_agents("004,313") == 0);
    assert(wazuh_gate_protected_agent_count() == 2);
    assert(wazuh_gate_set_protected_agents("4") == 0);          /* dup of 004 */
    assert(wazuh_gate_protected_agent_count() == 2);
    assert(wazuh_gate_set_protected_agents("0004, 00313") == 0);
    assert(wazuh_gate_protected_agent_count() == 2);

    /* Accumulates across devices (union), like the linux gate. */
    assert(wazuh_gate_set_protected_agents("7") == 0);
    assert(wazuh_gate_protected_agent_count() == 3);

    /* Malformed input is rejected AND registers nothing new. */
    size_t before = wazuh_gate_protected_agent_count();
    assert(wazuh_gate_set_protected_agents("abc") == -1);
    assert(wazuh_gate_set_protected_agents("1,abc") == -1);
    assert(wazuh_gate_set_protected_agents("1;2") == -1);
    assert(wazuh_gate_set_protected_agents("99999999999999999999") == -1);
    assert(wazuh_gate_protected_agent_count() == before);

    /* Overflow of the registry is an error, not a silent truncation. */
    wazuh_gate_clear_protected_agents();
    char big[WZ_PROTECTED_AGENT_MAX * 8];
    size_t off = 0;
    for (int i = 0; i < WZ_PROTECTED_AGENT_MAX + 1; i++)
        off += (size_t)snprintf(big + off, sizeof(big) - off, "%s%d",
                                i ? "," : "", 1000 + i);
    assert(wazuh_gate_set_protected_agents(big) == -1);
    assert(wazuh_gate_protected_agent_count() == 0);

    wazuh_gate_clear_protected_agents();
    TEST_PASS();
}

/* =========================================================================
 * Test: BLACK tier — static rules, independent of configuration
 * ========================================================================= */

static void test_black_static_rules(void)
{
    TEST_START("BLACK tier: static rules (no protected agents configured)");

    wazuh_gate_clear_protected_agents();

    /* The manager's / a cluster node's own configuration. */
    assert(wz_is_black_endpoint("/manager/configuration"));
    assert(wz_is_black_endpoint("GET /manager/configuration"));
    assert(wz_is_black_endpoint("PUT /manager/configuration"));
    assert(wz_is_black_endpoint("/cluster/node01/configuration"));

    /* Active-response dispatch. */
    assert(wz_is_black_endpoint("/active-response"));
    assert(wz_is_black_endpoint("PUT /active-response?agents_list=001"));

    /* Agent deletion — the METHOD is what separates this from the
     * GREEN /agents read, and the check is case-insensitive. */
    assert(wz_is_black_endpoint("DELETE /agents?agents_list=001"));
    assert(wz_is_black_endpoint("delete /agents"));
    assert(wz_is_black_endpoint("DELETE /agents/001"));

    /*
     * Malformed input is NOT black. BLACK means "forbidden by policy",
     * and a policy refusal is non-approvable and files no proposal; a
     * typo must stay an ordinary RED-by-absence rejection the operator
     * can read and re-file. Both callers refuse garbage on their own
     * paths, which is asserted immediately below.
     */
    assert(!wz_is_black_endpoint(NULL));
    assert(!wz_is_black_endpoint("agents"));         /* unrooted */
    assert(!wz_is_black_endpoint(""));
    assert(wazuh_gate_tier("agents") == VIRP_TIER_RED);
    assert(wazuh_gate_tier(NULL) == VIRP_TIER_RED);
    assert(wazuh_gate_tier("") == VIRP_TIER_RED);

    /*
     * NOT black: ordinary reads, and the writes that are meant to stay
     * RED-by-absence so they remain proposable. Restart and config PUT
     * are deliberately absent from the deny list.
     */
    assert(!wz_is_black_endpoint("/agents"));
    assert(!wz_is_black_endpoint("GET /agents?select=id,name,status,ip"));
    assert(!wz_is_black_endpoint("/agents/summary/status"));
    assert(!wz_is_black_endpoint("/rules"));
    assert(!wz_is_black_endpoint("/manager/status"));
    assert(!wz_is_black_endpoint("PUT /agents/001/restart"));
    assert(!wz_is_black_endpoint("/agents/001"));

    TEST_PASS();
}

/* =========================================================================
 * Test: BLACK tier — configured protected agents
 *
 * The whole point of the feature: agent 004 (the reasoning tier's own
 * host) and agent 313 (the O-Node's own host) must be untouchable
 * through every endpoint shape, and the ids must come from config
 * rather than the binary.
 * ========================================================================= */

static void test_black_protected_agents(void)
{
    TEST_START("BLACK tier: configured protected agents");

    wazuh_gate_clear_protected_agents();

    /* Before configuration, 004 is an ordinary agent — proving the
     * protection comes from devices.json and is NOT hardcoded. */
    assert(!wz_is_black_endpoint("/agents/004"));
    assert(!wz_is_black_endpoint("/syscheck/004"));

    assert(wazuh_gate_set_protected_agents("004,313") == 0);

    /* Path-segment shapes, across collections. */
    assert(wz_is_black_endpoint("/agents/004"));
    assert(wz_is_black_endpoint("GET /agents/004"));
    assert(wz_is_black_endpoint("/agents/004/config/client/buffer"));
    assert(wz_is_black_endpoint("PUT /agents/004/restart"));
    assert(wz_is_black_endpoint("/syscheck/004"));
    assert(wz_is_black_endpoint("/rootcheck/004"));
    assert(wz_is_black_endpoint("/vulnerability/004/last_scan"));
    assert(wz_is_black_endpoint("/sca/313"));
    assert(wz_is_black_endpoint("/agents/313"));

    /* Zero-padding is irrelevant — ids compare numerically. */
    assert(wz_is_black_endpoint("/agents/4"));
    assert(wz_is_black_endpoint("/agents/0004"));

    /* Agent-selecting query parameters, including inside a list. */
    assert(wz_is_black_endpoint("/agents?agents_list=004"));
    assert(wz_is_black_endpoint("/agents?agents_list=001,002,004"));
    assert(wz_is_black_endpoint("/agents?agents_list=004,001"));
    assert(wz_is_black_endpoint("GET /agents?agent_id=313"));
    assert(wz_is_black_endpoint("/agents/restart?agents_list=001,313"));
    assert(wz_is_black_endpoint("/agents?pretty=true&agents_list=004"));

    /* "all" on an agent-selecting parameter includes the protected
     * ones without naming them. */
    assert(wz_is_black_endpoint("/agents?agents_list=all"));
    assert(wz_is_black_endpoint("PUT /agents/restart?agents_list=ALL"));

    /*
     * Non-agent parameters are NOT scanned, so an ordinary read whose
     * limit or offset happens to equal a protected id still works.
     * This is why the query scan keys on the parameter NAME.
     */
    assert(!wz_is_black_endpoint("/agents?limit=313"));
    assert(!wz_is_black_endpoint("/agents?offset=4&limit=500"));

    /* Unprotected agents remain readable. */
    assert(!wz_is_black_endpoint("/agents/001"));
    assert(!wz_is_black_endpoint("/agents?agents_list=001,002"));
    assert(!wz_is_black_endpoint("/syscheck/001?limit=100"));

    /*
     * A protected id in ANY numeric path segment is refused, even where
     * that segment is not an agent id (a rule numbered 313). Documented
     * over-matching: a deny list should err toward refusing a read.
     */
    assert(wz_is_black_endpoint("/rules/313"));

    /*
     * ── Percent-encoding must not launder a protected agent ────────
     *
     * The endpoint goes to libcurl's CURLOPT_URL verbatim and the
     * MANAGER decodes it, so a scan of the raw bytes alone sees
     * "/agents/%30%30%34" as a non-numeric segment while Wazuh sees
     * "/agents/004". These pin the decode pass; without it every case
     * below reaches the protected agent.
     */
    assert(wz_is_black_endpoint("/agents/%30%30%34"));        /* 004      */
    assert(wz_is_black_endpoint("/agents/%30%30%34/restart"));
    assert(wz_is_black_endpoint("/syscheck/%304"));           /* 04       */
    assert(wz_is_black_endpoint("/agents?agents_list=%304"));
    assert(wz_is_black_endpoint("/agents?agents_list=%61%6C%6C"));  /* all */
    assert(wz_is_black_endpoint("/agents%2F004"));            /* enc slash */
    assert(wz_is_black_endpoint("/agents%2f004"));            /* lowercase */
    assert(wz_is_black_endpoint("/manager/%63onfiguration"));

    /*
     * Decoding is ONE pass, matching what an HTTP server does. "%2530"
     * reaches Wazuh as the literal text "%30" and never becomes "0", so
     * refusing it would deny an endpoint that cannot resolve to a
     * protected agent.
     */
    assert(!wz_is_black_endpoint("/agents/%2530%2530%2534"));

    /* An endpoint too long to analyse is refused rather than guessed at. */
    {
        char huge[6000];
        memset(huge, 'a', sizeof(huge) - 1);
        huge[0] = '/';
        huge[sizeof(huge) - 1] = '\0';
        assert(wz_is_black_endpoint(huge));
    }

    /* Encoding must not break the ordinary GREEN reads either. */
    assert(!wz_is_black_endpoint("/agents?select=id%2Cname%2Cstatus"));
    assert(!wz_is_black_endpoint("/agents/001"));

    wazuh_gate_clear_protected_agents();
    TEST_PASS();
}

/* =========================================================================
 * Test: BLACK is unreachable by approval — it is not a tier
 *
 * A BLACK endpoint must ALSO classify RED-by-absence in the tier table,
 * so there is no path where a classifier says GREEN and only the driver
 * objects. The two mechanisms have to agree about the direction.
 * ========================================================================= */

static void test_black_endpoints_are_not_green(void)
{
    TEST_START("Every BLACK endpoint classifies BLACK at the gate hook");

    wazuh_gate_clear_protected_agents();
    assert(wazuh_gate_set_protected_agents("004,313") == 0);

    static const char *black_cases[] = {
        "/manager/configuration",
        "/cluster/node01/configuration",
        "/active-response",
        "/agents/004",
        "/agents/313",
        "/syscheck/004",
        "/agents?agents_list=004",
        "/agents?agents_list=all",
        NULL,
    };

    int bad = 0;
    for (int i = 0; black_cases[i]; i++) {
        if (!wz_is_black_endpoint(black_cases[i])) {
            fprintf(stderr, "    NOT BLACK (should be): %s\n", black_cases[i]);
            bad++;
            continue;
        }
        /*
         * The GATE HOOK is the thing that must agree, not
         * wz_route_endpoint(): the table lookup strips the query string
         * by design, so "/agents?agents_list=004" is genuinely
         * indistinguishable from GREEN "/agents" to it. wazuh_gate_tier()
         * sees the full command and is what gate_classify() calls.
         */
        virp_trust_tier_t t = wazuh_gate_tier(black_cases[i]);
        if (t != VIRP_TIER_BLACK) {
            fprintf(stderr, "    BLACK endpoint classifies 0x%02x (want BLACK): "
                    "%s\n", t, black_cases[i]);
            bad++;
        }
    }

    /*
     * The converse: the GREEN read set must NOT be swept up by the deny
     * list. A protection that also blocks the monitoring it exists to
     * protect is a failure, just a quiet one.
     */
    static const char *green_cases[] = {
        "/agents", "GET /agents?select=id,name,status,ip",
        "/agents/summary/status", "/agents/summary/os",
        "/manager/status", "/manager/info", "/manager/stats",
        "/manager/stats/analysisd", "/manager/stats/remoted",
        "/manager/logs/summary", "/rules", "/rules/groups", "/decoders",
        NULL,
    };
    for (int i = 0; green_cases[i]; i++) {
        virp_trust_tier_t t = wazuh_gate_tier(green_cases[i]);
        if (t != VIRP_TIER_GREEN) {
            fprintf(stderr, "    GREEN read blocked, got 0x%02x: %s\n",
                    t, green_cases[i]);
            bad++;
        }
    }

    wazuh_gate_clear_protected_agents();

    if (bad) TEST_FAIL("BLACK/tier-table disagreement");
    else     TEST_PASS();
}

/* =========================================================================
 * Test: every route-table row is reachable and returns its declared tier
 *
 * The table-driven reachability check the cisco/fortigate suites run,
 * ported to exact-match endpoints. Catches a row shadowed by an earlier
 * duplicate or misspelled into unreachability.
 * ========================================================================= */

static void test_route_table_reachable(void)
{
    TEST_START("Every WZ_ROUTE_TABLE row is reachable");

    int bad = 0;
    for (size_t i = 0; i < WZ_ROUTE_TABLE_SIZE; i++) {
        const char *pat = WZ_ROUTE_TABLE[i].endpoint_pattern;
        virp_trust_tier_t want = WZ_ROUTE_TABLE[i].tier;
        virp_trust_tier_t got = wz_route_endpoint(pat);
        if (got != want) {
            fprintf(stderr, "    UNREACHABLE row %zu: %s → 0x%02x, want 0x%02x\n",
                    i, pat, got, want);
            bad++;
        }
        /* The table carries no YELLOW and no write rows by design. */
        if (want != VIRP_TIER_GREEN) {
            fprintf(stderr, "    Non-GREEN row %zu (%s) — this table is "
                    "GREEN-only by design\n", i, pat);
            bad++;
        }
    }

    fprintf(stderr, "    %zu rows checked\n", WZ_ROUTE_TABLE_SIZE);

    if (bad) TEST_FAIL("Route table reachability failures");
    else     TEST_PASS();
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
 * Test: GET-only transport refusal
 *
 * (Replaced the BLACK-tier rejection test: the table carries no BLACK
 * rows any more — writes are deliberately unclassified and the gate
 * REDs them by absence. The driver-level invariant that remains is
 * transport honesty: a non-GET method prefix must be refused, never
 * silently GETted.)
 * ========================================================================= */

static void test_non_get_refusal(void)
{
    REQUIRE_LIVE("GET-only refusal against the live manager");
    TEST_START("Non-GET method prefix refusal");

    if (!g_conn) {
        TEST_FAIL("No connection (auth test failed)");
        return;
    }

    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
    virp_exec_result_t result;

    virp_error_t err = drv->execute(g_conn, "PUT /agents/restart", &result);
    if (err != VIRP_OK) {
        TEST_FAIL("execute() should return VIRP_OK even for refused commands");
        return;
    }

    if (result.success) {
        TEST_FAIL("Non-GET command should have been refused");
        return;
    }

    if (strstr(result.error_msg, "GET-only") == NULL) {
        char msg[512];
        snprintf(msg, sizeof(msg),
                 "Error msg should mention GET-only: '%.200s'", result.error_msg);
        TEST_FAIL(msg);
        return;
    }

    fprintf(stderr, "    Correctly refused: %s\n", result.error_msg);
    TEST_PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

/*
 * Formerly a KNOWN GAP: prefix matching let "/agents_evil" inherit the
 * GREEN "/agents" row. Fixed by the exact-match rewrite (a URL path
 * either IS an enumerated read or it is RED), so the gap test is now a
 * live assertion, plus the gate-hook method rules the fix introduced.
 */
static void test_prefix_boundary_fixed(void)
{
    TEST_START("Endpoint boundary + gate-hook method rules");

    assert(wz_route_endpoint("/agents_evil") == VIRP_TIER_RED);
    assert(wz_route_endpoint("/agents/") == VIRP_TIER_RED);

    /* route_command hook: optional GET prefix OK, any other method or
     * unrooted string is RED (write intents deliberately unclassified). */
    assert(wazuh_gate_tier("GET /agents") == VIRP_TIER_GREEN);
    assert(wazuh_gate_tier("GET /agents/summary/status") == VIRP_TIER_GREEN);
    assert(wazuh_gate_tier("/manager/stats/analysisd") == VIRP_TIER_GREEN);
    assert(wazuh_gate_tier("POST /agents") == VIRP_TIER_RED);
    assert(wazuh_gate_tier("PUT /agents/restart") == VIRP_TIER_RED);
    /*
     * Agent DELETION is BLACK, not RED, as of the 2026-08-19 governance
     * set — deletion is the one write that destroys the evidence a
     * later review would need, so it is refused rather than made
     * approvable. Every OTHER write stays RED by absence and therefore
     * proposable; the two lines above pin that.
     */
    assert(wazuh_gate_tier("DELETE /agents/001") == VIRP_TIER_BLACK);
    assert(wazuh_gate_tier("DELETE /agents") == VIRP_TIER_BLACK);
    assert(wazuh_gate_tier("agents") == VIRP_TIER_RED);
    assert(wazuh_gate_tier(NULL) == VIRP_TIER_RED);

    /* The registered driver must actually carry the hook. */
    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_WAZUH);
    assert(drv && drv->route_command == wazuh_gate_tier);

    /*
     * The health probe must sit INSIDE the GREEN set.
     *
     * /manager/status is GREEN as of the 2026-08-19 governance set, but
     * the probe deliberately stays on /agents/summary/status: a
     * properly least-privileged credential (virp-node2's account) gets
     * HTTP 403 on /manager/status, which caused an endless health-fail
     * → drop → reconnect churn. Being classifiable is not the same as
     * being readable by every credential, and the probe has to hold for
     * the tightest one.
     */
    assert(wz_route_endpoint(WZ_EP_AGENT_SUMMARY) == VIRP_TIER_GREEN);
    assert(wz_route_endpoint(WZ_EP_MANAGER_STATUS) == VIRP_TIER_GREEN);

    TEST_PASS();
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
    test_prefix_boundary_fixed();
    test_route_table_reachable();
    test_protected_agent_parsing();
    test_black_static_rules();
    test_black_protected_agents();
    test_black_endpoints_are_not_green();

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
    test_non_get_refusal();

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
