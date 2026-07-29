/*
 * test_driver_librenms.c — LibreNMS REST API driver tests
 *
 * Offline-only: driver registration and the gate classifier. The
 * driver's network path is exercised live by the autopilot battery on
 * virp-lab; this binary never originates network contact, so it needs
 * no VIRP_LIVE_* fence.
 *
 * Build:  make LIBRENMS=1 test-librenms
 *
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_driver.h"
#include "virp_driver_librenms.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

static void test_registration(void)
{
    printf("\n=== Registration ===\n");

    TEST("driver registered with route hooks");
    virp_driver_librenms_init();
    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_LIBRENMS);
    assert(drv != NULL);
    assert(strcmp(drv->name, "librenms") == 0);
    assert(drv->connect && drv->execute && drv->disconnect &&
           drv->detect && drv->health_check);
    assert(drv->route_command == librenms_gate_tier);
    PASS();
}

static void test_green_rows(void)
{
    printf("\n=== GREEN — the autopilot read set, exactly ===\n");

    TEST("/api/v0/devices -> GREEN");
    assert(ln_route_path("/api/v0/devices") == VIRP_TIER_GREEN); PASS();

    TEST("/api/v0/devices?type=all -> GREEN (query ignored)");
    assert(ln_route_path("/api/v0/devices?type=all") == VIRP_TIER_GREEN); PASS();

    TEST("/api/v0/alerts -> GREEN");
    assert(ln_route_path("/api/v0/alerts") == VIRP_TIER_GREEN); PASS();

    TEST("/api/v0/alerts?state=1 -> GREEN");
    assert(ln_route_path("/api/v0/alerts?state=1") == VIRP_TIER_GREEN); PASS();

    TEST("/api/v0/devices/1/health -> GREEN (one-segment wildcard)");
    assert(ln_route_path("/api/v0/devices/1/health") == VIRP_TIER_GREEN); PASS();

    TEST("/api/v0/devices/core-sw1/health -> GREEN");
    assert(ln_route_path("/api/v0/devices/core-sw1/health") == VIRP_TIER_GREEN); PASS();
}

static void test_red_by_absence(void)
{
    printf("\n=== RED — everything else, fail closed ===\n");

    TEST("device detail (unlisted read) -> RED");
    assert(ln_route_path("/api/v0/devices/1") == VIRP_TIER_RED); PASS();

    TEST("two segments before /health -> RED");
    assert(ln_route_path("/api/v0/devices/a/b/health") == VIRP_TIER_RED); PASS();

    TEST("empty segment before /health -> RED");
    assert(ln_route_path("/api/v0/devices//health") == VIRP_TIER_RED); PASS();

    TEST("prefix creep /api/v0/devices_evil -> RED");
    assert(ln_route_path("/api/v0/devices_evil") == VIRP_TIER_RED); PASS();

    TEST("suffix creep /api/v0/alerts/1 -> RED");
    assert(ln_route_path("/api/v0/alerts/1") == VIRP_TIER_RED); PASS();

    TEST("write endpoints are unclassified -> RED by absence");
    assert(ln_route_path("/api/v0/devices/1/maintenance") == VIRP_TIER_RED);
    assert(ln_route_path("/api/v0/bills") == VIRP_TIER_RED);
    assert(ln_route_path("/api/v0/system") == VIRP_TIER_RED);
    PASS();

    TEST("path traversal -> RED");
    assert(ln_route_path("/api/v0/../etc/passwd") == VIRP_TIER_RED); PASS();

    TEST("NULL / empty / unrooted -> RED");
    assert(ln_route_path(NULL) == VIRP_TIER_RED);
    assert(ln_route_path("") == VIRP_TIER_RED);
    assert(ln_route_path("api/v0/devices") == VIRP_TIER_RED);
    PASS();
}

static void test_gate_hook_methods(void)
{
    printf("\n=== Gate hook — GET-only method rules ===\n");

    TEST("GET prefix accepted");
    assert(librenms_gate_tier("GET /api/v0/devices") == VIRP_TIER_GREEN); PASS();

    TEST("bare path accepted");
    assert(librenms_gate_tier("/api/v0/alerts") == VIRP_TIER_GREEN); PASS();

    TEST("non-GET methods -> RED");
    assert(librenms_gate_tier("POST /api/v0/devices") == VIRP_TIER_RED);
    assert(librenms_gate_tier("DELETE /api/v0/devices/1") == VIRP_TIER_RED);
    assert(librenms_gate_tier("PATCH /api/v0/devices/1") == VIRP_TIER_RED);
    PASS();

    TEST("garbage -> RED");
    assert(librenms_gate_tier("devices") == VIRP_TIER_RED);
    assert(librenms_gate_tier(NULL) == VIRP_TIER_RED);
    PASS();
}

/*
 * The daemon must never touch an endpoint its OWN classifier calls RED.
 * Both drivers previously probed outside their GREEN set on connect and
 * health_check (/api/v0/system here, /manager/status in Wazuh), which on
 * a least-privileged credential produced an endless
 * health-check-fail → drop → reconnect churn. These assertions pin the
 * probe paths inside the GREEN set.
 */
static void test_internal_probes_are_green(void)
{
    printf("\n=== Internal probe paths stay inside the GREEN set ===\n");

    TEST("connect/health probe path is GREEN");
    assert(ln_route_path("/api/v0/devices") == VIRP_TIER_GREEN);
    PASS();

    TEST("the old probe path is RED (must not be probed)");
    assert(ln_route_path("/api/v0/system") == VIRP_TIER_RED);
    PASS();

    TEST("driver source probes /devices, never /system");
    {
        FILE *f = fopen("src/drivers/driver_librenms.c", "r");
        if (!f) {
            printf("SKIP (run from repo root)\n");
            tests_passed++;
        } else {
            char buf[262144];
            size_t n = fread(buf, 1, sizeof(buf) - 1, f);
            fclose(f);
            buf[n] = '\0';
            assert(strstr(buf, "LN_API_PREFIX \"/system\"") == NULL);
            assert(strstr(buf, "ln_get(conn, LN_API_PREFIX \"/devices\"") != NULL);
            PASS();
        }
    }
}

int main(void)
{
    printf("=== LibreNMS Driver Tests (offline) ===\n");

    test_registration();
    test_green_rows();
    test_red_by_absence();
    test_gate_hook_methods();
    test_internal_probes_are_green();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
