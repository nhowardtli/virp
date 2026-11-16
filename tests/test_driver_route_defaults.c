/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — unmapped commands classify RED in every table-driven CLI driver
 *
 * Security review H3 asked whether the asa / junos / fortigate route
 * functions default an unmapped command to YELLOW. They do not — each
 * ends in `return best ? best->tier : VIRP_TIER_RED` — but that is one
 * line per driver, and the default gate ceiling is YELLOW: a default that
 * drifted back to YELLOW would clear the gate and execute unreviewed. So
 * the property is pinned here for all five classifiers in ONE table,
 * rather than left to five separate suites to each remember.
 *
 * Table-driven on purpose. The commands are plausible, unlisted and
 * mostly state-changing: the point is that absence from a table can
 * never be read as permission.
 *
 * Pure classification — no connect, no socket, no device.
 */
#include "virp.h"
#include "virp_driver.h"
#include "virp_driver_asa.h"
#include "virp_driver_fortigate.h"
#include "virp_driver_juniper.h"
#include "driver_panos.h"

#include <stdio.h>
#include <string.h>

/* virp_driver_cisco.h embeds the driver-private connection struct and
 * cannot be included from a test; the classifier's signature is all that
 * is needed (tests/test_driver_cisco_gate.c does the same). */
extern virp_trust_tier_t cisco_gate_tier(const char *command);

typedef virp_trust_tier_t (*route_fn)(const char *);

static const struct { const char *driver; route_fn fn; } DRIVERS[] = {
    { "cisco_asa", asa_route_command   },
    { "juniper",   junos_route_command },
    { "fortigate", fg_route_command    },
    { "panos",     pa_route_command    },
    { "cisco_ios", cisco_gate_tier     },
};

/* None of these is a row, or a token-bounded prefix of a row, in any of
 * the five tables. */
static const char *const UNMAPPED[] = {
    "frobnicate the widget",
    "xyzzy",
    "zz-unlisted-verb with arguments",
    "showdown at noon",              /* must not inherit a "show" row     */
    "configured-looking nonsense",   /* nor a "config"/"configure" row    */
    "getaway",                       /* nor a "get" row                   */
    "9",
    "?",
    "",
    "   ",
};

static const char *tier_name(virp_trust_tier_t t)
{
    switch (t) {
    case VIRP_TIER_UNCLASSIFIED: return "UNCLASSIFIED";
    case VIRP_TIER_GREEN:        return "GREEN";
    case VIRP_TIER_YELLOW:       return "YELLOW";
    case VIRP_TIER_RED:          return "RED";
    case VIRP_TIER_BLACK:        return "BLACK";
    default:                     return "?";
    }
}

int main(void)
{
    int failures = 0, checks = 0;
    printf("\n=== VIRP route tables: unmapped commands default to RED (H3) ===\n");

    for (size_t d = 0; d < sizeof(DRIVERS) / sizeof(DRIVERS[0]); d++) {
        for (size_t c = 0; c < sizeof(UNMAPPED) / sizeof(UNMAPPED[0]); c++) {
            virp_trust_tier_t t = DRIVERS[d].fn(UNMAPPED[c]);
            checks++;
            if (t != VIRP_TIER_RED) {
                printf("    FAIL: %-9s \"%s\" -> %s (want RED)\n",
                       DRIVERS[d].driver, UNMAPPED[c], tier_name(t));
                failures++;
            }
        }
        /* NULL is the degenerate unmapped command. */
        checks++;
        if (DRIVERS[d].fn(NULL) != VIRP_TIER_RED) {
            printf("    FAIL: %-9s NULL -> %s (want RED)\n",
                   DRIVERS[d].driver, tier_name(DRIVERS[d].fn(NULL)));
            failures++;
        }
        printf("    ok:   %-9s every unmapped command classifies RED\n",
               DRIVERS[d].driver);
    }

    /* The claim the blocked-address comment in virp_onode.c leans on: a
     * FortiGate `config ...` change is RED. It is RED by an explicit
     * "config" row, and would be RED by absence without it. */
    static const char *const FG_CONFIG[] = {
        "config system interface",
        "config firewall policy",
        "config",
    };
    for (size_t i = 0; i < sizeof(FG_CONFIG) / sizeof(FG_CONFIG[0]); i++) {
        checks++;
        if (fg_route_command(FG_CONFIG[i]) != VIRP_TIER_RED) {
            printf("    FAIL: fortigate \"%s\" -> %s (want RED)\n", FG_CONFIG[i],
                   tier_name(fg_route_command(FG_CONFIG[i])));
            failures++;
        }
    }
    printf("    ok:   fortigate config-mode changes classify RED\n");

    if (failures) {
        printf("\n=== Results: %d of %d route-default checks FAILED ===\n\n",
               failures, checks);
        return 1;
    }
    printf("\n=== Results: %d route-default checks passed ===\n\n", checks);
    return 0;
}
