/*
 * test_jx_uint32.c — regression tests for the jx_uint32 JSON helper in
 * src/virp_onode_json.c.
 *
 * Prior to this fix, jx_uint32 delegated to jx_string first, so only
 * quoted numbers were accepted. Unquoted JSON numbers silently fell
 * back to the caller-supplied default, which for `node_id` was 0 — a
 * silent trust-chain failure. These tests assert that both quoted and
 * unquoted numeric forms yield the expected value.
 *
 * Copyright (c) 2026 Third Level IT LLC.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

/* Include the translation unit under test so we can call the static helper
 * directly. We stub onode_state_t and the driver header bits jx_uint32 does
 * not actually use so this stays a self-contained unit test. */
struct onode_state; /* forward-declared via virp_onode.h include */

/* Pull in the real declarations. */
#include "virp_onode.h"
#include "virp_driver.h"

/* Include the source of the helper under test. onode_load_devices_json also
 * lives in this TU; it references onode_state_t internals and log_* helpers,
 * which we don't link here, so we only call jx_uint32 / jx_int from the
 * test. The unreferenced onode_load_devices_json is kept out of the final
 * link via the linker since we never call it. */
#include "../src/virp_onode_json.c"

static int tests_run = 0, tests_passed = 0, tests_failed = 0;

#define CHECK(expr, msg) do { \
    tests_run++; \
    if (expr) { tests_passed++; printf("  [%02d] PASS: %s\n", tests_run, msg); } \
    else      { tests_failed++; printf("  [%02d] FAIL: %s\n", tests_run, msg); } \
} while (0)

int main(void)
{
    printf("=== jx_uint32 regression tests ===\n");

    /* The bug: unquoted number used to return default. */
    const char *js_unquoted = "{\"node_id\": 5}";
    CHECK(jx_uint32(js_unquoted, "node_id", 999) == 5,
          "unquoted \"node_id\": 5 parses to 5");

    /* Legacy behavior: quoted hex still works (node_id is usually hex). */
    const char *js_quoted_dec = "{\"node_id\": \"5\"}";
    CHECK(jx_uint32(js_quoted_dec, "node_id", 999) == 5,
          "quoted \"node_id\": \"5\" parses to 5");

    const char *js_quoted_hex = "{\"node_id\": \"0A0000FD\"}";
    CHECK(jx_uint32(js_quoted_hex, "node_id", 0) == 0x0A0000FDu,
          "quoted hex \"0A0000FD\" parses correctly (ASA node_id)");

    /* Unquoted decimal with surrounding keys. */
    const char *js_middle = "{\"host\": \"1.2.3.4\", \"node_id\": 42, \"vendor\": \"cisco\"}";
    CHECK(jx_uint32(js_middle, "node_id", 999) == 42,
          "unquoted node_id between other keys");

    /* Unquoted 0x hex (base 0 auto-detect). */
    const char *js_0x = "{\"node_id\": 0xDEADBEEF}";
    CHECK(jx_uint32(js_0x, "node_id", 0) == 0xDEADBEEFu,
          "unquoted 0x-prefixed hex parses correctly");

    /* Missing key returns default. */
    const char *js_missing = "{\"host\": \"1.2.3.4\"}";
    CHECK(jx_uint32(js_missing, "node_id", 7777) == 7777,
          "missing key returns default");

    /* Unparseable value returns default. */
    const char *js_garbage = "{\"node_id\": abc}";
    CHECK(jx_uint32(js_garbage, "node_id", 1234) == 1234,
          "non-numeric unquoted value returns default");

    printf("\n--- Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed) printf(" (%d FAILED)", tests_failed);
    printf(" ---\n");
    return tests_failed ? 1 : 0;
}
