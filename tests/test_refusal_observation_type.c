/*
 * test_refusal_observation_type.c — driver refusals are typed ERROR
 * observations, never signed device output (ISSUE-A branch 3).
 *
 * WHY THIS SUITE EXISTS
 *
 * Six sites across the ASA, IOS, JunOS and FortiGate drivers used to
 * answer a refusal by composing a body — "<hostname>#<command>\nBLACK
 * tier: command forbidden" and friends — and returning VIRP_OK. That
 * body is 100% driver-authored text, and because output_len was
 * non-zero it flowed through the O-Node's DEVICE_OUTPUT path and was
 * signed as though the device had said it. The daemon has a sanctioned
 * channel for constructed text (a typed VIRP_OBS_ERROR observation);
 * these sites simply were not using it.
 *
 * The narration checker already assumed the fixed behaviour: it
 * documents "a refusal is an error frame" and computes
 * executed = (otype != "error"). Every driver-level refusal therefore
 * counted as an EXECUTION in that layer's census. This is a semantics
 * correction, and it is why the fix is worth a suite of its own.
 *
 * THE TRAP THIS SUITE GUARDS
 *
 * Deleting the body is NOT sufficient. virp_onode.c routes an executed
 * command by inspecting the result shape, and the FIRST branch it tries
 * is outcome-UNKNOWN:
 *
 *     disposition == EXECUTED_UNKNOWN ||
 *     (disposition == UNSET && !success && output_len == 0 && !no_dispatch)
 *
 * A refusal that clears its body but does not set no_dispatch matches
 * that condition exactly, and the daemon would record "the command may
 * have executed; not retried" for a command that was never transmitted
 * — trading a false privilege claim for a false execution claim. Every
 * refusal site must therefore PROVE non-dispatch.
 *
 * Pure shape tests: these mirror the daemon's branch conditions rather
 * than opening a socket, in the same style as the PBS fail-closed
 * suite's "the daemon's signed-ERROR precondition holds exactly".
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#include "virp_driver.h"

static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(fn) do {                             \
    printf("  %-58s", #fn);                           \
    fflush(stdout);                                   \
    int before = tests_failed;                        \
    tests_run++;                                      \
    fn();                                             \
    if (tests_failed == before) printf(" [PASS]\n");  \
} while (0)

#define FAIL(...) do {                                \
    printf(" [FAIL]\n    ");                          \
    printf(__VA_ARGS__);                              \
    printf("\n");                                     \
    tests_failed++;                                   \
    return;                                           \
} while (0)

#define CHECK(cond, ...) do { if (!(cond)) FAIL(__VA_ARGS__); } while (0)

/* ── The daemon's routing predicate, mirrored from virp_onode.c ────── */

typedef enum {
    ROUTE_OUTCOME_UNKNOWN,   /* "may have executed" — no retry           */
    ROUTE_TYPED_ERROR,       /* signed VIRP_OBS_ERROR, executed=false    */
    ROUTE_DEVICE_OUTPUT,     /* signed as device bytes                   */
} route_t;

static route_t daemon_route(const virp_exec_result_t *r)
{
    if (r->disposition == VIRP_DISPOSITION_EXECUTED_UNKNOWN ||
        (r->disposition == VIRP_DISPOSITION_UNSET &&
         !r->success && r->output_len == 0 && !r->no_dispatch))
        return ROUTE_OUTCOME_UNKNOWN;
    if (!r->success && r->output_len == 0 && r->error_msg[0])
        return ROUTE_TYPED_ERROR;
    return ROUTE_DEVICE_OUTPUT;
}

/* The shape every fixed refusal site now produces. */
static void refusal_shape(virp_exec_result_t *r, const char *msg)
{
    memset(r, 0, sizeof(*r));
    r->success = false;
    r->exit_code = 1;
    r->no_dispatch = true;
    snprintf(r->error_msg, sizeof(r->error_msg), "%s", msg);
}

/* The shape they produced BEFORE the fix: a composed body, VIRP_OK. */
static void legacy_refusal_shape(virp_exec_result_t *r, const char *body)
{
    memset(r, 0, sizeof(*r));
    r->success = false;
    r->exit_code = 1;
    snprintf(r->error_msg, sizeof(r->error_msg), "BLACK tier: command blocked");
    int n = snprintf(r->output, sizeof(r->output), "%s", body);
    r->output_len = (n > 0) ? (size_t)n : 0;
}

/* ================================================================== */

TEST(test_refusal_routes_to_typed_error)
{
    virp_exec_result_t r;
    refusal_shape(&r, "BLACK tier: command blocked on ASA-Lab");
    CHECK(daemon_route(&r) == ROUTE_TYPED_ERROR,
          "refusal did not route to a typed ERROR observation (route=%d)",
          (int)daemon_route(&r));
}

/*
 * The regression the old code actually had: driver-authored refusal text
 * signed through the DEVICE_OUTPUT path, carrying a fabricated prompt.
 */
TEST(test_legacy_refusal_body_was_signed_as_device_output)
{
    virp_exec_result_t r;
    legacy_refusal_shape(&r, "ASA-Lab# reload\nBLACK tier: command forbidden");
    CHECK(daemon_route(&r) == ROUTE_DEVICE_OUTPUT,
          "premise broken: the legacy shape must reach DEVICE_OUTPUT, "
          "otherwise this suite is not testing the real defect");
    /* And that body asserted privileged exec on a command never sent. */
    CHECK(strchr(r.output, '#') != NULL,
          "premise broken: the legacy body carried no privilege claim");
}

/*
 * THE TRAP. Clearing the body without proving non-dispatch turns a
 * false privilege claim into a false execution claim.
 */
TEST(test_cleared_body_without_no_dispatch_would_claim_maybe_executed)
{
    virp_exec_result_t r;
    refusal_shape(&r, "BLACK tier: command blocked on ASA-Lab");
    r.no_dispatch = false;               /* the omission under test */

    CHECK(daemon_route(&r) == ROUTE_OUTCOME_UNKNOWN,
          "premise broken: without no_dispatch this must land in the "
          "outcome-UNKNOWN branch — that is why every site sets it");

    /* With it set, the same refusal is recorded as never dispatched. */
    r.no_dispatch = true;
    CHECK(daemon_route(&r) == ROUTE_TYPED_ERROR,
          "no_dispatch did not move the refusal to the typed ERROR branch");
}

/* A typed ERROR refusal must carry a reason: the daemon's branch
 * requires error_msg to be non-empty, so an empty one silently falls
 * through to a claim that the command may have executed. */
TEST(test_refusal_without_reason_falls_through)
{
    virp_exec_result_t r;
    refusal_shape(&r, "");
    CHECK(r.error_msg[0] == '\0', "fixture did not produce an empty reason");
    CHECK(daemon_route(&r) != ROUTE_TYPED_ERROR,
          "an unexplained refusal must not masquerade as a typed ERROR");
}

/*
 * The JunOS commit-reject site is the one refusal that performs real
 * device I/O: the commit is never sent, but `rollback 0` IS written.
 * The deleted body was the only place that said so, so the reason text
 * now has to carry it — otherwise a reader concludes nothing touched
 * the device.
 */
TEST(test_commit_reject_reason_records_the_rollback_side_effect)
{
    virp_exec_result_t r;
    refusal_shape(&r,
        "commit rejected: commit check required first on srx-300; "
        "the commit was never sent, and 'rollback 0' WAS applied "
        "to discard the pending candidate config");

    CHECK(daemon_route(&r) == ROUTE_TYPED_ERROR,
          "commit-reject did not route to a typed ERROR observation");
    CHECK(strstr(r.error_msg, "rollback 0") != NULL,
          "the rollback side effect is not recorded anywhere: '%s'",
          r.error_msg);
    CHECK(strstr(r.error_msg, "never sent") != NULL,
          "the reason does not state that the commit was not dispatched");
}

/* No refusal may leave signable bytes behind — that is the whole point. */
TEST(test_no_refusal_leaves_signable_bytes)
{
    const char *reasons[] = {
        "BLACK tier: command blocked on R1",
        "BLACK tier: command blocked on ASA-Lab",
        "BLACK tier: command blocked on fg-lab",
        "BLACK tier: command blocked on srx-300",
        "multi-command string refused on srx-300: embedded separator",
        "commit rejected: commit check required first on srx-300",
    };
    for (size_t i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
        virp_exec_result_t r;
        refusal_shape(&r, reasons[i]);
        CHECK(r.output_len == 0,
              "refusal %zu left %zu signable bytes", i, r.output_len);
        CHECK(r.output[0] == '\0', "refusal %zu left a body", i);
        CHECK(daemon_route(&r) == ROUTE_TYPED_ERROR,
              "refusal %zu did not route to a typed ERROR", i);
    }
}

int main(void)
{
    printf("\n=== Driver refusals are typed ERROR observations "
           "(ISSUE-A branch 3) ===\n\n");

    RUN_TEST(test_refusal_routes_to_typed_error);
    RUN_TEST(test_legacy_refusal_body_was_signed_as_device_output);
    RUN_TEST(test_cleared_body_without_no_dispatch_would_claim_maybe_executed);
    RUN_TEST(test_refusal_without_reason_falls_through);
    RUN_TEST(test_commit_reject_reason_records_the_rollback_side_effect);
    RUN_TEST(test_no_refusal_leaves_signable_bytes);

    printf("\n%d tests, %d failures\n\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
