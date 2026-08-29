/*
 * refusal_contract.h — shared assertions for the driver refusal contract
 * (Defect B, 2026-08-26).
 *
 * The contract, as implemented by driver_linux.c:352-372 and now by the
 * ASA / IOS / JunOS / FortiGate backstops: when a driver declines a
 * command it must
 *
 *   1. set success = false,
 *   2. set no_dispatch = true      — the O-Node's proof standard,
 *   3. set disposition = NOT_SENT  — stating it positively, not by omission,
 *   4. leave output EMPTY          — output is the DEVICE's voice, and the
 *                                    device was never asked,
 *   5. return VIRP_OK              — the refusal is a successful outcome of
 *                                    the call, not a driver error.
 *
 * Miss (2) or (3) and virp_onode.c:963 records the refusal as
 * "executed":true; miss (4) and it is additionally signed as
 * DEVICE_OUTPUT, because both O-Node refusal filters key on
 * output_len == 0.
 *
 * Each driver is exercised in its own TU: execute() and struct virp_conn
 * are private to each driver source, and two drivers cannot be #included
 * into one translation unit without symbol collision.
 */
#ifndef VIRP_TEST_REFUSAL_CONTRACT_H
#define VIRP_TEST_REFUSAL_CONTRACT_H

#include <stdio.h>
#include <string.h>

static int rc_failures = 0;

#define RC_CHECK(cond, ...) do {                        \
    if (!(cond)) {                                      \
        printf("    FAIL: "); printf(__VA_ARGS__);      \
        printf("\n"); rc_failures++;                    \
    }                                                   \
} while (0)

/*
 * Assert the full contract on an already-populated result. `what` names
 * the refusal for the failure message.
 */
#define RC_ASSERT_REFUSAL(err, r, what) do {                                \
    RC_CHECK((err) == VIRP_OK,                                              \
             "%s: execute returned %d, must be VIRP_OK", (what), (int)(err));\
    RC_CHECK((r).success == false, "%s: reported success", (what));         \
    RC_CHECK((r).no_dispatch == true,                                       \
             "%s: no_dispatch=false — O-Node will record executed=true",    \
             (what));                                                       \
    RC_CHECK((r).disposition == VIRP_DISPOSITION_NOT_SENT,                  \
             "%s: disposition=%d, must be NOT_SENT(1)",                     \
             (what), (int)(r).disposition);                                 \
    RC_CHECK((r).output_len == 0,                                           \
             "%s: wrote %zu bytes of output — a refusal has no device "     \
             "output, and a non-empty body defeats both O-Node refusal "    \
             "filters", (what), (size_t)(r).output_len);                    \
    RC_CHECK((r).output[0] == '\0',                                         \
             "%s: output buffer non-empty: '%.40s'", (what), (r).output);   \
    RC_CHECK((r).error_msg[0] != '\0',                                      \
             "%s: no error_msg — the signed ERROR observation is built "    \
             "from it", (what));                                            \
} while (0)

#define RC_REPORT(name) do {                                                \
    if (rc_failures == 0) { printf("  %s [PASS]\n", (name)); return 0; }     \
    printf("  %s [FAIL] (%d)\n", (name), rc_failures); return 1;             \
} while (0)

#endif
