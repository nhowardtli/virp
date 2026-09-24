/*
 * The PAN-OS driver's BLACK-tier backstop must obey the refusal
 * contract. Source is #included directly: pa_execute() and struct
 * virp_conn are private. Built WITHOUT PANOS=1 so libvirp.a does not
 * also export them.
 *
 * connected=false is deliberate. pa_execute places the BLACK backstop
 * BEFORE the connected check (driver_linux.c precedent — refusing a
 * destructive command is a policy decision independent of
 * reachability), so the refusal must fire on an unreachable device
 * too. No transport is touched: the backstop returns before any
 * session use.
 */
#include "../src/driver_panos.c"
#include "refusal_contract.h"
#include "virp_scrub.h"

int main(void)
{
    printf("test_driver_panos_refusal:\n");
    virp_conn_t conn;
    virp_exec_result_t r;

    if (pa_route_command("request restart system") != VIRP_TIER_BLACK) {
        printf("    FAIL: precondition — 'request restart system' is not "
               "BLACK\n");
        return 1;
    }

    memset(&conn, 0, sizeof(conn));
    conn.connected = false;              /* policy beats reachability */
    snprintf(conn.device.hostname, sizeof(conn.device.hostname), "PA-Lab");

    memset(&r, 0, sizeof(r));
    virp_error_t e = pa_execute(&conn, "request restart system", &r);
    RC_ASSERT_REFUSAL(e, r, "PAN-OS BLACK refusal (disconnected)");

    memset(&r, 0, sizeof(r));
    e = pa_execute(&conn, "commit force", &r);
    RC_ASSERT_REFUSAL(e, r, "PAN-OS BLACK refusal (commit)");

    /* Complete reply fits raw capture but not hostname + command + reply.
     * The returned length must remain safe through the real scrub path. */
    static char large[VIRP_OUTPUT_MAX];
    memset(large, 'x', sizeof(large)-1);
    large[sizeof(large)-1] = 0;
    memset(&r, 0, sizeof(r));
    if (pa_store_output(&r, "long-hostname-for-boundary", "show version", large) != VIRP_OK ||
        r.output_len != sizeof(r.output)-1 || !r.output_truncated) {
        fprintf(stderr, "FAIL: oversized formatted reply was not bounded\n");
        return 1;
    }
    virp_scrub_exec_result(&r); /* ASan detects any downstream over-read. */
    if (r.output_len >= sizeof(r.output)) return 1;

    RC_REPORT("test_panos_black_refusal_obeys_contract");
}
