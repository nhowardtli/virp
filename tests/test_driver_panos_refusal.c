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

    RC_REPORT("test_panos_black_refusal_obeys_contract");
}
