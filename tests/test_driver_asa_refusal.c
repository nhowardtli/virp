/*
 * The ASA driver's BLACK-tier backstop must obey the refusal contract.
 * Source is #included directly: asa_execute() and struct virp_conn are
 * private. Built WITHOUT ASA=1 so libvirp.a does not also export them.
 *
 * connected=true is deliberate. asa_execute checks connectivity BEFORE
 * the BLACK backstop (driver_asa.c:1005 vs :1022), so a disconnected
 * conn would return "Not connected" and never reach the branch under
 * test. driver_linux.c places the same backstop first, which is the
 * stronger invariant; the ASA source carries a dated note proposing the
 * move. Until it moves, this test must connect to reach the code.
 * No transport is touched: the backstop returns before any session use.
 */
#include "../src/drivers/driver_asa.c"
#include "refusal_contract.h"

int main(void)
{
    printf("test_driver_asa_refusal:\n");
    virp_conn_t conn;
    virp_exec_result_t r;

    if (asa_route_command("reload") != VIRP_TIER_BLACK) {
        printf("    FAIL: precondition — 'reload' is not BLACK\n");
        return 1;
    }

    memset(&conn, 0, sizeof(conn));
    conn.connected = true;
    snprintf(conn.device.hostname, sizeof(conn.device.hostname), "ASA-Lab");

    memset(&r, 0, sizeof(r));
    virp_error_t e = asa_execute(&conn, "reload", &r);
    RC_ASSERT_REFUSAL(e, r, "ASA BLACK refusal");

    RC_REPORT("test_asa_black_refusal_obeys_contract");
}
