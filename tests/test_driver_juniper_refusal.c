/*
 * The JunOS driver has TWO refusal paths and both must obey the contract:
 * the BLACK-tier backstop, and the multi-command separator guard — a
 * command-injection refusal that was being recorded as an execution.
 *
 * connected=true for the BLACK case: junos_execute_single checks
 * connectivity first (driver_juniper.c:671 vs :680). The separator guard
 * sits in junos_execute ahead of any connectivity check, so that case
 * runs disconnected and proves the refusal is reachability-independent.
 */
#include "../src/drivers/driver_juniper.c"
#include "refusal_contract.h"
#include "virp_scrub.h"

int main(void)
{
    printf("test_driver_juniper_refusal:\n");
    virp_conn_t conn;
    virp_exec_result_t r;

    if (junos_route_command("request system reboot") != VIRP_TIER_BLACK) {
        printf("    FAIL: precondition — reboot is not BLACK\n");
        return 1;
    }

    memset(&conn, 0, sizeof(conn));
    conn.connected = true;
    snprintf(conn.device.hostname, sizeof(conn.device.hostname), "MX-Lab");
    memset(&r, 0, sizeof(r));
    virp_error_t e = junos_execute(&conn, "request system reboot", &r);
    RC_ASSERT_REFUSAL(e, r, "JunOS BLACK refusal");

    /* Separator guard: never reaches the wire, so it stays disconnected. */
    memset(&conn, 0, sizeof(conn));
    conn.connected = false;
    snprintf(conn.device.hostname, sizeof(conn.device.hostname), "MX-Lab");
    memset(&r, 0, sizeof(r));
    e = junos_execute(&conn, "show version\nrequest system reboot", &r);
    RC_ASSERT_REFUSAL(e, r, "JunOS separator refusal");

    /* Complete reply fits raw capture but not hostname + command + reply.
     * The returned length must remain safe through the real scrub path. */
    static char large[VIRP_OUTPUT_MAX];
    memset(large, 'x', sizeof(large)-1);
    large[sizeof(large)-1] = 0;
    memset(&r, 0, sizeof(r));
    if (junos_store_output(&r, "long-hostname-for-boundary", "show version", large) != VIRP_OK ||
        r.output_len != sizeof(r.output)-1 || !r.output_truncated) {
        fprintf(stderr, "FAIL: oversized formatted reply was not bounded\n");
        return 1;
    }
    virp_scrub_exec_result(&r); /* ASan detects any downstream over-read. */
    if (r.output_len >= sizeof(r.output)) return 1;

    RC_REPORT("test_juniper_refusals_obey_contract");
}
