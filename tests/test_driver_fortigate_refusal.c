/*
 * The FortiGate driver had TWO false-execution paths by two different
 * mechanisms, and both are covered here:
 *
 *   1. the BLACK backstop, which set no no_dispatch at all (this driver
 *      had zero no_dispatch assignments anywhere in the file), and
 *   2. not-connected, which returned FG_ERR_NOT_CONNECTED. A non-VIRP_OK
 *      return reaches virp_onode.c:1804 with result==NULL, where executed
 *      defaults to true because a driver that errored proved nothing.
 *      Not-connected IS provable non-dispatch; every other driver signals
 *      it as VIRP_OK + no_dispatch.
 */
#include "../src/drivers/driver_fortigate.c"
#include "refusal_contract.h"

int main(void)
{
    printf("test_driver_fortigate_refusal:\n");
    virp_conn_t conn;
    virp_exec_result_t r;

    if (!fg_is_black_tier("execute reboot")) {
        printf("    FAIL: precondition — 'execute reboot' is not BLACK\n");
        return 1;
    }

    memset(&conn, 0, sizeof(conn));
    conn.ssh_connected = false;
    snprintf(conn.device.hostname, sizeof(conn.device.hostname), "FG-Lab");
    memset(&r, 0, sizeof(r));
    virp_error_t e = fg_execute((virp_conn_t *)&conn, "execute reboot", &r);
    RC_ASSERT_REFUSAL(e, r, "FortiGate BLACK refusal");

    /* Not-connected must now be a contract refusal, not an error return. */
    memset(&conn, 0, sizeof(conn));
    conn.ssh_connected = false;
    snprintf(conn.device.hostname, sizeof(conn.device.hostname), "FG-Lab");
    memset(&r, 0, sizeof(r));
    e = fg_execute((virp_conn_t *)&conn, "get system status", &r);
    RC_ASSERT_REFUSAL(e, r, "FortiGate not-connected");

    RC_REPORT("test_fortigate_refusals_obey_contract");
}
