/*
 * The IOS driver's BLACK-tier backstop must obey the refusal contract.
 * cisco_execute checks BLACK before connectivity (driver_cisco.c:1075 vs
 * :1095), so a disconnected conn reaches the branch — which is the
 * stronger placement, matching driver_linux.c.
 */
#include "../src/drivers/driver_cisco.c"
#include "refusal_contract.h"

int main(void)
{
    printf("test_driver_cisco_refusal:\n");
    virp_conn_t conn;
    virp_exec_result_t r;

    if (!cisco_is_black_tier("reload")) {
        printf("    FAIL: precondition — 'reload' is not BLACK\n");
        return 1;
    }

    memset(&conn, 0, sizeof(conn));
    conn.connected = false;   /* refusal must not depend on reachability */
    snprintf(conn.device.hostname, sizeof(conn.device.hostname), "R1");

    memset(&r, 0, sizeof(r));
    virp_error_t e = cisco_execute(&conn, "reload", &r);
    RC_ASSERT_REFUSAL(e, r, "IOS BLACK refusal");

    RC_REPORT("test_cisco_black_refusal_obeys_contract");
}
