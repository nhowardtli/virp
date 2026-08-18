/*
 * test_driver_linux_black.c — the linux/proxmox driver must refuse a
 * BLACK-tier command inside its own execute(), regardless of gate mode.
 *
 * Why this exists (audit finding #4): the O-Node gate blocks BLACK only
 * when gate_effective_mode == ENFORCE. Under a per-driver SHADOW override
 * (gate_modes: {"linux":"shadow"}) the gate logs "would-block" and still
 * dispatches to drv->execute(). The ASA/JunOS/IOS/FortiGate drivers each
 * carry an in-driver BLACK refusal for exactly this reason; the
 * linux/proxmox driver did not, so a BLACK `pvesm wipedisk`/`pvesh delete`/`shutdown` would run.
 *
 * linux_execute() and struct virp_conn are private to the driver, so the
 * source is #included directly to exercise the backstop without a live
 * SSH session. Built WITHOUT LINUX=1: linking is against a libvirp.a that
 * does not export the driver, and static-archive extraction never pulls
 * the duplicate object because this TU already defines the symbols.
 */
#include "../src/drivers/driver_linux.c"

#include <stdio.h>
#include <string.h>
#include <assert.h>

static int failures = 0;

#define CHECK(cond, ...) do {                         \
    if (!(cond)) {                                    \
        printf("  FAIL: "); printf(__VA_ARGS__);      \
        printf("\n"); failures++;                     \
    }                                                 \
} while (0)

static void fresh_conn(virp_conn_t *conn, const char *host)
{
    memset(conn, 0, sizeof(*conn));
    /* Deliberately NOT connected: a BLACK refusal must not depend on
     * connectivity, and leaving the session NULL proves the backstop
     * returns before any transport use. */
    conn->connected = false;
    snprintf(conn->device.hostname, sizeof(conn->device.hostname), "%s", host);
}

int main(void)
{
    printf("test_driver_linux_black:\n");
    virp_conn_t conn;
    virp_exec_result_t r;

    /* Precondition: the classifier already grades a destructive Proxmox
     * command BLACK (this is the tier the gate would honour under
     * ENFORCE and skip under SHADOW). */
    assert(linux_gate_tier("pvesm wipedisk local") == VIRP_TIER_BLACK);

    /* 1. THE BACKSTOP: linux_execute must refuse the BLACK command in the
     *    driver, with nothing dispatched — even disconnected, i.e. even
     *    when the O-Node gate was bypassed by a SHADOW override. */
    fresh_conn(&conn, "pve-lab");
    printf("  test_black_command_is_refused_in_driver");
    virp_error_t e = linux_execute(&conn, "pvesm wipedisk local", &r);
    CHECK(e == VIRP_OK, "linux_execute returned err %d", (int)e);
    CHECK(r.success == false, "a BLACK command reported success");
    CHECK(r.no_dispatch == true, "a BLACK command was dispatched (no_dispatch=false)");
    CHECK(r.disposition == VIRP_DISPOSITION_NOT_SENT,
          "BLACK disposition must be NOT_SENT, got %d", (int)r.disposition);
    CHECK(strstr(r.error_msg, "BLACK") != NULL,
          "refusal must name BLACK; got: '%s'", r.error_msg);
    if (!failures) printf(" [PASS]\n");

    /* 2. CONTROL: a non-BLACK command is NOT swallowed by the backstop —
     *    it falls through to the ordinary not-connected path. This proves
     *    the guard is BLACK-specific, not a blanket refusal. */
    int before = failures;
    fresh_conn(&conn, "pve-lab");
    printf("  test_non_black_command_falls_through");
    e = linux_execute(&conn, "uptime", &r);   /* GREEN */
    CHECK(e == VIRP_OK, "linux_execute returned err %d", (int)e);
    CHECK(strstr(r.error_msg, "BLACK") == NULL,
          "a non-BLACK command wrongly hit the BLACK path: '%s'", r.error_msg);
    CHECK(strstr(r.error_msg, "Not connected") != NULL,
          "a non-BLACK disconnected command should be 'Not connected': '%s'",
          r.error_msg);
    if (failures == before) printf(" [PASS]\n");

    printf("\n%s\n", failures
           ? "FAILED"
           : "  PASS: linux/proxmox driver refuses BLACK regardless of gate mode");
    return failures ? 1 : 0;
}
