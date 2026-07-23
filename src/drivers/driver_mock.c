/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Mock Device Driver — simulates network devices for testing
 *
 * This driver returns realistic-looking output for common commands
 * so the entire O-Node pipeline can be tested without real hardware.
 */

#define _DEFAULT_SOURCE
#include "virp_driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* Test hook: optional per-execute delay in milliseconds */
static int mock_delay_ms = 0;
void virp_driver_mock_set_delay(int ms) { mock_delay_ms = ms; }

/* Test hook: force drv->execute() to return this error code (0 = disabled) */
static virp_error_t mock_forced_error = VIRP_OK;
void virp_driver_mock_set_forced_error(virp_error_t err) { mock_forced_error = err; }

/* Test hook: force connect() to fail (simulates an unreachable device) */
static bool mock_connect_fail = false;
void virp_driver_mock_set_connect_fail(bool fail) { mock_connect_fail = fail; }

/* Test hook: execute() returns VIRP_OK with success=false, no output, and
 * this error_msg — the soft-failure shape REST drivers use for refused
 * requests (e.g. the Wazuh driver's invalid/BLACK-tier endpoint checks).
 * NULL disables. */
static const char *mock_soft_fail_msg = NULL;
void virp_driver_mock_set_soft_fail(const char *msg) { mock_soft_fail_msg = msg; }

/* =========================================================================
 * Mock connection — just stores the device info
 * ========================================================================= */

struct virp_conn {
    virp_device_t   device;
    bool            connected;
    int             cmd_count;
};

/* =========================================================================
 * Simulated command responses
 * ========================================================================= */

typedef struct {
    const char *command;
    const char *output;
} mock_response_t;

static const mock_response_t mock_cisco_responses[] = {
    {
        "show ip route",
        "Codes: C - connected, S - static, R - RIP, M - mobile, B - BGP\n"
        "Gateway of last resort is not set\n"
        "\n"
        "      6.0.0.0/32 is subnetted, 1 subnets\n"
        "C        6.6.6.6 is directly connected, Loopback0\n"
        "      10.0.0.0/8 is variably subnetted, 6 subnets, 2 masks\n"
        "C        10.0.56.0/24 is directly connected, GigabitEthernet0/1\n"
        "C        10.0.67.0/24 is directly connected, GigabitEthernet0/2\n"
        "C        10.0.68.0/24 is directly connected, GigabitEthernet0/3\n"
        "B        10.0.78.0/24 [200/0] via 10.0.67.7, 02:15:00\n"
        "B        10.0.89.0/24 [200/0] via 10.0.68.8, 01:30:00\n"
    },
    {
        "show ip bgp summary",
        "BGP router identifier 6.6.6.6, local AS number 300\n"
        "BGP table version is 8, main routing table version 8\n"
        "9 network entries using 1296 bytes of memory\n"
        "\n"
        "Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd\n"
        "10.0.56.5       4   300     142     145        8    0    0 02:10:33        4\n"
        "10.0.67.7       4   300     138     140        8    0    0 02:10:30        3\n"
        "10.0.68.8       4   400      95      97        8    0    0 01:30:15        2\n"
    },
    {
        "show ip ospf neighbor",
        "Neighbor ID     Pri   State           Dead Time   Address         Interface\n"
        "5.5.5.5           1   FULL/DR         00:00:35    10.0.56.5       GigabitEthernet0/1\n"
        "7.7.7.7           1   FULL/BDR        00:00:38    10.0.67.7       GigabitEthernet0/2\n"
    },
    {
        "show version",
        "Cisco IOS Software, Version 15.9(3)M7\n"
        "ROM: System Bootstrap, Version 15.1(4)M4\n"
        "R6 uptime is 2 days, 14 hours, 33 minutes\n"
        "System image file is \"flash:c7200-adventerprisek9-mz.152-4.M7.bin\"\n"
        "Cisco 7206VXR (NPE400) processor with 491520K/32768K bytes of memory.\n"
    },
    {
        "show interfaces brief",
        "Interface              IP-Address      OK? Method Status                Protocol\n"
        "GigabitEthernet0/1     10.0.56.6       YES manual up                    up\n"
        "GigabitEthernet0/2     10.0.67.6       YES manual up                    up\n"
        "GigabitEthernet0/3     10.0.68.6       YES manual up                    up\n"
        "Loopback0              6.6.6.6         YES manual up                    up\n"
    },
    { NULL, NULL }
};

static const char *mock_find_response(const char *command)
{
    for (int i = 0; mock_cisco_responses[i].command != NULL; i++) {
        if (strstr(command, mock_cisco_responses[i].command) != NULL)
            return mock_cisco_responses[i].output;
    }
    return NULL;
}

/* =========================================================================
 * Driver Implementation
 * ========================================================================= */

static virp_conn_t *mock_connect(const virp_device_t *device)
{
    if (mock_connect_fail)
        return NULL;

    virp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->connected = true;
    conn->cmd_count = 0;

    return conn;
}

static virp_error_t mock_execute(virp_conn_t *conn,
                                 const char *command,
                                 virp_exec_result_t *result)
{
    if (!conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));

    /* Test hook: simulate driver-level error (not just result.success=false) */
    if (mock_forced_error != VIRP_OK)
        return mock_forced_error;

    /* Test hook: simulate a driver soft-failure (refused before device I/O) */
    if (mock_soft_fail_msg) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "%s", mock_soft_fail_msg);
        return VIRP_OK;
    }

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return VIRP_OK;
    }

    conn->cmd_count++;

    /* Optional delay for parallel execution testing */
    if (mock_delay_ms > 0)
        usleep((unsigned)(mock_delay_ms * 1000));

    /* Look up simulated response */
    const char *response = mock_find_response(command);

    if (response) {
        /* Format like real CLI output: hostname#command\noutput */
        int n = snprintf(result->output, sizeof(result->output),
                         "%s#%s\n%s",
                         conn->device.hostname, command, response);
        result->output_len = (n > 0) ? (size_t)n : 0;
        result->success = true;
        result->exit_code = 0;
    } else {
        /* Unknown command — simulate IOS error */
        int n = snprintf(result->output, sizeof(result->output),
                         "%s#%s\n%% Invalid input detected at '^' marker.\n",
                         conn->device.hostname, command);
        result->output_len = (n > 0) ? (size_t)n : 0;
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Command not recognized: %s", command);
    }

    /* Simulate execution time (5-50ms) */
    result->exec_time_ms = 5 + (rand() % 46);

    return VIRP_OK;
}

static void mock_disconnect(virp_conn_t *conn)
{
    if (!conn) return;
    conn->connected = false;
    free(conn);
}

static bool mock_detect(virp_conn_t *conn)
{
    if (!conn) return false;
    return conn->device.vendor == VIRP_VENDOR_MOCK;
}

static virp_error_t mock_health_check(virp_conn_t *conn)
{
    if (!conn) return VIRP_ERR_NULL_PTR;
    return conn->connected ? VIRP_OK : VIRP_ERR_KEY_NOT_LOADED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

/*
 * Minimal gate classifier so the mock driver behaves like a production
 * driver under the fail-closed ENFORCE default: read-only commands are
 * GREEN, state-changing ones YELLOW, destructive ones RED, anything
 * unrecognized stays UNCLASSIFIED (blocked under ENFORCE).
 */
static virp_trust_tier_t mock_route_command(const char *command)
{
    if (!command) return VIRP_TIER_UNCLASSIFIED;
    while (*command == ' ' || *command == '\t') command++;

    if (strncmp(command, "show ", 5) == 0 ||
        strcmp(command, "show") == 0 ||
        strncmp(command, "get ", 4) == 0)
        return VIRP_TIER_GREEN;

    if (strncmp(command, "configure", 9) == 0 ||
        strncmp(command, "clear ", 6) == 0 ||
        strncmp(command, "write", 5) == 0 ||
        strncmp(command, "copy ", 5) == 0)
        return VIRP_TIER_YELLOW;

    if (strncmp(command, "reload", 6) == 0 ||
        strncmp(command, "erase ", 6) == 0)
        return VIRP_TIER_RED;

    return VIRP_TIER_UNCLASSIFIED;
}

static virp_driver_t mock_driver = {
    .name       = "mock",
    .vendor     = VIRP_VENDOR_MOCK,
    .connect    = mock_connect,
    .execute    = mock_execute,
    .disconnect = mock_disconnect,
    .detect     = mock_detect,
    .health_check = mock_health_check,
    .route_command = mock_route_command,
};

void virp_driver_mock_init(void)
{
    virp_driver_register(&mock_driver);
}
