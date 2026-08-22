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
#include <pthread.h>
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

/* Test hook: execute() returns VIRP_OK with success=false, no output,
 * this error_msg, and no_dispatch=false — the shape of a command that
 * may have DISPATCHED but produced no response (SSH write completed,
 * response lost; REST timeout after send). The O-Node must not retry
 * this and must report OUTCOME_UNKNOWN. NULL disables. */
static const char *mock_unknown_fail_msg = NULL;
void virp_driver_mock_set_unknown_fail(const char *msg) { mock_unknown_fail_msg = msg; }

/* Test hook: execute() returns VIRP_OK with success=false, exit_code=1
 * (trusted) and this text as the device's own response — a command that
 * DISPATCHED, completed, and was refused by the device ("% Invalid
 * input"). disposition is left UNSET on purpose so the O-Node's
 * resolver exercises the legacy rule most real drivers still rely on:
 * failure WITH output is EXECUTED_FAILED. NULL disables. */
static const char *mock_exec_failed_output = NULL;
void virp_driver_mock_set_exec_failed(const char *output) { mock_exec_failed_output = output; }

/* Test hook: execute() succeeds and returns EXACTLY this text as the
 * device response body. Lets a test put chosen bytes — credential-shaped
 * material in particular — into a GREEN device response and then assert
 * what does and does not reach the chain. NULL disables. */
static const char *mock_output_override = NULL;
void virp_driver_mock_set_output(const char *text) { mock_output_override = text; }

/*
 * Test hook: simulate a single shared SSH channel per connection.
 *
 * A real driver holds one libssh2 channel per session: execute() writes
 * the command, then reads until the prompt, and ANY bytes another
 * caller put on that channel meanwhile are read as part of this
 * command's output — and then signed. When enabled, health_check()
 * appends MOCK_HEALTH_PROBE_MARKER to the connection's channel buffer
 * and execute() prepends whatever landed there during its read window
 * to its own output, so an unserialized watchdog probe is visible in
 * the observation body. Off by default; no other test is affected.
 */
static bool mock_shared_channel = false;

/*
 * Count of health_check() calls for ONE watched hostname, so a
 * concurrency test can prove the watchdog actually probed its device
 * rather than passing because it never ran. Filtered by hostname
 * because other O-Node instances in the same test process run their
 * own watchdogs against their own mock devices.
 *
 * These hook globals are read by watchdog threads while test threads
 * write them, so they are guarded. mock_hook_mutex is a leaf lock — no
 * other lock is ever acquired while it is held.
 */
static pthread_mutex_t mock_hook_mutex = PTHREAD_MUTEX_INITIALIZER;
static int  mock_probe_count = 0;
static char mock_probe_filter[64] = "";

/* Count every execute() invocation, so retry tests can assert exactly
 * how many times the O-Node dispatched. Reset returns the prior count. */
static int mock_exec_attempts = 0;
int virp_driver_mock_exec_attempts_reset(void)
{
    pthread_mutex_lock(&mock_hook_mutex);
    int n = mock_exec_attempts;
    mock_exec_attempts = 0;
    pthread_mutex_unlock(&mock_hook_mutex);
    return n;
}

static void mock_count_exec_attempt(void)
{
    pthread_mutex_lock(&mock_hook_mutex);
    mock_exec_attempts++;
    pthread_mutex_unlock(&mock_hook_mutex);
}

void virp_driver_mock_set_shared_channel(bool on)
{
    pthread_mutex_lock(&mock_hook_mutex);
    mock_shared_channel = on;
    pthread_mutex_unlock(&mock_hook_mutex);
}

static bool mock_shared_channel_on(void)
{
    pthread_mutex_lock(&mock_hook_mutex);
    bool on = mock_shared_channel;
    pthread_mutex_unlock(&mock_hook_mutex);
    return on;
}

void virp_driver_mock_watch_probes(const char *hostname)
{
    pthread_mutex_lock(&mock_hook_mutex);
    snprintf(mock_probe_filter, sizeof(mock_probe_filter), "%s",
             hostname ? hostname : "");
    mock_probe_count = 0;
    pthread_mutex_unlock(&mock_hook_mutex);
}

int virp_driver_mock_probe_count(void)
{
    pthread_mutex_lock(&mock_hook_mutex);
    int n = mock_probe_count;
    pthread_mutex_unlock(&mock_hook_mutex);
    return n;
}

/* =========================================================================
 * Mock connection — just stores the device info
 * ========================================================================= */

struct virp_conn {
    virp_device_t   device;
    bool            connected;
    int             cmd_count;
    /* Simulated shared channel buffer — see mock_shared_channel. */
    char            chan_buf[256];
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
    mock_count_exec_attempt();

    /* Test hook: simulate driver-level error (not just result.success=false) */
    if (mock_forced_error != VIRP_OK)
        return mock_forced_error;

    /* Test hook: possible dispatch, no response — no_dispatch stays
     * false; the O-Node must not retry and must report OUTCOME_UNKNOWN. */
    if (mock_unknown_fail_msg) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "%s", mock_unknown_fail_msg);
        return VIRP_OK;
    }

    /* Test hook: device answered with a failure (dispatched, completed,
     * refused by the device) — EXECUTED_FAILED through the resolver. */
    if (mock_exec_failed_output) {
        int n = snprintf(result->output, sizeof(result->output), "%s",
                         mock_exec_failed_output);
        size_t cap = sizeof(result->output) - 1;
        result->output_len = (n > 0) ? (((size_t)n > cap) ? cap : (size_t)n)
                                     : 0;
        result->success = false;
        result->exit_code = 1;
        result->exit_code_trusted = true;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "device rejected command");
        return VIRP_OK;
    }

    /* Test hook: simulate a driver soft-failure (refused before device I/O) */
    if (mock_soft_fail_msg) {
        result->success = false;
        result->no_dispatch = true;   /* refusal is provably pre-dispatch */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "%s", mock_soft_fail_msg);
        return VIRP_OK;
    }

    if (!conn->connected) {
        result->success = false;
        result->no_dispatch = true;   /* refused before any transport write */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return VIRP_OK;
    }

    conn->cmd_count++;

    /* Command written to the channel — the read window opens here, so
     * anything already buffered from a previous read is drained. */
    bool shared = mock_shared_channel_on();
    if (shared)
        conn->chan_buf[0] = '\0';

    /* Optional delay for parallel execution testing */
    if (mock_delay_ms > 0)
        usleep((unsigned)(mock_delay_ms * 1000));

    /* Test hook: caller-chosen response body, returned verbatim. Length is
     * clamped to what the buffer actually holds — snprintf reports the
     * would-be length, and output_len must never describe bytes that are
     * not there. */
    if (mock_output_override) {
        int n = snprintf(result->output, sizeof(result->output), "%s",
                         mock_output_override);
        size_t cap = sizeof(result->output) - 1;
        result->output_len = (n > 0) ? (((size_t)n > cap) ? cap : (size_t)n)
                                     : 0;
        result->success = true;
        result->exit_code = 0;
        result->exec_time_ms = 5;
        return VIRP_OK;
    }

    /* Look up simulated response */
    const char *response = mock_find_response(command);

    /* Read the channel: foreign bytes that arrived during the window
     * come off it first, exactly as a real driver would read them. */
    const char *chan = shared ? conn->chan_buf : "";

    if (response) {
        /* Format like real CLI output: hostname#command\noutput */
        int n = snprintf(result->output, sizeof(result->output),
                         "%s%s#%s\n%s",
                         chan, conn->device.hostname, command, response);
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

    pthread_mutex_lock(&mock_hook_mutex);
    bool shared = mock_shared_channel;
    if (mock_probe_filter[0] &&
        strcmp(conn->device.hostname, mock_probe_filter) == 0)
        mock_probe_count++;
    pthread_mutex_unlock(&mock_hook_mutex);

    /* A real health_check writes a keepalive/probe to the channel and
     * reads the reply. With mock_shared_channel on, those bytes are
     * left on the same channel execute() reads from. */
    if (shared) {
        size_t used = strlen(conn->chan_buf);
        snprintf(conn->chan_buf + used, sizeof(conn->chan_buf) - used,
                 "%s", MOCK_HEALTH_PROBE_MARKER);
    }

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
