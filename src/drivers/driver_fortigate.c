/*
 * driver_fortigate.c — FortiGate device driver implementation
 *
 * Ported to VIRP appliance type system (fixed buffers, virp_driver.h).
 *
 * Implements the five virp_driver_t functions:
 *   connect     — Establish SSH connection
 *   execute     — Run command via SSH, return output
 *   disconnect  — Tear down SSH transport
 *   detect      — Probe device to confirm it's a FortiGate
 *   health_check — Verify device is responsive and healthy
 *
 * SSH-only transport. Commands collected:
 *   get system status
 *   get system performance status
 *   get router info bgp summary
 *   get system interface physical
 *   diagnose sys session stat
 *
 * Dependencies:
 *   - libssh2 (SSH transport)
 *   - libssl  (TLS, already a VIRP dependency)
 *
 * Build:  make CISCO=1 FORTIGATE=1
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libssh2.h>
#include <openssl/crypto.h>

#include "virp_driver.h"
#include "virp_driver_fortigate.h"
#include "virp_ssh_hostkey.h"


/* ══════════════════════════════════════════════════════════════════
 * CONNECTION STATE
 *
 * Appliance pattern: each driver defines its own 'struct virp_conn'.
 * The O-Node sees only an opaque pointer.
 * ══════════════════════════════════════════════════════════════════ */

struct virp_conn {
    virp_device_t       device;         /* Copy of device config */

    /* SSH transport */
    LIBSSH2_SESSION    *ssh_session;
    int                 ssh_socket;
    int                 ssh_port;

    /* State */
    bool                ssh_connected;
    bool                vdom_enabled;
    bool                vdom_probed;
};


/* ══════════════════════════════════════════════════════════════════
 * SSH HELPERS
 * ══════════════════════════════════════════════════════════════════ */

#define FG_SSH_READ_TIMEOUT_MS  15000
#define FG_SSH_BUFFER_SIZE      65536

static int fg_ssh_connect(struct virp_conn *conn)
{
    struct sockaddr_in sin;
    int sock;
    int rc;
    char *errmsg = NULL;
    int errlen = 0;

    fprintf(stderr, "[virp-fg] SSH connect to %s:%d as %s\n",
            conn->device.host, conn->ssh_port, conn->device.username);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[virp-fg] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(conn->ssh_port);

    if (inet_pton(AF_INET, conn->device.host, &sin.sin_addr) <= 0) {
        fprintf(stderr, "[virp-fg] inet_pton(%s) failed: %s\n",
                conn->device.host, strerror(errno));
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        fprintf(stderr, "[virp-fg] TCP connect to %s:%d failed: %s\n",
                conn->device.host, conn->ssh_port, strerror(errno));
        close(sock);
        return -1;
    }

    fprintf(stderr, "[virp-fg] TCP connected, starting libssh2 handshake\n");
    conn->ssh_socket = sock;

    LIBSSH2_SESSION *session = libssh2_session_init();
    if (!session) {
        fprintf(stderr, "[virp-fg] libssh2_session_init() returned NULL\n");
        close(sock);
        return -1;
    }

    libssh2_session_set_timeout(session, 30000);

    rc = libssh2_session_handshake(session, sock);
    if (rc != 0) {
        libssh2_session_last_error(session, &errmsg, &errlen, 0);
        fprintf(stderr, "[virp-fg] libssh2_session_handshake() failed: "
                "rc=%d errmsg=\"%s\"\n", rc, errmsg ? errmsg : "(null)");
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    fprintf(stderr, "[virp-fg] handshake OK, verifying host key\n");

    virp_error_t hk_err = virp_ssh_verify_hostkey(session, conn->device.host,
                                                   conn->ssh_port);
    if (hk_err != VIRP_OK) {
        fprintf(stderr, "[virp-fg] Host key verification failed: %s\n",
                virp_error_str(hk_err));
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    rc = libssh2_userauth_password(session,
                                   conn->device.username,
                                   conn->device.password);
    if (rc != 0) {
        libssh2_session_last_error(session, &errmsg, &errlen, 0);
        fprintf(stderr, "[virp-fg] libssh2_userauth_password() failed: "
                "rc=%d errmsg=\"%s\"\n", rc, errmsg ? errmsg : "(null)");
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    fprintf(stderr, "[virp-fg] SSH authenticated to %s:%d\n",
            conn->device.host, conn->ssh_port);

    conn->ssh_session = session;
    conn->ssh_connected = true;

    return 0;
}

/* Returns true if command requires VDOM context (routing/diag commands) */
static bool fg_command_needs_vdom(const char *command)
{
    while (*command == ' ' || *command == '\t') command++;

    return (strncasecmp(command, "get router ",      11) == 0
         || strncasecmp(command, "show router ",     12) == 0
         || strncasecmp(command, "diagnose ",         9) == 0);
}

static virp_error_t fg_ssh_execute(struct virp_conn *conn,
                                   const char *command,
                                   virp_exec_result_t *result)
{
    if (!conn->ssh_session || !conn->ssh_connected)
        return FG_ERR_NOT_CONNECTED;

    LIBSSH2_SESSION *session = conn->ssh_session;
    LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
    if (!channel)
        return FG_ERR_TRANSPORT;

    if (libssh2_channel_request_pty(channel, "xterm") != 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return FG_ERR_TRANSPORT;
    }

    if (libssh2_channel_shell(channel) != 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return FG_ERR_TRANSPORT;
    }

    /* Drain initial prompt/banner before sending command */
    libssh2_session_set_blocking(session, 0);
    {
        char drain[4096];
        int drain_idle = 0;
        while (drain_idle < 15) {
            ssize_t n = libssh2_channel_read(channel, drain, sizeof(drain) - 1);
            if (n > 0) {
                drain_idle = 0;
            } else if (n == LIBSSH2_ERROR_EAGAIN) {
                drain_idle++;
                usleep(100000);
            } else {
                break;
            }
        }
    }
    libssh2_session_set_blocking(session, 1);

    /* If VDOMs are enabled and this command needs VDOM context,
     * prepend the context switch before the actual command.
     * Each channel is a fresh shell so we must switch every time. */
    const char *vdom = conn->device.vdom[0] ? conn->device.vdom : "root";

    char cmd_buf[4096];
    int cmd_len;

    if (conn->vdom_enabled && fg_command_needs_vdom(command)) {
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf),
                           "config vdom\nedit %s\n%s\nend\n",
                           vdom, command);
    } else {
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "%s\n", command);
    }
    libssh2_channel_write(channel, cmd_buf, cmd_len);

    /* Read output into temp buffer */
    char *raw = calloc(FG_SSH_BUFFER_SIZE, 1);
    if (!raw) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "out of memory for SSH read buffer");
        result->success = false;
        return VIRP_OK;
    }

    size_t total = 0;
    int idle_cycles = 0;
    libssh2_session_set_blocking(session, 0);

    while (total < FG_SSH_BUFFER_SIZE - 1 && idle_cycles < 30) {
        ssize_t n = libssh2_channel_read(channel,
                                         raw + total,
                                         FG_SSH_BUFFER_SIZE - total - 1);
        if (n > 0) {
            total += n;
            idle_cycles = 0;

            if (total > 3 && raw[total - 1] == ' '
                          && raw[total - 2] == '#') {
                break;
            }
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            idle_cycles++;
            usleep(100000);
        } else {
            break;
        }
    }

    libssh2_session_set_blocking(session, 1);
    raw[total] = '\0';

    /* Strip command echo and trailing prompt */
    char *start = strstr(raw, "\n");
    if (start) start++;
    else start = raw;

    char *end = raw + total;
    while (end > start && (end[-1] == ' ' || end[-1] == '#'
                           || end[-1] == '\r' || end[-1] == '\n'))
        end--;
    char *prompt_line = end;
    while (prompt_line > start && prompt_line[-1] != '\n')
        prompt_line--;

    size_t payload_len = (size_t)(prompt_line - start);
    if (payload_len > 0 && start[payload_len - 1] == '\r')
        payload_len--;

    /* Copy into fixed-size result buffer */
    if (payload_len >= VIRP_OUTPUT_MAX)
        payload_len = VIRP_OUTPUT_MAX - 1;

    memcpy(result->output, start, payload_len);
    result->output[payload_len] = '\0';
    result->output_len = payload_len;
    result->success = true;
    result->exit_code = 0;

    free(raw);
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);

    return VIRP_OK;
}


/* ══════════════════════════════════════════════════════════════════
 * DRIVER INTERFACE IMPLEMENTATION
 * ══════════════════════════════════════════════════════════════════ */

/* ── connect ────────────────────────────────────────────────────── */
static virp_conn_t *fg_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    /* Copy device config */
    memcpy(&conn->device, device, sizeof(*device));

    conn->ssh_port = device->port ? device->port : 22;
    conn->ssh_socket = -1;

    /* Establish SSH connection */
    if (device->username[0] == '\0' || device->password[0] == '\0') {
        free(conn);
        return NULL;
    }

    if (fg_ssh_connect(conn) != 0) {
        free(conn);
        return NULL;
    }

    /* Probe for VDOM mode — run "get system status" and look for
     * "Virtual domain configuration: enable" in the output.
     * This runs once at connect time so fg_execute knows whether
     * to prepend VDOM context switches. */
    virp_exec_result_t probe;
    memset(&probe, 0, sizeof(probe));
    if (fg_ssh_execute(conn, "get system status", &probe) == VIRP_OK
        && probe.success) {
        conn->vdom_enabled =
            (strstr(probe.output, "Virtual domain configuration: enable")
             != NULL);
        conn->vdom_probed = true;
        fprintf(stderr, "[virp-fg] VDOM probe: %s\n",
                conn->vdom_enabled ? "enabled" : "disabled");
    }

    return (virp_conn_t *)conn;
}


/* ══════════════════════════════════════════════════════════════════
 * Command Routing Table — FortiOS commands → trust tiers
 *
 * Prefix-matched, longest match wins (mirrors asa_route_command /
 * junos_route_command). FAIL-CLOSED: unmapped commands default to RED
 * (they used to default YELLOW, which cleared the gate).
 *
 * Tiering policy for this fleet:
 *   GREEN  — passive monitoring reads (status, perf, routing table)
 *   YELLOW — config-visibility reads, backups, active diagnostics.
 *            'show full-configuration' is the backup path and MUST stay
 *            at/under a YELLOW threshold so scheduled backups keep working.
 *   RED    — credential / admin-account reads and any config-mode change
 *            (approval-worthy).
 *
 * NOTE: destructive ops (reboot/factoryreset/…) are handled separately
 * by fg_is_black_tier() and are intentionally NOT in this table.
 * ══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char        *command_pattern;   /* CLI command prefix */
    virp_trust_tier_t  tier;
} fg_command_route_t;

static const fg_command_route_t FG_ROUTE_TABLE[] = {
    /* ── GREEN — passive monitoring (no approval) ──────────────── */
    { "get system status",          VIRP_TIER_GREEN  },
    { "get system performance",     VIRP_TIER_GREEN  },
    { "get hardware",               VIRP_TIER_GREEN  },
    { "get system interface",       VIRP_TIER_GREEN  },
    { "get router info",            VIRP_TIER_GREEN  },
    { "get router",                 VIRP_TIER_GREEN  },
    { "show router",                VIRP_TIER_GREEN  },

    /* ── YELLOW — config reads, backups, active diagnostics ────── */
    { "show full-configuration",    VIRP_TIER_YELLOW },  /* backup path — keep <= YELLOW */
    { "execute backup",             VIRP_TIER_YELLOW },  /* alternate backup path */
    { "diagnose",                   VIRP_TIER_YELLOW },  /* active diagnostics */
    { "execute ping",               VIRP_TIER_YELLOW },
    { "execute traceroute",         VIRP_TIER_YELLOW },
    { "show system interface",      VIRP_TIER_YELLOW },
    { "show firewall",              VIRP_TIER_YELLOW },
    { "show vpn",                   VIRP_TIER_YELLOW },
    { "show",                       VIRP_TIER_YELLOW },  /* generic config-section read */

    /* ── RED — credential/admin reads + config-mode changes ────── */
    { "show system admin",          VIRP_TIER_RED    },  /* admin accounts, pw hashes, tokens */
    { "get system admin",           VIRP_TIER_RED    },
    { "show system api-user",       VIRP_TIER_RED    },  /* API credentials */
    { "get system api-user",        VIRP_TIER_RED    },
    { "show user",                  VIRP_TIER_RED    },  /* credential/user reads */
    { "get user",                   VIRP_TIER_RED    },
    { "config system admin",        VIRP_TIER_RED    },  /* admin-account change */
    { "config",                     VIRP_TIER_RED    },  /* any config-mode change */
};

static const size_t FG_ROUTE_TABLE_SIZE =
    sizeof(FG_ROUTE_TABLE) / sizeof(FG_ROUTE_TABLE[0]);

/*
 * Test-support accessors — see the equivalent pair in driver_cisco.c.
 * Lets the table-driven reachability suite prove every entry is
 * reachable and returns the tier it declares.
 */
size_t fg_route_table_count(void)
{
    return FG_ROUTE_TABLE_SIZE;
}

const char *fg_route_table_entry(size_t i, virp_trust_tier_t *tier)
{
    if (i >= FG_ROUTE_TABLE_SIZE) return NULL;
    if (tier) *tier = FG_ROUTE_TABLE[i].tier;
    return FG_ROUTE_TABLE[i].command_pattern;
}

virp_trust_tier_t fg_route_command(const char *command)
{
    if (!command) return VIRP_TIER_RED;              /* fail closed */

    /*
     * Layer 3a — a separator-carrying string is not one command, so this
     * table cannot vouch for it. Fail closed to RED here as well as at
     * the daemon boundary, because fg_route_command is directly callable.
     */
    if (virp_command_check_separators(command, NULL, 0) != 0)
        return VIRP_TIER_RED;

    /* Skip leading whitespace so " show system admin" still classifies. */
    while (*command == ' ' || *command == '\t') command++;

    const fg_command_route_t *best = NULL;
    size_t best_len = 0;

    for (size_t i = 0; i < FG_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(FG_ROUTE_TABLE[i].command_pattern);
        if (strncasecmp(command, FG_ROUTE_TABLE[i].command_pattern, plen) != 0)
            continue;

        /*
         * Layer 3b — the match must END on a token boundary so a listed
         * prefix cannot stand in for a longer word. This matters most for
         * the deliberately broad catch-alls here ("show", "config"):
         * without it "showdown" would inherit "show"'s YELLOW. Entries
         * ending in a space carry their own boundary; longest valid match
         * still wins.
         */
        char after = command[plen];
        bool self_terminated = (plen > 0 &&
            FG_ROUTE_TABLE[i].command_pattern[plen - 1] == ' ');
        if (!self_terminated && after != '\0' &&
            after != ' ' && after != '\t')
            continue;

        if (plen > best_len) {
            best = &FG_ROUTE_TABLE[i];
            best_len = plen;
        }
    }

    /* Fail-closed: anything not explicitly listed is RED. An unlisted
     * command used to return YELLOW, which CLEARED the default YELLOW
     * gate threshold and executed unreviewed. */
    return best ? best->tier : VIRP_TIER_RED;
}


/* ══════════════════════════════════════════════════════════════════
 * BLACK Tier — Destructive commands that must never reach the wire.
 *
 * Prefix-matched (case-insensitive).  Any command that starts with
 * one of these strings is rejected outright at the driver level.
 * ══════════════════════════════════════════════════════════════════ */

static const char *FG_BLACK_COMMANDS[] = {
    "execute factoryreset",
    "execute formatdisk",
    "execute reboot",
    "execute shutdown",
    "fnsysctl",
};
static const size_t FG_BLACK_COUNT =
    sizeof(FG_BLACK_COMMANDS) / sizeof(FG_BLACK_COMMANDS[0]);

bool fg_is_black_tier(const char *command)
{
    if (!command) return false;
    for (size_t i = 0; i < FG_BLACK_COUNT; i++) {
        size_t plen = strlen(FG_BLACK_COMMANDS[i]);
        if (strncasecmp(command, FG_BLACK_COMMANDS[i], plen) == 0)
            return true;
    }
    return false;
}

/* ── execute ────────────────────────────────────────────────────── */
static virp_error_t fg_execute(virp_conn_t *base_conn,
                               const char *command,
                               virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    /* ── BLACK tier safety: never execute destructive commands ── */
    if (fg_is_black_tier(command)) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "BLACK tier: command blocked on %s",
                 conn->device.hostname);
        fprintf(stderr, "[FortiGate] BLACK tier blocked: '%s' on %s\n",
                command, conn->device.hostname);
        int written = snprintf(result->output, sizeof(result->output),
                               "%s $ %s\nBLACK tier: command forbidden",
                               conn->device.hostname, command);
        result->output_len = (written > 0) ? (size_t)written : 0;
        return VIRP_OK;
    }

    if (!conn->ssh_connected) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "SSH not connected");
        result->success = false;
        return FG_ERR_NOT_CONNECTED;
    }

    return fg_ssh_execute(conn, command, result);
}


/* ── disconnect ─────────────────────────────────────────────────── */
static void fg_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (conn->ssh_session) {
        libssh2_session_disconnect(conn->ssh_session, "VIRP disconnect");
        libssh2_session_free(conn->ssh_session);
        conn->ssh_session = NULL;
    }
    if (conn->ssh_socket >= 0) {
        close(conn->ssh_socket);
        conn->ssh_socket = -1;
    }
    conn->ssh_connected = false;

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
    free(conn);
}


/* ── detect ─────────────────────────────────────────────────────── */
static bool fg_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->ssh_connected) return false;

    virp_exec_result_t result;
    memset(&result, 0, sizeof(result));

    virp_error_t err = fg_ssh_execute(conn, "get system status", &result);
    if (err != VIRP_OK || !result.success)
        return false;

    return (strstr(result.output, "Version") != NULL
         && strstr(result.output, "FortiGate") != NULL);
}


/* ── health_check ───────────────────────────────────────────────── */
static virp_error_t fg_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->ssh_connected)
        return FG_ERR_NOT_CONNECTED;

    virp_exec_result_t result;
    memset(&result, 0, sizeof(result));

    virp_error_t err = fg_ssh_execute(conn, "get system status", &result);
    if (err != VIRP_OK || !result.success)
        return err ? err : FG_ERR_TRANSPORT;

    return VIRP_OK;
}


/* ══════════════════════════════════════════════════════════════════
 * DRIVER REGISTRATION
 * ══════════════════════════════════════════════════════════════════ */

static const virp_driver_t fg_driver = {
    .name        = "fortigate",
    .vendor      = VIRP_VENDOR_FORTINET,
    .connect     = fg_connect,
    .execute     = fg_execute,
    .disconnect  = fg_disconnect,
    .detect      = fg_detect,
    .health_check = fg_health_check,
    .route_command = fg_route_command,
};

void virp_driver_fortinet_init(void)
{
    virp_driver_register(&fg_driver);
}
