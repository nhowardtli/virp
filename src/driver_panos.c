/*
 * driver_panos.c — PAN-OS device driver implementation
 *
 * SSH-only driver for Palo Alto Networks firewalls (PA-series, VM-series).
 * Uses interactive SSH shell with plain-text CLI output.
 *
 * Implements the five virp_driver_t functions:
 *   connect     — Establish SSH session, disable pager
 *   execute     — Send command, read until prompt, scrub output
 *   disconnect  — Tear down SSH session
 *   detect      — Run 'show system info' and look for PAN-OS markers
 *   health_check — Verify device is responsive via 'show clock'
 *
 * Key design decisions:
 *   - SSH only. PAN-OS XML API is available but CLI is simpler for VIRP.
 *   - Interactive shell (like Cisco driver), NOT exec channels.
 *   - Prompt: username@hostname> (op mode) or username@hostname# (config).
 *   - Paging disabled via "set cli pager off" at connect.
 *   - No enable mode — PAN-OS op mode has full read access.
 *   - Command routing table maps CLI patterns to VIRP trust tiers.
 *
 * Dependencies:
 *   - libssh2 (SSH transport)
 *
 * Build:  make PANOS=1
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "driver_panos.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <libssh2.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

#define PA_SSH_READ_TIMEOUT_MS     15000   /* 15 seconds per read */
#define PA_SSH_CONNECT_TIMEOUT_SEC 10
#define PA_SSH_READ_BUF_SIZE       32768
#define PA_SSH_MAX_PROMPT_LEN      128

/* =========================================================================
 * Command Routing Table — maps CLI commands to VIRP trust tiers
 *
 * Prefix-matched against incoming commands. First match wins.
 * Unmatched commands default to YELLOW tier.
 * ========================================================================= */

const pa_command_route_t PA_ROUTE_TABLE[] = {
    /* GREEN TIER — passive read-only monitoring */
    { "show system info",                   VIRP_TIER_GREEN },
    { "show system state",                  VIRP_TIER_GREEN },
    { "show system resources",              VIRP_TIER_GREEN },
    { "show system environmentals",         VIRP_TIER_GREEN },
    { "show system software",              VIRP_TIER_GREEN },
    { "show system disk-space",             VIRP_TIER_GREEN },
    { "show interface all",                 VIRP_TIER_GREEN },
    { "show interface ethernet",            VIRP_TIER_GREEN },
    { "show interface loopback",            VIRP_TIER_GREEN },
    { "show interface tunnel",              VIRP_TIER_GREEN },
    { "show interface vlan",                VIRP_TIER_GREEN },
    { "show interface aggregate-ethernet",  VIRP_TIER_GREEN },
    { "show session info",                  VIRP_TIER_GREEN },
    { "show session all",                   VIRP_TIER_GREEN },
    { "show session id",                    VIRP_TIER_GREEN },
    { "show session meter",                 VIRP_TIER_GREEN },
    { "show high-availability state",       VIRP_TIER_GREEN },
    { "show high-availability all",         VIRP_TIER_GREEN },
    { "show high-availability",             VIRP_TIER_GREEN },
    { "show arp all",                       VIRP_TIER_GREEN },
    { "show arp",                           VIRP_TIER_GREEN },
    { "show routing route",                 VIRP_TIER_GREEN },
    { "show routing summary",              VIRP_TIER_GREEN },
    { "show routing protocol",              VIRP_TIER_GREEN },
    { "show routing",                       VIRP_TIER_GREEN },
    { "show clock",                         VIRP_TIER_GREEN },
    { "show counter global",               VIRP_TIER_GREEN },
    { "show counter interface",             VIRP_TIER_GREEN },
    { "show counter",                       VIRP_TIER_GREEN },
    { "show jobs all",                      VIRP_TIER_GREEN },
    { "show jobs",                          VIRP_TIER_GREEN },
    { "show mac all",                       VIRP_TIER_GREEN },
    { "show neighbor",                      VIRP_TIER_GREEN },
    { "show ntp",                           VIRP_TIER_GREEN },
    { "show zone",                          VIRP_TIER_GREEN },
    { "show vpn ipsec-sa",                  VIRP_TIER_GREEN },
    { "show vpn ike-sa",                    VIRP_TIER_GREEN },
    { "show vpn flow",                      VIRP_TIER_GREEN },
    { "show vpn",                           VIRP_TIER_GREEN },
    { "show dns-proxy cache",              VIRP_TIER_GREEN },
    { "show dhcp server",                   VIRP_TIER_GREEN },
    { "show global-protect-gateway",        VIRP_TIER_GREEN },
    { "show log system",                    VIRP_TIER_GREEN },
    { "show log traffic",                   VIRP_TIER_GREEN },
    { "show log threat",                    VIRP_TIER_GREEN },
    { "show log",                           VIRP_TIER_GREEN },

    /* YELLOW TIER — configuration reads, active diagnostics */
    { "show running security-policy",       VIRP_TIER_YELLOW },
    { "show running nat-policy",            VIRP_TIER_YELLOW },
    { "show running qos-policy",            VIRP_TIER_YELLOW },
    { "show running",                       VIRP_TIER_YELLOW },
    { "show config",                        VIRP_TIER_YELLOW },
    { "debug",                              VIRP_TIER_YELLOW },
    { "test",                               VIRP_TIER_YELLOW },
    { "ping",                               VIRP_TIER_YELLOW },
    { "traceroute",                         VIRP_TIER_YELLOW },
    { "less",                               VIRP_TIER_YELLOW },
    { "tail",                               VIRP_TIER_YELLOW },

    /* RED TIER — security-sensitive reads */
    { "show admins",                        VIRP_TIER_RED },
    { "show user ip-user-mapping",          VIRP_TIER_RED },
    { "show user group",                    VIRP_TIER_RED },
    { "show user",                          VIRP_TIER_RED },
    { "show certificate",                   VIRP_TIER_RED },
    { "request password-hash",              VIRP_TIER_RED },
    { "show device-group",                  VIRP_TIER_RED },
    { "show panorama-status",              VIRP_TIER_RED },
};

const size_t PA_ROUTE_TABLE_SIZE =
    sizeof(PA_ROUTE_TABLE) / sizeof(PA_ROUTE_TABLE[0]);

/* =========================================================================
 * Command Routing — prefix match against table
 * ========================================================================= */

virp_trust_tier_t pa_route_command(const char *command)
{
    if (!command) return VIRP_TIER_YELLOW;

    /* Skip leading whitespace */
    while (*command == ' ' || *command == '\t') command++;

    for (size_t i = 0; i < PA_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(PA_ROUTE_TABLE[i].command_pattern);
        if (strncasecmp(command, PA_ROUTE_TABLE[i].command_pattern, plen) == 0) {
            char next = command[plen];
            if (next == '\0' || next == ' ' || next == '\t' || next == '\n')
                return PA_ROUTE_TABLE[i].tier;
        }
    }

    /* No match — default to YELLOW */
    return VIRP_TIER_YELLOW;
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    int                 sock_fd;
    LIBSSH2_SESSION     *session;
    LIBSSH2_CHANNEL     *channel;
    char                prompt[PA_SSH_MAX_PROMPT_LEN];
    size_t              prompt_len;
    bool                connected;
};

/* =========================================================================
 * TCP Connection
 * ========================================================================= */

static int pa_tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints, *res, *p;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    if (getaddrinfo(host, port_str, &hints, &res) != 0)
        return -1;

    for (p = res; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd < 0) continue;

        struct timeval tv = { .tv_sec = PA_SSH_CONNECT_TIMEOUT_SEC, .tv_usec = 0 };
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == 0)
            break;

        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);
    return sockfd;
}

/* =========================================================================
 * SSH Read Helper — reads until PAN-OS prompt or timeout
 *
 * PAN-OS prompt format:
 *   username@hostname>    (operational mode)
 *   username@hostname#    (configuration mode)
 *
 * We detect the prompt by looking for a line ending in > or # that
 * contains an @ character (the username@hostname pattern).
 * ========================================================================= */

static ssize_t pa_ssh_read_until_prompt(virp_conn_t *conn,
                                         char *buf, size_t buf_len,
                                         int timeout_ms)
{
    size_t total = 0;
    int elapsed = 0;
    int poll_interval = 50;  /* ms */

    while (total < buf_len - 1 && elapsed < timeout_ms) {
        ssize_t n = libssh2_channel_read(conn->channel,
                                          buf + total,
                                          buf_len - total - 1);
        if (n > 0) {
            total += n;
            buf[total] = '\0';

            /*
             * Check for PAN-OS prompt: username@hostname> or username@hostname#
             * Look for a line ending in > or # that contains @
             */
            if (total >= 2) {
                char last = buf[total - 1];
                if (last == '>' || last == '#' || last == ' ') {
                    /* Handle trailing space after > or # */
                    size_t check_pos = total - 1;
                    if (last == ' ' && check_pos > 0) {
                        last = buf[check_pos - 1];
                        if (last != '>' && last != '#') {
                            elapsed = 0;
                            continue;
                        }
                    }

                    /* Extract the last line as potential prompt */
                    char *last_nl = NULL;
                    for (ssize_t i = (ssize_t)total - 2; i >= 0; i--) {
                        if (buf[i] == '\n') {
                            last_nl = buf + i;
                            break;
                        }
                    }
                    const char *prompt_start = last_nl ? last_nl + 1 : buf;

                    /* Verify it looks like username@hostname> */
                    size_t plen = (buf + total) - prompt_start;
                    if (plen > 2 && plen < PA_SSH_MAX_PROMPT_LEN &&
                        memchr(prompt_start, '@', plen) != NULL) {
                        /* Save detected prompt if we don't have one */
                        if (conn->prompt_len == 0) {
                            memcpy(conn->prompt, prompt_start, plen);
                            conn->prompt[plen] = '\0';
                            conn->prompt_len = plen;

                            /* Trim trailing whitespace from saved prompt */
                            while (conn->prompt_len > 0 &&
                                   conn->prompt[conn->prompt_len - 1] == ' ') {
                                conn->prompt[--conn->prompt_len] = '\0';
                            }
                        }
                        break;  /* Got a prompt, we're done */
                    }
                }
            }
            elapsed = 0;  /* Reset timeout on data received */
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            usleep(poll_interval * 1000);
            elapsed += poll_interval;
        } else if (n == 0) {
            break;  /* Channel EOF */
        } else {
            break;  /* Error */
        }
    }

    buf[total] = '\0';
    return (ssize_t)total;
}

/* =========================================================================
 * SSH Write Helper
 * ========================================================================= */

static int pa_ssh_write(virp_conn_t *conn, const char *data)
{
    size_t len = strlen(data);
    size_t written = 0;

    while (written < len) {
        ssize_t n = libssh2_channel_write(conn->channel,
                                           data + written,
                                           len - written);
        if (n > 0)
            written += n;
        else if (n == LIBSSH2_ERROR_EAGAIN)
            usleep(10000);
        else
            return -1;
    }
    return 0;
}

/* =========================================================================
 * Driver: connect
 * ========================================================================= */

static virp_conn_t *pa_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    virp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->sock_fd = -1;
    conn->connected = false;
    conn->prompt_len = 0;

    /* TCP connect */
    uint16_t port = device->port ? device->port : 22;
    conn->sock_fd = pa_tcp_connect(device->host, port);
    if (conn->sock_fd < 0) {
        fprintf(stderr, "[PAN-OS] TCP connect failed: %s:%u\n",
                device->host, port);
        free(conn);
        return NULL;
    }

    /* Initialize libssh2 session */
    conn->session = libssh2_session_init();
    if (!conn->session) {
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Set preferred algorithms — PAN-OS supports modern ciphers */
    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_KEX,
        "curve25519-sha256,"
        "curve25519-sha256@libssh.org,"
        "ecdh-sha2-nistp256,"
        "ecdh-sha2-nistp384,"
        "ecdh-sha2-nistp521,"
        "diffie-hellman-group14-sha256,"
        "diffie-hellman-group14-sha1,"
        "diffie-hellman-group-exchange-sha256");

    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_CS,
        "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc");
    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_SC,
        "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc");

    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_HOSTKEY,
        "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-ed25519");

    /* SSH handshake */
    int rc = libssh2_session_handshake(conn->session, conn->sock_fd);
    if (rc != 0) {
        char *errmsg;
        int errcode = libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[PAN-OS] SSH handshake failed: rc=%d errcode=%d msg='%s' (%s:%u)\n",
                rc, errcode, errmsg, device->host, port);
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Log negotiated KEX for debugging */
    const char *kex_used = libssh2_session_methods(conn->session, LIBSSH2_METHOD_KEX);
    fprintf(stderr, "[PAN-OS] KEX negotiated: %s (%s:%u)\n",
            kex_used ? kex_used : "(null)", device->host, port);

    const char *hk_used = libssh2_session_methods(conn->session, LIBSSH2_METHOD_HOSTKEY);
    fprintf(stderr, "[PAN-OS] Host key type: %s (%s:%u)\n",
            hk_used ? hk_used : "(null)", device->host, port);

    /* Password authentication */
    if (libssh2_userauth_password(conn->session,
                                   device->username,
                                   device->password) != 0) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[PAN-OS] Auth failed for %s@%s: %s\n",
                device->username, device->host, errmsg);
        libssh2_session_disconnect(conn->session, "auth failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Open interactive shell channel */
    conn->channel = libssh2_channel_open_session(conn->session);
    if (!conn->channel) {
        fprintf(stderr, "[PAN-OS] Failed to open channel\n");
        libssh2_session_disconnect(conn->session, "channel failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Request PTY */
    if (libssh2_channel_request_pty(conn->channel, "vt100") != 0) {
        fprintf(stderr, "[PAN-OS] PTY request failed\n");
    }

    /* Start shell */
    if (libssh2_channel_shell(conn->channel) != 0) {
        fprintf(stderr, "[PAN-OS] Shell start failed\n");
        libssh2_channel_free(conn->channel);
        libssh2_session_disconnect(conn->session, "shell failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Set non-blocking mode */
    libssh2_session_set_blocking(conn->session, 0);

    /* Read initial banner/prompt */
    char banner[4096];
    pa_ssh_read_until_prompt(conn, banner, sizeof(banner), 5000);

    /* Disable paging — PAN-OS uses 'set cli pager off' */
    pa_ssh_write(conn, "set cli pager off\n");
    char discard[4096];
    pa_ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);

    conn->connected = true;

    fprintf(stderr, "[PAN-OS] Connected: %s@%s:%u prompt='%s'\n",
            device->username, device->host, port, conn->prompt);

    return conn;
}

/* =========================================================================
 * Driver: execute
 * ========================================================================= */

static virp_error_t pa_execute(virp_conn_t *conn,
                                const char *command,
                                virp_exec_result_t *result)
{
    if (!conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return VIRP_OK;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Send command */
    char cmd_buf[2048];
    snprintf(cmd_buf, sizeof(cmd_buf), "%s\n", command);

    if (pa_ssh_write(conn, cmd_buf) != 0) {
        conn->connected = false;
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to send command to %s", conn->device.hostname);
        return VIRP_OK;
    }

    /* Read response */
    char raw_output[VIRP_OUTPUT_MAX];
    ssize_t n = pa_ssh_read_until_prompt(conn, raw_output, sizeof(raw_output),
                                          PA_SSH_READ_TIMEOUT_MS);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

    if (n <= 0) {
        conn->connected = false;
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Read timeout on %s", conn->device.hostname);
        return VIRP_OK;
    }

    /*
     * PAN-OS interactive shell output format:
     *   <echoed command>\r\n
     *   <actual output>
     *   username@hostname>
     *
     * We want: hostname>command\nactual output
     * (Matches existing VIRP output format)
     */

    /* Find end of echoed command (first \n) */
    char *output_start = raw_output;
    char *first_nl = strchr(raw_output, '\n');
    if (first_nl)
        output_start = first_nl + 1;

    /* Remove trailing prompt */
    if (conn->prompt_len > 0) {
        size_t out_len = strlen(output_start);
        if (out_len >= conn->prompt_len) {
            /* Search backwards for the prompt — may have trailing space */
            char *search = output_start + out_len - conn->prompt_len;
            while (search > output_start) {
                if (strncmp(search, conn->prompt, conn->prompt_len) == 0) {
                    *search = '\0';
                    break;
                }
                search--;
                /* Don't search too far back */
                if ((size_t)(output_start + out_len - search) > conn->prompt_len + 4)
                    break;
            }
        }
    }

    /* Strip trailing \r\n */
    size_t clean_len = strlen(output_start);
    while (clean_len > 0 &&
           (output_start[clean_len - 1] == '\r' ||
            output_start[clean_len - 1] == '\n')) {
        output_start[--clean_len] = '\0';
    }

    /* Format: hostname>command\noutput */
    int written = snprintf(result->output, sizeof(result->output),
                           "%s>%s\n%s",
                           conn->device.hostname, command, output_start);
    result->output_len = (written > 0) ? (size_t)written : 0;
    result->success = true;
    result->exit_code = 0;

    /* Check for PAN-OS error markers */
    if (strstr(output_start, "Unknown command:") ||
        strstr(output_start, "Invalid syntax.") ||
        strstr(output_start, "Server error:") ||
        strstr(output_start, "Validation Error")) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "PAN-OS error in command: %s", command);
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect
 * ========================================================================= */

static void pa_disconnect(virp_conn_t *conn)
{
    if (!conn) return;

    if (conn->channel) {
        if (conn->connected) {
            libssh2_session_set_blocking(conn->session, 1);
            pa_ssh_write(conn, "exit\n");
        }
        libssh2_channel_close(conn->channel);
        libssh2_channel_free(conn->channel);
    }

    if (conn->session) {
        libssh2_session_disconnect(conn->session, "VIRP disconnect");
        libssh2_session_free(conn->session);
    }

    if (conn->sock_fd >= 0)
        close(conn->sock_fd);

    fprintf(stderr, "[PAN-OS] Disconnected: %s\n", conn->device.hostname);

    free(conn);
}

/* =========================================================================
 * Driver: detect
 *
 * Run 'show system info' and look for PAN-OS markers in the output.
 * PAN-OS returns fields like "sw-version:" and "model:" that are unique.
 * ========================================================================= */

static bool pa_detect(virp_conn_t *conn)
{
    if (!conn || !conn->connected) return false;

    virp_exec_result_t result;
    virp_error_t err = pa_execute(conn, "show system info", &result);
    if (err != VIRP_OK || !result.success) return false;

    /* PAN-OS 'show system info' always contains these fields */
    return (strstr(result.output, "sw-version:") != NULL &&
            strstr(result.output, "model:") != NULL);
}

/* =========================================================================
 * Driver: health_check
 * ========================================================================= */

static virp_error_t pa_health_check(virp_conn_t *conn)
{
    if (!conn) return VIRP_ERR_NULL_PTR;
    if (!conn->connected) return PA_ERR_NOT_CONNECTED;

    virp_exec_result_t result;
    virp_error_t err = pa_execute(conn, "show clock", &result);
    if (err != VIRP_OK) return err;

    return result.success ? VIRP_OK : PA_ERR_NOT_CONNECTED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t pa_driver = {
    .name       = "panos",
    .vendor     = VIRP_VENDOR_PALOALTO,
    .connect    = pa_connect,
    .execute    = pa_execute,
    .disconnect = pa_disconnect,
    .detect     = pa_detect,
    .health_check = pa_health_check,
};

void virp_driver_paloalto_init(void)
{
    virp_driver_register(&pa_driver);
}
