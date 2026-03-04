/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Intent Routing Protocol
 * Cisco IOS Device Driver — real SSH communication via libssh2
 *
 * Handles:
 *   - Interactive SSH shell (IOS doesn't support exec channels well)
 *   - Legacy cipher negotiation (aes256-cbc, diffie-hellman-group14-sha1)
 *   - Prompt detection (hostname# or hostname>)
 *   - Enable mode entry
 *   - Terminal length 0 (no paging)
 *   - Output scrubbing (remove echoed command and trailing prompt)
 *
 * Ported from aiops_executor.c SSH patterns.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define SSH_READ_TIMEOUT_MS     10000   /* 10 seconds per read */
#define SSH_CONNECT_TIMEOUT_SEC 10
#define SSH_PROMPT_WAIT_MS      500     /* Wait after command for output */
#define SSH_READ_BUF_SIZE       32768
#define SSH_MAX_PROMPT_LEN      128

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    int                 sock_fd;
    LIBSSH2_SESSION     *session;
    LIBSSH2_CHANNEL     *channel;
    char                prompt[SSH_MAX_PROMPT_LEN];    /* Detected prompt */
    size_t              prompt_len;
    bool                connected;
    bool                in_enable;
};

/* =========================================================================
 * TCP Connection
 * ========================================================================= */

static int tcp_connect(const char *host, uint16_t port)
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

        /* Set connect timeout via SO_RCVTIMEO */
        struct timeval tv = { .tv_sec = SSH_CONNECT_TIMEOUT_SEC, .tv_usec = 0 };
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
 * SSH Read Helper — reads until prompt or timeout
 * ========================================================================= */

static ssize_t ssh_read_until_prompt(virp_conn_t *conn,
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

            /* Check if we see a prompt (hostname# or hostname>) */
            if (total >= 1) {
                char last = buf[total - 1];
                if (last == '#' || last == '>') {
                    /* Look back for a newline to extract the prompt */
                    char *last_nl = strrchr(buf, '\n');
                    const char *prompt_start = last_nl ? last_nl + 1 : buf;

                    /* Verify it looks like a prompt (ends with # or >) */
                    size_t plen = strlen(prompt_start);
                    if (plen > 0 && plen < SSH_MAX_PROMPT_LEN) {
                        /* Save detected prompt if we don't have one */
                        if (conn->prompt_len == 0) {
                            memcpy(conn->prompt, prompt_start, plen);
                            conn->prompt[plen] = '\0';
                            conn->prompt_len = plen;
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
            /* Channel EOF */
            break;
        } else {
            /* Error */
            break;
        }
    }

    buf[total] = '\0';
    return (ssize_t)total;
}

/* =========================================================================
 * SSH Write Helper
 * ========================================================================= */

static int ssh_write(virp_conn_t *conn, const char *data)
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

static virp_conn_t *cisco_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    virp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->sock_fd = -1;
    conn->connected = false;
    conn->in_enable = false;
    conn->prompt_len = 0;

    /* TCP connect */
    uint16_t port = device->port ? device->port : 22;
    conn->sock_fd = tcp_connect(device->host, port);
    if (conn->sock_fd < 0) {
        fprintf(stderr, "[Cisco] TCP connect failed: %s:%u\n",
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

    /* Set preferred algorithms — support legacy IOS */
    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_KEX,
        "diffie-hellman-group14-sha256,"
        "diffie-hellman-group14-sha1,"
        "diffie-hellman-group-exchange-sha256,"
        "diffie-hellman-group-exchange-sha1");

    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_CS,
        "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc,3des-cbc");
    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_SC,
        "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc,3des-cbc");

    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_HOSTKEY,
        "ssh-rsa,rsa-sha2-256,rsa-sha2-512");

    /* SSH handshake */
    if (libssh2_session_handshake(conn->session, conn->sock_fd) != 0) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[Cisco] SSH handshake failed: %s (%s:%u)\n",
                errmsg, device->host, port);
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Password authentication */
    if (libssh2_userauth_password(conn->session,
                                   device->username,
                                   device->password) != 0) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[Cisco] Auth failed for %s@%s: %s\n",
                device->username, device->host, errmsg);
        libssh2_session_disconnect(conn->session, "auth failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Open interactive shell channel (IOS requires this) */
    conn->channel = libssh2_channel_open_session(conn->session);
    if (!conn->channel) {
        fprintf(stderr, "[Cisco] Failed to open channel\n");
        libssh2_session_disconnect(conn->session, "channel failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Request PTY — IOS needs this for interactive shell */
    if (libssh2_channel_request_pty(conn->channel, "vt100") != 0) {
        fprintf(stderr, "[Cisco] PTY request failed\n");
    }

    /* Start shell */
    if (libssh2_channel_shell(conn->channel) != 0) {
        fprintf(stderr, "[Cisco] Shell start failed\n");
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
    ssh_read_until_prompt(conn, banner, sizeof(banner), 5000);

    /* Disable paging */
    ssh_write(conn, "terminal length 0\n");
    char discard[4096];
    ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);

    /* Enter enable mode if we have an enable password and we're at > */
    if (conn->prompt_len > 0 && conn->prompt[conn->prompt_len - 1] == '>') {
        if (device->enable_password[0] != '\0') {
            ssh_write(conn, "enable\n");
            ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);

            /* If we got a password prompt, send enable password */
            if (strstr(discard, "assword") != NULL) {
                char enable_cmd[256];
                snprintf(enable_cmd, sizeof(enable_cmd), "%s\n",
                         device->enable_password);
                ssh_write(conn, enable_cmd);
                ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);
            }

            /* Reset prompt — should now be hostname# */
            conn->prompt_len = 0;

            /* Disable paging again in enable mode */
            ssh_write(conn, "terminal length 0\n");
            ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);
        }
    }

    conn->connected = true;
    conn->in_enable = (conn->prompt_len > 0 &&
                       conn->prompt[conn->prompt_len - 1] == '#');

    fprintf(stderr, "[Cisco] Connected: %s@%s:%u prompt='%s' enable=%d\n",
            device->username, device->host, port,
            conn->prompt, conn->in_enable);

    return conn;
}

/* =========================================================================
 * Driver: execute
 * ========================================================================= */

static virp_error_t cisco_execute(virp_conn_t *conn,
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

    if (ssh_write(conn, cmd_buf) != 0) {
        conn->connected = false;  /* Mark stale for reconnect */
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to send command to %s", conn->device.hostname);
        return VIRP_OK;
    }

    /* Read response */
    char raw_output[VIRP_OUTPUT_MAX];
    ssize_t n = ssh_read_until_prompt(conn, raw_output, sizeof(raw_output),
                                      SSH_READ_TIMEOUT_MS);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

    if (n <= 0) {
        conn->connected = false;  /* Mark stale for reconnect */
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Read timeout on %s", conn->device.hostname);
        return VIRP_OK;
    }

    /*
     * Output format from IOS interactive shell:
     *   <echoed command>\r\n
     *   <actual output>
     *   hostname#
     *
     * We want: hostname#command\nactual output
     * (Matches existing executor format for compatibility)
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
            char *possible_prompt = output_start + out_len - conn->prompt_len;
            if (strncmp(possible_prompt, conn->prompt, conn->prompt_len) == 0) {
                *possible_prompt = '\0';
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

    /* Format: hostname#command\noutput */
    int written = snprintf(result->output, sizeof(result->output),
                           "%s#%s\n%s",
                           conn->device.hostname, command, output_start);
    result->output_len = (written > 0) ? (size_t)written : 0;
    result->success = true;
    result->exit_code = 0;

    /* Check for IOS error markers */
    if (strstr(output_start, "% Invalid input") ||
        strstr(output_start, "% Incomplete command") ||
        strstr(output_start, "% Ambiguous command")) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "IOS error in command: %s", command);
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect
 * ========================================================================= */

static void cisco_disconnect(virp_conn_t *conn)
{
    if (!conn) return;

    if (conn->channel) {
        /* Try graceful exit */
        if (conn->connected) {
            libssh2_session_set_blocking(conn->session, 1);
            ssh_write(conn, "exit\n");
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

    fprintf(stderr, "[Cisco] Disconnected: %s\n", conn->device.hostname);

    free(conn);
}

/* =========================================================================
 * Driver: detect
 * ========================================================================= */

static bool cisco_detect(virp_conn_t *conn)
{
    if (!conn || !conn->connected) return false;

    /* If the prompt contains # or > and we got a response to
     * "terminal length 0" without error, it's probably IOS */
    return conn->device.vendor == VIRP_VENDOR_CISCO_IOS;
}

/* =========================================================================
 * Driver: health_check
 * ========================================================================= */

static virp_error_t cisco_health_check(virp_conn_t *conn)
{
    if (!conn) return VIRP_ERR_NULL_PTR;
    if (!conn->connected) return VIRP_ERR_KEY_NOT_LOADED;

    /* Send a simple command and check for valid response */
    virp_exec_result_t result;
    virp_error_t err = cisco_execute(conn, "show clock", &result);
    if (err != VIRP_OK) return err;

    return result.success ? VIRP_OK : VIRP_ERR_KEY_NOT_LOADED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t cisco_driver = {
    .name       = "cisco_ios",
    .vendor     = VIRP_VENDOR_CISCO_IOS,
    .connect    = cisco_connect,
    .execute    = cisco_execute,
    .disconnect = cisco_disconnect,
    .detect     = cisco_detect,
    .health_check = cisco_health_check,
};

void virp_driver_cisco_init(void)
{
    virp_driver_register(&cisco_driver);
}
