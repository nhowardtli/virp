/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Linux Device Driver — SSH exec channel via libssh2
 *
 * Handles:
 *   - SSH exec channels (one per command, not interactive shell)
 *   - Exit code capture
 *   - stdout/stderr collection
 *   - Standard Linux hosts, Proxmox, Wazuh, etc.
 *
 * Design:
 *   - Uses exec channels, not interactive shell. Linux SSH servers
 *     handle exec properly (unlike IOS which needs a PTY shell).
 *   - Each execute() opens a new channel, runs the command, reads
 *     output, captures exit code, and closes the channel.
 *   - The SSH session persists across commands (lazy connect).
 *   - No prompt detection needed — exec channel has clean EOF.
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

#define SSH_CONNECT_TIMEOUT_SEC 10
#define SSH_READ_TIMEOUT_MS     30000   /* 30s — some commands are slow */
#define SSH_READ_BUF_SIZE       32768

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    int                 sock_fd;
    LIBSSH2_SESSION     *session;
    bool                connected;
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
 * Keyboard-Interactive Auth Callback
 *
 * libssh2 keyboard-interactive has no user-data pointer, so we pass the
 * password via a file-scope static set just before the auth call.
 * ========================================================================= */

static const char *s_kbd_password = NULL;

static void kbd_interactive_cb(const char *name, int name_len,
                               const char *instruction, int instruction_len,
                               int num_prompts,
                               const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                               LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                               void **abstract)
{
    (void)name; (void)name_len;
    (void)instruction; (void)instruction_len;
    (void)prompts; (void)abstract;

    for (int i = 0; i < num_prompts; i++) {
        if (s_kbd_password) {
            responses[i].text = strdup(s_kbd_password);
            responses[i].length = (unsigned int)strlen(s_kbd_password);
        } else {
            responses[i].text = strdup("");
            responses[i].length = 0;
        }
    }
}

/* =========================================================================
 * Driver: connect
 * ========================================================================= */

static virp_conn_t *linux_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    virp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->sock_fd = -1;
    conn->connected = false;

    /* TCP connect */
    uint16_t port = device->port ? device->port : 22;
    conn->sock_fd = tcp_connect(device->host, port);
    if (conn->sock_fd < 0) {
        fprintf(stderr, "[Linux] TCP connect failed: %s:%u\n",
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

    /* SSH handshake */
    if (libssh2_session_handshake(conn->session, conn->sock_fd) != 0) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[Linux] SSH handshake failed: %s (%s:%u)\n",
                errmsg, device->host, port);
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Try password auth first, fall back to keyboard-interactive */
    if (libssh2_userauth_password(conn->session,
                                   device->username,
                                   device->password) != 0) {
        /* keyboard-interactive fallback (Proxmox, hardened Linux) */
        s_kbd_password = device->password;
        if (libssh2_userauth_keyboard_interactive(conn->session,
                                                   device->username,
                                                   kbd_interactive_cb) != 0) {
            char *errmsg;
            libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
            fprintf(stderr, "[Linux] Auth failed for %s@%s: %s\n",
                    device->username, device->host, errmsg);
            libssh2_session_disconnect(conn->session, "auth failed");
            libssh2_session_free(conn->session);
            close(conn->sock_fd);
            free(conn);
            return NULL;
        }
    }

    conn->connected = true;
    fprintf(stderr, "[Linux] Connected: %s@%s:%u\n",
            device->username, device->host, port);

    return conn;
}

/* =========================================================================
 * Driver: execute
 *
 * Opens an exec channel per command. Clean EOF, exit code capture.
 * ========================================================================= */

static virp_error_t linux_execute(virp_conn_t *conn,
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

    /* Ensure blocking mode for exec channel setup */
    libssh2_session_set_blocking(conn->session, 1);

    /* Open exec channel */
    LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(conn->session);
    if (!channel) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        conn->connected = false;
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Channel open failed on %s: %s", conn->device.hostname, errmsg);
        return VIRP_OK;
    }

    /* Execute the command */
    if (libssh2_channel_exec(channel, command) != 0) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Exec failed on %s: %s", conn->device.hostname, errmsg);
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return VIRP_OK;
    }

    /* Switch to non-blocking for reading */
    libssh2_session_set_blocking(conn->session, 0);

    /* Read stdout */
    size_t total = 0;
    int elapsed = 0;
    int poll_interval = 50;  /* ms */
    /* Reserve space for hostname prefix */
    size_t prefix_len = (size_t)snprintf(result->output, sizeof(result->output),
                                          "%s$ %s\n", conn->device.hostname, command);
    total = prefix_len;

    while (total < sizeof(result->output) - 1 && elapsed < SSH_READ_TIMEOUT_MS) {
        ssize_t n = libssh2_channel_read(channel,
                                          result->output + total,
                                          sizeof(result->output) - total - 1);
        if (n > 0) {
            total += n;
            elapsed = 0;
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            usleep(poll_interval * 1000);
            elapsed += poll_interval;
        } else {
            break;  /* EOF or error */
        }
    }

    /* Also capture stderr and append */
    int stderr_elapsed = 0;
    while (total < sizeof(result->output) - 1 && stderr_elapsed < 1000) {
        ssize_t n = libssh2_channel_read_stderr(channel,
                                                 result->output + total,
                                                 sizeof(result->output) - total - 1);
        if (n > 0) {
            total += n;
            stderr_elapsed = 0;
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            usleep(poll_interval * 1000);
            stderr_elapsed += poll_interval;
        } else {
            break;
        }
    }

    result->output[total] = '\0';
    result->output_len = total;

    /* Back to blocking for channel close */
    libssh2_session_set_blocking(conn->session, 1);

    /* Close channel and get exit status */
    libssh2_channel_send_eof(channel);
    libssh2_channel_wait_eof(channel);
    libssh2_channel_close(channel);
    libssh2_channel_wait_closed(channel);

    result->exit_code = libssh2_channel_get_exit_status(channel);
    libssh2_channel_free(channel);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

    result->success = (result->exit_code == 0);
    if (!result->success && result->error_msg[0] == '\0') {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Command exited with code %d", result->exit_code);
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect
 * ========================================================================= */

static void linux_disconnect(virp_conn_t *conn)
{
    if (!conn) return;

    if (conn->session) {
        libssh2_session_disconnect(conn->session, "VIRP disconnect");
        libssh2_session_free(conn->session);
    }

    if (conn->sock_fd >= 0)
        close(conn->sock_fd);

    fprintf(stderr, "[Linux] Disconnected: %s\n", conn->device.hostname);

    free(conn);
}

/* =========================================================================
 * Driver: detect
 * ========================================================================= */

static bool linux_detect(virp_conn_t *conn)
{
    if (!conn || !conn->connected) return false;
    return conn->device.vendor == VIRP_VENDOR_LINUX;
}

/* =========================================================================
 * Driver: health_check
 * ========================================================================= */

static virp_error_t linux_health_check(virp_conn_t *conn)
{
    if (!conn) return VIRP_ERR_NULL_PTR;
    if (!conn->connected) return VIRP_ERR_KEY_NOT_LOADED;

    virp_exec_result_t result;
    virp_error_t err = linux_execute(conn, "uptime", &result);
    if (err != VIRP_OK) return err;

    return result.success ? VIRP_OK : VIRP_ERR_KEY_NOT_LOADED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t linux_driver = {
    .name       = "linux",
    .vendor     = VIRP_VENDOR_LINUX,
    .connect    = linux_connect,
    .execute    = linux_execute,
    .disconnect = linux_disconnect,
    .detect     = linux_detect,
    .health_check = linux_health_check,
};

void virp_driver_linux_init(void)
{
    virp_driver_register(&linux_driver);
}
