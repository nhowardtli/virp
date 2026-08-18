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
#include <fcntl.h>
#include <poll.h>
#include <libssh2.h>
#include <openssl/crypto.h>
#include "virp_ssh_hostkey.h"

/* Forward declaration: the classifier is defined far below but the
 * in-driver BLACK backstop in linux_execute() (near the top) calls it. */
virp_trust_tier_t linux_gate_tier(const char *command);

/* =========================================================================
 * Constants
 * ========================================================================= */

#define SSH_CONNECT_TIMEOUT_SEC 10
#define SSH_READ_TIMEOUT_MS     30000   /* 30s idle — some commands are slow */
#define SSH_READ_BUF_SIZE       32768
#define SSH_POLL_INTERVAL_MS    50
/*
 * Hard wall-clock cap on the WHOLE post-exec sequence (read + stderr drain +
 * EOF + close). SSH_READ_TIMEOUT_MS bounds only idle time between reads; it
 * bounded nothing at all in the teardown, which ran blocking with no
 * deadline. TRANSCRIPT-05 measured a device that accepted a command and went
 * silent holding its execute path open for >200s. Exceeding this deadline is
 * an EXECUTED_UNKNOWN outcome, not a retry and not a success.
 */
#define SSH_EXEC_DEADLINE_MS    40000

/* Credential scrub for FRR config reads — defined with the gate
 * helpers below, needed by linux_execute above them. Exposed
 * (non-static) for the unit suite, same as cisco_scrub_config. */
virp_error_t linux_scrub_config(const char *in, size_t in_len,
                                char *out, size_t out_cap,
                                size_t *out_len);
bool linux_command_returns_config(const char *command);
virp_error_t linux_scrub_result(virp_exec_result_t *result);

static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/*
 * Drive one non-blocking libssh2 channel call to completion or to the
 * deadline. Returns the call's own rc, or LIBSSH2_ERROR_TIMEOUT if the
 * deadline passed first. Every completion-sequence call goes through this so
 * none of them can block indefinitely.
 */
static int chan_wait(int (*op)(LIBSSH2_CHANNEL *), LIBSSH2_CHANNEL *ch,
                     uint64_t deadline_ms)
{
    for (;;) {
        int rc = op(ch);
        if (rc != LIBSSH2_ERROR_EAGAIN)
            return rc;
        if (mono_ms() >= deadline_ms)
            return LIBSSH2_ERROR_TIMEOUT;
        usleep(SSH_POLL_INTERVAL_MS * 1000);
    }
}

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

/*
 * Non-blocking connect with an explicit deadline (Item 6,
 * 2026-08-11). A blocking connect(2) toward an address whose SYNs
 * are silently dropped sits in the kernel's retry schedule for
 * ~130 s — on the single serial watchdog thread that every other
 * device queues behind. SO_RCVTIMEO/SO_SNDTIMEO do NOT bound
 * connect(2); only a non-blocking connect polled against a deadline
 * does. Returns 0 with the socket back in blocking mode, -1 on
 * error or timeout.
 */
static int connect_bounded(int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen, int timeout_ms)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0 || fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0)
        return -1;

    int rc = connect(sockfd, addr, addrlen);
    if (rc != 0) {
        if (errno != EINPROGRESS)
            return -1;
        struct pollfd pfd = { .fd = sockfd, .events = POLLOUT };
        rc = poll(&pfd, 1, timeout_ms);
        if (rc != 1)
            return -1;                    /* timeout or poll error */
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 ||
            soerr != 0)
            return -1;
    }

    return (fcntl(sockfd, F_SETFL, flags) < 0) ? -1 : 0;
}

/* Exposed (non-static) for the unit suite: the time bound is the
 * property under test. */
int linux_tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints, *res, *p;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    /* AI_ADDRCONFIG: do not return addresses in families this host
     * has no configured (non-loopback) address for — a v4-only host
     * never even attempts a AAAA. NOTE: a host with ANY global v6
     * address (a docker bridge is enough) still gets AAAA results;
     * connect_bounded is what protects the watchdog there. */
    hints.ai_flags = AI_ADDRCONFIG;

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

        if (connect_bounded(sockfd, p->ai_addr, p->ai_addrlen,
                            SSH_CONNECT_TIMEOUT_SEC * 1000) == 0)
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

#define KBD_MAX_PROMPTS 4

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

    if (num_prompts > KBD_MAX_PROMPTS) {
        fprintf(stderr, "[Linux] keyboard-interactive: server sent %d prompts "
                "(max %d) — rejecting\n", num_prompts, KBD_MAX_PROMPTS);
        for (int i = 0; i < num_prompts; i++) {
            responses[i].text   = NULL;
            responses[i].length = 0;
        }
        return;
    }

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
    conn->sock_fd = linux_tcp_connect(device->host, port);
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

    /* Verify host key before authentication */
    virp_error_t hk_err = virp_ssh_verify_hostkey(conn->session,
                                                   device->host, port);
    if (hk_err != VIRP_OK) {
        fprintf(stderr, "[Linux] Host key verification failed: %s\n",
                virp_error_str(hk_err));
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

    /*
     * BLACK-tier backstop — MODE-INDEPENDENT. The ASA, JunOS, IOS and
     * FortiGate drivers each refuse a BLACK-classified command inside
     * their own execute() (e.g. driver_asa.c). The linux/proxmox driver
     * did not, even though linux_gate_tier() is exactly what classifies
     * qm|pct destroy, pvesh delete, pvesm remove|wipedisk and
     * shutdown/halt self-harm as BLACK. That gap matters because the
     * O-Node gate only blocks BLACK when gate_effective_mode == ENFORCE;
     * under a per-driver SHADOW override the gate logs "would-block" and
     * still dispatches to the driver — so the driver is the last line of
     * defence. This refusal is deliberately placed BEFORE the connected
     * check: forbidding a destructive command is a policy decision that
     * does not depend on whether the device is reachable, and it keeps
     * the guarantee independent of connection state. (This is stricter
     * than the ASA driver, which refuses BLACK only after the connected
     * check.)
     */
    if (linux_gate_tier(command) == VIRP_TIER_BLACK) {
        result->success = false;
        result->exit_code = 1;
        result->no_dispatch = true;   /* nothing was ever sent */
        result->disposition = VIRP_DISPOSITION_NOT_SENT;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "BLACK tier: command blocked on %s", conn->device.hostname);
        fprintf(stderr, "[Linux] BLACK tier blocked: '%s' on %s\n",
                command, conn->device.hostname);
        return VIRP_OK;
    }

    if (!conn->connected) {
        result->success = false;
        result->no_dispatch = true;   /* refused before any transport write */
        result->disposition = VIRP_DISPOSITION_NOT_SENT;
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
        result->no_dispatch = true;   /* channel never opened; command not sent */
        result->disposition = VIRP_DISPOSITION_NOT_SENT;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Channel open failed on %s: %s", conn->device.hostname, errmsg);
        return VIRP_OK;
    }

    /* Execute the command */
    if (libssh2_channel_exec(channel, command) != 0) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        result->success = false;
        /* The exec request may have reached the server before the failure —
         * not provably non-dispatch, so it is never retried. */
        result->disposition = VIRP_DISPOSITION_EXECUTED_UNKNOWN;
        result->exit_code_trusted = false;
        result->exit_code = -1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Exec failed on %s: %s", conn->device.hostname, errmsg);
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return VIRP_OK;
    }

    /*
     * Non-blocking for the ENTIRE completion sequence — read, stderr drain,
     * EOF and close are all polled against one deadline. The teardown used to
     * run blocking with no timeout, so a silent device wedged this path
     * indefinitely.
     */
    libssh2_session_set_blocking(conn->session, 0);
    const uint64_t deadline = mono_ms() + SSH_EXEC_DEADLINE_MS;

    /* Reserve space for hostname prefix. NOTE: this is exactly why output
     * length can never be the "did we get a response" signal — the buffer is
     * non-empty before a single byte is read from the device. */
    size_t total = (size_t)snprintf(result->output, sizeof(result->output),
                                    "%s$ %s\n", conn->device.hostname, command);

    /*
     * Record HOW the read ended. Previously EOF and transport error shared
     * one `break`, which is what made an aborted command indistinguishable
     * from a completed one.
     */
    /*
     * WHY the read stopped. Do not try to decide "was this a clean end"
     * inside the loop from the EOF flag at the instant of a zero-length
     * read: the flag is set when libssh2 processes the peer's EOF packet,
     * which races the drained-buffer read. Testing it there made normally
     * completed commands spin to the deadline and classify UNKNOWN — an
     * over-correction worse than the original bug. Record the reason here;
     * let the deadline-bounded EOF/close handshake below be the authority.
     */
    enum { END_DATA, END_DEADLINE, END_TRANSPORT, END_BUFFER } how = END_DATA;
    int idle_ms = 0;
    int last_rc = 0;   /* libssh2 rc that ended the loop, for diagnostics */

    for (;;) {
        if (total >= sizeof(result->output) - 1) { how = END_BUFFER; break; }

        ssize_t n = libssh2_channel_read(channel,
                                          result->output + total,
                                          sizeof(result->output) - total - 1);
        if (n > 0) {
            total += n;
            idle_ms = 0;
            continue;
        }
        if (n == 0) {          /* stream drained */
            how = END_DATA;
            break;
        }
        if (n == LIBSSH2_ERROR_EAGAIN) {
            if (mono_ms() >= deadline || idle_ms >= SSH_READ_TIMEOUT_MS) {
                how     = END_DEADLINE;   /* silent device: nothing concluded */
                last_rc = -1000;          /* sentinel: our deadline */
                break;
            }
            usleep(SSH_POLL_INTERVAL_MS * 1000);
            idle_ms += SSH_POLL_INTERVAL_MS;
            continue;
        }
        /* n < 0 and not EAGAIN. A peer that already finished and closed the
         * channel makes reads fail here, which is an end of stream, not a
         * transport failure — the EOF flag distinguishes them. */
        last_rc = (int)n;
        how = libssh2_channel_eof(channel) ? END_DATA : END_TRANSPORT;
        break;
    }

    /* Drain stderr into the same body. Bounded, and never extends the
     * deadline; stdout has already decided the verdict. */
    int stderr_idle = 0;
    while (how == END_DATA && total < sizeof(result->output) - 1) {
        ssize_t n = libssh2_channel_read_stderr(channel,
                                                 result->output + total,
                                                 sizeof(result->output) - total - 1);
        if (n > 0) {
            total += n;
            stderr_idle = 0;
            continue;
        }
        if (n == LIBSSH2_ERROR_EAGAIN) {
            if (stderr_idle >= 1000 || mono_ms() >= deadline)
                break;
            usleep(SSH_POLL_INTERVAL_MS * 1000);
            stderr_idle += SSH_POLL_INTERVAL_MS;
            continue;
        }
        break;
    }

    result->output[total] = '\0';
    result->output_len = total;
    if (total >= sizeof(result->output) - 1)
        result->output_truncated = true;   /* body is a PREFIX, not a response */

    /* Completion sequence — every call deadline-bounded. */
    int eof_rc = chan_wait(libssh2_channel_send_eof, channel, deadline);
    if (eof_rc == 0)
        eof_rc = chan_wait(libssh2_channel_wait_eof, channel, deadline);
    int close_rc  = chan_wait(libssh2_channel_close, channel, deadline);
    int closed_rc = (close_rc == 0)
                    ? chan_wait(libssh2_channel_wait_closed, channel, deadline)
                    : close_rc;

    /*
     * A command killed by a signal did NOT exit cleanly, whatever
     * get_exit_status() reports for it. Ask explicitly.
     */
    int died_on_signal = 0;
    char signame[64] = {0};
    {
        char *sig = NULL, *em = NULL, *lt = NULL;
        size_t siglen = 0, emlen = 0, ltlen = 0;
        if (libssh2_channel_get_exit_signal(channel, &sig, &siglen,
                                            &em, &emlen, &lt, &ltlen) == 0
            && sig && siglen > 0) {
            died_on_signal = 1;
            snprintf(signame, sizeof(signame), "%.*s", (int)siglen, sig);
        }
        free(sig); free(em); free(lt);
    }

    /*
     * THE DISCRIMINATOR. exit_code is trustworthy only when the channel
     * reached a clean, complete close: the peer signalled EOF, and both the
     * EOF wait and the close handshake completed without error or deadline.
     * Anything else means we never received the peer's verdict, and
     * libssh2_channel_get_exit_status() would hand back its initial 0 —
     * indistinguishable from a genuine exit-0. That conflation is the false
     * attestation this classifier exists to prevent.
     *
     * Residual assumption, stated: a peer that completes the channel
     * normally is required by RFC 4254 to send exit-status or exit-signal,
     * so a clean close without either is protocol-anomalous and is not
     * separately detectable through libssh2's API.
     */
    const int peer_eof = libssh2_channel_eof(channel) ? 1 : 0;
    const int clean_close = (how == END_DATA) && !result->output_truncated
                            && eof_rc == 0 && closed_rc == 0 && peer_eof;

    if (!clean_close) {
        result->disposition       = VIRP_DISPOSITION_EXECUTED_UNKNOWN;
        result->success           = false;
        result->exit_code_trusted = false;
        result->exit_code         = -1;   /* never read; not a real status */
        if (result->error_msg[0] == '\0')
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "No clean close on %s (how=%d peer_eof=%d trunc=%d "
                     "read_rc=%d eof_rc=%d closed_rc=%d) — command may have "
                     "executed",
                     conn->device.hostname, (int)how, peer_eof,
                     (int)result->output_truncated, last_rc, eof_rc, closed_rc);
    } else if (died_on_signal) {
        /*
         * The peer explicitly reported an exit-signal, so this is a KNOWN
         * fate, not an unknown one: the command ran and was killed. That is
         * strictly more information than EXECUTED_UNKNOWN, and it is never a
         * success. Whatever output arrived is what the command emitted
         * before dying — a prefix, not a complete response — so it is
         * flagged rather than presented as the whole answer.
         */
        result->disposition       = VIRP_DISPOSITION_EXECUTED_FAILED;
        result->success           = false;
        result->exit_code_trusted = false;
        result->exit_code         = -1;
        result->output_truncated  = true;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Command on %s died on signal %s",
                 conn->device.hostname, signame);
    } else {
        result->exit_code         = libssh2_channel_get_exit_status(channel);
        result->exit_code_trusted = true;
        result->disposition = (result->exit_code == 0)
                              ? VIRP_DISPOSITION_EXECUTED_CONFIRMED
                              : VIRP_DISPOSITION_EXECUTED_FAILED;
        result->success = (result->disposition ==
                           VIRP_DISPOSITION_EXECUTED_CONFIRMED);
        if (!result->success && result->error_msg[0] == '\0')
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Command exited with code %d", result->exit_code);
    }

    libssh2_channel_free(channel);

    /* Config-bearing reads are scrubbed BEFORE the body leaves the
     * driver (2026-08-11): FRR configs carry credential material
     * (passwords, OSPF md5 keys, key-strings) and observation bodies
     * are signed into an append-only chain. Fail-closed, same
     * contract as cisco_scrub_config: if the scrub cannot complete,
     * the body is withheld from signing and a typed error returned.
     * Runs on every disposition — even a truncated or unclean body
     * must never carry cleartext secrets onward. */
    if (linux_command_returns_config(command)) {
        virp_error_t serr = linux_scrub_result(result);
        if (serr != VIRP_OK) {
            fprintf(stderr, "[Linux] Config scrub failed on %s — "
                    "refusing to sign unscrubbed or clamped body\n",
                    conn->device.hostname);
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Config scrub failed on %s: body withheld from "
                     "signing", conn->device.hostname);
            return serr;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

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

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
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
 * Gate classifier — FRR/vtysh table (linux driver only)
 *
 * The linux driver runs raw shell over an SSH exec channel, so the
 * classifier's first job is refusing anything that is not exactly ONE
 * command. Guards run before any table row and fail RED:
 *
 *   1. virp_command_check_separators() — rejects ; | & ` $( ${ and every
 *      control byte (so newlines) ANYWHERE, quoted or not. The remaining
 *      shell-composition bytes (< > ( ) { } \ " outside the vtysh
 *      argument) are excluded by the anchored form check below: the only
 *      accepted vtysh shape is exactly `vtysh -c "<arg>"`, so any stray
 *      byte outside the quotes fails the anchor.
 *   2. vtysh commands must match that anchor exactly — one -c, one
 *      double-quoted argument, nothing before or after. Two or more -c
 *      flags are RED unconditionally (a multi-command sequence is a
 *      config session, not an observation).
 *   3. Whitespace runs are collapsed (the same equivalence
 *      virp_canonicalize_command() applies before the v2 command hash
 *      is signed), but keywords are matched CASE-SENSITIVELY and
 *      abbreviations are NOT expanded: FRR's parser would accept
 *      "SHOW VERSION" and "sh ip os nei", this table accepts neither —
 *      an unlisted spelling falls through RED, fail closed.
 *
 *      Case-folding here was the 2026-08-09 classified≠executed bug:
 *      `VTYSH -C "SHOW IP OSPF"` classified GREEN on the lowercased
 *      copy while the driver executed the ORIGINAL bytes, so the gate
 *      signed a GREEN execution of a string it never actually
 *      classified. The invariant is: the exact byte string that was
 *      classified is the exact byte string that executes, or nothing
 *      executes (classifier equivalence may not exceed the equivalence
 *      the signed command hash itself collapses — whitespace runs
 *      only). Do NOT restore tolower() here, and do NOT "fix" a case
 *      mismatch by canonicalizing before execution — rewriting the
 *      executed bytes is the same bug in the other direction.
 *
 * Rows (on the vtysh argument):
 *   GREEN  — show <rest>, rest limited to [a-z0-9 ./-]
 *   YELLOW — clear ip ospf (interface|neighbor) <rest>, ping/traceroute
 *   RED    — configure …, clear ip ospf process (instructive reasons via
 *            linux_gate_reason so the signed rejection teaches the
 *            propose/approve/apply path)
 * Bare shell: mutating tools touching /etc/frr/ and `systemctl … frr`
 * carry instructive RED reasons; everything else is RED by absence.
 * This table never returns BLACK, so every RED here stays approvable.
 * ========================================================================= */

#define LINUX_GATE_CANON_MAX 1024

static const char *const REASON_CONFIG =
    "configuration change — use propose/approve/apply";
static const char *const REASON_OSPF_PROCESS =
    "disruptive OSPF process reset — use propose/approve/apply";
static const char *const REASON_FRR_FILES =
    "FRR config file change — use propose/approve/apply";
static const char *const REASON_FRR_SERVICE =
    "FRR service control — use propose/approve/apply";
static const char *const REASON_SEPARATOR =
    "shell metacharacter refused — one plain command per request";
static const char *const REASON_MULTI_C =
    "multiple -c flags — a command sequence is not an observation";
static const char *const REASON_VTYSH_FORM =
    "malformed vtysh invocation — expected exactly: vtysh -c \"<command>\"";

/* Collapse whitespace runs and trim — case is PRESERVED (see the
 * classified≠executed note in the table header). Returns -1 if too
 * long. */
static int linux_gate_canon(const char *in, char *out, size_t out_len)
{
    size_t j = 0;
    int last_was_space = 1;              /* eats leading whitespace */
    for (const char *p = in; *p; p++) {
        char c = *p;
        if (c == ' ' || c == '\t') {
            if (!last_was_space) {
                if (j + 1 >= out_len) return -1;
                out[j++] = ' ';
                last_was_space = 1;
            }
            continue;
        }
        last_was_space = 0;
        if (j + 1 >= out_len) return -1;
        out[j++] = c;
    }
    while (j > 0 && out[j - 1] == ' ') j--;
    out[j] = '\0';
    return (int)j;
}

/* Does `canon` start with the full word `tok`? ("show" matches "show x"
 * and "show", never "shower" — and never the abbreviation "sh"). */
static bool tok_prefix(const char *canon, const char *tok)
{
    size_t n = strlen(tok);
    return strncmp(canon, tok, n) == 0 &&
           (canon[n] == '\0' || canon[n] == ' ');
}

/* Row charset for GREEN/YELLOW remainders: [a-z0-9 ./-] only. */
static bool rest_charset_ok(const char *rest)
{
    for (const char *p = rest; *p; p++) {
        if ((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
            *p == ' ' || *p == '.' || *p == '/' || *p == '-')
            continue;
        return false;
    }
    return true;
}

/* Is the first word of `rest` a non-empty prefix of `full`? vtysh
 * resolves unambiguous command prefixes, so `run`, `ru`, `runn`, …
 * all EXECUTE as `running-config`. Deliberately broader than vtysh's
 * own ambiguity resolution: any word that COULD resolve to `full`
 * matches, and the caller errs toward the stricter tier. */
static bool word_prefixes(const char *rest, const char *full)
{
    size_t n = 0;
    while (rest[n] && rest[n] != ' ') n++;
    return n > 0 && n <= strlen(full) && strncmp(rest, full, n) == 0;
}

/* Skip a matched token and the space after it (if any). */
static const char *tok_rest(const char *canon, const char *tok)
{
    const char *r = canon + strlen(tok);
    while (*r == ' ') r++;
    return r;
}

/* First word of `canon` equals `tok` exactly. */
static bool first_tok_is(const char *canon, const char *tok)
{
    return tok_prefix(canon, tok);
}

/* Any full word in `canon` starts with "frr" (frr, frr.service, frrouting
 * would also match — over-matching here only ever REDs, fail closed). */
static bool has_frr_token(const char *canon)
{
    const char *p = canon;
    while (*p) {
        while (*p == ' ') p++;
        if (strncmp(p, "frr", 3) == 0) return true;
        while (*p && *p != ' ') p++;
    }
    return false;
}

/* =========================================================================
 * Peer-health rows (VIRP node watching another VIRP node)
 *
 * EXACT-match only — the whole canonicalized command must equal a row.
 * No wildcards, no prefixes, no argument charset: a peer probe is a
 * fixed, enumerated read or it is nothing. This is deliberately
 * stricter than the vtysh GREEN row (which allows a charset-limited
 * remainder), because the peer rows run against another node's control
 * plane, where "close enough" would be an unforced error:
 *
 *   systemctl is-active virp-onode    → daemon liveness. Exact match
 *     means `systemctl stop virp-onode` is NOT reachable through this
 *     row; it stays RED by absence.
 *   virp-tool chain tail -n 1 …       → the peer's chain HEAD, which is
 *     what the comparator cross-references inside its own signed
 *     observation (see the federation note in the comparator: this is
 *     an observation OF the peer's report, not verification of the
 *     peer's signature — VIRP has no asymmetric observation signing).
 *   cat …/autopilot/published.json    → the peer's last published cycle
 *     summary (one fixed path). Without this the comparator cannot diff
 *     what the two nodes independently saw, which is the entire reason
 *     the second node exists.
 * ========================================================================= */

static const char *const LINUX_PEER_GREEN_EXACT[] = {
    "systemctl is-active virp-onode",
    "/opt/virp/build/virp-tool chain tail -n 1 --db /var/lib/virp/chain.db",
    "cat /var/lib/virp/autopilot/published.json",
};

/* =========================================================================
 * Host-health reads (2026-08-12)
 *
 * EXACT-match, same discipline as the peer rows above, and for the same
 * reason: these are the first rows that make any part of the bare-shell
 * surface non-RED, so they are enumerated spellings or they are nothing.
 *
 * Exactness is also what makes them metacharacter-proof without a
 * separate scan — `uptime > /tmp/x` and `df -h; rm -rf /` are not equal
 * to any row, so they fall through to RED by absence rather than needing
 * the Proxmox branch's raw-byte scan to catch them.
 *
 * `df -h` (not bare `df`) and `uname -a` (not bare `uname`) are the
 * spellings the requirement names; a neighbouring spelling such as
 * `df -h /var` carries an argument this table has not reasoned about and
 * stays RED.
 *
 * THE LIST IS NOT GROWING. A DELIBERATE HOLD (2026-08-13)
 *
 * A live probing session widened the Proxmox rows and kept `cat`, `ip`,
 * `ss`, `pvs`, `vgs`, `lvdisplay` and `lsblk` RED. That was not an
 * oversight or a to-do, and the argument is not "those commands are
 * dangerous" — `ip addr` is as harmless a read as `uptime`.
 *
 * The argument is about what the gate would then have to be able to do.
 * Every read the session actually needed had a Proxmox API answer:
 * `pvesh get /nodes/<node>/network` for `ip`, `pvesm status` and
 * `pvesm list <storage>` for `pvs`/`vgs`/`lvdisplay`,
 * `pvesh get /nodes/<node>/disks/list` for `lsblk`, and the config and
 * status endpoints for anything `cat` would have been pointed at. Those
 * arrive as a bounded verb over a structured path — `pvesh get` is one
 * decision this table can make correctly and completely, and the
 * enumerated `qm`/`pct`/`pvesm` rows are finite sets.
 *
 * Adding generic host shell changes the job description. `cat <path>`
 * means the gate must decide which of a filesystem's paths are reads
 * worth signing (`cat /etc/shadow`? `cat /root/.ssh/id_ed25519`?), and
 * `ip`/`ss` bring subcommand trees where `ip addr` and `ip route add`
 * differ by one word. That is no longer "know the Proxmox API"; it is
 * "police arbitrary Linux", which is an open-ended surface with no
 * schema behind it and no natural place to stop. The three rows here are
 * exact spellings precisely because they are the exception to that, and
 * a fourth is only earned by a read the API genuinely cannot answer.
 * ========================================================================= */

static const char *const LINUX_HOST_GREEN_EXACT[] = {
    "df -h",
    "uptime",
    "uname -a",
};

static bool is_host_green_exact(const char *canon)
{
    for (size_t i = 0;
         i < sizeof(LINUX_HOST_GREEN_EXACT) / sizeof(LINUX_HOST_GREEN_EXACT[0]);
         i++) {
        if (strcmp(canon, LINUX_HOST_GREEN_EXACT[i]) == 0)
            return true;
    }
    return false;
}

static bool is_peer_green_exact(const char *canon)
{
    for (size_t i = 0;
         i < sizeof(LINUX_PEER_GREEN_EXACT) / sizeof(LINUX_PEER_GREEN_EXACT[0]);
         i++) {
        if (strcmp(canon, LINUX_PEER_GREEN_EXACT[i]) == 0)
            return true;
    }
    return false;
}

/* Mutating tools whose mention of /etc/frr/ is a config write. Reads
 * (cat, less, grep …) stay RED by absence with the generic reason. */
static bool is_mutating_tool(const char *canon)
{
    static const char *const TOOLS[] = {
        "sed", "tee", "cp", "mv", "rm", "chmod", "chown", "truncate",
        "dd", "ln", "echo", "printf", "install", "touch",
    };
    for (size_t i = 0; i < sizeof(TOOLS) / sizeof(TOOLS[0]); i++)
        if (first_tok_is(canon, TOOLS[i])) return true;
    return false;
}

/* =========================================================================
 * Gate classifier — Proxmox VE table (linux driver only)
 *
 * pve-lab is registered as a `linux` device: Proxmox VE is Debian, the
 * transport is the same SSH exec channel, so the same classifier runs.
 * Everything here is ADDITIVE — no vtysh/FRR row changes, and a command
 * that is not one of the enumerated Proxmox tools never enters this
 * branch at all.
 *
 * Order inside the branch is load-bearing, top to bottom:
 *
 *   1. RAW metacharacter scan, on the ORIGINAL bytes, before tokenizing
 *      or matching anything: ; | & $( ${ ` > < and every control byte
 *      (newline included). `qm list; rm -rf /` starts with a GREEN row's
 *      exact spelling, so a prefix match that ran first would classify
 *      the whole compound string GREEN. This scan can never move below
 *      the rows.
 *
 *      The daemon's ingress filter and Guard 1 above already refuse most
 *      of that set, and `>` / `<` are in NEITHER of them
 *      (virp_command_check_separators covers separators and command
 *      substitution, not redirection). The scan is repeated here IN FULL
 *      rather than only for the two missing bytes, so this table is
 *      correct on its own terms instead of on a neighbour's — a caller
 *      that reaches linux_gate_classify() directly, as the tests do, gets
 *      the same answer as one that came through the daemon.
 *
 *   2. Argument charset — [A-Za-z0-9 ._/:=,-]. Everything a Proxmox read
 *      needs (API paths, node names, option values) and nothing that
 *      composes a shell word. Quotes, backslash, parens, braces, glob
 *      bytes and ~ are all absent, so there is no second layer of shell
 *      syntax left to reason about after step 1.
 *
 *   3. SELF-PROTECTION — see linux_prox_self_protect(). Runs BEFORE any
 *      tier is assigned, and its RED is final.
 *
 *   4. Verb tiers, RED rows first, then GREEN, then YELLOW, then RED by
 *      absence. Case is matched exactly, as in the FRR table: `QM LIST`
 *      is not a spelling of `qm list` (see the classified≠executed note
 *      in the FRR table header — the bytes classified are the bytes that
 *      execute, and this table must never launder a case difference).
 *
 * Tier table (on the canonicalized command):
 *   GREEN  — qm list, pct list, pveversion, pvecm status, pvecm nodes,
 *            pvesm status, pvesm list <storage>, qm|pct status <vmid>,
 *            qm|pct config <vmid>, pvesh get <path> where <path> is not
 *            under /access and carries no `agent` segment
 *   YELLOW — qm|pct start|stop|shutdown|reboot|suspend|resume|create|
 *            set|clone|migrate|snapshot <vmid> …, pvesh create|set
 *            <path> …, vzdump … (without a deletion flag),
 *            pvesh get /access…
 *   RED    — qm guest …, qm|pct agent …, pct exec|enter,
 *            pvesh <any method> on a path with an `agent` segment,
 *            qm|pct delsnapshot, a malformed or unconfigured VMID, and
 *            everything else by absence. Blocked, but approvable.
 *   BLACK  — qm|pct destroy, pvesh delete, pvesm remove|free|wipedisk,
 *            vzdump --delete|--remove|--prune-backups, and ANY command
 *            naming a protected VMID.
 *
 * BLACK is new as of 2026-08-12 and is a deliberate reversal of this
 * table's original "never BLACK, every RED stays approvable" rule. The
 * reasoning, and why it applies to exactly these rows and no others,
 * is in the NEVER-tier section header further down this file.
 *
 * ----------------------------------------------------------------------
 * Why `pvesh get` is GREEN as a whole VERB, not as a path allowlist
 * (2026-08-13)
 *
 * `get` is read-only by construction in the Proxmox REST API: the four
 * methods are the tier boundary, so the verb is already the bounded,
 * structured surface a per-path allowlist would be trying to approximate.
 * An allowlist of paths approximates it badly — the API has 341 GET
 * endpoints, an operator question arrives as whichever one answers it,
 * and every path nobody thought to enumerate is a false RED on a pure
 * read. The verb is the row; the path is an argument to it.
 *
 * That claim was checked against the published API schema rather than
 * assumed (pve-docs api-viewer apidoc.js, 678 endpoints, read
 * 2026-08-13). Two results are what this row rests on:
 *
 *   - NO GET endpoint returns a UPID. A Proxmox endpoint that starts a
 *     background worker returns one, so zero UPID-returning GETs means
 *     no GET spawns a task. Every mutation in the schema is POST, PUT or
 *     DELETE, including the pairs where the GET is the read half of the
 *     same path (`GET /nodes/<n>/apt/update` lists pending updates;
 *     POST on the same path is the `apt-get update` that fetches them).
 *
 *   - ONE subtree is the exception, and it is excluded below:
 *     the /nodes/<node>/qemu/<vmid>/agent subtree. Those GETs are
 *     described as "Execute get-osinfo", "Execute get-users" …, and
 *     that is literal — they dispatch a command to the QEMU guest agent
 *     INSIDE the guest. Read-only as far as the guest is concerned, but
 *     the boundary crossed is the one `qm guest` is already RED for: a
 *     command running somewhere this gate did not classify. The whole
 *     `agent` segment is refused, for every pvesh method, because the
 *     same subtree also holds exec, file-write and set-user-password —
 *     refusing only the GET half would leave those approvable at YELLOW
 *     through the `pvesh create` row.
 *
 * Three further GET classes DO act on the world, and all three are
 * already unreachable because a GREEN row is an EXACT shape: each needs
 * at least one --flag, and a fourth token drops the command to RED by
 * absence. They are recorded here so a future widening of the shape does
 * not reopen them silently:
 *
 *   - /nodes/<node>/scan/{nfs,cifs,iscsi,pbs} — connects OUT to an
 *     operator-named server; the pbs variant takes --password, which
 *     would put a credential in the signed command bytes.
 *   - /nodes/<node>/{qemu,lxc}/<vmid>/vncwebsocket, mtunnelwebsocket —
 *     upgrades the connection to a websocket. Needs a ticket that only
 *     a POST can mint, so it is inert on its own.
 *   - /nodes/<node>/storage/<s>/file-restore/download — materializes a
 *     zip of a file extracted from a PBS backup.
 *
 * 35 of the 341 GET endpoints need a flag like this. The other 306 are
 * reachable as a clean three-token `pvesh get <path>`, which is the
 * surface this row deliberately opens.
 * ========================================================================= */

/* Protected VMIDs — a guest this gate may not touch at ANY tier.
 *
 * Sourced from devices.json ("protected_vmids": [313]) and registered by
 * the device loader at startup via linux_gate_set_protected_vmids(); it
 * is deliberately NOT a constant in this file. The set is a property of
 * the deployment (which VM is this node), not of the code, and a
 * hardcoded 313 would be silently wrong on the next node.
 *
 * The route_command() hook is handed a command and nothing else — no
 * device, no connection (see the write_ops_allow note in virp_driver.h,
 * which is the same problem solved the other way). So the registry here
 * is the UNION of every linux/proxmox device's protected_vmids. Union is
 * the fail-closed direction: with two Proxmox hosts, a VMID protected on
 * either is refused on both. Over-refusal is an operator inconvenience;
 * under-refusal is the loop switching off its own gate.
 *
 * Written once at startup, before the daemon serves, and read-only
 * afterwards — no locking, same lifetime discipline as the device table.
 */
#define LINUX_PROTECTED_VMID_MAX  64
#define LINUX_PROX_MAX_TOK        64

static uint32_t linux_protected_vmids[LINUX_PROTECTED_VMID_MAX];
static size_t   linux_protected_vmid_count;
/*
 * Has ANY device declared the field? Distinct from count > 0: an
 * operator who has not configured this yet, and one who configured an
 * empty list, are not the same claim, and the first must not classify
 * `qm stop 313` as an ordinary YELLOW action just because nobody said
 * 313 was special. Unconfigured + a VMID in the command = RED.
 */
static bool     linux_protected_vmids_configured;

static const char *const REASON_PROX_METACHAR =
    "shell metacharacter refused — one plain command per request";
static const char *const REASON_PROX_CHARSET =
    "illegal byte in Proxmox argument — refused";
static const char *const REASON_PROX_VMID_FORM =
    "VMID expected and unparseable — refused rather than classified by verb";
static const char *const REASON_PROX_PROTECTED =
    "protected VMID — this guest runs a VIRP gate; never transmitted at "
    "any tier and deliberately not approvable";
static const char *const REASON_PROX_NO_SET =
    "protected_vmids is not configured for this device — VMID-bearing "
    "Proxmox commands are refused until it is";
static const char *const REASON_PROX_DESTROY =
    "irreversible guest or storage destruction — never transmitted, and "
    "deliberately not approvable; do it deliberately outside VIRP";
static const char *const REASON_PROX_BACKUP_DELETE =
    "removes existing backups — the restore path is what makes a YELLOW "
    "action reversible; never transmitted, not approvable";
static const char *const REASON_PROX_GUEST_EXEC =
    "qm guest exec runs arbitrary commands inside a guest — a classifier "
    "bypass by proxy";
static const char *const REASON_PROX_AGENT_PATH =
    "the guest-agent API subtree executes inside the guest — read or "
    "write, the payload is a command this gate never classified";
static const char *const REASON_PROX_ACCESS_WRITE =
    "writes to the /access tree mint or re-grant identity — the "
    "credential outlives the approval and works outside VIRP; reachable "
    "only through propose/approve/apply";
static const char *const REASON_PROX_QUOTE_FORM =
    "quoted argument refused — a quote may only open a whole token, must "
    "close, and may not contain a tab or a double space";
static const char *const REASON_PROX_SHELL_PATH =
    "this API path opens a shell on the node or dispatches a batch of "
    "API calls — the payload is a command this gate never classified";
static const char *const REASON_PROX_VZDUMP_HOOK =
    "--script runs an operator-named program as root during the backup "
    "and --stdout redirects the archive off its storage — neither "
    "payload is classified by this gate";

/*
 * Register protected VMIDs from one device's config. `csv` is a
 * comma-separated decimal list ("313" / "313,400"); empty or NULL
 * declares nothing and leaves the registry untouched.
 *
 * Returns 0 on success, -1 if the list is unparseable or overflows, in
 * which case `configured` is NOT set — a config the loader could not
 * understand must not be mistaken for a config that protects nothing.
 * Every VMID-bearing Proxmox command then classifies RED.
 *
 * Non-static: called by the device loader (virp_onode_prod.c) and by
 * tests/test_driver_linux_gate.c.
 */
int linux_gate_set_protected_vmids(const char *csv)
{
    if (!csv || !*csv) return 0;

    /* Parse into a scratch list first: a list that fails halfway must
     * not leave half of itself registered. */
    uint32_t parsed[LINUX_PROTECTED_VMID_MAX];
    size_t   n = 0;

    for (const char *p = csv; *p; ) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;

        uint64_t v = 0;
        size_t digits = 0;
        while (*p >= '0' && *p <= '9') {
            v = v * 10 + (uint64_t)(*p - '0');
            if (v > 0xFFFFFFFFull) return -1;   /* not a VMID */
            digits++;
            p++;
        }
        if (digits == 0) return -1;             /* non-numeric entry */
        while (*p == ' ') p++;
        if (*p && *p != ',') return -1;         /* trailing junk */

        if (n >= LINUX_PROTECTED_VMID_MAX) return -1;
        parsed[n++] = (uint32_t)v;
    }

    for (size_t i = 0; i < n; i++) {
        bool dup = false;
        for (size_t j = 0; j < linux_protected_vmid_count; j++)
            if (linux_protected_vmids[j] == parsed[i]) { dup = true; break; }
        if (dup) continue;
        if (linux_protected_vmid_count >= LINUX_PROTECTED_VMID_MAX) return -1;
        linux_protected_vmids[linux_protected_vmid_count++] = parsed[i];
    }

    linux_protected_vmids_configured = true;
    return 0;
}

/* Test-only reset — the daemon never calls this. */
void linux_gate_clear_protected_vmids(void)
{
    linux_protected_vmid_count = 0;
    linux_protected_vmids_configured = false;
}

static bool linux_prox_is_protected(uint32_t vmid)
{
    for (size_t i = 0; i < linux_protected_vmid_count; i++)
        if (linux_protected_vmids[i] == vmid) return true;
    return false;
}

/* Step 1 — raw metacharacter scan. See the branch header: this runs on
 * the ORIGINAL bytes, before tokenizing, and is the reason a compound
 * command can never prefix-match a GREEN row. */
static bool linux_prox_has_metachar(const char *raw)
{
    for (const unsigned char *p = (const unsigned char *)raw; *p; p++) {
        if (*p < 0x20 || *p == 0x7F) return true;   /* newline, all controls */
        if (*p == ';' || *p == '|' || *p == '&' || *p == '`' ||
            *p == '>' || *p == '<')
            return true;
        if (*p == '$' && (p[1] == '(' || p[1] == '{')) return true;
    }
    return false;
}

/*
 * Step 1b — quote shape, on the RAW bytes, before canonicalization.
 *
 * This has to see the raw string, because what it refuses is precisely
 * what canonicalization would erase. linux_gate_canon() collapses every
 * run of spaces and turns tabs into spaces, with no idea that quotes
 * exist. The device executes the RAW command (libssh2_channel_exec gets
 * the request bytes, not the canon), so once a quoted value may contain
 * a space, `--description "a    b"` would be CLASSIFIED as "a b" and
 * EXECUTED as "a    b" — different bytes, and the chain would record a
 * signature over a command that is not the one that ran.
 *
 * Rather than teach canonicalization about quotes — which would change a
 * function the vtysh/FRR table also depends on — the interior is
 * required to be something canonicalization cannot alter: no tabs, and
 * no run of two or more spaces. Single interior spaces survive canon
 * byte-for-byte, so after this check the canon's quoted regions are
 * identical to the raw's, and the tokenizer may walk the canon safely.
 *
 * An operator who genuinely needs a double space in a description is
 * refused. That is the trade: a false refusal is a config edit, a
 * classified-vs-executed split is the gate signing something it did not
 * read.
 */
static bool linux_prox_quotes_raw_ok(const char *raw)
{
    bool in_quote = false;
    for (const char *p = raw; *p; p++) {
        if (*p == '"') { in_quote = !in_quote; continue; }
        if (!in_quote) continue;
        if (*p == '\t') return false;                  /* canon would fold */
        if (*p == ' ' && p[1] == ' ') return false;    /* canon would fold */
    }
    return !in_quote;                                  /* unbalanced */
}

/* Bytes legal in a BARE (unquoted) token. Unchanged from the original
 * row: everything a Proxmox path, node name or option value needs, and
 * nothing that composes a shell word. */
static bool prox_byte_bare_ok(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == ' ' || c == '.' || c == '_' || c == '/' ||
           c == ':' || c == '=' || c == ',' || c == '-';
}

/*
 * Bytes legal INSIDE a quoted value.
 *
 * The quoted region reaches the device intact — libssh2_channel_exec()
 * hands the RAW request bytes to the remote login shell, so the very
 * quotes classified here are the quotes that shell parses, and the
 * region becomes exactly one argv element. What has to be excluded is
 * therefore precisely what is still active INSIDE double quotes:
 *
 *   "   would close the region early and start a new word
 *   \   escapes the next byte, including the closing quote
 *   $   parameter expansion — note step 1 refuses only `$(` and `${`,
 *       so a bare `$HOME` would otherwise survive it and expand here
 *   `   command substitution (step 1 refuses it too; excluded again
 *       here so this function is correct on its own terms)
 *
 * ; | & < > are already refused by step 1 for the whole raw string,
 * quoted region included. They are excluded again below for the same
 * reason: a neighbour's guarantee is not this function's.
 *
 * Glob and brace bytes (* ? [ ] { } ~) are LITERAL inside double quotes
 * and are allowed — a description or a tag legitimately contains them,
 * and the region can never be split into a second word for them to act
 * on. Single quote is allowed as ordinary punctuation (an apostrophe);
 * it has no meaning inside a double-quoted region.
 */
static bool prox_byte_quoted_ok(char c)
{
    if (prox_byte_bare_ok(c)) return true;
    switch (c) {
    case '"': case '\\': case '$': case '`':
    case ';':  case '|':  case '&': case '<': case '>':
        return false;
    default:
        /* Printable ASCII only — no control bytes (step 1 refuses those
         * too), no high-bit bytes. */
        return c >= 0x20 && c <= 0x7E;
    }
}

typedef struct {
    const char *p;
    size_t      len;
    bool        quoted;   /* value came from inside a "..." region */
} prox_tok_t;

typedef enum {
    PROX_TOK_OK = 0,
    PROX_TOK_BAD_CHARSET,   /* illegal byte for its context */
    PROX_TOK_BAD_QUOTE,     /* unbalanced, misplaced or nested quote */
    PROX_TOK_TOO_MANY,      /* more tokens than the table will consider */
} prox_tok_status_t;

/*
 * Steps 2 + 3 — ONE quote-aware tokenizer, charset-validating as it
 * goes. Both jobs live here on purpose: the old code had a charset scan
 * and a separate splitter, and once a quoted value can contain a space
 * the two would disagree about where tokens end. Two tokenizers that
 * disagree is the classified-vs-executed split this file's header
 * forbids, so there is exactly one.
 *
 * QUOTES ARE STRIPPED from the stored token. This is load-bearing, not
 * cosmetic: the remote shell strips them too, so `vzdump 100 "--delete"`
 * arrives at vzdump as --delete. A token stored WITH its quotes would
 * not match the BLACK deletion row, and the fix admitting quoted values
 * would itself have opened a never-class bypass. Every tier row matches
 * what the device will see; `quoted` records where the bytes came from
 * so rows that need a bare word can still insist on one.
 *
 * Accepted token shapes — deliberately narrow, so the result is
 * auditable rather than merely parseable:
 *
 *   bare        qm, /nodes/x, --memory, 4096
 *   "quoted"    an ENTIRE token, quotes stripped
 *
 * A quote may only open at the start of a token. `--flag="a b"` is
 * refused, and that is a deliberate choice rather than an oversight:
 * the shell yields `--flag=a b` for it, which is not a contiguous run
 * in this buffer, so the stored token could not be byte-identical to
 * what executes. Rather than store a token that only mostly matches —
 * the exact class of near-miss that turns into a bypass — the shape is
 * refused. `--flag "a b"`, two tokens, expresses the same thing and is
 * what an operator writes anyway.
 *
 * Anything else — a quote opening mid-word, text after a closing quote,
 * a second quoted region in one token — is BAD_QUOTE.
 *
 * Interior whitespace is NOT re-examined here. linux_prox_quotes_raw_ok()
 * has already refused any quoted region containing a tab or a run of two
 * or more spaces, on the RAW bytes, which is what makes canonicalization
 * a provable no-op inside quotes and lets this walk the canon safely.
 */
static prox_tok_status_t linux_prox_tokenize(const char *canon,
                                             prox_tok_t *out, size_t max,
                                             size_t *out_n)
{
    size_t n = 0;
    const char *p = canon;

    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (n >= max) return PROX_TOK_TOO_MANY;

        const char *start = p;

        if (*p == '"') {
            /* Quoted token: the whole token is one quoted region, and
             * the stored span is the INTERIOR — quotes stripped, exactly
             * the bytes the remote shell will produce. */
            p++;
            start = p;
            while (*p && *p != '"') {
                if (!prox_byte_quoted_ok(*p)) return PROX_TOK_BAD_CHARSET;
                p++;
            }
            if (*p != '"') return PROX_TOK_BAD_QUOTE;   /* unbalanced */
            out[n].p = start;
            out[n].len = (size_t)(p - start);
            p++;                                        /* past closing " */
            if (*p && *p != ' ') return PROX_TOK_BAD_QUOTE; /* trailing junk */
            out[n].quoted = true;
            n++;
            continue;
        }

        /* Bare run. A quote anywhere inside it is refused — see the
         * shape note above. */
        while (*p && *p != ' ') {
            if (*p == '"') return PROX_TOK_BAD_QUOTE;
            if (!prox_byte_bare_ok(*p)) return PROX_TOK_BAD_CHARSET;
            p++;
        }

        out[n].p = start;
        out[n].len = (size_t)(p - start);
        out[n].quoted = false;
        n++;
    }

    *out_n = n;
    return PROX_TOK_OK;
}

/*
 * Content equality — quotes already stripped, so this compares what the
 * device will see. It does NOT consider `quoted`: use prox_tok_eq_bare()
 * wherever a row needs an actual bare word.
 */
static bool prox_tok_eq(const prox_tok_t *t, const char *s)
{
    return strlen(s) == t->len && strncmp(t->p, s, t->len) == 0;
}

/*
 * Equality that also insists the token was NOT quoted.
 *
 * Every row naming a structural element — the tool, a verb, an API
 * method — uses this. `"qm" list` and `qm "list"` are not spellings of
 * `qm list`: they reach the shell as the same argv, but a table that
 * accepted them would be reasoning about a quoted string in a position
 * where it enumerated bare words, and the enumeration is the whole
 * safety argument. Refused (RED by absence), which is the safe
 * direction and keeps the row set exactly as narrow as it reads.
 */
static bool prox_tok_eq_bare(const prox_tok_t *t, const char *s)
{
    return !t->quoted && prox_tok_eq(t, s);
}

static bool prox_tok_in(const prox_tok_t *t, const char *const *set, size_t n)
{
    if (t->quoted) return false;
    for (size_t i = 0; i < n; i++)
        if (prox_tok_eq(t, set[i])) return true;
    return false;
}

/*
 * Flag-denylist matching, normalized to what the TOOL will parse.
 *
 * Two spellings reach the same flag and neither may evade a never-class
 * row:
 *
 *   vzdump 100 "--delete"    quotes stripped by the shell -> --delete
 *   vzdump 100 --delete=1    Proxmox CLI accepts --flag=value
 *
 * The first is why the tokenizer stores stripped content; without it,
 * admitting quoted values would have opened a BLACK bypass. The second
 * predates quoting entirely — `vzdump 100 --delete=1` classified YELLOW
 * against a row that exists to make deletion unapprovable — and is why
 * this compares the HEAD, the span before the first '=', rather than the
 * whole token.
 *
 * Quote-agnostic on purpose: a denylist must match the bytes the tool
 * acts on, wherever they came from. That is the opposite of the bare-word
 * rows above, and deliberately so — one asks "is this the word I
 * enumerated", the other asks "will this do the thing I refuse".
 */
static bool prox_flag_in(const prox_tok_t *t, const char *const *set, size_t n)
{
    size_t head = 0;
    while (head < t->len && t->p[head] != '=') head++;
    for (size_t i = 0; i < n; i++) {
        if (strlen(set[i]) == head && strncmp(t->p, set[i], head) == 0)
            return true;
    }
    return false;
}

/* A VMID is a non-empty run of decimal digits and NOTHING else — no
 * sign, no whitespace, no name. "313x", "0x139", "-1" and "" all fail,
 * and a failure at an expected position is RED, never a fall-through. */
static bool prox_vmid_digits(const prox_tok_t *t, uint32_t *out)
{
    if (t->len == 0 || t->len > 9) return false;
    uint32_t v = 0;
    for (size_t i = 0; i < t->len; i++) {
        if (t->p[i] < '0' || t->p[i] > '9') return false;
        v = v * 10 + (uint32_t)(t->p[i] - '0');
    }
    *out = v;
    return true;
}

/* A guest id as the HA and pool APIs spell it: `vm:313`, `ct:313`.
 *
 * This is a THIRD spelling of the same thing. /nodes/<n>/qemu/<vmid>
 * names a guest positionally, `qm stop <vmid>` names it as an argument,
 * and the cluster-scoped APIs name it as a typed sid. Self-protection
 * has to recognize all three, or the guard is only as good as the
 * spelling an operator happens to use. */
static bool prox_sid_vmid(const char *p, size_t len, uint32_t *out)
{
    if (len <= 3 || p[2] != ':') return false;
    if (!((p[0] == 'v' && p[1] == 'm') || (p[0] == 'c' && p[1] == 't')))
        return false;
    prox_tok_t idt = { p + 3, len - 3, false };
    return prox_vmid_digits(&idt, out);
}

typedef enum {
    PROX_ID_NONE = 0,      /* no field in this token named a guest */
    PROX_ID_CLEAR,         /* named one or more, none protected */
    PROX_ID_PROTECTED,     /* named a protected guest */
} prox_id_scan_t;

/*
 * Scan ONE token for guest ids, splitting on commas.
 *
 * The comma split is not cosmetic. `--vms 100,313` is how the pool API
 * takes a list and `--vmid 100,313` is how vzdump takes one, and a scan
 * that judged whole tokens saw neither: `vzdump --vmid 313` was BLACK
 * while `vzdump --vmid 100,313` was YELLOW, naming the same guest. That
 * is the same defect as the vm:313 spelling — a way of writing the
 * protected id that self-protection could not read — so both are fixed
 * here, in one place used by every branch.
 *
 * `numeric_ok` is the caller's judgement about whether a BARE number
 * names a guest in this context. It does after a qm/pct verb and in a
 * vzdump argument vector; it does not in an arbitrary pvesh argument,
 * where a number is usually a size or a flag value, so pvesh passes
 * true only for cluster- and pool-scoped paths.
 *
 * *saw_sid reports whether a field used the unambiguous vm:/ct: form,
 * which is what lets a caller distinguish "this names a guest" from
 * "this contains a number".
 */
static prox_id_scan_t prox_scan_token_ids(const prox_tok_t *t, bool numeric_ok,
                                          bool *saw_sid)
{
    prox_id_scan_t res = PROX_ID_NONE;
    size_t f = 0;

    while (f < t->len) {
        while (f < t->len && t->p[f] == ',') f++;
        size_t fs = f;
        while (f < t->len && t->p[f] != ',') f++;
        size_t flen = f - fs;
        if (flen == 0) continue;

        uint32_t v;
        bool named = false;
        if (prox_sid_vmid(t->p + fs, flen, &v)) {
            named = true;
            if (saw_sid) *saw_sid = true;
        } else if (numeric_ok) {
            /* `quoted` is deliberately false on the field view: a scan
             * hunting a protected id must read "313" the same as 313,
             * exactly as prox_vmid_digits() does for whole tokens. */
            prox_tok_t ft = { t->p + fs, flen, false };
            named = prox_vmid_digits(&ft, &v);
        }
        if (!named) continue;

        if (linux_protected_vmids_configured && linux_prox_is_protected(v))
            return PROX_ID_PROTECTED;
        res = PROX_ID_CLEAR;
    }
    return res;
}

/*
 * A VMID in a position where the table EXPECTS one. Quoted is refused:
 * `qm stop "313"` is not a spelling of `qm stop 313` for this table, and
 * the refusal is PROX_VMID_BAD -> RED, never a fall-through to the verb
 * tier.
 *
 * Note the asymmetry with prox_vmid_digits() above, which ignores
 * `quoted` and is what the self-protection SCANS use. That is the
 * important half: a scan looking for a protected id must find `"313"`
 * too, because the shell hands the device 313 either way. If the scan
 * used this function, a quoted id would simply fail to parse, the loop
 * would skip it, and quoting would become a second protected-VMID
 * bypass alongside the `vm:313` spelling. One function refuses a
 * malformed argument; the other hunts for a dangerous value. They must
 * not be the same function.
 */
static bool prox_parse_vmid(const prox_tok_t *t, uint32_t *out)
{
    if (t->quoted) return false;
    return prox_vmid_digits(t, out);
}

/* A storage ID as Proxmox spells it (pve-storage-id): alphanumeric first
 * byte, then [A-Za-z0-9._-].
 *
 * The leading-alphanumeric requirement is the load-bearing half. The
 * `pvesm list <storage>` row is an exact three-token shape, and the
 * branch-wide charset permits `-`, so `pvesm list --content` is also
 * three tokens: a row that only counted tokens would classify a flag as
 * a storage name. Requiring the shape of the argument, not just its
 * position, is what keeps the row as narrow as it reads.
 *
 * `local:100/vm-100-disk-0` is rejected too — `:` and `/` are absent
 * here. That is a volume ID, not a storage ID, and the narrower answer
 * is the one to be wrong with. */
static bool prox_is_storage_id(const prox_tok_t *t)
{
    if (t->quoted) return false;   /* structural argument — bare only */
    if (t->len == 0 || t->len > 64) return false;
    char c = t->p[0];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9')))
        return false;
    for (size_t i = 1; i < t->len; i++) {
        char b = t->p[i];
        if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') ||
            (b >= '0' && b <= '9') || b == '.' || b == '_' || b == '-')
            continue;
        return false;
    }
    return true;
}

/* Does an API path carry an `agent` segment? See the whole-verb note in
 * the branch header: that subtree runs commands inside the guest, so it
 * is refused for every pvesh method rather than tiered by method.
 *
 * Matched segment-wise, and checked at ANY depth rather than only at the
 * documented /nodes/<node>/qemu/<vmid>/agent position. The schema has the
 * segment nowhere else (26 endpoints, all under that one subtree), so a
 * depth-agnostic match costs nothing today and stays correct if Proxmox
 * grows a second one. */
static bool prox_path_has_seg_in(const prox_tok_t *t,
                                 const char *const *set, size_t n)
{
    const char *p = t->p;
    size_t plen = t->len, i = 0;
    while (i < plen) {
        while (i < plen && p[i] == '/') i++;
        size_t start = i;
        while (i < plen && p[i] != '/') i++;
        prox_tok_t seg = { p + start, i - start, false };
        if (seg.len && prox_tok_in(&seg, set, n)) return true;
    }
    return false;
}

static const char *const PROX_AGENT_SEGS[] = { "agent" };

/*
 * API path segments that hand out a shell on the NODE, or dispatch a
 * batch of API calls this gate never saw. Same reasoning as the `agent`
 * subtree and `qm guest exec`: one classified command carrying an
 * unclassified payload.
 *
 *   execute      POST runs an ARRAY of API calls in one request
 *   termproxy    terminal proxy on the node — a root shell
 *   vncshell     VNC shell on the node — a root shell
 *   spiceshell   SPICE shell on the node — a root shell
 *   vncproxy     the guest-console equivalents; console keystrokes are
 *   spiceproxy   the same unclassified-payload problem `qm terminal` is
 *                already RED by absence for
 *
 * Refused for EVERY pvesh method, not just the write half: the read half
 * is what mints the ticket the write half consumes, and splitting them
 * would leave the bypass assembled out of two permitted requests.
 *
 * These were YELLOW through the whole-verb `pvesh create` row. Note that
 * the 2026-08-13 schema review justifying `pvesh get` as a whole verb
 * enumerated the 341 GET endpoints only — the POST/PUT side never had
 * the equivalent reasoning, and these six are why that gap mattered.
 */
static const char *const PROX_PVESH_SHELL_SEGS[] = {
    "execute", "termproxy", "vncshell", "spiceshell",
    "vncproxy", "spiceproxy",
};

typedef enum {
    PROX_VMID_NONE = 0,     /* no VMID involved — nothing to protect */
    PROX_VMID_CLEAR,        /* VMID(s) parsed, none protected */
    PROX_VMID_PROTECTED,    /* a protected VMID is a target */
    PROX_VMID_BAD,          /* a VMID was expected here and did not parse */
    PROX_VMID_UNCONFIGURED, /* a VMID is present, no protected set declared */
} prox_vmid_verdict_t;

/*
 * Step 3 — SELF-PROTECTION, before any tier is assigned.
 *
 * `qm stop 313` is, on any other guest, an ordinary bounded YELLOW
 * action. On 313 it is the gate powering itself off, and no tier
 * arithmetic downstream can distinguish the two — so the VMID is judged
 * first, and its RED is not a tier that something else can outrank.
 *
 * VMID positions recognised:
 *   qm|pct <verb> <vmid>                verb != list, argv position 2
 *   pvesh <m> /nodes/<node>/qemu/<vmid> segment after qemu/ or lxc/
 *   pvesh <m> /nodes/<node>/lxc/<vmid>
 *
 * Two deliberate over-reaches, both in the refusing direction:
 *
 *   - EVERY purely-numeric token after a qm/pct verb is checked, not
 *     just argv[2]. `qm clone 100 313` names its destination in argv[3]
 *     and `qm migrate` names targets further right; a rule that only
 *     looked at the documented position would let the protected VMID
 *     through as an argument. The cost is that `qm set 100 --memory 313`
 *     also refuses. That is the correct trade — a wrong refusal is a
 *     config edit, a wrong permit is the gate.
 *   - vzdump's numeric arguments are checked the same way even though
 *     vzdump is not a per-VMID verb in the requirement, because
 *     `vzdump 313` does name the protected guest.
 *
 * An EXPECTED-but-unparseable VMID is PROX_VMID_BAD → RED. It never
 * falls through to the verb tier: `qm stop notanumber` must not become
 * "well, the verb is YELLOW".
 */
static prox_vmid_verdict_t linux_prox_self_protect(const prox_tok_t *tok,
                                                   size_t ntok)
{
    if (ntok == 0) return PROX_VMID_NONE;

    bool saw_vmid = false;

    if (prox_tok_eq_bare(&tok[0], "qm") || prox_tok_eq_bare(&tok[0], "pct")) {
        if (ntok < 2) return PROX_VMID_NONE;        /* bare `qm` — RED later */
        if (prox_tok_eq_bare(&tok[1], "list")) return PROX_VMID_NONE;

        /* Every qm/pct verb takes the VMID at argv position 2, except
         * the guest-agent subtree, which spells it one further right
         * (`qm guest exec <vmid> …`, `qm guest cmd <vmid> …`). That
         * subtree is RED on its own row below; the position is still
         * resolved here so a protected VMID is named as such rather
         * than reported as a malformed argument. */
        size_t vpos = (prox_tok_eq_bare(&tok[0], "qm") &&
                       prox_tok_eq_bare(&tok[1], "guest")) ? 3 : 2;
        if (ntok <= vpos) return PROX_VMID_BAD;
        uint32_t vmid;
        if (!prox_parse_vmid(&tok[vpos], &vmid)) return PROX_VMID_BAD;
        saw_vmid = true;

        /* prox_vmid_digits(), NOT prox_parse_vmid(): this is the SCAN,
         * and it must find a protected id however it was spelled. A
         * quoted "313" reaches the device as 313, so a scan that skipped
         * quoted tokens would make quoting a second protected-VMID
         * bypass — the same shape of hole as the `vm:313` spelling. */
        for (size_t i = vpos; i < ntok; i++) {
            if (prox_scan_token_ids(&tok[i], true, NULL) == PROX_ID_PROTECTED)
                return PROX_VMID_PROTECTED;
        }
    } else if (prox_tok_eq_bare(&tok[0], "pvesh")) {
        if (ntok < 3) return PROX_VMID_NONE;        /* malformed — RED later */

        /* Walk the path segment by segment; the segment following a
         * `qemu` or `lxc` segment is the VMID. Anchoring on the parent
         * segment rather than on a fixed offset keeps this correct for
         * both /nodes/<node>/qemu/<vmid> and any longer path that
         * carries the same pair (…/qemu/<vmid>/status/stop). */
        const char *path = tok[2].p;
        size_t plen = tok[2].len;
        size_t i = 0;
        while (i < plen) {
            while (i < plen && path[i] == '/') i++;
            size_t start = i;
            while (i < plen && path[i] != '/') i++;
            size_t seglen = i - start;
            bool is_qemu = (seglen == 4 && strncmp(path + start, "qemu", 4) == 0);
            bool is_lxc  = (seglen == 3 && strncmp(path + start, "lxc", 3) == 0);
            if (!is_qemu && !is_lxc) continue;

            /* Next segment must be the VMID. */
            while (i < plen && path[i] == '/') i++;
            size_t vstart = i;
            while (i < plen && path[i] != '/') i++;
            /* A span carved out of a path token. Its bytes are content,
             * never a quoted region of their own, so `quoted` is false
             * and prox_parse_vmid() applies normally — including when
             * the enclosing path token was itself quoted, which is what
             * keeps `pvesh set "/nodes/x/qemu/313/config"` protected. */
            prox_tok_t vt = { path + vstart, i - vstart, false };
            uint32_t vmid;
            if (!prox_parse_vmid(&vt, &vmid)) return PROX_VMID_BAD;
            saw_vmid = true;
            if (linux_protected_vmids_configured && linux_prox_is_protected(vmid))
                return PROX_VMID_PROTECTED;
        }

        /*
         * The walk above anchors on `qemu`/`lxc`, which is how the
         * PER-GUEST API spells a VMID. The cluster-scoped APIs spell the
         * same guest differently, and reached YELLOW because the walk
         * found nothing to judge:
         *
         *   pvesh set    /cluster/ha/resources/vm:313 --state stopped
         *   pvesh create /cluster/ha/resources --sid vm:313
         *   pvesh set    /pools/<pool> --vms 313
         *
         * DEFENCE IN DEPTH, not a live-hole fix. Corrected 2026-08-13
         * after the first write of this comment overstated it.
         *
         * What was actually measured on pve-lab, by reads only: 313 is a
         * running guest there, pve-ha-crm and pve-ha-lrm are active and
         * enabled, and /cluster/ha/status/current reports quorum OK,
         * quorate=1. Those are PRECONDITIONS, and they were mistakenly
         * written up as proof of reachability.
         *
         * What the same read does NOT show is the part that matters:
         * there is no `master` row and no `lrm` row, only the quorum row.
         * No CRM master has been elected and no LRM has registered, so
         * the HA stack is idle rather than managing, and no HA resources
         * are configured. On this single standalone node the enroll-then-
         * stop sequence is very likely INERT today. It was never executed
         * to find out — the target is the guest running this gate.
         *
         * The classifier gap is real and unconditional regardless: the
         * self-protection walk could not read `vm:313`, so the guard's
         * coverage depended on which spelling an operator happened to
         * use. That is worth closing on its own terms. It should not be
         * described as closing a live bypass on this box.
         *
         * Two rules, deliberately different in strength:
         *
         *   - `vm:<n>` / `ct:<n>` ANYWHERE, path segment or argument.
         *     Unambiguously names a guest, so it also sets saw_vmid and
         *     an unconfigured protected set refuses, exactly as a
         *     positional VMID does.
         *   - Every bare numeric, but ONLY when the path is cluster- or
         *     pool-scoped, which is where `--vms 313` lives. This one
         *     does NOT set saw_vmid: `--migration-unsecure 1` is a
         *     numeric that names no guest, and treating it as one would
         *     turn an unconfigured deployment's ordinary cluster edits
         *     into refusals.
         */
        bool cluster_scope =
            (plen >= 8 && strncmp(path, "/cluster", 8) == 0) ||
            (plen >= 6 && strncmp(path, "/pools", 6) == 0);

        i = 0;
        while (i < plen) {                        /* path segments */
            while (i < plen && path[i] == '/') i++;
            size_t sstart = i;
            while (i < plen && path[i] != '/') i++;
            uint32_t sv;
            if (prox_sid_vmid(path + sstart, i - sstart, &sv)) {
                saw_vmid = true;
                if (linux_protected_vmids_configured &&
                    linux_prox_is_protected(sv))
                    return PROX_VMID_PROTECTED;
            }
        }

        for (size_t t = 1; t < ntok; t++) {       /* argument tokens */
            bool sid = false;
            prox_id_scan_t r = prox_scan_token_ids(&tok[t], cluster_scope, &sid);
            if (sid) saw_vmid = true;
            if (r == PROX_ID_PROTECTED) return PROX_VMID_PROTECTED;
        }
    } else if (prox_tok_eq_bare(&tok[0], "vzdump")) {
        /* Scan, not an expected position — quote- and comma-agnostic for
         * the same reason as the qm/pct scan above. `vzdump --vmid
         * 100,313` names the protected guest just as `vzdump --vmid 313`
         * does, and only the comma split sees it. */
        for (size_t i = 1; i < ntok; i++) {
            prox_id_scan_t r = prox_scan_token_ids(&tok[i], true, NULL);
            if (r != PROX_ID_NONE) saw_vmid = true;
            if (r == PROX_ID_PROTECTED) return PROX_VMID_PROTECTED;
        }
    }

    if (!saw_vmid) return PROX_VMID_NONE;
    if (!linux_protected_vmids_configured) return PROX_VMID_UNCONFIGURED;
    return PROX_VMID_CLEAR;
}

/* Is `canon`'s first word one of the Proxmox tools this table covers?
 * Anything else is not a Proxmox command and never enters the branch. */
static bool linux_prox_is_tool(const char *canon)
{
    static const char *const TOOLS[] = {
        "qm", "pct", "pvesh", "pveversion", "pvecm", "pvesm", "vzdump",
    };
    for (size_t i = 0; i < sizeof(TOOLS) / sizeof(TOOLS[0]); i++)
        if (tok_prefix(canon, TOOLS[i])) return true;
    return false;
}

/* qm/pct verbs that mutate a guest but stay bounded and reversible.
 *
 * `snapshot` joins them (2026-08-12): taking a snapshot is additive and
 * is the thing an operator does BEFORE a risky change, so gating it
 * harder than the change it protects would be backwards. Note the
 * asymmetry with `delsnapshot`, which destroys a restore point and is
 * deliberately NOT listed — it stays RED by absence. */
static const char *const PROX_GUEST_YELLOW_VERBS[] = {
    "start", "stop", "shutdown", "reboot", "suspend", "resume",
    "create", "set", "clone", "migrate", "snapshot",
};
/* qm/pct verbs that only read one guest's state. */
static const char *const PROX_GUEST_GREEN_VERBS[] = { "status", "config" };

/* pvesm verbs that destroy storage or the volumes on it. RED by absence
 * already refused these; naming them promotes the refusal to BLACK so an
 * enrolled approval key cannot authorize a wipe. */
static const char *const PROX_STORAGE_BLACK_VERBS[] = {
    "remove", "free", "wipedisk", "zfsscan-destroy", "destroy",
};

/* vzdump flags that turn a backup into a deletion. Bare `vzdump <vmid>`
 * writes a new archive and stays YELLOW; these remove existing ones. */
static const char *const PROX_VZDUMP_BLACK_FLAGS[] = {
    "--delete", "--remove", "--prune-backups", "-delete", "-remove",
};

/* vzdump flags whose payload this gate never sees. `--script` runs an
 * operator-named program as root at each backup phase, which is the
 * `qm guest exec` problem wearing a backup flag; `--stdout` sends the
 * archive to the channel instead of to its storage, so the backup this
 * gate authorized is not the artifact that results.
 *
 * RED, not BLACK: the command is legitimate and reversible, and a human
 * reading the script path is exactly the check that is missing. */
static const char *const PROX_VZDUMP_RED_FLAGS[] = {
    "--script", "-script", "--stdout", "-stdout",
};

/*
 * Proxmox branch of linux_gate_classify(). `command` is the raw request
 * bytes, `canon` the whitespace-collapsed copy the FRR table also uses.
 */
static virp_trust_tier_t linux_prox_classify(const char *command,
                                             const char *canon,
                                             const char **reason)
{
    /* 1 — raw metacharacters, before anything is tokenized or matched.
     * UNCHANGED and still first: quoting must never become a container
     * that shields a metacharacter from this scan. It runs on the raw
     * bytes with no notion of quotes, so ` and $( inside a quoted region
     * are refused exactly as they are outside one. The ordering — raw
     * metachars, then quote/charset rules, then tiers — is what makes
     * admitting quoted values safe at all. */
    if (linux_prox_has_metachar(command)) {
        if (reason) *reason = REASON_PROX_METACHAR;
        return VIRP_TIER_RED;
    }

    /* 1b — quote shape, also on the raw bytes: balanced, and carrying
     * nothing canonicalization would rewrite. See the function. */
    if (!linux_prox_quotes_raw_ok(command)) {
        if (reason) *reason = REASON_PROX_QUOTE_FORM;
        return VIRP_TIER_RED;
    }

    /* 2 — tokenize and charset-validate in one pass, quote-aware. */
    prox_tok_t tok[LINUX_PROX_MAX_TOK];
    size_t ntok = 0;
    switch (linux_prox_tokenize(canon, tok, LINUX_PROX_MAX_TOK, &ntok)) {
    case PROX_TOK_BAD_CHARSET:
        if (reason) *reason = REASON_PROX_CHARSET;
        return VIRP_TIER_RED;
    case PROX_TOK_BAD_QUOTE:
        if (reason) *reason = REASON_PROX_QUOTE_FORM;
        return VIRP_TIER_RED;
    case PROX_TOK_TOO_MANY:
        return VIRP_TIER_RED;
    case PROX_TOK_OK:
        break;
    }
    if (ntok == 0)
        return VIRP_TIER_RED;

    /* 3 — self-protection, ahead of every tier row. */
    switch (linux_prox_self_protect(tok, ntok)) {
    case PROX_VMID_PROTECTED:
        /* BLACK, not RED (2026-08-12). A protected VMID is the guest
         * running this gate; an approval key that could unlock
         * `qm stop 313` would be a key that switches off the thing
         * checking the key. PROX_VMID_BAD and PROX_VMID_UNCONFIGURED
         * below stay RED on purpose — those are malformed input and a
         * missing config, both of which a human should be able to look
         * at and escalate, not permanent refusals. */
        if (reason) *reason = REASON_PROX_PROTECTED;
        return VIRP_TIER_BLACK;
    case PROX_VMID_BAD:
        if (reason) *reason = REASON_PROX_VMID_FORM;
        return VIRP_TIER_RED;
    case PROX_VMID_UNCONFIGURED:
        if (reason) *reason = REASON_PROX_NO_SET;
        return VIRP_TIER_RED;
    case PROX_VMID_NONE:
    case PROX_VMID_CLEAR:
        break;
    }

    bool is_qm  = prox_tok_eq_bare(&tok[0], "qm");
    bool is_pct = prox_tok_eq_bare(&tok[0], "pct");

    /* 4a — refusal rows, with the teaching reason, before any permit.
     * `destroy` is BLACK (2026-08-12): a destroyed guest has no restore
     * path inside VIRP, so an approval would be authorizing something
     * the chain can record but not undo. */
    if ((is_qm || is_pct) && ntok >= 2) {
        if (prox_tok_eq_bare(&tok[1], "destroy")) {
            if (reason) *reason = REASON_PROX_DESTROY;
            return VIRP_TIER_BLACK;
        }
        /* `qm guest exec` is arbitrary execution inside the guest: it
         * would carry an unclassified command through a classified one,
         * so the gate would be signing "ran a classified command" over a
         * payload it never saw. The whole `guest` subtree is refused
         * rather than just `exec` — the bypass is the subtree's purpose,
         * not one verb's.
         *
         * pct's container equivalents (`pct exec`, `pct enter`) are the
         * same bypass and were already RED by absence; naming them here
         * only changes which reason the signed refusal carries, never
         * the tier. */
        if (is_qm && prox_tok_eq_bare(&tok[1], "guest")) {
            if (reason) *reason = REASON_PROX_GUEST_EXEC;
            return VIRP_TIER_RED;
        }
        if (is_pct && (prox_tok_eq_bare(&tok[1], "exec") ||
                       prox_tok_eq_bare(&tok[1], "enter"))) {
            if (reason) *reason = REASON_PROX_GUEST_EXEC;
            return VIRP_TIER_RED;
        }
        /* `qm agent <vmid> <cmd>` is the same guest-agent dispatch as the
         * API subtree below, spelled shorter. It was already RED by
         * absence; naming it changes only which reason the signed refusal
         * carries. (pct has no agent verb — the row costs nothing there
         * and is not worth a separate condition.) */
        if (prox_tok_eq_bare(&tok[1], "agent")) {
            if (reason) *reason = REASON_PROX_AGENT_PATH;
            return VIRP_TIER_RED;
        }
    }
    if (prox_tok_eq_bare(&tok[0], "pvesh") && ntok >= 2 &&
        prox_tok_eq_bare(&tok[1], "delete")) {
        if (reason) *reason = REASON_PROX_DESTROY;
        return VIRP_TIER_BLACK;
    }

    /* The guest-agent API subtree, for EVERY pvesh method. This is the
     * one carve-out from "get is read-only by construction" (branch
     * header): `pvesh get …/agent/get-users` executes get-users inside
     * the guest, and the same subtree's exec, file-write and
     * set-user-password would otherwise be approvable YELLOW through the
     * `pvesh create` row. Refused as a subtree because the bypass is the
     * subtree's purpose, exactly as with `qm guest`. */
    if (prox_tok_eq_bare(&tok[0], "pvesh") && ntok >= 3 &&
        prox_path_has_seg_in(&tok[2], PROX_AGENT_SEGS, 1)) {
        if (reason) *reason = REASON_PROX_AGENT_PATH;
        return VIRP_TIER_RED;
    }

    /* Host-shell and batch-dispatch endpoints — see PROX_PVESH_SHELL_SEGS.
     * `pvesh create /nodes/<n>/termproxy` is a root shell on the guest
     * running this gate, and was reachable at YELLOW. */
    if (prox_tok_eq_bare(&tok[0], "pvesh") && ntok >= 3 &&
        prox_path_has_seg_in(&tok[2], PROX_PVESH_SHELL_SEGS,
                             sizeof(PROX_PVESH_SHELL_SEGS) /
                             sizeof(PROX_PVESH_SHELL_SEGS[0]))) {
        if (reason) *reason = REASON_PROX_SHELL_PATH;
        return VIRP_TIER_RED;
    }

    /* Storage destruction. `pvesm status` is GREEN below; every other
     * pvesm verb was already RED by absence, and the destructive ones
     * are named here so the refusal is BLACK and carries a reason. */
    if (prox_tok_eq_bare(&tok[0], "pvesm") && ntok >= 2 &&
        prox_tok_in(&tok[1], PROX_STORAGE_BLACK_VERBS,
                    sizeof(PROX_STORAGE_BLACK_VERBS) /
                    sizeof(PROX_STORAGE_BLACK_VERBS[0]))) {
        if (reason) *reason = REASON_PROX_DESTROY;
        return VIRP_TIER_BLACK;
    }

    /* Backup deletion — checked across the whole argument vector, since
     * the flag's position varies and `vzdump 100 --remove 1` names it
     * after the VMID. */
    if (prox_tok_eq_bare(&tok[0], "vzdump")) {
        for (size_t i = 1; i < ntok; i++) {
            if (prox_flag_in(&tok[i], PROX_VZDUMP_BLACK_FLAGS,
                             sizeof(PROX_VZDUMP_BLACK_FLAGS) /
                             sizeof(PROX_VZDUMP_BLACK_FLAGS[0]))) {
                if (reason) *reason = REASON_PROX_BACKUP_DELETE;
                return VIRP_TIER_BLACK;
            }
        }
    }

    /* Backup hooks and redirection. Checked AFTER the BLACK loop above so
     * `vzdump 100 --script x --delete` keeps the stronger answer, and
     * across the whole vector for the same position-independence reason. */
    if (prox_tok_eq_bare(&tok[0], "vzdump")) {
        for (size_t i = 1; i < ntok; i++) {
            if (prox_flag_in(&tok[i], PROX_VZDUMP_RED_FLAGS,
                             sizeof(PROX_VZDUMP_RED_FLAGS) /
                             sizeof(PROX_VZDUMP_RED_FLAGS[0]))) {
                if (reason) *reason = REASON_PROX_VZDUMP_HOOK;
                return VIRP_TIER_RED;
            }
        }
    }

    /* 4b — GREEN reads. Each is an exact shape, not a prefix: a trailing
     * argument the table has not reasoned about drops to RED by absence
     * rather than riding a permitted verb. */
    if (ntok == 1 && prox_tok_eq_bare(&tok[0], "pveversion"))
        return VIRP_TIER_GREEN;
    if (ntok == 2 && (is_qm || is_pct) && prox_tok_eq_bare(&tok[1], "list"))
        return VIRP_TIER_GREEN;
    if (ntok == 2 && prox_tok_eq_bare(&tok[0], "pvecm") &&
        (prox_tok_eq_bare(&tok[1], "status") || prox_tok_eq_bare(&tok[1], "nodes")))
        return VIRP_TIER_GREEN;
    if (ntok == 2 && prox_tok_eq_bare(&tok[0], "pvesm") &&
        prox_tok_eq_bare(&tok[1], "status"))
        return VIRP_TIER_GREEN;
    /* `pvesm list <storage>` — the volumes on one storage. `pvesm status`
     * above answers "how full is it"; this answers "what is on it", which
     * is the question that follows it, and there is no way to reach the
     * second one through the first. The destructive pvesm verbs are BLACK
     * on their own rows above, so `list` is not riding a permissive tool:
     * every other pvesm verb is still RED by absence. */
    if (ntok == 3 && prox_tok_eq_bare(&tok[0], "pvesm") &&
        prox_tok_eq_bare(&tok[1], "list") && prox_is_storage_id(&tok[2]))
        return VIRP_TIER_GREEN;
    /* <vmid> already parsed and cleared by self-protection above. */
    if (ntok == 3 && (is_qm || is_pct) &&
        prox_tok_in(&tok[1], PROX_GUEST_GREEN_VERBS,
                    sizeof(PROX_GUEST_GREEN_VERBS) /
                    sizeof(PROX_GUEST_GREEN_VERBS[0])))
        return VIRP_TIER_GREEN;

    if (prox_tok_eq_bare(&tok[0], "pvesh") && ntok >= 2) {
        /* The API path is a structural argument, so it must be a bare
         * word: `pvesh get "/nodes/x"` reaches the device as the same
         * path, but this table reasons about path SHAPE — leading '/',
         * `agent` segments, the /access prefix — and it enumerates those
         * over bare words. A quoted path falls through to RED by
         * absence, the safe direction. (The self-protection walker above
         * still inspects it either way: a scan hunting a protected VMID
         * must not care how the path was spelled.) */
        bool path_ok = ntok >= 3 && !tok[2].quoted &&
                       tok[2].len > 0 && tok[2].p[0] == '/';

        if (prox_tok_eq_bare(&tok[1], "get") && ntok == 3 && path_ok) {
            /*
             * The access tree is a read that returns credential
             * material — user records, token ids, ACLs, realm
             * configuration. An observation body is HMAC-signed and
             * appended to a chain that cannot be trimmed, so a GREEN
             * `pvesh get /access/users` would durably commit that
             * material into the chain on the strength of it being
             * "a read". YELLOW instead: still reachable, but through
             * propose/approve/apply where a human sees what is about
             * to be signed.
             *
             * Matched as a plain "/access" prefix rather than segment-
             * wise on purpose — a hypothetical /accessfoo classifying
             * YELLOW is a stricter answer, and stricter is the side to
             * be wrong on.
             */
            if (strncmp(tok[2].p, "/access", 7) == 0 && tok[2].len >= 7)
                return VIRP_TIER_YELLOW;
            return VIRP_TIER_GREEN;
        }

        /* 4c — pvesh writes. Trailing parameters are expected here (a
         * create/set carries its arguments), so the shape is a minimum
         * rather than an exact token count. */
        if ((prox_tok_eq_bare(&tok[1], "create") || prox_tok_eq_bare(&tok[1], "set")) &&
            path_ok) {
            /* /access WRITES mint and re-grant identity: users, tokens,
             * roles, ACLs and the root password. The GET half of this
             * tree is YELLOW above for chain-hygiene reasons — the bytes
             * it RETURNS get signed into a chain that cannot be trimmed.
             * The write half is a different problem: a credential created
             * here OUTLIVES the approval that authorized it and works
             * outside VIRP entirely, so a one-time YELLOW permit buys
             * standing access. RED — still reachable, but only through
             * propose/approve/apply, where a human reads the userid
             * before it exists.
             *
             * Prefix-matched rather than segment-wise, exactly as the GET
             * row above: /accessfoo classifying stricter is the safe
             * direction to be wrong in. */
            if (tok[2].len >= 7 && strncmp(tok[2].p, "/access", 7) == 0) {
                if (reason) *reason = REASON_PROX_ACCESS_WRITE;
                return VIRP_TIER_RED;
            }
            return VIRP_TIER_YELLOW;
        }

        return VIRP_TIER_RED;   /* unlisted pvesh method — fail closed */
    }

    /* 4c (cont.) — bounded guest actions. */
    if (ntok >= 3 && (is_qm || is_pct) &&
        prox_tok_in(&tok[1], PROX_GUEST_YELLOW_VERBS,
                    sizeof(PROX_GUEST_YELLOW_VERBS) /
                    sizeof(PROX_GUEST_YELLOW_VERBS[0])))
        return VIRP_TIER_YELLOW;

    if (prox_tok_eq_bare(&tok[0], "vzdump"))
        return VIRP_TIER_YELLOW;

    return VIRP_TIER_RED;   /* unlisted Proxmox command — fail closed */
}

/* =========================================================================
 * NEVER tier (BLACK) — gate self-preservation and host destruction
 * (2026-08-12)
 *
 * POLICY CHANGE. Until now this table topped out at RED and carried an
 * invariant test saying so: RED is blocked-but-approvable, so every
 * refusal kept a propose→approve→apply escape hatch for a human. That
 * remains true for almost everything here.
 *
 * It is NOT true for the rows below. BLACK is refused by virp_onode.c
 * twice over — no proposal is ever filed (`gate_tier != VIRP_TIER_BLACK`
 * guards the propose branch) and the apply path returns
 * VIRP_ERR_TIER_VIOLATION before any signature is checked — so these
 * commands have no approval path at all, by design and on request.
 *
 * What earns BLACK is a single property: executing it would remove the
 * gate's own ability to refuse anything afterwards. An operator with an
 * enrolled approval key is exactly who this protects against, because
 * that operator can otherwise approve `systemctl stop virp-onode` and
 * the next command is ungated. A tier that a key can unlock is not a
 * defence against the holder of the key.
 *
 * The cost is real and deliberate: nobody can halt this host or stop
 * this daemon THROUGH VIRP. Both remain available on the host console
 * and over ordinary SSH — VIRP is not the only way in, and it should not
 * be the thing that decides whether the machine can be rebooted.
 *
 * ORDERING — this scan runs BEFORE the separator guard and before the
 * Proxmox raw-byte metacharacter scan. That is not a weakening of the
 * "metachars in front of all tiers" rule, which exists so no GREEN or
 * YELLOW permit can be reached through a compound string. This scan
 * issues no permits: its only possible outcomes are BLACK and
 * fall-through. Running it first strictly tightens, never loosens.
 *
 * It has to run first, too. `qm list; shutdown -h now` trips the
 * separator guard and would classify RED — approvable — and an approved
 * apply re-submits the raw bytes, separator included. Judging command
 * positions across separators before the guard closes that hole: the
 * segment after the `;` is judged on its own merits.
 *
 * A "command position" is the start of the string or the first token
 * after a `;`, `|` or `&`. Position matters because the same word is
 * innocent elsewhere: `reboot` at a command position halts this host,
 * while `qm reboot 100` reboots a guest and is an ordinary YELLOW
 * action. Matching the bare word anywhere would have collapsed the two.
 *
 * Path spellings are folded to their basename — `/sbin/shutdown` is
 * `shutdown`. Case is matched exactly, as everywhere else in this file:
 * `SHUTDOWN` is not a spelling of `shutdown`, it is a command that does
 * not exist, and it stays RED by absence.
 * ========================================================================= */

static const char *const REASON_BLACK_HOST_HALT =
    "halts or reboots the host running this gate — never transmitted, "
    "and deliberately not approvable; use the host console";
static const char *const REASON_BLACK_GATE_SERVICE =
    "stops or disables the VIRP gate daemon — a gate that can be asked "
    "to switch itself off is not a gate; never transmitted, not approvable";

/* Host-halting commands, judged at a command position only. */
static const char *const LINUX_BLACK_HALT_CMDS[] = {
    "shutdown", "poweroff", "halt", "reboot", "telinit", "init",
};
/* `systemctl <verb>` verbs that halt the host outright. */
static const char *const LINUX_BLACK_SYSTEMCTL_HOST[] = {
    "poweroff", "reboot", "halt", "kexec", "emergency", "rescue",
};
/* `systemctl <verb> <unit>` verbs that take a unit down; BLACK only when
 * the unit named is VIRP's own. */
static const char *const LINUX_BLACK_SYSTEMCTL_UNIT[] = {
    "stop", "disable", "mask", "kill", "restart", "reload-or-restart",
};
/* Signal-senders that can take the daemon down without systemd. */
static const char *const LINUX_BLACK_KILLERS[] = {
    "pkill", "killall",
};

/* Fold a token to its basename: `/sbin/shutdown` -> `shutdown`. */
static prox_tok_t linux_tok_basename(const prox_tok_t *t)
{
    prox_tok_t out = *t;
    for (size_t i = 0; i < t->len; i++) {
        if (t->p[i] == '/') {
            out.p   = t->p + i + 1;
            out.len = t->len - (i + 1);
        }
    }
    return out;
}

/* Does this token name a VIRP unit/process? Substring, not exact:
 * `virp-onode`, `virp-onode.service` and `virp-onode@1` are all the same
 * target, and over-matching here only ever adds BLACK. */
/*
 * Shell quoting bytes — the ones the remote shell REMOVES before the
 * command runs, so the never-class scanner must ignore them too.
 *
 * `"shutdown" -h now`, `'shutdown' -h now`, `\shutdown -h now` and
 * `/sbin/"shutdown"` all execute shutdown. Judged byte-for-byte, none of
 * them matched the halt row, and the never-class command fell through to
 * RED — which is APPROVABLE. An enrolled key could then unlock the one
 * thing BLACK exists to keep locked, which is the entire point of the
 * tier. Same defect the Proxmox tokenizer fixed by stripping quotes
 * before denylist matching; this is that rule for the scanner running
 * ahead of it.
 *
 * Backslash is included alongside the quote characters. It is a
 * different shell mechanism, but it removes bytes the same way and
 * leaving it open while closing quotes would just relocate the bypass.
 */
static bool linux_black_is_shell_quote(char c)
{
    return c == '"' || c == '\'' || c == '\\';
}

/*
 * Compare a raw-scanner token to an enumerated word, ignoring quoting
 * bytes.
 *
 * STREAMING on purpose. The segment scanner below deliberately carries
 * flags rather than a token buffer, because a fixed buffer would have to
 * decide what to do when a token overruns it and every answer is wrong
 * (see the black_seg_t header). Normalizing into a scratch buffer here
 * would reintroduce exactly that bound, so this walks both strings at
 * once and allocates nothing.
 */
static bool linux_black_word_eq(const prox_tok_t *t, const char *word)
{
    size_t wi = 0;
    for (size_t i = 0; i < t->len; i++) {
        char c = t->p[i];
        if (linux_black_is_shell_quote(c)) continue;
        if (word[wi] == '\0' || c != word[wi]) return false;
        wi++;
    }
    return word[wi] == '\0';
}

static bool linux_black_word_in(const prox_tok_t *t,
                                const char *const *set, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (linux_black_word_eq(t, set[i])) return true;
    return false;
}

static bool linux_tok_names_virp(const prox_tok_t *t)
{
    /* Substring, skipping quoting bytes, so `"virp-onode"` and
     * `v\irp-onode` still name the unit. Over-matching here only ever
     * adds BLACK, exactly as before. */
    static const char V[] = "virp";
    size_t m = 0;
    for (size_t i = 0; i < t->len; i++) {
        char c = t->p[i];
        if (linux_black_is_shell_quote(c)) continue;
        if (c == V[m]) {
            if (++m == 4) return true;
        } else {
            m = (c == V[0]) ? 1 : 0;
        }
    }
    return false;
}

/*
 * Accumulated judgement of ONE command segment.
 *
 * Deliberately STREAMING rather than tokenize-then-inspect. A fixed
 * token buffer would have to decide what to do when a segment overruns
 * it, and every answer is wrong: dropping the tail means
 * `systemctl stop <64 filler args> virp-onode` loses the `virp` token
 * and falls back to approvable RED, which is a never-class command
 * escaping through an array bound. Carrying flags instead means there is
 * no bound to overrun and no argument vector long enough to launder a
 * takedown.
 */
typedef struct {
    bool   have_cmd;
    bool   halt_cmd;            /* first word halts the host */
    bool   is_systemctl;
    bool   is_killer;
    bool   systemctl_host_verb; /* `systemctl poweroff` — no unit needed */
    bool   takedown_verb;       /* stop/disable/mask/kill/restart */
    bool   names_virp;          /* some argument names a VIRP unit */
} black_seg_t;

static void linux_black_seg_reset(black_seg_t *s)
{
    memset(s, 0, sizeof(*s));
}

static void linux_black_seg_token(black_seg_t *s, const prox_tok_t *t)
{
    if (!s->have_cmd) {
        /* First token of the segment — the command position. */
        prox_tok_t cmd = linux_tok_basename(t);
        s->have_cmd = true;
        s->halt_cmd = linux_black_word_in(&cmd, LINUX_BLACK_HALT_CMDS,
                                  sizeof(LINUX_BLACK_HALT_CMDS) /
                                  sizeof(LINUX_BLACK_HALT_CMDS[0]));
        s->is_systemctl = linux_black_word_eq(&cmd, "systemctl");
        s->is_killer = linux_black_word_in(&cmd, LINUX_BLACK_KILLERS,
                                   sizeof(LINUX_BLACK_KILLERS) /
                                   sizeof(LINUX_BLACK_KILLERS[0]));
        return;
    }

    /* Argument positions. The verb and the unit may be separated by
     * flags, so both are looked for anywhere in the segment rather than
     * at fixed offsets. */
    if (s->is_systemctl) {
        if (linux_black_word_in(t, LINUX_BLACK_SYSTEMCTL_HOST,
                        sizeof(LINUX_BLACK_SYSTEMCTL_HOST) /
                        sizeof(LINUX_BLACK_SYSTEMCTL_HOST[0])))
            s->systemctl_host_verb = true;
        if (linux_black_word_in(t, LINUX_BLACK_SYSTEMCTL_UNIT,
                        sizeof(LINUX_BLACK_SYSTEMCTL_UNIT) /
                        sizeof(LINUX_BLACK_SYSTEMCTL_UNIT[0])))
            s->takedown_verb = true;
    }
    if (linux_tok_names_virp(t))
        s->names_virp = true;
}

/* Decide the accumulated segment. */
static bool linux_black_seg_verdict(const black_seg_t *s, const char **reason)
{
    if (!s->have_cmd) return false;

    if (s->halt_cmd || (s->is_systemctl && s->systemctl_host_verb)) {
        if (reason) *reason = REASON_BLACK_HOST_HALT;
        return true;
    }
    /* `systemctl restart frr` keeps its existing RED — the unit has to
     * be VIRP's own for the takedown row to fire. */
    if (s->is_systemctl && s->takedown_verb && s->names_virp) {
        if (reason) *reason = REASON_BLACK_GATE_SERVICE;
        return true;
    }
    if (s->is_killer && s->names_virp) {
        if (reason) *reason = REASON_BLACK_GATE_SERVICE;
        return true;
    }
    return false;
}

/*
 * Walk the RAW request bytes as a sequence of separator-delimited
 * segments and judge each one. Returns true (with `reason` set) if any
 * segment is a never-tier command.
 */
static bool linux_black_self_harm(const char *raw, const char **reason)
{
    black_seg_t seg;
    linux_black_seg_reset(&seg);
    const char *p = raw;

    for (;;) {
        if (*p == '\0' || *p == ';' || *p == '|' || *p == '&') {
            if (linux_black_seg_verdict(&seg, reason)) return true;
            if (*p == '\0') return false;
            linux_black_seg_reset(&seg);
            p++;
            continue;
        }
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') { p++; continue; }

        const char *start = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r' &&
               *p != ';' && *p != '|' && *p != '&')
            p++;
        /* The never-class scanner runs on RAW bytes and does its own
         * whitespace splitting; it has no quote handling and needs none
         * (it only ever adds BLACK, and substring-matches `virp`). */
        prox_tok_t t = { start, (size_t)(p - start), false };
        linux_black_seg_token(&seg, &t);
    }
}

/*
 * Core classification. `reason` (optional) receives a static string for
 * rows that carry an instructive rejection reason, NULL otherwise.
 * Non-static: exercised directly by tests/test_driver_linux_gate.c.
 */
virp_trust_tier_t linux_gate_classify(const char *command, const char **reason)
{
    if (reason) *reason = NULL;
    if (!command) return VIRP_TIER_RED;

    /* Guard 0 — NEVER tier. Runs ahead of the separator guard on
     * purpose (see the BLACK section header): it issues no permits, so
     * running it first can only tighten, and it is the only thing that
     * judges the segment AFTER a separator rather than refusing the
     * whole string as an approvable RED. */
    if (linux_black_self_harm(command, reason))
        return VIRP_TIER_BLACK;

    /* Guard 1 — separator policy on the RAW string: ; | & ` $( ${ and
     * control bytes (newlines) are refused everywhere, even inside the
     * quoted vtysh argument. */
    if (virp_command_check_separators(command, NULL, 0) != 0) {
        if (reason) *reason = REASON_SEPARATOR;
        return VIRP_TIER_RED;
    }

    char canon[LINUX_GATE_CANON_MAX];
    if (linux_gate_canon(command, canon, sizeof(canon)) < 0)
        return VIRP_TIER_RED;
    if (canon[0] == '\0')
        return VIRP_TIER_RED;

    if (tok_prefix(canon, "vtysh")) {
        /* Guard 2 — two or more -c flags: RED always. */
        int c_flags = 0;
        for (const char *p = canon; *p; p++) {
            if (p[0] == '-' && p[1] == 'c' &&
                (p == canon || p[-1] == ' ') &&
                (p[2] == '\0' || p[2] == ' '))
                c_flags++;
        }
        if (c_flags >= 2) {
            if (reason) *reason = REASON_MULTI_C;
            return VIRP_TIER_RED;
        }

        /* Guard 2 (cont.) — anchored form: exactly `vtysh -c "<arg>"`.
         * Anything else (env prefix, missing quotes, trailing bytes,
         * a second quote inside the argument) is RED. Note an env-var
         * prefix like `FOO=x vtysh …` never reaches this branch: the
         * canon then starts with "foo=x", not "vtysh", and falls through
         * to the bare-shell rows below — RED by absence. */
        static const char SCAFFOLD[] = "vtysh -c \"";
        if (strncmp(canon, SCAFFOLD, sizeof(SCAFFOLD) - 1) != 0) {
            if (reason) *reason = REASON_VTYSH_FORM;
            return VIRP_TIER_RED;
        }
        const char *arg = canon + sizeof(SCAFFOLD) - 1;
        const char *close = strchr(arg, '"');
        if (!close || close == arg || close[1] != '\0') {
            if (reason) *reason = REASON_VTYSH_FORM;
            return VIRP_TIER_RED;
        }

        char vcmd[LINUX_GATE_CANON_MAX];
        size_t vlen = (size_t)(close - arg);
        if (vlen >= sizeof(vcmd)) return VIRP_TIER_RED;
        memcpy(vcmd, arg, vlen);
        vcmd[vlen] = '\0';

        /* RED teaching rows before anything else. */
        if (tok_prefix(vcmd, "configure")) {
            if (reason) *reason = REASON_CONFIG;
            return VIRP_TIER_RED;
        }
        if (tok_prefix(vcmd, "clear ip ospf process")) {
            if (reason) *reason = REASON_OSPF_PROCESS;
            return VIRP_TIER_RED;
        }

        /* YELLOW — config-visibility reads (2026-08-11): FRR's
         * running-config (and startup-config) carries credential
         * material inline (OSPF message-digest keys, BGP neighbor
         * passwords, key-chain key-strings). Because vtysh resolves
         * command prefixes, `show run` and `show start` execute as
         * the full config reads — so ANY show argument that could
         * resolve to running-config or startup-config is trapped
         * here, before the generic GREEN show row. `show` itself
         * must still be the full spelled-out token. */
        if (tok_prefix(vcmd, "show")) {
            const char *arg = tok_rest(vcmd, "show");
            if ((word_prefixes(arg, "running-config") ||
                 word_prefixes(arg, "startup-config")) &&
                rest_charset_ok(arg))
                return VIRP_TIER_YELLOW;
        }

        /* GREEN — reads. "show" must be the full spelled-out token:
         * "sh ip os nei" is not expanded and falls through RED. */
        if (tok_prefix(vcmd, "show") &&
            rest_charset_ok(tok_rest(vcmd, "show")))
            return VIRP_TIER_GREEN;

        /* YELLOW — bounded operational actions. */
        if (tok_prefix(vcmd, "clear ip ospf interface") &&
            rest_charset_ok(tok_rest(vcmd, "clear ip ospf interface")))
            return VIRP_TIER_YELLOW;
        if (tok_prefix(vcmd, "clear ip ospf neighbor") &&
            rest_charset_ok(tok_rest(vcmd, "clear ip ospf neighbor")))
            return VIRP_TIER_YELLOW;
        if (tok_prefix(vcmd, "ping") &&
            rest_charset_ok(tok_rest(vcmd, "ping")))
            return VIRP_TIER_YELLOW;
        if (tok_prefix(vcmd, "traceroute") &&
            rest_charset_ok(tok_rest(vcmd, "traceroute")))
            return VIRP_TIER_YELLOW;

        return VIRP_TIER_RED;   /* unlisted vtysh command — fail closed */
    }

    /* Proxmox VE rows — entered only when the first word is one of the
     * enumerated Proxmox tools, so no FRR or bare-shell command reaches
     * this table. Every path out of it returns; nothing falls through to
     * the rows below. */
    if (linux_prox_is_tool(canon))
        return linux_prox_classify(command, canon, reason);

    /* Peer-health reads — exact match, checked before the bare-shell RED
     * rows so an enumerated peer probe classifies GREEN while every
     * neighbouring spelling of it stays RED by absence. */
    if (is_peer_green_exact(canon))
        return VIRP_TIER_GREEN;

    /* Host-health reads — same exact-match discipline, same position in
     * the order, for the same reason. */
    if (is_host_green_exact(canon))
        return VIRP_TIER_GREEN;

    /* Bare shell. Everything is RED; these two rows carry teaching
     * reasons instead of the generic unclassified rejection. */
    if (strstr(canon, "/etc/frr/") && is_mutating_tool(canon)) {
        if (reason) *reason = REASON_FRR_FILES;
        return VIRP_TIER_RED;
    }
    if (first_tok_is(canon, "systemctl") && has_frr_token(canon)) {
        if (reason) *reason = REASON_FRR_SERVICE;
        return VIRP_TIER_RED;
    }

    return VIRP_TIER_RED;
}

/* route_command hook — tier only. */
virp_trust_tier_t linux_gate_tier(const char *command)
{
    return linux_gate_classify(command, NULL);
}

/* route_reason hook — static instructive string, or NULL for rows that
 * take the daemon's generic rejection message. */
/* =========================================================================
 * Credential scrub for FRR config reads (2026-08-11)
 *
 * FRR's running-config (and startup-config) carries credential
 * material inline: `password`, `enable password`, `neighbor <ip>
 * password`, `ip ospf message-digest-key <n> md5`, key-chain
 * `key-string`, `ip ospf authentication-key`. Observation bodies are
 * HMAC-signed and appended to a chain that cannot be trimmed, so the
 * scrub runs INSIDE the driver, on the reply body, BEFORE the result
 * is handed to the signer — never after.
 *
 * Same shape and contract as cisco_scrub_config: a pure function
 * over the reply text, exposed (non-static) so tests can drive it
 * with recorded config shapes, fail-closed — if the scrub cannot
 * complete (output would not fit), the caller reports a typed ERROR
 * instead of signing an unscrubbed or truncated body.
 *
 * Redaction model (keyword-anchored, deliberately over-broad —
 * over-redaction is the fail-closed direction): a line whose token
 * stream contains one of the secret-bearing keywords (password, md5,
 * key-string, authentication-key) has everything AFTER that keyword
 * replaced with "<removed>". Exact-token matching keeps non-secret
 * lines untouched: `ip ospf authentication message-digest` carries
 * no value and is preserved verbatim.
 * ========================================================================= */

#define LINUX_SCRUB_MARK "<removed>"

static bool linux_scrub_tok_eq(const char *tok, size_t len,
                               const char *word)
{
    return strlen(word) == len && strncmp(tok, word, len) == 0;
}

static bool linux_scrub_emit(char *out, size_t cap, size_t *pos,
                             const char *src, size_t n)
{
    if (*pos + n >= cap) return false;
    memcpy(out + *pos, src, n);
    *pos += n;
    return true;
}

/* Scrub one line [line, line+len) (terminator excluded) into out.
 * Returns false only on output overflow. */
static bool linux_scrub_line(const char *line, size_t len,
                             char *out, size_t cap, size_t *pos)
{
    static const char *const SECRET_KEYWORDS[] = {
        "password", "md5", "key-string", "authentication-key",
    };
    static const size_t SECRET_KEYWORD_COUNT =
        sizeof(SECRET_KEYWORDS) / sizeof(SECRET_KEYWORDS[0]);

    size_t i = 0;
    size_t cut = 0;              /* redact from here (0 = no redaction) */

    while (i < len && cut == 0) {
        while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && line[i] != ' ' && line[i] != '\t') i++;
        const char *tok = line + start;
        size_t tlen = i - start;

        for (size_t k = 0; k < SECRET_KEYWORD_COUNT; k++) {
            if (linux_scrub_tok_eq(tok, tlen, SECRET_KEYWORDS[k])) {
                size_t j = i;
                while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
                if (j < len) cut = j;   /* keyword with a value */
                break;
            }
        }
    }

    if (cut == 0)
        return linux_scrub_emit(out, cap, pos, line, len);

    return linux_scrub_emit(out, cap, pos, line, cut) &&
           linux_scrub_emit(out, cap, pos, LINUX_SCRUB_MARK,
                            strlen(LINUX_SCRUB_MARK));
}

/*
 * Pure scrub: rewrite FRR config text so no credential material
 * survives. Fail-closed: VIRP_ERR_BUFFER_TOO_SMALL means the caller
 * must NOT use (or sign) any partial output.
 */
virp_error_t linux_scrub_config(const char *in, size_t in_len,
                                char *out, size_t out_cap,
                                size_t *out_len)
{
    if (!in || !out || !out_len) return VIRP_ERR_NULL_PTR;
    *out_len = 0;

    size_t pos = 0;
    size_t i = 0;
    while (i < in_len) {
        size_t start = i;
        while (i < in_len && in[i] != '\n') i++;
        size_t line_end = i;                    /* excl. terminator */
        size_t content_end = line_end;
        if (content_end > start && in[content_end - 1] == '\r')
            content_end--;                      /* keep \r with the terminator */

        if (!linux_scrub_line(in + start, content_end - start,
                              out, out_cap, &pos))
            return VIRP_ERR_BUFFER_TOO_SMALL;
        /* terminator bytes verbatim (\r\n, \n, or none at EOF) */
        if (!linux_scrub_emit(out, out_cap, &pos, in + content_end,
                              (line_end - content_end) +
                              ((i < in_len) ? 1 : 0)))
            return VIRP_ERR_BUFFER_TOO_SMALL;
        if (i < in_len) i++;                    /* past the \n */
    }

    out[pos] = '\0';
    *out_len = pos;
    return VIRP_OK;
}

/*
 * Scrub a completed exec result in place (Item 5 hardening,
 * 2026-08-11): the scrub can GROW the body (each redaction can add
 * bytes), so a reply that fit result->output pre-scrub can exceed it
 * post-scrub. A grown body that no longer fits is WITHHELD typed
 * (VIRP_ERR_BUFFER_TOO_SMALL, output zeroed) — never clamped and
 * handed back, which the O-Node would sign as complete with
 * truncated=no. Exposed (non-static) for the unit suite.
 */
virp_error_t linux_scrub_result(virp_exec_result_t *result)
{
    if (!result) return VIRP_ERR_NULL_PTR;

    size_t cap = 3 * result->output_len + 64;
    char *scrubbed = malloc(cap);
    size_t scrubbed_len = 0;
    virp_error_t serr = scrubbed
        ? linux_scrub_config(result->output, result->output_len,
                             scrubbed, cap, &scrubbed_len)
        : VIRP_ERR_BUFFER_TOO_SMALL;
    if (serr == VIRP_OK && scrubbed_len >= sizeof(result->output))
        serr = VIRP_ERR_BUFFER_TOO_SMALL;   /* grown past the cap */
    if (serr != VIRP_OK) {
        free(scrubbed);
        result->success = false;
        result->output[0] = '\0';
        result->output_len = 0;
        return serr;
    }
    memcpy(result->output, scrubbed, scrubbed_len);
    result->output[scrubbed_len] = '\0';
    result->output_len = scrubbed_len;
    free(scrubbed);
    return VIRP_OK;
}

/*
 * Commands whose reply embeds FRR configuration (and therefore
 * credential material). Casts the same net as the gate's YELLOW
 * config-read row: `vtysh -c "show <arg> …"` where <arg> could
 * resolve, via vtysh prefix expansion, to running-config or
 * startup-config. Malformed or out-of-charset forms never pass the
 * gate, so returning false for them cannot leak an executed body.
 */
bool linux_command_returns_config(const char *command)
{
    if (!command) return false;

    char canon[LINUX_GATE_CANON_MAX];
    if (linux_gate_canon(command, canon, sizeof(canon)) < 0)
        return false;   /* over-long: RED at the gate, never executes */

    static const char SCAFFOLD[] = "vtysh -c \"";
    if (strncmp(canon, SCAFFOLD, sizeof(SCAFFOLD) - 1) != 0)
        return false;
    const char *arg = canon + sizeof(SCAFFOLD) - 1;
    const char *close = strchr(arg, '"');
    if (!close || close == arg || close[1] != '\0')
        return false;   /* malformed: RED at the gate */

    char vcmd[LINUX_GATE_CANON_MAX];
    size_t vlen = (size_t)(close - arg);
    if (vlen >= sizeof(vcmd)) return false;
    memcpy(vcmd, arg, vlen);
    vcmd[vlen] = '\0';

    if (!tok_prefix(vcmd, "show")) return false;
    const char *rest = tok_rest(vcmd, "show");
    return word_prefixes(rest, "running-config") ||
           word_prefixes(rest, "startup-config");
}

const char *linux_gate_reason(const char *command)
{
    const char *reason = NULL;
    (void)linux_gate_classify(command, &reason);
    return reason;
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
    .route_command = linux_gate_tier,
    .route_reason  = linux_gate_reason,
};

/* Proxmox is Debian Linux — same driver, different vendor enum */
static virp_driver_t proxmox_driver = {
    .name       = "proxmox",
    .vendor     = VIRP_VENDOR_PROXMOX,
    .connect    = linux_connect,
    .execute    = linux_execute,
    .disconnect = linux_disconnect,
    .detect     = linux_detect,
    .health_check = linux_health_check,
    /* A driver with no route_command classifies EVERY command
     * UNCLASSIFIED (gate_classify falls back to UNCLASSIFIED when the hook
     * is NULL). This vtable was missing the classifier, so a device with
     * vendor "proxmox" got UNCLASSIFIED for everything — fail-closed under
     * ENFORCE (total lockout), but fail-OPEN under any per-driver SHADOW
     * override (every command, destructive included, "would-block" then
     * runs). The Proxmox verbs (qm/pct/pvesh/pvesm) are exactly what
     * linux_gate_tier classifies, so wire proxmox to the SAME classifier
     * and reason hook the linux vendor uses. (linux_execute already
     * carries the mode-independent BLACK backstop for both vendors.) */
    .route_command = linux_gate_tier,
    .route_reason  = linux_gate_reason,
};

void virp_driver_linux_init(void)
{
    virp_driver_register(&linux_driver);
    virp_driver_register(&proxmox_driver);
}
