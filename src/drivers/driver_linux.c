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
#include <openssl/crypto.h>
#include "virp_ssh_hostkey.h"

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

static int tcp_connect(const char *host, uint16_t port)
{
    struct addrinfo hints, *res, *p;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
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

/*
 * Core classification. `reason` (optional) receives a static string for
 * rows that carry an instructive rejection reason, NULL otherwise.
 * Non-static: exercised directly by tests/test_driver_linux_gate.c.
 */
virp_trust_tier_t linux_gate_classify(const char *command, const char **reason)
{
    if (reason) *reason = NULL;
    if (!command) return VIRP_TIER_RED;

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

    /* Peer-health reads — exact match, checked before the bare-shell RED
     * rows so an enumerated peer probe classifies GREEN while every
     * neighbouring spelling of it stays RED by absence. */
    if (is_peer_green_exact(canon))
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
};

void virp_driver_linux_init(void)
{
    virp_driver_register(&linux_driver);
    virp_driver_register(&proxmox_driver);
}
