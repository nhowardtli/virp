/*
 * driver_panos.c — PAN-OS device driver implementation
 *
 * SSH-only driver for Palo Alto Networks firewalls (PA-series, VM-series).
 * Uses interactive SSH shell with plain-text CLI output.
 *
 * Implements the five virp_driver_t functions:
 *   connect     — Establish SSH session (transport only; no shell reads)
 *   execute     — Send command, read until prompt, scrub output
 *   disconnect  — Tear down SSH session
 *   detect      — Run 'show system info' and look for PAN-OS markers
 *   health_check — Verify device is responsive via 'show clock'
 *
 * Key design decisions:
 *   - SSH only. PAN-OS XML API is available but CLI is simpler for VIRP.
 *   - Interactive shell (like Cisco driver), NOT exec channels.
 *   - Prompt: username@hostname> (op mode) or username@hostname# (config).
 *   - Banner settle, strict prompt learn and "set cli pager off" are
 *     DEFERRED out of connect (pa_ensure_session_ready_locked): they run
 *     on the keepalive thread or under the first caller's exec mutex,
 *     never on the watchdog thread. No command executes before the
 *     two-probe learn has confirmed a prompt.
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
#include "virp_ssh_io.h"
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
#include <poll.h>
#include <pthread.h>
#include <libssh2.h>
#include <openssl/crypto.h>
#include "virp_ssh_hostkey.h"

/* =========================================================================
 * Constants
 * ========================================================================= */

#define PA_SSH_READ_TIMEOUT_MS     15000   /* 15 seconds — normal commands */
#define PA_SSH_LONG_TIMEOUT_MS     120000  /* 120 seconds — commit/load/save */
#define PA_SSH_CONNECT_TIMEOUT_SEC 10
#define PA_SSH_READ_BUF_SIZE       32768
#define PA_SSH_MAX_PROMPT_LEN      128
#define PA_KEEPALIVE_INTERVAL_SEC  55      /* Keepalive every 55s (PA-850 idles at ~5 min) */
#define PA_KEEPALIVE_READ_TIMEOUT_MS 5000  /* Prompt must return within 5s */

/* =========================================================================
 * Command Routing Table — maps CLI commands to VIRP trust tiers
 *
 * Prefix-matched against incoming commands. First match wins.
 * FAIL-CLOSED: unmatched commands default to RED (they used to
 * default YELLOW, which cleared the gate).
 * ========================================================================= */

const pa_command_route_t PA_ROUTE_TABLE[] = {
    /* GREEN TIER — passive read-only monitoring */
    { "show system info",                   VIRP_TIER_GREEN, false },
    { "show system state",                  VIRP_TIER_GREEN, false },
    { "show system resources",              VIRP_TIER_GREEN, false },
    { "show system environmentals",         VIRP_TIER_GREEN, false },
    { "show system software",              VIRP_TIER_GREEN, false },
    { "show system disk-space",             VIRP_TIER_GREEN, false },
    { "show interface all",                 VIRP_TIER_GREEN, false },
    { "show interface ethernet",            VIRP_TIER_GREEN, true },
    { "show interface loopback",            VIRP_TIER_GREEN, true },
    { "show interface tunnel",              VIRP_TIER_GREEN, true },
    { "show interface vlan",                VIRP_TIER_GREEN, true },
    { "show interface aggregate-ethernet",  VIRP_TIER_GREEN, true },
    { "show session info",                  VIRP_TIER_GREEN, false },
    { "show session all",                   VIRP_TIER_GREEN, false },
    { "show session id",                    VIRP_TIER_GREEN, false },
    { "show session meter",                 VIRP_TIER_GREEN, false },
    { "show high-availability state",       VIRP_TIER_GREEN, false },
    { "show high-availability all",         VIRP_TIER_GREEN, false },
    { "show high-availability",             VIRP_TIER_GREEN, false },
    { "show arp all",                       VIRP_TIER_GREEN, false },
    { "show arp",                           VIRP_TIER_GREEN, false },
    { "show routing route",                 VIRP_TIER_GREEN, false },
    { "show routing summary",              VIRP_TIER_GREEN, false },
    { "show routing protocol",              VIRP_TIER_GREEN, false },
    { "show routing",                       VIRP_TIER_GREEN, false },
    { "show clock",                         VIRP_TIER_GREEN, false },
    { "show counter global",               VIRP_TIER_GREEN, false },
    { "show counter interface",             VIRP_TIER_GREEN, false },
    { "show counter",                       VIRP_TIER_GREEN, false },
    { "show jobs all",                      VIRP_TIER_GREEN, false },
    { "show jobs",                          VIRP_TIER_GREEN, false },
    { "show mac all",                       VIRP_TIER_GREEN, false },
    { "show neighbor",                      VIRP_TIER_GREEN, false },
    { "show ntp",                           VIRP_TIER_GREEN, false },
    { "show zone",                          VIRP_TIER_GREEN, false },
    { "show vpn ipsec-sa",                  VIRP_TIER_GREEN, false },
    { "show vpn ike-sa",                    VIRP_TIER_GREEN, false },
    { "show vpn flow",                      VIRP_TIER_GREEN, false },
    { "show vpn",                           VIRP_TIER_GREEN, false },
    { "show dns-proxy cache",              VIRP_TIER_GREEN, false },
    { "show dhcp server",                   VIRP_TIER_GREEN, false },
    { "show global-protect-gateway",        VIRP_TIER_GREEN, false },
    { "show log system",                    VIRP_TIER_GREEN, false },
    { "show log traffic",                   VIRP_TIER_GREEN, false },
    { "show log threat",                    VIRP_TIER_GREEN, false },
    { "show log",                           VIRP_TIER_GREEN, false },

    /* YELLOW TIER — configuration reads, active diagnostics */
    { "show running security-policy",       VIRP_TIER_YELLOW, false },
    { "show running nat-policy",            VIRP_TIER_YELLOW, false },
    { "show running qos-policy",            VIRP_TIER_YELLOW, false },
    { "show running",                       VIRP_TIER_YELLOW, false },
    { "show config",                        VIRP_TIER_YELLOW, false },
    /* 2026-08-27: the broad verbs `debug`, `test`, `less` and `tail`
     * are OUT of YELLOW. Their safe subsets were never enumerated —
     * `debug` reaches process restarts (debug software restart
     * process), `less`/`tail` read arbitrary on-box log files — and
     * "we have not enumerated what's safe" is RED by the tier
     * definitions (blocked, approvable), which is where their commands
     * now fall by absence. Only COMPLETE, known-safe `test` forms are
     * listed, per the PAN-OS CLI reference (Test the Configuration /
     * Test Policy Matches; policy-match simulators and FIB lookups are
     * read-only evaluations of candidate traffic): */
    { "test security-policy-match",         VIRP_TIER_YELLOW, false },
    { "test nat-policy-match",              VIRP_TIER_YELLOW, false },
    { "test pbf-policy-match",              VIRP_TIER_YELLOW, false },
    { "test decryption-policy-match",       VIRP_TIER_YELLOW, false },
    { "test routing fib-lookup",            VIRP_TIER_YELLOW, false },
    { "ping",                               VIRP_TIER_YELLOW, false },
    { "traceroute",                         VIRP_TIER_YELLOW, false },
    /* Operational/topology reads — NOT credential-exposing; YELLOW to
     * match the config-read precedent. show panorama-status reveals the
     * Panorama mgmt IP + connection state; show device-group reveals
     * group membership / pushed config. (No earlier entry word-boundary-
     * matches these, so placement here is order-safe for first-match.) */
    { "show device-group",                  VIRP_TIER_YELLOW, false },
    { "show panorama-status",               VIRP_TIER_YELLOW, false },

    /* RED TIER — credential-exposing reads only */
    { "show admins",                        VIRP_TIER_RED, false },
    { "show user ip-user-mapping",          VIRP_TIER_RED, false },
    { "show user group",                    VIRP_TIER_RED, false },
    { "show user",                          VIRP_TIER_RED, false },
    { "show certificate",                   VIRP_TIER_RED, false },
    { "request password-hash",              VIRP_TIER_RED, false },
};

const size_t PA_ROUTE_TABLE_SIZE =
    sizeof(PA_ROUTE_TABLE) / sizeof(PA_ROUTE_TABLE[0]);

/* =========================================================================
 * BLACK Tier — Destructive commands that must never reach the wire.
 *
 * Prefix-matched, CASE-INSENSITIVE, same structure and rationale as
 * CISCO_BLACK_COMMANDS / FG_BLACK_COMMANDS: this is a DENY list, and
 * over-matching a deny list is the fail-closed direction ("COMMIT"
 * stays BLACK, never RED-by-absence where the propose/approve path
 * could in principle reach it). Nothing matched here ever executes.
 *
 * Entries derived from the PAN-OS CLI reference (PAN-OS CLI Quick
 * Start: Modify the Configuration / Test the Configuration; PAN-OS
 * op-mode `request` and `delete` families; scp/tftp import per "CLI
 * Commands to Export/Import Configuration and Log Files"):
 *
 *   commit                            — apply the candidate config
 *   load                              — stage a config / device-state
 *                                       replacement (load config from,
 *                                       load config partial, ...)
 *   scp import / tftp import          — pull config/software/certs
 *                                       onto the box (there is no bare
 *                                       `import` verb in PAN-OS)
 *   delete                            — op- and config-mode deletion:
 *                                       delete config saved, delete
 *                                       certificate, key material
 *                                       (ASA precedent: bare `delete`
 *                                       is BLACK there too)
 *   request restart system            — reboot
 *   request shutdown system           — power off
 *   request system private-data-reset — wipe logs + config to factory
 *   request system raid               — RAID membership changes
 *                                       (add/remove/copy log disks)
 * ========================================================================= */

static const char *PA_BLACK_COMMANDS[] = {
    "commit",
    "load ",
    "scp import",
    "tftp import",
    "delete",
    "request restart system",
    "request shutdown system",
    "request system private-data-reset",
    "request system raid",
};
static const size_t PA_BLACK_COUNT =
    sizeof(PA_BLACK_COMMANDS) / sizeof(PA_BLACK_COMMANDS[0]);

bool pa_is_black_tier(const char *command)
{
    if (!command) return false;
    while (*command == ' ' || *command == '\t') command++;
    for (size_t i = 0; i < PA_BLACK_COUNT; i++) {
        size_t plen = strlen(PA_BLACK_COMMANDS[i]);
        if (strncasecmp(command, PA_BLACK_COMMANDS[i], plen) == 0)
            return true;
    }
    return false;
}

/* =========================================================================
 * Command Routing — prefix match against table
 * ========================================================================= */

/*
 * Characters a prefix entry may absorb without an intervening space:
 * [A-Za-z0-9._/-]. Deliberately narrow — see pa_command_route_t.prefix.
 */
static bool pa_prefix_char_ok(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '/' || c == '-';
}

virp_trust_tier_t pa_route_command(const char *command)
{
    if (!command) return VIRP_TIER_RED;              /* fail closed */

    /*
     * Layer 3a — a separator-carrying string is not one command, so this
     * table cannot vouch for it. Fail closed to RED here as well as at
     * the daemon boundary, because pa_route_command is directly callable.
     */
    if (virp_command_check_separators(command, NULL, 0) != 0)
        return VIRP_TIER_RED;

    /* Skip leading whitespace */
    while (*command == ' ' || *command == '\t') command++;

    /*
     * BLACK deny list FIRST: unlike Cisco/FortiGate (whose classifiers
     * top out at RED and rely on their execute() backstop alone), this
     * classifier RETURNS BLACK — like ASA and JunOS — so the O-Node
     * gate refuses these commands unconditionally, in ENFORCE and
     * SHADOW alike, before any connection attempt. The execute()
     * backstop below is the second, driver-local belt.
     */
    if (pa_is_black_tier(command))
        return VIRP_TIER_BLACK;

    /*
     * First match wins here (NOT longest match) — table order is load-
     * bearing and documented at the entries. Kept as-is.
     */
    for (size_t i = 0; i < PA_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(PA_ROUTE_TABLE[i].command_pattern);
        /*
         * 2026-08-09 classified≠executed fix: CASE-SENSITIVE — the
         * driver executes the caller's original bytes, so this table
         * may not vouch for a spelling it did not literally see;
         * "SHOW SYSTEM INFO" falls through RED by absence.
         */
        if (strncmp(command, PA_ROUTE_TABLE[i].command_pattern, plen) == 0) {
            /*
             * Layer 3b — the match must END on a token boundary. '\n' was
             * previously accepted as a boundary, which WAS this driver's
             * copy of the multi-command bypass: "show system info\nreload"
             * matched the GREEN entry and returned its tier. A newline is
             * a command separator, never a token boundary. Entries ending
             * in a space carry their own boundary.
             */
            char next = command[plen];
            bool self_terminated = (plen > 0 &&
                PA_ROUTE_TABLE[i].command_pattern[plen - 1] == ' ');
            if (self_terminated ||
                next == '\0' || next == ' ' || next == '\t') {
                return PA_ROUTE_TABLE[i].tier;
            }
            /*
             * Opt-in prefix entry: the remainder may attach with no
             * space, but only over a restricted class — alphanumerics
             * plus '.', '/', '-' and '_'. That covers every PAN-OS
             * interface unit form ("ethernet1/1.100", "loopback.1",
             * "ae1") while refusing anything shell- or CLI-meaningful.
             * Separators are already impossible here: the shared policy
             * rejects them for the whole string before this point.
             */
            if (PA_ROUTE_TABLE[i].prefix && pa_prefix_char_ok(next))
                return PA_ROUTE_TABLE[i].tier;
        }
    }

    /* Fail-closed: anything not explicitly listed is RED. An unlisted
     * command used to return YELLOW, which CLEARED the default YELLOW
     * gate threshold and executed unreviewed. */
    return VIRP_TIER_RED;
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    int                 sock_fd;
    LIBSSH2_SESSION     *session;
    LIBSSH2_CHANNEL     *channel;
    virp_ssh_prompt_t   prompt;      /* learned AFTER connect — see warm-up below */
    virp_ssh_io_t       io;          /* shared read path transport adapter */
    bool                connected;
    bool                pager_disabled;
    time_t              connect_time; /* when the shell opened — bounds how
                                         long health_check may defer to a
                                         warm-up that has not reported in */

    /* Keepalive — background thread sends periodic newlines to prevent
     * PAN-OS from killing the PTY session during idle periods.
     * The session_mutex serializes all libssh2 operations (channel
     * read/write) between the keepalive thread and execute calls. */
    pthread_t           keepalive_tid;
    pthread_mutex_t     session_mutex;
    volatile bool       keepalive_running;
    bool                keepalive_started;   /* true if pthread_create succeeded */
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

/* ── Transport adapter for the shared read path ─────────────────── */

static ssize_t pa_io_read(void *ctx, char *buf, size_t len)
{
    virp_conn_t *conn = (virp_conn_t *)ctx;
    ssize_t n = libssh2_channel_read(conn->channel, buf, len);
    if (n == LIBSSH2_ERROR_EAGAIN)
        return VIRP_SSH_IO_EAGAIN;
    return n;
}

static ssize_t pa_io_write(void *ctx, const char *buf, size_t len)
{
    virp_conn_t *conn = (virp_conn_t *)ctx;
    size_t written = 0;
    while (written < len) {
        ssize_t n = libssh2_channel_write(conn->channel, buf + written,
                                          len - written);
        if (n > 0)
            written += (size_t)n;
        else if (n == LIBSSH2_ERROR_EAGAIN)
            usleep(10000);
        else
            return -1;
    }
    return (ssize_t)written;
}

/* =========================================================================
 * Session Liveness Probe
 *
 * Quick non-blocking check to detect a dead PTY session *before* we waste
 * 15 seconds waiting for a write+read timeout on a dead channel.
 *
 * Checks two layers:
 *   1. TCP socket — poll() for POLLERR/POLLHUP/POLLNVAL
 *   2. SSH channel — libssh2_channel_eof() for graceful remote close
 *
 * Returns true if the session appears alive, false if definitely dead.
 * ========================================================================= */

static bool pa_session_alive(virp_conn_t *conn)
{
    if (!conn || conn->sock_fd < 0 || !conn->channel || !conn->session)
        return false;

    /* Layer 1: TCP socket health — zero-timeout poll */
    struct pollfd pfd = { .fd = conn->sock_fd, .events = POLLIN };
    int prc = poll(&pfd, 1, 0);
    if (prc > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        fprintf(stderr, "[PAN-OS] Liveness probe: TCP socket dead (%s)\n",
                conn->device.hostname);
        return false;
    }

    /* Layer 2: SSH channel EOF — remote side closed gracefully */
    if (libssh2_channel_eof(conn->channel)) {
        fprintf(stderr, "[PAN-OS] Liveness probe: SSH channel EOF (%s)\n",
                conn->device.hostname);
        return false;
    }

    return true;
}

/* =========================================================================
 * Deferred session warm-up — learn the prompt, then disable paging
 *
 * The pa-850 takes ~13 s from shell start to first prompt while it
 * prints its login banner (observed 2026-08-09), and connect() runs on
 * the O-Node's single serial watchdog thread. So connect no longer
 * settles the banner: the session is handed back the moment the shell
 * opens, and THIS function arms the read path afterwards — normally on
 * the connection's own keepalive thread, or under the caller's exec
 * mutex if a command arrives first.
 *
 * Learning stays exactly as strict as at-connect learning was: each
 * attempt below is one unmodified virp_ssh_learn_prompt() call, and
 * acceptance still requires the same answer to two consecutive probes
 * (the 2026-07-29 R24/'R25#' cross-learn is why). What retrying adds is
 * only TIME: an attempt that lands mid-banner gets two different banner
 * lines, fails, and is re-measured after the drain has paced us past
 * the chatter. A mismatch is never accepted; it is re-asked.
 *
 * On failure the session is marked dead — a channel that cannot produce
 * a confirmable prompt inside the deadline cannot be read reliably, and
 * the watchdog rebuilds it with backoff. No command is ever dispatched
 * without a learned prompt (virp_ssh_exec refuses independently).
 *
 * Caller must hold session_mutex.
 * ========================================================================= */

#define PA_WARMUP_DEADLINE_MS 45000  /* ~3x the observed 13 s settle */

static virp_error_t pa_ensure_session_ready_locked(virp_conn_t *conn)
{
    if (conn->prompt.learned && conn->pager_disabled)
        return VIRP_OK;

    const char *host = conn->device.hostname;
    struct timespec t0, now;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long elapsed_ms = 0;
    int attempts = 0;
    bool spoken = false;

    while (!conn->prompt.learned) {
        attempts++;

        /* The drain does double duty: it clears banner/residue bytes so
         * they cannot become a probe answer, and it paces the retry
         * loop — while the banner is still streaming, the drain sits on
         * the channel until a quiescent gap instead of spinning. */
        size_t drained = virp_ssh_drain(&conn->io, host);
        spoken = spoken || drained > 0;

        virp_ssh_learn_opts_t lopts = { .channel_has_spoken = spoken };
        if (virp_ssh_learn_prompt(&conn->io, host, &lopts,
                                  &conn->prompt) == VIRP_OK)
            break;

        /* The probes themselves have now been sent; whatever the device
         * is, it has had bytes on the wire. One long silent budget per
         * warm-up, never one per attempt (mirrors the per-probe rule in
         * virp_ssh_io.h). */
        spoken = true;

        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed_ms = (now.tv_sec - t0.tv_sec) * 1000 +
                     (now.tv_nsec - t0.tv_nsec) / 1000000;
        if (elapsed_ms >= PA_WARMUP_DEADLINE_MS) {
            fprintf(stderr, "[PAN-OS] Warm-up failed: no confirmed prompt "
                    "on %s after %d attempt(s) / %ld ms — marking session "
                    "dead\n", host, attempts, elapsed_ms);
            conn->connected = false;
            return VIRP_ERR_NO_PROMPT;
        }
    }

    /* Pager off — now that the prompt is known this reads to the prompt
     * like any command, so it can leave no residue on the channel. */
    if (!conn->pager_disabled) {
        char discard[4096];
        size_t got = 0;
        virp_error_t prc = virp_ssh_exec(&conn->io, &conn->prompt,
                                         "set cli pager off",
                                         discard, sizeof(discard), &got,
                                         PA_SSH_READ_TIMEOUT_MS, host);
        if (prc != VIRP_OK) {
            fprintf(stderr, "[PAN-OS] Warm-up: pager-off got no prompt on "
                    "%s — marking session dead\n", host);
            conn->connected = false;
            return prc;
        }
        conn->pager_disabled = true;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed_ms = (now.tv_sec - t0.tv_sec) * 1000 +
                 (now.tv_nsec - t0.tv_nsec) / 1000000;
    fprintf(stderr, "[PAN-OS] Session ready: %s prompt='%s' (attempts=%d, "
            "warmup=%ld ms)\n", host, conn->prompt.prompt, attempts,
            elapsed_ms);
    return VIRP_OK;
}

/* =========================================================================
 * Keepalive Thread
 *
 * Sends a newline to the PAN-OS PTY shell every PA_KEEPALIVE_INTERVAL_SEC
 * seconds and drains the prompt echo.  This prevents the PA-850 from
 * killing the SSH session due to idle timeout (~5 minutes default).
 *
 * It is also the preferred payer of the deferred warm-up above, first
 * thing after connect — a per-connection thread can sit through the
 * banner settle without costing anyone else wall-clock.
 *
 * The session_mutex is held only during the brief write+read (and once,
 * at start, across the warm-up), so normal execute calls are not blocked
 * for more than a few milliseconds.
 * ========================================================================= */

static void *pa_keepalive_thread(void *arg)
{
    virp_conn_t *conn = (virp_conn_t *)arg;

    /* Arm the read path off the connect path: the cold-start settle is
     * paid here, not by the watchdog thread that called connect() and
     * not (usually) by the first command. If a command beats us to the
     * mutex, pa_execute runs the same warm-up and this reduces to a
     * no-op. */
    pthread_mutex_lock(&conn->session_mutex);
    if (conn->keepalive_running && conn->connected &&
        pa_ensure_session_ready_locked(conn) != VIRP_OK) {
        pthread_mutex_unlock(&conn->session_mutex);
        fprintf(stderr, "[PAN-OS] Keepalive: warm-up failed, exiting (%s)\n",
                conn->device.hostname);
        return NULL;
    }
    pthread_mutex_unlock(&conn->session_mutex);

    while (1) {
        /* Sleep in 1-second increments so we can check for shutdown quickly */
        for (int i = 0; i < PA_KEEPALIVE_INTERVAL_SEC; i++) {
            sleep(1);
            if (!conn->keepalive_running)
                return NULL;
        }

        /* Recheck after sleep */
        if (!conn->keepalive_running || !conn->connected)
            return NULL;

        pthread_mutex_lock(&conn->session_mutex);

        if (!conn->keepalive_running || !conn->connected) {
            pthread_mutex_unlock(&conn->session_mutex);
            return NULL;
        }

        /* Quick liveness check before attempting I/O */
        if (!pa_session_alive(conn)) {
            conn->connected = false;
            pthread_mutex_unlock(&conn->session_mutex);
            fprintf(stderr, "[PAN-OS] Keepalive: session dead, marking stale (%s)\n",
                    conn->device.hostname);
            return NULL;
        }

        /*
         * Keepalive is a bare newline; PAN-OS answers with the prompt.
         *
         * It runs through the SAME primitive as a command — drain, send,
         * read to the LEARNED prompt — for one reason: a quiescent read
         * is timing-based and can return before the reply lands, and the
         * old one read into a 1024-byte buffer. Either way the unread
         * tail stays on the channel, and this driver holds ONE channel
         * for the life of the connection, so that tail becomes the head
         * of the next command's read and ends up in its signed body.
         * Terminating on the prompt consumes exactly this keepalive's
         * own reply and nothing more, so the window cannot leave residue
         * behind whatever the device's timing.
         *
         * (Interleaving was never the gap: session_mutex, held here and
         * across the whole of pa_execute, already serialized the two.
         * The gap was this read window.)
         */
        char discard[VIRP_OUTPUT_MAX];
        size_t got = 0;
        virp_error_t krc = virp_ssh_exec(&conn->io, &conn->prompt, "",
                                         discard, sizeof(discard), &got,
                                         PA_KEEPALIVE_READ_TIMEOUT_MS,
                                         conn->device.hostname);
        if (krc != VIRP_OK) {
            /*
             * A keepalive that does not get its prompt back is the
             * definition of a session that can no longer be read
             * reliably. Marking it stale drops the connection so the
             * watchdog rebuilds it — the alternative, reporting OK and
             * leaving an unterminated read on the channel, is exactly
             * how the contamination started.
             */
            conn->connected = false;
            fprintf(stderr, "[PAN-OS] Keepalive: no prompt after %zu bytes "
                    "(%s) — marking stale\n", got, conn->device.hostname);
            pthread_mutex_unlock(&conn->session_mutex);
            return NULL;
        }

        fprintf(stderr, "[PAN-OS] Keepalive OK (%s)\n", conn->device.hostname);

        pthread_mutex_unlock(&conn->session_mutex);
    }
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
    conn->io.ctx = conn;
    conn->io.read = pa_io_read;
    conn->io.write = pa_io_write;
    conn->pager_disabled = false;
    conn->keepalive_running = false;
    conn->keepalive_started = false;
    pthread_mutex_init(&conn->session_mutex, NULL);

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

    /* Verify host key before authentication */
    virp_error_t hk_err = virp_ssh_verify_hostkey(conn->session,
                                                   device->host, port);
    if (hk_err != VIRP_OK) {
        fprintf(stderr, "[PAN-OS] Host key verification failed: %s\n",
                virp_error_str(hk_err));
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

    /* Configure SSH-level keepalives (belt & suspenders with our PTY keepalive thread).
     * want_reply=1 so a missing reply signals a dead connection.
     * interval=60 seconds — SSH protocol layer, independent of our application keepalive. */
    libssh2_keepalive_config(conn->session, 1, 60);

    /*
     * DEFERRED SETTLE (2026-08-09): connect reads nothing from the
     * shell. The pa-850 spends ~13 s printing its login banner before
     * the first prompt, and this function runs on the O-Node's single
     * serial watchdog thread — a settle here is wall-clock every other
     * device waits behind. The old (pre-34e57a0) driver "solved" this
     * by ignoring the settle result and connecting with an empty
     * prompt, which is no check at all; the at-connect strict learn
     * solved the check and made connect pay the settle. This splits
     * them: connect is transport-only, and the strict learn runs in
     * pa_ensure_session_ready_locked() — on the keepalive thread right
     * below, or under the first caller's exec mutex, whichever comes
     * first. Until it succeeds, no command can execute.
     */
    conn->connected = true;
    conn->connect_time = time(NULL);

    /* Start keepalive thread — its first act is the deferred warm-up
     * (banner settle + strict learn + pager-off), then it sends periodic
     * newlines so PAN-OS never kills the PTY session during idle and the
     * settle is never paid again unless the device reboots. */
    conn->keepalive_running = true;
    if (pthread_create(&conn->keepalive_tid, NULL,
                        pa_keepalive_thread, conn) == 0) {
        conn->keepalive_started = true;
        fprintf(stderr, "[PAN-OS] Keepalive thread started (interval=%ds) for %s\n",
                PA_KEEPALIVE_INTERVAL_SEC, device->hostname);
    } else {
        conn->keepalive_running = false;
        conn->keepalive_started = false;
        fprintf(stderr, "[PAN-OS] WARNING: keepalive thread failed to start for %s"
                " — warm-up falls to the first execute\n",
                device->hostname);
    }

    fprintf(stderr, "[PAN-OS] Connected: %s@%s:%u (prompt learn deferred)\n",
            device->username, device->host, port);

    return conn;
}

/* =========================================================================
 * Timeout selection — long timeout for commit/load/save/import/export
 * ========================================================================= */

static int pa_timeout_for_command(const char *command)
{
    /* Skip leading whitespace */
    while (*command == ' ') command++;

    if (strncmp(command, "commit", 6) == 0 ||
        strncmp(command, "load ", 5) == 0 ||
        strncmp(command, "save ", 5) == 0 ||
        strncmp(command, "import ", 7) == 0 ||
        strncmp(command, "export ", 7) == 0 ||
        strncmp(command, "request ", 8) == 0) {
        return PA_SSH_LONG_TIMEOUT_MS;
    }
    return PA_SSH_READ_TIMEOUT_MS;
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

    /* ── BLACK tier safety: never execute destructive commands ──
     * Placed BEFORE the connected check (driver_linux.c precedent):
     * refusing a destructive command is a policy decision independent
     * of reachability. The O-Node gate already refuses BLACK
     * unconditionally in both modes; this is the driver-local belt,
     * following the refusal contract (tests/refusal_contract.h):
     * no_dispatch + NOT_SENT, empty output (the device's voice — it
     * was never asked), reason in error_msg, VIRP_OK. */
    if (pa_is_black_tier(command)) {
        result->success = false;
        result->exit_code = 1;
        result->no_dispatch = true;   /* nothing was ever sent */
        result->disposition = VIRP_DISPOSITION_NOT_SENT;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "BLACK tier: command blocked on %s", conn->device.hostname);
        fprintf(stderr, "[PAN-OS] BLACK tier blocked: '%s' on %s\n",
                command, conn->device.hostname);
        return VIRP_OK;
    }

    if (!conn->connected) {
        result->success = false;
        result->no_dispatch = true;   /* refused before any transport write */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return VIRP_OK;
    }

    /* Lock session mutex — serializes with keepalive thread */
    pthread_mutex_lock(&conn->session_mutex);

    /* Quick liveness probe — detect dead session in <1ms instead of
     * waiting 15 seconds for a write+read timeout on a dead channel.
     * If the session died during idle, O-Node retry logic will do a
     * single fresh reconnect (~15s) instead of timeout + reconnect (~30s). */
    if (!pa_session_alive(conn)) {
        conn->connected = false;
        pthread_mutex_unlock(&conn->session_mutex);
        result->success = false;
        result->no_dispatch = true;   /* probe failed before the command was sent */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Session dead (liveness probe) on %s", conn->device.hostname);
        return VIRP_OK;
    }

    /*
     * A command may arrive before the keepalive thread has armed the
     * read path (or that thread may have failed to start). The strict
     * two-probe learn then runs here — under the caller's per-device
     * exec mutex and this session_mutex — before anything is sent.
     * virp_ssh_exec refuses an unlearned prompt independently, so this
     * cannot be skipped, only paid earlier by another thread.
     */
    if (!conn->prompt.learned || !conn->pager_disabled) {
        if (pa_ensure_session_ready_locked(conn) != VIRP_OK) {
            pthread_mutex_unlock(&conn->session_mutex);
            result->success = false;
            result->no_dispatch = true;  /* the command was never sent */
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "No confirmed prompt on %s — command refused",
                     conn->device.hostname);
            return VIRP_OK;
        }
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Read response — use longer timeout for commit/load/save/request */
    int read_timeout = pa_timeout_for_command(command);
    if (read_timeout > PA_SSH_READ_TIMEOUT_MS) {
        fprintf(stderr, "[PAN-OS] Long-running command, timeout=%ds: %s\n",
                read_timeout / 1000, command);
    }

    /* Shared read path: drain residue, send, read to the LEARNED prompt. */
    char raw_output[VIRP_OUTPUT_MAX];
    size_t n = 0;
    virp_error_t rerr = virp_ssh_exec(&conn->io, &conn->prompt, command,
                                      raw_output, sizeof(raw_output), &n,
                                      read_timeout, conn->device.hostname);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

    if (rerr == VIRP_ERR_NO_PROMPT) {
        /* Incomplete read — hard error so the O-Node emits a typed
         * ERROR observation instead of signing a truncated body. */
        conn->connected = false;
        pthread_mutex_unlock(&conn->session_mutex);
        result->success = false;
        result->output_len = 0;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Incomplete read on %s: no prompt after %zu bytes",
                 conn->device.hostname, n);
        return VIRP_ERR_NO_PROMPT;
    }
    if (rerr != VIRP_OK) {
        conn->connected = false;
        pthread_mutex_unlock(&conn->session_mutex);
        result->success = false;
        result->output_len = 0;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Transport failure on %s: %s",
                 conn->device.hostname, virp_error_str(rerr));
        return rerr;
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

    /* Strip the echoed command by matching its text, not by position. */
    char *output_start = virp_ssh_strip_echo(raw_output, command);

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

    pthread_mutex_unlock(&conn->session_mutex);
    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect
 * ========================================================================= */

static void pa_disconnect(virp_conn_t *conn)
{
    if (!conn) return;

    /* Stop keepalive thread before tearing down the SSH session.
     * Set flag first, then join — the thread checks keepalive_running
     * every second and exits promptly. */
    conn->keepalive_running = false;
    if (conn->keepalive_started) {
        pthread_join(conn->keepalive_tid, NULL);
        conn->keepalive_started = false;
        fprintf(stderr, "[PAN-OS] Keepalive thread stopped (%s)\n",
                conn->device.hostname);
    }

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

    pthread_mutex_destroy(&conn->session_mutex);

    fprintf(stderr, "[PAN-OS] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
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

/* How long health_check will defer to a warm-up that has not reported
 * in before probing the session itself (and paying the settle on the
 * watchdog thread as a last resort). Comfortably past the warm-up
 * deadline so the two never race. */
#define PA_WARMUP_GRACE_SEC 60

static virp_error_t pa_health_check(virp_conn_t *conn)
{
    if (!conn) return VIRP_ERR_NULL_PTR;
    if (!conn->connected) return PA_ERR_NOT_CONNECTED;

    /*
     * The watchdog calls this from its single serial thread on every
     * sweep. A blocking probe here would park that thread behind the
     * deferred warm-up (or a long command) for the whole settle. Busy
     * IS a health signal: a session another thread is actively driving
     * is not idle-dead, and a warm-up that ultimately fails reports as
     * connected=false on the next sweep.
     */
    int rc = pthread_mutex_trylock(&conn->session_mutex);
    if (rc == EBUSY)
        return VIRP_OK;
    if (rc != 0)
        return PA_ERR_NOT_CONNECTED;

    bool warming = !conn->prompt.learned;
    pthread_mutex_unlock(&conn->session_mutex);

    /*
     * Not armed yet and nobody holds the lock: normally the keepalive
     * thread just hasn't got there yet — give it PA_WARMUP_GRACE_SEC
     * from connect before concluding it will never come. Past the
     * grace (or if the thread never started), fall through and let the
     * execute path run the warm-up here; masking a device forever
     * behind "still warming" would turn this probe into a no-op.
     */
    if (warming && conn->keepalive_started &&
        (time(NULL) - conn->connect_time) < PA_WARMUP_GRACE_SEC)
        return VIRP_OK;

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
    .route_command = pa_route_command,
};

void virp_driver_paloalto_init(void)
{
    virp_driver_register(&pa_driver);
}
