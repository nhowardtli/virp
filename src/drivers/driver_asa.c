/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco ASA Device Driver — SSH-only, ASA-OS 9.8.x through 9.20.x
 *
 * Handles:
 *   - SSH with ASA-specific KEX (group14-sha1 for 9.8.x, group14-sha256 for 9.12+)
 *   - Enable mode entry AND re-entry (ASA drops enable after some commands)
 *   - terminal pager 0 (not terminal length 0)
 *   - Buffer flush before each command (ASA stale output quirk)
 *   - Prompt detection across user/enable/config/multi-context modes
 *   - ASA-specific error messages
 *
 * NOT for FTD (Firepower Threat Defense) — that uses FMC REST API.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_ssh_io.h"
#include "virp_driver_asa.h"
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
#include <openssl/crypto.h>
#include "virp_ssh_hostkey.h"

/* =========================================================================
 * Constants
 * ========================================================================= */

#define ASA_READ_TIMEOUT_MS     10000   /* 10 seconds per read            */
#define ASA_CONNECT_TIMEOUT_SEC 10
#define ASA_PROMPT_WAIT_MS      500
#define ASA_READ_BUF_SIZE       32768
#define ASA_MAX_PROMPT_LEN      128
#define ASA_FLUSH_TIMEOUT_MS    200     /* Brief drain for stale output   */
#define ASA_ENABLE_TIMEOUT_MS   5000    /* Timeout for enable negotiation */

/* =========================================================================
 * Command Routing Table — ASA-specific commands → trust tiers
 *
 * Prefix-matched, longest match wins. FAIL-CLOSED: unmapped commands
 * default to RED (they used to default YELLOW, which cleared the gate).
 * ========================================================================= */

const asa_command_route_t ASA_ROUTE_TABLE[] = {
    /* ── Tier 1: GREEN — Passive monitoring (no approval) ──────── */
    { "show version",               VIRP_TIER_GREEN  },
    { "show interface ip brief",    VIRP_TIER_GREEN  },
    { "show interface brief",       VIRP_TIER_GREEN  },
    { "show firewall",              VIRP_TIER_GREEN  },
    { "show failover",              VIRP_TIER_GREEN  },
    { "show conn count",            VIRP_TIER_GREEN  },
    { "show route",                 VIRP_TIER_GREEN  },
    { "show clock",                 VIRP_TIER_GREEN  },
    { "show cpu usage",             VIRP_TIER_GREEN  },
    { "show memory",                VIRP_TIER_GREEN  },
    { "show xlate count",           VIRP_TIER_GREEN  },
    { "show conn detail",           VIRP_TIER_GREEN  },
    { "show conn",                  VIRP_TIER_GREEN  },
    { "show inventory",             VIRP_TIER_GREEN  },
    { "show module",                VIRP_TIER_GREEN  },
    { "show environment",           VIRP_TIER_GREEN  },
    { "show process",               VIRP_TIER_GREEN  },
    { "show nameif",                VIRP_TIER_GREEN  },
    /* Read-only operational state, promoted from RED-by-absence
     * 2026-08-14. These carry no credential or policy content: they are
     * counters, tables and inventory. Singular and plural are SEPARATE
     * rows because the matcher requires a token boundary — "show
     * interface" does not cover "show interfaces", and "show process"
     * does not cover "show processes". Deliberately NOT promoted, and
     * still RED by absence: show tech-support and
     * more system:running-config (both bundle the config, which is
     * YELLOW), the show run/running/conf abbreviations (the device
     * would expand them into a config read), show ssh, show username,
     * show user-identity and show crypto key mypubkey rsa. */
    { "show interface",             VIRP_TIER_GREEN  },
    { "show interfaces",            VIRP_TIER_GREEN  },
    { "show ip address",            VIRP_TIER_GREEN  },
    { "show ipv6 interface brief",  VIRP_TIER_GREEN  },
    { "show arp",                   VIRP_TIER_GREEN  },
    { "show mac-address-table",     VIRP_TIER_GREEN  },
    { "show switch vlan",           VIRP_TIER_GREEN  },
    { "show xlate",                 VIRP_TIER_GREEN  },
    { "show local-host",            VIRP_TIER_GREEN  },
    { "show uptime",                VIRP_TIER_GREEN  },
    { "show blocks",                VIRP_TIER_GREEN  },
    { "show traffic",               VIRP_TIER_GREEN  },
    { "show perfmon",               VIRP_TIER_GREEN  },
    { "show resource usage",        VIRP_TIER_GREEN  },
    { "show processes",             VIRP_TIER_GREEN  },
    { "show flash",                 VIRP_TIER_GREEN  },
    { "show disk0",                 VIRP_TIER_GREEN  },
    { "show file system",           VIRP_TIER_GREEN  },
    { "show ospf",                  VIRP_TIER_GREEN  },
    { "show bgp",                   VIRP_TIER_GREEN  },
    { "show eigrp",                 VIRP_TIER_GREEN  },

    /* ── Tier 2: YELLOW — Security posture reads (single approval) */
    { "show access-list",           VIRP_TIER_YELLOW },
    /* Spelling-variant closure, 2026-08-14. "show access-lists" does not
     * match the singular row (token boundary), so it was RED by absence
     * — i.e. refused, but for the wrong reason and one promotion away
     * from being LOOSER than its sibling. Pinned YELLOW so a variant can
     * never out-permit the row it varies. "show access-group" is the
     * ACL-to-interface binding, i.e. where enforcement is applied; it
     * belongs with access-list, not in the operational GREEN set. */
    { "show access-lists",          VIRP_TIER_YELLOW },
    { "show access-group",          VIRP_TIER_YELLOW },
    { "show running-config access-list", VIRP_TIER_YELLOW },
    { "show crypto isakmp sa",      VIRP_TIER_YELLOW },
    { "show crypto ipsec sa",       VIRP_TIER_YELLOW },
    { "show crypto ca certificates",VIRP_TIER_YELLOW },
    { "show vpn-sessiondb",         VIRP_TIER_YELLOW },
    { "show logging",               VIRP_TIER_YELLOW },
    { "show service-policy",        VIRP_TIER_YELLOW },
    { "show asp drop",              VIRP_TIER_YELLOW },
    { "show threat-detection",      VIRP_TIER_YELLOW },
    { "show nat",                   VIRP_TIER_YELLOW },
    { "show object",                VIRP_TIER_YELLOW },
    { "show object-group",          VIRP_TIER_YELLOW },
    /* Config-visibility reads — YELLOW to match the FortiGate precedent
     * (config reads = YELLOW; keep backups/audits under the threshold).
     * Sensitive credential/session reads stay RED below. */
    { "show running-config",        VIRP_TIER_YELLOW },
    { "show startup-config",        VIRP_TIER_YELLOW },

    /* ── Tier 3: RED — Sensitive credential/session reads (multi-approval) */
    { "show aaa-server",            VIRP_TIER_RED    },
    { "show ssh sessions",          VIRP_TIER_RED    },

    /* ── BLACK — Destructive operations (never transmitted) ────── */
    { "erase",                      VIRP_TIER_BLACK  },
    { "reload",                     VIRP_TIER_BLACK  },
    { "delete",                     VIRP_TIER_BLACK  },
    { "format",                     VIRP_TIER_BLACK  },
    { "write erase",                VIRP_TIER_BLACK  },
};

const size_t ASA_ROUTE_TABLE_SIZE =
    sizeof(ASA_ROUTE_TABLE) / sizeof(ASA_ROUTE_TABLE[0]);

/* =========================================================================
 * Command Routing — prefix match, longest wins
 * ========================================================================= */

virp_trust_tier_t asa_route_command(const char *command)
{
    if (!command) return VIRP_TIER_RED;              /* fail closed */

    /*
     * Layer 3a — a separator-carrying string is not one command, so this
     * table cannot vouch for it: the prefix match only ever sees the
     * first command while the driver sends the whole string to the
     * device. Fail closed to RED here as well as at the daemon boundary,
     * because asa_route_command is directly callable.
     */
    if (virp_command_check_separators(command, NULL, 0) != 0)
        return VIRP_TIER_RED;

    const asa_command_route_t *best = NULL;
    size_t best_len = 0;

    for (size_t i = 0; i < ASA_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(ASA_ROUTE_TABLE[i].command_pattern);
        /*
         * 2026-08-09 classified≠executed fix: tier rows match
         * CASE-SENSITIVELY — the driver executes the caller's original
         * bytes, so the table may not vouch for a spelling it did not
         * literally see; "SHOW VERSION" falls through RED by absence.
         * BLACK rows alone stay case-insensitive: they are a DENY
         * list, over-matching is the fail-closed direction there
         * ("RELOAD" must stay unapprovable BLACK, and nothing matched
         * BLACK ever executes, so the invariant is untouched).
         */
        bool is_black = (ASA_ROUTE_TABLE[i].tier == VIRP_TIER_BLACK);
        int cmp = is_black
            ? strncasecmp(command, ASA_ROUTE_TABLE[i].command_pattern, plen)
            : strncmp(command, ASA_ROUTE_TABLE[i].command_pattern, plen);
        if (cmp != 0)
            continue;

        /*
         * Layer 3b — the match must END on a token boundary so a listed
         * prefix can never stand in for a longer word ("reload" must not
         * cover "reloadable"). Entries that already end in a space carry
         * their own boundary. Longest valid match still wins.
         */
        char after = command[plen];
        bool self_terminated = (plen > 0 &&
            ASA_ROUTE_TABLE[i].command_pattern[plen - 1] == ' ');
        if (!self_terminated && after != '\0' &&
            after != ' ' && after != '\t')
            continue;

        if (plen > best_len) {
            best = &ASA_ROUTE_TABLE[i];
            best_len = plen;
        }
    }

    /* Fail-closed: anything not explicitly listed is RED. An unlisted
     * command used to return YELLOW, which CLEARED the default YELLOW
     * gate threshold and executed unreviewed. */
    return best ? best->tier : VIRP_TIER_RED;
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    int                 sock_fd;
    LIBSSH2_SESSION     *session;
    LIBSSH2_CHANNEL     *channel;
    virp_ssh_prompt_t   prompt;      /* learned at connect / after mode change */
    virp_ssh_io_t       io;          /* shared read path transport adapter */
    bool                connected;
    bool                in_enable;
    asa_mode_t          current_mode;
    asa_context_t       context;
};

/* ── Transport adapter for the shared read path ─────────────────── */

static ssize_t asa_io_read(void *ctx, char *buf, size_t len)
{
    virp_conn_t *conn = (virp_conn_t *)ctx;
    ssize_t n = libssh2_channel_read(conn->channel, buf, len);
    if (n == LIBSSH2_ERROR_EAGAIN)
        return VIRP_SSH_IO_EAGAIN;
    return n;
}

static ssize_t asa_io_write(void *ctx, const char *buf, size_t len)
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
 * Prompt Parsing — determine ASA mode from prompt string
 *
 * Patterns:
 *   ASA>                    — user EXEC
 *   ASA#                    — privileged EXEC
 *   ASA(config)#            — global config
 *   ASA(config-if)#         — sub-config
 *   ASA/ctx1>               — multi-context user
 *   ASA/ctx1#               — multi-context privileged
 * ========================================================================= */

asa_mode_t asa_parse_mode(const char *prompt)
{
    if (!prompt || !*prompt) return ASA_MODE_UNKNOWN;

    size_t len = strlen(prompt);

    /* Strip trailing whitespace */
    while (len > 0 && (prompt[len - 1] == ' ' || prompt[len - 1] == '\r'
                       || prompt[len - 1] == '\n'))
        len--;

    if (len == 0) return ASA_MODE_UNKNOWN;

    char last = prompt[len - 1];

    if (last == '>') return ASA_MODE_USER;

    if (last == '#') {
        /* Check for (config...) pattern */
        const char *paren = strchr(prompt, '(');
        if (paren) {
            if (strstr(paren, "(config)"))
                return ASA_MODE_CONFIG;
            if (strstr(paren, "(config-"))
                return ASA_MODE_CONFIG_SUB;
        }
        return ASA_MODE_ENABLE;
    }

    return ASA_MODE_UNKNOWN;
}

/* =========================================================================
 * TCP Connection (same pattern as IOS driver)
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

        struct timeval tv = { .tv_sec = ASA_CONNECT_TIMEOUT_SEC, .tv_usec = 0 };
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
 *
 * ASA prompts: hostname>, hostname#, hostname(config)#, hostname/ctx>
 * ========================================================================= */

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
 * Enable Mode — enter or re-enter privileged EXEC
 *
 * Returns true if now in enable mode (prompt ends with #).
 * ASA drops enable mode after certain commands (notably show running-config).
 * ========================================================================= */

static bool asa_enter_enable(virp_conn_t *conn)
{
    char buf[4096];

    /* Already privileged? */
    if (conn->prompt.learned && conn->prompt.prompt_len > 0 &&
        conn->prompt.prompt[conn->prompt.prompt_len - 1] == '#') {
        conn->in_enable = true;
        return true;
    }

    /*
     * The enable exchange changes the prompt, so it runs on quiescent
     * reads and the prompt is RE-LEARNED afterwards. Nothing read here
     * is signed.
     */
    ssh_write(conn, "enable\n");
    virp_ssh_read_quiescent(&conn->io, buf, sizeof(buf), ASA_ENABLE_TIMEOUT_MS);

    if (strstr(buf, "assword") != NULL) {
        char enable_cmd[256];
        snprintf(enable_cmd, sizeof(enable_cmd), "%s\n",
                 conn->device.enable_password);
        ssh_write(conn, enable_cmd);
        virp_ssh_read_quiescent(&conn->io, buf, sizeof(buf),
                                ASA_ENABLE_TIMEOUT_MS);
    }

    /* Pager/width do not persist across an enable transition. */
    ssh_write(conn, "terminal pager 0\n");
    virp_ssh_read_quiescent(&conn->io, buf, sizeof(buf), 3000);
    ssh_write(conn, "terminal width 512\n");
    virp_ssh_read_quiescent(&conn->io, buf, sizeof(buf), 3000);

    virp_ssh_learn_opts_t lopts = { .channel_has_spoken = true };
    if (virp_ssh_learn_prompt(&conn->io, conn->device.hostname, &lopts,
                              &conn->prompt) != VIRP_OK) {
        conn->in_enable = false;
        return false;
    }

    conn->current_mode = asa_parse_mode(conn->prompt.prompt);
    conn->in_enable = (conn->prompt.prompt_len > 0 &&
                       conn->prompt.prompt[conn->prompt.prompt_len - 1] == '#');
    return conn->in_enable;
}

/* =========================================================================
 * Verify enable mode — check prompt and re-enable if needed
 *
 * Must be called before every command execution.
 * ========================================================================= */

static bool asa_verify_enable(virp_conn_t *conn)
{
    /*
     * Re-learn rather than re-detect. ASA silently drops out of enable
     * after some commands, which changes the prompt; the learned prompt
     * is an input to every read, so a stale one would make every later
     * read fail. Re-learning IS the check — it sends the probes and
     * confirms the answer.
     */
    virp_ssh_learn_opts_t lopts = { .channel_has_spoken = true };
    if (virp_ssh_learn_prompt(&conn->io, conn->device.hostname, &lopts,
                              &conn->prompt) != VIRP_OK) {
        conn->in_enable = false;
        return false;
    }

    conn->current_mode = asa_parse_mode(conn->prompt.prompt);

    if (conn->current_mode == ASA_MODE_ENABLE ||
        conn->current_mode == ASA_MODE_CONFIG ||
        conn->current_mode == ASA_MODE_CONFIG_SUB) {
        conn->in_enable = true;
        return true;
    }

    /* Dropped to user mode — re-enable */
    fprintf(stderr, "[ASA] Enable mode dropped on %s, re-entering\n",
            conn->device.hostname);
    return asa_enter_enable(conn);
}

/* =========================================================================
 * Driver: connect
 * ========================================================================= */

static virp_conn_t *asa_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    virp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->sock_fd = -1;
    conn->connected = false;
    conn->in_enable = false;
    conn->io.ctx = conn;
    conn->io.read = asa_io_read;
    conn->io.write = asa_io_write;
    conn->current_mode = ASA_MODE_UNKNOWN;
    memset(&conn->context, 0, sizeof(conn->context));

    /* TCP connect */
    uint16_t port = device->port ? device->port : 22;
    conn->sock_fd = tcp_connect(device->host, port);
    if (conn->sock_fd < 0) {
        fprintf(stderr, "[ASA] TCP connect failed: %s:%u\n",
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

    /*
     * ASA SSH algorithm negotiation.
     *
     * Legacy mode (ssh_legacy=true): strict subset for older ASA firmware
     * (e.g. ASA-OS 9.2.x) that only offers group14-sha1, ssh-rsa, aes256-cbc.
     * Must be set BEFORE libssh2_session_handshake().
     *
     * Normal mode: group14-sha256 first (9.12+), group14-sha1 fallback (9.8.x).
     * Do NOT offer ECDH — most ASA firmware doesn't support it.
     */
    if (device->ssh_legacy) {
        fprintf(stderr, "[ASA] Legacy SSH mode for %s\n", device->hostname);
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_KEX,
            "diffie-hellman-group14-sha1");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_HOSTKEY,
            "ssh-rsa");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_CS,
            "aes256-cbc");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_SC,
            "aes256-cbc");
    } else {
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_KEX,
            "diffie-hellman-group14-sha256,"
            "diffie-hellman-group14-sha1,"
            "diffie-hellman-group-exchange-sha256,"
            "diffie-hellman-group-exchange-sha1");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_CS,
            "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_SC,
            "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_HOSTKEY,
            "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    }

    /* SSH handshake */
    if (libssh2_session_handshake(conn->session, conn->sock_fd) != 0) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[ASA] SSH handshake failed: %s (%s:%u)\n",
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
        fprintf(stderr, "[ASA] Host key verification failed: %s\n",
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
        fprintf(stderr, "[ASA] Auth failed for %s@%s: %s\n",
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
        fprintf(stderr, "[ASA] Failed to open channel\n");
        libssh2_session_disconnect(conn->session, "channel failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Request PTY — ASA needs this; 200 cols to prevent command wrapping */
    if (libssh2_channel_request_pty_ex(conn->channel, "vt100", 5,
                                        NULL, 0, 200, 24, 0, 0) != 0) {
        fprintf(stderr, "[ASA] PTY request failed\n");
    }

    /* Start shell */
    if (libssh2_channel_shell(conn->channel) != 0) {
        fprintf(stderr, "[ASA] Shell start failed\n");
        libssh2_channel_free(conn->channel);
        libssh2_session_disconnect(conn->session, "shell failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Set non-blocking mode */
    libssh2_session_set_blocking(conn->session, 0);

    /*
     * Connect-time reads precede any known prompt, so they are
     * quiescence-based and never signed.
     */
    char scratch[4096];
    size_t setup_bytes =
        virp_ssh_read_quiescent(&conn->io, scratch, sizeof(scratch), 5000);

    /* Learn the prompt before deciding anything from it. */
    virp_ssh_learn_opts_t lopts = { .channel_has_spoken = setup_bytes > 0 };
    if (virp_ssh_learn_prompt(&conn->io, device->hostname, &lopts,
                              &conn->prompt) != VIRP_OK) {
        fprintf(stderr, "[ASA] Prompt learning failed — refusing connection "
                "to %s (%s:%u)\n", device->hostname, device->host, port);
        goto learn_failed;
    }
    conn->current_mode = asa_parse_mode(conn->prompt.prompt);

    /* Enter enable mode if needed */
    if (conn->current_mode == ASA_MODE_USER) {
        if (device->enable_password[0] != '\0') {
            if (!asa_enter_enable(conn)) {
                fprintf(stderr, "[ASA] Warning: failed to enter enable mode on %s\n",
                        device->hostname);
                /* Don't fail — some ASA configs allow show commands from user mode */
            }
        }
    } else if (conn->current_mode == ASA_MODE_ENABLE ||
               conn->current_mode == ASA_MODE_CONFIG) {
        conn->in_enable = true;
        /* Already in enable — just disable pager and set width */
        ssh_write(conn, "terminal pager 0\n");
        virp_ssh_read_quiescent(&conn->io, scratch, sizeof(scratch), 3000);

        ssh_write(conn, "terminal width 512\n");
        virp_ssh_read_quiescent(&conn->io, scratch, sizeof(scratch), 3000);

        /* Those commands can alter the prompt line — re-learn. The
         * device has already produced a prompt once, so it has spoken. */
        virp_ssh_learn_opts_t relearn = { .channel_has_spoken = true };
        if (virp_ssh_learn_prompt(&conn->io, device->hostname, &relearn,
                                  &conn->prompt) != VIRP_OK) {
            fprintf(stderr, "[ASA] Prompt re-learn failed after pager setup "
                    "on %s\n", device->hostname);
            goto learn_failed;
        }
        conn->current_mode = asa_parse_mode(conn->prompt.prompt);
    }

    conn->connected = true;

    fprintf(stderr, "[ASA] Connected: %s@%s:%u prompt='%s' enable=%d mode=%d\n",
            device->username, device->host, port,
            conn->prompt.prompt, conn->in_enable, conn->current_mode);

    return conn;

learn_failed:
    libssh2_channel_close(conn->channel);
    libssh2_channel_free(conn->channel);
    libssh2_session_disconnect(conn->session, "prompt learn failed");
    libssh2_session_free(conn->session);
    close(conn->sock_fd);
    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
    OPENSSL_cleanse(conn->device.enable_password,
                    sizeof(conn->device.enable_password));
    free(conn);
    return NULL;
}

/* =========================================================================
 * Driver: execute
 *
 * Before each command:
 *   1. Flush buffer (ASA stale output quirk)
 *   2. Verify enable mode (re-enter if dropped)
 *   3. Send command
 *   4. Read response
 *   5. Scrub output (remove echo + trailing prompt)
 * ========================================================================= */

/* =========================================================================
 * Credential scrub for config-bearing reads
 *
 * Port of cisco_scrub_config (driver_cisco.c, 2026-08-10) to the ASA
 * directive set — same architecture: a pure function over the reply
 * text, run INSIDE the driver BEFORE the body is copied into the
 * result the O-Node signs, fail-closed (scrub cannot complete → typed
 * ERROR, nothing signed). ASA `show running-config` is YELLOW, but an
 * approval should let a human read a config — not pin the firewall's
 * credential set into the append-only chain.
 *
 * ASA-specific redactions on top of the shared keyword model
 * (password, secret, community, key-string, authentication-key, md5,
 * pre-shared-key, passphrase):
 *   - `passwd <hash> encrypted` and `ldap-login-password <val>`;
 *   - `failover key ...` — the value after `key` is the secret;
 *   - aaa-server: both the block form (indented `key <val>`, covered
 *     by the leading-`key` rule) and the legacy inline form
 *     `aaa-server G (if) host <ip> <key> [timeout N]` — everything
 *     after the host IP is redacted, the IP stays visible;
 *   - `snmp-server host <ifc> <ip> ...` keeps interface + IP, redacts
 *     the positional remainder (community string included);
 *   - EIGRP/RIP interface auth `authentication key eigrp <as> <val>
 *     key-id <n>` — redacted from the value after `key`;
 *   - `crypto isakmp key [enc] <val> address ...` keeps the peer.
 * ASA has no HSRP/VRRP, so the cisco standby/vrrp rule is dropped.
 * Over-redaction (trailing timeout/version/privilege tokens) is
 * accepted: it is the fail-closed direction.
 * ========================================================================= */

#define ASA_SCRUB_MARK "<removed>"
#define ASA_SCRUB_CAP(len) (3 * (len) + 64)

static bool asa_tok_eq(const char *tok, size_t len, const char *word)
{
    return strlen(word) == len && strncmp(tok, word, len) == 0;
}

static bool asa_scrub_emit(char *out, size_t cap, size_t *pos,
                           const char *src, size_t n)
{
    if (*pos + n >= cap) return false;
    memcpy(out + *pos, src, n);
    *pos += n;
    return true;
}

/* Scrub one line [line, line+len) (terminator excluded) into out.
 * Returns false only on output overflow. */
static bool asa_scrub_line(const char *line, size_t len,
                           char *out, size_t cap, size_t *pos)
{
    static const char *SECRET_KEYWORDS[] = {
        "password", "passwd", "secret", "community", "key-string",
        "authentication-key", "md5", "sha", "pre-shared-key",
        "passphrase", "ldap-login-password",
    };
    static const size_t SECRET_KEYWORD_COUNT =
        sizeof(SECRET_KEYWORDS) / sizeof(SECRET_KEYWORDS[0]);

    size_t i = 0;
    size_t tok_index = 0;
    size_t cut = 0;              /* redact from here (0 = no redaction) */
    bool   first_is_key = false; /* leading token is bare `key` */
    bool   first_is_failover = false;
    bool   prev_is_auth = false; /* previous token was `authentication` */
    size_t isakmp_state = 0;     /* tokens matched of crypto/isakmp/key */
    size_t snmp_host_state = 0;  /* snmp-server / host / <ifc> / <ip> */
    size_t aaa_host_state = 0;   /* aaa-server ... host / <ip> */

    while (i < len && cut == 0) {
        while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && line[i] != ' ' && line[i] != '\t') i++;
        const char *tok = line + start;
        size_t tlen = i - start;

        if (tok_index == 0) {
            if (asa_tok_eq(tok, tlen, "key"))         first_is_key = true;
            if (asa_tok_eq(tok, tlen, "crypto"))      isakmp_state = 1;
            if (asa_tok_eq(tok, tlen, "snmp-server")) snmp_host_state = 1;
            if (asa_tok_eq(tok, tlen, "aaa-server"))  aaa_host_state = 1;
            if (asa_tok_eq(tok, tlen, "failover"))    first_is_failover = true;
        } else if (tok_index == 1) {
            if (first_is_key) {
                /* `key chain NAME` is a block header; `key 1` is a
                 * key-chain index. Neither carries a secret. A numeric
                 * token is an index ONLY when it ends the line: the
                 * scan is bounded at the token end `i`, and anything
                 * after it (`key 0 12345678`, `key 7 070C285F4D06`)
                 * is a server-block secret and must be redacted. */
                bool numeric = true;
                for (size_t k = start; k < i; k++)
                    if (!(line[k] >= '0' && line[k] <= '9') &&
                        line[k] != '\r')
                        { numeric = false; break; }
                size_t rest = i;
                while (rest < len && (line[rest] == ' ' ||
                       line[rest] == '\t' || line[rest] == '\r'))
                    rest++;
                if (!asa_tok_eq(tok, tlen, "chain") &&
                    !(numeric && rest >= len))
                    cut = start;
                first_is_key = false;
            }
            if (first_is_failover && asa_tok_eq(tok, tlen, "key")) {
                /* `failover key [hex] SECRET` — secret follows */
                size_t j = i;
                while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
                if (j < len) cut = j;
            }
            if (isakmp_state == 1 && asa_tok_eq(tok, tlen, "isakmp"))
                isakmp_state = 2;
            else
                isakmp_state = 0;
            if (snmp_host_state == 1 && asa_tok_eq(tok, tlen, "host"))
                snmp_host_state = 2;   /* next: interface name */
            else
                snmp_host_state = 0;
        } else if (isakmp_state == 2 && asa_tok_eq(tok, tlen, "key")) {
            /* `crypto isakmp key [0|6|7] SECRET address A.B.C.D` */
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            size_t s2 = j;
            while (j < len && line[j] != ' ' && line[j] != '\t') j++;
            if (j - s2 == 1 && (line[s2] == '0' || line[s2] == '6' ||
                                line[s2] == '7')) {
                while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
                s2 = j;
                while (j < len && line[j] != ' ' && line[j] != '\t') j++;
            }
            if (s2 < len) {
                if (!asa_scrub_emit(out, cap, pos, line, s2) ||
                    !asa_scrub_emit(out, cap, pos, ASA_SCRUB_MARK,
                                    strlen(ASA_SCRUB_MARK)) ||
                    !asa_scrub_emit(out, cap, pos, line + j, len - j))
                    return false;
                return true;
            }
            isakmp_state = 0;
        } else if (snmp_host_state == 2) {
            snmp_host_state = 3;       /* interface name seen; next: ip */
        } else if (snmp_host_state == 3) {
            /* Past `snmp-server host <ifc> <ip>`: positional remainder
             * carries the community string — redact all of it. */
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            if (j < len) cut = j;
            snmp_host_state = 0;
        }

        /* aaa-server legacy inline key: `aaa-server G (if) host <ip>
         * <key> [timeout N]` — keep the IP, redact what follows. The
         * modern block form prints the key on its own indented `key`
         * line, which the leading-`key` rule catches. */
        if (cut == 0 && aaa_host_state >= 1 && tok_index >= 1) {
            if (aaa_host_state == 2) {
                /* this token is the host IP — redact from the next */
                size_t j = i;
                while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
                if (j < len) cut = j;
                aaa_host_state = 0;
            } else if (asa_tok_eq(tok, tlen, "host")) {
                aaa_host_state = 2;
            }
        }

        /* EIGRP/RIP interface auth: `authentication key eigrp <as>
         * <secret> key-id <n>` — the secret sits after `key`. */
        if (cut == 0 && prev_is_auth && asa_tok_eq(tok, tlen, "key")) {
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            if (j < len) cut = j;
        }
        prev_is_auth = asa_tok_eq(tok, tlen, "authentication");

        /* Mid-line `key <value>` (2026-08-11): ASA also carries keys
         * past token 0 — `cluster key <secret>` in vpn load-balancing
         * blocks, legacy inline aaa forms. Redact everything after
         * the `key` token. Token-0 `key` keeps its key-chain handling
         * above (block header / bare numeric index); mid-line there
         * is no index form, so a purely numeric value redacts too.
         * `crypto isakmp key` never reaches here — its branch emits
         * and returns, keeping the peer address visible. */
        if (cut == 0 && tok_index >= 1 && asa_tok_eq(tok, tlen, "key")) {
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            if (j < len) cut = j;
        }

        if (cut == 0) {
            for (size_t k = 0; k < SECRET_KEYWORD_COUNT; k++) {
                if (asa_tok_eq(tok, tlen, SECRET_KEYWORDS[k])) {
                    size_t j = i;
                    while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
                    if (j < len) cut = j;   /* keyword with a value */
                    break;
                }
            }
        }
        tok_index++;
    }

    if (cut == 0)
        return asa_scrub_emit(out, cap, pos, line, len);

    return asa_scrub_emit(out, cap, pos, line, cut) &&
           asa_scrub_emit(out, cap, pos, ASA_SCRUB_MARK,
                          strlen(ASA_SCRUB_MARK));
}

virp_error_t asa_scrub_config(const char *in, size_t in_len,
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
        size_t line_end = i;
        size_t content_end = line_end;
        if (content_end > start && in[content_end - 1] == '\r')
            content_end--;

        if (!asa_scrub_line(in + start, content_end - start,
                            out, out_cap, &pos))
            return VIRP_ERR_BUFFER_TOO_SMALL;
        if (!asa_scrub_emit(out, out_cap, &pos, in + content_end,
                            (line_end - content_end) +
                            ((i < in_len) ? 1 : 0)))
            return VIRP_ERR_BUFFER_TOO_SMALL;
        if (i < in_len) i++;
    }

    out[pos] = '\0';
    *out_len = pos;
    return VIRP_OK;
}

/*
 * Commands whose reply embeds ASA configuration. `more
 * system:running-config` matters even though it classifies RED
 * (fail-closed, unlisted): it is the variant that prints tunnel-group
 * pre-shared-keys UNMASKED, so if it is ever approved through the
 * proposal path the scrub must still stand between the reply and the
 * signer.
 */
bool asa_command_returns_config(const char *command)
{
    if (!command) return false;
    while (*command == ' ' || *command == '\t') command++;
    return strncmp(command, "show running-config",        19) == 0 ||
           strncmp(command, "show startup-config",        19) == 0 ||
           strncmp(command, "show tech-support",          17) == 0 ||
           strncmp(command, "more system:running-config", 26) == 0;
}

/*
 * Compose `hostname#command\nbody` into result->output — the bytes
 * the O-Node signs. snprintf returns the length it WOULD have
 * written; storing that as output_len let a clamped body sign with
 * success=true and truncated=no (Item 5, 2026-08-11). Mirror
 * driver_fortigate.c: output_len is ALWAYS the actual stored byte
 * count. A clamp on a SCRUBBED body is withheld typed — the scrub
 * grew the body past the capture buffer, and signing a prefix as the
 * config read would be a false attestation (same contract as the
 * scrub-failure branch). A clamp on a raw body keeps the legacy
 * clamped copy but is marked output_truncated so it can never sign
 * as complete. Exposed (non-static) for the unit suite.
 */
virp_error_t asa_store_output(virp_exec_result_t *result,
                              const char *hostname,
                              const char *command,
                              const char *body,
                              bool scrubbed_body)
{
    int written = snprintf(result->output, sizeof(result->output),
                           "%s#%s\n%s", hostname, command, body);
    if (written >= 0 && (size_t)written < sizeof(result->output)) {
        result->output_len = (size_t)written;
        result->success = true;
        return VIRP_OK;
    }
    if (written < 0 || scrubbed_body) {
        result->output[0] = '\0';
        result->output_len = 0;
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Scrubbed config exceeds capture buffer on %s: body "
                 "withheld from signing", hostname);
        return VIRP_ERR_BUFFER_TOO_SMALL;
    }
    result->output_len = sizeof(result->output) - 1;  /* ACTUAL stored */
    result->output_truncated = true;
    result->success = true;
    return VIRP_OK;
}

static virp_error_t asa_execute(virp_conn_t *conn,
                                const char *command,
                                virp_exec_result_t *result)
{
    if (!conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));

    if (!conn->connected) {
        result->success = false;
        result->no_dispatch = true;   /* refused before any transport write */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return VIRP_OK;
    }

    /* ── BLACK tier safety: never execute destructive commands ── */
    virp_trust_tier_t tier = asa_route_command(command);
    if (tier == VIRP_TIER_BLACK) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "BLACK tier: command blocked on %s", conn->device.hostname);
        fprintf(stderr, "[ASA] BLACK tier blocked: '%s' on %s\n",
                command, conn->device.hostname);
        int written = snprintf(result->output, sizeof(result->output),
                               "%s# %s\nBLACK tier: command forbidden",
                               conn->device.hostname, command);
        result->output_len = (written > 0) ? (size_t)written : 0;
        return VIRP_OK;
    }

    /* Step 1: Verify enable mode before every command (re-learns the
     * prompt, which also drains anything buffered). */
    if (!asa_verify_enable(conn)) {
        fprintf(stderr, "[ASA] Warning: not in enable mode on %s, "
                "command may fail: %s\n", conn->device.hostname, command);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Step 2: shared read path — drain residue, send, read to the
     * LEARNED prompt (which the helper strips). */
    char raw_output[VIRP_OUTPUT_MAX];
    size_t n = 0;
    virp_error_t rerr = virp_ssh_exec(&conn->io, &conn->prompt, command,
                                      raw_output, sizeof(raw_output), &n,
                                      ASA_READ_TIMEOUT_MS,
                                      conn->device.hostname);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

    if (rerr == VIRP_ERR_NO_PROMPT) {
        /* Incomplete read — a hard error so the O-Node emits a typed
         * ERROR observation rather than signing a truncated body. */
        conn->connected = false;
        result->success = false;
        result->output_len = 0;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Incomplete read on %s: no prompt after %zu bytes",
                 conn->device.hostname, n);
        return VIRP_ERR_NO_PROMPT;
    }
    if (rerr != VIRP_OK) {
        conn->connected = false;
        result->success = false;
        result->output_len = 0;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Transport failure on %s: %s",
                 conn->device.hostname, virp_error_str(rerr));
        return rerr;
    }

    /* Step 3: strip the echo by matching the command text. */
    char *output_start = virp_ssh_strip_echo(raw_output, command);

    /* Strip trailing \r\n */
    size_t clean_len = strlen(output_start);
    while (clean_len > 0 &&
           (output_start[clean_len - 1] == '\r' ||
            output_start[clean_len - 1] == '\n')) {
        output_start[--clean_len] = '\0';
    }

    /*
     * Credential scrub for config-bearing reads — BEFORE the body is
     * copied into result->output: what leaves this function is what
     * the O-Node signs into the append-only chain. Fail-closed: if the
     * scrub cannot complete, report a typed ERROR rather than signing
     * an unscrubbed body.
     */
    char *scrubbed = NULL;
    if (asa_command_returns_config(command)) {
        size_t cap = ASA_SCRUB_CAP(clean_len);
        scrubbed = malloc(cap);
        size_t scrubbed_len = 0;
        virp_error_t serr = scrubbed
            ? asa_scrub_config(output_start, clean_len,
                               scrubbed, cap, &scrubbed_len)
            : VIRP_ERR_BUFFER_TOO_SMALL;
        if (serr != VIRP_OK) {
            free(scrubbed);
            fprintf(stderr, "[ASA] Config scrub failed on %s "
                    "(%zu bytes) — refusing to sign unscrubbed body\n",
                    conn->device.hostname, clean_len);
            result->success = false;
            result->output_len = 0;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Config scrub failed on %s: body withheld from "
                     "signing", conn->device.hostname);
            return serr;
        }
        output_start = scrubbed;
    }

    /* Format: hostname#command\noutput (compatible with existing
     * format) — actual-length accounting and honest truncation/
     * withhold live in asa_store_output. */
    virp_error_t werr = asa_store_output(result, conn->device.hostname,
                                         command, output_start,
                                         scrubbed != NULL);
    if (werr != VIRP_OK) {
        fprintf(stderr, "[ASA] %s\n", result->error_msg);
        free(scrubbed);
        return werr;
    }
    result->exit_code = 0;

    /* Check for ASA error markers */
    if (strstr(output_start, "% Invalid input") ||
        strstr(output_start, "% Incomplete command") ||
        strstr(output_start, "% Ambiguous command") ||
        strstr(output_start, "% Authorization denied") ||
        strstr(output_start, "ERROR:")) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "ASA error in command: %s", command);
    }

    free(scrubbed);
    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect
 * ========================================================================= */

static void asa_disconnect(virp_conn_t *conn)
{
    if (!conn) return;

    if (conn->channel) {
        if (conn->connected) {
            libssh2_session_set_blocking(conn->session, 1);
            /* Exit gracefully — back out of any config mode first */
            if (conn->current_mode == ASA_MODE_CONFIG ||
                conn->current_mode == ASA_MODE_CONFIG_SUB) {
                ssh_write(conn, "end\n");
            }
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

    fprintf(stderr, "[ASA] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
    OPENSSL_cleanse(conn->device.enable_password, sizeof(conn->device.enable_password));
    free(conn);
}

/* =========================================================================
 * Driver: detect
 * ========================================================================= */

static bool asa_detect(virp_conn_t *conn)
{
    if (!conn || !conn->connected) return false;
    return conn->device.vendor == VIRP_VENDOR_CISCO_ASA;
}

/* =========================================================================
 * Driver: health_check — "show clock" is lightweight on ASA too
 * ========================================================================= */

static virp_error_t asa_health_check(virp_conn_t *conn)
{
    if (!conn) return VIRP_ERR_NULL_PTR;
    if (!conn->connected) return VIRP_ERR_KEY_NOT_LOADED;

    virp_exec_result_t result;
    virp_error_t err = asa_execute(conn, "show clock", &result);
    if (err != VIRP_OK) return err;

    return result.success ? VIRP_OK : VIRP_ERR_KEY_NOT_LOADED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t asa_driver = {
    .name       = "cisco_asa",
    .vendor     = VIRP_VENDOR_CISCO_ASA,
    .connect    = asa_connect,
    .execute    = asa_execute,
    .disconnect = asa_disconnect,
    .detect     = asa_detect,
    .health_check = asa_health_check,
    .route_command = asa_route_command,
};

const virp_driver_t *virp_driver_asa(void)
{
    return &asa_driver;
}

void virp_driver_asa_init(void)
{
    virp_driver_register(&asa_driver);
}
