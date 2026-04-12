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
 * Prefix-matched, longest match wins. Unmapped commands default YELLOW.
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

    /* ── Tier 2: YELLOW — Security posture reads (single approval) */
    { "show access-list",           VIRP_TIER_YELLOW },
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

    /* ── Tier 3: RED — Full config / sensitive (multi-approval) ── */
    { "show running-config",        VIRP_TIER_RED    },
    { "show startup-config",        VIRP_TIER_RED    },
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
    if (!command) return VIRP_TIER_YELLOW;

    const asa_command_route_t *best = NULL;
    size_t best_len = 0;

    for (size_t i = 0; i < ASA_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(ASA_ROUTE_TABLE[i].command_pattern);
        if (strncasecmp(command, ASA_ROUTE_TABLE[i].command_pattern, plen) == 0) {
            if (plen > best_len) {
                best = &ASA_ROUTE_TABLE[i];
                best_len = plen;
            }
        }
    }

    return best ? best->tier : VIRP_TIER_YELLOW;
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    int                 sock_fd;
    LIBSSH2_SESSION     *session;
    LIBSSH2_CHANNEL     *channel;
    char                prompt[ASA_MAX_PROMPT_LEN];
    size_t              prompt_len;
    bool                connected;
    bool                in_enable;
    asa_mode_t          current_mode;
    asa_context_t       context;
};

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

static ssize_t ssh_read_until_prompt(virp_conn_t *conn,
                                     char *buf, size_t buf_len,
                                     int timeout_ms)
{
    size_t total = 0;
    int elapsed = 0;
    int poll_interval = 50;

    while (total < buf_len - 1 && elapsed < timeout_ms) {
        ssize_t n = libssh2_channel_read(conn->channel,
                                          buf + total,
                                          buf_len - total - 1);
        if (n > 0) {
            total += n;
            buf[total] = '\0';

            /*
             * ASA prompt detection: look for # or > at end of last line.
             * Must handle (config)# and /context# patterns.
             */
            if (total >= 1) {
                /* Find the last line */
                char *last_nl = strrchr(buf, '\n');
                const char *last_line = last_nl ? last_nl + 1 : buf;

                /* Strip trailing spaces */
                size_t llen = strlen(last_line);
                while (llen > 0 && last_line[llen - 1] == ' ')
                    llen--;

                if (llen > 0) {
                    char last = last_line[llen - 1];
                    if (last == '#' || last == '>') {
                        /* Looks like a prompt — save it */
                        if (llen < ASA_MAX_PROMPT_LEN) {
                            if (conn->prompt_len == 0) {
                                memcpy(conn->prompt, last_line, llen);
                                conn->prompt[llen] = '\0';
                                conn->prompt_len = llen;
                            }
                            break;
                        }
                    }
                }
            }
            elapsed = 0;
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            usleep(poll_interval * 1000);
            elapsed += poll_interval;
        } else if (n == 0) {
            break;
        } else {
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
 * Buffer Flush — drain any stale output from the ASA
 *
 * ASA quirk: output from a previous command can appear in the buffer
 * if the read didn't fully drain. Always flush before sending a command.
 * ========================================================================= */

static void asa_flush_buffer(virp_conn_t *conn)
{
    char drain[4096];
    int elapsed = 0;

    while (elapsed < ASA_FLUSH_TIMEOUT_MS) {
        ssize_t n = libssh2_channel_read(conn->channel,
                                          drain, sizeof(drain) - 1);
        if (n > 0) {
            elapsed = 0;  /* More data, keep draining */
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            usleep(50 * 1000);
            elapsed += 50;
        } else {
            break;
        }
    }
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

    /* Check current prompt */
    if (conn->prompt_len > 0 &&
        conn->prompt[conn->prompt_len - 1] == '#') {
        conn->in_enable = true;
        return true;
    }

    /* Send enable */
    ssh_write(conn, "enable\n");
    ssh_read_until_prompt(conn, buf, sizeof(buf), ASA_ENABLE_TIMEOUT_MS);

    /* If we got a password prompt, send enable password */
    if (strstr(buf, "assword") != NULL) {
        char enable_cmd[256];
        snprintf(enable_cmd, sizeof(enable_cmd), "%s\n",
                 conn->device.enable_password);
        ssh_write(conn, enable_cmd);

        /* Reset prompt — will be re-detected */
        conn->prompt_len = 0;
        ssh_read_until_prompt(conn, buf, sizeof(buf), ASA_ENABLE_TIMEOUT_MS);
    }

    /* Check if we're now in enable mode */
    if (conn->prompt_len > 0 &&
        conn->prompt[conn->prompt_len - 1] == '#') {
        conn->in_enable = true;

        /* Re-apply terminal pager 0 — doesn't persist across enable transitions */
        ssh_write(conn, "terminal pager 0\n");
        char discard[4096];
        ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);

        /* Set terminal width to prevent 80-char line wrapping */
        ssh_write(conn, "terminal width 512\n");
        ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);

        return true;
    }

    conn->in_enable = false;
    return false;
}

/* =========================================================================
 * Verify enable mode — check prompt and re-enable if needed
 *
 * Must be called before every command execution.
 * ========================================================================= */

static bool asa_verify_enable(virp_conn_t *conn)
{
    /*
     * Send an empty line to get a fresh prompt.
     * This also detects if we dropped to user mode.
     */
    ssh_write(conn, "\n");

    /* Reset prompt to re-detect */
    conn->prompt_len = 0;

    char buf[4096];
    ssh_read_until_prompt(conn, buf, sizeof(buf), 2000);

    conn->current_mode = asa_parse_mode(conn->prompt);

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
    conn->prompt_len = 0;
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

    /* Read initial banner/prompt */
    char banner[4096];
    ssh_read_until_prompt(conn, banner, sizeof(banner), 5000);

    /* Detect initial mode */
    conn->current_mode = asa_parse_mode(conn->prompt);

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
        char discard[4096];
        ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);

        ssh_write(conn, "terminal width 512\n");
        ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);
    }

    conn->connected = true;

    fprintf(stderr, "[ASA] Connected: %s@%s:%u prompt='%s' enable=%d mode=%d\n",
            device->username, device->host, port,
            conn->prompt, conn->in_enable, conn->current_mode);

    return conn;
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

static virp_error_t asa_execute(virp_conn_t *conn,
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

    /* Step 1: Flush stale output */
    asa_flush_buffer(conn);

    /* Step 2: Verify enable mode before every command */
    if (!asa_verify_enable(conn)) {
        fprintf(stderr, "[ASA] Warning: not in enable mode on %s, "
                "command may fail: %s\n", conn->device.hostname, command);
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Step 3: Send command */
    char cmd_buf[2048];
    snprintf(cmd_buf, sizeof(cmd_buf), "%s\n", command);

    if (ssh_write(conn, cmd_buf) != 0) {
        conn->connected = false;
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to send command to %s", conn->device.hostname);
        return VIRP_OK;
    }

    /* Step 4: Read response */
    char raw_output[VIRP_OUTPUT_MAX];
    ssize_t n = ssh_read_until_prompt(conn, raw_output, sizeof(raw_output),
                                      ASA_READ_TIMEOUT_MS);

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

    /* Update mode from fresh prompt */
    conn->current_mode = asa_parse_mode(conn->prompt);

    /* Step 5: Scrub output — remove echoed command and trailing prompt */
    char *output_start = raw_output;
    char *first_nl = strchr(raw_output, '\n');
    if (first_nl)
        output_start = first_nl + 1;

    /* Remove trailing prompt */
    if (conn->prompt_len > 0) {
        size_t out_len = strlen(output_start);
        if (out_len >= conn->prompt_len) {
            char *possible_prompt = output_start + out_len - conn->prompt_len;
            if (strncmp(possible_prompt, conn->prompt, conn->prompt_len) == 0)
                *possible_prompt = '\0';
        }
    }

    /* Strip trailing \r\n */
    size_t clean_len = strlen(output_start);
    while (clean_len > 0 &&
           (output_start[clean_len - 1] == '\r' ||
            output_start[clean_len - 1] == '\n')) {
        output_start[--clean_len] = '\0';
    }

    /* Format: hostname#command\noutput (compatible with existing format) */
    int written = snprintf(result->output, sizeof(result->output),
                           "%s#%s\n%s",
                           conn->device.hostname, command, output_start);
    result->output_len = (written > 0) ? (size_t)written : 0;
    result->success = true;
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
};

const virp_driver_t *virp_driver_asa(void)
{
    return &asa_driver;
}

void virp_driver_asa_init(void)
{
    virp_driver_register(&asa_driver);
}
