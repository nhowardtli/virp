/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Juniper JunOS Device Driver — SSH-only, JunOS 12.x+
 *
 * Handles:
 *   - SSH with legacy cipher negotiation for older JunOS (15.1 and below)
 *   - No enable mode (JunOS flat privilege model)
 *   - Pager disable: "set cli screen-length 0"
 *   - Prompt detection: user@hostname> (operational) / user@hostname# (config)
 *   - Interactive shell via PTY (same transport as Cisco/ASA)
 *   - Output scrubbing (remove echoed command and trailing prompt)
 *   - JunOS-specific error detection
 *
 * NOTE on JunOS 15.1X49 (SRX300 series):
 *   - SSH banner: SSH-2.0-OpenSSH_6.9
 *   - Supports group14-sha1, ssh-rsa, aes256-cbc (legacy)
 *   - Also supports group14-sha256, aes256-ctr on patched builds
 *   - Interactive shell works; exec channel may drop output on long commands
 *   - Prompt includes username: "aiops-svc@srx-300>"
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_driver_juniper.h"
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

#define JUNOS_READ_TIMEOUT_MS       10000   /* 10 seconds per read            */
#define JUNOS_CONNECT_TIMEOUT_SEC   10
#define JUNOS_READ_BUF_SIZE         32768
#define JUNOS_MAX_PROMPT_LEN        128
#define JUNOS_FLUSH_TIMEOUT_MS      200     /* Brief drain for stale output   */
#define JUNOS_BATCH_MAX_CMDS        32      /* Max commands in a single batch  */
#define JUNOS_BATCH_CMD_BUF         8192    /* Max total batch command length  */

/* =========================================================================
 * Command Routing Table — JunOS-specific commands → trust tiers
 *
 * Prefix-matched, longest match wins. Unmapped commands default YELLOW.
 * ========================================================================= */

const junos_command_route_t JUNOS_ROUTE_TABLE[] = {
    /* ── Tier 1: GREEN — Passive monitoring (no approval) ──────── */
    { "show route",                     VIRP_TIER_GREEN  },
    { "show interfaces terse",          VIRP_TIER_GREEN  },
    { "show interfaces",                VIRP_TIER_GREEN  },
    { "show version",                   VIRP_TIER_GREEN  },
    { "show system uptime",             VIRP_TIER_GREEN  },
    { "show system alarms",             VIRP_TIER_GREEN  },
    { "show system storage",            VIRP_TIER_GREEN  },
    { "show system processes",          VIRP_TIER_GREEN  },
    { "show system memory",             VIRP_TIER_GREEN  },
    { "show chassis hardware",          VIRP_TIER_GREEN  },
    { "show chassis alarms",            VIRP_TIER_GREEN  },
    { "show chassis environment",       VIRP_TIER_GREEN  },
    { "show chassis routing-engine",    VIRP_TIER_GREEN  },
    { "show arp",                       VIRP_TIER_GREEN  },
    { "show bgp summary",              VIRP_TIER_GREEN  },
    { "show bgp neighbor",             VIRP_TIER_GREEN  },
    { "show ospf neighbor",            VIRP_TIER_GREEN  },
    { "show ospf interface",           VIRP_TIER_GREEN  },
    { "show isis adjacency",           VIRP_TIER_GREEN  },
    { "show isis interface",           VIRP_TIER_GREEN  },
    { "show lldp neighbors",           VIRP_TIER_GREEN  },
    { "show ethernet-switching table", VIRP_TIER_GREEN  },
    { "show pfe statistics traffic",   VIRP_TIER_GREEN  },

    /* ── Tier 2: YELLOW — Security posture reads (single approval) */
    { "show security policies",         VIRP_TIER_YELLOW },
    { "show security zones",            VIRP_TIER_YELLOW },
    { "show security nat",              VIRP_TIER_YELLOW },
    { "show security ipsec",            VIRP_TIER_YELLOW },
    { "show security ike",              VIRP_TIER_YELLOW },
    { "show security flow session",     VIRP_TIER_YELLOW },
    { "show security screen",           VIRP_TIER_YELLOW },
    { "show security alg",              VIRP_TIER_YELLOW },
    { "show configuration protocols",   VIRP_TIER_YELLOW },
    { "show log",                       VIRP_TIER_YELLOW },
    { "show firewall",                  VIRP_TIER_YELLOW },
    { "show policy-options",            VIRP_TIER_YELLOW },

    /* ── Tier 3: RED — Full config / sensitive (multi-approval) ── */
    { "show configuration",             VIRP_TIER_RED    },
    { "show configuration | display set", VIRP_TIER_RED  },

    /* ── BLACK — Destructive operations (never transmitted) ────── */
    { "request system reboot",          VIRP_TIER_BLACK  },
    { "request system halt",            VIRP_TIER_BLACK  },
    { "request system zeroize",         VIRP_TIER_BLACK  },
    { "request system power-off",       VIRP_TIER_BLACK  },
    { "file delete",                    VIRP_TIER_BLACK  },
    { "request system software delete", VIRP_TIER_BLACK  },

    /* ── Write Ops: YELLOW — address book, policies, DHCP ──────── */
    { "set security address-book",          VIRP_TIER_YELLOW },
    { "set security policies",              VIRP_TIER_YELLOW },
    { "set system services dhcp",           VIRP_TIER_YELLOW },
    { "delete security address-book",       VIRP_TIER_YELLOW },
    { "delete security policies",           VIRP_TIER_YELLOW },
    { "delete system services dhcp",        VIRP_TIER_YELLOW },

    /* ── Write Ops: RED — NAT, routing, interfaces, commit ─────── */
    { "configure",                          VIRP_TIER_RED    },
    { "set security nat",                   VIRP_TIER_RED    },
    { "set interfaces",                     VIRP_TIER_RED    },
    { "set routing-options",                VIRP_TIER_RED    },
    { "set protocols",                      VIRP_TIER_RED    },
    { "delete",                            VIRP_TIER_RED    },
    { "delete security nat",               VIRP_TIER_RED    },
    { "delete interfaces",                 VIRP_TIER_RED    },
    { "delete routing-options",            VIRP_TIER_RED    },
    { "delete protocols",                  VIRP_TIER_RED    },
    { "commit check",                       VIRP_TIER_RED    },
    { "commit",                             VIRP_TIER_RED    },
    { "rollback",                           VIRP_TIER_RED    },
};

const size_t JUNOS_ROUTE_TABLE_SIZE =
    sizeof(JUNOS_ROUTE_TABLE) / sizeof(JUNOS_ROUTE_TABLE[0]);

/* =========================================================================
 * Command Routing — prefix match, longest wins
 * ========================================================================= */

virp_trust_tier_t junos_route_command(const char *command)
{
    if (!command) return VIRP_TIER_YELLOW;

    const junos_command_route_t *best = NULL;
    size_t best_len = 0;

    for (size_t i = 0; i < JUNOS_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(JUNOS_ROUTE_TABLE[i].command_pattern);
        if (strncasecmp(command, JUNOS_ROUTE_TABLE[i].command_pattern, plen) == 0) {
            if (plen > best_len) {
                best = &JUNOS_ROUTE_TABLE[i];
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
    char                prompt[JUNOS_MAX_PROMPT_LEN];
    size_t              prompt_len;
    bool                connected;
    junos_mode_t        current_mode;
    bool                config_error;       /* set/delete failed in config session */
    bool                commit_check_ok;    /* commit check passed for this batch */
};

/* =========================================================================
 * Prompt Parsing — determine JunOS mode from prompt string
 *
 * Patterns:
 *   user@hostname>              — operational mode
 *   user@hostname#              — configuration mode
 *   user@hostname%              — shell mode (BSD)
 *   {master:0}[edit]            — config mode prefix (ignored)
 *
 * JunOS prompts always include the username. The '@' is the giveaway.
 * ========================================================================= */

junos_mode_t junos_parse_mode(const char *prompt)
{
    if (!prompt || !*prompt) return JUNOS_MODE_UNKNOWN;

    size_t len = strlen(prompt);

    /* Strip trailing whitespace */
    while (len > 0 && (prompt[len - 1] == ' ' || prompt[len - 1] == '\r'
                       || prompt[len - 1] == '\n'))
        len--;

    if (len == 0) return JUNOS_MODE_UNKNOWN;

    char last = prompt[len - 1];

    /* JunOS prompts always contain '@' (user@hostname pattern).
     * Without it, this could be a Cisco or other vendor prompt. */
    if (!memchr(prompt, '@', len)) return JUNOS_MODE_UNKNOWN;

    if (last == '>') return JUNOS_MODE_OPERATIONAL;
    if (last == '#') return JUNOS_MODE_CONFIGURE;
    if (last == '%') return JUNOS_MODE_SHELL;

    return JUNOS_MODE_UNKNOWN;
}

/* =========================================================================
 * TCP Connection (same pattern as Cisco/ASA drivers)
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

        struct timeval tv = { .tv_sec = JUNOS_CONNECT_TIMEOUT_SEC, .tv_usec = 0 };
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
 * SSH Read Helper — reads until JunOS prompt or timeout
 *
 * JunOS prompts: user@hostname>, user@hostname#, user@hostname%
 * Also handles "{master:0}" prefix lines before the prompt.
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
             * JunOS prompt detection.
             *
             * JunOS prompt is always on the last line and ends with > # or %
             * It contains '@' (user@hostname pattern).
             *
             * Watch out for "{master:0}" or "[edit]" lines that appear
             * before the prompt in config mode — scan the actual last line.
             */
            if (total >= 1) {
                /* Find the last non-empty line */
                char *last_nl = strrchr(buf, '\n');
                const char *last_line = last_nl ? last_nl + 1 : buf;

                /* Skip if empty (might have trailing newline before prompt) */
                if (*last_line == '\0' && last_nl && last_nl > buf) {
                    /* Look one line further back */
                    char saved = *last_nl;
                    *last_nl = '\0';
                    char *prev_nl = strrchr(buf, '\n');
                    *last_nl = saved;
                    if (prev_nl)
                        last_line = prev_nl + 1;
                    else
                        last_line = buf;
                }

                size_t llen = strlen(last_line);
                /* Strip trailing whitespace for matching */
                while (llen > 0 && (last_line[llen - 1] == ' ' ||
                                     last_line[llen - 1] == '\r' ||
                                     last_line[llen - 1] == '\n'))
                    llen--;

                if (llen > 0) {
                    char last = last_line[llen - 1];
                    if ((last == '>' || last == '#' || last == '%') &&
                        memchr(last_line, '@', llen) != NULL) {
                        /* Looks like a JunOS prompt — save it */
                        if (llen < JUNOS_MAX_PROMPT_LEN) {
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
 * Buffer Flush — drain any stale output
 *
 * Same pattern as ASA — older JunOS can leave bytes in the buffer
 * between commands, especially after long "show" outputs.
 * ========================================================================= */

static void junos_flush_buffer(virp_conn_t *conn)
{
    char drain[4096];
    int elapsed = 0;

    while (elapsed < JUNOS_FLUSH_TIMEOUT_MS) {
        ssize_t n = libssh2_channel_read(conn->channel,
                                          drain, sizeof(drain) - 1);
        if (n > 0) {
            elapsed = 0;
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            usleep(50 * 1000);
            elapsed += 50;
        } else {
            break;
        }
    }
}

/* =========================================================================
 * Keyboard-interactive auth callback for libssh2
 *
 * Some JunOS versions (particularly older JUNOS_KEY_MGMT builds)
 * only advertise keyboard-interactive.
 * ========================================================================= */

#define KBD_MAX_PROMPTS 4

static void kbd_interactive_callback(const char *name, int name_len,
                                      const char *instruction, int instruction_len,
                                      int num_prompts,
                                      const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
                                      LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses,
                                      void **abstract)
{
    (void)name; (void)name_len;
    (void)instruction; (void)instruction_len;
    (void)prompts;

    if (num_prompts > KBD_MAX_PROMPTS) {
        fprintf(stderr, "[JunOS] keyboard-interactive: server sent %d prompts "
                "(max %d) — rejecting\n", num_prompts, KBD_MAX_PROMPTS);
        for (int i = 0; i < num_prompts; i++) {
            responses[i].text   = NULL;
            responses[i].length = 0;
        }
        return;
    }

    const char *password = (const char *)*abstract;

    for (int i = 0; i < num_prompts; i++) {
        responses[i].text   = strdup(password);
        responses[i].length = (unsigned int)strlen(password);
    }
}

/* =========================================================================
 * Driver: connect
 *
 * JunOS connection flow:
 *   1. TCP connect
 *   2. SSH handshake (legacy ciphers for older JunOS)
 *   3. Authenticate (keyboard-interactive first, password fallback)
 *   4. Open interactive shell via PTY
 *   5. Read banner/prompt
 *   6. Disable paging: "set cli screen-length 0"
 *   7. Disable line wrapping: "set cli screen-width 0"
 *   8. Ready for commands
 *
 * NOTE: We use interactive shell (PTY + shell) rather than exec channel.
 * JunOS 15.1 exec channels can silently truncate output on long commands
 * and don't preserve the session state between invocations.
 * ========================================================================= */

static virp_conn_t *junos_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    virp_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->sock_fd = -1;
    conn->connected = false;
    conn->prompt_len = 0;
    conn->current_mode = JUNOS_MODE_UNKNOWN;
    conn->config_error = false;
    conn->commit_check_ok = false;

    /* TCP connect */
    uint16_t port = device->port ? device->port : 22;
    conn->sock_fd = tcp_connect(device->host, port);
    if (conn->sock_fd < 0) {
        fprintf(stderr, "[JunOS] TCP connect failed: %s:%u\n",
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
     * JunOS SSH algorithm negotiation.
     *
     * Legacy mode (ssh_legacy=true): for JunOS 15.1 and older that only
     * offer group14-sha1, ssh-rsa, aes256-cbc. The SRX300 with 15.1X49
     * falls into this category.
     *
     * Normal mode: modern algorithms first, legacy fallback.
     * JunOS 18.x+ supports ECDH and sha2, but we always keep group14-sha1
     * as fallback since even modern JunOS still accepts it.
     */
    if (device->ssh_legacy) {
        fprintf(stderr, "[JunOS] Legacy SSH mode for %s\n", device->hostname);
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_KEX,
            "diffie-hellman-group14-sha1,"
            "diffie-hellman-group-exchange-sha1");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_HOSTKEY,
            "ssh-rsa");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_CS,
            "aes256-cbc,aes128-cbc,3des-cbc");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_SC,
            "aes256-cbc,aes128-cbc,3des-cbc");
    } else {
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_KEX,
            "ecdh-sha2-nistp256,"
            "ecdh-sha2-nistp384,"
            "diffie-hellman-group14-sha256,"
            "diffie-hellman-group14-sha1,"
            "diffie-hellman-group-exchange-sha256,"
            "diffie-hellman-group-exchange-sha1");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_CS,
            "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_SC,
            "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc");
        libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_HOSTKEY,
            "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-ed25519");
    }

    /* SSH handshake */
    if (libssh2_session_handshake(conn->session, conn->sock_fd) != 0) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[JunOS] SSH handshake failed: %s (%s:%u)\n",
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
        fprintf(stderr, "[JunOS] Host key verification failed: %s\n",
                virp_error_str(hk_err));
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Authentication — query supported methods, try each in order.
     * JunOS typically offers both password and keyboard-interactive.
     * Older JunOS with RADIUS may only offer keyboard-interactive. */
    bool authenticated = false;

    char *auth_list = libssh2_userauth_list(conn->session,
                                             device->username,
                                             (unsigned int)strlen(device->username));

    if (!auth_list && libssh2_userauth_authenticated(conn->session)) {
        authenticated = true;
    }

    if (auth_list) {
        fprintf(stderr, "[JunOS] Auth methods for %s@%s: %s\n",
                device->username, device->host, auth_list);
    }

    /* Try keyboard-interactive first */
    if (!authenticated && auth_list && strstr(auth_list, "keyboard-interactive")) {
        *libssh2_session_abstract(conn->session) = (void *)device->password;

        if (libssh2_userauth_keyboard_interactive(conn->session,
                                                   device->username,
                                                   kbd_interactive_callback) == 0) {
            authenticated = true;
            fprintf(stderr, "[JunOS] Auth OK (keyboard-interactive): %s@%s\n",
                    device->username, device->host);
        }
    }

    /* Fallback to password auth */
    if (!authenticated && auth_list && strstr(auth_list, "password")) {
        if (libssh2_userauth_password(conn->session,
                                       device->username,
                                       device->password) == 0) {
            authenticated = true;
            fprintf(stderr, "[JunOS] Auth OK (password): %s@%s\n",
                    device->username, device->host);
        }
    }

    if (!authenticated) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[JunOS] All auth methods failed for %s@%s: %s "
                "(server offered: %s)\n",
                device->username, device->host, errmsg,
                auth_list ? auth_list : "none");
        libssh2_session_disconnect(conn->session, "auth failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Open interactive shell channel.
     * JunOS supports exec channels, but 15.1X49 can truncate long output
     * and doesn't maintain state between exec calls. Interactive shell
     * is more reliable across JunOS versions. */
    conn->channel = libssh2_channel_open_session(conn->session);
    if (!conn->channel) {
        fprintf(stderr, "[JunOS] Failed to open channel\n");
        libssh2_session_disconnect(conn->session, "channel failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Request PTY — 200 cols to prevent line wrapping on wide output */
    if (libssh2_channel_request_pty_ex(conn->channel, "vt100", 5,
                                        NULL, 0, 200, 24, 0, 0) != 0) {
        fprintf(stderr, "[JunOS] PTY request failed\n");
    }

    /* Start shell */
    if (libssh2_channel_shell(conn->channel) != 0) {
        fprintf(stderr, "[JunOS] Shell start failed\n");
        libssh2_channel_free(conn->channel);
        libssh2_session_disconnect(conn->session, "shell failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Set non-blocking mode */
    libssh2_session_set_blocking(conn->session, 0);

    /* Read initial banner/prompt.
     * JunOS often sends a MOTD banner before the CLI prompt.
     * The prompt will be the last line: "user@hostname>" */
    char banner[4096];
    ssh_read_until_prompt(conn, banner, sizeof(banner), 5000);

    /* Detect initial mode */
    conn->current_mode = junos_parse_mode(conn->prompt);

    /* Disable paging — JunOS uses "set cli screen-length 0" */
    ssh_write(conn, "set cli screen-length 0\n");
    char discard[4096];
    ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);

    /* Disable line wrapping — prevents mid-line breaks on wide output */
    ssh_write(conn, "set cli screen-width 0\n");
    conn->prompt_len = 0;  /* Reset — prompt may have changed */
    ssh_read_until_prompt(conn, discard, sizeof(discard), 3000);

    conn->connected = true;

    fprintf(stderr, "[JunOS] Connected: %s@%s:%u prompt='%s' mode=%d\n",
            device->username, device->host, port,
            conn->prompt, conn->current_mode);

    return conn;
}

/* =========================================================================
 * Driver: execute
 *
 * Before each command:
 *   1. Flush buffer (stale output)
 *   2. Send command
 *   3. Read response
 *   4. Scrub output (remove echo + trailing prompt)
 *
 * No enable mode verification needed — JunOS has no enable concept.
 * If we somehow ended up in config mode, exit first.
 * ========================================================================= */

static virp_error_t junos_execute_single(virp_conn_t *conn,
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

    /* Step 1: Flush stale output */
    junos_flush_buffer(conn);

    /* ── BLACK tier safety: never execute forbidden commands ── */
    virp_trust_tier_t tier = junos_route_command(command);
    if (tier == VIRP_TIER_BLACK) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "BLACK tier: command blocked on %s", conn->device.hostname);
        fprintf(stderr, "[JunOS] BLACK tier blocked: '%s' on %s\n",
                command, conn->device.hostname);
        int written = snprintf(result->output, sizeof(result->output),
                               "%s>%s\nBLACK tier: command forbidden",
                               conn->device.hostname, command);
        result->output_len = (written > 0) ? (size_t)written : 0;
        return VIRP_OK;
    }

    /* ── Configure mode: classify incoming command ── */
    bool is_configure = (strncasecmp(command, "configure", 9) == 0 &&
                         (command[9] == '\0' || command[9] == ' ' ||
                          command[9] == '\n'));
    bool is_commit_check = (strncasecmp(command, "commit check", 12) == 0);
    bool is_commit = !is_commit_check &&
                     (strncasecmp(command, "commit", 6) == 0) &&
                     (command[6] == '\0' || command[6] == ' ' ||
                      command[6] == '\n');
    bool is_rollback = (strncasecmp(command, "rollback", 8) == 0);
    bool is_set_delete = (strncasecmp(command, "set ", 4) == 0 ||
                          strncasecmp(command, "delete ", 7) == 0);

    /* Reset config state when entering configure mode */
    if (is_configure) {
        conn->config_error = false;
        conn->commit_check_ok = false;
    }

    /* Refuse commit without prior successful commit check */
    if (is_commit && !conn->commit_check_ok) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "commit rejected: commit check required first on %s",
                 conn->device.hostname);
        fprintf(stderr, "[JunOS] Commit blocked (no commit check) on %s "
                "— auto-rollback\n", conn->device.hostname);
        /* Auto-rollback for safety */
        ssh_write(conn, "rollback 0\n");
        char rb_buf[4096];
        conn->prompt_len = 0;
        ssh_read_until_prompt(conn, rb_buf, sizeof(rb_buf), 5000);
        conn->config_error = false;
        conn->commit_check_ok = false;
        int written = snprintf(result->output, sizeof(result->output),
                               "%s>%s\ncommit rejected: run 'commit check' "
                               "first (auto-rollback applied)",
                               conn->device.hostname, command);
        result->output_len = (written > 0) ? (size_t)written : 0;
        return VIRP_OK;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Step 2: Send command.
     * If in configure mode and the command is operational (show/ping),
     * auto-prepend "run " so JunOS executes it from config context. */
    char cmd_buf[2048];
    if (conn->current_mode == JUNOS_MODE_CONFIGURE &&
        (strncasecmp(command, "show ", 5) == 0 ||
         strncasecmp(command, "ping ", 5) == 0 ||
         strncasecmp(command, "traceroute ", 11) == 0)) {
        snprintf(cmd_buf, sizeof(cmd_buf), "run %s\n", command);
    } else {
        snprintf(cmd_buf, sizeof(cmd_buf), "%s\n", command);
    }

    if (ssh_write(conn, cmd_buf) != 0) {
        conn->connected = false;
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to send command to %s", conn->device.hostname);
        return VIRP_OK;
    }

    /* Step 3: Read response.
     * Reset prompt detection — JunOS may change prompt after some commands
     * (e.g., entering config mode changes > to #). */
    conn->prompt_len = 0;

    char raw_output[VIRP_OUTPUT_MAX];
    ssize_t n = ssh_read_until_prompt(conn, raw_output, sizeof(raw_output),
                                      JUNOS_READ_TIMEOUT_MS);

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
    conn->current_mode = junos_parse_mode(conn->prompt);

    /* Step 4: Scrub output — remove echoed command and trailing prompt.
     *
     * JunOS interactive shell output format:
     *   <echoed command>\r\n
     *   <actual output>
     *   \r\n
     *   user@hostname>
     *
     * Additional wrinkle: in config mode, JunOS may emit
     * "{master:0}" or "[edit]" lines before the prompt.
     */
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

    /* Also strip {master:0} lines if present at end */
    char *master_tag = strstr(output_start, "\n{master:");
    if (master_tag)
        *master_tag = '\0';

    /* Strip trailing \r\n */
    size_t clean_len = strlen(output_start);
    while (clean_len > 0 &&
           (output_start[clean_len - 1] == '\r' ||
            output_start[clean_len - 1] == '\n')) {
        output_start[--clean_len] = '\0';
    }

    /* Format: hostname>command\noutput (matches existing executor format) */
    int written = snprintf(result->output, sizeof(result->output),
                           "%s>%s\n%s",
                           conn->device.hostname, command, output_start);
    result->output_len = (written > 0) ? (size_t)written : 0;
    result->success = true;
    result->exit_code = 0;

    /* Check for JunOS error markers */
    if (strstr(output_start, "syntax error") ||
        strstr(output_start, "unknown command") ||
        strstr(output_start, "invalid value") ||
        strstr(output_start, "error:") ||
        strstr(output_start, "missing argument") ||
        strstr(output_start, "permission denied")) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "JunOS error in command: %s", command);
    }

    /* ── Post-execute: configure mode state tracking ── */

    /* Verify configure mode entry */
    if (is_configure && conn->current_mode != JUNOS_MODE_CONFIGURE) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Failed to enter configure mode on %s",
                 conn->device.hostname);
    }

    /* Track config errors on set/delete */
    if (is_set_delete && conn->current_mode == JUNOS_MODE_CONFIGURE &&
        !result->success) {
        conn->config_error = true;
        fprintf(stderr, "[JunOS] Config error on %s: %s\n",
                conn->device.hostname, command);
    }

    /* Commit check result */
    if (is_commit_check) {
        if (strstr(output_start, "check succeeds")) {
            conn->commit_check_ok = true;
            fprintf(stderr, "[JunOS] Commit check passed on %s\n",
                    conn->device.hostname);
        } else {
            conn->commit_check_ok = false;
            result->success = false;
            result->exit_code = 1;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "commit check failed on %s", conn->device.hostname);
            fprintf(stderr, "[JunOS] Commit check FAILED on %s — "
                    "auto-rollback\n", conn->device.hostname);
            /* Auto-rollback on commit check failure */
            junos_flush_buffer(conn);
            ssh_write(conn, "rollback 0\n");
            char rb_buf[4096];
            conn->prompt_len = 0;
            ssh_read_until_prompt(conn, rb_buf, sizeof(rb_buf), 5000);
        }
    }

    /* Commit success — reset state */
    if (is_commit && result->success) {
        conn->config_error = false;
        conn->commit_check_ok = false;
        fprintf(stderr, "[JunOS] Commit complete on %s\n",
                conn->device.hostname);
    }

    /* Rollback — reset state */
    if (is_rollback) {
        conn->config_error = false;
        conn->commit_check_ok = false;
        fprintf(stderr, "[JunOS] Rollback on %s\n", conn->device.hostname);
    }

    return VIRP_OK;
}

/* =========================================================================
 * Batch Command Detection
 *
 * JunOS candidate configuration is session-bound — when a session closes,
 * uncommitted config is discarded. Config sequences (configure → set →
 * commit check → commit) MUST execute in the same PTY session.
 *
 * Batch commands use ';' or '\n' as separators:
 *   "configure; set interfaces ge-0/0/0 ...; commit check; commit"
 * ========================================================================= */

bool junos_is_batch_command(const char *command)
{
    if (!command) return false;
    for (const char *p = command; *p; p++) {
        if (*p == ';') return true;
        if (*p == '\n' && *(p + 1) != '\0') return true;
    }
    return false;
}

/* =========================================================================
 * Driver: execute — dispatch to single or batch mode
 *
 * If the command contains ';' or '\n' separators, all sub-commands run
 * sequentially in the same PTY session, preserving candidate config.
 *
 * Batch semantics:
 *   - Pre-scan: any BLACK-tier command → entire batch rejected
 *   - Config state (config_error, commit_check_ok) tracked across batch
 *   - If set/delete fails, remaining set/delete are skipped
 *     (rollback, commit check, exit, show commands still execute)
 *   - result->success = false if ANY sub-command failed
 *   - Output: each sub-command formatted as hostname>cmd\noutput
 * ========================================================================= */

static virp_error_t junos_execute(virp_conn_t *conn,
                                  const char *command,
                                  virp_exec_result_t *result)
{
    if (!conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    /* Single command — fast path */
    if (!junos_is_batch_command(command))
        return junos_execute_single(conn, command, result);

    /* ── Batch mode ── */
    memset(result, 0, sizeof(*result));

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return VIRP_OK;
    }

    /* Copy command string for tokenization */
    size_t cmd_len = strlen(command);
    if (cmd_len >= JUNOS_BATCH_CMD_BUF) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Batch too long (%zu bytes, max %d)",
                 cmd_len, JUNOS_BATCH_CMD_BUF - 1);
        return VIRP_OK;
    }

    char cmds_copy[JUNOS_BATCH_CMD_BUF];
    memcpy(cmds_copy, command, cmd_len + 1);

    /* Split by ';' or '\n', trim whitespace */
    char *cmd_ptrs[JUNOS_BATCH_MAX_CMDS];
    int cmd_count = 0;

    char *saveptr;
    char *tok = strtok_r(cmds_copy, ";\n", &saveptr);
    while (tok && cmd_count < JUNOS_BATCH_MAX_CMDS) {
        while (*tok == ' ' || *tok == '\t') tok++;
        size_t tlen = strlen(tok);
        while (tlen > 0 && (tok[tlen - 1] == ' ' || tok[tlen - 1] == '\t' ||
                             tok[tlen - 1] == '\r'))
            tok[--tlen] = '\0';

        if (tlen > 0)
            cmd_ptrs[cmd_count++] = tok;

        tok = strtok_r(NULL, ";\n", &saveptr);
    }

    if (cmd_count == 0) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Empty batch on %s", conn->device.hostname);
        return VIRP_OK;
    }

    /* Pre-scan for BLACK tier — reject entire batch upfront */
    for (int i = 0; i < cmd_count; i++) {
        if (junos_route_command(cmd_ptrs[i]) == VIRP_TIER_BLACK) {
            result->success = false;
            result->exit_code = 1;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "BLACK tier: batch rejected — '%s' blocked on %s",
                     cmd_ptrs[i], conn->device.hostname);
            int w = snprintf(result->output, sizeof(result->output),
                             "%s>[batch]\nBLACK tier: command '%s' "
                             "forbidden — entire batch rejected",
                             conn->device.hostname, cmd_ptrs[i]);
            result->output_len = (w > 0) ? (size_t)w : 0;
            fprintf(stderr, "[JunOS] BLACK tier in batch — "
                    "rejected '%s' on %s\n",
                    cmd_ptrs[i], conn->device.hostname);
            return VIRP_OK;
        }
    }

    /* Execute each command sequentially in the same session */
    struct timespec batch_start, batch_end;
    clock_gettime(CLOCK_MONOTONIC, &batch_start);

    result->success = true;
    size_t out_off = 0;
    bool skip_config = false;

    fprintf(stderr, "[JunOS] Batch: %d commands on %s\n",
            cmd_count, conn->device.hostname);

    for (int i = 0; i < cmd_count; i++) {
        bool is_sd = (strncasecmp(cmd_ptrs[i], "set ", 4) == 0 ||
                      strncasecmp(cmd_ptrs[i], "delete ", 7) == 0);

        /* Skip set/delete after config error — allow rollback, commit check,
         * exit, and show commands to continue so the session stays clean */
        if (skip_config && is_sd) {
            int w = snprintf(result->output + out_off,
                             sizeof(result->output) - out_off,
                             "%s%s>%s\nskipped: prior config error",
                             out_off > 0 ? "\n" : "",
                             conn->device.hostname, cmd_ptrs[i]);
            if (w > 0 && out_off + (size_t)w < sizeof(result->output))
                out_off += (size_t)w;
            fprintf(stderr, "[JunOS] Batch skip (config error): %s\n",
                    cmd_ptrs[i]);
            continue;
        }

        virp_exec_result_t sub;
        virp_error_t err = junos_execute_single(conn, cmd_ptrs[i], &sub);
        if (err != VIRP_OK) {
            result->success = false;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Driver error on command %d/%d: %s",
                     i + 1, cmd_count, cmd_ptrs[i]);
            break;
        }

        /* Append sub-command output */
        int w = snprintf(result->output + out_off,
                         sizeof(result->output) - out_off,
                         "%s%s",
                         out_off > 0 ? "\n" : "",
                         sub.output);
        if (w > 0 && out_off + (size_t)w < sizeof(result->output))
            out_off += (size_t)w;

        if (!sub.success) {
            result->success = false;
            if (result->error_msg[0] == '\0')
                snprintf(result->error_msg, sizeof(result->error_msg),
                         "%s", sub.error_msg);

            if (is_sd && conn->current_mode == JUNOS_MODE_CONFIGURE) {
                skip_config = true;
                fprintf(stderr, "[JunOS] Batch config error at cmd %d, "
                        "skipping remaining set/delete\n", i + 1);
            }
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &batch_end);
    result->exec_time_ms = (uint64_t)(
        (batch_end.tv_sec - batch_start.tv_sec) * 1000 +
        (batch_end.tv_nsec - batch_start.tv_nsec) / 1000000);
    result->output_len = out_off;
    result->exit_code = result->success ? 0 : 1;

    fprintf(stderr, "[JunOS] Batch done on %s: %d cmds, %s, %lums\n",
            conn->device.hostname, cmd_count,
            result->success ? "OK" : "FAILED",
            (unsigned long)result->exec_time_ms);

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect
 * ========================================================================= */

static void junos_disconnect(virp_conn_t *conn)
{
    if (!conn) return;

    if (conn->channel) {
        if (conn->connected) {
            libssh2_session_set_blocking(conn->session, 1);
            /* Exit gracefully — if in config mode, rollback and exit */
            if (conn->current_mode == JUNOS_MODE_CONFIGURE) {
                ssh_write(conn, "rollback 0\n");
                ssh_write(conn, "exit configuration-mode\n");
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

    fprintf(stderr, "[JunOS] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
    free(conn);
}

/* =========================================================================
 * Driver: detect
 * ========================================================================= */

static bool junos_detect(virp_conn_t *conn)
{
    if (!conn || !conn->connected) return false;
    return conn->device.vendor == VIRP_VENDOR_JUNIPER;
}

/* =========================================================================
 * Driver: health_check — "show system uptime" is lightweight on JunOS
 * ========================================================================= */

static virp_error_t junos_health_check(virp_conn_t *conn)
{
    if (!conn) return VIRP_ERR_NULL_PTR;
    if (!conn->connected) return VIRP_ERR_KEY_NOT_LOADED;

    virp_exec_result_t result;
    virp_error_t err = junos_execute(conn, "show system uptime", &result);
    if (err != VIRP_OK) return err;

    return result.success ? VIRP_OK : VIRP_ERR_KEY_NOT_LOADED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t junos_driver = {
    .name       = "juniper",
    .vendor     = VIRP_VENDOR_JUNIPER,
    .connect    = junos_connect,
    .execute    = junos_execute,
    .disconnect = junos_disconnect,
    .detect     = junos_detect,
    .health_check = junos_health_check,
};

const virp_driver_t *virp_driver_juniper(void)
{
    return &junos_driver;
}

void virp_driver_juniper_init(void)
{
    virp_driver_register(&junos_driver);
}
