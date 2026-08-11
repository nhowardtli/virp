/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco IOS Device Driver — real SSH communication via libssh2
 *
 * Handles:
 *   - Interactive SSH shell (IOS doesn't support exec channels well)
 *   - Legacy cipher negotiation (aes256-cbc, diffie-hellman-group14-sha1)
 *   - Prompt detection (hostname# or hostname>)
 *   - Enable mode entry
 *   - Terminal length 0 (no paging)
 *   - Output scrubbing (remove echoed command and trailing prompt)
 *   - Keyboard-interactive auth fallback (IOS 7200, IOS 15.x AAA)
 *
 * Ported from aiops_executor.c SSH patterns.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_ssh_io.h"
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
    virp_ssh_prompt_t   prompt;      /* learned at connect — see virp_ssh_io.h */
    virp_ssh_io_t       io;          /* shared read path transport adapter */
    bool                connected;
    bool                in_enable;
};

/* ── Transport adapter for the shared read path ─────────────────── */

static ssize_t cisco_io_read(void *ctx, char *buf, size_t len)
{
    virp_conn_t *conn = (virp_conn_t *)ctx;
    ssize_t n = libssh2_channel_read(conn->channel, buf, len);
    if (n == LIBSSH2_ERROR_EAGAIN)
        return VIRP_SSH_IO_EAGAIN;
    return n;
}

static ssize_t cisco_io_write(void *ctx, const char *buf, size_t len)
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
 * Keyboard-interactive auth callback for libssh2
 *
 * IOS 7200 (and many other IOS versions) only advertise
 * keyboard-interactive — not password. This callback supplies
 * the password for every prompt the server sends.
 *
 * Prompt cap: A legitimate IOS device sends 1–2 prompts (password,
 * sometimes OTP). A hostile or broken server could request thousands.
 * We cap at 4 to bound memory allocation.
 *
 * Ownership: libssh2 takes ownership of each responses[i].text and
 * calls free() on it after the callback returns. We strdup() the
 * password into each response. Because libssh2 frees the buffer
 * internally (not us), we cannot OPENSSL_cleanse the copy — the
 * password material persists in freed heap until overwritten. The
 * authoritative copy on conn->device.password is wiped at disconnect.
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
        fprintf(stderr, "[Cisco] keyboard-interactive: server sent %d prompts "
                "(max %d) — rejecting\n", num_prompts, KBD_MAX_PROMPTS);
        /* Zero all responses so libssh2 sees empty answers */
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
 * KEX method preference (issue #5)
 *
 * The default list covers every IOS-XE release and most in-service
 * classic IOS. The legacy list additionally offers
 * diffie-hellman-group1-sha1 for pre-2014 IOS 12.x trains (older 7200
 * NPE images, some catalyst classic) — these advertise only group1
 * and libssh2 will refuse to negotiate it unless we explicitly include
 * it. group1 is weak, so it stays gated on device->ssh_legacy.
 *
 * Exposed (non-static) so tests/test_driver_cisco.c can assert that
 * the default list is unaffected when ssh_legacy is false.
 * ========================================================================= */

static const char CISCO_KEX_DEFAULT[] =
    "ecdh-sha2-nistp256,"
    "ecdh-sha2-nistp384,"
    "ecdh-sha2-nistp521,"
    "diffie-hellman-group14-sha256,"
    "diffie-hellman-group14-sha1,"
    "diffie-hellman-group-exchange-sha256,"
    "diffie-hellman-group-exchange-sha1";

static const char CISCO_KEX_LEGACY[] =
    "ecdh-sha2-nistp256,"
    "ecdh-sha2-nistp384,"
    "ecdh-sha2-nistp521,"
    "diffie-hellman-group14-sha256,"
    "diffie-hellman-group14-sha1,"
    "diffie-hellman-group-exchange-sha256,"
    "diffie-hellman-group-exchange-sha1,"
    "diffie-hellman-group1-sha1";

const char *virp_cisco_kex_list(bool ssh_legacy)
{
    return ssh_legacy ? CISCO_KEX_LEGACY : CISCO_KEX_DEFAULT;
}

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
    conn->io.ctx = conn;
    conn->io.read = cisco_io_read;
    conn->io.write = cisco_io_write;

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

    /*
     * KEX preference (issue #5).
     *
     * Default: modern ECDH first, group14/group-exchange fallbacks. This
     * covers every IOS-XE release and most in-service classic IOS.
     *
     * When the device opts in via ssh_legacy=true, the very old
     * diffie-hellman-group1-sha1 is appended. group1 is the only KEX
     * advertised by some pre-2014 IOS 12.x trains (e.g. older 7200 NPE
     * images) and libssh2 won't negotiate it unless we explicitly offer
     * it. group1 stays opt-in because it's weak — adding it to every
     * Cisco session would silently lower the bar for modern devices.
     */
    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_KEX,
        virp_cisco_kex_list(device->ssh_legacy));

    if (device->ssh_legacy) {
        fprintf(stderr,
            "[Cisco] WARNING: ssh_legacy=true for %s — offering weak "
            "diffie-hellman-group1-sha1 KEX\n",
            device->hostname[0] ? device->hostname : device->host);
    }

    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_CS,
        "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc,3des-cbc");
    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_CRYPT_SC,
        "aes256-ctr,aes128-ctr,aes256-cbc,aes128-cbc,3des-cbc");

    libssh2_session_method_pref(conn->session, LIBSSH2_METHOD_HOSTKEY,
        "rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-ed25519");

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

    /* Verify host key before authentication */
    virp_error_t hk_err = virp_ssh_verify_hostkey(conn->session,
                                                   device->host, port);
    if (hk_err != VIRP_OK) {
        fprintf(stderr, "[Cisco] Host key verification failed: %s\n",
                virp_error_str(hk_err));
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        free(conn);
        return NULL;
    }

    /* Authentication — query supported methods, try each in order.
     * IOS 7200 devices typically only advertise keyboard-interactive,
     * while IOS-XE 16.x supports both password and keyboard-interactive. */
    bool authenticated = false;

    char *auth_list = libssh2_userauth_list(conn->session,
                                             device->username,
                                             (unsigned int)strlen(device->username));

    if (!auth_list && libssh2_userauth_authenticated(conn->session)) {
        /* "none" auth succeeded (unlikely on IOS, but handle it) */
        authenticated = true;
    }

    if (auth_list) {
        fprintf(stderr, "[Cisco] Auth methods for %s@%s: %s\n",
                device->username, device->host, auth_list);
    }

    /* Try keyboard-interactive first (IOS 7200, IOS 15.x AAA) */
    if (!authenticated && auth_list && strstr(auth_list, "keyboard-interactive")) {
        *libssh2_session_abstract(conn->session) = (void *)device->password;

        if (libssh2_userauth_keyboard_interactive(conn->session,
                                                   device->username,
                                                   kbd_interactive_callback) == 0) {
            authenticated = true;
            fprintf(stderr, "[Cisco] Auth OK (keyboard-interactive): %s@%s\n",
                    device->username, device->host);
        }
    }

    /* Fallback to password auth (IOS-XE, some ISR platforms) */
    if (!authenticated && auth_list && strstr(auth_list, "password")) {
        if (libssh2_userauth_password(conn->session,
                                       device->username,
                                       device->password) == 0) {
            authenticated = true;
            fprintf(stderr, "[Cisco] Auth OK (password): %s@%s\n",
                    device->username, device->host);
        }
    }

    if (!authenticated) {
        char *errmsg;
        libssh2_session_last_error(conn->session, &errmsg, NULL, 0);
        fprintf(stderr, "[Cisco] All auth methods failed for %s@%s: %s "
                "(server offered: %s)\n",
                device->username, device->host, errmsg,
                auth_list ? auth_list : "none");
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

    /* Request PTY — IOS needs this for interactive shell; 200 cols */
    if (libssh2_channel_request_pty_ex(conn->channel, "vt100", 5,
                                        NULL, 0, 200, 24, 0, 0) != 0) {
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

    /*
     * Connect-time reads run before a prompt exists to match, so they
     * are quiescence-based. Nothing read here is ever signed — it is
     * discarded or pattern-matched for the enable password prompt.
     */
    char scratch[4096];
    size_t setup_bytes =
        virp_ssh_read_quiescent(&conn->io, scratch, sizeof(scratch), 5000);

    /* Disable paging */
    ssh_write(conn, "terminal length 0\n");
    setup_bytes += virp_ssh_read_quiescent(&conn->io, scratch,
                                           sizeof(scratch), 3000);

    /* Enter enable mode if we have an enable password */
    if (device->enable_password[0] != '\0') {
        ssh_write(conn, "enable\n");
        setup_bytes += virp_ssh_read_quiescent(&conn->io, scratch,
                                               sizeof(scratch), 3000);

        /* If we got a password prompt, send enable password */
        if (strstr(scratch, "assword") != NULL) {
            char enable_cmd[256];
            snprintf(enable_cmd, sizeof(enable_cmd), "%s\n",
                     device->enable_password);
            ssh_write(conn, enable_cmd);
            setup_bytes += virp_ssh_read_quiescent(&conn->io, scratch,
                                                   sizeof(scratch), 3000);
        }

        /* Disable paging again in enable mode */
        ssh_write(conn, "terminal length 0\n");
        setup_bytes += virp_ssh_read_quiescent(&conn->io, scratch,
                                               sizeof(scratch), 3000);
    }

    /*
     * Learn the prompt. Every later read matches it exactly, so a
     * connection without one cannot produce a trustworthy observation:
     * failure here fails the connect. No heuristic fallback.
     */
    virp_ssh_learn_opts_t lopts = { .channel_has_spoken = setup_bytes > 0 };
    if (virp_ssh_learn_prompt(&conn->io, device->hostname, &lopts,
                              &conn->prompt) != VIRP_OK) {
        fprintf(stderr, "[Cisco] Prompt learning failed — refusing connection "
                "to %s (%s:%u)\n", device->hostname, device->host, port);
        libssh2_channel_close(conn->channel);
        libssh2_channel_free(conn->channel);
        libssh2_session_disconnect(conn->session, "prompt learn failed");
        libssh2_session_free(conn->session);
        close(conn->sock_fd);
        OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
        free(conn);
        return NULL;
    }

    conn->connected = true;
    conn->in_enable = (conn->prompt.prompt_len > 0 &&
                       conn->prompt.prompt[conn->prompt.prompt_len - 1] == '#');

    fprintf(stderr, "[Cisco] Connected: %s@%s:%u prompt='%s' enable=%d\n",
            device->username, device->host, port,
            conn->prompt.prompt, conn->in_enable);

    return conn;
}

/* =========================================================================
 * Driver: execute
 * ========================================================================= */

/* =========================================================================
 * BLACK Tier — Destructive commands that must never reach the wire.
 *
 * These are prefix-matched (case-insensitive).  Any command that starts
 * with one of these strings is rejected outright — no SSH, no approval
 * queue, no code path.
 *
 * DELIBERATELY still case-insensitive after the 2026-08-09
 * classified≠executed fix made the tier table exact-match: this is a
 * DENY list, and over-matching a deny list is the fail-closed
 * direction. "RELOAD" must stay BLACK (unapprovable, never
 * transmitted), not fall through to RED-by-absence where the
 * propose/approve path could in principle reach it. Nothing matched
 * here ever executes, so the invariant "the classified bytes are the
 * executed bytes" is untouched by the wider match.
 * ========================================================================= */

static const char *CISCO_BLACK_COMMANDS[] = {
    "reload",
    "write erase",
    "erase startup-config",
    "erase startup",
    "delete flash:",
    "delete bootflash:",
    "delete nvram:",
    "squeeze flash:",
    "format flash:",
    "format bootflash:",
};
static const size_t CISCO_BLACK_COUNT =
    sizeof(CISCO_BLACK_COMMANDS) / sizeof(CISCO_BLACK_COMMANDS[0]);

bool cisco_is_black_tier(const char *command)
{
    if (!command) return false;
    for (size_t i = 0; i < CISCO_BLACK_COUNT; i++) {
        size_t plen = strlen(CISCO_BLACK_COMMANDS[i]);
        if (strncasecmp(command, CISCO_BLACK_COMMANDS[i], plen) == 0)
            return true;
    }
    return false;
}

/* =========================================================================
 * Gate classifier — SHARED CORE for classic IOS and IOS-XE
 *
 * Longest-prefix match, CASE-SENSITIVE (2026-08-09: the driver executes
 * the caller's original bytes, so the classifier may not vouch for any
 * spelling it did not literally see — "SHOW VERSION" is not "show
 * version" and falls through RED, exactly as abbreviations already
 * did). FAIL-CLOSED: unmatched -> RED.
 * BLACK is handled separately by cisco_is_black_tier() and is NOT in this
 * table. The XE-delta table is intentionally empty for now — cisco_ios and
 * cisco_iosxe share this core until shadow evidence justifies a delta.
 * ========================================================================= */

typedef struct { const char *prefix; virp_trust_tier_t tier; } cisco_route_t;

static const cisco_route_t CISCO_GATE_TABLE[] = {
    /* ── GREEN — read-only status/monitoring (explicit allow-list) ── */
    { "show version",                 VIRP_TIER_GREEN  },
    { "show ip interface brief",      VIRP_TIER_GREEN  },
    { "show interfaces",              VIRP_TIER_GREEN  },
    { "show ip route",                VIRP_TIER_GREEN  },
    { "show cdp neighbors",           VIRP_TIER_GREEN  },
    { "show lldp neighbors",          VIRP_TIER_GREEN  },
    { "show inventory",               VIRP_TIER_GREEN  },
    { "show processes",               VIRP_TIER_GREEN  },
    { "show clock",                   VIRP_TIER_GREEN  },
    { "show environment",             VIRP_TIER_GREEN  },
    { "show ip protocols",            VIRP_TIER_GREEN  },
    { "show vlan",                    VIRP_TIER_GREEN  },
    { "show spanning-tree",           VIRP_TIER_GREEN  },
    { "show mac address-table",       VIRP_TIER_GREEN  },
    { "show ip arp",                  VIRP_TIER_GREEN  },
    /* Shadow-evidence promotions (2026-07-16): routing adjacency + status */
    { "show ip ospf",                 VIRP_TIER_GREEN  },
    { "show ip bgp",                  VIRP_TIER_GREEN  },
    { "show ip eigrp",                VIRP_TIER_GREEN  },
    { "show ip ssh",                  VIRP_TIER_GREEN  },
    { "show arp",                     VIRP_TIER_GREEN  },
    { "show etherchannel",            VIRP_TIER_GREEN  },
    { "show redundancy",              VIRP_TIER_GREEN  },
    { "show platform",                VIRP_TIER_GREEN  },
    { "show memory",                  VIRP_TIER_GREEN  },
    { "show ntp",                     VIRP_TIER_GREEN  },
    { "show bootvar",                 VIRP_TIER_GREEN  },
    { "show boot",                    VIRP_TIER_GREEN  },
    { "show file systems",            VIRP_TIER_GREEN  },

    /* ── YELLOW — config-visibility reads (backups/audits) ────────── */
    /* Reverted GREEN → YELLOW (2026-08-11): the scrub misses whole
     * secret classes (server-block `key 0 <numeric>` among them), so
     * the GREEN row let a GREEN-ceiling requester auto-sign credential
     * material into the append-only chain. The scrub stays wired —
     * approval gates the read, the scrub still cleans the body. */
    { "show running-config",          VIRP_TIER_YELLOW },
    { "show startup-config",          VIRP_TIER_YELLOW },
    { "show access-lists",            VIRP_TIER_YELLOW },
    { "show ip nat translations",     VIRP_TIER_YELLOW },
    { "show tech-support",            VIRP_TIER_YELLOW },  /* dump incl. config */
    /* Shadow-evidence promotions (2026-07-16): config-visibility, security
     * posture (SA state), session visibility, and active diagnostics.
     * "show crypto" (read) is distinct from bare "crypto" (write=RED). */
    { "show ip access-lists",         VIRP_TIER_YELLOW },
    { "show crypto",                  VIRP_TIER_YELLOW },
    { "show logging",                 VIRP_TIER_YELLOW },
    { "show users",                   VIRP_TIER_YELLOW },
    { "show port-security",           VIRP_TIER_YELLOW },  /* per-port security config */
    { "ping",                         VIRP_TIER_YELLOW },
    { "traceroute",                   VIRP_TIER_YELLOW },
    /* Reclassified RED → YELLOW (2026-07-23): counter reset is a
     * diagnostic action, not a config write. Bare "clear " stays RED
     * via the fail-closed default. */
    { "clear counters",               VIRP_TIER_YELLOW },

    /* ── RED — config writes (explicit for audit; default also RED) ── */
    { "configure terminal",           VIRP_TIER_RED    },
    { "configure",                    VIRP_TIER_RED    },
    { "conf t",                       VIRP_TIER_RED    },
    { "interface",                    VIRP_TIER_RED    },
    { "ip route",                     VIRP_TIER_RED    },
    { "router bgp",                   VIRP_TIER_RED    },
    { "router ospf",                  VIRP_TIER_RED    },
    { "router eigrp",                 VIRP_TIER_RED    },
    { "router",                       VIRP_TIER_RED    },
    { "no ",                          VIRP_TIER_RED    },  /* negation = write */
    { "hostname",                     VIRP_TIER_RED    },

    /* ── RED — credential/security writes (adversarial; each tested) ─ */
    { "username",                     VIRP_TIER_RED    },  /* incl. privilege 15 / secret / password */
    { "enable secret",                VIRP_TIER_RED    },
    { "enable password",              VIRP_TIER_RED    },
    { "aaa",                          VIRP_TIER_RED    },
    { "tacacs-server",                VIRP_TIER_RED    },
    { "tacacs server",                VIRP_TIER_RED    },  /* IOS-XE form */
    { "radius-server",                VIRP_TIER_RED    },
    { "radius server",                VIRP_TIER_RED    },  /* IOS-XE form */
    { "snmp-server community",        VIRP_TIER_RED    },
    { "snmp-server",                  VIRP_TIER_RED    },
    { "crypto key",                   VIRP_TIER_RED    },
    { "crypto pki",                   VIRP_TIER_RED    },
    { "crypto",                       VIRP_TIER_RED    },
    { "key chain",                    VIRP_TIER_RED    },
    { "key config-key",               VIRP_TIER_RED    },  /* master key */
    { "line vty",                     VIRP_TIER_RED    },
    { "line",                         VIRP_TIER_RED    },
    { "login",                        VIRP_TIER_RED    },
    { "password",                     VIRP_TIER_RED    },
};
static const size_t CISCO_GATE_TABLE_SIZE =
    sizeof(CISCO_GATE_TABLE) / sizeof(CISCO_GATE_TABLE[0]);

/*
 * Test-support accessors — let a test iterate the gate table without
 * exposing its struct layout (virp_driver_cisco.h cannot be included
 * standalone, so the table itself stays static). Used by the
 * table-driven reachability suite: every entry must classify as the
 * tier it declares, or it is shadowed by a broader/earlier entry and
 * would never fire in production.
 */
size_t cisco_gate_table_count(void)
{
    return CISCO_GATE_TABLE_SIZE;
}

const char *cisco_gate_table_entry(size_t i, virp_trust_tier_t *tier)
{
    if (i >= CISCO_GATE_TABLE_SIZE) return NULL;
    if (tier) *tier = CISCO_GATE_TABLE[i].tier;
    return CISCO_GATE_TABLE[i].prefix;
}

virp_trust_tier_t cisco_gate_tier(const char *command)
{
    if (!command) return VIRP_TIER_RED;              /* fail closed */

    /*
     * Layer 2a — a separator-carrying string is not one command, so this
     * table cannot vouch for it. Fail closed here as well as at the
     * daemon boundary: the classifier is called directly by tests and
     * (via route_command) by any future caller, and must not hand back a
     * benign tier for "show version;reload" just because the daemon
     * would have refused it first.
     */
    if (virp_command_check_separators(command, NULL, 0) != 0)
        return VIRP_TIER_RED;

    while (*command == ' ' || *command == '\t') command++;

    const cisco_route_t *best = NULL;
    size_t best_len = 0;
    for (size_t i = 0; i < CISCO_GATE_TABLE_SIZE; i++) {
        size_t plen = strlen(CISCO_GATE_TABLE[i].prefix);
        if (strncmp(command, CISCO_GATE_TABLE[i].prefix, plen) != 0)
            continue;

        /*
         * Layer 2b — the match must END on a token boundary, so a listed
         * prefix can never stand in for a longer word: "show boot"
         * (GREEN) must not classify "show bootleg", and "no " must not
         * be reached by "nonsense". Entries that already end in a space
         * carry their own boundary.
         */
        char after = command[plen];
        bool self_terminated =
            (plen > 0 && CISCO_GATE_TABLE[i].prefix[plen - 1] == ' ');
        if (!self_terminated && after != '\0' &&
            after != ' ' && after != '\t')
            continue;

        if (plen > best_len) { best = &CISCO_GATE_TABLE[i]; best_len = plen; }
    }
    /* Fail-closed: anything not explicitly GREEN/YELLOW/RED-listed is RED. */
    return best ? best->tier : VIRP_TIER_RED;
}

/* =========================================================================
 * Credential scrub for config-bearing reads
 *
 * IOS `show running-config` (and startup-config / tech-support) carries
 * the device's credential material inline: `enable secret 5 $1$...`,
 * `username ... password 7 ...`, SNMP communities, ISAKMP pre-shared
 * keys, routing-protocol MD5 keys, key-chain key-strings. Observation
 * bodies are HMAC-signed and appended to a chain that cannot be
 * trimmed, so a single unscrubbed config read pins that material into
 * the audit record forever. The scrub therefore runs INSIDE the driver,
 * on the reply body, BEFORE the result is handed back to the O-Node
 * signer — never after.
 *
 * Same shape as fg_scrub_reply: a pure function over the reply text,
 * exposed (non-static) so tests can drive it with recorded config
 * shapes, with a fail-closed contract — if the scrub cannot complete
 * (output would not fit), the caller reports a typed ERROR instead of
 * signing an unscrubbed or truncated body.
 *
 * Redaction model (RANCID/Oxidized-style, deliberately over-broad —
 * over-redaction is the fail-closed direction):
 *   - a line whose token stream contains one of the secret-bearing
 *     keywords (password, secret, community, key-string, md5,
 *     authentication-key, pre-shared-key, passphrase) has everything
 *     AFTER that keyword replaced with "<removed>";
 *   - `crypto isakmp key [enc] SECRET address ...` redacts only the
 *     key token so the peer address stays visible;
 *   - `snmp-server host <ip> ...` redacts everything after the host —
 *     the trailing community string is positional, not keyword-marked;
 *   - `standby|vrrp ... authentication ...` redacts after
 *     `authentication`;
 *   - a line whose FIRST token is `key` (tacacs/radius server-block
 *     `key 7 SECRET`) is redacted unless the remainder is purely
 *     numeric (`key 1` — a key-chain index, not a secret) or the next
 *     token is `chain` (`key chain NAME` — a block header).
 * Exact-token matching keeps non-secret lines untouched:
 * `service password-encryption` and `ip ospf authentication
 * message-digest` carry no value and are preserved verbatim.
 * ========================================================================= */

#define CISCO_SCRUB_MARK "<removed>"

/* Longest growth per line: a redaction appends "<removed>" after the
 * keyword; sizing the output at 3x input + slack makes overflow a
 * cannot-happen guarded anyway by the fail-closed contract. */
#define CISCO_SCRUB_CAP(len) (3 * (len) + 64)

static bool tok_eq(const char *tok, size_t len, const char *word)
{
    return strlen(word) == len && strncmp(tok, word, len) == 0;
}

/* Emit helper: append [src, src+n) to out, fail on overflow. */
static bool scrub_emit(char *out, size_t cap, size_t *pos,
                       const char *src, size_t n)
{
    if (*pos + n >= cap) return false;
    memcpy(out + *pos, src, n);
    *pos += n;
    return true;
}

/*
 * Scrub one line [line, line+len) (terminator excluded) into out.
 * Returns false only on output overflow.
 */
static bool scrub_line(const char *line, size_t len,
                       char *out, size_t cap, size_t *pos)
{
    static const char *SECRET_KEYWORDS[] = {
        "password", "secret", "community", "key-string",
        "authentication-key", "md5", "sha", "pre-shared-key",
        "passphrase",
    };
    static const size_t SECRET_KEYWORD_COUNT =
        sizeof(SECRET_KEYWORDS) / sizeof(SECRET_KEYWORDS[0]);

    /* Walk tokens; remember where the first secret-bearing keyword
     * ends so everything after it can be replaced. */
    size_t i = 0;
    size_t tok_index = 0;
    size_t cut = 0;              /* redact from here (0 = no redaction) */
    bool   first_is_key = false; /* leading token is bare `key` */
    bool   first_is_aaa = false; /* tacacs-server / radius-server */
    bool   standby_line = false; /* standby / vrrp line */
    size_t isakmp_state = 0;     /* tokens matched of crypto/isakmp/key */
    size_t snmp_host_state = 0;  /* tokens matched of snmp-server/host */
    size_t nhrp_state = 0;       /* tokens matched of ip/nhrp */

    while (i < len && cut == 0) {
        while (i < len && (line[i] == ' ' || line[i] == '\t')) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && line[i] != ' ' && line[i] != '\t') i++;
        const char *tok = line + start;
        size_t tlen = i - start;

        if (tok_index == 0) {
            if (tok_eq(tok, tlen, "key"))     first_is_key = true;
            if (tok_eq(tok, tlen, "crypto"))  isakmp_state = 1;
            if (tok_eq(tok, tlen, "snmp-server")) snmp_host_state = 1;
            if (tok_eq(tok, tlen, "ip"))      nhrp_state = 1;
            if (tok_eq(tok, tlen, "standby") || tok_eq(tok, tlen, "vrrp"))
                standby_line = true;
            if (tok_eq(tok, tlen, "tacacs-server") ||
                tok_eq(tok, tlen, "radius-server"))
                first_is_aaa = true;
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
                if (!tok_eq(tok, tlen, "chain") &&
                    !(numeric && rest >= len))
                    cut = start;
                first_is_key = false;
            }
            if (first_is_aaa && tok_eq(tok, tlen, "key")) {
                /* `tacacs-server key [7] SECRET` — secret follows */
                size_t j = i;
                while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
                if (j < len) cut = j;
            }
            if (isakmp_state == 1 && tok_eq(tok, tlen, "isakmp"))
                isakmp_state = 2;
            else
                isakmp_state = 0;
            if (snmp_host_state == 1 && tok_eq(tok, tlen, "host"))
                snmp_host_state = 2;
            else
                snmp_host_state = 0;
            if (nhrp_state == 1 && tok_eq(tok, tlen, "nhrp"))
                nhrp_state = 2;
            else
                nhrp_state = 0;
        } else if (isakmp_state == 2 && tok_eq(tok, tlen, "key")) {
            /* `crypto isakmp key [0|6|7] SECRET address A.B.C.D`:
             * redact the key token only, keep the address visible. */
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            size_t s2 = j;
            while (j < len && line[j] != ' ' && line[j] != '\t') j++;
            if (j - s2 == 1 && (line[s2] == '0' || line[s2] == '6' ||
                                line[s2] == '7')) {
                /* encryption-type token — the secret is the NEXT one */
                while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
                s2 = j;
                while (j < len && line[j] != ' ' && line[j] != '\t') j++;
            }
            if (s2 < len) {
                if (!scrub_emit(out, cap, pos, line, s2) ||
                    !scrub_emit(out, cap, pos, CISCO_SCRUB_MARK,
                                strlen(CISCO_SCRUB_MARK)) ||
                    !scrub_emit(out, cap, pos, line + j, len - j))
                    return false;
                return true;
            }
            isakmp_state = 0;
        } else if (snmp_host_state == 2) {
            /* Past `snmp-server host <ip>`: the rest is positional and
             * ends in a community string — redact all of it. */
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            if (j < len) cut = j;
            snmp_host_state = 0;
        }

        /* `standby [grp] authentication ...` / `vrrp ...` — the value
         * after `authentication` is the secret (or a md5/key-string
         * form the generic keywords would also catch). Checked at any
         * token position: the group number is optional. */
        if (cut == 0 && standby_line && tok_index >= 1 &&
            tok_eq(tok, tlen, "authentication")) {
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            if (j < len) cut = j;
        }

        /* `ip nhrp authentication <string>` — the DMVPN auth string
         * is a secret; same shape as the standby/vrrp rule
         * (2026-08-11). Other `ip nhrp …` subcommands (map, nhs,
         * holdtime) carry no secret and pass untouched. */
        if (cut == 0 && nhrp_state == 2 && tok_index >= 2 &&
            tok_eq(tok, tlen, "authentication")) {
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            if (j < len) cut = j;
        }

        /* Mid-line `key <value>` (2026-08-11): real IOS puts AAA keys
         * past token 0 — `tacacs-server host <ip> key 7 …`,
         * `radius-server host … key …`, `server-private … key 7 …`.
         * Redact everything after the `key` token. Token-0 `key`
         * keeps its key-chain handling above (block header / bare
         * numeric index); mid-line there is no index form, so a
         * purely numeric value redacts too. `crypto isakmp key`
         * never reaches here — its branch emits and returns,
         * keeping the peer address visible. */
        if (cut == 0 && tok_index >= 1 && tok_eq(tok, tlen, "key")) {
            size_t j = i;
            while (j < len && (line[j] == ' ' || line[j] == '\t')) j++;
            if (j < len) cut = j;
        }

        if (cut == 0) {
            for (size_t k = 0; k < SECRET_KEYWORD_COUNT; k++) {
                if (tok_eq(tok, tlen, SECRET_KEYWORDS[k])) {
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
        return scrub_emit(out, cap, pos, line, len);

    return scrub_emit(out, cap, pos, line, cut) &&
           scrub_emit(out, cap, pos, CISCO_SCRUB_MARK,
                      strlen(CISCO_SCRUB_MARK));
}

/*
 * Pure scrub: rewrite config text so no credential material survives.
 * Exposed (non-static) for the unit suite — see fg_scrub_reply for the
 * precedent. Fail-closed: VIRP_ERR_BUFFER_TOO_SMALL means the caller
 * must NOT use (or sign) any partial output.
 */
virp_error_t cisco_scrub_config(const char *in, size_t in_len,
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

        if (!scrub_line(in + start, content_end - start, out, out_cap, &pos))
            return VIRP_ERR_BUFFER_TOO_SMALL;
        /* terminator bytes verbatim (\r\n, \n, or none at EOF) */
        if (!scrub_emit(out, out_cap, &pos, in + content_end,
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
 * Commands whose reply embeds device configuration (and therefore
 * credential material). Matches the gate table's literal spellings —
 * abbreviations never reach GREEN/YELLOW (fail-closed classifier), so
 * prefix-matching the canonical forms here is exhaustive.
 */
bool cisco_command_returns_config(const char *command)
{
    if (!command) return false;
    while (*command == ' ' || *command == '\t') command++;
    return strncmp(command, "show running-config", 19) == 0 ||
           strncmp(command, "show startup-config", 19) == 0 ||
           strncmp(command, "show tech-support",   17) == 0;
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
virp_error_t cisco_store_output(virp_exec_result_t *result,
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

static virp_error_t cisco_execute(virp_conn_t *conn,
                                  const char *command,
                                  virp_exec_result_t *result)
{
    if (!conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));

    /* ── BLACK tier safety: never execute destructive commands ── */
    if (cisco_is_black_tier(command)) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "BLACK tier: command blocked on %s", conn->device.hostname);
        fprintf(stderr, "[Cisco] BLACK tier blocked: '%s' on %s\n",
                command, conn->device.hostname);
        int written = snprintf(result->output, sizeof(result->output),
                               "%s#%s\nBLACK tier: command forbidden",
                               conn->device.hostname, command);
        result->output_len = (written > 0) ? (size_t)written : 0;
        return VIRP_OK;
    }

    if (!conn->connected) {
        result->success = false;
        result->no_dispatch = true;   /* refused before any transport write */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return VIRP_OK;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /*
     * Shared read path: drain residue, send, read until the LEARNED
     * prompt. The prompt is stripped by the helper.
     */
    char raw_output[VIRP_OUTPUT_MAX];
    size_t n = 0;
    virp_error_t rerr = virp_ssh_exec(&conn->io, &conn->prompt, command,
                                      raw_output, sizeof(raw_output), &n,
                                      SSH_READ_TIMEOUT_MS,
                                      conn->device.hostname);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

    if (rerr == VIRP_ERR_NO_PROMPT) {
        /*
         * Incomplete read. Returning a hard error (rather than VIRP_OK
         * with a short body) is what makes the O-Node emit a typed
         * ERROR observation instead of signing a truncated body as
         * device output.
         */
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

    /* Strip the echoed command by matching its text, not by position. */
    char *output_start = virp_ssh_strip_echo(raw_output, command);

    /* Strip trailing \r\n */
    size_t clean_len = strlen(output_start);
    while (clean_len > 0 &&
           (output_start[clean_len - 1] == '\r' ||
            output_start[clean_len - 1] == '\n')) {
        output_start[--clean_len] = '\0';
    }

    /*
     * Credential scrub for config-bearing reads. This MUST happen here,
     * before the body is copied into result->output: what leaves this
     * function is what the O-Node signs into the append-only chain.
     * Fail-closed — if the scrub cannot complete, report a typed ERROR
     * rather than signing an unscrubbed body.
     */
    char *scrubbed = NULL;
    if (cisco_command_returns_config(command)) {
        size_t cap = CISCO_SCRUB_CAP(clean_len);
        scrubbed = malloc(cap);
        size_t scrubbed_len = 0;
        virp_error_t serr = scrubbed
            ? cisco_scrub_config(output_start, clean_len,
                                 scrubbed, cap, &scrubbed_len)
            : VIRP_ERR_BUFFER_TOO_SMALL;
        if (serr != VIRP_OK) {
            free(scrubbed);
            fprintf(stderr, "[Cisco] Config scrub failed on %s "
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

    /* Format: hostname#command\noutput — actual-length accounting and
     * honest truncation/withhold live in cisco_store_output. */
    virp_error_t werr = cisco_store_output(result, conn->device.hostname,
                                           command, output_start,
                                           scrubbed != NULL);
    if (werr != VIRP_OK) {
        fprintf(stderr, "[Cisco] %s\n", result->error_msg);
        free(scrubbed);
        return werr;
    }
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

    free(scrubbed);
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

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
    OPENSSL_cleanse(conn->device.enable_password, sizeof(conn->device.enable_password));
    free(conn);
}

/* =========================================================================
 * Driver: detect
 * ========================================================================= */

static bool cisco_detect(virp_conn_t *conn)
{
    if (!conn || !conn->connected) return false;

    /* If the prompt contains # or > and we got a response to
     * "terminal length 0" without error, it's probably IOS/IOS-XE */
    return conn->device.vendor == VIRP_VENDOR_CISCO_IOS ||
           conn->device.vendor == VIRP_VENDOR_CISCO_IOSXE;
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
    .route_command = cisco_gate_tier,
};

/* IOS-XE: identical driver functions + the SAME shared gate core
 * (cisco_gate_tier). Distinct vendor/name so the gate can address IOS vs
 * IOS-XE independently (separate gate_modes keys) and log which variant a
 * command hit, while the classifier itself is shared. */
static virp_driver_t cisco_iosxe_driver = {
    .name       = "cisco_iosxe",
    .vendor     = VIRP_VENDOR_CISCO_IOSXE,
    .connect    = cisco_connect,
    .execute    = cisco_execute,
    .disconnect = cisco_disconnect,
    .detect     = cisco_detect,
    .health_check = cisco_health_check,
    .route_command = cisco_gate_tier,
};

void virp_driver_cisco_init(void)
{
    virp_driver_register(&cisco_driver);
    virp_driver_register(&cisco_iosxe_driver);
}
