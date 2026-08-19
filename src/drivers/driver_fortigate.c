/*
 * driver_fortigate.c — FortiGate device driver implementation
 *
 * Ported to VIRP appliance type system (fixed buffers, virp_driver.h).
 *
 * Implements the five virp_driver_t functions:
 *   connect     — Establish SSH connection
 *   execute     — Run command via SSH, return output
 *   disconnect  — Tear down SSH transport
 *   detect      — Probe device to confirm it's a FortiGate
 *   health_check — Verify device is responsive and healthy
 *
 * SSH-only transport. Commands collected:
 *   get system status
 *   get system performance status
 *   get router info bgp summary
 *   get system interface physical
 *   diagnose sys session stat
 *
 * Dependencies:
 *   - libssh2 (SSH transport)
 *   - libssl  (TLS, already a VIRP dependency)
 *
 * Build:  make CISCO=1 FORTIGATE=1
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <libssh2.h>
#include <openssl/crypto.h>

#include "virp_driver.h"
#include "virp_driver_fortigate.h"
#include "virp_ssh_hostkey.h"


/* ══════════════════════════════════════════════════════════════════
 * CONNECTION STATE
 *
 * Appliance pattern: each driver defines its own 'struct virp_conn'.
 * The O-Node sees only an opaque pointer.
 * ══════════════════════════════════════════════════════════════════ */

struct virp_conn {
    virp_device_t       device;         /* Copy of device config */

    /* SSH transport */
    LIBSSH2_SESSION    *ssh_session;
    int                 ssh_socket;
    int                 ssh_port;

    /* State */
    bool                ssh_connected;
    bool                vdom_enabled;
    bool                vdom_probed;
};


/* ══════════════════════════════════════════════════════════════════
 * SSH HELPERS
 * ══════════════════════════════════════════════════════════════════ */

#define FG_SSH_READ_TIMEOUT_MS  15000
#define FG_SSH_BUFFER_SIZE      65536

static int fg_ssh_connect(struct virp_conn *conn)
{
    struct sockaddr_in sin;
    int sock;
    int rc;
    char *errmsg = NULL;
    int errlen = 0;

    fprintf(stderr, "[virp-fg] SSH connect to %s:%d as %s\n",
            conn->device.host, conn->ssh_port, conn->device.username);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        fprintf(stderr, "[virp-fg] socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(conn->ssh_port);

    if (inet_pton(AF_INET, conn->device.host, &sin.sin_addr) <= 0) {
        fprintf(stderr, "[virp-fg] inet_pton(%s) failed: %s\n",
                conn->device.host, strerror(errno));
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&sin, sizeof(sin)) != 0) {
        fprintf(stderr, "[virp-fg] TCP connect to %s:%d failed: %s\n",
                conn->device.host, conn->ssh_port, strerror(errno));
        close(sock);
        return -1;
    }

    fprintf(stderr, "[virp-fg] TCP connected, starting libssh2 handshake\n");
    conn->ssh_socket = sock;

    LIBSSH2_SESSION *session = libssh2_session_init();
    if (!session) {
        fprintf(stderr, "[virp-fg] libssh2_session_init() returned NULL\n");
        close(sock);
        return -1;
    }

    libssh2_session_set_timeout(session, 30000);

    rc = libssh2_session_handshake(session, sock);
    if (rc != 0) {
        libssh2_session_last_error(session, &errmsg, &errlen, 0);
        fprintf(stderr, "[virp-fg] libssh2_session_handshake() failed: "
                "rc=%d errmsg=\"%s\"\n", rc, errmsg ? errmsg : "(null)");
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    fprintf(stderr, "[virp-fg] handshake OK, verifying host key\n");

    virp_error_t hk_err = virp_ssh_verify_hostkey(session, conn->device.host,
                                                   conn->ssh_port);
    if (hk_err != VIRP_OK) {
        fprintf(stderr, "[virp-fg] Host key verification failed: %s\n",
                virp_error_str(hk_err));
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    rc = libssh2_userauth_password(session,
                                   conn->device.username,
                                   conn->device.password);
    if (rc != 0) {
        libssh2_session_last_error(session, &errmsg, &errlen, 0);
        fprintf(stderr, "[virp-fg] libssh2_userauth_password() failed: "
                "rc=%d errmsg=\"%s\"\n", rc, errmsg ? errmsg : "(null)");
        libssh2_session_free(session);
        close(sock);
        return -1;
    }

    fprintf(stderr, "[virp-fg] SSH authenticated to %s:%d\n",
            conn->device.host, conn->ssh_port);

    conn->ssh_session = session;
    conn->ssh_connected = true;

    return 0;
}

/* Returns true if command requires VDOM context (routing/diag commands) */
static bool fg_command_needs_vdom(const char *command)
{
    while (*command == ' ' || *command == '\t') command++;

    return (strncasecmp(command, "get router ",      11) == 0
         || strncasecmp(command, "show router ",     12) == 0
         || strncasecmp(command, "diagnose ",         9) == 0);
}

/*
 * FortiGate output scrubbing.
 *
 * FortiOS echoes every line it is sent, each preceded by a prompt, so a
 * VDOM-wrapped command comes back roughly as:
 *
 *   FGT # config vdom
 *   FGT (vdom) # edit <vdom>
 *   current vf=<vdom>:0
 *   FGT (<vdom>) # <command>
 *   <the output we actually want>
 *   FGT (<vdom>) # end
 *   FGT #
 *
 * The previous scrub dropped only the FIRST line, so `edit <vdom>`, the
 * command echo and the trailing `end` echo all landed inside the SIGNED
 * observation body. Locating the boundaries by matching the text we
 * sent — rather than by counting lines — is what keeps the body to the
 * device's actual answer.
 */

/* Start of the line following the first line that contains `needle`. */
char *fg_line_after_containing(char *buf, const char *needle)
{
    char *hit = strstr(buf, needle);
    if (!hit) return NULL;
    char *nl = strchr(hit, '\n');
    return nl ? nl + 1 : NULL;
}

/*
 * Start of the last line whose content (after any "prompt # " prefix) is
 * exactly `word`. Used to find the trailing `end` echo.
 */
char *fg_find_last_echo_line(char *buf, const char *word)
{
    size_t wlen = strlen(word);
    char *best = NULL;
    char *line = buf;

    while (line && *line) {
        char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);

        /* Skip a leading "<prompt> # " if present. */
        const char *content = line;
        size_t clen = len;
        for (size_t i = 0; i + 1 < len; i++) {
            if (line[i] == '#' && line[i + 1] == ' ') {
                content = line + i + 2;
                clen = len - (i + 2);
            }
        }
        while (clen > 0 && (content[clen - 1] == '\r' ||
                            content[clen - 1] == ' '))
            clen--;

        if (clen == wlen && strncmp(content, word, wlen) == 0)
            best = line;

        line = nl ? nl + 1 : NULL;
    }
    return best;
}


/*
 * Pure scrub: given the raw reply, return the device's answer.
 *
 * Returns NULL if the command echo is absent — meaning the reply cannot
 * be reduced to a trustworthy body, which the caller reports as an
 * error rather than guessing at boundaries. Exposed (non-static) so
 * tests can drive it with recorded FortiOS transcripts; the SSH path
 * around it needs a live device.
 */
char *fg_scrub_reply(char *raw, size_t total, const char *command,
                     bool vdom_wrapped, size_t *out_len)
{
    if (!raw || !command || !out_len) return NULL;
    *out_len = 0;

    char *start = fg_line_after_containing(raw, command);
    if (!start)
        return NULL;

    char *end = raw + total;

    /*
     * Cut at the trailing `end` echo that closes the VDOM wrapper. The
     * LAST such line is the wrapper's: FortiOS config output can itself
     * contain `end` lines (a `show router ...` block ends with one), and
     * those precede the wrapper echo.
     */
    bool cut_at_wrapper = false;
    if (vdom_wrapped) {
        char *end_echo = fg_find_last_echo_line(start, "end");
        if (end_echo) {
            end = end_echo;
            cut_at_wrapper = true;
        }
    }

    size_t payload_len;
    if (cut_at_wrapper) {
        /*
         * The wrapper echo line and the final prompt after it are
         * already outside [start, end). Only trim the line break that
         * preceded the echo — running the prompt-line walk below here
         * would delete the last line of real output.
         */
        while (end > start && (end[-1] == '\r' || end[-1] == '\n'))
            end--;
        payload_len = (size_t)(end - start);
    } else {
        /* No wrapper: drop the trailing prompt line itself. */
        while (end > start && (end[-1] == ' ' || end[-1] == '#' ||
                               end[-1] == '\r' || end[-1] == '\n'))
            end--;
        char *prompt_line = end;
        while (prompt_line > start && prompt_line[-1] != '\n')
            prompt_line--;
        payload_len = (size_t)(prompt_line - start);
        if (payload_len > 0 && start[payload_len - 1] == '\r')
            payload_len--;
    }

    *out_len = payload_len;
    return start;
}

static virp_error_t fg_ssh_execute(struct virp_conn *conn,
                                   const char *command,
                                   virp_exec_result_t *result)
{
    if (!conn->ssh_session || !conn->ssh_connected)
        return FG_ERR_NOT_CONNECTED;

    LIBSSH2_SESSION *session = conn->ssh_session;
    LIBSSH2_CHANNEL *channel = libssh2_channel_open_session(session);
    if (!channel)
        return FG_ERR_TRANSPORT;

    if (libssh2_channel_request_pty(channel, "xterm") != 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return FG_ERR_TRANSPORT;
    }

    if (libssh2_channel_shell(channel) != 0) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        return FG_ERR_TRANSPORT;
    }

    /* Drain initial prompt/banner before sending command */
    libssh2_session_set_blocking(session, 0);
    {
        char drain[4096];
        int drain_idle = 0;
        while (drain_idle < 15) {
            ssize_t n = libssh2_channel_read(channel, drain, sizeof(drain) - 1);
            if (n > 0) {
                drain_idle = 0;
            } else if (n == LIBSSH2_ERROR_EAGAIN) {
                drain_idle++;
                usleep(100000);
            } else {
                break;
            }
        }
    }
    libssh2_session_set_blocking(session, 1);

    /* If VDOMs are enabled and this command needs VDOM context,
     * prepend the context switch before the actual command.
     * Each channel is a fresh shell so we must switch every time. */
    const char *vdom = conn->device.vdom[0] ? conn->device.vdom : "root";

    char cmd_buf[4096];
    int cmd_len;

    bool vdom_wrapped = (conn->vdom_enabled && fg_command_needs_vdom(command));
    if (vdom_wrapped) {
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf),
                           "config vdom\nedit %s\n%s\nend\n",
                           vdom, command);
    } else {
        cmd_len = snprintf(cmd_buf, sizeof(cmd_buf), "%s\n", command);
    }
    libssh2_channel_write(channel, cmd_buf, cmd_len);

    /* Read output into temp buffer */
    char *raw = calloc(FG_SSH_BUFFER_SIZE, 1);
    if (!raw) {
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "out of memory for SSH read buffer");
        result->success = false;
        return VIRP_OK;
    }

    size_t total = 0;
    int idle_cycles = 0;
    bool prompt_seen = false;
    libssh2_session_set_blocking(session, 0);

    while (total < FG_SSH_BUFFER_SIZE - 1 && idle_cycles < 30) {
        ssize_t n = libssh2_channel_read(channel,
                                         raw + total,
                                         FG_SSH_BUFFER_SIZE - total - 1);
        if (n > 0) {
            total += n;
            idle_cycles = 0;

            /*
             * Trim trailing padding before testing, rather than
             * requiring the read to land exactly on "# ". The old test
             * only fired when a fragment boundary happened to sit on
             * those two bytes.
             */
            size_t t = total;
            while (t > 0 && (raw[t - 1] == ' ' || raw[t - 1] == '\r' ||
                             raw[t - 1] == '\n'))
                t--;
            if (t > 0 && raw[t - 1] == '#') {
                prompt_seen = true;
                break;
            }
        } else if (n == LIBSSH2_ERROR_EAGAIN) {
            idle_cycles++;
            usleep(100000);
        } else {
            break;
        }
    }

    libssh2_session_set_blocking(session, 1);
    raw[total] = '\0';

    /*
     * Inspect the read outcome. The loop can also end on a full buffer,
     * a 3s idle timeout or a transport error; those produce a partial
     * body, which must never be reported as the device's answer. This
     * used to set success = true unconditionally.
     */
    if (!prompt_seen) {
        fprintf(stderr, "[FortiGate] Read ended without prompt: device=%s "
                "bytes=%zu (buffer_full=%s) — reporting as error\n",
                conn->device.hostname, total,
                (total >= FG_SSH_BUFFER_SIZE - 1) ? "yes" : "no");
        free(raw);
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        result->success = false;
        result->output_len = 0;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Incomplete read on %s: no prompt after %zu bytes",
                 conn->device.hostname, total);
        return VIRP_ERR_NO_PROMPT;
    }

    /* Strip the command echo and, when VDOM-wrapped, the wrapper
     * echoes around it. */
    size_t payload_len = 0;
    char *start = fg_scrub_reply(raw, total, command, vdom_wrapped,
                                 &payload_len);
    if (!start) {
        fprintf(stderr, "[FortiGate] Command echo not found in reply: "
                "device=%s command='%s' — reporting as error\n",
                conn->device.hostname, command);
        free(raw);
        libssh2_channel_close(channel);
        libssh2_channel_free(channel);
        result->success = false;
        result->output_len = 0;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Malformed reply on %s: command echo missing",
                 conn->device.hostname);
        return VIRP_ERR_NO_PROMPT;
    }

    /* Copy into fixed-size result buffer */
    if (payload_len >= VIRP_OUTPUT_MAX)
        payload_len = VIRP_OUTPUT_MAX - 1;

    memcpy(result->output, start, payload_len);
    result->output[payload_len] = '\0';
    result->output_len = payload_len;
    result->success = true;
    result->exit_code = 0;

    free(raw);
    libssh2_channel_close(channel);
    libssh2_channel_free(channel);

    return VIRP_OK;
}


/* ══════════════════════════════════════════════════════════════════
 * DRIVER INTERFACE IMPLEMENTATION
 * ══════════════════════════════════════════════════════════════════ */

/* ── connect ────────────────────────────────────────────────────── */
static virp_conn_t *fg_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    /* Copy device config */
    memcpy(&conn->device, device, sizeof(*device));

    conn->ssh_port = device->port ? device->port : 22;
    conn->ssh_socket = -1;

    /* Establish SSH connection */
    if (device->username[0] == '\0' || device->password[0] == '\0') {
        free(conn);
        return NULL;
    }

    if (fg_ssh_connect(conn) != 0) {
        free(conn);
        return NULL;
    }

    /* Probe for VDOM mode — run "get system status" and look for
     * "Virtual domain configuration: enable" in the output.
     * This runs once at connect time so fg_execute knows whether
     * to prepend VDOM context switches. */
    virp_exec_result_t probe;
    memset(&probe, 0, sizeof(probe));
    if (fg_ssh_execute(conn, "get system status", &probe) == VIRP_OK
        && probe.success) {
        conn->vdom_enabled =
            (strstr(probe.output, "Virtual domain configuration: enable")
             != NULL);
        conn->vdom_probed = true;
        fprintf(stderr, "[virp-fg] VDOM probe: %s\n",
                conn->vdom_enabled ? "enabled" : "disabled");
    }

    return (virp_conn_t *)conn;
}


/* ══════════════════════════════════════════════════════════════════
 * Command Routing Table — FortiOS commands → trust tiers
 *
 * Prefix-matched, longest match wins (mirrors asa_route_command /
 * junos_route_command). FAIL-CLOSED: unmapped commands default to RED
 * (they used to default YELLOW, which cleared the gate).
 *
 * Tiering policy for this fleet:
 *   GREEN  — passive monitoring reads (status, perf, routing table)
 *            plus the explicit read-only audit set: non-secret `get`
 *            reads, the two non-secret `show firewall` reads, and the
 *            single `diagnose sys session stat` counter read.
 *   YELLOW — config-visibility reads, backups, active diagnostics.
 *            'show full-configuration' is the backup path and MUST stay
 *            at/under a YELLOW threshold so scheduled backups keep working.
 *   RED    — credential / admin-account reads and any config-mode change
 *            (approval-worthy).
 *
 * NOTE: destructive ops (reboot/factoryreset/…) are handled separately
 * by fg_is_black_tier() and are intentionally NOT in this table.
 * ══════════════════════════════════════════════════════════════════ */

typedef struct {
    const char        *command_pattern;   /* CLI command prefix */
    virp_trust_tier_t  tier;
} fg_command_route_t;

static const fg_command_route_t FG_ROUTE_TABLE[] = {
    /* ── GREEN — passive monitoring (no approval) ──────────────── */
    { "get system status",          VIRP_TIER_GREEN  },
    { "get system performance",     VIRP_TIER_GREEN  },
    { "get hardware",               VIRP_TIER_GREEN  },
    { "get system interface",       VIRP_TIER_GREEN  },
    { "get router info",            VIRP_TIER_GREEN  },
    { "get router",                 VIRP_TIER_GREEN  },
    { "show router",                VIRP_TIER_GREEN  },

    /*
     * ── GREEN — read-only audit set (added 2026-08-19) ──────────
     *
     * Explicit entries, NOT a `{ "get ", GREEN }` / `{ "show ", GREEN }`
     * prefix pair. A bare `show` catch-all lived here once and was
     * removed in b26e34d because it UNDERCUT the RED credential entries:
     * "show system admins", "show users", "show system api-users" lose
     * the RED entry's token boundary at the extra character and fall
     * through to the shorter catch-all. A GREEN prefix would reproduce
     * that failure one tier lower — those reads would clear the gate
     * with no approval at all. Every entry below is >= 3 tokens, so
     * none of them can stand in for a RED entry's variant; a suffixed
     * variant ("get system globals") fails the boundary check and lands
     * on the fail-closed RED default.
     *
     * `show full-configuration` is deliberately absent: it keeps its
     * YELLOW entry below and stays approval-gated.
     */
    { "get system global",          VIRP_TIER_GREEN  },
    { "get system service",         VIRP_TIER_GREEN  },
    { "get system certificate local", VIRP_TIER_GREEN },  /* cert metadata/expiry, not key material */
    { "get vpn ssl settings",       VIRP_TIER_GREEN  },
    { "get wireless-controller vap", VIRP_TIER_GREEN },
    { "show firewall policy",       VIRP_TIER_GREEN  },   /* longest match beats "show firewall" YELLOW */
    { "show firewall address",      VIRP_TIER_GREEN  },
    /*
     * phase2-interface only. "show vpn ipsec phase1-interface" carries
     * `set psksecret ENC ...` and stays on the "show vpn" YELLOW entry —
     * the same call this table already makes for "show system ha"
     * ("incl. encrypted HA password"). phase2 carries no secret.
     */
    { "show vpn ipsec phase2-interface", VIRP_TIER_GREEN },
    /*
     * The one diagnose read singled out. Longest match beats the
     * { "diagnose", YELLOW } catch-all below, so every OTHER diagnose —
     * including "diagnose sys session clear" and the debug toggles —
     * keeps its YELLOW and never becomes GREEN by this entry.
     */
    { "diagnose sys session stat",  VIRP_TIER_GREEN  },

    /* ── YELLOW — config reads, backups, active diagnostics ────── */
    { "show full-configuration",    VIRP_TIER_YELLOW },  /* backup path — keep <= YELLOW */
    { "diagnose",                   VIRP_TIER_YELLOW },  /* active diagnostics */
    { "execute ping",               VIRP_TIER_YELLOW },
    { "execute traceroute",         VIRP_TIER_YELLOW },
    { "show system interface",      VIRP_TIER_YELLOW },
    { "show firewall",              VIRP_TIER_YELLOW },
    { "show vpn",                   VIRP_TIER_YELLOW },
    /*
     * Explicit config-section reads. These replace the former bare
     * { "show", YELLOW } catch-all, which was removed because it
     * UNDERCUT the RED credential entries below: any variant of a RED
     * read ("show system admins", "show system admin-profile",
     * "show system api-users", "show users") lost the RED entry's token
     * boundary at the extra character and landed on the catch-all's
     * YELLOW instead of failing closed.
     *
     * YELLOW, not GREEN, on this table's own principle: `get` is an
     * operational/status read (GREEN), `show` displays CONFIGURATION
     * (YELLOW) — the same call already made for "show full-configuration",
     * "show system interface", "show firewall" and "show vpn".
     * "show system interface physical" needs no entry: the existing
     * "show system interface" covers it by longest match.
     */
    { "show system global",         VIRP_TIER_YELLOW },
    { "show system dns",            VIRP_TIER_YELLOW },
    { "show system ha",             VIRP_TIER_YELLOW },  /* incl. encrypted HA password — same class as show full-configuration */
    { "show system snmp",           VIRP_TIER_YELLOW },
    { "show system dhcp",           VIRP_TIER_YELLOW },
    { "show system central-management", VIRP_TIER_YELLOW },
    { "show system fortiguard",     VIRP_TIER_YELLOW },
    { "show log",                   VIRP_TIER_YELLOW },
    { "show antivirus",             VIRP_TIER_YELLOW },
    { "show webfilter",             VIRP_TIER_YELLOW },

    /* ── RED — credential/admin reads + config-mode changes ────── */
    /*
     * `execute backup` is RED, not YELLOW (audit §4.3, 2026-08-01).
     *
     * It reads like a sibling of "show full-configuration" — both dump
     * the config — but they are not siblings. `show` returns the config
     * THROUGH the O-Node, which signs and chains what it saw.
     * `execute backup config ftp <file> <server> <user> <pass>` makes the
     * DEVICE open its own connection to a caller-supplied host and push
     * the whole config there: admin password hashes, VPN PSKs, API
     * tokens. None of it is observed, signed, or chained — the O-Node
     * sees only "command accepted".
     *
     * That is untraced egress to an attacker-chosen destination, and at
     * the shipped gate_max_tier=yellow it ran with no approval at all.
     * RED rather than BLACK on purpose: backup-to-external is a
     * legitimate operator action, so it stays possible behind human
     * approval instead of being forbidden outright. Anything that makes
     * the device talk to a caller-named host belongs at RED at minimum.
     *
     * Pinned by test_execute_backup_is_gated() in
     * tests/test_driver_fortigate_black.c.
     */
    { "execute backup",             VIRP_TIER_RED    },  /* off-channel config egress */
    { "show system admin",          VIRP_TIER_RED    },  /* admin accounts, pw hashes, tokens */
    { "get system admin",           VIRP_TIER_RED    },
    { "show system api-user",       VIRP_TIER_RED    },  /* API credentials */
    { "get system api-user",        VIRP_TIER_RED    },
    { "show user",                  VIRP_TIER_RED    },  /* credential/user reads */
    { "get user",                   VIRP_TIER_RED    },
    { "config system admin",        VIRP_TIER_RED    },  /* admin-account change */
    { "config",                     VIRP_TIER_RED    },  /* any config-mode change */
};

static const size_t FG_ROUTE_TABLE_SIZE =
    sizeof(FG_ROUTE_TABLE) / sizeof(FG_ROUTE_TABLE[0]);

/*
 * Test-support accessors — see the equivalent pair in driver_cisco.c.
 * Lets the table-driven reachability suite prove every entry is
 * reachable and returns the tier it declares.
 */
size_t fg_route_table_count(void)
{
    return FG_ROUTE_TABLE_SIZE;
}

const char *fg_route_table_entry(size_t i, virp_trust_tier_t *tier)
{
    if (i >= FG_ROUTE_TABLE_SIZE) return NULL;
    if (tier) *tier = FG_ROUTE_TABLE[i].tier;
    return FG_ROUTE_TABLE[i].command_pattern;
}

virp_trust_tier_t fg_route_command(const char *command)
{
    if (!command) return VIRP_TIER_RED;              /* fail closed */

    /*
     * Layer 3a — a separator-carrying string is not one command, so this
     * table cannot vouch for it. Fail closed to RED here as well as at
     * the daemon boundary, because fg_route_command is directly callable.
     */
    if (virp_command_check_separators(command, NULL, 0) != 0)
        return VIRP_TIER_RED;

    /* Skip leading whitespace so " show system admin" still classifies. */
    while (*command == ' ' || *command == '\t') command++;

    const fg_command_route_t *best = NULL;
    size_t best_len = 0;

    for (size_t i = 0; i < FG_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(FG_ROUTE_TABLE[i].command_pattern);
        /*
         * 2026-08-09 classified≠executed fix: CASE-SENSITIVE — the
         * driver executes the caller's original bytes, so this table
         * may not vouch for a spelling it did not literally see;
         * "SHOW SYSTEM STATUS" falls through RED by absence. (The
         * separate FG_BLACK_COMMANDS deny list stays case-insensitive
         * on purpose — over-matching a deny list is fail-closed.)
         */
        if (strncmp(command, FG_ROUTE_TABLE[i].command_pattern, plen) != 0)
            continue;

        /*
         * Layer 3b — the match must END on a token boundary so a listed
         * prefix cannot stand in for a longer word. This matters most for
         * the deliberately broad catch-alls here ("show", "config"):
         * without it "showdown" would inherit "show"'s YELLOW. Entries
         * ending in a space carry their own boundary; longest valid match
         * still wins.
         */
        char after = command[plen];
        bool self_terminated = (plen > 0 &&
            FG_ROUTE_TABLE[i].command_pattern[plen - 1] == ' ');
        if (!self_terminated && after != '\0' &&
            after != ' ' && after != '\t')
            continue;

        if (plen > best_len) {
            best = &FG_ROUTE_TABLE[i];
            best_len = plen;
        }
    }

    /* Fail-closed: anything not explicitly listed is RED. An unlisted
     * command used to return YELLOW, which CLEARED the default YELLOW
     * gate threshold and executed unreviewed. */
    return best ? best->tier : VIRP_TIER_RED;
}


/* ══════════════════════════════════════════════════════════════════
 * BLACK Tier — Destructive commands that must never reach the wire.
 *
 * Prefix-matched (case-insensitive).  Any command that starts with
 * one of these strings is rejected outright at the driver level.
 * Deliberately still case-insensitive after the 2026-08-09 exact-match
 * fix to the tier table: this is a DENY list, over-matching it is
 * fail-closed ("EXECUTE REBOOT" stays BLACK), and nothing matched here
 * ever executes.
 * ══════════════════════════════════════════════════════════════════ */

static const char *FG_BLACK_COMMANDS[] = {
    "execute factoryreset",
    "execute formatdisk",
    "execute reboot",
    "execute shutdown",
    "fnsysctl",
};
static const size_t FG_BLACK_COUNT =
    sizeof(FG_BLACK_COMMANDS) / sizeof(FG_BLACK_COMMANDS[0]);

bool fg_is_black_tier(const char *command)
{
    if (!command) return false;
    for (size_t i = 0; i < FG_BLACK_COUNT; i++) {
        size_t plen = strlen(FG_BLACK_COMMANDS[i]);
        if (strncasecmp(command, FG_BLACK_COMMANDS[i], plen) == 0)
            return true;
    }
    return false;
}

/* ── execute ────────────────────────────────────────────────────── */
static virp_error_t fg_execute(virp_conn_t *base_conn,
                               const char *command,
                               virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    /* ── BLACK tier safety: never execute destructive commands ── */
    if (fg_is_black_tier(command)) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "BLACK tier: command blocked on %s",
                 conn->device.hostname);
        fprintf(stderr, "[FortiGate] BLACK tier blocked: '%s' on %s\n",
                command, conn->device.hostname);
        int written = snprintf(result->output, sizeof(result->output),
                               "%s $ %s\nBLACK tier: command forbidden",
                               conn->device.hostname, command);
        result->output_len = (written > 0) ? (size_t)written : 0;
        return VIRP_OK;
    }

    if (!conn->ssh_connected) {
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "SSH not connected");
        result->success = false;
        return FG_ERR_NOT_CONNECTED;
    }

    return fg_ssh_execute(conn, command, result);
}


/* ── disconnect ─────────────────────────────────────────────────── */
static void fg_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (conn->ssh_session) {
        libssh2_session_disconnect(conn->ssh_session, "VIRP disconnect");
        libssh2_session_free(conn->ssh_session);
        conn->ssh_session = NULL;
    }
    if (conn->ssh_socket >= 0) {
        close(conn->ssh_socket);
        conn->ssh_socket = -1;
    }
    conn->ssh_connected = false;

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
    free(conn);
}


/* ── detect ─────────────────────────────────────────────────────── */
static bool fg_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->ssh_connected) return false;

    virp_exec_result_t result;
    memset(&result, 0, sizeof(result));

    virp_error_t err = fg_ssh_execute(conn, "get system status", &result);
    if (err != VIRP_OK || !result.success)
        return false;

    return (strstr(result.output, "Version") != NULL
         && strstr(result.output, "FortiGate") != NULL);
}


/* ── health_check ───────────────────────────────────────────────── */
static virp_error_t fg_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->ssh_connected)
        return FG_ERR_NOT_CONNECTED;

    virp_exec_result_t result;
    memset(&result, 0, sizeof(result));

    virp_error_t err = fg_ssh_execute(conn, "get system status", &result);
    if (err != VIRP_OK || !result.success)
        return err ? err : FG_ERR_TRANSPORT;

    return VIRP_OK;
}


/* ══════════════════════════════════════════════════════════════════
 * DRIVER REGISTRATION
 * ══════════════════════════════════════════════════════════════════ */

static const virp_driver_t fg_driver = {
    .name        = "fortigate",
    .vendor      = VIRP_VENDOR_FORTINET,
    .connect     = fg_connect,
    .execute     = fg_execute,
    .disconnect  = fg_disconnect,
    .detect      = fg_detect,
    .health_check = fg_health_check,
    .route_command = fg_route_command,
};

void virp_driver_fortinet_init(void)
{
    virp_driver_register(&fg_driver);
}
