/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco IOS command canonicalizer + exact-match tier table (v1, EXEC mode)
 *
 * See virp_driver_cisco_canon.h for the layering contract. Short form:
 * ALL prefix logic lives in the canonicalizer, where ambiguity fails
 * closed; the tier table is exact-match on canonical strings ONLY.
 *
 * CASE FOLDING, revisited (supersedes the 2026-08-09 case-sensitivity
 * fix FOR THIS DRIVER PAIR ONLY). That fix made tier tables
 * case-sensitive because the driver executed the caller's ORIGINAL
 * bytes — the classifier could not vouch for a spelling it never saw.
 * With this module the daemon executes, hashes, and classifies the
 * CANONICAL bytes (virp_driver_t.canon_command), so `SH RUN` and
 * `show running-config` are the same executed string and folding
 * keyword case is honest again. Arguments are never folded: they pass
 * through byte-for-byte, and a canonical string that reaches the tier
 * table carries them verbatim (where they simply fail the exact match
 * and land RED by absence). Tables for drivers that still execute raw
 * bytes keep the 2026-08-09 rule unchanged.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_driver_cisco_canon.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

const char CISCO_CANON_VERSION[] = "ios-canon/1";

/* =========================================================================
 * Keyword tree
 *
 * One node per keyword the v1 table needs. This tree is NOT a model of
 * the full IOS grammar — it resolves abbreviations relative to the
 * commands VIRP has tiered, exactly as the tier table is not a model
 * of every IOS command. A prefix that is ambiguous on a real device
 * but unique in this tree (e.g. `show r`) canonicalizes here; it can
 * only ever resolve to a command that already has a tier, so the gate
 * decision is unchanged — the expansion is just more permissive than
 * the device's own parser and is always logged canonically.
 *
 * accepts_args: this node's IOS grammar takes user operands (interface
 * names, prefixes, hosts, filesystem targets). Once one token is
 * consumed as an argument, EVERY remaining token is an argument —
 * arguments are trailing, and resuming keyword resolution after an
 * argument would let attacker-shaped operands steer the tree.
 *
 * expand: default-subcommand alias, applied ONLY when the input ends
 * exactly at this node with no arguments. `write` alone IS `write
 * memory` on IOS; without the alias, `wr` and `wr mem` would produce
 * two canonical strings — two hash identities for one device action.
 * ========================================================================= */

typedef struct cisco_kw_node {
    const char                  *keyword;
    const struct cisco_kw_node  *children;
    size_t                       n_children;
    bool                         accepts_args;
    const char                  *expand;
} cisco_kw_node_t;

#define KIDS(arr) arr, sizeof(arr) / sizeof((arr)[0])
#define LEAF(kw, args) { kw, NULL, 0, args, NULL }

/* show ip interface … */
static const cisco_kw_node_t N_SHOW_IP_INTERFACE[] = {
    LEAF("brief", false),
};
/* show ip route … */
static const cisco_kw_node_t N_SHOW_IP_ROUTE[] = {
    LEAF("summary", false),
};
static const cisco_kw_node_t N_SHOW_IP[] = {
    { "interface", KIDS(N_SHOW_IP_INTERFACE), true,  NULL },
    { "route",     KIDS(N_SHOW_IP_ROUTE),     true,  NULL },
};
static const cisco_kw_node_t N_SHOW_CDP[] = {
    LEAF("neighbors", true),
};
static const cisco_kw_node_t N_SHOW_PROCESSES[] = {
    LEAF("cpu",    false),
    LEAF("memory", false),
};
static const cisco_kw_node_t N_SHOW_NTP[] = {
    LEAF("status", false),
};
static const cisco_kw_node_t N_SHOW[] = {
    LEAF("arp",            true),
    { "cdp",       KIDS(N_SHOW_CDP),       false, NULL },
    LEAF("clock",          false),
    LEAF("environment",    false),
    LEAF("interfaces",     true),
    LEAF("inventory",      false),
    { "ip",        KIDS(N_SHOW_IP),        false, NULL },
    { "ntp",       KIDS(N_SHOW_NTP),       false, NULL },
    { "processes", KIDS(N_SHOW_PROCESSES), false, NULL },
    LEAF("running-config", true),
    LEAF("spanning-tree",  true),
    LEAF("startup-config", false),
    LEAF("tech-support",   false),
    LEAF("users",          false),
    LEAF("version",        false),
    LEAF("vlan",           true),
};
static const cisco_kw_node_t N_WRITE[] = {
    LEAF("erase",  false),
    LEAF("memory", false),
};
static const cisco_kw_node_t N_COPY_RUNNING[] = {
    LEAF("startup-config", false),
};
static const cisco_kw_node_t N_COPY[] = {
    { "running-config", KIDS(N_COPY_RUNNING), true, NULL },
};
static const cisco_kw_node_t N_CLEAR[] = {
    LEAF("counters", true),
};
static const cisco_kw_node_t N_CONFIGURE[] = {
    LEAF("terminal", false),
};
static const cisco_kw_node_t N_ERASE[] = {
    LEAF("startup-config", false),
};

static const cisco_kw_node_t N_ROOT_CHILDREN[] = {
    { "clear",      KIDS(N_CLEAR),     false, NULL },
    { "configure",  KIDS(N_CONFIGURE), true,  NULL },
    { "copy",       KIDS(N_COPY),      true,  NULL },
    LEAF("debug",      true),
    { "erase",      KIDS(N_ERASE),     true,  NULL },
    LEAF("ping",       true),
    LEAF("reload",     true),
    { "show",       KIDS(N_SHOW),      false, NULL },
    LEAF("traceroute", true),
    /* `write` with no subcommand is IOS shorthand for `write memory`. */
    { "write",      KIDS(N_WRITE),     false, "write memory" },
};
static const cisco_kw_node_t N_ROOT =
    { "", KIDS(N_ROOT_CHILDREN), false, NULL };

/* =========================================================================
 * Tier table — EXACT MATCH ON CANONICAL STRINGS ONLY.
 *
 * HARD RULE: no prefix matching of any kind in this table. IOS
 * abbreviations ARE prefixes; a prefix-shaped row here is the
 * FortiGate `show ` catch-all boundary bug (removed in b26e34d) all
 * over again. All prefix logic lives in the canonicalizer above,
 * where ambiguity fails closed. cisco_canon_table_validate() refuses
 * registration if a row even LOOKS prefix-shaped (trailing space).
 *
 * v1 scope: EXEC mode only, argument-free canonical forms only. A
 * canonical string carrying arguments (`show interfaces Gi0/1`,
 * `ping 10.0.0.1`) finds no exact row and is RED by absence — the
 * fail-closed direction for a read-only shadow run.
 *
 * NO BLACK ROWS, deliberately:
 *   - the mgmt-access-severing commands (no ssh, vty transport/ACL
 *     changes, shutting the mgmt interface) are all config-mode, and
 *     config-mode entry is already RED here — they cannot be reached
 *     through this table at any tier;
 *   - a gate-classifier BLACK is unapprovable BY DESIGN (the
 *     propose→approve→apply path dead-ends on it — see the gate's
 *     BLACK check in virp_onode.c), so driver tables top out at RED;
 *   - the execute-layer deny list (cisco_is_black_tier) independently
 *     refuses reload/erase/format at dispatch, mode-independent.
 * ========================================================================= */

typedef struct {
    const char        *canonical;
    virp_trust_tier_t  tier;
    const char        *rule_id;
    const char        *reason;   /* NULL = gate's generic message */
} cisco_tier_row_t;

/* Secrets-in-ledger reason, shared by the config-visibility reads:
 * enable secrets and SNMP strings must not land in the append-only
 * chain via a GREEN read — the same reasoning that kept FortiGate's
 * `show full-configuration` out of GREEN. The scrub still runs on the
 * approved read; approval gates it. */
#define REASON_CONFIG_READ \
    "config-visibility read (secrets-in-ledger) — propose/approve/apply"
#define REASON_CONFIG_MODE \
    "config-mode entry is out of scope in v1: multi-line config " \
    "sessions do not fit the single-command model"

static const cisco_tier_row_t CISCO_TIER_TABLE[] = {
    /* ── GREEN — curated read-only status set (v1) ─────────────────── */
    { "show version",            VIRP_TIER_GREEN, "green:show-version",            NULL },
    { "show clock",              VIRP_TIER_GREEN, "green:show-clock",              NULL },
    { "show inventory",          VIRP_TIER_GREEN, "green:show-inventory",          NULL },
    { "show ip interface brief", VIRP_TIER_GREEN, "green:show-ip-interface-brief", NULL },
    { "show interfaces",         VIRP_TIER_GREEN, "green:show-interfaces",         NULL },
    { "show ip route",           VIRP_TIER_GREEN, "green:show-ip-route",           NULL },
    { "show ip route summary",   VIRP_TIER_GREEN, "green:show-ip-route-summary",   NULL },
    { "show arp",                VIRP_TIER_GREEN, "green:show-arp",                NULL },
    { "show cdp neighbors",      VIRP_TIER_GREEN, "green:show-cdp-neighbors",      NULL },
    { "show vlan",               VIRP_TIER_GREEN, "green:show-vlan",               NULL },
    { "show spanning-tree",      VIRP_TIER_GREEN, "green:show-spanning-tree",      NULL },
    { "show processes cpu",      VIRP_TIER_GREEN, "green:show-processes-cpu",      NULL },
    { "show processes memory",   VIRP_TIER_GREEN, "green:show-processes-memory",   NULL },
    { "show environment",        VIRP_TIER_GREEN, "green:show-environment",        NULL },
    { "show users",              VIRP_TIER_GREEN, "green:show-users",              NULL },
    { "show ntp status",         VIRP_TIER_GREEN, "green:show-ntp-status",         NULL },

    /* ── YELLOW — proposable, never GREEN ──────────────────────────── */
    { "show running-config",     VIRP_TIER_YELLOW, "yellow:show-running-config",
      REASON_CONFIG_READ },
    { "show startup-config",     VIRP_TIER_YELLOW, "yellow:show-startup-config",
      REASON_CONFIG_READ },
    { "show tech-support",       VIRP_TIER_YELLOW, "yellow:show-tech-support",
      REASON_CONFIG_READ },
    /* `write memory` and its exact IOS equivalent share one rule id:
     * one device action, one rule, one audit identity. (`wr` and bare
     * `write` reach the first row via the canonicalizer's
     * default-subcommand alias.) */
    { "write memory",            VIRP_TIER_YELLOW, "yellow:write-memory",
      "NVRAM config save — proposable state write" },
    { "copy running-config startup-config",
                                 VIRP_TIER_YELLOW, "yellow:copy-run-start",
      "NVRAM config save — proposable state write" },
    { "clear counters",          VIRP_TIER_YELLOW, "yellow:clear-counters",
      "counter reset — diagnostic action, proposable" },
    { "ping",                    VIRP_TIER_YELLOW, "yellow:ping",
      "active probe — proposable" },
    { "traceroute",              VIRP_TIER_YELLOW, "yellow:traceroute",
      "active probe — proposable" },

    /* ── RED — explicit rows with distinct reasons (default also RED) ─ */
    { "configure terminal",      VIRP_TIER_RED, "red:config-mode-entry",
      REASON_CONFIG_MODE },
    { "configure",               VIRP_TIER_RED, "red:config-mode-entry",
      REASON_CONFIG_MODE },
    { "reload",                  VIRP_TIER_RED, "red:reload",
      "device restart" },
    { "write erase",             VIRP_TIER_RED, "red:erase",
      "startup-config destruction" },
    { "erase startup-config",    VIRP_TIER_RED, "red:erase",
      "startup-config destruction" },
};
static const size_t CISCO_TIER_TABLE_SIZE =
    sizeof(CISCO_TIER_TABLE) / sizeof(CISCO_TIER_TABLE[0]);

/*
 * RED-by-absence annotations, keyed on the FIRST canonical token.
 * These assign a distinct rule id + instructive reason to families
 * whose members carry arguments and therefore cannot be exact rows
 * (`debug ip packet`, `copy tftp: …`, `reload in 5`). They NEVER
 * assign a tier — a table miss is RED unconditionally; this only
 * explains it. First-token matching is safe here precisely because
 * no permission flows through it.
 */
typedef struct {
    const char *first_token;
    const char *rule_id;
    const char *reason;
} cisco_red_family_t;

static const cisco_red_family_t CISCO_RED_FAMILIES[] = {
    { "configure", "red:config-mode-entry", REASON_CONFIG_MODE },
    { "reload",    "red:reload",  "device restart" },
    { "erase",     "red:erase",   "filesystem/config destruction" },
    { "debug",     "red:debug",   "debug output — crash risk on loaded devices" },
    { "copy",      "red:copy-offbox",
      "copy involving a network or filesystem location — off-box "
      "egress / image change, out of scope v1" },
};
static const size_t CISCO_RED_FAMILY_COUNT =
    sizeof(CISCO_RED_FAMILIES) / sizeof(CISCO_RED_FAMILIES[0]);

/* Rule ids for classifications that never reach the table. */
static const char RULE_INVALID[]     = "red:invalid";
static const char RULE_SEPARATOR[]   = "red:separator";
static const char RULE_AMBIGUOUS[]   = "red:canon-ambiguous";
static const char RULE_UNMATCHED[]   = "red:canon-unmatched";
static const char RULE_ABSENT[]      = "red:absent";

static const char REASON_AMBIGUOUS[] =
    "ambiguous abbreviation — no canonical form; spell the command out";
static const char REASON_UNMATCHED[] =
    "unrecognized token — not a v1 EXEC-mode command";

/* =========================================================================
 * Canonicalizer
 * ========================================================================= */

static bool tok_ieq(const char *tok, size_t tlen, const char *kw)
{
    if (strlen(kw) != tlen) return false;
    for (size_t i = 0; i < tlen; i++)
        if (tolower((unsigned char)tok[i]) != (unsigned char)kw[i])
            return false;
    return true;
}

static bool tok_iprefix(const char *tok, size_t tlen, const char *kw)
{
    if (tlen == 0 || tlen > strlen(kw)) return false;
    for (size_t i = 0; i < tlen; i++)
        if (tolower((unsigned char)tok[i]) != (unsigned char)kw[i])
            return false;
    return true;
}

static bool emit(char *out, size_t cap, size_t *pos,
                 const char *src, size_t n, bool space_before)
{
    size_t need = n + (space_before ? 1 : 0);
    if (*pos + need >= cap) return false;
    if (space_before) out[(*pos)++] = ' ';
    memcpy(out + *pos, src, n);
    *pos += n;
    out[*pos] = '\0';
    return true;
}

/*
 * Core walk. Returns canonical length >= 0, or -1 with *fail_rule set
 * to the static rule id and (when diag != NULL) a human-readable
 * failure detail in diag.
 */
static int canon_walk(const char *cmd, char *out, size_t cap,
                      const char **fail_rule, char *diag, size_t diag_cap)
{
    if (diag && diag_cap) diag[0] = '\0';
    *fail_rule = RULE_INVALID;

    if (!cmd || !out || cap == 0) return -1;

    /* A separator-carrying string is not one command; this walk cannot
     * produce a canonical form for it. Checked here as well as at the
     * daemon boundary — cisco_canon_command is directly callable. */
    if (virp_command_check_separators(cmd, NULL, 0) != 0) {
        *fail_rule = RULE_SEPARATOR;
        if (diag)
            snprintf(diag, diag_cap, "illegal separator/control byte");
        return -1;
    }

    const cisco_kw_node_t *node = &N_ROOT;
    bool in_args = false;
    bool any_token = false;
    size_t pos = 0;
    out[0] = '\0';

    size_t i = 0, len = strlen(cmd);
    while (i < len) {
        while (i < len && (cmd[i] == ' ' || cmd[i] == '\t')) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && cmd[i] != ' ' && cmd[i] != '\t') i++;
        const char *tok = cmd + start;
        size_t tlen = i - start;

        if (in_args) {
            /* Arguments: preserved byte-for-byte, never case-folded,
             * never expanded. */
            if (!emit(out, cap, &pos, tok, tlen, any_token)) return -1;
            any_token = true;
            continue;
        }

        /* Keyword resolution: exact match first (so a keyword that is
         * also a prefix of a sibling — and every already-canonical
         * string — resolves unambiguously), then unique prefix. */
        const cisco_kw_node_t *hit = NULL;
        size_t nmatch = 0;
        for (size_t c = 0; c < node->n_children; c++) {
            if (tok_ieq(tok, tlen, node->children[c].keyword)) {
                hit = &node->children[c];
                nmatch = 1;
                break;
            }
        }
        if (!hit) {
            for (size_t c = 0; c < node->n_children; c++) {
                if (tok_iprefix(tok, tlen, node->children[c].keyword)) {
                    hit = &node->children[c];
                    nmatch++;
                }
            }
        }

        if (nmatch >= 2) {
            /* AMBIGUOUS prefix — fail closed, name the candidates. */
            *fail_rule = RULE_AMBIGUOUS;
            if (diag) {
                size_t d = (size_t)snprintf(diag, diag_cap,
                        "ambiguous token '%.*s': candidates", (int)tlen, tok);
                for (size_t c = 0; c < node->n_children && d < diag_cap; c++)
                    if (tok_iprefix(tok, tlen, node->children[c].keyword))
                        d += (size_t)snprintf(diag + d, diag_cap - d, " %s",
                                              node->children[c].keyword);
            }
            return -1;
        }

        if (nmatch == 1) {
            if (!emit(out, cap, &pos, hit->keyword, strlen(hit->keyword),
                      any_token))
                return -1;
            any_token = true;
            node = hit;
            continue;
        }

        /* No child matched. */
        if (node->accepts_args) {
            in_args = true;
            if (!emit(out, cap, &pos, tok, tlen, any_token)) return -1;
            any_token = true;
            continue;
        }
        *fail_rule = RULE_UNMATCHED;
        if (diag)
            snprintf(diag, diag_cap,
                     "unrecognized token '%.*s' after \"%s\"",
                     (int)tlen, tok, out);
        return -1;
    }

    if (!any_token) {
        *fail_rule = RULE_UNMATCHED;
        if (diag) snprintf(diag, diag_cap, "empty command");
        return -1;
    }

    /* Default-subcommand alias: applies only when the input ended
     * exactly on this keyword node with no arguments consumed. */
    if (!in_args && node->expand) {
        size_t elen = strlen(node->expand);
        if (elen + 1 > cap) return -1;
        memcpy(out, node->expand, elen + 1);
        pos = elen;
    }

    return (int)pos;
}

int cisco_canon_command(const char *command, char *out, size_t out_cap)
{
    const char *fail_rule;
    char diag[256];
    int n = canon_walk(command, out, out_cap, &fail_rule, diag, sizeof(diag));
    if (n < 0) {
        /* Runs once per request in the daemon — the one place failure
         * detail (both ambiguity candidates) belongs in the journal. */
        fprintf(stderr, "[cisco-canon] no canonical form (%s): %s\n",
                fail_rule, diag[0] ? diag : "-");
        if (out && out_cap) out[0] = '\0';
    }
    return n;
}

/* =========================================================================
 * Classification — canonical string in, tier + rule + reason out
 * ========================================================================= */

const char *cisco_canon_table_lookup(const char *canonical,
                                     virp_trust_tier_t *tier)
{
    if (!canonical) return NULL;
    for (size_t i = 0; i < CISCO_TIER_TABLE_SIZE; i++) {
        if (strcmp(canonical, CISCO_TIER_TABLE[i].canonical) == 0) {
            if (tier) *tier = CISCO_TIER_TABLE[i].tier;
            return CISCO_TIER_TABLE[i].rule_id;
        }
    }
    return NULL;
}

typedef struct {
    virp_trust_tier_t  tier;
    const char        *rule_id;
    const char        *reason;
} cisco_class_t;

static void classify(const char *command, cisco_class_t *res)
{
    res->tier = VIRP_TIER_RED;          /* fail closed */
    res->rule_id = RULE_INVALID;
    res->reason = NULL;

    if (!command) return;

    char canon[CISCO_CANON_MAX];
    const char *fail_rule;
    if (canon_walk(command, canon, sizeof(canon), &fail_rule, NULL, 0) < 0) {
        res->rule_id = fail_rule;
        if (fail_rule == RULE_AMBIGUOUS)      res->reason = REASON_AMBIGUOUS;
        else if (fail_rule == RULE_UNMATCHED) res->reason = REASON_UNMATCHED;
        return;
    }

    for (size_t i = 0; i < CISCO_TIER_TABLE_SIZE; i++) {
        if (strcmp(canon, CISCO_TIER_TABLE[i].canonical) == 0) {
            res->tier    = CISCO_TIER_TABLE[i].tier;
            res->rule_id = CISCO_TIER_TABLE[i].rule_id;
            res->reason  = CISCO_TIER_TABLE[i].reason;
            return;
        }
    }

    /* RED by absence. Annotate known families; the tier is already
     * decided and no annotation can change it. */
    res->rule_id = RULE_ABSENT;
    size_t first_len = strcspn(canon, " ");
    for (size_t i = 0; i < CISCO_RED_FAMILY_COUNT; i++) {
        const char *ft = CISCO_RED_FAMILIES[i].first_token;
        if (strlen(ft) == first_len && strncmp(canon, ft, first_len) == 0) {
            res->rule_id = CISCO_RED_FAMILIES[i].rule_id;
            res->reason  = CISCO_RED_FAMILIES[i].reason;
            return;
        }
    }
}

virp_trust_tier_t cisco_gate_tier(const char *command)
{
    cisco_class_t res;
    classify(command, &res);
    return res.tier;
}

const char *cisco_gate_rule(const char *command)
{
    cisco_class_t res;
    classify(command, &res);
    return res.rule_id;
}

const char *cisco_gate_reason(const char *command)
{
    cisco_class_t res;
    classify(command, &res);
    return res.reason;
}

/* =========================================================================
 * Registration-time table invariants (zammad pattern: loud, blocking)
 * ========================================================================= */

size_t cisco_canon_table_count(void)
{
    return CISCO_TIER_TABLE_SIZE;
}

const char *cisco_canon_table_entry(size_t i, virp_trust_tier_t *tier,
                                    const char **rule_id)
{
    if (i >= CISCO_TIER_TABLE_SIZE) return NULL;
    if (tier)    *tier    = CISCO_TIER_TABLE[i].tier;
    if (rule_id) *rule_id = CISCO_TIER_TABLE[i].rule_id;
    return CISCO_TIER_TABLE[i].canonical;
}

int cisco_canon_table_validate(void)
{
    int bad = 0;

    for (size_t i = 0; i < CISCO_TIER_TABLE_SIZE; i++) {
        const cisco_tier_row_t *r = &CISCO_TIER_TABLE[i];

        /* Untierable / BLACK rows are startup failures. */
        if (r->tier != VIRP_TIER_GREEN && r->tier != VIRP_TIER_YELLOW &&
            r->tier != VIRP_TIER_RED) {
            fprintf(stderr, "[cisco-canon] row %zu \"%s\": invalid tier "
                    "0x%02x\n", i, r->canonical, (unsigned)r->tier);
            bad = 1;
        }
        if (!r->rule_id || !r->rule_id[0]) {
            fprintf(stderr, "[cisco-canon] row %zu \"%s\": missing rule "
                    "id\n", i, r->canonical);
            bad = 1;
        }

        /* Prefix-shaped or non-canonical spelling: leading/trailing
         * space, doubled space, tab, empty. Exact match is only exact
         * when the row is byte-canonical. */
        size_t n = strlen(r->canonical);
        if (n == 0 || r->canonical[0] == ' ' || r->canonical[n - 1] == ' ' ||
            strstr(r->canonical, "  ") || strchr(r->canonical, '\t')) {
            fprintf(stderr, "[cisco-canon] row %zu \"%s\": prefix-shaped "
                    "or non-canonical whitespace\n", i, r->canonical);
            bad = 1;
        }

        /* Idempotence: the row must survive its own canonicalizer
         * unchanged, or exact-match can never fire for it. */
        char canon[CISCO_CANON_MAX];
        const char *fail_rule;
        if (canon_walk(r->canonical, canon, sizeof(canon),
                       &fail_rule, NULL, 0) < 0 ||
            strcmp(canon, r->canonical) != 0) {
            fprintf(stderr, "[cisco-canon] row %zu \"%s\": not a fixed "
                    "point of the canonicalizer (tree gap?)\n",
                    i, r->canonical);
            bad = 1;
            continue;
        }

        /* Reachability through the REAL classify path. */
        cisco_class_t res;
        classify(r->canonical, &res);
        if (res.tier != r->tier || res.rule_id != r->rule_id) {
            fprintf(stderr, "[cisco-canon] row %zu \"%s\": declares %u/%s "
                    "but classifies %u/%s\n", i, r->canonical,
                    (unsigned)r->tier, r->rule_id,
                    (unsigned)res.tier, res.rule_id);
            bad = 1;
        }

        /* Duplicates would make "the fired rule" ambiguous. */
        for (size_t j = i + 1; j < CISCO_TIER_TABLE_SIZE; j++) {
            if (strcmp(r->canonical, CISCO_TIER_TABLE[j].canonical) == 0) {
                fprintf(stderr, "[cisco-canon] rows %zu and %zu duplicate "
                        "\"%s\"\n", i, j, r->canonical);
                bad = 1;
            }
        }
    }

    return bad ? -1 : 0;
}
