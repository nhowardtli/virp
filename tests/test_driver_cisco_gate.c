/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco IOS/IOS-XE gate classifier unit tests — canonicalizer +
 * exact-match tier table (cisco_canon).
 *
 * THE acceptance criterion (NATO shadow-run engineer, verbatim: "sh
 * run, conf t, wr — if the model or the gate treats abbreviations
 * differently from canonical verbs, that is the cosmetic-gate case"):
 * every spelling of one IOS command must produce ONE classification,
 * ONE fired rule id, and ONE canonical string (hence one signed
 * command hash). Pinned explicitly in test_acceptance_criterion().
 *
 * Layering under test:
 *   canonicalizer — ALL prefix logic; ambiguity fails closed.
 *   tier table    — exact-match on canonical strings ONLY; RED by
 *                   absence. (The FortiGate `show ` catch-all removed
 *                   in b26e34d is the precedent: prefix rows in a tier
 *                   table are a boundary bug, and IOS abbreviations
 *                   ARE prefixes.)
 */

#include "virp_driver_cisco_canon.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Execute-layer deny list — defined in driver_cisco.c (linked via
 * CISCO=1), declared in virp_driver_cisco.h which cannot be included
 * standalone. */
bool cisco_is_black_tier(const char *command);

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

static const char *tier_name(virp_trust_tier_t t)
{
    switch (t) {
    case VIRP_TIER_GREEN:  return "GREEN";
    case VIRP_TIER_YELLOW: return "YELLOW";
    case VIRP_TIER_RED:    return "RED";
    case VIRP_TIER_BLACK:  return "BLACK";
    default:               return "UNCLASSIFIED";
    }
}

/* Assert tier + rule id for one spelling. */
static void expect(const char *cmd, virp_trust_tier_t tier, const char *rule)
{
    virp_trust_tier_t got_tier = cisco_gate_tier(cmd);
    const char *got_rule = cisco_gate_rule(cmd);
    if (got_tier != tier || strcmp(got_rule, rule) != 0) {
        printf("\n    MISMATCH: \"%s\" -> %s/%s, expected %s/%s\n",
               cmd ? cmd : "(null)", tier_name(got_tier), got_rule,
               tier_name(tier), rule);
        assert(got_tier == tier);
        assert(strcmp(got_rule, rule) == 0);
    }
}

/* Assert that every spelling in a NULL-terminated list yields ONE
 * canonical string, ONE tier, ONE rule id — the anti-cosmetic-gate
 * identity. Identical canonical bytes imply identical SHA-256, so this
 * pins hash identity too. */
static void expect_identical(const char *const *spellings,
                             const char *canonical,
                             virp_trust_tier_t tier, const char *rule)
{
    for (size_t i = 0; spellings[i]; i++) {
        char canon[CISCO_CANON_MAX];
        int n = cisco_canon_command(spellings[i], canon, sizeof(canon));
        if (n < 0 || strcmp(canon, canonical) != 0) {
            printf("\n    CANON MISMATCH: \"%s\" -> \"%s\", expected "
                   "\"%s\"\n", spellings[i], n >= 0 ? canon : "(none)",
                   canonical);
            assert(n >= 0);
            assert(strcmp(canon, canonical) == 0);
        }
        expect(spellings[i], tier, rule);
    }
}

/* Assert NO canonical form exists and classification fails closed. */
static void expect_no_canon(const char *cmd, const char *rule)
{
    char canon[CISCO_CANON_MAX];
    assert(cisco_canon_command(cmd, canon, sizeof(canon)) < 0);
    expect(cmd, VIRP_TIER_RED, rule);
}

/* =========================================================================
 * THE acceptance criterion — pinned verbatim
 * ========================================================================= */

static void test_acceptance_criterion(void)
{
    printf("\n=== ACCEPTANCE: abbreviations == canonical verbs "
           "(one tier, one rule, one hash identity) ===\n");

    static const char *const RUN[] = {
        "sh run", "sho running", "show run", "show running-config", NULL
    };
    TEST("sh run family -> one YELLOW identity");
    expect_identical(RUN, "show running-config",
                     VIRP_TIER_YELLOW, "yellow:show-running-config");
    PASS();

    static const char *const CONF[] = {
        "conf t", "conf term", "configure t", "configure terminal", NULL
    };
    TEST("conf t family -> one RED identity");
    expect_identical(CONF, "configure terminal",
                     VIRP_TIER_RED, "red:config-mode-entry");
    PASS();

    /* `write` with no subcommand IS `write memory` on IOS — the
     * default-subcommand alias makes all four spellings ONE canonical
     * string, hence one signed command hash. */
    static const char *const WR[] = {
        "wr", "wr mem", "write", "write memory", NULL
    };
    TEST("wr family -> one YELLOW identity (incl. default subcommand)");
    expect_identical(WR, "write memory",
                     VIRP_TIER_YELLOW, "yellow:write-memory");
    PASS();
}

/* =========================================================================
 * Every GREEN row pinned individually
 * ========================================================================= */

static void test_green_rows(void)
{
    printf("\n=== GREEN — every curated read pinned ===\n");
    static const struct { const char *cmd; const char *rule; } G[] = {
        { "show version",            "green:show-version" },
        { "show clock",              "green:show-clock" },
        { "show inventory",          "green:show-inventory" },
        { "show ip interface brief", "green:show-ip-interface-brief" },
        { "show interfaces",         "green:show-interfaces" },
        { "show ip route",           "green:show-ip-route" },
        { "show ip route summary",   "green:show-ip-route-summary" },
        { "show arp",                "green:show-arp" },
        { "show cdp neighbors",      "green:show-cdp-neighbors" },
        { "show vlan",               "green:show-vlan" },
        { "show spanning-tree",      "green:show-spanning-tree" },
        { "show processes cpu",      "green:show-processes-cpu" },
        { "show processes memory",   "green:show-processes-memory" },
        { "show environment",        "green:show-environment" },
        { "show users",              "green:show-users" },
        { "show ntp status",         "green:show-ntp-status" },
    };
    for (size_t i = 0; i < sizeof(G) / sizeof(G[0]); i++) {
        char label[96];
        snprintf(label, sizeof(label), "%s -> GREEN", G[i].cmd);
        TEST(label);
        expect(G[i].cmd, VIRP_TIER_GREEN, G[i].rule);
        PASS();
    }

    /* Abbreviated spellings of GREEN reads resolve to the same rows. */
    TEST("sh ver -> GREEN (show version)");
    expect("sh ver", VIRP_TIER_GREEN, "green:show-version");
    PASS();
    TEST("sh ip int br -> GREEN (show ip interface brief)");
    expect("sh ip int br", VIRP_TIER_GREEN, "green:show-ip-interface-brief");
    PASS();
    TEST("sh ip route summ -> GREEN (show ip route summary)");
    expect("sh ip route summ", VIRP_TIER_GREEN, "green:show-ip-route-summary");
    PASS();
    TEST("sh cdp nei -> GREEN (show cdp neighbors)");
    expect("sh cdp nei", VIRP_TIER_GREEN, "green:show-cdp-neighbors");
    PASS();
    TEST("sh proc c -> GREEN (show processes cpu)");
    expect("sh proc c", VIRP_TIER_GREEN, "green:show-processes-cpu");
    PASS();
}

/* =========================================================================
 * Every YELLOW row pinned individually
 * ========================================================================= */

static void test_yellow_rows(void)
{
    printf("\n=== YELLOW — proposable, never GREEN ===\n");
    static const struct { const char *cmd; const char *rule; } Y[] = {
        /* Secrets-in-ledger: config-visibility reads stay behind
         * approval — enable secrets / SNMP strings must not enter the
         * append-only chain via a GREEN read (the FortiGate
         * show full-configuration precedent). */
        { "show running-config", "yellow:show-running-config" },
        { "show startup-config", "yellow:show-startup-config" },
        { "show tech-support",   "yellow:show-tech-support" },
        { "write memory",        "yellow:write-memory" },
        { "copy running-config startup-config", "yellow:copy-run-start" },
        { "clear counters",      "yellow:clear-counters" },
        { "ping",                "yellow:ping" },
        { "traceroute",          "yellow:traceroute" },
    };
    for (size_t i = 0; i < sizeof(Y) / sizeof(Y[0]); i++) {
        char label[96];
        snprintf(label, sizeof(label), "%s -> YELLOW", Y[i].cmd);
        TEST(label);
        expect(Y[i].cmd, VIRP_TIER_YELLOW, Y[i].rule);
        PASS();
    }

    TEST("copy run start -> YELLOW (same row as full spelling)");
    expect("copy run start", VIRP_TIER_YELLOW, "yellow:copy-run-start");
    PASS();
    TEST("sh start -> YELLOW (show startup-config)");
    expect("sh start", VIRP_TIER_YELLOW, "yellow:show-startup-config");
    PASS();
    TEST("sh tech -> YELLOW (show tech-support)");
    expect("sh tech", VIRP_TIER_YELLOW, "yellow:show-tech-support");
    PASS();
}

/* =========================================================================
 * Explicit RED rows + RED families, each with its distinct reason rule
 * ========================================================================= */

static void test_red_explicit(void)
{
    printf("\n=== RED — explicit rows and annotated families ===\n");

    TEST("configure terminal -> RED red:config-mode-entry");
    expect("configure terminal", VIRP_TIER_RED, "red:config-mode-entry");
    PASS();
    TEST("configure (bare) -> RED red:config-mode-entry");
    expect("configure", VIRP_TIER_RED, "red:config-mode-entry");
    PASS();
    TEST("reload -> RED red:reload");
    expect("reload", VIRP_TIER_RED, "red:reload");
    PASS();
    TEST("reload in 5 -> RED red:reload (argument form)");
    expect("reload in 5", VIRP_TIER_RED, "red:reload");
    PASS();
    TEST("write erase -> RED red:erase");
    expect("write erase", VIRP_TIER_RED, "red:erase");
    PASS();
    TEST("wr era -> RED red:erase (abbreviated, same rule)");
    expect("wr era", VIRP_TIER_RED, "red:erase");
    PASS();
    TEST("erase startup-config -> RED red:erase");
    expect("erase startup-config", VIRP_TIER_RED, "red:erase");
    PASS();
    TEST("era sta -> RED red:erase (abbreviated, same rule)");
    expect("era sta", VIRP_TIER_RED, "red:erase");
    PASS();
    TEST("debug ip packet -> RED red:debug (crash risk)");
    expect("debug ip packet", VIRP_TIER_RED, "red:debug");
    PASS();
    TEST("copy tftp: running-config -> RED red:copy-offbox");
    expect("copy tftp: running-config", VIRP_TIER_RED, "red:copy-offbox");
    PASS();
    TEST("copy running-config tftp: -> RED red:copy-offbox");
    expect("copy running-config tftp:", VIRP_TIER_RED, "red:copy-offbox");
    PASS();

    /* Distinct reasons really are distinct rules. */
    TEST("config-mode / reload / erase / debug / copy rules all differ");
    {
        const char *r1 = cisco_gate_rule("configure terminal");
        const char *r2 = cisco_gate_rule("reload");
        const char *r3 = cisco_gate_rule("write erase");
        const char *r4 = cisco_gate_rule("debug ip packet");
        const char *r5 = cisco_gate_rule("copy tftp: flash:");
        assert(strcmp(r1, r2) && strcmp(r1, r3) && strcmp(r1, r4) &&
               strcmp(r1, r5) && strcmp(r2, r3) && strcmp(r2, r4) &&
               strcmp(r2, r5) && strcmp(r3, r4) && strcmp(r3, r5) &&
               strcmp(r4, r5));
    }
    PASS();

    /* route_reason companion: instructive text where it matters. */
    TEST("configure terminal carries an instructive reason");
    assert(cisco_gate_reason("configure terminal") != NULL);
    assert(strstr(cisco_gate_reason("configure terminal"), "config-mode")
           != NULL ||
           strstr(cisco_gate_reason("configure terminal"), "out of scope")
           != NULL);
    PASS();
    TEST("GREEN rows carry no rejection reason");
    assert(cisco_gate_reason("show version") == NULL);
    PASS();
}

/* =========================================================================
 * Ambiguity fails closed — no canonical form, RED, both candidates
 * ========================================================================= */

static void test_ambiguity_fails_closed(void)
{
    printf("\n=== Ambiguous prefixes fail closed (no canonical form) ===\n");

    TEST("c -> RED red:canon-ambiguous (clear/configure/copy)");
    expect_no_canon("c", "red:canon-ambiguous");
    PASS();
    TEST("co -> RED red:canon-ambiguous (configure/copy)");
    expect_no_canon("co", "red:canon-ambiguous");
    PASS();
    TEST("show i -> RED red:canon-ambiguous (interfaces/inventory/ip)");
    expect_no_canon("show i", "red:canon-ambiguous");
    PASS();
    TEST("show in -> RED red:canon-ambiguous (interfaces/inventory)");
    expect_no_canon("show in", "red:canon-ambiguous");
    PASS();
    TEST("show v -> RED red:canon-ambiguous (version/vlan)");
    expect_no_canon("show v", "red:canon-ambiguous");
    PASS();
    TEST("sh c -> RED red:canon-ambiguous (cdp/clock)");
    expect_no_canon("sh c", "red:canon-ambiguous");
    PASS();

    /* One more character resolves each. */
    TEST("show int -> unique (interfaces), GREEN");
    expect("show int", VIRP_TIER_GREEN, "green:show-interfaces");
    PASS();
    TEST("show inv -> unique (inventory), GREEN");
    expect("show inv", VIRP_TIER_GREEN, "green:show-inventory");
    PASS();
    TEST("show ve -> unique (version), GREEN");
    expect("show ve", VIRP_TIER_GREEN, "green:show-version");
    PASS();
}

/* =========================================================================
 * Near-miss boundaries
 * ========================================================================= */

static void test_near_miss_boundaries(void)
{
    printf("\n=== Near-miss boundaries ===\n");

    TEST("show running-configg -> RED (token overruns keyword)");
    expect_no_canon("show running-configg", "red:canon-unmatched");
    PASS();
    TEST("show versionitis -> RED (overrun)");
    expect_no_canon("show versionitis", "red:canon-unmatched");
    PASS();
    TEST("pingu -> RED (overrun of root keyword)");
    expect_no_canon("pingu", "red:canon-unmatched");
    PASS();
    TEST("show clockwork -> RED (overrun)");
    expect_no_canon("show clockwork", "red:canon-unmatched");
    PASS();

    /* Keyword-vs-argument: a token that matches no child at a node
     * that takes NO arguments is unmatched — it must not be silently
     * kept as an argument. */
    TEST("show version detail -> RED (version takes no operands)");
    expect_no_canon("show version detail", "red:canon-unmatched");
    PASS();
    TEST("show users all -> RED (users takes no operands here)");
    expect_no_canon("show users all", "red:canon-unmatched");
    PASS();

    /* Where the grammar DOES take operands, the operand is preserved
     * byte-for-byte and the exact table (argument-free rows only)
     * misses -> RED by absence, with the canonical form intact. */
    TEST("show interfaces GigabitEthernet0/0 -> RED by absence, "
         "argument preserved byte-for-byte");
    {
        char canon[CISCO_CANON_MAX];
        assert(cisco_canon_command("sh int GigabitEthernet0/0",
                                   canon, sizeof(canon)) >= 0);
        assert(strcmp(canon, "show interfaces GigabitEthernet0/0") == 0);
        expect("sh int GigabitEthernet0/0", VIRP_TIER_RED, "red:absent");
    }
    PASS();
    TEST("argument case preserved (GigabitEthernet stays mixed-case)");
    {
        char canon[CISCO_CANON_MAX];
        assert(cisco_canon_command("SH INT GigabitEthernet0/0",
                                   canon, sizeof(canon)) >= 0);
        /* keywords folded, argument untouched */
        assert(strcmp(canon, "show interfaces GigabitEthernet0/0") == 0);
    }
    PASS();
    TEST("ping 10.0.0.1 -> RED by absence (v1 table is argument-free)");
    expect("ping 10.0.0.1", VIRP_TIER_RED, "red:absent");
    PASS();

    /* Keyword case-insensitivity: same identity, not a new spelling. */
    TEST("SH RUN / Sh Run / sh run -> one YELLOW identity");
    {
        static const char *const CASES[] =
            { "SH RUN", "Sh Run", "sh run", "SHOW RUNNING-CONFIG", NULL };
        expect_identical(CASES, "show running-config",
                         VIRP_TIER_YELLOW, "yellow:show-running-config");
    }
    PASS();

    /* Whitespace runs collapse; identity unchanged. (Tabs are NOT
     * tested here: the separator policy rejects every control byte,
     * tab included, before tokenization — pinned in the separator
     * suite below.) */
    TEST("whitespace runs collapse ('  show    version  ')");
    {
        char canon[CISCO_CANON_MAX];
        assert(cisco_canon_command("  show    version  ",
                                   canon, sizeof(canon)) >= 0);
        assert(strcmp(canon, "show version") == 0);
        expect("  show    version  ", VIRP_TIER_GREEN,
               "green:show-version");
    }
    PASS();
}

/* =========================================================================
 * Default-deny sweep — unknown token strings are all RED
 * ========================================================================= */

static void test_default_deny_sweep(void)
{
    printf("\n=== Default-deny sweep ===\n");
    static const char *const CORPUS[] = {
        /* config-mode vocabulary arriving as EXEC strings */
        "interface GigabitEthernet0/0", "ip route 0.0.0.0 0.0.0.0 10.0.0.1",
        "router bgp 65000", "router ospf 1", "no shutdown", "hostname EVIL",
        "username attacker privilege 15 secret x", "enable secret 5 $1$x",
        "aaa new-model", "snmp-server community public RW",
        "crypto key generate rsa", "line vty 0 4", "login local",
        "password 0 x", "tacacs-server host 10.0.0.9 key S",
        /* other-vendor and shell vocabulary */
        "get system status", "vtysh -c \"show running-config\"",
        "ls -la", "cat /etc/passwd", "rm -rf /", "exit", "enable",
        "terminal length 0", "set system host-name evil",
        /* unlisted IOS reads (curated set only in v1) */
        "show sessions", "show snmp", "show logging", "show ip ospf",
        "show ip bgp summary", "show mac address-table",
        "show access-lists", "show cdp", "show ip",
        /* junk */
        "frobnicate the widget", "xyzzy", "0000 1111 2222",
        "____", "-", ".", "show", "sh",
    };
    for (size_t i = 0; i < sizeof(CORPUS) / sizeof(CORPUS[0]); i++) {
        char label[128];
        snprintf(label, sizeof(label), "\"%s\" -> RED", CORPUS[i]);
        TEST(label);
        virp_trust_tier_t t = cisco_gate_tier(CORPUS[i]);
        if (t != VIRP_TIER_RED) {
            printf("\n    NOT RED: \"%s\" -> %s\n", CORPUS[i], tier_name(t));
            assert(t == VIRP_TIER_RED);
        }
        PASS();
    }

    TEST("NULL -> RED");
    assert(cisco_gate_tier(NULL) == VIRP_TIER_RED);
    PASS();
    TEST("empty string -> RED");
    expect_no_canon("", "red:canon-unmatched");
    PASS();
    TEST("whitespace-only -> RED");
    expect_no_canon("      ", "red:canon-unmatched");
    PASS();
}

/* =========================================================================
 * Separators fail closed in the classifier itself (defense in depth —
 * the daemon boundary rejects them first, but the hooks are directly
 * callable)
 * ========================================================================= */

static void test_separators_fail_closed(void)
{
    printf("\n=== Separators fail closed to RED ===\n");
    static const char *const SEP[] = {
        "show version;reload", "show version|reload", "show version&reload",
        "show version`reload`", "show version$(reload)", "show version${x}",
        "show clock\rreload", "show version\nreload", "\nreload",
        "show version\n", "sh run;wr", "show version\treload",
        "\tshow version",
    };
    for (size_t i = 0; i < sizeof(SEP) / sizeof(SEP[0]); i++) {
        TEST("separator variant -> RED red:separator");
        expect_no_canon(SEP[i], "red:separator");
        PASS();
    }
}

/* =========================================================================
 * Canonical-only invariant — a raw abbreviated spelling can NEVER
 * reach the tier table
 * ========================================================================= */

static void test_canonical_only_invariant(void)
{
    printf("\n=== Canonical-only invariant ===\n");

    TEST("exact lookup misses every abbreviated spelling");
    assert(cisco_canon_table_lookup("sh run", NULL) == NULL);
    assert(cisco_canon_table_lookup("show run", NULL) == NULL);
    assert(cisco_canon_table_lookup("conf t", NULL) == NULL);
    assert(cisco_canon_table_lookup("wr", NULL) == NULL);
    assert(cisco_canon_table_lookup("wr mem", NULL) == NULL);
    assert(cisco_canon_table_lookup("sh ver", NULL) == NULL);
    PASS();

    TEST("exact lookup misses case variants of canonical rows");
    assert(cisco_canon_table_lookup("SHOW RUNNING-CONFIG", NULL) == NULL);
    assert(cisco_canon_table_lookup("Show Version", NULL) == NULL);
    PASS();

    TEST("exact lookup hits the canonical rows themselves");
    {
        virp_trust_tier_t t = 0;
        assert(cisco_canon_table_lookup("show running-config", &t) != NULL);
        assert(t == VIRP_TIER_YELLOW);
        assert(cisco_canon_table_lookup("show version", &t) != NULL);
        assert(t == VIRP_TIER_GREEN);
    }
    PASS();

    /* Table-driven: for EVERY row, drop the last character of the last
     * token. The abbreviation must (a) miss the exact table — no
     * prefix row can catch it — while (b) classifying IDENTICALLY to
     * the full row through the canonicalizer. Together these prove the
     * table does exact-match only and the canonicalizer carries all
     * prefix semantics. */
    TEST("every row: last-token abbreviation misses table, classifies same");
    {
        size_t n = cisco_canon_table_count();
        for (size_t i = 0; i < n; i++) {
            virp_trust_tier_t tier;
            const char *rule;
            const char *cmd = cisco_canon_table_entry(i, &tier, &rule);
            assert(cmd != NULL);

            char abbr[CISCO_CANON_MAX];
            size_t len = strlen(cmd);
            assert(len > 0 && len < sizeof(abbr));
            const char *last = strrchr(cmd, ' ');
            size_t last_len = last ? strlen(last + 1) : len;
            if (last_len < 4)
                continue;   /* too short to abbreviate unambiguously */
            memcpy(abbr, cmd, len - 1);
            abbr[len - 1] = '\0';

            assert(cisco_canon_table_lookup(abbr, NULL) == NULL);
            virp_trust_tier_t got_tier = cisco_gate_tier(abbr);
            const char *got_rule = cisco_gate_rule(abbr);
            if (got_tier != tier || strcmp(got_rule, rule) != 0) {
                printf("\n    row \"%s\": abbreviation \"%s\" -> %s/%s, "
                       "expected %s/%s\n", cmd, abbr, tier_name(got_tier),
                       got_rule, tier_name(tier), rule);
                assert(got_tier == tier);
                assert(strcmp(got_rule, rule) == 0);
            }
        }
    }
    PASS();
}

/* =========================================================================
 * Table-driven: registration invariants + reachability + no BLACK
 * ========================================================================= */

static void test_table_invariants(void)
{
    printf("\n=== Table invariants (registration-time checks) ===\n");

    TEST("cisco_canon_table_validate() holds");
    assert(cisco_canon_table_validate() == 0);
    PASS();

    TEST("every row reachable at its declared tier + rule; none BLACK; "
         "none prefix-shaped");
    {
        size_t n = cisco_canon_table_count();
        assert(n > 0);
        for (size_t i = 0; i < n; i++) {
            virp_trust_tier_t tier;
            const char *rule;
            const char *cmd = cisco_canon_table_entry(i, &tier, &rule);
            assert(cmd && rule);
            assert(tier == VIRP_TIER_GREEN || tier == VIRP_TIER_YELLOW ||
                   tier == VIRP_TIER_RED);
            /* prefix-shaped = trailing space (the FortiGate `show `
             * catch-all shape), doubled space, or tab */
            size_t len = strlen(cmd);
            assert(len > 0);
            assert(cmd[0] != ' ' && cmd[len - 1] != ' ');
            assert(strstr(cmd, "  ") == NULL);
            assert(strchr(cmd, '\t') == NULL);
            /* reachability through the REAL path */
            assert(cisco_gate_tier(cmd) == tier);
            assert(strcmp(cisco_gate_rule(cmd), rule) == 0);
            /* idempotence: each row is a fixed point of the canonicalizer */
            char canon[CISCO_CANON_MAX];
            assert(cisco_canon_command(cmd, canon, sizeof(canon)) >= 0);
            assert(strcmp(canon, cmd) == 0);
        }
    }
    PASS();

    /* The classifier tops out at RED: gate-classifier BLACK is
     * unapprovable by design (the propose→approve→apply path dead-ends
     * on it). The execute-layer deny list holds the BLACK line. */
    TEST("classifier never returns BLACK; execute-layer deny holds");
    assert(cisco_gate_tier("reload") == VIRP_TIER_RED);
    assert(cisco_is_black_tier("reload"));
    assert(cisco_gate_tier("write erase") == VIRP_TIER_RED);
    assert(cisco_is_black_tier("write erase"));
    assert(cisco_gate_tier("erase startup-config") == VIRP_TIER_RED);
    assert(cisco_is_black_tier("erase startup-config"));
    PASS();

    TEST("classifier version is stamped and stable-format");
    assert(strcmp(CISCO_CANON_VERSION, "ios-canon/1") == 0);
    PASS();
}

/* =========================================================================
 * Canonicalizer hook contract details
 * ========================================================================= */

static void test_canon_hook_contract(void)
{
    printf("\n=== canon_command hook contract ===\n");

    TEST("failure empties the output buffer");
    {
        char canon[CISCO_CANON_MAX];
        memset(canon, 'X', sizeof(canon));
        assert(cisco_canon_command("show i", canon, sizeof(canon)) < 0);
        assert(canon[0] == '\0');
    }
    PASS();

    TEST("canonicalizing a canonical string is the identity");
    {
        char c1[CISCO_CANON_MAX], c2[CISCO_CANON_MAX];
        assert(cisco_canon_command("sh ip route summ", c1, sizeof(c1)) >= 0);
        assert(cisco_canon_command(c1, c2, sizeof(c2)) >= 0);
        assert(strcmp(c1, c2) == 0);
    }
    PASS();

    TEST("tiny output buffer fails, never truncates");
    {
        char small[8];
        assert(cisco_canon_command("show running-config",
                                   small, sizeof(small)) < 0);
    }
    PASS();

    TEST("NULL command fails");
    {
        char canon[CISCO_CANON_MAX];
        assert(cisco_canon_command(NULL, canon, sizeof(canon)) < 0);
    }
    PASS();
}

int main(void)
{
    printf("VIRP Cisco IOS/IOS-XE Gate Classifier — canonicalizer + "
           "exact-match table (%s)\n", CISCO_CANON_VERSION);
    printf("==================================================\n");
    test_acceptance_criterion();
    test_green_rows();
    test_yellow_rows();
    test_red_explicit();
    test_ambiguity_fails_closed();
    test_near_miss_boundaries();
    test_default_deny_sweep();
    test_separators_fail_closed();
    test_canonical_only_invariant();
    test_table_invariants();
    test_canon_hook_contract();
    printf("\n==================================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
