/*
 * interface <name> description <text> — the typed config operation
 * (C-04 Option A on the C node, 2026-09-15).
 *
 * Covers the parser's grammar, the executor's refusals that must happen
 * BEFORE any byte reaches a device (not connected; connected but not in
 * privileged EXEC), and the refusal contract for those paths. Device I/O
 * itself (the four-step transaction) is exercised live, not here: it needs
 * a prompt-bearing IOS session, and the settle helper is the same
 * mode-transition code cisco_execute already uses for "configure terminal".
 */
#include "../src/drivers/driver_cisco.c"
#include "refusal_contract.h"
#include <assert.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)

static void test_parser(void)
{
    char ifn[64], dsc[256]; bool neg = true;

    TEST("full form parses: name, text, negate=false");
    assert(cisco_parse_interface_description(
        "interface GigabitEthernet1/0/48 description uplink to core",
        ifn, sizeof ifn, dsc, sizeof dsc, &neg));
    assert(strcmp(ifn, "GigabitEthernet1/0/48") == 0);
    assert(strcmp(dsc, "uplink to core") == 0);
    assert(neg == false); PASS();

    TEST("leading/trailing whitespace tolerated, text trimmed");
    assert(cisco_parse_interface_description(
        "   interface Gi1/0/1   description   hello   ", ifn, sizeof ifn,
        dsc, sizeof dsc, &neg));
    assert(strcmp(ifn, "Gi1/0/1") == 0 && strcmp(dsc, "hello") == 0); PASS();

    TEST("no description parses with negate=true and empty text");
    assert(cisco_parse_interface_description(
        "interface Gi1/0/1 no description", ifn, sizeof ifn, dsc, sizeof dsc, &neg));
    assert(neg == true && dsc[0] == '\0'); PASS();

    TEST("NULL outputs are allowed (classifier use)");
    assert(cisco_parse_interface_description(
        "interface Gi1/0/1 description x", NULL, 0, NULL, 0, NULL)); PASS();

    TEST("rejects: not interface, bare, empty text, bad name, extra tokens");
    assert(!cisco_parse_interface_description("show version", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description  ", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface 1/0/1 description x", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 extra description x", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 no description x", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interfaceGi1/0/1 description x", NULL, 0, NULL, 0, NULL));
    PASS();

    TEST("rejects: separators, help char, control bytes in text");
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description a;b", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description a|b", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description a?", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description a`b", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description a\tb", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description a\nend", NULL, 0, NULL, 0, NULL));
    assert(!cisco_parse_interface_description("interface Gi1/0/1 description caf\xc3\xa9", NULL, 0, NULL, 0, NULL));
    PASS();

    TEST("rejects: interface name over 63 bytes");
    {
        char cmd[200]; char name[70]; memset(name, 'G', 64); name[64] = '\0';
        snprintf(cmd, sizeof cmd, "interface %s description x", name);
        assert(!cisco_parse_interface_description(cmd, NULL, 0, NULL, 0, NULL));
    }
    PASS();
}

static void test_executor_refuses_before_transport(void)
{
    virp_conn_t conn;
    virp_exec_result_t r;

    TEST("not connected: refused with no_dispatch (existing contract)");
    memset(&conn, 0, sizeof conn);
    conn.connected = false;
    snprintf(conn.device.hostname, sizeof conn.device.hostname, "R1");
    memset(&r, 0, sizeof r);
    virp_error_t e = cisco_execute(&conn, "interface Gi1/0/1 description x", &r);
    assert(e == VIRP_OK && !r.success && r.no_dispatch);
    PASS();

    TEST("connected but user EXEC (no enable): refused, NOT_SENT, no I/O");
    memset(&conn, 0, sizeof conn);
    conn.connected = true;               /* no io adapter: any transport use would crash */
    conn.in_enable = false;
    conn.current_mode = CISCO_MODE_USER;
    snprintf(conn.device.hostname, sizeof conn.device.hostname, "R1");
    memset(&r, 0, sizeof r);
    e = cisco_execute(&conn, "interface Gi1/0/1 description x", &r);
    RC_ASSERT_REFUSAL(e, r, "description transaction from user EXEC");
    assert(strstr(r.error_msg, "requires privileged EXEC") != NULL);
    PASS();

    TEST("connected but already in config mode: refused, NOT_SENT, no I/O");
    memset(&conn, 0, sizeof conn);
    conn.connected = true;
    conn.in_enable = true;
    conn.current_mode = CISCO_MODE_CONFIG;
    snprintf(conn.device.hostname, sizeof conn.device.hostname, "R1");
    memset(&r, 0, sizeof r);
    e = cisco_execute(&conn, "interface Gi1/0/1 description x", &r);
    RC_ASSERT_REFUSAL(e, r, "description transaction from config mode");
    PASS();

    TEST("BLACK still wins over the typed op (reload is never a description)");
    memset(&conn, 0, sizeof conn);
    conn.connected = true; conn.in_enable = true; conn.current_mode = CISCO_MODE_EXEC;
    snprintf(conn.device.hostname, sizeof conn.device.hostname, "R1");
    memset(&r, 0, sizeof r);
    e = cisco_execute(&conn, "reload", &r);
    RC_ASSERT_REFUSAL(e, r, "BLACK");
    PASS();
}

/* The retired flag must never authorize BLACK. Only the exact typed reboot
 * capability can pass its specific backstop; no actual device is contacted. */
static void test_black_backstop_only_exact_reboot(void)
{
    virp_conn_t conn;
    virp_exec_result_t r;
    memset(&conn, 0, sizeof conn);
    snprintf(conn.device.hostname, sizeof conn.device.hostname, "R1");
    TEST("retired passthrough flag cannot authorize config erasure");
    memset(&r, 0, sizeof r);
    virp_exec_passthrough = true;
    virp_error_t e = cisco_execute(&conn, "write erase", &r);
    virp_exec_passthrough = false;
    RC_ASSERT_REFUSAL(e, r, "BLACK even with retired flag");
    assert(strstr(r.error_msg, "BLACK tier") != NULL);
    PASS();

    TEST("exact reboot capability passes only its reboot backstop");
    virp_policy_action_t a;
    assert(!virp_policy_classify(VIRP_VENDOR_CISCO_IOS, "reload", &a));
    virp_policy_dispatch_enter(&a);
    memset(&r, 0, sizeof r);
    e = cisco_execute(&conn, "reload", &r);
    assert(e == VIRP_OK && !r.success && r.no_dispatch);
    assert(strstr(r.error_msg, "Not connected") != NULL);
    memset(&r, 0, sizeof r);
    e = cisco_execute(&conn, "write erase", &r);
    RC_ASSERT_REFUSAL(e, r, "reboot capability does not allow erase");
    assert(strstr(r.error_msg, "BLACK tier") != NULL);
    virp_policy_dispatch_leave();
    PASS();

    TEST("reboot is blocked again when scoped capability ends");
    memset(&r, 0, sizeof r);
    e = cisco_execute(&conn, "reload", &r);
    RC_ASSERT_REFUSAL(e, r, "BLACK after capability cleared");
    assert(strstr(r.error_msg, "BLACK tier") != NULL);
    PASS();
}

static void test_classifier_agrees_with_parser(void)
{
    TEST("classifier YELLOW iff the parser accepts (sample matrix)");
    const char *yes[] = { "interface Gi1/0/48 description uplink",
                          "interface Loopback0 no description",
                          "interface Te1/1/1.100 description sub-if" };
    const char *no[]  = { "interface Gi1/0/48 shutdown",
                          "interface Gi1/0/48 description",
                          "int Gi1/0/48 description x",
                          "interface Gi1/0/48 description a;reload" };
    for (size_t i = 0; i < sizeof yes / sizeof *yes; i++) {
        assert(cisco_parse_interface_description(yes[i], NULL, 0, NULL, 0, NULL));
        assert(cisco_gate_tier(yes[i]) == VIRP_TIER_YELLOW);
    }
    for (size_t i = 0; i < sizeof no / sizeof *no; i++) {
        assert(!cisco_parse_interface_description(no[i], NULL, 0, NULL, 0, NULL));
        assert(cisco_gate_tier(no[i]) == VIRP_TIER_RED);
    }
    PASS();
}

static void test_aaa_denials(void)
{
    TEST("TACACS command denials cannot report a successful transaction");
    assert(cisco_ios_rejected("% Authorization failed.\r\n"));
    assert(cisco_ios_rejected("Command authorization failed.\r\n"));
    assert(cisco_ios_rejected("% Command authorization failed.\r\n"));
    assert(cisco_ios_rejected("% Access denied\r\n"));
    assert(cisco_ios_rejected("% Permission denied\r\n"));
    assert(cisco_ios_rejected("% Unknown command: show interfaces absent\r\n"));
    assert(cisco_ios_rejected("  % Unknown command: bogus\r\n"));
    assert(!cisco_ios_rejected("description Unknown command: lab fixture\r\n"));
    assert(!cisco_ios_rejected("description Authorization failed. lab fixture\r\n"));
    assert(!cisco_ios_rejected("\r\n3850-Stack(config-if)#"));
    PASS();
}

static void test_health_probe_selection(void)
{
    TEST("health probe is explicit, bounded and mode-aware");
    virp_conn_t c; memset(&c, 0, sizeof(c));
    c.current_mode = CISCO_MODE_EXEC;
    assert(strcmp(cisco_health_probe(&c), "show clock") == 0);
    c.device.cisco_health_version = true;
    assert(strcmp(cisco_health_probe(&c), "show version") == 0);
    c.current_mode = CISCO_MODE_CONFIG_SUB;
    assert(strcmp(cisco_health_probe(&c), "do show version") == 0);
    c.device.cisco_health_version = false;
    assert(strcmp(cisco_health_probe(&c), "do show clock") == 0);
    PASS();
}

int main(void)
{
    printf("VIRP Cisco typed config op — interface description (C-04 Option A)\n");
    printf("================================================================\n");
    assert(cisco_driver.route_reason != NULL && cisco_iosxe_driver.route_reason != NULL);
    assert(strstr(cisco_gate_reason("interface Gi1/0/22 description test"), "exact device") != NULL);
    assert(cisco_gate_reason("show interfaces GigabitEthernet1/0/22") == NULL);
    test_health_probe_selection();
    test_aaa_denials();
    test_parser();
    test_classifier_agrees_with_parser();
    test_executor_refuses_before_transport();
    test_black_backstop_only_exact_reboot();
    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    RC_REPORT("test_driver_cisco_description");
    return tests_passed == tests_run ? 0 : 1;
}
