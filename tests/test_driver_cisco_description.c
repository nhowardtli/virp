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

int main(void)
{
    printf("VIRP Cisco typed config op — interface description (C-04 Option A)\n");
    printf("================================================================\n");
    test_parser();
    test_classifier_agrees_with_parser();
    test_executor_refuses_before_transport();
    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    RC_REPORT("test_driver_cisco_description");
    return tests_passed == tests_run ? 0 : 1;
}
