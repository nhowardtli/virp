/*
 * test_driver_asa_scrub.c — ASA config credential scrubbing
 *
 * Port of the cisco scrub suite (test_driver_cisco_scrub.c) to the ASA
 * directive set. ASA `show running-config` stays YELLOW — but an
 * approval should let a human read a config, not pin the firewall's
 * enable/passwd hashes, aaa-server keys, SNMP communities and
 * tunnel-group pre-shared-keys into the append-only chain. The scrub
 * runs inside asa_execute BEFORE the body reaches the signer.
 *
 * Same property-based core: every planted secret carries "CANARY", and
 * no CANARY may survive asa_scrub_config. Structural assertions keep
 * the scrub honest about preserving the config's diagnostic value.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "virp_driver.h"
#include "virp_driver_asa.h"

static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(fn) do {                             \
    printf("  %-58s", #fn);                           \
    fflush(stdout);                                   \
    int before = tests_failed;                        \
    tests_run++;                                      \
    fn();                                             \
    if (tests_failed == before) printf(" [PASS]\n");  \
} while (0)

#define FAIL(...) do {                                \
    printf(" [FAIL]\n    ");                          \
    printf(__VA_ARGS__);                              \
    printf("\n");                                     \
    tests_failed++;                                   \
    return;                                           \
} while (0)

#define CHECK(cond, ...) do { if (!(cond)) FAIL(__VA_ARGS__); } while (0)

/*
 * A running-config the way ASA 9.x prints it (post prompt-strip, as
 * asa_execute sees it). Every secret is a CANARY; every non-secret
 * line must survive byte-for-byte.
 */
static const char RUN_CFG[] =
    ": Saved\n"
    ":\n"
    "ASA Version 9.16(4)\n"
    "!\n"
    "hostname ASA-Lab\n"
    "domain-name lab.example\n"
    "enable password CANARY0enable pbkdf2\n"
    "passwd CANARY1passwd encrypted\n"
    "names\n"
    "!\n"
    "interface GigabitEthernet0/0\n"
    " nameif outside\n"
    " security-level 0\n"
    " ip address 203.0.113.2 255.255.255.0\n"
    " authentication key eigrp 100 CANARY2eigrp key-id 1\n"
    " ospf message-digest-key 1 md5 CANARY3ospf\n"
    "!\n"
    "username aiops-svc password CANARY4user pbkdf2 privilege 15\n"
    "username aiops-svc attributes\n"
    " service-type admin\n"
    "!\n"
    "aaa-server TACSRV protocol tacacs+\n"
    "aaa-server TACSRV (inside) host 10.0.0.9\n"
    " key CANARY5aaakey\n"
    " timeout 10\n"
    "aaa-server LEGACY (inside) host 10.0.0.8 CANARY6inlinekey timeout 10\n"
    "aaa-server LDAPSRV (inside) host 10.0.0.7\n"
    " ldap-login-password CANARY7ldap\n"
    " ldap-login-dn cn=svc,dc=lab\n"
    "aaa authentication ssh console TACSRV LOCAL\n"
    "!\n"
    "snmp-server host inside 10.0.0.99 community CANARY8trapcomm version 2c\n"
    "snmp-server community CANARY9community\n"
    "snmp-server location lab-rack-1\n"
    "!\n"
    "crypto isakmp key CANARY10isakmp address 198.51.100.7\n"
    "crypto ikev1 policy 10\n"
    " authentication pre-share\n"
    "tunnel-group 198.51.100.9 type ipsec-l2l\n"
    "tunnel-group 198.51.100.9 ipsec-attributes\n"
    " ikev1 pre-shared-key CANARY11psk\n"
    " ikev2 remote-authentication pre-shared-key CANARY12psk2\n"
    " ikev2 local-authentication pre-shared-key CANARY13psk3\n"
    "!\n"
    "failover\n"
    "failover lan unit primary\n"
    "failover key CANARY14failover\n"
    "!\n"
    "ntp authentication-key 1 md5 CANARY15ntp\n"
    "key chain EIGRPCHAIN\n"
    " key 1\n"
    "  key-string CANARY16chain\n"
    "!\n"
    "Cryptochecksum:0123456789abcdef0123456789abcdef\n"
    ": end";

/* Lines that carry no secret and must come through untouched. */
static const char *PRESERVED_LINES[] = {
    ": Saved",
    "ASA Version 9.16(4)",
    "hostname ASA-Lab",
    "names",
    "interface GigabitEthernet0/0",
    " nameif outside",
    " security-level 0",
    " ip address 203.0.113.2 255.255.255.0",
    "username aiops-svc attributes",
    " service-type admin",
    "aaa-server TACSRV protocol tacacs+",
    "aaa-server TACSRV (inside) host 10.0.0.9",
    " timeout 10",
    " ldap-login-dn cn=svc,dc=lab",
    "aaa authentication ssh console TACSRV LOCAL",
    "snmp-server location lab-rack-1",
    "crypto ikev1 policy 10",
    " authentication pre-share",
    "tunnel-group 198.51.100.9 type ipsec-l2l",
    "failover lan unit primary",
    "key chain EIGRPCHAIN",
    " key 1",
    "Cryptochecksum:0123456789abcdef0123456789abcdef",
    ": end",
};

/* Redacted forms the scrub must produce (spot checks on shape). */
static const char *EXPECTED_REDACTIONS[] = {
    "enable password <removed>",
    "passwd <removed>",
    " authentication key <removed>",
    " ospf message-digest-key 1 md5 <removed>",
    "username aiops-svc password <removed>",
    " key <removed>",
    "aaa-server LEGACY (inside) host 10.0.0.8 <removed>",
    " ldap-login-password <removed>",
    "snmp-server host inside 10.0.0.99 <removed>",
    "snmp-server community <removed>",
    "crypto isakmp key <removed> address 198.51.100.7",
    " ikev1 pre-shared-key <removed>",
    " ikev2 remote-authentication pre-shared-key <removed>",
    " ikev2 local-authentication pre-shared-key <removed>",
    "failover key <removed>",
    "ntp authentication-key <removed>",
    "  key-string <removed>",
};

static size_t count_lines(const char *s)
{
    size_t n = 1;
    for (; *s; s++) if (*s == '\n') n++;
    return n;
}

static char OUT[4 * sizeof(RUN_CFG) + 64];

TEST(test_no_canary_survives)
{
    size_t out_len = 0;
    virp_error_t err = asa_scrub_config(RUN_CFG, strlen(RUN_CFG),
                                        OUT, sizeof(OUT), &out_len);
    CHECK(err == VIRP_OK, "scrub returned %d", (int)err);
    CHECK(out_len == strlen(OUT), "out_len %zu != strlen %zu",
          out_len, strlen(OUT));
    CHECK(strstr(OUT, "CANARY") == NULL,
          "credential material survived the scrub: ...%.40s",
          strstr(OUT, "CANARY"));
}

TEST(test_expected_redactions_present)
{
    size_t out_len = 0;
    CHECK(asa_scrub_config(RUN_CFG, strlen(RUN_CFG),
                           OUT, sizeof(OUT), &out_len) == VIRP_OK,
          "scrub failed");
    for (size_t i = 0;
         i < sizeof(EXPECTED_REDACTIONS) / sizeof(EXPECTED_REDACTIONS[0]);
         i++) {
        CHECK(strstr(OUT, EXPECTED_REDACTIONS[i]) != NULL,
              "missing redacted form: '%s'", EXPECTED_REDACTIONS[i]);
    }
}

TEST(test_non_secret_lines_preserved)
{
    size_t out_len = 0;
    CHECK(asa_scrub_config(RUN_CFG, strlen(RUN_CFG),
                           OUT, sizeof(OUT), &out_len) == VIRP_OK,
          "scrub failed");
    for (size_t i = 0;
         i < sizeof(PRESERVED_LINES) / sizeof(PRESERVED_LINES[0]); i++) {
        CHECK(strstr(OUT, PRESERVED_LINES[i]) != NULL,
              "non-secret line damaged: '%s'", PRESERVED_LINES[i]);
    }
    CHECK(count_lines(OUT) == count_lines(RUN_CFG),
          "line count changed: %zu -> %zu",
          count_lines(RUN_CFG), count_lines(OUT));
}

TEST(test_idempotent)
{
    static char out2[sizeof(OUT)];
    size_t len1 = 0, len2 = 0;
    CHECK(asa_scrub_config(RUN_CFG, strlen(RUN_CFG),
                           OUT, sizeof(OUT), &len1) == VIRP_OK,
          "first scrub failed");
    CHECK(asa_scrub_config(OUT, len1,
                           out2, sizeof(out2), &len2) == VIRP_OK,
          "second scrub failed");
    CHECK(len1 == len2 && memcmp(OUT, out2, len1) == 0,
          "scrub is not idempotent");
}

TEST(test_crlf_preserved)
{
    const char crlf_cfg[] =
        "hostname ASA-9\r\n"
        "enable password CANARYcrlf pbkdf2\r\n"
        ": end\r\n";
    char out[256];
    size_t out_len = 0;
    CHECK(asa_scrub_config(crlf_cfg, strlen(crlf_cfg),
                           out, sizeof(out), &out_len) == VIRP_OK,
          "scrub failed");
    CHECK(strstr(out, "CANARY") == NULL, "CRLF secret survived");
    CHECK(strstr(out, "hostname ASA-9\r\n") != NULL, "CRLF ending lost");
    CHECK(strstr(out, "enable password <removed>\r\n") != NULL,
          "redacted CRLF line malformed");
}

TEST(test_overflow_fails_closed)
{
    char tiny[8];
    size_t out_len = 123;
    virp_error_t err = asa_scrub_config(RUN_CFG, strlen(RUN_CFG),
                                        tiny, sizeof(tiny), &out_len);
    CHECK(err == VIRP_ERR_BUFFER_TOO_SMALL,
          "expected BUFFER_TOO_SMALL, got %d", (int)err);
    CHECK(out_len == 0, "out_len not zeroed on failure");
}

TEST(test_null_args)
{
    size_t out_len = 0;
    CHECK(asa_scrub_config(NULL, 0, OUT, sizeof(OUT), &out_len)
              == VIRP_ERR_NULL_PTR, "NULL in accepted");
    CHECK(asa_scrub_config(RUN_CFG, 4, NULL, 0, &out_len)
              == VIRP_ERR_NULL_PTR, "NULL out accepted");
    CHECK(asa_scrub_config(RUN_CFG, 4, OUT, sizeof(OUT), NULL)
              == VIRP_ERR_NULL_PTR, "NULL out_len accepted");
}

TEST(test_trigger_commands)
{
    CHECK(asa_command_returns_config("show running-config"),
          "running-config not flagged");
    CHECK(asa_command_returns_config("show running-config access-list"),
          "running-config subsection not flagged");
    CHECK(asa_command_returns_config("show startup-config"),
          "startup-config not flagged");
    CHECK(asa_command_returns_config("show tech-support"),
          "tech-support not flagged");
    CHECK(asa_command_returns_config("more system:running-config"),
          "more system:running-config not flagged");
    CHECK(!asa_command_returns_config("show version"),
          "show version wrongly flagged");
    CHECK(!asa_command_returns_config("show route"),
          "show route wrongly flagged");
    CHECK(!asa_command_returns_config(NULL), "NULL wrongly flagged");
}

TEST(test_gate_tier_alignment)
{
    /* ASA config reads stay YELLOW — the scrub protects the APPROVED
     * path; it does not reclassify. */
    CHECK(asa_route_command("show running-config") == VIRP_TIER_YELLOW,
          "show running-config not YELLOW");
    CHECK(asa_route_command("show startup-config") == VIRP_TIER_YELLOW,
          "show startup-config not YELLOW");
    /* Every gate-listed config-bearing read must hit the scrub. */
    CHECK(asa_command_returns_config("show running-config") &&
          asa_command_returns_config("show running-config access-list") &&
          asa_command_returns_config("show startup-config"),
          "a config-bearing command escapes the scrub trigger");
    /* The unmasked-config variant stays RED (fail-closed, unlisted)
     * AND is covered by the scrub if it is ever approved. */
    CHECK(asa_route_command("more system:running-config") == VIRP_TIER_RED,
          "more system:running-config not RED");
}

int main(void)
{
    printf("test_driver_asa_scrub:\n");

    RUN_TEST(test_no_canary_survives);
    RUN_TEST(test_expected_redactions_present);
    RUN_TEST(test_non_secret_lines_preserved);
    RUN_TEST(test_idempotent);
    RUN_TEST(test_crlf_preserved);
    RUN_TEST(test_overflow_fails_closed);
    RUN_TEST(test_null_args);
    RUN_TEST(test_trigger_commands);
    RUN_TEST(test_gate_tier_alignment);

    printf("\n%d tests, %d failures\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
