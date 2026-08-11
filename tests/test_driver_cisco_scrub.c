/*
 * test_driver_cisco_scrub.c — IOS config credential scrubbing
 *
 * `show running-config` is YELLOW (approval-gated) — briefly GREEN
 * 2026-08-10, reverted 2026-08-11 when the scrub was found to miss
 * secret classes. cisco_execute still scrubs credential material out
 * of the body BEFORE it reaches the signer: observation bodies land in
 * an append-only chain, so one unscrubbed config read would pin enable
 * secrets, password 7 strings, SNMP communities and ISAKMP keys into
 * the audit record permanently, across the whole fleet.
 *
 * Every secret value planted in the transcripts below carries the
 * substring "CANARY". The core assertion of this suite is a single
 * property: after cisco_scrub_config, no CANARY survives. The
 * structural assertions (non-secret lines preserved verbatim, line
 * count unchanged, CRLF endings kept, idempotence) keep the scrub
 * honest about NOT destroying the config's diagnostic value.
 *
 * Coverage boundary, stated plainly: the scrub is a pure function and
 * is tested against recorded IOS config shapes. The wiring inside
 * cisco_execute (scrub-before-copy, fail-closed on overflow) sits
 * around a live SSH channel and is exercised by the gate/driver suites
 * and the deployment canary, not here.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "virp_driver.h"

/* Declared in virp_driver_cisco.h, but that header embeds an opaque
 * virp_conn_t by value (the RESTCONF struct) and cannot be included
 * standalone — forward-declare the symbols under test, exactly as
 * test_driver_cisco_gate.c does. */
virp_trust_tier_t cisco_gate_tier(const char *command);
virp_error_t cisco_scrub_config(const char *in, size_t in_len,
                                char *out, size_t out_cap,
                                size_t *out_len);
bool cisco_command_returns_config(const char *command);

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
 * A running-config the way IOSv actually prints it (post prompt-strip,
 * as cisco_execute sees it). Every secret is a CANARY; every
 * non-secret line must survive byte-for-byte.
 */
static const char RUN_CFG[] =
    "Building configuration...\n"
    "\n"
    "Current configuration : 1834 bytes\n"
    "!\n"
    "version 15.9\n"
    "service timestamps debug datetime msec\n"
    "service password-encryption\n"
    "!\n"
    "hostname R1\n"
    "!\n"
    "enable secret 5 $1$abcd$CANARY0enablehash\n"
    "enable password 7 06CANARY1enablepw\n"
    "!\n"
    "username aiops-svc privilege 15 secret 5 $1$wxyz$CANARY2userhash\n"
    "username backup password 7 121ACANARY3userpw\n"
    "!\n"
    "aaa new-model\n"
    "tacacs-server host 10.0.0.9\n"
    "tacacs-server key 7 30CANARY4tacacs\n"
    "radius-server key CANARY5radius\n"
    "!\n"
    "radius server RAD1\n"
    " address ipv4 10.0.0.9 auth-port 1812 acct-port 1813\n"
    " key 0 12345678\n"
    "!\n"
    "tacacs server TAC1\n"
    " key 7 070C285F4D06\n"
    "!\n"
    "crypto isakmp key CANARY6isakmp address 203.0.113.7\n"
    "crypto isakmp key 6 CANARY7isakmpenc address 203.0.113.8\n"
    "!\n"
    "key chain RIPCHAIN\n"
    " key 1\n"
    "  key-string 7 073CANARY8chain\n"
    "!\n"
    "interface GigabitEthernet0/0\n"
    " ip address 10.0.0.50 255.255.255.0\n"
    " ip ospf authentication message-digest\n"
    " ip ospf message-digest-key 1 md5 7 05CANARY9ospf\n"
    " standby 1 ip 10.0.0.1\n"
    " standby 1 authentication CANARY10hsrp\n"
    "!\n"
    "router bgp 65001\n"
    " neighbor 10.0.0.2 password 7 095CANARY11bgp\n"
    "!\n"
    "snmp-server community CANARY12community RO 99\n"
    "snmp-server host 10.0.0.99 version 2c CANARY13trapcomm\n"
    "snmp-server location lab-rack-1\n"
    "ntp authentication-key 1 md5 141CANARY14ntp 7\n"
    "!\n"
    "line vty 0 4\n"
    " password 7 044CANARY15vty\n"
    " login local\n"
    "!\n"
    "end";

/* Lines that carry no secret and must come through untouched. */
static const char *PRESERVED_LINES[] = {
    "Building configuration...",
    "service password-encryption",
    "hostname R1",
    "tacacs-server host 10.0.0.9",
    "radius server RAD1",
    " address ipv4 10.0.0.9 auth-port 1812 acct-port 1813",
    "tacacs server TAC1",
    "key chain RIPCHAIN",
    " key 1",
    "interface GigabitEthernet0/0",
    " ip address 10.0.0.50 255.255.255.0",
    " ip ospf authentication message-digest",
    " standby 1 ip 10.0.0.1",
    "snmp-server location lab-rack-1",
    " login local",
    "end",
};

/* Redacted forms the scrub must produce (spot checks on shape). */
static const char *EXPECTED_REDACTIONS[] = {
    "enable secret <removed>",
    "enable password <removed>",
    "username aiops-svc privilege 15 secret <removed>",
    "tacacs-server key <removed>",
    "crypto isakmp key <removed> address 203.0.113.7",
    "crypto isakmp key 6 <removed> address 203.0.113.8",
    "  key-string <removed>",
    " ip ospf message-digest-key 1 md5 <removed>",
    " standby 1 authentication <removed>",
    " neighbor 10.0.0.2 password <removed>",
    "snmp-server community <removed>",
    "snmp-server host 10.0.0.99 <removed>",
    " password <removed>",
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
    virp_error_t err = cisco_scrub_config(RUN_CFG, strlen(RUN_CFG),
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
    CHECK(cisco_scrub_config(RUN_CFG, strlen(RUN_CFG),
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
    CHECK(cisco_scrub_config(RUN_CFG, strlen(RUN_CFG),
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
    CHECK(cisco_scrub_config(RUN_CFG, strlen(RUN_CFG),
                             OUT, sizeof(OUT), &len1) == VIRP_OK,
          "first scrub failed");
    CHECK(cisco_scrub_config(OUT, len1,
                             out2, sizeof(out2), &len2) == VIRP_OK,
          "second scrub failed");
    CHECK(len1 == len2 && memcmp(OUT, out2, len1) == 0,
          "scrub is not idempotent");
}

TEST(test_crlf_preserved)
{
    const char crlf_cfg[] =
        "hostname R9\r\n"
        "enable secret 5 $1$zz$CANARYcrlf\r\n"
        "end\r\n";
    char out[256];
    size_t out_len = 0;
    CHECK(cisco_scrub_config(crlf_cfg, strlen(crlf_cfg),
                             out, sizeof(out), &out_len) == VIRP_OK,
          "scrub failed");
    CHECK(strstr(out, "CANARY") == NULL, "CRLF secret survived");
    CHECK(strstr(out, "hostname R9\r\n") != NULL, "CRLF ending lost");
    CHECK(strstr(out, "enable secret <removed>\r\n") != NULL,
          "redacted CRLF line malformed");
}

TEST(test_overflow_fails_closed)
{
    char tiny[8];
    size_t out_len = 123;
    virp_error_t err = cisco_scrub_config(RUN_CFG, strlen(RUN_CFG),
                                          tiny, sizeof(tiny), &out_len);
    CHECK(err == VIRP_ERR_BUFFER_TOO_SMALL,
          "expected BUFFER_TOO_SMALL, got %d", (int)err);
    CHECK(out_len == 0, "out_len not zeroed on failure");
}

TEST(test_null_args)
{
    size_t out_len = 0;
    CHECK(cisco_scrub_config(NULL, 0, OUT, sizeof(OUT), &out_len)
              == VIRP_ERR_NULL_PTR, "NULL in accepted");
    CHECK(cisco_scrub_config(RUN_CFG, 4, NULL, 0, &out_len)
              == VIRP_ERR_NULL_PTR, "NULL out accepted");
    CHECK(cisco_scrub_config(RUN_CFG, 4, OUT, sizeof(OUT), NULL)
              == VIRP_ERR_NULL_PTR, "NULL out_len accepted");
}

TEST(test_trigger_commands)
{
    CHECK(cisco_command_returns_config("show running-config"),
          "running-config not flagged");
    CHECK(cisco_command_returns_config("show running-config interface g0/0"),
          "running-config subsection not flagged");
    CHECK(cisco_command_returns_config("show startup-config"),
          "startup-config not flagged");
    CHECK(cisco_command_returns_config("show tech-support"),
          "tech-support not flagged");
    CHECK(!cisco_command_returns_config("show version"),
          "show version wrongly flagged");
    CHECK(!cisco_command_returns_config("show ip route"),
          "show ip route wrongly flagged");
    CHECK(!cisco_command_returns_config(NULL), "NULL wrongly flagged");
}

/* Numeric and type-7 server-block keys carry no CANARY letters — a
 * purely numeric secret is exactly the class the letter-based canary
 * cannot catch, so these assert on the literal secret values. */
TEST(test_numeric_server_block_keys_redacted)
{
    size_t out_len = 0;
    CHECK(cisco_scrub_config(RUN_CFG, strlen(RUN_CFG),
                             OUT, sizeof(OUT), &out_len) == VIRP_OK,
          "scrub failed");
    CHECK(strstr(OUT, "12345678") == NULL,
          "numeric radius key survived: `key 0 12345678`");
    CHECK(strstr(OUT, "070C285F4D06") == NULL,
          "type-7 tacacs key survived: `key 7 070C285F4D06`");
    /* the key-chain index and block header must stay untouched */
    CHECK(strstr(OUT, " key 1\n") != NULL, "key-chain index damaged");
    CHECK(strstr(OUT, "key chain RIPCHAIN") != NULL,
          "key chain header damaged");
}

TEST(test_gate_tier_alignment)
{
    /* Reverted GREEN → YELLOW (2026-08-11): scrub misses secret
     * classes, so the read is approval-gated again. The scrub stays
     * wired on the YELLOW path. */
    CHECK(cisco_gate_tier("show running-config") == VIRP_TIER_YELLOW,
          "show running-config not YELLOW");
    /* Everything GREEN/YELLOW that returns config must be scrubbed. */
    CHECK(cisco_command_returns_config("show running-config") &&
          cisco_command_returns_config("show startup-config") &&
          cisco_command_returns_config("show tech-support"),
          "a config-bearing command escapes the scrub trigger");
    /* Startup-config and tech-support stay approval-gated. */
    CHECK(cisco_gate_tier("show startup-config") == VIRP_TIER_YELLOW,
          "show startup-config not YELLOW");
    CHECK(cisco_gate_tier("show tech-support") == VIRP_TIER_YELLOW,
          "show tech-support not YELLOW");
    /* Abbreviations still fail closed — the scrub trigger only needs
     * to recognize the canonical spellings the gate lets through. */
    CHECK(cisco_gate_tier("sh run") == VIRP_TIER_RED,
          "abbreviation escaped the fail-closed default");
    CHECK(cisco_gate_tier("show run") == VIRP_TIER_RED,
          "abbreviation escaped the fail-closed default");
}

int main(void)
{
    printf("test_driver_cisco_scrub:\n");

    RUN_TEST(test_no_canary_survives);
    RUN_TEST(test_numeric_server_block_keys_redacted);
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
