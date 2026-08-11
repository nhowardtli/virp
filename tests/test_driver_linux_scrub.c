/*
 * test_driver_linux_scrub.c — FRR config credential scrubbing
 *
 * `vtysh -c "show running-config"` (and startup-config, and their
 * vtysh-expanded abbreviations) is YELLOW on the linux/FRR driver,
 * but an approved read still returns config text carrying credential
 * material inline: `password`, `enable password`, `neighbor <ip>
 * password`, `ip ospf message-digest-key <n> md5`, key-chain
 * `key-string`, `ip ospf authentication-key`. Observation bodies are
 * signed into an append-only chain, so linux_execute scrubs the body
 * BEFORE it reaches the signer — same contract as cisco_scrub_config
 * (pure function, fail-closed, exposed for tests).
 *
 * Every secret planted below carries the substring "CANARY"; the core
 * property is that no CANARY survives the scrub. Structural
 * assertions (non-secret lines preserved, line count unchanged,
 * idempotence) keep the scrub honest about NOT destroying the
 * config's diagnostic value.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "virp_driver.h"

/* Defined in driver_linux.c, exposed for this suite — same
 * forward-declaration pattern as the cisco/ASA scrub suites. */
virp_error_t linux_scrub_config(const char *in, size_t in_len,
                                char *out, size_t out_cap,
                                size_t *out_len);
bool linux_command_returns_config(const char *command);
virp_trust_tier_t linux_gate_tier(const char *command);

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
 * An FRR running-config the way vtysh prints it (with the driver's
 * hostname-prefix line, as linux_execute assembles the body). Every
 * secret is a CANARY; every non-secret line must survive verbatim.
 */
static const char RUN_CFG[] =
    "netclaw-node$ vtysh -c \"show running-config\"\n"
    "Building configuration...\n"
    "\n"
    "Current configuration:\n"
    "!\n"
    "frr version 8.4.4\n"
    "frr defaults traditional\n"
    "hostname frr-r1\n"
    "password CANARY0zebra\n"
    "enable password CANARY1enable\n"
    "log syslog informational\n"
    "!\n"
    "key chain OSPFKEYS\n"
    " key 1\n"
    "  key-string CANARY2chain\n"
    "!\n"
    "interface eth0\n"
    " ip address 10.10.12.1/24\n"
    " ip ospf authentication message-digest\n"
    " ip ospf message-digest-key 1 md5 CANARY3ospf\n"
    " ip ospf authentication-key CANARY4authkey\n"
    "!\n"
    "router bgp 65001\n"
    " neighbor 10.10.12.2 remote-as 65002\n"
    " neighbor 10.10.12.2 password CANARY5bgp\n"
    "!\n"
    "router ospf\n"
    " ospf router-id 1.1.1.1\n"
    " area 0 authentication message-digest\n"
    "!\n"
    "line vty\n"
    "end";

static const char *PRESERVED_LINES[] = {
    "netclaw-node$ vtysh -c \"show running-config\"",
    "Building configuration...",
    "frr version 8.4.4",
    "frr defaults traditional",
    "hostname frr-r1",
    "log syslog informational",
    "key chain OSPFKEYS",
    " key 1",
    "interface eth0",
    " ip address 10.10.12.1/24",
    " ip ospf authentication message-digest",
    " neighbor 10.10.12.2 remote-as 65002",
    " ospf router-id 1.1.1.1",
    " area 0 authentication message-digest",
    "line vty",
    "end",
};

static size_t count_lines(const char *s)
{
    size_t n = 1;
    for (; *s; s++) if (*s == '\n') n++;
    return n;
}

static char OUT[4 * sizeof(RUN_CFG) + 64];

static bool scrub_ok(size_t *out_len)
{
    return linux_scrub_config(RUN_CFG, strlen(RUN_CFG),
                              OUT, sizeof(OUT), out_len) == VIRP_OK;
}

TEST(test_no_canary_survives)
{
    size_t out_len = 0;
    CHECK(scrub_ok(&out_len), "scrub failed");
    CHECK(out_len == strlen(OUT), "out_len %zu != strlen %zu",
          out_len, strlen(OUT));
    CHECK(strstr(OUT, "CANARY") == NULL,
          "credential material survived the scrub: ...%.40s",
          strstr(OUT, "CANARY"));
}

/* One class per test, each asserting the secret value is gone. */

TEST(test_password_redacted)
{
    size_t out_len = 0;
    CHECK(scrub_ok(&out_len), "scrub failed");
    CHECK(strstr(OUT, "CANARY0zebra") == NULL, "vty password survived");
    CHECK(strstr(OUT, "password <removed>") != NULL,
          "password redacted form missing");
}

TEST(test_enable_password_redacted)
{
    size_t out_len = 0;
    CHECK(scrub_ok(&out_len), "scrub failed");
    CHECK(strstr(OUT, "CANARY1enable") == NULL, "enable password survived");
    CHECK(strstr(OUT, "enable password <removed>") != NULL,
          "enable password redacted form missing");
}

TEST(test_neighbor_password_redacted)
{
    size_t out_len = 0;
    CHECK(scrub_ok(&out_len), "scrub failed");
    CHECK(strstr(OUT, "CANARY5bgp") == NULL, "bgp neighbor password survived");
    CHECK(strstr(OUT, " neighbor 10.10.12.2 password <removed>") != NULL,
          "neighbor address not preserved on redaction");
}

TEST(test_message_digest_key_redacted)
{
    size_t out_len = 0;
    CHECK(scrub_ok(&out_len), "scrub failed");
    CHECK(strstr(OUT, "CANARY3ospf") == NULL, "ospf md5 key survived");
    CHECK(strstr(OUT, " ip ospf message-digest-key 1 md5 <removed>") != NULL,
          "message-digest-key redacted form missing");
}

TEST(test_keystring_and_authkey_redacted)
{
    size_t out_len = 0;
    CHECK(scrub_ok(&out_len), "scrub failed");
    CHECK(strstr(OUT, "CANARY2chain") == NULL, "key-string survived");
    CHECK(strstr(OUT, "CANARY4authkey") == NULL,
          "ospf authentication-key survived");
    CHECK(strstr(OUT, "  key-string <removed>") != NULL,
          "key-string redacted form missing");
}

TEST(test_non_secret_lines_preserved)
{
    size_t out_len = 0;
    CHECK(scrub_ok(&out_len), "scrub failed");
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
    CHECK(scrub_ok(&len1), "first scrub failed");
    CHECK(linux_scrub_config(OUT, len1,
                             out2, sizeof(out2), &len2) == VIRP_OK,
          "second scrub failed");
    CHECK(len1 == len2 && memcmp(OUT, out2, len1) == 0,
          "scrub is not idempotent");
}

TEST(test_overflow_fails_closed)
{
    char tiny[8];
    size_t out_len = 123;
    CHECK(linux_scrub_config(RUN_CFG, strlen(RUN_CFG),
                             tiny, sizeof(tiny), &out_len)
              == VIRP_ERR_BUFFER_TOO_SMALL,
          "undersized output not refused");
    CHECK(out_len == 0, "out_len not zeroed on failure");
}

TEST(test_null_args)
{
    size_t out_len = 0;
    CHECK(linux_scrub_config(NULL, 0, OUT, sizeof(OUT), &out_len)
              == VIRP_ERR_NULL_PTR, "NULL in accepted");
    CHECK(linux_scrub_config(RUN_CFG, strlen(RUN_CFG),
                             NULL, 0, &out_len)
              == VIRP_ERR_NULL_PTR, "NULL out accepted");
    CHECK(linux_scrub_config(RUN_CFG, strlen(RUN_CFG),
                             OUT, sizeof(OUT), NULL)
              == VIRP_ERR_NULL_PTR, "NULL out_len accepted");
}

/* The scrub trigger must cast the same net as the gate's YELLOW
 * config-read row, vtysh prefix expansion included. */
TEST(test_trigger_commands)
{
    CHECK(linux_command_returns_config("vtysh -c \"show running-config\""),
          "running-config not flagged");
    CHECK(linux_command_returns_config("vtysh -c \"show run\""),
          "abbreviated show run not flagged");
    CHECK(linux_command_returns_config("vtysh -c \"show startup-config\""),
          "startup-config not flagged");
    CHECK(linux_command_returns_config("vtysh -c \"show start\""),
          "abbreviated show start not flagged");
    CHECK(linux_command_returns_config("vtysh  -c  \"show  run\""),
          "whitespace-run form not flagged");
    CHECK(!linux_command_returns_config("vtysh -c \"show ip route\""),
          "show ip route wrongly flagged");
    CHECK(!linux_command_returns_config("vtysh -c \"show rundown\""),
          "show rundown wrongly flagged");
    CHECK(!linux_command_returns_config("uptime"), "uptime wrongly flagged");
    CHECK(!linux_command_returns_config(NULL), "NULL wrongly flagged");
}

/* Gate alignment: every command the trigger flags must be YELLOW at
 * the gate — a config read that could auto-execute GREEN would sign
 * its body without approval. */
TEST(test_gate_tier_alignment)
{
    static const char *const config_reads[] = {
        "vtysh -c \"show running-config\"",
        "vtysh -c \"show run\"",
        "vtysh -c \"show startup-config\"",
        "vtysh -c \"show start\"",
    };
    for (size_t i = 0;
         i < sizeof(config_reads) / sizeof(config_reads[0]); i++) {
        CHECK(linux_command_returns_config(config_reads[i]),
              "trigger misses '%s'", config_reads[i]);
        CHECK(linux_gate_tier(config_reads[i]) == VIRP_TIER_YELLOW,
              "'%s' not YELLOW at the gate", config_reads[i]);
    }
}

int main(void)
{
    printf("test_driver_linux_scrub:\n");

    RUN_TEST(test_no_canary_survives);
    RUN_TEST(test_password_redacted);
    RUN_TEST(test_enable_password_redacted);
    RUN_TEST(test_neighbor_password_redacted);
    RUN_TEST(test_message_digest_key_redacted);
    RUN_TEST(test_keystring_and_authkey_redacted);
    RUN_TEST(test_non_secret_lines_preserved);
    RUN_TEST(test_idempotent);
    RUN_TEST(test_overflow_fails_closed);
    RUN_TEST(test_null_args);
    RUN_TEST(test_trigger_commands);
    RUN_TEST(test_gate_tier_alignment);

    printf("\n%d tests, %d failures\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
