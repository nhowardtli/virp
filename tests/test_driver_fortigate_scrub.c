/*
 * test_driver_fortigate_scrub.c — FortiGate reply scrubbing (N1 / 2c)
 *
 * FortiGate is the one SSH driver with no cross-command carry-over: it
 * opens a fresh channel per command. Its body-integrity defects were
 * different, and both are covered here:
 *
 *   (a) the VDOM wrapper (`config vdom` / `edit <vdom>` / ... / `end`)
 *       was only partially scrubbed, so its echoes landed inside the
 *       SIGNED observation body;
 *   (b) the read outcome was never inspected — success was set
 *       unconditionally, so a truncated reply was signed as the
 *       device's answer.
 *
 * Coverage boundary, stated plainly: the scrub is a pure function and
 * is tested here against recorded FortiOS transcript shapes. The read
 * loop's new prompt_seen check (b) sits around libssh2 calls and needs
 * a live channel, so it is NOT directly exercised — what is tested is
 * the failure CONTRACT it shares with the malformed-reply path:
 * VIRP_ERR_NO_PROMPT out of fg_ssh_execute, which the O-Node turns
 * into a typed ERROR observation. Driving prompt_seen itself would
 * need FortiGate behind the same io vtable the other four drivers use;
 * that refactor is not part of 2c.
 *
 * The legacy scrub is frozen in below so each case is differential:
 * legacy must get it wrong, the current scrub must get it right.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "virp_driver.h"
#include "virp_driver_fortigate.h"

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
 * A VDOM-wrapped reply as FortiOS actually returns it: every line we
 * sent is echoed after a prompt.
 */
static const char VDOM_REPLY[] =
    "FGT-200G # config vdom\r\n"
    "FGT-200G (vdom) # edit root\r\n"
    "current vf=root:0\r\n"
    "FGT-200G (root) # get router info routing-table all\r\n"
    "Routing table for VRF=0\r\n"
    "S*    0.0.0.0/0 [10/0] via 203.0.113.1, wan1\r\n"
    "C     10.0.10.0/24 is directly connected, internal\r\n"
    "FGT-200G (root) # end\r\n"
    "FGT-200G # ";

static const char PLAIN_REPLY[] =
    "get system status\r\n"
    "Version: FortiOS v7.4.1 build2463\r\n"
    "Serial-Number: FG200G0000000000\r\n"
    "FGT-200G # ";

/* ── FROZEN legacy scrub (driver as of hardening-2026-07-29) ───────
 * Dropped the first line only, then trimmed the trailing prompt line.
 * Do NOT "fix" this — it exists to reproduce the defect. */
static char *legacy_scrub(char *raw, size_t total, size_t *out_len)
{
    char *start = strstr(raw, "\n");
    if (start) start++;
    else start = raw;

    char *end = raw + total;
    while (end > start && (end[-1] == ' ' || end[-1] == '#'
                           || end[-1] == '\r' || end[-1] == '\n'))
        end--;
    char *prompt_line = end;
    while (prompt_line > start && prompt_line[-1] != '\n')
        prompt_line--;

    size_t payload_len = (size_t)(prompt_line - start);
    if (payload_len > 0 && start[payload_len - 1] == '\r')
        payload_len--;
    *out_len = payload_len;
    return start;
}

/* ========================================================================= */

TEST(test_vdom_wrapper_echoes_not_in_body)
{
    char raw[2048];
    snprintf(raw, sizeof(raw), "%s", VDOM_REPLY);
    size_t out_len = 0;

    char *body = fg_scrub_reply(raw, strlen(raw),
                                "get router info routing-table all",
                                true, &out_len);
    CHECK(body != NULL, "scrub returned NULL on a well-formed reply");

    char got[2048];
    snprintf(got, sizeof(got), "%.*s", (int)out_len, body);

    CHECK(strstr(got, "config vdom") == NULL,
          "'config vdom' echo is in the signed body:\n---\n%s\n---", got);
    CHECK(strstr(got, "edit root") == NULL,
          "'edit root' echo is in the signed body:\n---\n%s\n---", got);
    CHECK(strstr(got, "get router info") == NULL,
          "command echo is in the signed body:\n---\n%s\n---", got);
    CHECK(strstr(got, "# end") == NULL && strstr(got, "\nend") == NULL,
          "'end' echo is in the signed body:\n---\n%s\n---", got);

    /* The device's actual answer must survive intact. */
    CHECK(strstr(got, "Routing table for VRF=0") != NULL,
          "first output line lost:\n---\n%s\n---", got);
    CHECK(strstr(got, "10.0.10.0/24") != NULL,
          "last output line lost:\n---\n%s\n---", got);

    /* --- frozen legacy: keeps the wrapper echoes --- */
    char lraw[2048];
    snprintf(lraw, sizeof(lraw), "%s", VDOM_REPLY);
    size_t llen = 0;
    char *lbody = legacy_scrub(lraw, strlen(lraw), &llen);
    char lgot[2048];
    snprintf(lgot, sizeof(lgot), "%.*s", (int)llen, lbody);
    CHECK(strstr(lgot, "edit root") != NULL && strstr(lgot, "end") != NULL,
          "legacy scrub no longer leaks wrapper echoes — this case has "
          "stopped being a regression test");
}

TEST(test_plain_command_body_is_output_only)
{
    char raw[2048];
    snprintf(raw, sizeof(raw), "%s", PLAIN_REPLY);
    size_t out_len = 0;

    char *body = fg_scrub_reply(raw, strlen(raw), "get system status",
                                false, &out_len);
    CHECK(body != NULL, "scrub returned NULL on a well-formed reply");

    char got[2048];
    snprintf(got, sizeof(got), "%.*s", (int)out_len, body);

    CHECK(strstr(got, "get system status") == NULL,
          "command echo is in the body: '%s'", got);
    CHECK(strstr(got, "Version: FortiOS") != NULL,
          "output lost: '%s'", got);
    CHECK(strstr(got, "Serial-Number") != NULL,
          "output truncated: '%s'", got);
}

TEST(test_config_end_line_does_not_truncate_body)
{
    /*
     * `show router ...` output contains its own `end` line. Cutting at
     * the FIRST `end` would swallow the rest of the answer; the
     * wrapper's echo is always the LAST one.
     */
    static const char reply[] =
        "FGT-200G # config vdom\r\n"
        "FGT-200G (vdom) # edit root\r\n"
        "FGT-200G (root) # show router bgp\r\n"
        "config router bgp\r\n"
        "    set as 65001\r\n"
        "    config neighbor\r\n"
        "        edit \"10.0.0.2\"\r\n"
        "        next\r\n"
        "    end\r\n"
        "TRAILING-MARKER-AFTER-CONFIG-END\r\n"
        "end\r\n"
        "FGT-200G (root) # end\r\n"
        "FGT-200G # ";

    char raw[2048];
    snprintf(raw, sizeof(raw), "%s", reply);
    size_t out_len = 0;

    char *body = fg_scrub_reply(raw, strlen(raw), "show router bgp",
                                true, &out_len);
    CHECK(body != NULL, "scrub returned NULL");

    char got[2048];
    snprintf(got, sizeof(got), "%.*s", (int)out_len, body);

    CHECK(strstr(got, "set as 65001") != NULL,
          "config body lost:\n---\n%s\n---", got);
    CHECK(strstr(got, "TRAILING-MARKER-AFTER-CONFIG-END") != NULL,
          "body truncated at the config's own 'end' line:\n---\n%s\n---", got);
    /* The config's OWN closing 'end' is part of the device's answer and
     * must survive; only the wrapper's echo is scaffolding. */
    CHECK(strstr(got, "\nend") != NULL,
          "config's own closing 'end' was eaten:\n---\n%s\n---", got);
    /* The wrapper's own echo line must still be gone. */
    CHECK(strstr(got, "(root) # end") == NULL,
          "wrapper 'end' echo retained:\n---\n%s\n---", got);
}

TEST(test_missing_command_echo_is_refused)
{
    /*
     * Without the echo there is no way to locate where the device's
     * answer starts. The old positional skip would have returned a body
     * anyway — either carrying wrapper echoes or missing a real line.
     */
    static const char reply[] =
        "FGT-200G # config vdom\r\n"
        "FGT-200G (vdom) # edit root\r\n"
        "some output with no command echo\r\n"
        "FGT-200G # ";

    char raw[1024];
    snprintf(raw, sizeof(raw), "%s", reply);
    size_t out_len = 0;

    char *body = fg_scrub_reply(raw, strlen(raw),
                                "get router info routing-table all",
                                true, &out_len);
    CHECK(body == NULL, "expected refusal, got a body");
    CHECK(out_len == 0, "expected zero length on refusal, got %zu", out_len);
}

/* ========================================================================= */

int main(void)
{
    printf("\n=== VIRP FortiGate Reply Scrub Tests (finding N1 / 2c) ===\n\n");

    RUN_TEST(test_vdom_wrapper_echoes_not_in_body);
    RUN_TEST(test_plain_command_body_is_output_only);
    RUN_TEST(test_config_end_line_does_not_truncate_body);
    RUN_TEST(test_missing_command_echo_is_refused);

    printf("\n================================================================\n");
    printf("  Results: %d/%d passed%s\n", tests_run - tests_failed, tests_run,
           tests_failed ? "  (FAILED)" : "");
    printf("================================================================\n\n");
    return tests_failed ? 1 : 0;
}
