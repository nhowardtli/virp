/*
 * test_virp_scrub.c — scrub-at-capture (S-1) unit suite
 *
 * The generic O-Node capture-path scrubber: known-shapes secret
 * redaction applied to the exec result BEFORE the body is hashed,
 * signed, or committed to anywhere (insertion point: the
 * virp_scrub_exec_result call in onode_execute_obs_ex). This suite
 * drives the pure scanner and the fail-closed wrapper directly; the
 * end-to-end gates (capture → sign → chain → verify, G1–G4) live in
 * tests/test_onode.c where the gx_* chain harness is.
 *
 * Same core property as the driver scrub suites: every planted secret
 * carries the substring "CANARY", and after the scrub no CANARY
 * survives. The structural assertions keep the scrub honest about NOT
 * destroying the body's diagnostic value — and about the honesty
 * limit: an UNLABELED secret is deliberately not caught, and there is
 * a test pinning that so nobody ever claims otherwise.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "virp_scrub.h"

static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(fn) do {                             \
    printf("  %-58s", #fn);                           \
    fflush(stdout);                                    \
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

static char OUT[4 * VIRP_OUTPUT_MAX];
static unsigned N;   /* redaction count from the last scrub() call */

/* run the scanner, NUL-terminate for strstr-based assertions */
static virp_error_t scrub(const char *in)
{
    size_t out_len = 0;
    N = 0;
    virp_error_t err = virp_scrub_body(in, strlen(in), OUT, sizeof(OUT),
                                       &out_len, &N);
    OUT[(err == VIRP_OK) ? out_len : 0] = '\0';
    return err;
}

/* =========================================================================
 * The ruleset, shape by shape
 * ========================================================================= */

TEST(test_cisco_credential_lines)
{
    CHECK(scrub("hostname R1\n"
                "enable secret 5 $1$abcd$CANARY0hash\n"
                "enable password 7 06CANARY1pw\n"
                "username svc privilege 15 secret 5 $1$wx$CANARY2u\n"
                "username backup password 7 121ACANARY3pw\n"
                "line vty 0 4\n"
                " password CANARY4vty\n") == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "secret survived:\n%s", OUT);
    CHECK(N == 5, "expected 5 redactions, got %u", N);
    CHECK(strstr(OUT, "hostname R1\n") != NULL, "clean line lost");
    CHECK(strstr(OUT, "enable secret [REDACTED: enable-secret]") != NULL,
          "enable-secret marker missing:\n%s", OUT);
    CHECK(strstr(OUT, "enable password [REDACTED: enable-password]") != NULL,
          "enable-password marker missing");
    CHECK(strstr(OUT, "username svc privilege 15 secret [REDACTED: secret]")
              != NULL, "username secret structure lost:\n%s", OUT);
    CHECK(strstr(OUT, " password [REDACTED: password]") != NULL,
          "vty password marker missing");
}

TEST(test_password_encryption_service_line_untouched)
{
    /* exact-token matching: "password-encryption" is not "password" */
    CHECK(scrub("service password-encryption\n"
                "ip ospf authentication message-digest\n") == VIRP_OK,
          "scrub failed");
    CHECK(N == 0, "false positive: %u redactions on clean config", N);
    CHECK(strcmp(OUT, "service password-encryption\n"
                      "ip ospf authentication message-digest\n") == 0,
          "clean lines not byte-identical");
}

TEST(test_snmp_community_token_only)
{
    CHECK(scrub("snmp-server community CANARYcomm RO 99\n"
                "snmp-server location closet-3\n") == VIRP_OK,
          "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "community survived");
    CHECK(N == 1, "expected 1 redaction, got %u", N);
    /* the token is replaced; RO and the ACL stay visible */
    CHECK(strstr(OUT,
          "snmp-server community [REDACTED: snmp-community] RO 99\n")
              != NULL, "community line structure lost:\n%s", OUT);
    CHECK(strstr(OUT, "snmp-server location closet-3\n") != NULL,
          "unrelated snmp-server line damaged");
}

TEST(test_isakmp_key_keeps_peer_address)
{
    CHECK(scrub("crypto isakmp key CANARY6psk address 203.0.113.7\n"
                "crypto isakmp key 6 CANARY7enc address 203.0.113.8\n")
              == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "isakmp key survived");
    CHECK(N == 2, "expected 2 redactions, got %u", N);
    CHECK(strstr(OUT, "[REDACTED: pre-shared-key] address 203.0.113.7\n")
              != NULL, "peer address lost:\n%s", OUT);
    CHECK(strstr(OUT, "key 6 [REDACTED: pre-shared-key] address 203.0.113.8")
              != NULL, "encrypted-form key line malformed:\n%s", OUT);
}

TEST(test_psk_and_wpa_psk)
{
    CHECK(scrub("pre-shared-key CANARY8psk\n"
                "wpa-psk CANARY9wpa\n"
                "psk=CANARY10supplicant\n") == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "psk survived:\n%s", OUT);
    CHECK(N == 3, "expected 3 redactions, got %u", N);
    CHECK(strstr(OUT, "pre-shared-key [REDACTED: pre-shared-key]") != NULL,
          "pre-shared-key marker missing");
    CHECK(strstr(OUT, "psk=[REDACTED: psk]") != NULL,
          "wpa_supplicant psk= form missed:\n%s", OUT);
}

TEST(test_leading_key_with_exceptions)
{
    CHECK(scrub("key chain RIPCHAIN\n"
                " key 2\n"
                "  key-string CANARY11ks\n"
                "key CANARY12tacacs\n") == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "key value survived:\n%s", OUT);
    CHECK(N == 2, "expected 2 redactions, got %u", N);
    /* the two exceptions are preserved verbatim */
    CHECK(strstr(OUT, "key chain RIPCHAIN\n") != NULL,
          "key-chain block header damaged");
    CHECK(strstr(OUT, " key 2\n") != NULL, "key-chain index damaged");
    CHECK(strstr(OUT, "key-string [REDACTED: key-string]") != NULL,
          "key-string marker missing");
    CHECK(strstr(OUT, "key [REDACTED: key]") != NULL,
          "leading-key marker missing");
}

TEST(test_pem_private_key_block)
{
    CHECK(scrub("host key follows\n"
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "CANARY13line1base64\n"
                "CANARY14line2base64\n"
                "-----END OPENSSH PRIVATE KEY-----\n"
                "trailing diagnostic\n") == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "PEM interior survived:\n%s", OUT);
    CHECK(N == 1, "block counts as ONE redaction, got %u", N);
    /* BEGIN/END kept so the block stays recognizable; interior is the
     * single marker line */
    CHECK(strstr(OUT, "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                      "[REDACTED: private-key-block]\n"
                      "-----END OPENSSH PRIVATE KEY-----\n") != NULL,
          "block structure lost:\n%s", OUT);
    CHECK(strstr(OUT, "host key follows\n") != NULL, "preamble lost");
    CHECK(strstr(OUT, "trailing diagnostic\n") != NULL, "trailer lost");
}

TEST(test_pem_certificate_not_redacted)
{
    /* a certificate is public material — only PRIVATE KEY blocks match */
    CHECK(scrub("-----BEGIN CERTIFICATE-----\n"
                "MIIBpublicbytes\n"
                "-----END CERTIFICATE-----\n") == VIRP_OK, "scrub failed");
    CHECK(N == 0, "certificate block falsely redacted");
    CHECK(strstr(OUT, "MIIBpublicbytes") != NULL, "cert body lost");
}

TEST(test_unterminated_pem_redacts_to_end)
{
    /* fail-closed direction: a truncated key block never leaks its tail */
    CHECK(scrub("-----BEGIN RSA PRIVATE KEY-----\n"
                "CANARY15firstline\n"
                "CANARY16lastline") == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "truncated block leaked:\n%s", OUT);
    CHECK(strstr(OUT, "[REDACTED: private-key-block]") != NULL,
          "marker missing");
}

TEST(test_generic_labeled_secrets)
{
    CHECK(scrub("PVE_API_TOKEN=CANARY17token\n"
                "api_key: CANARY18key\n"
                "admin_password = CANARY19pw\n"
                "secret=CANARY20s\n"
                "X-Api-Key: CANARY21hdr\n") == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "labeled secret survived:\n%s", OUT);
    CHECK(N == 5, "expected 5 redactions, got %u", N);
    /* label + separator survive — the line stays recognizable */
    CHECK(strstr(OUT, "PVE_API_TOKEN=[REDACTED: token]\n") != NULL,
          "attached-value form malformed:\n%s", OUT);
    CHECK(strstr(OUT, "api_key: [REDACTED: api-key]") != NULL,
          "detached-value form malformed:\n%s", OUT);
    CHECK(strstr(OUT, "admin_password = [REDACTED: password]") != NULL,
          "spaced-separator form malformed:\n%s", OUT);
}

TEST(test_prose_words_without_separator_untouched)
{
    /* "token" / "secret" as prose must not fire the labeled rule */
    CHECK(scrub("token ring interface is down\n"
                "the secret to uptime is boring changes\n") == VIRP_OK,
          "scrub failed");
    /* line 2 DOES fire the exact-keyword rule ("secret" token redacts
     * the remainder) — that over-redaction is the accepted fail-closed
     * direction and is pinned here so a future "fix" is a decision,
     * not an accident. Line 1 must be untouched. */
    CHECK(strstr(OUT, "token ring interface is down\n") != NULL,
          "prose 'token' falsely redacted:\n%s", OUT);
    CHECK(N == 1, "expected exactly the 'secret' prose hit, got %u", N);
}

/* =========================================================================
 * The honesty limit — pinned as a test so the claim can't drift
 * ========================================================================= */

TEST(test_unlabeled_secret_is_NOT_caught)
{
    /* An unlabeled plaintext credential passes through. That is the
     * DOCUMENTED limit of a known-shapes scanner: this test exists so
     * the limit stays true in code and honest in prose. If a future
     * change makes this fail, update SCRUB-DESIGN.md the same day. */
    CHECK(scrub("hunter2\n"
                "8f3a9c0d4e5b6a71\n") == VIRP_OK, "scrub failed");
    CHECK(N == 0, "unlabeled text unexpectedly redacted — update the "
          "design doc if this is intentional");
    CHECK(strstr(OUT, "hunter2") != NULL, "bare word dropped");
}

/* =========================================================================
 * Contract properties
 * ========================================================================= */

TEST(test_clean_body_byte_identical)
{
    static const char CLEAN[] =
        "Cisco IOS Software, C2900 Software\n"
        "R1 uptime is 3 weeks, 2 days\r\n"
        "System image file is \"flash:c2900-universalk9-mz.bin\"\n"
        "interface GigabitEthernet0/0\n"
        " ip address 10.0.0.1 255.255.255.0\n";
    CHECK(scrub(CLEAN) == VIRP_OK, "scrub failed");
    CHECK(N == 0, "clean body got %u redactions", N);
    CHECK(strcmp(OUT, CLEAN) == 0, "clean body not byte-identical");
}

TEST(test_idempotent)
{
    unsigned n2 = 0;
    CHECK(scrub("enable secret 5 $1$abcd$CANARYhash\n"
                "PVE_API_TOKEN=CANARYtok\n") == VIRP_OK,
          "first scrub failed");
    char first[sizeof(OUT)];
    memcpy(first, OUT, strlen(OUT) + 1);
    size_t out_len = 0;
    CHECK(virp_scrub_body(first, strlen(first), OUT, sizeof(OUT),
                          &out_len, &n2) == VIRP_OK, "second scrub failed");
    OUT[out_len] = '\0';
    CHECK(strcmp(first, OUT) == 0,
          "not idempotent:\nfirst:  %s\nsecond: %s", first, OUT);
}

TEST(test_crlf_preserved)
{
    CHECK(scrub("hostname R9\r\n"
                "enable secret 5 $1$CANARYcrlf\r\n") == VIRP_OK,
          "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "CRLF secret survived");
    CHECK(strstr(OUT, "hostname R9\r\n") != NULL, "CRLF ending lost");
    CHECK(strstr(OUT, "enable secret [REDACTED: enable-secret]\r\n") != NULL,
          "redacted CRLF line malformed:\n%s", OUT);
}

TEST(test_overflow_fails_closed)
{
    char tiny[8];
    size_t out_len = 123;
    unsigned n = 0;
    virp_error_t err = virp_scrub_body("enable secret 5 x\n", 18,
                                       tiny, sizeof(tiny), &out_len, &n);
    CHECK(err == VIRP_ERR_BUFFER_TOO_SMALL,
          "expected BUFFER_TOO_SMALL, got %d", (int)err);
    CHECK(out_len == 0, "out_len not zeroed on failure");
}

TEST(test_null_args)
{
    size_t out_len = 0;
    unsigned n = 0;
    CHECK(virp_scrub_body(NULL, 0, OUT, sizeof(OUT), &out_len, &n)
              == VIRP_ERR_NULL_PTR, "NULL in accepted");
    CHECK(virp_scrub_body("x", 1, NULL, 0, &out_len, &n)
              == VIRP_ERR_NULL_PTR, "NULL out accepted");
    CHECK(virp_scrub_body("x", 1, OUT, sizeof(OUT), NULL, &n)
              == VIRP_ERR_NULL_PTR, "NULL out_len accepted");
    CHECK(virp_scrub_body("x", 1, OUT, sizeof(OUT), &out_len, NULL)
              == VIRP_ERR_NULL_PTR, "NULL redactions accepted");
}

/* =========================================================================
 * The fail-closed wrapper (G3's unit form — the end-to-end capture
 * form is in test_onode.c)
 * ========================================================================= */

TEST(test_wrapper_clean_body_untouched)
{
    virp_exec_result_t r;
    memset(&r, 0, sizeof(r));
    static const char BODY[] = "status: running\nuptime: 12 days\n";
    memcpy(r.output, BODY, sizeof(BODY) - 1);
    r.output_len = sizeof(BODY) - 1;
    r.success = true;

    virp_scrub_exec_result(&r);

    CHECK(r.output_len == sizeof(BODY) - 1, "clean body length changed");
    CHECK(memcmp(r.output, BODY, r.output_len) == 0,
          "clean body bytes changed");
}

TEST(test_wrapper_redacts_in_place)
{
    virp_exec_result_t r;
    memset(&r, 0, sizeof(r));
    static const char BODY[] =
        "config snippet\nenable secret 5 $1$CANARYwrap\n";
    memcpy(r.output, BODY, sizeof(BODY) - 1);
    r.output_len = sizeof(BODY) - 1;

    virp_scrub_exec_result(&r);

    r.output[r.output_len] = '\0';
    CHECK(strstr(r.output, "CANARY") == NULL, "secret survived wrapper");
    CHECK(strstr(r.output, "[REDACTED: enable-secret]") != NULL,
          "marker missing after wrapper");
    CHECK(strstr(r.output, "config snippet\n") != NULL,
          "clean line lost in wrapper");
}

TEST(test_wrapper_forced_error_fails_closed)
{
    /* G3 (unit form): an internal scrubber failure must yield a body
     * that is ENTIRELY the scrub-error marker — never the raw content,
     * never a partial copy. */
    virp_exec_result_t r;
    memset(&r, 0, sizeof(r));
    static const char BODY[] = "totally innocuous CANARY23 body\n";
    memcpy(r.output, BODY, sizeof(BODY) - 1);
    r.output_len = sizeof(BODY) - 1;
    snprintf(r.error_msg, sizeof(r.error_msg), "driver said CANARY24");

    virp_scrub_test_force_error(true);
    virp_scrub_exec_result(&r);
    virp_scrub_test_force_error(false);

    r.output[r.output_len] = '\0';
    CHECK(strcmp(r.output, "[REDACTED: scrub-error]") == 0,
          "body is not exactly the scrub-error marker: '%s'", r.output);
    CHECK(r.output_len == strlen("[REDACTED: scrub-error]"),
          "output_len not updated on fail-closed");
    CHECK(strstr(r.output, "CANARY") == NULL, "body leaked on scrub error");
    CHECK(strcmp(r.error_msg, "[REDACTED: scrub-error]") == 0,
          "error_msg leaked on scrub error: '%s'", r.error_msg);
}

TEST(test_wrapper_error_msg_scrubbed)
{
    /* driver error text can quote device output — it feeds signed
     * ERROR observation bodies, so it is scrubbed too */
    virp_exec_result_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.error_msg, sizeof(r.error_msg),
             "device rejected line: enable secret 5 $1$CANARY25err");

    virp_scrub_exec_result(&r);

    CHECK(strstr(r.error_msg, "CANARY") == NULL,
          "error_msg secret survived: '%s'", r.error_msg);
    CHECK(strstr(r.error_msg, "[REDACTED: enable-secret]") != NULL,
          "error_msg marker missing: '%s'", r.error_msg);
}

TEST(test_wrapper_empty_fields_stay_empty)
{
    /* nothing captured = nothing to mark; a marker here would
     * fabricate content */
    virp_exec_result_t r;
    memset(&r, 0, sizeof(r));
    virp_scrub_exec_result(&r);
    CHECK(r.output_len == 0, "empty body grew content");
    CHECK(r.output[0] == '\0', "empty body written to");
    CHECK(r.error_msg[0] == '\0', "empty error_msg written to");
}

/* =========================================================================
 * JSON key syntax — the blind spot measured during the merge
 * reconciliation (MERGE-RECONCILIATION-20260829.md §3.2, result 1)
 *
 * The labeled-secret rule wants `<label>[:=] <value>` with the label as
 * a whitespace token. JSON puts the closing quote between the label and
 * the colon, and a compact body has no whitespace at all — so a real
 * LibreNMS device record came back byte-identical, zero redactions.
 * On an endpoint the allowlist body filter has no rule for (thirteen of
 * the fourteen gate-admitted REST endpoints today), that left the
 * credential protected by neither barrier.
 * ========================================================================= */

TEST(test_json_compact_body_credentials)
{
    /* the §3.2 body shape: one line, no whitespace, four credential
     * keys and one non-secret key */
    CHECK(scrub("{\"status\":\"ok\",\"devices\":[{\"hostname\":\"pve01\","
                "\"community\":\"CANARY-COMMUNITY\","
                "\"authpass\":\"CANARY-AUTHPASS\","
                "\"cryptopass\":\"CANARY-CRYPTOPASS\","
                "\"api_token\":\"CANARY-TOKEN\"}]}\n") == VIRP_OK,
          "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL,
          "a JSON credential survived: %s", OUT);
    CHECK(N == 1, "expected one redacted line, got %u", N);
    CHECK(strstr(OUT, "[REDACTED: snmp-community]") != NULL,
          "community marker missing: %s", OUT);
    CHECK(strstr(OUT, "[REDACTED: snmp-authpass]") != NULL,
          "authpass marker missing: %s", OUT);
    CHECK(strstr(OUT, "[REDACTED: snmp-privpass]") != NULL,
          "cryptopass marker missing: %s", OUT);
    CHECK(strstr(OUT, "[REDACTED: token]") != NULL,
          "api_token marker missing: %s", OUT);
    /* diagnostic value kept: the non-secret keys and the envelope */
    CHECK(strstr(OUT, "\"hostname\":\"pve01\"") != NULL,
          "non-secret field destroyed: %s", OUT);
    CHECK(strstr(OUT, "\"status\":\"ok\"") != NULL,
          "envelope destroyed: %s", OUT);
}

TEST(test_json_redacted_body_still_parses)
{
    /* the marker goes in a VALUE position, so it is emitted QUOTED —
     * a redacted body must still be JSON for anything downstream */
    CHECK(scrub("{\"password\":\"CANARY1\",\"n\":1}\n") == VIRP_OK,
          "scrub failed");
    CHECK(strcmp(OUT, "{\"password\":\"[REDACTED: password]\",\"n\":1}\n")
          == 0, "unexpected form: %s", OUT);
}

TEST(test_json_pretty_printed_keys)
{
    /* whitespace around the colon, one key per line */
    CHECK(scrub("{\n"
                "  \"hostname\" : \"pve01\",\n"
                "  \"api_token\" : \"CANARY-TOKEN\"\n"
                "}\n") == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "pretty JSON leaked: %s", OUT);
    CHECK(strstr(OUT, "\"hostname\" : \"pve01\"") != NULL,
          "non-secret line changed: %s", OUT);
}

TEST(test_json_non_string_values)
{
    /* a secret key whose value is a number, a literal, an object or an
     * array: the WHOLE value span goes, and nothing after it */
    CHECK(scrub("{\"a_token\":12345,\"b\":1}\n"
                "{\"a_secret\":null,\"b\":2}\n"
                "{\"a_password\":{\"x\":\"CANARY1\"},\"b\":3}\n"
                "{\"a_apikey\":[\"CANARY2\",\"CANARY3\"],\"b\":4}\n")
          == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "structured value leaked: %s", OUT);
    CHECK(strstr(OUT, "12345") == NULL, "numeric secret kept: %s", OUT);
    CHECK(strstr(OUT, "\"b\":1") != NULL, "trailing key lost: %s", OUT);
    CHECK(strstr(OUT, "\"b\":3") != NULL, "key after object lost: %s", OUT);
    CHECK(strstr(OUT, "\"b\":4") != NULL, "key after array lost: %s", OUT);
    CHECK(N == 4, "expected 4 redacted lines, got %u", N);
}

TEST(test_json_non_secret_keys_untouched)
{
    static const char CLEAN[] =
        "{\"status\":\"ok\",\"count\":6,\"hostname\":\"pve01\","
        "\"os\":\"linux\",\"uptime\":98123,\"notes\":\"see the runbook\"}\n";
    CHECK(scrub(CLEAN) == VIRP_OK, "scrub failed");
    CHECK(N == 0, "clean JSON body redacted: %s", OUT);
    CHECK(strcmp(OUT, CLEAN) == 0, "clean JSON body not byte-identical");
}

TEST(test_json_string_value_carrying_a_bare_label_over_redacts)
{
    /* PRE-EXISTING, and measured byte-identical before and after this
     * rule was added: a JSON string VALUE containing `token: ` puts the
     * whitespace token `token:` in front of the line's token sweep,
     * which redacts the remainder of the line — closing braces
     * included, so the body stops being JSON. The new rule does not see
     * it (the label is not a KEY), does not fire, and leaves the line
     * to the sweep exactly as before.
     *
     * Over-redaction is the fail-closed direction, so this is pinned
     * rather than fixed: making the token sweep JSON-aware would mean
     * teaching it to NOT redact things it redacts today, which is a
     * weakening and belongs in its own item with its own review. */
    CHECK(scrub("{\"notes\":\"see token: 5\",\"n\":1}\n") == VIRP_OK,
          "scrub failed");
    CHECK(N == 1, "expected the pre-existing sweep hit, got %u", N);
    CHECK(strstr(OUT, "[REDACTED: token]") != NULL,
          "pre-existing behaviour changed: %s", OUT);
    CHECK(strstr(OUT, "\"n\":1") == NULL,
          "the sweep no longer redacts to end of line: %s", OUT);
}

TEST(test_json_value_is_not_mistaken_for_a_key)
{
    /* a VALUE that itself contains a colon, and an escaped quote, must
     * not be read as a key — and must not shift the scan */
    CHECK(scrub("{\"desc\":\"ratio 1:2\",\"esc\":\"a\\\"b\","
                "\"password\":\"CANARY1\"}\n") == VIRP_OK, "scrub failed");
    CHECK(strstr(OUT, "CANARY") == NULL, "secret survived: %s", OUT);
    CHECK(strstr(OUT, "\"desc\":\"ratio 1:2\"") != NULL,
          "value with a colon was rewritten: %s", OUT);
}

TEST(test_json_idempotent)
{
    CHECK(scrub("{\"authpass\":\"CANARY1\",\"n\":1}\n") == VIRP_OK,
          "scrub failed");
    char once[sizeof(OUT)];
    snprintf(once, sizeof(once), "%s", OUT);
    CHECK(scrub(once) == VIRP_OK, "second scrub failed");
    CHECK(N == 0, "second pass redacted again: %s", OUT);
    CHECK(strcmp(OUT, once) == 0, "second pass changed the body: %s", OUT);
}

TEST(test_json_rule_does_not_disturb_cli_text)
{
    /* the §3.2 measured-result-2 control: CLI output is the scrubber's
     * own class of body and must come out exactly as it did before */
    static const char CLI[] =
        "R1>show running-config\n"
        "username admin password 7 CANARY1\n"
        "snmp-server community CANARY2 RO 99\n"
        "interface GigabitEthernet0/0\n"
        " description uplink to core\n";
    CHECK(scrub(CLI) == VIRP_OK, "scrub failed");
    CHECK(strcmp(OUT,
                 "R1>show running-config\n"
                 "username admin password [REDACTED: password]\n"
                 "snmp-server community [REDACTED: snmp-community] RO 99\n"
                 "interface GigabitEthernet0/0\n"
                 " description uplink to core\n") == 0,
          "CLI scrubbing moved: %s", OUT);
    CHECK(N == 2, "expected 2 CLI redactions, got %u", N);
}

TEST(test_json_unlabeled_value_is_still_NOT_caught)
{
    /* the honesty limit holds one level down: JSON syntax is now read,
     * but the vocabulary is still known key names only. A credential
     * under a name this rule does not know passes through. */
    CHECK(scrub("{\"opaque\":\"hunter2\",\"blob\":\"8f3a9c0d4e5b6a71\"}\n")
          == VIRP_OK, "scrub failed");
    CHECK(N == 0, "unknown JSON key unexpectedly redacted — update "
          "SCRUB-DESIGN.md if this is intentional");
    CHECK(strstr(OUT, "hunter2") != NULL, "value dropped");
}

int main(void)
{
    printf("test_virp_scrub:\n");

    RUN_TEST(test_cisco_credential_lines);
    RUN_TEST(test_password_encryption_service_line_untouched);
    RUN_TEST(test_snmp_community_token_only);
    RUN_TEST(test_isakmp_key_keeps_peer_address);
    RUN_TEST(test_psk_and_wpa_psk);
    RUN_TEST(test_leading_key_with_exceptions);
    RUN_TEST(test_pem_private_key_block);
    RUN_TEST(test_pem_certificate_not_redacted);
    RUN_TEST(test_unterminated_pem_redacts_to_end);
    RUN_TEST(test_generic_labeled_secrets);
    RUN_TEST(test_prose_words_without_separator_untouched);
    RUN_TEST(test_unlabeled_secret_is_NOT_caught);
    RUN_TEST(test_json_compact_body_credentials);
    RUN_TEST(test_json_redacted_body_still_parses);
    RUN_TEST(test_json_pretty_printed_keys);
    RUN_TEST(test_json_non_string_values);
    RUN_TEST(test_json_non_secret_keys_untouched);
    RUN_TEST(test_json_string_value_carrying_a_bare_label_over_redacts);
    RUN_TEST(test_json_value_is_not_mistaken_for_a_key);
    RUN_TEST(test_json_idempotent);
    RUN_TEST(test_json_rule_does_not_disturb_cli_text);
    RUN_TEST(test_json_unlabeled_value_is_still_NOT_caught);
    RUN_TEST(test_clean_body_byte_identical);
    RUN_TEST(test_idempotent);
    RUN_TEST(test_crlf_preserved);
    RUN_TEST(test_overflow_fails_closed);
    RUN_TEST(test_null_args);
    RUN_TEST(test_wrapper_clean_body_untouched);
    RUN_TEST(test_wrapper_redacts_in_place);
    RUN_TEST(test_wrapper_forced_error_fails_closed);
    RUN_TEST(test_wrapper_empty_fields_stay_empty);
    RUN_TEST(test_wrapper_error_msg_scrubbed);

    printf("\n%d tests, %d failures\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
