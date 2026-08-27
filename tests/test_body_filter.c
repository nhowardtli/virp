/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Collector-side body filter tests (virp_body_filter.c)
 *
 * Every credential-shaped value in this file is SYNTHESIZED for the
 * test and marked as such. No real credential ever appears here, and
 * no test may add one.
 *
 * Tests: sensitive fields removed + recorded; clean body untouched and
 * unannotated; non-matching driver/path untouched; unparseable matched
 * payload withheld (fail closed); filtered body hashes and chains
 * cleanly; rules loadable from a config file.
 */

#define _GNU_SOURCE   /* memmem — scans the WHOLE buffer, cleansed tail included */

#include "virp_body_filter.h"
#include "virp_chain.h"
#include "virp_crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { printf("  [TEST] %-50s ", name); } while (0)

#define PASS() \
    do { printf("PASS\n"); tests_passed++; } while (0)

#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

#define ASSERT(cond, msg) \
    do { if (!(cond)) { FAIL(msg); return; } } while (0)

static const char *TEST_DB   = "/tmp/virp_test_body_filter.db";
static const char *TEST_KEY  = "/tmp/virp_test_body_filter.key";
static const char *TEST_CONF = "/tmp/virp_test_body_filter_rules.json";

/* Synthesized librenms-shaped response. The secret-shaped values are
 * fabricated markers chosen to be greppable in output, never real. */
#define SYNTH_AUTHPASS  "SYNTHETIC-authpass-value-000"
#define SYNTH_CRYPTOPASS "SYNTHETIC-cryptopass-value-000"
#define SYNTH_COMMUNITY "SYNTHETIC-community-000"
#define SYNTH_CONTACT   "synthetic.contact@example.invalid"

static const char SYNTH_DEVICES_JSON[] =
    "{\"status\":\"ok\",\"count\":2,\"devices\":["
    "{\"device_id\":1,\"hostname\":\"synth-sw1\",\"sysName\":\"synth-sw1\","
    "\"ip\":\"192.0.2.10\",\"os\":\"ios\",\"status\":1,"
    "\"community\":\"" SYNTH_COMMUNITY "\","
    "\"authname\":\"synthuser\",\"authpass\":\"" SYNTH_AUTHPASS "\","
    "\"cryptopass\":\"" SYNTH_CRYPTOPASS "\",\"authalgo\":\"SHA\","
    "\"cryptoalgo\":\"AES\",\"sysContact\":\"" SYNTH_CONTACT "\"},"
    "{\"device_id\":2,\"hostname\":\"synth-sw2\",\"sysName\":\"synth-sw2\","
    "\"ip\":\"192.0.2.11\",\"os\":\"ios\",\"status\":0,"
    "\"community\":\"" SYNTH_COMMUNITY "\","
    "\"sysContact\":\"" SYNTH_CONTACT "\"}]}";

static void make_result(virp_exec_result_t *r, const char *prefix,
                        const char *payload)
{
    memset(r, 0, sizeof(*r));
    int n = snprintf(r->output, sizeof(r->output), "%s%s", prefix, payload);
    r->output_len = (n > 0) ? (size_t)n : 0;
    r->success = true;
}

/* =========================================================================
 * Sensitive fields are removed, and the removal is recorded by key
 * ========================================================================= */

static void test_sensitive_fields_filtered(void)
{
    TEST("Sensitive fields removed and recorded");
    virp_body_filter_reset_for_tests();
    unsetenv("VIRP_BODY_FILTERS");

    virp_exec_result_t r;
    make_result(&r, "librenms-lab>/api/v0/devices [HTTP 200]\n",
                SYNTH_DEVICES_JSON);

    virp_bf_outcome_t out = virp_body_filter_apply(
        "librenms", "GET /api/v0/devices", &r);
    ASSERT(out == VIRP_BF_FILTERED, "expected VIRP_BF_FILTERED");
    ASSERT(r.output_len == strlen(r.output), "output_len out of sync");

    /* No secret-shaped value survives — not in the payload, not in the
     * cleansed buffer tail either. */
    ASSERT(memmem(r.output, sizeof(r.output), SYNTH_AUTHPASS,
                  strlen(SYNTH_AUTHPASS)) == NULL, "authpass survived");
    ASSERT(memmem(r.output, sizeof(r.output), SYNTH_CRYPTOPASS,
                  strlen(SYNTH_CRYPTOPASS)) == NULL, "cryptopass survived");
    ASSERT(memmem(r.output, sizeof(r.output), SYNTH_COMMUNITY,
                  strlen(SYNTH_COMMUNITY)) == NULL, "community survived");
    ASSERT(memmem(r.output, sizeof(r.output), SYNTH_CONTACT,
                  strlen(SYNTH_CONTACT)) == NULL, "sysContact survived");

    /* The filtering is recorded, naming removed fields BY KEY. */
    ASSERT(strstr(r.output, "\"_virp_filtered\"") != NULL,
           "no _virp_filtered annotation");
    ASSERT(strstr(r.output, "\"mode\":\"allowlist\"") != NULL,
           "annotation lacks mode");
    ASSERT(strstr(r.output, "\"authpass\"") != NULL,
           "removed key 'authpass' not recorded");
    ASSERT(strstr(r.output, "\"cryptopass\"") != NULL,
           "removed key 'cryptopass' not recorded");
    ASSERT(strstr(r.output, "\"community\"") != NULL,
           "removed key 'community' not recorded");
    ASSERT(strstr(r.output, "\"sysContact\"") != NULL,
           "removed key 'sysContact' not recorded");

    /* Allowlisted content and the transport prefix survive. */
    ASSERT(strncmp(r.output, "librenms-lab>/api/v0/devices [HTTP 200]\n",
                   40) == 0, "transport prefix lost");
    ASSERT(strstr(r.output, "\"hostname\":\"synth-sw1\"") != NULL,
           "allowlisted hostname lost");
    ASSERT(strstr(r.output, "\"count\":2") != NULL,
           "allowlisted envelope count lost");
    PASS();
}

/* =========================================================================
 * A body with nothing to remove stays byte-identical and unannotated
 * ========================================================================= */

static void test_clean_body_untouched(void)
{
    TEST("Clean body byte-identical, no annotation");
    virp_body_filter_reset_for_tests();
    unsetenv("VIRP_BODY_FILTERS");

    const char *clean =
        "{\"status\":\"ok\",\"count\":1,\"devices\":["
        "{\"device_id\":1,\"hostname\":\"synth-sw1\",\"status\":1}]}";
    virp_exec_result_t r;
    make_result(&r, "librenms-lab>/api/v0/devices [HTTP 200]\n", clean);
    char before[sizeof(r.output)];
    memcpy(before, r.output, sizeof(before));
    size_t len_before = r.output_len;

    virp_bf_outcome_t out = virp_body_filter_apply(
        "librenms", "GET /api/v0/devices", &r);
    ASSERT(out == VIRP_BF_UNTOUCHED, "expected VIRP_BF_UNTOUCHED");
    ASSERT(r.output_len == len_before, "length changed");
    ASSERT(memcmp(r.output, before, sizeof(before)) == 0, "bytes changed");
    ASSERT(strstr(r.output, "_virp_filtered") == NULL,
           "annotation added to unmodified body");
    PASS();
}

/* =========================================================================
 * Non-matching driver or endpoint is untouched
 * ========================================================================= */

static void test_no_rule_untouched(void)
{
    TEST("Non-matching driver/path untouched");
    virp_body_filter_reset_for_tests();
    unsetenv("VIRP_BODY_FILTERS");

    virp_exec_result_t r;
    make_result(&r, "librenms-lab>/api/v0/alerts [HTTP 200]\n",
                "{\"status\":\"ok\",\"count\":0,\"alerts\":[],"
                "\"free_text\":\"" SYNTH_AUTHPASS "\"}");
    char before[sizeof(r.output)];
    memcpy(before, r.output, sizeof(before));

    ASSERT(virp_body_filter_apply("librenms", "GET /api/v0/alerts?state=1",
                                  &r) == VIRP_BF_UNTOUCHED,
           "alerts endpoint unexpectedly matched");
    ASSERT(memcmp(r.output, before, sizeof(before)) == 0,
           "alerts body modified");

    make_result(&r, "wazuh-lab>/api/v0/devices [HTTP 200]\n",
                SYNTH_DEVICES_JSON);
    ASSERT(virp_body_filter_apply("wazuh", "GET /api/v0/devices",
                                  &r) == VIRP_BF_UNTOUCHED,
           "rule matched wrong driver");
    PASS();
}

/* =========================================================================
 * Matched but unparseable payload is withheld, never chained raw
 * ========================================================================= */

static void test_unparseable_withheld(void)
{
    TEST("Unparseable matched payload withheld");
    virp_body_filter_reset_for_tests();
    unsetenv("VIRP_BODY_FILTERS");

    /* A capture-truncated response: unparseable, still full of the
     * secret-shaped value. Exactly the case that must not pass raw. */
    virp_exec_result_t r;
    make_result(&r, "librenms-lab>/api/v0/devices [HTTP 200]\n",
                "{\"status\":\"ok\",\"devices\":[{\"authpass\":\""
                SYNTH_AUTHPASS);
    size_t payload_len = r.output_len - 40;
    char orig_sha[65];
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)r.output + 40, payload_len, md);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(orig_sha + i * 2, 3, "%02x", md[i]);
    orig_sha[64] = '\0';

    virp_bf_outcome_t out = virp_body_filter_apply(
        "librenms", "GET /api/v0/devices", &r);
    ASSERT(out == VIRP_BF_WITHHELD, "expected VIRP_BF_WITHHELD");
    ASSERT(memmem(r.output, sizeof(r.output), SYNTH_AUTHPASS,
                  strlen(SYNTH_AUTHPASS)) == NULL,
           "secret-shaped value survived withholding");
    ASSERT(strstr(r.output, "\"mode\":\"withheld\"") != NULL,
           "withhold stub missing mode");
    ASSERT(strstr(r.output, orig_sha) != NULL,
           "withhold stub does not commit to original bytes");
    ASSERT(strncmp(r.output, "librenms-lab>/api/v0/devices [HTTP 200]\n",
                   40) == 0, "transport prefix lost in withholding");
    PASS();
}

/* =========================================================================
 * A filtered body hashes and chains cleanly (GATE 2 shape)
 * ========================================================================= */

static void test_filtered_body_chains(void)
{
    TEST("Filtered body hashes and chains cleanly");
    virp_body_filter_reset_for_tests();
    unsetenv("VIRP_BODY_FILTERS");
    unlink(TEST_DB);
    unlink("/tmp/virp_test_body_filter.db-wal");
    unlink("/tmp/virp_test_body_filter.db-shm");

    virp_exec_result_t r;
    make_result(&r, "librenms-lab>/api/v0/devices [HTTP 200]\n",
                SYNTH_DEVICES_JSON);
    ASSERT(virp_body_filter_apply("librenms", "GET /api/v0/devices",
                                  &r) == VIRP_BF_FILTERED, "filter failed");

    /* Encode exactly as the collectors do: "base64:" + b64(bytes). */
    size_t b64_max = (r.output_len + 2) / 3 * 4 + 8;
    char *content = malloc(b64_max + 8);
    ASSERT(content != NULL, "oom");
    strcpy(content, "base64:");
    int b64_len = EVP_EncodeBlock((unsigned char *)content + 7,
                                  (const unsigned char *)r.output,
                                  (int)r.output_len);
    ASSERT(b64_len > 0, "base64 encode failed");

    /* The digest the daemon computes (GATE 2) must equal the digest a
     * client declares over the same filtered bytes. */
    char declared[65], computed[65];
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)r.output, r.output_len, md);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(declared + i * 2, 3, "%02x", md[i]);
    declared[64] = '\0';
    ASSERT(virp_chain_artifact_digest(content, computed) == VIRP_OK,
           "artifact digest failed");
    ASSERT(strcmp(declared, computed) == 0,
           "daemon digest != declared digest over filtered body");

    /* And the pair appends + verifies like any healthy entry. */
    virp_signing_key_t sk;
    virp_key_generate(&sk, VIRP_KEY_TYPE_CHAIN);
    virp_key_save_file(&sk, TEST_KEY);
    virp_key_destroy(&sk);

    virp_chain_state_t chain;
    ASSERT(virp_chain_init(&chain, TEST_DB, TEST_KEY, 1, "test-org")
           == VIRP_OK, "chain_init failed");
    virp_chain_entry_t entry;
    virp_error_t err = virp_chain_append_with_artifact(
        &chain, "bf-test", "observation", "obs:synth:1", declared,
        content, &entry);
    if (err != VIRP_OK) { virp_chain_destroy(&chain); free(content); }
    ASSERT(err == VIRP_OK, "append_with_artifact failed");

    virp_chain_verify_result_t vres;
    memset(&vres, 0, sizeof(vres));
    err = virp_chain_verify(&chain, "bf-test", 0, 0, &vres);
    virp_chain_destroy(&chain);
    free(content);
    unlink(TEST_DB);
    unlink(TEST_KEY);
    ASSERT(err == VIRP_OK && vres.valid, "chain verify failed");
    PASS();
}

/* =========================================================================
 * Rules load from a config file (config-driven per endpoint)
 * ========================================================================= */

static void test_config_file_rules(void)
{
    TEST("Config file drives the rule set");
    virp_body_filter_reset_for_tests();

    FILE *fh = fopen(TEST_CONF, "w");
    ASSERT(fh != NULL, "cannot write test config");
    fputs("{\"version\":1,\"rules\":[{"
          "\"name\":\"synth-endpoint-v1\","
          "\"driver\":\"mock\","
          "\"path\":\"/synth/things\","
          "\"envelope_allow\":[\"status\"],"
          "\"array_key\":\"things\","
          "\"item_allow\":[\"id\"]}]}", fh);
    fclose(fh);

    ASSERT(virp_body_filter_init(TEST_CONF) == VIRP_OK, "init failed");

    virp_exec_result_t r;
    make_result(&r, "mock>/synth/things [HTTP 200]\n",
                "{\"status\":\"ok\",\"secret_field\":\"" SYNTH_AUTHPASS
                "\",\"things\":[{\"id\":1,\"token\":\"" SYNTH_CRYPTOPASS
                "\"}]}");
    virp_bf_outcome_t out = virp_body_filter_apply(
        "mock", "GET /synth/things?limit=5", &r);
    unlink(TEST_CONF);
    ASSERT(out == VIRP_BF_FILTERED, "config rule did not fire");
    ASSERT(memmem(r.output, sizeof(r.output), SYNTH_AUTHPASS,
                  strlen(SYNTH_AUTHPASS)) == NULL, "envelope secret survived");
    ASSERT(memmem(r.output, sizeof(r.output), SYNTH_CRYPTOPASS,
                  strlen(SYNTH_CRYPTOPASS)) == NULL, "item secret survived");
    ASSERT(strstr(r.output, "\"secret_field\"") != NULL &&
           strstr(r.output, "\"token\"") != NULL,
           "removed keys not recorded");

    /* Builtin librenms rule is NOT active when a config replaces it —
     * the config is the whole rule set, not an overlay. */
    make_result(&r, "librenms-lab>/api/v0/devices [HTTP 200]\n",
                SYNTH_DEVICES_JSON);
    ASSERT(virp_body_filter_apply("librenms", "GET /api/v0/devices", &r)
           == VIRP_BF_UNTOUCHED, "builtin rule active despite config");

    /* Back to builtin for any later test. */
    virp_body_filter_reset_for_tests();
    PASS();
}

int main(void)
{
    printf("VIRP body filter tests\n");
    printf("======================\n");

    test_sensitive_fields_filtered();
    test_clean_body_untouched();
    test_no_rule_untouched();
    test_unparseable_withheld();
    test_filtered_body_chains();
    test_config_file_rules();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
