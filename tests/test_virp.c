/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Test suite — every structural guarantee must be proven here
 *
 * If a test doesn't exist for a security property, that property
 * is not guaranteed. Write the test first.
 */

#define _POSIX_C_SOURCE 200809L   /* symlink, fileno */
#define _DEFAULT_SOURCE           /* fileno on glibc */

#include "virp.h"
#include "virp_crypto.h"
#include "virp_context.h"
#include "virp_message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <arpa/inet.h>

/* =========================================================================
 * Test framework — minimal, no dependencies
 * ========================================================================= */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(name) do { \
    printf("  %-60s", #name); \
    fflush(stdout); \
    name(); \
    tests_run++; \
    tests_passed++; \
    printf(" [PASS]\n"); \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf(" [FAIL]\n    Expected %d, got %d at %s:%d\n", \
               (int)(b), (int)(a), __FILE__, __LINE__); \
        tests_run++; tests_failed++; return; \
    } \
} while(0)

#define ASSERT_NEQ(a, b) do { \
    if ((a) == (b)) { \
        printf(" [FAIL]\n    Expected != %d at %s:%d\n", \
               (int)(b), __FILE__, __LINE__); \
        tests_run++; tests_failed++; return; \
    } \
} while(0)

#define ASSERT_TRUE(x) ASSERT_EQ(!!(x), 1)
#define ASSERT_OK(x) ASSERT_EQ((x), VIRP_OK)

/* =========================================================================
 * Test keys — generated once for the test suite
 * ========================================================================= */

static virp_signing_key_t okey;  /* O-Node key — observations only */
static virp_signing_key_t rkey;  /* R-Node key — intents only */

static void setup_keys(void)
{
    virp_error_t err;
    err = virp_key_generate(&okey, VIRP_KEY_TYPE_OKEY);
    assert(err == VIRP_OK);
    err = virp_key_generate(&rkey, VIRP_KEY_TYPE_RKEY);
    assert(err == VIRP_OK);
}

/* =========================================================================
 * 1. STRUCTURAL GUARANTEE: Header size is exactly 56 bytes
 * ========================================================================= */

TEST(test_header_size)
{
    ASSERT_EQ(sizeof(virp_header_t), 56);
    ASSERT_EQ(VIRP_HEADER_SIZE, 56);
}

/* =========================================================================
 * 2. STRUCTURAL GUARANTEE: BLACK tier can never be transmitted
 * ========================================================================= */

TEST(test_black_tier_rejected)
{
    virp_header_t hdr;
    virp_error_t err = virp_header_init(&hdr, VIRP_MSG_OBSERVATION,
                                        VIRP_CHANNEL_OC, VIRP_TIER_BLACK,
                                        0x01020304, 1);
    ASSERT_EQ(err, VIRP_ERR_TIER_VIOLATION);
}

TEST(test_black_tier_validation)
{
    /* Manually craft a header with BLACK tier and verify validation catches it */
    virp_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = VIRP_VERSION;
    hdr.type = VIRP_MSG_OBSERVATION;
    hdr.length = VIRP_HEADER_SIZE;
    hdr.channel = VIRP_CHANNEL_OC;
    hdr.tier = VIRP_TIER_BLACK;  /* THE FORBIDDEN TIER */

    virp_error_t err = virp_header_validate(&hdr);
    ASSERT_EQ(err, VIRP_ERR_TIER_VIOLATION);
}

/* =========================================================================
 * 3. STRUCTURAL GUARANTEE: O-Key can ONLY sign OC messages
 * ========================================================================= */

TEST(test_okey_signs_oc)
{
    uint8_t buf[256];
    size_t out_len;
    uint8_t data[] = "show ip route output";

    virp_error_t err = virp_build_observation(buf, sizeof(buf), &out_len,
                                              0x01020304, 1,
                                              VIRP_OBS_DEVICE_OUTPUT,
                                              VIRP_SCOPE_LOCAL,
                                              data, sizeof(data),
                                              &okey);
    ASSERT_OK(err);
}

TEST(test_okey_cannot_sign_ic)
{
    /* Try to build a proposal (IC) with an O-Key — MUST fail */
    uint8_t buf[256];
    size_t out_len;
    virp_obs_ref_t ref = { .node_id = 1, .seq_num = 1 };
    uint8_t data[] = "route inject";

    virp_error_t err = virp_build_proposal(buf, sizeof(buf), &out_len,
                                           0x01020304, 1,
                                           100, /* proposal_id */
                                           VIRP_PROP_ROUTE_INJECT,
                                           5,   /* blast_radius */
                                           &ref, 1,
                                           data, sizeof(data),
                                           &okey);  /* WRONG KEY TYPE */
    ASSERT_EQ(err, VIRP_ERR_CHANNEL_VIOLATION);
}

/* =========================================================================
 * 4. STRUCTURAL GUARANTEE: R-Key can ONLY sign IC messages
 * ========================================================================= */

TEST(test_rkey_signs_ic)
{
    uint8_t buf[256];
    size_t out_len;
    virp_obs_ref_t ref = { .node_id = 1, .seq_num = 1 };
    uint8_t data[] = "inject route 10.0.0.0/24";

    virp_error_t err = virp_build_proposal(buf, sizeof(buf), &out_len,
                                           0x01020304, 1,
                                           100,
                                           VIRP_PROP_ROUTE_INJECT,
                                           5,
                                           &ref, 1,
                                           data, sizeof(data),
                                           &rkey);
    ASSERT_OK(err);
}

TEST(test_rkey_cannot_sign_oc)
{
    /* Try to build an observation (OC) with an R-Key — MUST fail */
    uint8_t buf[256];
    size_t out_len;
    uint8_t data[] = "fabricated observation";

    virp_error_t err = virp_build_observation(buf, sizeof(buf), &out_len,
                                              0x01020304, 1,
                                              VIRP_OBS_DEVICE_OUTPUT,
                                              VIRP_SCOPE_LOCAL,
                                              data, sizeof(data),
                                              &rkey);  /* WRONG KEY TYPE */
    ASSERT_EQ(err, VIRP_ERR_CHANNEL_VIOLATION);
}

/* =========================================================================
 * 5. STRUCTURAL GUARANTEE: Proposals without evidence are rejected
 * ========================================================================= */

TEST(test_proposal_requires_evidence)
{
    uint8_t buf[256];
    size_t out_len;
    uint8_t data[] = "inject something";

    /* Zero observation references — MUST be rejected */
    virp_error_t err = virp_build_proposal(buf, sizeof(buf), &out_len,
                                           0x01020304, 1,
                                           100,
                                           VIRP_PROP_ROUTE_INJECT,
                                           5,
                                           NULL, 0,  /* NO EVIDENCE */
                                           data, sizeof(data),
                                           &rkey);
    ASSERT_EQ(err, VIRP_ERR_NO_EVIDENCE);
}

/* =========================================================================
 * 6. STRUCTURAL GUARANTEE: HMAC verification catches tampering
 * ========================================================================= */

TEST(test_hmac_detects_tamper)
{
    uint8_t buf[256];
    size_t out_len;
    uint8_t data[] = "real observation data";

    virp_error_t err = virp_build_observation(buf, sizeof(buf), &out_len,
                                              0x01020304, 1,
                                              VIRP_OBS_DEVICE_OUTPUT,
                                              VIRP_SCOPE_LOCAL,
                                              data, sizeof(data),
                                              &okey);
    ASSERT_OK(err);

    /* Verify the untampered message */
    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &okey, &hdr);
    ASSERT_OK(err);

    /* Tamper with one byte in the payload */
    buf[VIRP_HEADER_SIZE + 5] ^= 0xFF;

    /* Verification MUST fail */
    err = virp_validate_message(buf, out_len, &okey, &hdr);
    ASSERT_EQ(err, VIRP_ERR_HMAC_FAILED);
}

TEST(test_hmac_detects_header_tamper)
{
    uint8_t buf[256];
    size_t out_len;
    uint8_t data[] = "observation";

    virp_error_t err = virp_build_observation(buf, sizeof(buf), &out_len,
                                              0x01020304, 1,
                                              VIRP_OBS_DEVICE_OUTPUT,
                                              VIRP_SCOPE_LOCAL,
                                              data, sizeof(data),
                                              &okey);
    ASSERT_OK(err);

    /* Tamper with the node_id in the header */
    buf[4] ^= 0xFF;

    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &okey, &hdr);
    ASSERT_EQ(err, VIRP_ERR_HMAC_FAILED);
}

/* =========================================================================
 * 6b. AUDIT HONESTY: observation records the ACTUAL tier (incl. UNCLASSIFIED)
 * ========================================================================= */

TEST(test_observation_tier_honesty)
{
    uint8_t buf[256];
    size_t out_len;
    uint8_t data[] = "device output";
    virp_header_t hdr;

    /* UNCLASSIFIED (0x00) must stamp as UNCLASSIFIED and validate on the
     * wire — NOT clamped to GREEN. This is the Snow audit-integrity fix. */
    virp_error_t err = virp_build_observation_tiered(
        buf, sizeof(buf), &out_len, 0x0A0B0C0D, 7,
        VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
        VIRP_TIER_UNCLASSIFIED, data, sizeof(data), &okey);
    ASSERT_OK(err);
    ASSERT_EQ(buf[9], VIRP_TIER_UNCLASSIFIED);   /* header tier byte @ offset 9 */
    ASSERT_OK(virp_validate_message(buf, out_len, &okey, &hdr));
    ASSERT_EQ(hdr.tier, VIRP_TIER_UNCLASSIFIED);

    /* GREEN/YELLOW/RED pass through faithfully. */
    uint8_t tiers[] = { VIRP_TIER_GREEN, VIRP_TIER_YELLOW, VIRP_TIER_RED };
    for (size_t i = 0; i < sizeof(tiers); i++) {
        err = virp_build_observation_tiered(
            buf, sizeof(buf), &out_len, 1, 1,
            VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
            tiers[i], data, sizeof(data), &okey);
        ASSERT_OK(err);
        ASSERT_EQ(buf[9], tiers[i]);
        ASSERT_OK(virp_validate_message(buf, out_len, &okey, &hdr));
    }

    /* BLACK is untransmittable — the builder MUST refuse it. This is why
     * gate_obs_tier maps BLACK->RED before ever calling the builder. */
    err = virp_build_observation_tiered(
        buf, sizeof(buf), &out_len, 1, 1,
        VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
        VIRP_TIER_BLACK, data, sizeof(data), &okey);
    ASSERT_EQ(err, VIRP_ERR_TIER_VIOLATION);
}

TEST(test_observation_wrapper_unchanged_green)
{
    /* The 16 non-command callers use virp_build_observation (no tier arg).
     * It must still stamp GREEN, byte-for-byte unchanged behavior. */
    uint8_t buf[256];
    size_t out_len;
    uint8_t data[] = "legacy caller";
    virp_header_t hdr;
    virp_error_t err = virp_build_observation(
        buf, sizeof(buf), &out_len, 1, 1,
        VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL, data, sizeof(data), &okey);
    ASSERT_OK(err);
    ASSERT_EQ(buf[9], VIRP_TIER_GREEN);
    ASSERT_OK(virp_validate_message(buf, out_len, &okey, &hdr));
    ASSERT_EQ(hdr.tier, VIRP_TIER_GREEN);
}

/* =========================================================================
 * 7. STRUCTURAL GUARANTEE: Wrong key cannot verify
 * ========================================================================= */

TEST(test_wrong_key_fails_verify)
{
    uint8_t buf[256];
    size_t out_len;
    uint8_t data[] = "signed by okey";

    virp_error_t err = virp_build_observation(buf, sizeof(buf), &out_len,
                                              0x01020304, 1,
                                              VIRP_OBS_DEVICE_OUTPUT,
                                              VIRP_SCOPE_LOCAL,
                                              data, sizeof(data),
                                              &okey);
    ASSERT_OK(err);

    /* Generate a different O-Key */
    virp_signing_key_t wrong_key;
    virp_key_generate(&wrong_key, VIRP_KEY_TYPE_OKEY);

    /* Verify with wrong key — MUST fail */
    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &wrong_key, &hdr);
    ASSERT_EQ(err, VIRP_ERR_HMAC_FAILED);
}

/* =========================================================================
 * 8. Channel-type consistency enforcement
 * ========================================================================= */

TEST(test_observation_on_ic_rejected)
{
    ASSERT_EQ(virp_check_channel_type(VIRP_CHANNEL_IC, VIRP_MSG_OBSERVATION),
              VIRP_ERR_CHANNEL_VIOLATION);
}

TEST(test_proposal_on_oc_rejected)
{
    ASSERT_EQ(virp_check_channel_type(VIRP_CHANNEL_OC, VIRP_MSG_PROPOSAL),
              VIRP_ERR_CHANNEL_VIOLATION);
}

TEST(test_heartbeat_on_ic_rejected)
{
    ASSERT_EQ(virp_check_channel_type(VIRP_CHANNEL_IC, VIRP_MSG_HEARTBEAT),
              VIRP_ERR_CHANNEL_VIOLATION);
}

TEST(test_teardown_on_both_channels)
{
    ASSERT_OK(virp_check_channel_type(VIRP_CHANNEL_OC, VIRP_MSG_TEARDOWN));
    ASSERT_OK(virp_check_channel_type(VIRP_CHANNEL_IC, VIRP_MSG_TEARDOWN));
}

/* =========================================================================
 * 9. Round-trip serialization
 * ========================================================================= */

TEST(test_observation_round_trip)
{
    uint8_t buf[512];
    size_t out_len;
    uint8_t data[] = "R6#show ip bgp summary\nBGP router identifier 6.6.6.6";

    virp_error_t err = virp_build_observation(buf, sizeof(buf), &out_len,
                                              0x06060606, 42,
                                              VIRP_OBS_DEVICE_OUTPUT,
                                              VIRP_SCOPE_LOCAL,
                                              data, sizeof(data),
                                              &okey);
    ASSERT_OK(err);

    /* Validate */
    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &okey, &hdr);
    ASSERT_OK(err);

    ASSERT_EQ(hdr.version, VIRP_VERSION);
    ASSERT_EQ(hdr.type, VIRP_MSG_OBSERVATION);
    ASSERT_EQ(hdr.channel, VIRP_CHANNEL_OC);
    ASSERT_EQ(hdr.tier, VIRP_TIER_GREEN);
    ASSERT_EQ(hdr.node_id, 0x06060606);
    ASSERT_EQ(hdr.seq_num, 42);

    /* Parse observation payload */
    virp_observation_t obs;
    const uint8_t *obs_data;
    uint16_t obs_data_len;
    err = virp_parse_observation(buf + VIRP_HEADER_SIZE,
                                out_len - VIRP_HEADER_SIZE,
                                &obs, &obs_data, &obs_data_len);
    ASSERT_OK(err);
    ASSERT_EQ(obs.obs_type, VIRP_OBS_DEVICE_OUTPUT);
    ASSERT_EQ(obs.obs_scope, VIRP_SCOPE_LOCAL);
    ASSERT_EQ(obs_data_len, sizeof(data));
    ASSERT_TRUE(memcmp(obs_data, data, sizeof(data)) == 0);
}

TEST(test_proposal_round_trip)
{
    uint8_t buf[512];
    size_t out_len;
    virp_obs_ref_t refs[2] = {
        { .node_id = 0x05050505, .seq_num = 10 },
        { .node_id = 0x07070707, .seq_num = 20 },
    };
    uint8_t data[] = "router bgp 300\nneighbor 5.5.5.5 remote-as 300";

    virp_error_t err = virp_build_proposal(buf, sizeof(buf), &out_len,
                                           0x06060606, 43,
                                           1001,
                                           VIRP_PROP_CONFIG_APPLY,
                                           3,
                                           refs, 2,
                                           data, sizeof(data),
                                           &rkey);
    ASSERT_OK(err);

    /* Validate */
    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &rkey, &hdr);
    ASSERT_OK(err);

    ASSERT_EQ(hdr.type, VIRP_MSG_PROPOSAL);
    ASSERT_EQ(hdr.channel, VIRP_CHANNEL_IC);
    ASSERT_EQ(hdr.tier, VIRP_TIER_YELLOW);

    /* Parse proposal */
    virp_proposal_t prop;
    const virp_obs_ref_t *parsed_refs;
    const uint8_t *prop_data;
    uint16_t prop_data_len;
    err = virp_parse_proposal(buf + VIRP_HEADER_SIZE,
                              out_len - VIRP_HEADER_SIZE,
                              &prop, &parsed_refs,
                              &prop_data, &prop_data_len);
    ASSERT_OK(err);
    ASSERT_EQ(prop.proposal_id, 1001);
    ASSERT_EQ(prop.prop_type, VIRP_PROP_CONFIG_APPLY);
    ASSERT_EQ(prop.prop_state, VIRP_PSTATE_PROPOSED);
    ASSERT_EQ(prop.blast_radius, 3);
    ASSERT_EQ(prop.obs_ref_count, 2);
}

TEST(test_heartbeat_round_trip)
{
    uint8_t buf[256];
    size_t out_len;

    virp_error_t err = virp_build_heartbeat(buf, sizeof(buf), &out_len,
                                            0x06060606, 44,
                                            3600, true, true,
                                            15, 3,
                                            &okey);
    ASSERT_OK(err);

    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &okey, &hdr);
    ASSERT_OK(err);

    virp_heartbeat_t hb;
    err = virp_parse_heartbeat(buf + VIRP_HEADER_SIZE,
                               out_len - VIRP_HEADER_SIZE, &hb);
    ASSERT_OK(err);
    ASSERT_EQ(hb.uptime_seconds, 3600);
    ASSERT_EQ(hb.onode_ok, 1);
    ASSERT_EQ(hb.rnode_ok, 1);
    ASSERT_EQ(hb.active_observations, 15);
    ASSERT_EQ(hb.active_proposals, 3);
}

TEST(test_approval_round_trip)
{
    uint8_t buf[256];
    size_t out_len;

    virp_error_t err = virp_build_approval(buf, sizeof(buf), &out_len,
                                           0x06060606, 45,
                                           1001,
                                           0xAABBCCDD,
                                           VIRP_APPROVAL_APPROVE,
                                           VIRP_APPROVER_HUMAN,
                                           &rkey);
    ASSERT_OK(err);

    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &rkey, &hdr);
    ASSERT_OK(err);

    virp_approval_t approval;
    err = virp_parse_approval(buf + VIRP_HEADER_SIZE,
                              out_len - VIRP_HEADER_SIZE, &approval);
    ASSERT_OK(err);
    ASSERT_EQ(approval.proposal_id, 1001);
    ASSERT_EQ(approval.approver_node_id, 0xAABBCCDD);
    ASSERT_EQ(approval.approval_type, VIRP_APPROVAL_APPROVE);
    ASSERT_EQ(approval.approver_class, VIRP_APPROVER_HUMAN);
}

TEST(test_intent_advertise_round_trip)
{
    uint8_t buf[512];
    size_t out_len;
    virp_obs_ref_t proofs[1] = {
        { .node_id = 0x06060606, .seq_num = 42 },
    };
    uint8_t data[] = "10.0.0.0/24 reachable latency<10ms";

    virp_error_t err = virp_build_intent_advertise(buf, sizeof(buf), &out_len,
                                                   0x06060606, 46,
                                                   2001,
                                                   VIRP_INTENT_REACHABILITY,
                                                   128, 300,
                                                   proofs, 1,
                                                   data, sizeof(data),
                                                   &rkey);
    ASSERT_OK(err);

    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &rkey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_INTENT_ADV);
}

TEST(test_intent_withdraw_round_trip)
{
    uint8_t buf[256];
    size_t out_len;

    virp_error_t err = virp_build_intent_withdraw(buf, sizeof(buf), &out_len,
                                                  0x06060606, 47,
                                                  2001,
                                                  &rkey);
    ASSERT_OK(err);

    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &rkey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_INTENT_WD);
}

/* =========================================================================
 * 10. Key management
 * ========================================================================= */

TEST(test_key_generate_and_destroy)
{
    virp_signing_key_t sk;
    virp_error_t err = virp_key_generate(&sk, VIRP_KEY_TYPE_OKEY);
    ASSERT_OK(err);
    ASSERT_TRUE(sk.key.loaded);
    ASSERT_EQ(sk.type, VIRP_KEY_TYPE_OKEY);

    /* Fingerprint should be non-zero */
    uint8_t zeros[VIRP_HMAC_SIZE] = {0};
    ASSERT_TRUE(memcmp(sk.fingerprint, zeros, VIRP_HMAC_SIZE) != 0);

    /* Destroy should zero everything */
    virp_key_destroy(&sk);
    ASSERT_TRUE(sk.key.loaded == false);
}

TEST(test_key_save_and_load)
{
    virp_signing_key_t original, loaded;
    const char *path = "/tmp/virp_test_key.bin";

    virp_key_generate(&original, VIRP_KEY_TYPE_RKEY);
    virp_error_t err = virp_key_save_file(&original, path);
    ASSERT_OK(err);

    err = virp_key_load_file(&loaded, VIRP_KEY_TYPE_RKEY, path);
    ASSERT_OK(err);

    ASSERT_TRUE(memcmp(original.key.key, loaded.key.key, VIRP_KEY_SIZE) == 0);
    ASSERT_TRUE(memcmp(original.fingerprint, loaded.fingerprint, VIRP_HMAC_SIZE) == 0);

    unlink(path);
}

/*
 * Hardening: a key file with group/other bits set must be refused by
 * virp_key_load_file. virp_key_save_file writes 0600, so we chmod
 * post-save to force the insecure mode. The daemon's onode_init calls
 * virp_key_load_file directly, so rejection here means the daemon
 * would refuse to start.
 */
TEST(test_key_load_rejects_insecure_mode)
{
    virp_signing_key_t original, loaded;
    const char *path = "/tmp/virp_test_key_perms.bin";

    virp_key_generate(&original, VIRP_KEY_TYPE_RKEY);
    ASSERT_OK(virp_key_save_file(&original, path));

    /* Force the mode the user's prompt calls out — 0644. */
    ASSERT_TRUE(chmod(path, 0644) == 0);
    virp_error_t err = virp_key_load_file(&loaded, VIRP_KEY_TYPE_RKEY, path);
    ASSERT_EQ(err, VIRP_ERR_KEY_NOT_LOADED);

    /* 0604 (other-readable) also rejected */
    ASSERT_TRUE(chmod(path, 0604) == 0);
    err = virp_key_load_file(&loaded, VIRP_KEY_TYPE_RKEY, path);
    ASSERT_EQ(err, VIRP_ERR_KEY_NOT_LOADED);

    /* 0640 (group-readable) also rejected */
    ASSERT_TRUE(chmod(path, 0640) == 0);
    err = virp_key_load_file(&loaded, VIRP_KEY_TYPE_RKEY, path);
    ASSERT_EQ(err, VIRP_ERR_KEY_NOT_LOADED);

    /* Sanity: 0600 is accepted. */
    ASSERT_TRUE(chmod(path, 0600) == 0);
    err = virp_key_load_file(&loaded, VIRP_KEY_TYPE_RKEY, path);
    ASSERT_OK(err);

    unlink(path);
}

/*
 * A symlinked key file must be refused — O_NOFOLLOW guards against
 * a swap-at-open attack where the target is replaced by a world-
 * writable file between stat and open.
 */
TEST(test_key_load_rejects_symlink)
{
    virp_signing_key_t original, loaded;
    const char *target = "/tmp/virp_test_key_target.bin";
    const char *link   = "/tmp/virp_test_key_link.bin";

    virp_key_generate(&original, VIRP_KEY_TYPE_RKEY);
    ASSERT_OK(virp_key_save_file(&original, target));
    unlink(link);
    ASSERT_TRUE(symlink(target, link) == 0);

    virp_error_t err = virp_key_load_file(&loaded, VIRP_KEY_TYPE_RKEY, link);
    ASSERT_EQ(err, VIRP_ERR_KEY_NOT_LOADED);

    unlink(link);
    unlink(target);
}

/*
 * Truncated key files (shorter than VIRP_KEY_SIZE) must be refused
 * rather than silently returning uninitialized bytes.
 */
TEST(test_key_load_rejects_truncated)
{
    virp_signing_key_t loaded;
    const char *path = "/tmp/virp_test_key_short.bin";

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT_TRUE(fd >= 0);
    uint8_t short_buf[VIRP_KEY_SIZE - 4] = {0};
    ssize_t wn = write(fd, short_buf, sizeof(short_buf));
    ASSERT_TRUE(wn == (ssize_t)sizeof(short_buf));
    close(fd);

    virp_error_t err = virp_key_load_file(&loaded, VIRP_KEY_TYPE_RKEY, path);
    ASSERT_EQ(err, VIRP_ERR_KEY_NOT_LOADED);

    unlink(path);
}

/* =========================================================================
 * 11. Edge cases and NULL safety
 * ========================================================================= */

TEST(test_null_pointers)
{
    ASSERT_EQ(virp_header_init(NULL, 0, 0, 0, 0, 0), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_header_serialize(NULL, NULL, 0), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_header_deserialize(NULL, NULL, 0), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_header_validate(NULL), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_sign(NULL, NULL, 0, NULL), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_verify(NULL, NULL, 0, NULL), VIRP_ERR_NULL_PTR);
}

TEST(test_buffer_too_small)
{
    uint8_t tiny[10];
    size_t out_len;
    uint8_t data[] = "test";

    virp_error_t err = virp_build_observation(tiny, sizeof(tiny), &out_len,
                                              1, 1,
                                              VIRP_OBS_DEVICE_OUTPUT,
                                              VIRP_SCOPE_LOCAL,
                                              data, sizeof(data),
                                              &okey);
    ASSERT_EQ(err, VIRP_ERR_BUFFER_TOO_SMALL);
}

TEST(test_reserved_nonzero_rejected)
{
    virp_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version = VIRP_VERSION;
    hdr.type = VIRP_MSG_OBSERVATION;
    hdr.length = VIRP_HEADER_SIZE;
    hdr.channel = VIRP_CHANNEL_OC;
    hdr.tier = VIRP_TIER_GREEN;
    hdr.reserved = 0x1234;  /* NON-ZERO — must be rejected */

    ASSERT_EQ(virp_header_validate(&hdr), VIRP_ERR_RESERVED_NONZERO);
}

/* =========================================================================
 * 11b. Embedded-length bounds — the parser must never return a data_len
 * that overruns the buffer it was given. obs_length and obs_ref_count
 * come off the wire; before these checks a malformed message could make
 * every downstream consumer (hex_dump, printf %.*s, memcpy) read past
 * the payload.
 * ========================================================================= */

/* Payload claims 20 data bytes but carries only 10: reject. */
TEST(test_parse_obs_truncated_claim)
{
    uint8_t payload[14];
    payload[0] = VIRP_OBS_DEVICE_OUTPUT;
    payload[1] = VIRP_SCOPE_LOCAL;
    uint16_t dl_n = htons(20);          /* claims 20 */
    memcpy(payload + 2, &dl_n, 2);
    memset(payload + 4, 'A', 10);       /* carries 10 */

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    virp_error_t err = virp_parse_observation(payload, sizeof(payload),
                                              &obs, &data, &data_len);
    ASSERT_EQ(err, VIRP_ERR_INVALID_LENGTH);
}

/* Maximum possible embedded length against a minimal payload: reject. */
TEST(test_parse_obs_oversized_length)
{
    uint8_t payload[8];
    payload[0] = VIRP_OBS_DEVICE_OUTPUT;
    payload[1] = VIRP_SCOPE_LOCAL;
    uint16_t dl_n = htons(0xFFFF);
    memcpy(payload + 2, &dl_n, 2);
    memset(payload + 4, 'B', 4);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    virp_error_t err = virp_parse_observation(payload, sizeof(payload),
                                              &obs, &data, &data_len);
    ASSERT_EQ(err, VIRP_ERR_INVALID_LENGTH);
}

/* Zero-length data in a bare 4-byte sub-header is legal. */
TEST(test_parse_obs_zero_length_data)
{
    uint8_t payload[4];
    payload[0] = VIRP_OBS_ERROR;
    payload[1] = VIRP_SCOPE_LOCAL;
    uint16_t dl_n = htons(0);
    memcpy(payload + 2, &dl_n, 2);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(payload, sizeof(payload),
                                     &obs, &data, &data_len));
    ASSERT_EQ(data_len, 0);
    ASSERT_TRUE(data == NULL);
}

/* obs_length exactly filling the payload is legal (the common case). */
TEST(test_parse_obs_exact_boundary)
{
    uint8_t payload[4 + 32];
    payload[0] = VIRP_OBS_DEVICE_OUTPUT;
    payload[1] = VIRP_SCOPE_LOCAL;
    uint16_t dl_n = htons(32);
    memcpy(payload + 2, &dl_n, 2);
    memset(payload + 4, 'C', 32);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(payload, sizeof(payload),
                                     &obs, &data, &data_len));
    ASSERT_EQ(data_len, 32);
    ASSERT_TRUE(data == payload + 4);
}

/* obs_length shorter than the payload is legal: spec §9 reserves the
 * tail for future trailer fields; data_len reports only the data. */
TEST(test_parse_obs_trailer_allowed)
{
    uint8_t payload[4 + 16];
    payload[0] = VIRP_OBS_DEVICE_OUTPUT;
    payload[1] = VIRP_SCOPE_LOCAL;
    uint16_t dl_n = htons(10);          /* 10 data + 6 trailer bytes */
    memcpy(payload + 2, &dl_n, 2);
    memset(payload + 4, 'D', 16);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(payload, sizeof(payload),
                                     &obs, &data, &data_len));
    ASSERT_EQ(data_len, 10);
}

/* Proposal whose obs_ref_count would overrun the payload: reject.
 * Before the fix the parser handed back the wire count and a refs
 * pointer into a 12-byte buffer. */
TEST(test_parse_proposal_refs_overrun)
{
    uint8_t payload[12];
    memset(payload, 0, sizeof(payload));
    uint32_t pid_n = htonl(77);
    memcpy(payload, &pid_n, 4);
    payload[4] = VIRP_PROP_CONFIG_APPLY;
    payload[5] = VIRP_PSTATE_PROPOSED;
    uint32_t orc_n = htonl(2);          /* 2 refs claimed, zero bytes of refs */
    memcpy(payload + 8, &orc_n, 4);

    virp_proposal_t prop;
    const virp_obs_ref_t *refs;
    const uint8_t *prop_data;
    uint16_t prop_data_len;
    virp_error_t err = virp_parse_proposal(payload, sizeof(payload),
                                           &prop, &refs,
                                           &prop_data, &prop_data_len);
    ASSERT_EQ(err, VIRP_ERR_INVALID_LENGTH);
}

/* obs_ref_count above VIRP_MAX_OBS_REFS is rejected even when the
 * bytes are physically present (builder parity). */
TEST(test_parse_proposal_count_over_max)
{
    static uint8_t payload[12 + (VIRP_MAX_OBS_REFS + 1) * sizeof(virp_obs_ref_t)];
    memset(payload, 0, sizeof(payload));
    uint32_t pid_n = htonl(78);
    memcpy(payload, &pid_n, 4);
    payload[4] = VIRP_PROP_CONFIG_APPLY;
    payload[5] = VIRP_PSTATE_PROPOSED;
    uint32_t orc_n = htonl(VIRP_MAX_OBS_REFS + 1);
    memcpy(payload + 8, &orc_n, 4);

    virp_proposal_t prop;
    const virp_obs_ref_t *refs;
    const uint8_t *prop_data;
    uint16_t prop_data_len;
    virp_error_t err = virp_parse_proposal(payload, sizeof(payload),
                                           &prop, &refs,
                                           &prop_data, &prop_data_len);
    ASSERT_EQ(err, VIRP_ERR_MESSAGE_TOO_LARGE);
}

/* Zero obs refs: the builder refuses to create one (proposals MUST
 * carry evidence); the parser must refuse to bless one. */
TEST(test_parse_proposal_zero_refs)
{
    uint8_t payload[12];
    memset(payload, 0, sizeof(payload));
    uint32_t pid_n = htonl(79);
    memcpy(payload, &pid_n, 4);
    payload[4] = VIRP_PROP_CONFIG_APPLY;
    payload[5] = VIRP_PSTATE_PROPOSED;
    /* obs_ref_count stays 0 */

    virp_proposal_t prop;
    const virp_obs_ref_t *refs;
    const uint8_t *prop_data;
    uint16_t prop_data_len;
    virp_error_t err = virp_parse_proposal(payload, sizeof(payload),
                                           &prop, &refs,
                                           &prop_data, &prop_data_len);
    ASSERT_EQ(err, VIRP_ERR_NO_EVIDENCE);
}

/* =========================================================================
 * 12. Hello message
 * ========================================================================= */

TEST(test_hello_round_trip)
{
    uint8_t buf[512];
    size_t out_len;

    virp_error_t err = virp_build_hello(buf, sizeof(buf), &out_len,
                                        0x06060606, 1,
                                        VIRP_NODE_HYBRID,
                                        VIRP_TIER_RED,
                                        &okey, &rkey);
    ASSERT_OK(err);

    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &okey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_HELLO);

    virp_hello_t hello;
    err = virp_parse_hello(buf + VIRP_HEADER_SIZE,
                           out_len - VIRP_HEADER_SIZE, &hello);
    ASSERT_OK(err);
    ASSERT_EQ(hello.magic, VIRP_MAGIC);
    ASSERT_EQ(hello.version, VIRP_VERSION);
    ASSERT_EQ(hello.node_type, VIRP_NODE_HYBRID);
    ASSERT_EQ(hello.max_tier, VIRP_TIER_RED);
    ASSERT_EQ(hello.node_id, 0x06060606);

    /* Fingerprints should match keys */
    ASSERT_TRUE(memcmp(hello.okey_fingerprint, okey.fingerprint, VIRP_HMAC_SIZE) == 0);
    ASSERT_TRUE(memcmp(hello.rkey_fingerprint, rkey.fingerprint, VIRP_HMAC_SIZE) == 0);
}

/* =========================================================================
 * 13. Teardown messages
 * ========================================================================= */

TEST(test_teardown_on_oc)
{
    uint8_t buf[256];
    size_t out_len;

    virp_error_t err = virp_build_teardown(buf, sizeof(buf), &out_len,
                                           0x06060606, 50,
                                           VIRP_CHANNEL_OC,
                                           "graceful shutdown",
                                           &okey);
    ASSERT_OK(err);

    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &okey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_TEARDOWN);
    ASSERT_EQ(hdr.channel, VIRP_CHANNEL_OC);
}

TEST(test_teardown_on_ic)
{
    uint8_t buf[256];
    size_t out_len;

    virp_error_t err = virp_build_teardown(buf, sizeof(buf), &out_len,
                                           0x06060606, 51,
                                           VIRP_CHANNEL_IC,
                                           "peer decommissioned",
                                           &rkey);
    ASSERT_OK(err);

    virp_header_t hdr;
    err = virp_validate_message(buf, out_len, &rkey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_TEARDOWN);
    ASSERT_EQ(hdr.channel, VIRP_CHANNEL_IC);
}

TEST(test_teardown_null_reason)
{
    uint8_t buf[256];
    size_t out_len;

    virp_error_t err = virp_build_teardown(buf, sizeof(buf), &out_len,
                                           0x06060606, 52,
                                           VIRP_CHANNEL_OC,
                                           NULL,
                                           &okey);
    ASSERT_OK(err);
}

/* =========================================================================
 * 14. TLV extension fields
 * ========================================================================= */

TEST(test_tlv_round_trip)
{
    uint8_t buf[256];
    uint8_t value[] = "37.7749,-122.4194";

    int new_offset = virp_tlv_append(buf, sizeof(buf), 0,
                                     VIRP_TLV_GEOCODE,
                                     value, sizeof(value));
    ASSERT_TRUE(new_offset > 0);
    ASSERT_EQ((size_t)new_offset, 4 + sizeof(value));

    virp_tlv_t tlv;
    const uint8_t *parsed_value;
    int parsed_offset = virp_tlv_parse(buf, sizeof(buf), 0,
                                       &tlv, &parsed_value);
    ASSERT_TRUE(parsed_offset > 0);
    ASSERT_EQ(tlv.type, VIRP_TLV_GEOCODE);
    ASSERT_EQ(tlv.length, sizeof(value));
    ASSERT_TRUE(memcmp(parsed_value, value, sizeof(value)) == 0);
}

TEST(test_tlv_chain)
{
    uint8_t buf[512];
    uint8_t geo[] = "42.331,-83.046";
    uint8_t trace[] = "abc-123-def";

    int off = virp_tlv_append(buf, sizeof(buf), 0,
                              VIRP_TLV_GEOCODE, geo, sizeof(geo));
    ASSERT_TRUE(off > 0);

    off = virp_tlv_append(buf, sizeof(buf), (size_t)off,
                          VIRP_TLV_TRACE_ID, trace, sizeof(trace));
    ASSERT_TRUE(off > 0);

    virp_tlv_t tlv;
    const uint8_t *val;
    int pos = virp_tlv_parse(buf, sizeof(buf), 0, &tlv, &val);
    ASSERT_TRUE(pos > 0);
    ASSERT_EQ(tlv.type, VIRP_TLV_GEOCODE);

    pos = virp_tlv_parse(buf, sizeof(buf), (size_t)pos, &tlv, &val);
    ASSERT_TRUE(pos > 0);
    ASSERT_EQ(tlv.type, VIRP_TLV_TRACE_ID);
    ASSERT_TRUE(memcmp(val, trace, sizeof(trace)) == 0);
}

TEST(test_tlv_buffer_overflow_protection)
{
    uint8_t tiny[4];
    uint8_t value[] = "too much data for this buffer";

    int result = virp_tlv_append(tiny, sizeof(tiny), 0,
                                 VIRP_TLV_VENDOR, value, sizeof(value));
    ASSERT_TRUE(result < 0);
}

/* =========================================================================
 * Key-file ownership gate (virp_key_owner_ok)
 *
 * The gate accepts owner == euid OR euid == 0: root reading a
 * service-owned key (`virp approve` as root loading the virp-onode-
 * owned chain.key) is not an escalation. Mode-bit checks are separate
 * and unchanged — these tests do not touch them.
 * ========================================================================= */

TEST(test_key_owner_check_predicate)
{
    /* owner == euid: accepted */
    ASSERT_TRUE(virp_key_owner_ok(1234, 1234));
    ASSERT_TRUE(virp_key_owner_ok(0, 0));
    /* euid == 0 with a foreign-owned file: accepted */
    ASSERT_TRUE(virp_key_owner_ok(999, 0));
    ASSERT_TRUE(virp_key_owner_ok(65534, 0));
    /* non-root euid with a foreign-owned file: refused */
    ASSERT_TRUE(!virp_key_owner_ok(999, 1000));
    ASSERT_TRUE(!virp_key_owner_ok(0, 999));
}

TEST(test_key_load_ownership_integration)
{
    const char *path = "/tmp/virp-test-foreign-owner.key";
    unlink(path);

    virp_signing_key_t sk;
    ASSERT_OK(virp_key_generate(&sk, VIRP_KEY_TYPE_OKEY));
    ASSERT_OK(virp_key_save_file(&sk, path));
    virp_key_destroy(&sk);

    /* owner == euid loads (all environments) */
    ASSERT_OK(virp_key_load_file(&sk, VIRP_KEY_TYPE_OKEY, path));
    virp_key_destroy(&sk);

    if (geteuid() != 0) {
        /* The root/foreign-owner cases need root; predicate coverage
         * above still pins the logic. */
        unlink(path);
        return;
    }

    /* euid == 0, service-owned file (the `virp approve` blocker case):
     * accepted. 65534 = nobody. */
    ASSERT_EQ(chown(path, 65534, 65534), 0);
    ASSERT_OK(virp_key_load_file(&sk, VIRP_KEY_TYPE_OKEY, path));
    virp_key_destroy(&sk);

    /* non-root euid, foreign-owned file: refused. (Owned by root again;
     * as uid 65534 the load must fail — the 0600 mode alone already
     * denies the open, and virp_key_owner_ok would refuse it too.) */
    ASSERT_EQ(chown(path, 0, 0), 0);
    ASSERT_EQ(seteuid(65534), 0);
    virp_error_t err = virp_key_load_file(&sk, VIRP_KEY_TYPE_OKEY, path);
    int restored = seteuid(0);
    ASSERT_EQ(restored, 0);
    ASSERT_EQ(err, VIRP_ERR_KEY_NOT_LOADED);

    unlink(path);
}

/* =========================================================================
 * Main — run all tests
 * ========================================================================= */


/* =========================================================================
 * Durable, symlink-safe file write (virp_write_file_durable)
 *
 * The WRITE path used to be weaker than the READ path: virp_key_load_file
 * has used O_NOFOLLOW/O_CLOEXEC plus fstat mode+owner checks for a while,
 * while the save path opened O_CREAT|O_TRUNC with no O_EXCL and no
 * O_NOFOLLOW — so a symlink planted at the target redirected where the
 * bytes landed. That asymmetry was the bug.
 * ========================================================================= */

#define WFD_DIR   "/tmp/virp-wfd-test"
#define WFD_TGT   WFD_DIR "/target.bin"
#define WFD_LINK  WFD_DIR "/decoy.bin"

static void wfd_cleanup(void)
{
    unlink(WFD_TGT); unlink(WFD_LINK);
    unlink(WFD_TGT ".tmp");
    rmdir(WFD_DIR);
}

TEST(test_wfd_writes_exact_bytes_and_mode)
{
    wfd_cleanup();
    ASSERT_EQ(mkdir(WFD_DIR, 0700), 0);

    /* Binary payload including an embedded NUL — the reason the helper
     * takes a length instead of a NUL-terminated string. */
    const uint8_t payload[8] = { 0xde, 0xad, 0x00, 0xbe, 0xef, 0x00, 0x01, 0x02 };
    ASSERT_OK(virp_write_file_durable(WFD_TGT, 0600, payload, sizeof(payload)));

    struct stat st;
    ASSERT_EQ(stat(WFD_TGT, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 07777), 0600);
    ASSERT_EQ((int)st.st_size, (int)sizeof(payload));
    ASSERT_EQ((int)(st.st_mode & (S_IRWXG | S_IRWXO)), 0);

    uint8_t back[8] = {0};
    int fd = open(WFD_TGT, O_RDONLY);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)read(fd, back, sizeof(back)), (int)sizeof(payload));
    close(fd);
    ASSERT_EQ(memcmp(back, payload, sizeof(payload)), 0);

    /* No temp file left behind. */
    ASSERT_NEQ(stat(WFD_TGT ".tmp", &st), 0);
    wfd_cleanup();
}

TEST(test_wfd_symlink_at_target_not_followed)
{
    wfd_cleanup();
    ASSERT_EQ(mkdir(WFD_DIR, 0700), 0);

    /* Decoy the link points at; it must NOT receive the bytes. */
    int fd = open(WFD_LINK, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)write(fd, "old", 3), 3);
    close(fd);

    /* Plant the symlink at the write target. */
    ASSERT_EQ(symlink(WFD_LINK, WFD_TGT), 0);

    const uint8_t secret[4] = { 0x11, 0x22, 0x33, 0x44 };
    ASSERT_OK(virp_write_file_durable(WFD_TGT, 0600, secret, sizeof(secret)));

    /*
     * rename(2) REPLACES the symlink rather than following it, so the
     * target is now a regular file holding our bytes...
     */
    struct stat lst;
    ASSERT_EQ(lstat(WFD_TGT, &lst), 0);
    ASSERT_EQ((int)S_ISLNK(lst.st_mode), 0);
    ASSERT_EQ((int)S_ISREG(lst.st_mode), 1);
    ASSERT_EQ((int)(lst.st_mode & 07777), 0600);

    /* ...and the decoy is untouched: the key did not land at the link
     * target. This is the assertion the finding is about. */
    struct stat dst;
    ASSERT_EQ(stat(WFD_LINK, &dst), 0);
    ASSERT_EQ((int)dst.st_size, 3);
    uint8_t decoy[8] = {0};
    fd = open(WFD_LINK, O_RDONLY);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)read(fd, decoy, sizeof(decoy)), 3);
    close(fd);
    ASSERT_EQ(memcmp(decoy, "old", 3), 0);
    wfd_cleanup();
}

TEST(test_wfd_symlink_at_temp_path_not_followed)
{
    wfd_cleanup();
    ASSERT_EQ(mkdir(WFD_DIR, 0700), 0);

    /* Plant a symlink at the TEMP name, the other half of the race. */
    int fd = open(WFD_LINK, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)write(fd, "old", 3), 3);
    close(fd);
    ASSERT_EQ(symlink(WFD_LINK, WFD_TGT ".tmp"), 0);

    const uint8_t secret[4] = { 0xaa, 0xbb, 0xcc, 0xdd };
    ASSERT_OK(virp_write_file_durable(WFD_TGT, 0600, secret, sizeof(secret)));

    /* Decoy still holds its original contents. */
    uint8_t decoy[8] = {0};
    fd = open(WFD_LINK, O_RDONLY);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)read(fd, decoy, sizeof(decoy)), 3);
    close(fd);
    ASSERT_EQ(memcmp(decoy, "old", 3), 0);
    wfd_cleanup();
}

TEST(test_wfd_stale_temp_does_not_wedge_writes)
{
    /*
     * Regression for the O_EXCL adoption: a stale <path>.tmp left by a
     * crash must not permanently break writes. The helper unlinks it
     * first, so the write succeeds and self-heals as it did before.
     */
    wfd_cleanup();
    ASSERT_EQ(mkdir(WFD_DIR, 0700), 0);

    int fd = open(WFD_TGT ".tmp", O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)write(fd, "stale", 5), 5);
    close(fd);

    const uint8_t payload[3] = { 1, 2, 3 };
    ASSERT_OK(virp_write_file_durable(WFD_TGT, 0600, payload, sizeof(payload)));

    struct stat st;
    ASSERT_EQ(stat(WFD_TGT, &st), 0);
    ASSERT_EQ((int)st.st_size, 3);
    wfd_cleanup();
}


/* =========================================================================
 * Key save: symmetry with the load path
 *
 * virp_key_load_file has long required O_NOFOLLOW plus a regular-file,
 * mode and owner check. virp_key_save_file opened O_CREAT|O_TRUNC with
 * neither O_EXCL nor O_NOFOLLOW, so a symlink planted at the key path
 * redirected the key material to the link target. These pin the save
 * path to the guarantees the load path already made.
 * ========================================================================= */

#define KS_DIR   "/tmp/virp-keysave-test"
#define KS_KEY   KS_DIR "/onode.key"
#define KS_DECOY KS_DIR "/decoy.key"

static void ks_cleanup(void)
{
    unlink(KS_KEY); unlink(KS_DECOY); unlink(KS_KEY ".tmp");
    rmdir(KS_DIR);
}

TEST(test_key_save_roundtrip_is_0600_and_intact)
{
    ks_cleanup();
    ASSERT_EQ(mkdir(KS_DIR, 0700), 0);

    virp_signing_key_t sk;
    ASSERT_OK(virp_key_generate(&sk, VIRP_KEY_TYPE_OKEY));
    ASSERT_OK(virp_key_save_file(&sk, KS_KEY));

    struct stat st;
    ASSERT_EQ(stat(KS_KEY, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 07777), 0600);
    ASSERT_EQ((int)(st.st_mode & (S_IRWXG | S_IRWXO)), 0);
    ASSERT_EQ((int)st.st_size, VIRP_KEY_SIZE);

    /* Reads back byte-identical through the hardened load path. */
    virp_signing_key_t loaded;
    ASSERT_OK(virp_key_load_file(&loaded, VIRP_KEY_TYPE_OKEY, KS_KEY));
    ASSERT_EQ(memcmp(loaded.key.key, sk.key.key, VIRP_KEY_SIZE), 0);

    virp_key_destroy(&loaded);
    virp_key_destroy(&sk);
    ks_cleanup();
}

TEST(test_key_save_does_not_follow_symlink)
{
    ks_cleanup();
    ASSERT_EQ(mkdir(KS_DIR, 0700), 0);

    /* Decoy the planted link points at. */
    int fd = open(KS_DECOY, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)write(fd, "not-a-key", 9), 9);
    close(fd);

    ASSERT_EQ(symlink(KS_DECOY, KS_KEY), 0);

    virp_signing_key_t sk;
    ASSERT_OK(virp_key_generate(&sk, VIRP_KEY_TYPE_OKEY));
    ASSERT_OK(virp_key_save_file(&sk, KS_KEY));

    /* The key path is now a regular 0600 file, not the symlink. */
    struct stat lst;
    ASSERT_EQ(lstat(KS_KEY, &lst), 0);
    ASSERT_EQ((int)S_ISLNK(lst.st_mode), 0);
    ASSERT_EQ((int)S_ISREG(lst.st_mode), 1);
    ASSERT_EQ((int)(lst.st_mode & 07777), 0600);
    ASSERT_EQ((int)lst.st_size, VIRP_KEY_SIZE);

    /* The key did NOT land at the link target — the whole point. */
    struct stat dst;
    ASSERT_EQ(stat(KS_DECOY, &dst), 0);
    ASSERT_EQ((int)dst.st_size, 9);
    uint8_t decoy[32] = {0};
    fd = open(KS_DECOY, O_RDONLY);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)read(fd, decoy, sizeof(decoy)), 9);
    close(fd);
    ASSERT_EQ(memcmp(decoy, "not-a-key", 9), 0);

    virp_key_destroy(&sk);
    ks_cleanup();
}

TEST(test_key_save_tightens_mode_on_existing_file)
{
    /*
     * 0600 used to apply only on create, so saving over a pre-existing
     * world-readable file left it world-readable. fchmod in the helper
     * makes the mode hold every time.
     */
    ks_cleanup();
    ASSERT_EQ(mkdir(KS_DIR, 0700), 0);

    int fd = open(KS_KEY, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    ASSERT_TRUE(fd >= 0);
    close(fd);
    ASSERT_EQ(chmod(KS_KEY, 0666), 0);

    virp_signing_key_t sk;
    ASSERT_OK(virp_key_generate(&sk, VIRP_KEY_TYPE_OKEY));
    ASSERT_OK(virp_key_save_file(&sk, KS_KEY));

    struct stat st;
    ASSERT_EQ(stat(KS_KEY, &st), 0);
    ASSERT_EQ((int)(st.st_mode & 07777), 0600);

    /* And it still loads: the load path rejects group/other bits. */
    virp_signing_key_t loaded;
    ASSERT_OK(virp_key_load_file(&loaded, VIRP_KEY_TYPE_OKEY, KS_KEY));
    virp_key_destroy(&loaded);
    virp_key_destroy(&sk);
    ks_cleanup();
}


/* =========================================================================
 * Key generation entropy
 *
 * The old path did a single un-looped read() of /dev/urandom and never
 * wiped the stack buffer. read(2) may return short; every other read in
 * this codebase loops. Generation now uses randombytes_buf(), which
 * fills the whole buffer or does not return, and sodium_memzero()s the
 * stack copy.
 * ========================================================================= */

TEST(test_key_generate_fills_full_length)
{
    virp_signing_key_t sk;
    memset(&sk, 0, sizeof(sk));
    ASSERT_OK(virp_key_generate(&sk, VIRP_KEY_TYPE_OKEY));

    ASSERT_TRUE(sk.key.loaded);
    ASSERT_EQ((int)sk.type, (int)VIRP_KEY_TYPE_OKEY);

    /* Not all-zero: a short or failed fill would leave a zero tail. */
    int nonzero = 0;
    for (int i = 0; i < VIRP_KEY_SIZE; i++)
        if (sk.key.key[i] != 0) nonzero++;
    ASSERT_TRUE(nonzero > 0);

    /*
     * A short read would most plausibly leave a run of trailing zeros.
     * Assert the last quarter of the key is not entirely zero — with
     * real entropy the chance of that is 256^-8.
     */
    int tail_nonzero = 0;
    for (int i = VIRP_KEY_SIZE - (VIRP_KEY_SIZE / 4); i < VIRP_KEY_SIZE; i++)
        if (sk.key.key[i] != 0) tail_nonzero++;
    ASSERT_TRUE(tail_nonzero > 0);

    virp_key_destroy(&sk);
}

TEST(test_key_generate_two_keys_differ)
{
    virp_signing_key_t a, b;
    ASSERT_OK(virp_key_generate(&a, VIRP_KEY_TYPE_OKEY));
    ASSERT_OK(virp_key_generate(&b, VIRP_KEY_TYPE_OKEY));

    /* Distinct, and neither is the all-zero key. */
    ASSERT_NEQ(memcmp(a.key.key, b.key.key, VIRP_KEY_SIZE), 0);

    uint8_t zero[VIRP_KEY_SIZE];
    memset(zero, 0, sizeof(zero));
    ASSERT_NEQ(memcmp(a.key.key, zero, VIRP_KEY_SIZE), 0);
    ASSERT_NEQ(memcmp(b.key.key, zero, VIRP_KEY_SIZE), 0);

    virp_key_destroy(&a);
    virp_key_destroy(&b);
}

TEST(test_key_generate_rejects_null)
{
    /* The only caller-reachable failure path returns an error rather
     * than partially initialising anything. */
    ASSERT_EQ(virp_key_generate(NULL, VIRP_KEY_TYPE_OKEY), VIRP_ERR_NULL_PTR);
}

TEST(test_key_generate_distinct_across_key_types)
{
    virp_signing_key_t o, r;
    ASSERT_OK(virp_key_generate(&o, VIRP_KEY_TYPE_OKEY));
    ASSERT_OK(virp_key_generate(&r, VIRP_KEY_TYPE_RKEY));
    ASSERT_EQ((int)o.type, (int)VIRP_KEY_TYPE_OKEY);
    ASSERT_EQ((int)r.type, (int)VIRP_KEY_TYPE_RKEY);
    ASSERT_NEQ(memcmp(o.key.key, r.key.key, VIRP_KEY_SIZE), 0);
    virp_key_destroy(&o);
    virp_key_destroy(&r);
}

int main(void)
{
    printf("\n");
    printf("================================================================\n");
    printf("  VIRP — Verified Infrastructure Response Protocol\n");
    printf("  Test Suite v1.0\n");
    printf("  Copyright (c) 2026 Third Level IT LLC\n");
    printf("================================================================\n\n");

    setup_keys();

    printf("[Structural Guarantees]\n");
    RUN_TEST(test_header_size);
    RUN_TEST(test_black_tier_rejected);
    RUN_TEST(test_black_tier_validation);
    RUN_TEST(test_okey_signs_oc);
    RUN_TEST(test_okey_cannot_sign_ic);
    RUN_TEST(test_rkey_signs_ic);
    RUN_TEST(test_rkey_cannot_sign_oc);
    RUN_TEST(test_proposal_requires_evidence);

    printf("\n[HMAC Integrity]\n");
    RUN_TEST(test_hmac_detects_tamper);
    RUN_TEST(test_hmac_detects_header_tamper);
    RUN_TEST(test_observation_tier_honesty);
    RUN_TEST(test_observation_wrapper_unchanged_green);
    RUN_TEST(test_wrong_key_fails_verify);

    printf("\n[Channel-Type Consistency]\n");
    RUN_TEST(test_observation_on_ic_rejected);
    RUN_TEST(test_proposal_on_oc_rejected);
    RUN_TEST(test_heartbeat_on_ic_rejected);
    RUN_TEST(test_teardown_on_both_channels);

    printf("\n[Round-Trip Serialization]\n");
    RUN_TEST(test_observation_round_trip);
    RUN_TEST(test_proposal_round_trip);
    RUN_TEST(test_heartbeat_round_trip);
    RUN_TEST(test_approval_round_trip);
    RUN_TEST(test_intent_advertise_round_trip);
    RUN_TEST(test_intent_withdraw_round_trip);
    RUN_TEST(test_hello_round_trip);

    printf("\n[Key Management]\n");
    RUN_TEST(test_key_generate_and_destroy);
    RUN_TEST(test_key_save_and_load);
    RUN_TEST(test_key_load_rejects_insecure_mode);
    RUN_TEST(test_key_load_rejects_symlink);
    RUN_TEST(test_key_load_rejects_truncated);

    printf("\n[Edge Cases]\n");
    RUN_TEST(test_null_pointers);
    RUN_TEST(test_buffer_too_small);
    RUN_TEST(test_reserved_nonzero_rejected);

    printf("\n[Embedded-Length Bounds]\n");
    RUN_TEST(test_parse_obs_truncated_claim);
    RUN_TEST(test_parse_obs_oversized_length);
    RUN_TEST(test_parse_obs_zero_length_data);
    RUN_TEST(test_parse_obs_exact_boundary);
    RUN_TEST(test_parse_obs_trailer_allowed);
    RUN_TEST(test_parse_proposal_refs_overrun);
    RUN_TEST(test_parse_proposal_count_over_max);
    RUN_TEST(test_parse_proposal_zero_refs);

    printf("\n[Teardown Messages]\n");
    RUN_TEST(test_teardown_on_oc);
    RUN_TEST(test_teardown_on_ic);
    RUN_TEST(test_teardown_null_reason);

    printf("\n[TLV Extensions]\n");
    RUN_TEST(test_tlv_round_trip);
    RUN_TEST(test_tlv_chain);
    RUN_TEST(test_tlv_buffer_overflow_protection);

    printf("\n[Key-File Ownership Gate]\n");
    RUN_TEST(test_key_owner_check_predicate);
    RUN_TEST(test_key_load_ownership_integration);


    printf("\n[Durable Symlink-Safe File Write]\n");
    RUN_TEST(test_wfd_writes_exact_bytes_and_mode);
    RUN_TEST(test_wfd_symlink_at_target_not_followed);
    RUN_TEST(test_wfd_symlink_at_temp_path_not_followed);
    RUN_TEST(test_wfd_stale_temp_does_not_wedge_writes);

    printf("\n[Key Save / Load Symmetry]\n");
    RUN_TEST(test_key_save_roundtrip_is_0600_and_intact);
    RUN_TEST(test_key_save_does_not_follow_symlink);
    RUN_TEST(test_key_save_tightens_mode_on_existing_file);

    printf("\n[Key Generation Entropy]\n");
    RUN_TEST(test_key_generate_fills_full_length);
    RUN_TEST(test_key_generate_two_keys_differ);
    RUN_TEST(test_key_generate_rejects_null);
    RUN_TEST(test_key_generate_distinct_across_key_types);
    printf("\n================================================================\n");
    printf("  Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (%d FAILED)", tests_failed);
    printf("\n================================================================\n\n");

    return (tests_failed > 0) ? 1 : 0;
}
