/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Test suite — every structural guarantee must be proven here
 *
 * If a test doesn't exist for a security property, that property
 * is not guaranteed. Write the test first.
 */

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

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

/* =========================================================================
 * 11. Edge cases and NULL safety
 * ========================================================================= */

TEST(test_null_pointers)
{
    ASSERT_EQ(virp_header_init(NULL, 0, 0, 0, 0, 0), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_header_serialize(NULL, NULL, 0), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_header_deserialize(NULL, NULL, 0), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_header_validate(NULL), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_sign(NULL, 0, NULL), VIRP_ERR_NULL_PTR);
    ASSERT_EQ(virp_verify(NULL, 0, NULL), VIRP_ERR_NULL_PTR);
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
 * Main — run all tests
 * ========================================================================= */

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

    printf("\n[Edge Cases]\n");
    RUN_TEST(test_null_pointers);
    RUN_TEST(test_buffer_too_small);
    RUN_TEST(test_reserved_nonzero_rejected);

    printf("\n[Teardown Messages]\n");
    RUN_TEST(test_teardown_on_oc);
    RUN_TEST(test_teardown_on_ic);
    RUN_TEST(test_teardown_null_reason);

    printf("\n[TLV Extensions]\n");
    RUN_TEST(test_tlv_round_trip);
    RUN_TEST(test_tlv_chain);
    RUN_TEST(test_tlv_buffer_overflow_protection);

    printf("\n================================================================\n");
    printf("  Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (%d FAILED)", tests_failed);
    printf("\n================================================================\n\n");

    return (tests_failed > 0) ? 1 : 0;
}
