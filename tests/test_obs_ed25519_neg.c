/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — v3 verifier malformed-framing negative battery (review P1-2)
 *
 * The public-key verifier is the surface a hostile party probes first,
 * with exactly the inputs this file constructs: truncations, lying
 * payload_len, stripped trailers, wrong dispatch bytes. Before this
 * battery existed, every test fed the verifier consistently-framed
 * input, so "all-tests green" and "asan green" said nothing about the
 * reject paths. Every assertion here checks the EXACT error code — a
 * rejection for the wrong reason fails the test.
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_obskey.h"

static int tests_run = 0, tests_passed = 0;

#define RUN_TEST(fn) do { \
        tests_run++; \
        printf("  %-58s", #fn); \
        fflush(stdout); \
        fn(); \
        tests_passed++; \
        printf("[PASS]\n"); \
    } while (0)

/*
 * A verifier-valid v3 blob needs NO session: the public-key verifier
 * ignores the HMAC trailer by design, so a crafted header + payload +
 * garbage HMAC + genuine Ed25519 signature is indistinguishable from
 * daemon output to it. PAYLOAD_LEN is 100 so that stripping the
 * 64-byte signature trailer still leaves a buffer above the v3
 * minimum size — forcing that case through the framing check rather
 * than the min-size check.
 */
#define PAYLOAD_LEN 100
static uint8_t  blob[VIRP_OBS_V2_HEADER_SIZE + PAYLOAD_LEN +
                     VIRP_OBS_V2_SIG_SIZE + VIRP_OBS_ED25519_SIG_SIZE];
static size_t   blob_len;
static uint8_t  pub[VIRP_OBSKEY_PK_SIZE];
static uint8_t  sec[VIRP_OBSKEY_SK_SIZE];

static void build_reference_blob(void)
{
    assert(sodium_init() >= 0);
    assert(crypto_sign_keypair(pub, sec) == 0);

    virp_obs_header_v2_t h;
    memset(&h, 0, sizeof(h));
    h.version      = VIRP_VERSION_3;
    h.channel      = VIRP_CHANNEL_OBS;
    h.tier         = VIRP_TIER_GREEN;
    h.node_id      = 0x0A0000D3ULL;
    h.device_id    = 0x1122334455667788ULL;
    h.seq_num      = 11;
    h.timestamp_ns = 1754582400ULL * 1000000000ULL;
    memset(h.session_id, 0x21, 16);
    memset(h.command_hash, 0x37, 32);
    h.payload_len  = PAYLOAD_LEN;

    assert(virp_obs_header_v2_serialize(&h, blob, sizeof(blob)) == VIRP_OK);
    memset(blob + VIRP_OBS_V2_HEADER_SIZE, 0x5A, PAYLOAD_LEN);
    size_t signed_len = VIRP_OBS_V2_HEADER_SIZE + PAYLOAD_LEN;
    memset(blob + signed_len, 0x44, VIRP_OBS_V2_SIG_SIZE);  /* HMAC: garbage */
    assert(crypto_sign_detached(blob + signed_len + VIRP_OBS_V2_SIG_SIZE,
                                NULL, blob, signed_len, sec) == 0);
    blob_len = signed_len + VIRP_OBS_V2_SIG_SIZE + VIRP_OBS_ED25519_SIG_SIZE;

    assert(virp_verify_observation_ed25519(pub, blob, blob_len,
                                           NULL, NULL, NULL) == VIRP_OK);
}

static virp_error_t verify_copy(const uint8_t *m, size_t len)
{
    return virp_verify_observation_ed25519(pub, m, len, NULL, NULL, NULL);
}

static void test_null_and_tiny_inputs(void)
{
    assert(virp_verify_observation_ed25519(NULL, blob, blob_len,
                                           NULL, NULL, NULL)
           == VIRP_ERR_NULL_PTR);
    assert(virp_verify_observation_ed25519(pub, NULL, blob_len,
                                           NULL, NULL, NULL)
           == VIRP_ERR_NULL_PTR);

    uint8_t one = 0x03;
    assert(verify_copy(blob, 0) == VIRP_ERR_INVALID_LENGTH);   /* zero-length */
    assert(verify_copy(&one, 1) == VIRP_ERR_INVALID_LENGTH);   /* single byte */

    /* Truncated below the header: every length under the v3 minimum
     * must reject on size alone, never read fields. */
    for (size_t len = 2; len < VIRP_OBS_V3_MIN_SIZE; len++)
        assert(verify_copy(blob, len) == VIRP_ERR_INVALID_LENGTH);
}

static void test_truncations_of_a_valid_blob(void)
{
    /* Every truncation from min-size up to full-1: mid-payload,
     * mid-HMAC, mid-signature — all must reject as framing
     * (payload_len no longer accounts for every byte). */
    for (size_t len = VIRP_OBS_V3_MIN_SIZE; len < blob_len; len++)
        assert(verify_copy(blob, len) == VIRP_ERR_INVALID_LENGTH);

    /* The named cases from the review, explicitly: */
    assert(verify_copy(blob, blob_len - PAYLOAD_LEN / 2)       /* mid-payload */
           == VIRP_ERR_INVALID_LENGTH);
    assert(verify_copy(blob, blob_len - 32)                    /* mid-signature */
           == VIRP_ERR_INVALID_LENGTH);
    assert(verify_copy(blob, blob_len - VIRP_OBS_ED25519_SIG_SIZE)
           == VIRP_ERR_INVALID_LENGTH);          /* signature trailer stripped */

    /* Oversize: one byte past the true length (surplus bytes are how
     * splices hide), and past the absolute message cap. */
    static uint8_t big[VIRP_MAX_MESSAGE_SIZE + 1];
    memcpy(big, blob, blob_len);
    assert(verify_copy(big, blob_len + 1) == VIRP_ERR_INVALID_LENGTH);
    assert(verify_copy(big, sizeof(big)) == VIRP_ERR_INVALID_LENGTH);
}

static void test_lying_payload_len(void)
{
    uint8_t m[sizeof(blob)];

    /* payload_len larger than the buffer holds (+1000). Field is
     * big-endian at offset 84..87. */
    memcpy(m, blob, blob_len);
    uint32_t lie = PAYLOAD_LEN + 1000;
    m[84] = (uint8_t)(lie >> 24); m[85] = (uint8_t)(lie >> 16);
    m[86] = (uint8_t)(lie >> 8);  m[87] = (uint8_t)lie;
    assert(verify_copy(m, blob_len) == VIRP_ERR_INVALID_LENGTH);

    /* payload_len smaller than actual (-1): the surplus byte is
     * unattributed — refused. */
    memcpy(m, blob, blob_len);
    lie = PAYLOAD_LEN - 1;
    m[84] = (uint8_t)(lie >> 24); m[85] = (uint8_t)(lie >> 16);
    m[86] = (uint8_t)(lie >> 8);  m[87] = (uint8_t)lie;
    assert(verify_copy(m, blob_len) == VIRP_ERR_INVALID_LENGTH);

    /* payload_len at and near UINT32_MAX: the framing equality must
     * hold in size_t with no wraparound acceptance. */
    const uint32_t evil[] = { UINT32_MAX, UINT32_MAX - 1,
                              UINT32_MAX - 95, UINT32_MAX - 96,
                              (uint32_t)VIRP_MAX_MESSAGE_SIZE };
    for (size_t i = 0; i < sizeof(evil) / sizeof(evil[0]); i++) {
        memcpy(m, blob, blob_len);
        m[84] = (uint8_t)(evil[i] >> 24); m[85] = (uint8_t)(evil[i] >> 16);
        m[86] = (uint8_t)(evil[i] >> 8);  m[87] = (uint8_t)evil[i];
        assert(verify_copy(m, blob_len) == VIRP_ERR_INVALID_LENGTH);
    }
}

static void test_wrong_dispatch_bytes(void)
{
    uint8_t m[sizeof(blob)];

    /* Wrong version byte: 1 (v1), 2 (v2), 4 (future), 0xFF. */
    const uint8_t bad_ver[] = { 1, 2, 4, 0xFF, 0 };
    for (size_t i = 0; i < sizeof(bad_ver); i++) {
        memcpy(m, blob, blob_len);
        m[0] = bad_ver[i];
        assert(verify_copy(m, blob_len) == VIRP_ERR_VERSION_MISMATCH);
    }

    /* Wrong channel. */
    memcpy(m, blob, blob_len);
    m[1] = VIRP_CHANNEL_IC;
    assert(verify_copy(m, blob_len) == VIRP_ERR_INVALID_CHANNEL);
    m[1] = 0xEE;
    assert(verify_copy(m, blob_len) == VIRP_ERR_INVALID_CHANNEL);

    /* Control: untouched blob still verifies after the battery. */
    assert(verify_copy(blob, blob_len) == VIRP_OK);
}

int main(void)
{
    printf("=== VIRP v3 Verifier Malformed-Framing Negative Battery ===\n");
    build_reference_blob();

    RUN_TEST(test_null_and_tiny_inputs);
    RUN_TEST(test_truncations_of_a_valid_blob);
    RUN_TEST(test_lying_payload_len);
    RUN_TEST(test_wrong_dispatch_bytes);

    printf("=== All %d negative-battery tests passed (%d/%d) — every\n"
           "    reject path executed with the EXACT expected error code ===\n",
           tests_run, tests_passed, tests_run);
    return 0;
}
