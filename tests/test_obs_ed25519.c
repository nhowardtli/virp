/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — v3 (Ed25519-signed) observation build tests
 *
 * Pins the wire contract of virp_build_observation_ed25519():
 *
 *   1. layout: [header 88, version=3][payload][hmac 32][ed25519 64]
 *   2. the Ed25519 signature verifies over EXACTLY the canonical
 *      bytes (serialized header || payload) — one byte more or less
 *      of coverage fails
 *   3. every covered byte is really covered: flipping any byte of
 *      header or payload breaks verification
 *   4. the HMAC trailer is PRESENT IN ADDITION to the signature and
 *      carries unchanged v2 semantics (HMAC-SHA256 of the same bytes
 *      with the session key)
 *   5. session discipline matches v2: no active session, no v3
 *
 * Forge-resistance (public key cannot mint) is proven separately in
 * test_obs_ed25519_forge.c.
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sodium.h>
#include <openssl/hmac.h>

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_session.h"
#include "virp_context.h"
#include "virp_handshake.h"
#include "virp_transcript.h"
#include "virp_obskey.h"

static const uint8_t test_master_key[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
};

#define TEST_NODE_ID    0x0A0000D3ULL
#define TEST_DEVICE_ID  0x1122334455667788ULL

static int tests_run = 0, tests_passed = 0;

#define RUN_TEST(fn) do { \
        tests_run++; \
        printf("  %-58s", #fn); \
        fflush(stdout); \
        fn(); \
        tests_passed++; \
        printf("[PASS]\n"); \
    } while (0)

/* Drive a context through HELLO → BIND → derive → ACTIVE (same
 * harness as test_obs_v2.c). */
static void activate_session(virp_context_t *ctx, uint8_t nonce_byte)
{
    virp_session_hello_t h;
    memset(&h, 0, sizeof(h));
    h.msg_type = VIRP_MSG_SESSION_HELLO;
    memcpy(h.client_id, "obs-v3-test", 11);
    h.versions[0] = 2; h.versions[1] = 1; h.version_count = 2;
    h.algorithms[0] = VIRP_ALG_HMAC_SHA256; h.algorithm_count = 1;
    memset(h.client_nonce, nonce_byte, 8);

    virp_session_hello_ack_t ack;
    assert(virp_handle_hello(ctx, &h, &ack) == VIRP_OK);

    virp_session_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    bind.msg_type = VIRP_MSG_SESSION_BIND;
    memcpy(bind.session_id,   ack.session_id,   16);
    memcpy(bind.client_nonce, ack.client_nonce,  8);
    memcpy(bind.server_nonce, ack.server_nonce,  8);
    assert(virp_handle_session_bind(ctx, &bind) == VIRP_OK);
    assert(virp_session_derive_key(ctx, test_master_key) == VIRP_OK);
    assert(virp_session_state(ctx) == VIRP_SESSION_ACTIVE);
}

static const char    *CMD        = "show ip route 203.0.113.0";
static const uint8_t  PAYLOAD[]  = "S 203.0.113.0/24 [1/0] via 10.0.0.2";
#define PAYLOAD_LEN   (sizeof(PAYLOAD) - 1)

static size_t build_v3(virp_context_t *ctx, const virp_obskey_t *kp,
                       uint64_t seq, uint8_t *buf, size_t buf_len)
{
    size_t out_len = 0;
    assert(virp_build_observation_ed25519(
               ctx, kp, TEST_NODE_ID, TEST_DEVICE_ID, VIRP_TIER_GREEN,
               seq, CMD, NULL, PAYLOAD, PAYLOAD_LEN,
               buf, buf_len, &out_len) == VIRP_OK);
    return out_len;
}

static void test_wire_layout(void)
{
    virp_context_t *ctx = virp_context_new();
    assert(ctx && virp_session_init(ctx, "obs-v3-test") == VIRP_OK);
    activate_session(ctx, 0x31);

    virp_obskey_t kp;
    assert(virp_obskey_generate(&kp) == VIRP_OK);

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = build_v3(ctx, &kp, 1, buf, sizeof(buf));

    assert(len == VIRP_OBS_V2_HEADER_SIZE + PAYLOAD_LEN +
                  VIRP_OBS_V2_SIG_SIZE + VIRP_OBS_ED25519_SIG_SIZE);
    assert(buf[0] == VIRP_VERSION_3);      /* the dispatch byte */

    /* Header parses with the v2 deserializer (identical layout). */
    virp_obs_header_v2_t hdr;
    assert(virp_obs_header_v2_deserialize(&hdr, buf, len) == VIRP_OK);
    assert(hdr.version == VIRP_VERSION_3);
    assert(hdr.device_id == TEST_DEVICE_ID);
    assert(hdr.payload_len == PAYLOAD_LEN);
    assert(memcmp(buf + VIRP_OBS_V2_HEADER_SIZE, PAYLOAD,
                  PAYLOAD_LEN) == 0);

    virp_obskey_destroy(&kp);
    virp_context_destroy(ctx);
}

static void test_signature_covers_exactly_canonical_bytes(void)
{
    virp_context_t *ctx = virp_context_new();
    assert(ctx && virp_session_init(ctx, "obs-v3-test") == VIRP_OK);
    activate_session(ctx, 0x32);

    virp_obskey_t kp;
    assert(virp_obskey_generate(&kp) == VIRP_OK);

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    (void)build_v3(ctx, &kp, 2, buf, sizeof(buf));

    size_t signed_len = VIRP_OBS_V2_HEADER_SIZE + PAYLOAD_LEN;
    const uint8_t *sig = buf + signed_len + VIRP_OBS_V2_SIG_SIZE;

    /* Verifies over exactly header || payload... */
    assert(crypto_sign_verify_detached(sig, buf, signed_len,
                                       kp.public_key) == 0);
    /* ...and over nothing else: one byte narrower or wider fails, and
     * including the HMAC trailer in the coverage fails. */
    assert(crypto_sign_verify_detached(sig, buf, signed_len - 1,
                                       kp.public_key) != 0);
    assert(crypto_sign_verify_detached(sig, buf, signed_len + 1,
                                       kp.public_key) != 0);
    assert(crypto_sign_verify_detached(sig, buf,
                                       signed_len + VIRP_OBS_V2_SIG_SIZE,
                                       kp.public_key) != 0);

    virp_obskey_destroy(&kp);
    virp_context_destroy(ctx);
}

static void test_every_covered_byte_is_covered(void)
{
    virp_context_t *ctx = virp_context_new();
    assert(ctx && virp_session_init(ctx, "obs-v3-test") == VIRP_OK);
    activate_session(ctx, 0x33);

    virp_obskey_t kp;
    assert(virp_obskey_generate(&kp) == VIRP_OK);

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = build_v3(ctx, &kp, 3, buf, sizeof(buf));
    size_t signed_len = VIRP_OBS_V2_HEADER_SIZE + PAYLOAD_LEN;
    const uint8_t *sig = buf + signed_len + VIRP_OBS_V2_SIG_SIZE;
    (void)len;

    /* Flip EVERY byte of header and payload in turn — version byte,
     * tier, device, command hash, payload content, all of it must be
     * bound by the signature. */
    for (size_t i = 0; i < signed_len; i++) {
        buf[i] ^= 0xFF;
        assert(crypto_sign_verify_detached(sig, buf, signed_len,
                                           kp.public_key) != 0);
        buf[i] ^= 0xFF;
    }
    /* Intact again after the sweep. */
    assert(crypto_sign_verify_detached(sig, buf, signed_len,
                                       kp.public_key) == 0);

    virp_obskey_destroy(&kp);
    virp_context_destroy(ctx);
}

static void test_hmac_present_in_addition_with_v2_semantics(void)
{
    virp_context_t *ctx = virp_context_new();
    assert(ctx && virp_session_init(ctx, "obs-v3-test") == VIRP_OK);
    activate_session(ctx, 0x34);

    virp_obskey_t kp;
    assert(virp_obskey_generate(&kp) == VIRP_OK);

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = build_v3(ctx, &kp, 4, buf, sizeof(buf));
    size_t signed_len = VIRP_OBS_V2_HEADER_SIZE + PAYLOAD_LEN;
    (void)len;

    /* The HMAC trailer is exactly what the v2 path would have emitted
     * for these bytes: HMAC-SHA256(session_key, header || payload).
     * Present IN ADDITION TO the Ed25519 trailer, not instead of. */
    uint8_t expect[VIRP_OBS_V2_SIG_SIZE];
    unsigned int elen = sizeof(expect);
    assert(HMAC(EVP_sha256(), ctx->session.session_key, 32,
                buf, signed_len, expect, &elen) != NULL);
    assert(memcmp(buf + signed_len, expect, VIRP_OBS_V2_SIG_SIZE) == 0);

    virp_obskey_destroy(&kp);
    virp_context_destroy(ctx);
}

/* Re-sign a (possibly mutated) v3 buffer with the real secret key —
 * the hostile-attester model: a signing-key holder emits a header the
 * format forbids. The signature is genuinely VALID over the mutated
 * bytes, so any rejection below is the shared structural gate firing,
 * not the signature check. Remove virp_obs_header_sanity() from the
 * verifier and every one of these accepts. */
static void resign_v3(uint8_t *buf, size_t len, const virp_obskey_t *kp)
{
    size_t signed_len = len - VIRP_OBS_V2_SIG_SIZE -
                        VIRP_OBS_ED25519_SIG_SIZE;
    assert(crypto_sign_detached(buf + signed_len + VIRP_OBS_V2_SIG_SIZE,
                                NULL, buf, signed_len,
                                kp->secret_key) == 0);
    /* Confirm the mutated blob really is validly signed. */
    assert(crypto_sign_verify_detached(
               buf + signed_len + VIRP_OBS_V2_SIG_SIZE,
               buf, signed_len, kp->public_key) == 0);
}

static void test_signed_but_malformed_header_rejected(void)
{
    virp_context_t *ctx = virp_context_new();
    assert(ctx && virp_session_init(ctx, "obs-v3-test") == VIRP_OK);
    activate_session(ctx, 0x36);

    virp_obskey_t kp;
    assert(virp_obskey_generate(&kp) == VIRP_OK);

    uint8_t ref[VIRP_MAX_MESSAGE_SIZE];
    size_t len = build_v3(ctx, &kp, 6, ref, sizeof(ref));
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];

    /* Nonzero reserved byte (offset 3), validly signed. */
    memcpy(buf, ref, len);
    buf[3] = 0x01;
    resign_v3(buf, len, &kp);
    assert(virp_verify_observation_ed25519(kp.public_key, buf, len,
                                           NULL, NULL, NULL)
           == VIRP_ERR_RESERVED_NONZERO);

    /* BLACK tier — buildable through the API, so exercise that path
     * end to end rather than by mutation. */
    size_t blen = 0;
    assert(virp_build_observation_ed25519(
               ctx, &kp, TEST_NODE_ID, TEST_DEVICE_ID, VIRP_TIER_BLACK,
               6, CMD, NULL, PAYLOAD, PAYLOAD_LEN,
               buf, sizeof(buf), &blen) == VIRP_OK);
    assert(virp_verify_observation_ed25519(kp.public_key, buf, blen,
                                           NULL, NULL, NULL)
           == VIRP_ERR_TIER_VIOLATION);

    /* Out-of-range tier (offset 2), validly signed. */
    memcpy(buf, ref, len);
    buf[2] = 0x7F;
    resign_v3(buf, len, &kp);
    assert(virp_verify_observation_ed25519(kp.public_key, buf, len,
                                           NULL, NULL, NULL)
           == VIRP_ERR_INVALID_TIER);

    /* Wrong version byte (a signed v2-labeled blob at the v3 door). */
    memcpy(buf, ref, len);
    buf[0] = VIRP_VERSION_2;
    resign_v3(buf, len, &kp);
    assert(virp_verify_observation_ed25519(kp.public_key, buf, len,
                                           NULL, NULL, NULL)
           == VIRP_ERR_VERSION_MISMATCH);

    /* Wrong channel (offset 1), validly signed. */
    memcpy(buf, ref, len);
    buf[1] = VIRP_CHANNEL_IC;
    resign_v3(buf, len, &kp);
    assert(virp_verify_observation_ed25519(kp.public_key, buf, len,
                                           NULL, NULL, NULL)
           == VIRP_ERR_INVALID_CHANNEL);

    /* payload_len inconsistent with the buffer (off by one, field at
     * offset 84..87), validly signed over the mutated header. */
    memcpy(buf, ref, len);
    buf[87] ^= 0x01;
    resign_v3(buf, len, &kp);
    assert(virp_verify_observation_ed25519(kp.public_key, buf, len,
                                           NULL, NULL, NULL)
           == VIRP_ERR_INVALID_LENGTH);

    /* Control: the untouched reference still verifies — the six
     * rejections above are the gate, not a broken verifier. */
    assert(virp_verify_observation_ed25519(kp.public_key, ref, len,
                                           NULL, NULL, NULL) == VIRP_OK);

    virp_obskey_destroy(&kp);
    virp_context_destroy(ctx);
}

static void test_v3_requires_active_session_and_loaded_key(void)
{
    virp_context_t *ctx = virp_context_new();
    assert(ctx && virp_session_init(ctx, "obs-v3-test") == VIRP_OK);

    virp_obskey_t kp;
    assert(virp_obskey_generate(&kp) == VIRP_OK);

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t out_len = 0;

    /* No session: refused, same discipline as v2. */
    assert(virp_build_observation_ed25519(
               ctx, &kp, TEST_NODE_ID, TEST_DEVICE_ID, VIRP_TIER_GREEN,
               1, CMD, NULL, PAYLOAD, PAYLOAD_LEN,
               buf, sizeof(buf), &out_len) != VIRP_OK);

    /* Unloaded key: refused. */
    activate_session(ctx, 0x35);
    virp_obskey_t dead;
    memset(&dead, 0, sizeof(dead));
    assert(virp_build_observation_ed25519(
               ctx, &dead, TEST_NODE_ID, TEST_DEVICE_ID, VIRP_TIER_GREEN,
               1, CMD, NULL, PAYLOAD, PAYLOAD_LEN,
               buf, sizeof(buf), &out_len) == VIRP_ERR_KEY_NOT_LOADED);

    virp_obskey_destroy(&kp);
    virp_context_destroy(ctx);
}

int main(void)
{
    printf("=== VIRP v3 (Ed25519-signed) Observation Build Tests ===\n");

    RUN_TEST(test_wire_layout);
    RUN_TEST(test_signature_covers_exactly_canonical_bytes);
    RUN_TEST(test_every_covered_byte_is_covered);
    RUN_TEST(test_hmac_present_in_addition_with_v2_semantics);
    RUN_TEST(test_signed_but_malformed_header_rejected);
    RUN_TEST(test_v3_requires_active_session_and_loaded_key);

    printf("=== All %d v3 observation build tests passed (%d/%d) ===\n",
           tests_run, tests_passed, tests_run);
    return 0;
}
