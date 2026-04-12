/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Session key derivation tests
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "virp_session.h"
#include "virp_context.h"
#include "virp_handshake.h"
#include "virp_transcript.h"
#include "virp_crypto.h"
#include "virp.h"

static const uint8_t test_master_key[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
};

/* Helper: build a valid SESSION_HELLO */
static virp_session_hello_t make_hello(void)
{
    virp_session_hello_t h;
    memset(&h, 0, sizeof(h));
    h.msg_type = VIRP_MSG_SESSION_HELLO;
    memcpy(h.client_id, "test-client", 11);
    h.versions[0] = 2; h.versions[1] = 1; h.version_count = 2;
    h.algorithms[0] = VIRP_ALG_HMAC_SHA256; h.algorithm_count = 1;
    memset(h.client_nonce, 0xAB, 8);
    return h;
}

/* Helper: complete full handshake through BOUND + derive → ACTIVE */
static void do_full_handshake(virp_context_t *ctx)
{
    virp_session_hello_t hello = make_hello();
    virp_session_hello_ack_t ack;
    assert(virp_handle_hello(ctx, &hello, &ack) == VIRP_OK);

    virp_session_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    bind.msg_type = VIRP_MSG_SESSION_BIND;
    memcpy(bind.session_id,   ack.session_id,   16);
    memcpy(bind.client_nonce, ack.client_nonce,  8);
    memcpy(bind.server_nonce, ack.server_nonce,  8);
    assert(virp_handle_session_bind(ctx, &bind) == VIRP_OK);
    assert(virp_session_state(ctx) == VIRP_SESSION_BOUND);

    assert(virp_session_derive_key(ctx, test_master_key) == VIRP_OK);
    assert(virp_session_state(ctx) == VIRP_SESSION_ACTIVE);
}

static void test_key_derived_and_valid(void)
{
    printf("  test_key_derived_and_valid... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");
    do_full_handshake(ctx);

    /* session key must be non-zero and marked valid */
    assert(ctx->session.session_key_valid == 1);

    uint8_t zeros[32];
    memset(zeros, 0, 32);
    assert(memcmp(ctx->session.session_key, zeros, 32) != 0);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_key_zeroed_on_reset(void)
{
    printf("  test_key_zeroed_on_reset... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");
    do_full_handshake(ctx);

    /* save key for comparison */
    uint8_t saved_key[32];
    memcpy(saved_key, ctx->session.session_key, 32);

    /* reset clears key */
    virp_session_reset(ctx);
    assert(ctx->session.session_key_valid == 0);

    uint8_t zeros[32];
    memset(zeros, 0, 32);
    assert(memcmp(ctx->session.session_key, zeros, 32) == 0);

    /* and it was non-zero before */
    assert(memcmp(saved_key, zeros, 32) != 0);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_keys_unique_per_session(void)
{
    printf("  test_keys_unique_per_session... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);

    /* Session 1 */
    virp_session_init(ctx, "onode-test");
    do_full_handshake(ctx);
    uint8_t key1[32];
    memcpy(key1, ctx->session.session_key, 32);

    /* Close and restart */
    virp_handle_session_close(ctx);
    assert(virp_session_state(ctx) == VIRP_SESSION_DISCONNECTED);

    /* Session 2 — different nonces → different transcript → different key */
    do_full_handshake(ctx);
    uint8_t key2[32];
    memcpy(key2, ctx->session.session_key, 32);

    assert(memcmp(key1, key2, 32) != 0);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_sign_without_derivation_fails(void)
{
    printf("  test_sign_without_derivation_fails... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    /* complete handshake but do NOT derive key — state is BOUND, not ACTIVE */
    virp_session_hello_t hello = make_hello();
    virp_session_hello_ack_t ack;
    assert(virp_handle_hello(ctx, &hello, &ack) == VIRP_OK);

    virp_session_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    bind.msg_type = VIRP_MSG_SESSION_BIND;
    memcpy(bind.session_id,   ack.session_id,   16);
    memcpy(bind.client_nonce, ack.client_nonce,  8);
    memcpy(bind.server_nonce, ack.server_nonce,  8);
    assert(virp_handle_session_bind(ctx, &bind) == VIRP_OK);
    assert(virp_session_state(ctx) == VIRP_SESSION_BOUND);

    /* attempt to sign — should fail because not ACTIVE */
    uint8_t payload[] = "test-payload";
    virp_obs_header_v2_t hdr;
    uint8_t sig[32];
    virp_error_t err = virp_sign_observation_v2(
        ctx,
        0x01, 0x02, VIRP_TIER_GREEN, 1,
        "show ip route",
        payload, sizeof(payload) - 1,
        &hdr, sig);
    assert(err == VIRP_ERR_SESSION_INVALID);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_derive_requires_bound_state(void)
{
    printf("  test_derive_requires_bound_state... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    /* DISCONNECTED — derive must fail */
    virp_error_t err = virp_session_derive_key(ctx, test_master_key);
    assert(err == VIRP_ERR_SESSION_INVALID);

    /* NEGOTIATED — derive must fail */
    virp_session_hello_t hello = make_hello();
    virp_session_hello_ack_t ack;
    assert(virp_handle_hello(ctx, &hello, &ack) == VIRP_OK);
    assert(virp_session_state(ctx) == VIRP_SESSION_NEGOTIATED);
    err = virp_session_derive_key(ctx, test_master_key);
    assert(err == VIRP_ERR_SESSION_INVALID);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_hkdf_deterministic(void)
{
    printf("  test_hkdf_deterministic... ");

    uint8_t ikm[32], salt[32], info[8];
    memset(ikm, 0xAA, 32);
    memset(salt, 0xBB, 32);
    memset(info, 0xCC, 8);

    uint8_t okm1[32], okm2[32];
    assert(virp_hkdf_sha256(ikm, 32, salt, 32, info, 8, okm1) == VIRP_OK);
    assert(virp_hkdf_sha256(ikm, 32, salt, 32, info, 8, okm2) == VIRP_OK);
    assert(memcmp(okm1, okm2, 32) == 0);

    /* different salt → different output */
    uint8_t salt2[32];
    memset(salt2, 0xDD, 32);
    uint8_t okm3[32];
    assert(virp_hkdf_sha256(ikm, 32, salt2, 32, info, 8, okm3) == VIRP_OK);
    assert(memcmp(okm1, okm3, 32) != 0);
    printf("PASS\n");
}

int main(void)
{
    printf("=== VIRP Session Key Derivation Tests ===\n");
    test_key_derived_and_valid();
    test_key_zeroed_on_reset();
    test_keys_unique_per_session();
    test_sign_without_derivation_fails();
    test_derive_requires_bound_state();
    test_hkdf_deterministic();
    printf("=== All 6 session key derivation tests passed ===\n");
    return 0;
}
