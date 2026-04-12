/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Session handshake negative-path tests
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "virp_session.h"
#include "virp_context.h"
#include "virp_handshake.h"
#include "virp_transcript.h"
#include "virp.h"

/* Dummy master key for tests */
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
    /* deterministic nonce for tests */
    memset(h.client_nonce, 0xAB, 8);
    return h;
}

/* Helper: complete a valid handshake, return the ack */
static virp_session_hello_ack_t do_hello(virp_context_t *ctx)
{
    virp_session_hello_t hello = make_hello();
    virp_session_hello_ack_t ack;
    virp_error_t err = virp_handle_hello(ctx, &hello, &ack);
    assert(err == VIRP_OK);
    return ack;
}

static void test_bind_before_hello(void)
{
    printf("  test_bind_before_hello... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    virp_session_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    bind.msg_type = VIRP_MSG_SESSION_BIND;

    virp_error_t err = virp_handle_session_bind(ctx, &bind);
    assert(err == VIRP_ERR_SESSION_INVALID);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_double_hello_while_active(void)
{
    printf("  test_double_hello_while_active... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    /* complete full handshake */
    virp_session_hello_ack_t ack = do_hello(ctx);
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

    /* try a second HELLO while active */
    virp_session_hello_t hello2 = make_hello();
    virp_session_hello_ack_t ack2;
    virp_error_t err = virp_handle_hello(ctx, &hello2, &ack2);
    assert(err == VIRP_ERR_SESSION_INVALID);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_wrong_nonce_rejected(void)
{
    printf("  test_wrong_nonce_rejected... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    virp_session_hello_ack_t ack = do_hello(ctx);

    virp_session_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    bind.msg_type = VIRP_MSG_SESSION_BIND;
    memcpy(bind.session_id,   ack.session_id,  16);
    memcpy(bind.client_nonce, ack.client_nonce, 8);
    /* deliberately wrong server nonce */
    memset(bind.server_nonce, 0xFF, 8);

    virp_error_t err = virp_handle_session_bind(ctx, &bind);
    assert(err == VIRP_ERR_CONTEXT_MISMATCH);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_wrong_session_id_rejected(void)
{
    printf("  test_wrong_session_id_rejected... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    virp_session_hello_ack_t ack = do_hello(ctx);

    virp_session_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    bind.msg_type = VIRP_MSG_SESSION_BIND;
    /* wrong session_id */
    memset(bind.session_id, 0xDE, 16);
    memcpy(bind.client_nonce, ack.client_nonce, 8);
    memcpy(bind.server_nonce, ack.server_nonce, 8);

    virp_error_t err = virp_handle_session_bind(ctx, &bind);
    assert(err == VIRP_ERR_CONTEXT_MISMATCH);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_sign_before_active_rejected(void)
{
    printf("  test_sign_before_active_rejected... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    /* session is DISCONNECTED — require_active must fail */
    virp_error_t err = virp_session_require_active(ctx);
    assert(err == VIRP_ERR_SESSION_INVALID);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_close_from_non_active(void)
{
    printf("  test_close_from_non_active... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    /* close from DISCONNECTED — should not crash, should leave DISCONNECTED */
    virp_handle_session_close(ctx);
    assert(virp_session_state(ctx) == VIRP_SESSION_DISCONNECTED);

    /* close from NEGOTIATED */
    virp_session_hello_ack_t ack = do_hello(ctx);
    (void)ack;
    assert(virp_session_state(ctx) == VIRP_SESSION_NEGOTIATED);
    virp_handle_session_close(ctx);
    assert(virp_session_state(ctx) == VIRP_SESSION_DISCONNECTED);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_reconnect_after_close(void)
{
    printf("  test_reconnect_after_close... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);
    virp_session_init(ctx, "onode-test");

    /* complete handshake */
    virp_session_hello_ack_t ack = do_hello(ctx);
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

    /* close */
    virp_handle_session_close(ctx);
    assert(virp_session_state(ctx) == VIRP_SESSION_DISCONNECTED);

    /* reconnect — new HELLO must succeed */
    virp_session_hello_t hello2 = make_hello();
    virp_session_hello_ack_t ack2;
    virp_error_t err = virp_handle_hello(ctx, &hello2, &ack2);
    assert(err == VIRP_OK);
    assert(virp_session_state(ctx) == VIRP_SESSION_NEGOTIATED);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_oversized_server_id_truncated(void)
{
    printf("  test_oversized_server_id_truncated... ");
    virp_context_t *ctx = virp_context_new();
    assert(ctx != NULL);

    /* 80-char string > 64-byte server_id buffer */
    char long_id[80];
    memset(long_id, 'A', sizeof(long_id) - 1);
    long_id[sizeof(long_id) - 1] = '\0';

    virp_error_t err = virp_session_init(ctx, long_id);
    assert(err == VIRP_ERR_INVALID_LENGTH);

    /* session should still be usable — server_id was truncated, not rejected */
    assert(virp_session_state(ctx) == VIRP_SESSION_DISCONNECTED);
    assert(strlen(ctx->session.server_id) == 63);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

int main(void)
{
    printf("=== VIRP Session Negative-Path Tests ===\n");
    test_bind_before_hello();
    test_double_hello_while_active();
    test_wrong_nonce_rejected();
    test_wrong_session_id_rejected();
    test_sign_before_active_rejected();
    test_close_from_non_active();
    test_reconnect_after_close();
    test_oversized_server_id_truncated();
    printf("=== All 8 session negative-path tests passed ===\n");
    return 0;
}
