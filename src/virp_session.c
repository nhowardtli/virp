/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Session state management implementation
 *
 * In-memory only. Each virp_context_t owns one session.
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime */

#include "virp_session.h"
#include "virp_context.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>  /* OPENSSL_cleanse */

virp_context_t *virp_context_new(void)
{
    virp_context_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx)
        return NULL;
    ctx->session.state = VIRP_SESSION_DISCONNECTED;
    return ctx;
}

void virp_context_destroy(virp_context_t *ctx)
{
    if (!ctx)
        return;
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    free(ctx);
}

virp_error_t virp_session_init(virp_context_t *ctx, const char *server_id)
{
    if (!ctx)
        return VIRP_ERR_NULL_PTR;
    memset(&ctx->session, 0, sizeof(ctx->session));
    ctx->session.state = VIRP_SESSION_DISCONNECTED;
    if (server_id) {
        size_t len = strlen(server_id);
        if (len >= sizeof(ctx->session.server_id)) {
            len = sizeof(ctx->session.server_id) - 1;
            memcpy(ctx->session.server_id, server_id, len);
            ctx->session.server_id[len] = '\0';
            return VIRP_ERR_INVALID_LENGTH;
        }
        memcpy(ctx->session.server_id, server_id, len);
    }
    return VIRP_OK;
}

void virp_session_reset(virp_context_t *ctx)
{
    if (!ctx)
        return;
    char server_id[64];
    memcpy(server_id, ctx->session.server_id, sizeof(server_id));
    uint64_t gen = ctx->session.generation + 1;
    /* Wipe session key before clearing struct */
    OPENSSL_cleanse(ctx->session.session_key,
                    sizeof(ctx->session.session_key));
    ctx->session.session_key_valid = 0;
    memset(&ctx->session, 0, sizeof(ctx->session));
    ctx->session.generation = gen;
    ctx->session.state = VIRP_SESSION_DISCONNECTED;
    memcpy(ctx->session.server_id, server_id, sizeof(server_id));
}

virp_session_state_t virp_session_state(virp_context_t *ctx)
{
    return ctx->session.state;
}

virp_error_t virp_session_require_active(virp_context_t *ctx)
{
    if (ctx->session.state != VIRP_SESSION_ACTIVE)
        return VIRP_ERR_SESSION_INVALID;
    return VIRP_OK;
}

virp_error_t virp_session_check_timeouts(virp_context_t *ctx)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    if (ctx->session.state == VIRP_SESSION_NEGOTIATED) {
        if (now - ctx->session.hello_ack_sent_at_ns >
                VIRP_SESSION_BIND_TIMEOUT_NS) {
            virp_session_reset(ctx);
            return VIRP_ERR_SESSION_INVALID;
        }
    }

    if (ctx->session.state == VIRP_SESSION_ACTIVE) {
        if (ctx->session.last_activity_ns > 0 &&
            now - ctx->session.last_activity_ns >
                VIRP_SESSION_IDLE_TIMEOUT_NS) {
            virp_session_reset(ctx);
            return VIRP_ERR_SESSION_INVALID;
        }
    }

    return VIRP_OK;
}

void virp_session_on_disconnect(virp_context_t *ctx)
{
    virp_session_reset(ctx);
    /* state is now DISCONNECTED, generation is incremented */
}
