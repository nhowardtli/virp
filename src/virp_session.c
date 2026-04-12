/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Session state management implementation
 *
 * In-memory only. Single active session enforced.
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime */

#include "virp_session.h"
#include "virp_context.h"
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>  /* OPENSSL_cleanse */

/*
 * Process-wide context — single backing store. Function bodies in
 * this file now reference ctx->session directly (commit 2). The
 * ctx->session macro alias in virp_context.h still resolves to
 * g_virp_ctx.session and exists only for the small number of
 * call sites in other files that have not been ported yet; commit
 * 3 deletes the global and the alias together.
 */
virp_context_t g_virp_ctx = {0};

virp_error_t virp_session_init(virp_context_t *ctx, const char *server_id)
{
    (void)ctx;
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
    (void)ctx;
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
    (void)ctx;
    return ctx->session.state;
}

virp_error_t virp_session_require_active(virp_context_t *ctx)
{
    (void)ctx;
    if (ctx->session.state != VIRP_SESSION_ACTIVE)
        return VIRP_ERR_SESSION_INVALID;
    return VIRP_OK;
}

virp_error_t virp_session_check_timeouts(virp_context_t *ctx)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    if (ctx->session.state == VIRP_SESSION_NEGOTIATED) {
        if (now - ctx->session.hello_ack_sent_at_ns >
                VIRP_SESSION_BIND_TIMEOUT_NS) {
            virp_session_reset(&g_virp_ctx);
            return VIRP_ERR_SESSION_INVALID;
        }
    }

    if (ctx->session.state == VIRP_SESSION_ACTIVE) {
        if (ctx->session.last_activity_ns > 0 &&
            now - ctx->session.last_activity_ns >
                VIRP_SESSION_IDLE_TIMEOUT_NS) {
            virp_session_reset(&g_virp_ctx);
            return VIRP_ERR_SESSION_INVALID;
        }
    }

    return VIRP_OK;
}

void virp_session_on_disconnect(virp_context_t *ctx)
{
    (void)ctx;
    virp_session_reset(&g_virp_ctx);
    /* state is now DISCONNECTED, generation is incremented */
}

void virp_session_destroy(virp_context_t *ctx)
{
    (void)ctx;
    OPENSSL_cleanse(&ctx->session, sizeof(ctx->session));
}
