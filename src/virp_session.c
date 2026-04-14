/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Session state management implementation
 *
 * In-memory only. Each virp_context_t owns one session.
 */

#define _POSIX_C_SOURCE 200809L  /* clock_gettime, strnlen */

#include "virp_session.h"
#include "virp_context.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/crypto.h>  /* OPENSSL_cleanse */

/*
 * server_id invariant
 * -------------------
 * virp_session_t::server_id is a fixed-size char[64] buffer that is
 * conceptually two things at once:
 *   (a) a NUL-terminated C string for logging / JSON emission — the
 *       valid length is always strnlen(server_id, 64), with a
 *       guaranteed NUL within the buffer;
 *   (b) a 64-byte fixed blob that is serialized verbatim into
 *       transcript frames and HELLO_ACK wire messages (see
 *       virp_transcript.c:memcpy(p, a->server_id, 64)).
 *
 * Any code that mutates server_id must preserve both: write the bytes,
 * NUL-terminate within the first 64, zero any trailing bytes. Reading
 * code should use strnlen(buf, sizeof(buf)) for string length — never
 * strlen — so a bad write elsewhere can't walk off the end.
 */
#define VIRP_SERVER_ID_MAX 64

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
        /* strnlen bounds the read even if the caller hands us an
         * unterminated buffer; memset above already zeroed the full
         * 64 bytes so the trailing pad is guaranteed to be zero. */
        size_t len = strnlen(server_id, VIRP_SERVER_ID_MAX);
        if (len >= VIRP_SERVER_ID_MAX) {
            len = VIRP_SERVER_ID_MAX - 1;
            memcpy(ctx->session.server_id, server_id, len);
            ctx->session.server_id[len] = '\0';
            return VIRP_ERR_INVALID_LENGTH;
        }
        memcpy(ctx->session.server_id, server_id, len);
        /* NUL byte already present from the memset at the top. */
    }
    return VIRP_OK;
}

void virp_session_reset(virp_context_t *ctx)
{
    if (!ctx)
        return;

    /*
     * Preserve server_id across reset. We copy only the valid string
     * portion (strnlen-bounded so an upstream bug cannot walk off the
     * end of the buffer) plus a mandatory NUL terminator; the staging
     * buffer is zero-initialised so trailing bytes become deterministic
     * zeros rather than random stack leftovers being memcpy'd back.
     */
    char server_id[VIRP_SERVER_ID_MAX] = {0};
    size_t sid_len = strnlen(ctx->session.server_id, VIRP_SERVER_ID_MAX);
    if (sid_len >= VIRP_SERVER_ID_MAX)
        sid_len = VIRP_SERVER_ID_MAX - 1;
    memcpy(server_id, ctx->session.server_id, sid_len);
    /* server_id[sid_len] onward is already \0 from the initialiser. */

    uint64_t gen = ctx->session.generation + 1;
    /* Wipe session key before clearing struct */
    OPENSSL_cleanse(ctx->session.session_key,
                    sizeof(ctx->session.session_key));
    ctx->session.session_key_valid = 0;
    memset(&ctx->session, 0, sizeof(ctx->session));
    ctx->session.generation = gen;
    ctx->session.state = VIRP_SESSION_DISCONNECTED;
    memcpy(ctx->session.server_id, server_id, VIRP_SERVER_ID_MAX);
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
