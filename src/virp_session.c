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
 * Process-wide context — single backing store for the global
 * session. Commit 1 intentionally keeps function bodies referring
 * to the old name via the g_virp_session macro alias declared in
 * virp_context.h.
 */
virp_context_t g_virp_ctx = {0};

virp_error_t virp_session_init(virp_context_t *ctx, const char *server_id)
{
    (void)ctx;
    memset(&g_virp_session, 0, sizeof(g_virp_session));
    g_virp_session.state = VIRP_SESSION_DISCONNECTED;
    if (server_id) {
        size_t len = strlen(server_id);
        if (len >= sizeof(g_virp_session.server_id)) {
            len = sizeof(g_virp_session.server_id) - 1;
            memcpy(g_virp_session.server_id, server_id, len);
            g_virp_session.server_id[len] = '\0';
            return VIRP_ERR_INVALID_LENGTH;
        }
        memcpy(g_virp_session.server_id, server_id, len);
    }
    return VIRP_OK;
}

void virp_session_reset(virp_context_t *ctx)
{
    (void)ctx;
    char server_id[64];
    memcpy(server_id, g_virp_session.server_id, sizeof(server_id));
    uint64_t gen = g_virp_session.generation + 1;
    /* Wipe session key before clearing struct */
    OPENSSL_cleanse(g_virp_session.session_key,
                    sizeof(g_virp_session.session_key));
    g_virp_session.session_key_valid = 0;
    memset(&g_virp_session, 0, sizeof(g_virp_session));
    g_virp_session.generation = gen;
    g_virp_session.state = VIRP_SESSION_DISCONNECTED;
    memcpy(g_virp_session.server_id, server_id, sizeof(server_id));
}

virp_session_state_t virp_session_state(virp_context_t *ctx)
{
    (void)ctx;
    return g_virp_session.state;
}

virp_error_t virp_session_require_active(virp_context_t *ctx)
{
    (void)ctx;
    if (g_virp_session.state != VIRP_SESSION_ACTIVE)
        return VIRP_ERR_SESSION_INVALID;
    return VIRP_OK;
}

virp_error_t virp_session_check_timeouts(virp_context_t *ctx)
{
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t now = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    if (g_virp_session.state == VIRP_SESSION_NEGOTIATED) {
        if (now - g_virp_session.hello_ack_sent_at_ns >
                VIRP_SESSION_BIND_TIMEOUT_NS) {
            virp_session_reset(&g_virp_ctx);
            return VIRP_ERR_SESSION_INVALID;
        }
    }

    if (g_virp_session.state == VIRP_SESSION_ACTIVE) {
        if (g_virp_session.last_activity_ns > 0 &&
            now - g_virp_session.last_activity_ns >
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
    OPENSSL_cleanse(&g_virp_session, sizeof(g_virp_session));
}
