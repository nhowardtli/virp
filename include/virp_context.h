/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Protocol context (wraps session state)
 *
 * virp_context_t is a wrapper around virp_session_t that exists so
 * that future additions — Ed25519 identity keypair, replay-window
 * state, per-peer policy — have an obvious home without forcing
 * another signature-level refactor. It is intentionally not a
 * rename of virp_session_t: the session is protocol-handshake state
 * in the narrow sense, while the context is the library handle that
 * holds it (compare OpenSSL's SSL_CTX vs. SSL).
 *
 * Ownership: contexts are allocated by callers via virp_context_new()
 * and released with virp_context_destroy(). There is no process-wide
 * default. Each caller — the o-node main, each test, any library
 * consumer — is responsible for the lifetime of its own context.
 * The parameter name used throughout the codebase is `ctx`.
 */

#ifndef VIRP_CONTEXT_H
#define VIRP_CONTEXT_H

#include "virp_session.h"

#ifdef __cplusplus
extern "C" {
#endif

struct virp_context_s {
    virp_session_t session;
};

/*
 * Allocate a zero-initialized virp_context_t. Session state starts
 * in VIRP_SESSION_DISCONNECTED. Returns NULL only on calloc failure.
 */
virp_context_t *virp_context_new(void);

/*
 * Wipe (OPENSSL_cleanse) and free a context. Safe to call with NULL.
 * The cleanse ensures session_key, transcript buffer, and nonces
 * are not left in the heap page after release.
 */
void virp_context_destroy(virp_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VIRP_CONTEXT_H */
