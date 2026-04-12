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
 * Today the struct contains exactly one field (session). The
 * parameter name used throughout the codebase is `ctx`.
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
 * Process-wide single context. Commit 1 keeps the global backing
 * store in place; commit 3 will delete it and require callers to
 * allocate their own. Until then, callers pass &g_virp_ctx into
 * the threaded prototypes.
 */
extern virp_context_t g_virp_ctx;

/*
 * Macro alias so existing code that refers to g_virp_session.foo
 * keeps compiling. Expands to the same lvalue as the new backing
 * store. Commit 2 will migrate function bodies to ctx->session
 * and commit 3 will retire this alias.
 */
#define g_virp_session (g_virp_ctx.session)

#ifdef __cplusplus
}
#endif

#endif /* VIRP_CONTEXT_H */
