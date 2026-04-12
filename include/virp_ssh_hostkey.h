/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * SSH Host Key Verification
 *
 * Shared across all SSH-based drivers. Call after
 * libssh2_session_handshake(), before any authentication.
 *
 * Behavior:
 *   - Loads known_hosts from VIRP_KNOWN_HOSTS (default ~/.virp/known_hosts)
 *   - MATCH    → VIRP_OK
 *   - MISMATCH → VIRP_ERR_HOST_KEY_MISMATCH (always fatal)
 *   - NOT_FOUND:
 *       If TOFU enabled  → record key, write file, return VIRP_OK
 *       If TOFU disabled → VIRP_ERR_HOST_KEY_UNKNOWN
 *
 * TOFU (trust-on-first-use) is controlled by:
 *   1. Environment: VIRP_SSH_TOFU=1 overrides everything
 *   2. Compile-time: VIRP_SSH_TOFU_DEFAULT (set in dev builds, unset in prod)
 */

#ifndef VIRP_SSH_HOSTKEY_H
#define VIRP_SSH_HOSTKEY_H

#include "virp.h"
#include <libssh2.h>

/*
 * Verify the remote host key of an established SSH session.
 *
 * Must be called AFTER libssh2_session_handshake() succeeds and
 * BEFORE any authentication attempt.
 *
 * session: active libssh2 session (handshake complete)
 * host:    remote hostname or IP
 * port:    remote SSH port
 *
 * Returns:
 *   VIRP_OK                    — key matches known_hosts (or TOFU accepted)
 *   VIRP_ERR_HOST_KEY_MISMATCH — key changed since last connection
 *   VIRP_ERR_HOST_KEY_UNKNOWN  — key not in known_hosts, TOFU disabled
 *   VIRP_ERR_CRYPTO            — libssh2 known-hosts API error
 */
virp_error_t virp_ssh_verify_hostkey(LIBSSH2_SESSION *session,
                                     const char *host, uint16_t port);

#endif /* VIRP_SSH_HOSTKEY_H */
