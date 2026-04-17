/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cryptographic operations — HMAC-SHA256 signing and verification
 *
 * Key separation is STRUCTURAL:
 *   - O-Keys sign Observation Channel messages ONLY
 *   - R-Keys sign Intent Channel messages ONLY
 *   - This file enforces that boundary. A caller cannot use
 *     the wrong key for a channel.
 */

#ifndef VIRP_CRYPTO_H
#define VIRP_CRYPTO_H

#include "virp.h"
#include "virp_session.h"  /* virp_context_t forward decl */

/* =========================================================================
 * Key Management
 *
 * Keys are loaded from files or raw bytes. Once loaded, a key is
 * bound to its type (O-Key or R-Key) and cannot be used for the
 * wrong channel.
 * ========================================================================= */

typedef enum {
    VIRP_KEY_TYPE_OKEY = 1,     /* Observation key — signs OC messages */
    VIRP_KEY_TYPE_RKEY = 2,     /* Reasoning key — signs IC messages */
    VIRP_KEY_TYPE_CHAIN = 3,    /* Chain key — signs trust chain entries */
} virp_key_type_t;

typedef struct {
    virp_key_t      key;
    virp_key_type_t type;
    uint8_t         fingerprint[VIRP_HMAC_SIZE]; /* SHA-256 of the key */
} virp_signing_key_t;

/*
 * Initialize a signing key from raw bytes.
 * Returns VIRP_OK on success.
 */
virp_error_t virp_key_init(virp_signing_key_t *sk,
                           virp_key_type_t type,
                           const uint8_t key_bytes[VIRP_KEY_SIZE]);

/*
 * Initialize a signing key from a file (32 bytes, raw binary).
 * Returns VIRP_OK on success.
 */
virp_error_t virp_key_load_file(virp_signing_key_t *sk,
                                virp_key_type_t type,
                                const char *path);

/*
 * Generate a random signing key.
 * Reads from /dev/urandom. Returns VIRP_OK on success.
 */
virp_error_t virp_key_generate(virp_signing_key_t *sk,
                               virp_key_type_t type);

/*
 * Write a signing key to a file (32 bytes, raw binary).
 * File permissions are set to 0600.
 */
virp_error_t virp_key_save_file(const virp_signing_key_t *sk,
                                const char *path);

/*
 * Zero out a key in memory.
 */
void virp_key_destroy(virp_signing_key_t *sk);

/*
 * Constant-time comparison of two buffers.
 * Returns 1 if equal, 0 otherwise. Evaluates all bytes regardless
 * of mismatch position to prevent timing side-channels.
 */
int virp_consttime_eq(const void *a, const void *b, size_t n);

/* =========================================================================
 * Signing and Verification
 *
 * virp_sign() computes HMAC-SHA256 over the message (excluding the
 * HMAC field) and writes the signature into the header's hmac field.
 *
 * CRITICAL: virp_sign() enforces channel-key binding:
 *   - VIRP_KEY_TYPE_OKEY can ONLY sign messages with channel == VIRP_CHANNEL_OC
 *   - VIRP_KEY_TYPE_RKEY can ONLY sign messages with channel == VIRP_CHANNEL_IC
 *   - Attempting to cross channels returns VIRP_ERR_CHANNEL_VIOLATION
 *
 * This is the structural guarantee that an R-Node cannot forge
 * an observation. The code enforces what the spec requires.
 * ========================================================================= */

/*
 * Sign a VIRP message in-place.
 *
 * The message buffer must contain a valid virp_header_t at offset 0
 * followed by the payload. The hmac field will be overwritten.
 *
 * msg:     Pointer to complete message (header + payload)
 * msg_len: Total message length (must match header.length)
 * sk:      Signing key (must match the message's channel)
 *
 * Returns VIRP_OK on success, VIRP_ERR_CHANNEL_VIOLATION if
 * key type doesn't match channel.
 */
virp_error_t virp_sign(virp_context_t *ctx,
                       uint8_t *msg, size_t msg_len,
                       const virp_signing_key_t *sk);

/*
 * Verify a VIRP message signature.
 *
 * msg:     Pointer to complete message (header + payload)
 * msg_len: Total message length
 * sk:      Signing key to verify against
 *
 * Returns VIRP_OK if signature is valid.
 * Returns VIRP_ERR_HMAC_FAILED if signature doesn't match.
 * Returns VIRP_ERR_CHANNEL_VIOLATION if key type doesn't match channel.
 */
virp_error_t virp_verify(virp_context_t *ctx,
                         const uint8_t *msg, size_t msg_len,
                         const virp_signing_key_t *sk);

/*
 * Compute HMAC-SHA256 over arbitrary data.
 * Low-level utility used internally. Exposed for testing.
 *
 * key:      32-byte HMAC key
 * data:     Data to sign
 * data_len: Length of data
 * out:      32-byte output buffer for HMAC
 */
void virp_hmac_sha256(const uint8_t key[VIRP_KEY_SIZE],
                      const uint8_t *data, size_t data_len,
                      uint8_t out[VIRP_HMAC_SIZE]);

/* =========================================================================
 * V2 Command Canonicalization and Signing
 * ========================================================================= */

/*
 * Canonicalize a CLI command string before hashing:
 *   1. trim leading/trailing whitespace
 *   2. collapse repeated internal spaces to single space
 *   3. strip \r characters
 *
 * Writes result to out (null-terminated). Returns length of canonical string,
 * or -1 if out buffer is too small.
 */
int virp_canonicalize_command(const char *cmd, char *out, size_t out_len);

/*
 * Build and sign a v2 observation header + payload.
 * Uses the HKDF-derived session key stored in ctx->session.
 * Session must be ACTIVE with a valid session key.
 *
 * Returns VIRP_OK on success, error code otherwise.
 */
virp_error_t virp_sign_observation_v2(
    virp_context_t *ctx,
    uint64_t node_id, uint64_t device_id,
    uint8_t tier, uint64_t seq_num,
    const char *command,
    const uint8_t *payload, size_t payload_len,
    virp_obs_header_v2_t *hdr_out,
    uint8_t sig_out[32]);

/* =========================================================================
 * Process hardening
 *
 * Call once at daemon startup, after any fork() that's going to stay
 * resident. Disables core dumps for this process (PR_SET_DUMPABLE=0
 * on Linux, a no-op elsewhere), and logs a warning if
 * /proc/self/coredump_filter is configured to dump anonymous or
 * shared-memory pages, since those are where a loaded key lives.
 *
 * Non-fatal on failure — returns VIRP_OK if the process is already
 * undumpable or if the filter looks safe.
 * ========================================================================= */
virp_error_t virp_crypto_harden_process(void);

#endif /* VIRP_CRYPTO_H */
