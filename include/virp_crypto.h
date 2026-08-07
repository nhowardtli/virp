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
#include "virp_seqstore.h" /* replay high-water store for v2 verification */
#include "virp_obskey.h"   /* virp_obskey_t (v3 Ed25519 observations) */
#include <sys/types.h>     /* uid_t (virp_key_owner_ok) */

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
 * Key-file ownership gate: true iff file_owner == euid OR euid == 0
 * (root reading a service-owned key is not an escalation; mode-bit
 * checks are enforced separately and unchanged). Exposed for the unit
 * tests; virp_key_load_file uses it internally.
 */
bool virp_key_owner_ok(uid_t file_owner, uid_t euid);

/*
 * Durable, symlink-safe small-file write: write to <path>.tmp, fsync it,
 * rename over <path>, then fsync the PARENT DIRECTORY so the rename
 * itself survives a crash.
 *
 * Symlink safety comes from two properties together:
 *   - the temp file is created with O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC
 *     after unlinking any stale temp, so we always own a fresh regular
 *     file and never write through a planted link;
 *   - rename(2) REPLACES whatever sits at `path`, including a symlink,
 *     rather than following it — so a link planted at the destination
 *     cannot redirect where the bytes land.
 *
 * The mode is applied with fchmod after creation, so it holds exactly
 * regardless of the caller's umask.
 *
 * Takes a length rather than a NUL-terminated string: key material is
 * binary and may contain NUL bytes.
 */
virp_error_t virp_write_file_durable(const char *path, mode_t mode,
                                     const void *buf, size_t len);

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
    const char *typed_profile,
    const uint8_t *payload, size_t payload_len,
    virp_obs_header_v2_t *hdr_out,
    uint8_t sig_out[32]);

/*
 * Exact-octet command hash for TYPED-OPERATION profiles.
 *
 *   SHA-256("VIRP-TYPED-OP\0" || u32be len(profile) || profile
 *                              || u32be len(command) || command)
 *
 * Used instead of the canonicalizing hash whenever a driver declares a
 * typed_profile. The canonicalizer collapses whitespace, so commands a
 * typed parser REFUSES hash identically to ones it accepts; binding an
 * approval or an observation to that hash is then ambiguous. See
 * docs/DRIVER-TYPED-OPS.md.
 */
virp_error_t virp_typed_op_hash(const char *profile,
                                const char *command, size_t command_len,
                                uint8_t out[32]);

/*
 * Build a complete v2 observation wire message:
 *   [serialized header (88)] [payload] [HMAC sig (32)]
 * Signs via virp_sign_observation_v2() with the session key.
 * Session must be ACTIVE with a valid derived key.
 */
virp_error_t virp_build_observation_v2(
    virp_context_t *ctx,
    uint64_t node_id, uint64_t device_id,
    uint8_t tier, uint64_t seq_num,
    const char *command,
    const char *typed_profile,
    const uint8_t *payload, size_t payload_len,
    uint8_t *out_buf, size_t out_buf_len, size_t *out_len);

/*
 * Build a complete v3 (Ed25519-signed) observation wire message:
 *   [header (88, version=3)] [payload] [hmac (32)] [ed25519 sig (64)]
 *
 * ADDITIVE alongside v1/v2 — deliberately implemented as its own
 * function rather than a refactor of the v2 path, so introducing it
 * provably cannot change v1/v2 behaviour; unification is the
 * observation re-cut's job. Both trailers cover exactly
 * serialized_header || payload (see the v3 comment in virp.h): the
 * HMAC keeps the v2 session semantics for the caller, the Ed25519
 * detached signature (obskey secret; the O-Node is the attester) is
 * what a public-key-only consumer verifies. Session must be ACTIVE
 * with a valid derived key; obskey must be loaded.
 */
virp_error_t virp_build_observation_ed25519(
    virp_context_t *ctx,
    const virp_obskey_t *obskey,
    uint64_t node_id, uint64_t device_id,
    uint8_t tier, uint64_t seq_num,
    const char *command,
    const char *typed_profile,
    const uint8_t *payload, size_t payload_len,
    uint8_t *out_buf, size_t out_buf_len, size_t *out_len);

/*
 * PUBLIC-KEY-ONLY verification of a v3 observation — no context, no
 * session, no secret parameter exists. Checks version=3, channel,
 * exact framing, and the Ed25519 trailer over header || payload;
 * returns VIRP_ERR_OBS_SIG_INVALID on a bad signature. Deliberately
 * does NOT check the HMAC trailer (session holder's check; a consumer
 * must not need a forge-capable key to verify) and does NOT apply
 * replay/staleness acceptance rules (accepting-endpoint duties; see
 * virp_verify_observation_v2). On success, optionally returns the
 * parsed header and a pointer into msg for the payload.
 */
virp_error_t virp_verify_observation_ed25519(
    const uint8_t public_key[VIRP_OBSKEY_PK_SIZE],
    const uint8_t *msg, size_t msg_len,
    virp_obs_header_v2_t *hdr_out,
    const uint8_t **payload_out, uint32_t *payload_len_out);

/*
 * Verify a v2 observation wire message. This is the single home for
 * every check an accepting verifier must make:
 *
 *   1. HMAC-SHA256 over serialized header || payload with the active
 *      session's HKDF-derived key, constant-time compare
 *      → VIRP_ERR_HMAC_FAILED
 *   2. header sanity: version/channel/tier/reserved/payload_len
 *   3. session binding: header session_id == active session's id
 *      → VIRP_ERR_SESSION_INVALID
 *   4. device binding: header device_id == expected_device_id
 *      → VIRP_ERR_CONTEXT_MISMATCH
 *   5. command binding: header command_hash ==
 *      SHA256(virp_canonicalize_command(expected_command))
 *      → VIRP_ERR_CONTEXT_MISMATCH
 *   6. freshness: |now − signed timestamp_ns| ≤
 *      VIRP_OBS_V2_FRESHNESS_WINDOW_NS → VIRP_ERR_STALE_OBSERVATION
 *   7. replay: seq_num strictly above the (session_id, node_id)
 *      high-water mark in seq_store → VIRP_ERR_REPLAY_DETECTED.
 *      The mark is only advanced after checks 1–6 pass.
 *
 * now_ns: verifier clock in nanoseconds; pass 0 to use CLOCK_REALTIME.
 *         (Injectable so staleness is testable with a mocked clock.)
 * seq_store: required — replay protection is not optional.
 *         Ordering caveat: seq acceptance is strictly monotonic per
 *         (session_id, node_id). A client that issues CONCURRENT
 *         requests on one session for the same device and verifies
 *         responses out of arrival order will reject the late-arriving
 *         (lower-seq) genuine observation as a replay. Serialize
 *         verification per (session, device), or use one session per
 *         concurrent stream.
 * hdr_out / payload_out / payload_len_out: optional; filled only on
 *         VIRP_OK. payload_out points into msg.
 */
virp_error_t virp_verify_observation_v2(
    virp_context_t *ctx,
    uint64_t expected_device_id,
    const char *expected_command,
    const char *expected_typed_profile,
    const uint8_t *msg, size_t msg_len,
    uint64_t now_ns,
    virp_seqstore_t *seq_store,
    virp_obs_header_v2_t *hdr_out,
    const uint8_t **payload_out, uint32_t *payload_len_out);

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
