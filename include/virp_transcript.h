/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Transcript hashing and HKDF session key derivation (RFC Section 4.5)
 *
 * The transcript is SHA-256(serialized HELLO || HELLO_ACK || SESSION_BIND).
 * Session key = HKDF-SHA256(master_key, transcript_hash, generation).
 */

#ifndef VIRP_TRANSCRIPT_H
#define VIRP_TRANSCRIPT_H

#include <stdint.h>
#include <stddef.h>
#include "virp.h"
#include "virp_session.h"  /* virp_context_t forward decl */
#include "virp_handshake.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Serialize handshake messages into a deterministic byte sequence.
 * Format: 4-byte big-endian length prefix + field data.
 * Returns number of bytes written, or -1 if buffer too small.
 */
int virp_serialize_hello(const virp_session_hello_t *h,
                         uint8_t *out, size_t out_len);

int virp_serialize_hello_ack(const virp_session_hello_ack_t *a,
                             uint8_t *out, size_t out_len);

int virp_serialize_session_bind(const virp_session_bind_t *b,
                                uint8_t *out, size_t out_len);

/*
 * Append serialized bytes to the session transcript buffer.
 * Returns VIRP_OK or VIRP_ERR_BUFFER_TOO_SMALL if transcript_buf overflows.
 */
virp_error_t virp_transcript_append(virp_context_t *ctx,
                                    const uint8_t *data, size_t len);

/*
 * Finalize the transcript: SHA-256(transcript_buf) → session.transcript_hash.
 */
void virp_transcript_finalize(virp_context_t *ctx);

/*
 * HKDF-SHA256 (RFC 5869). Single-block expand (output ≤ 32 bytes).
 *
 * ikm/ikm_len:   input keying material (master key)
 * salt/salt_len:  optional salt (transcript_hash)
 * info/info_len:  context info (generation counter)
 * okm:            output keying material (32 bytes)
 */
virp_error_t virp_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                               const uint8_t *salt, size_t salt_len,
                               const uint8_t *info, size_t info_len,
                               uint8_t okm[32]);

/*
 * Derive session key from master key + transcript hash + generation.
 * Sets g_virp_session.session_key and session_key_valid = 1.
 * Transitions state from BOUND → ACTIVE.
 *
 * master_key: 32-byte master observation key
 *
 * Returns VIRP_OK on success, VIRP_ERR_SESSION_INVALID if not in BOUND state.
 */
virp_error_t virp_session_derive_key(virp_context_t *ctx,
                                     const uint8_t master_key[32]);

#ifdef __cplusplus
}
#endif

#endif /* VIRP_TRANSCRIPT_H */
