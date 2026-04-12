/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Transcript serialization, hashing, and HKDF key derivation
 */

#define _POSIX_C_SOURCE 199309L

#include "virp_transcript.h"
#include "virp_session.h"
#include "virp_context.h"
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>  /* OPENSSL_cleanse */

/* =========================================================================
 * Serialization helpers
 *
 * Each message is serialized as a deterministic byte sequence:
 *   4-byte big-endian length prefix + concatenated fields (fixed order).
 * This ensures the transcript hash is identical on both sides regardless
 * of struct padding or compiler layout.
 * ========================================================================= */

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

static void put_be64(uint8_t *p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >>  8);
    p[7] = (uint8_t)(v);
}

int virp_serialize_hello(const virp_session_hello_t *h,
                         uint8_t *out, size_t out_len)
{
    /*
     * Layout: [4 len][1 msg_type][64 client_id][8 versions][1 version_count]
     *         [8 algorithms][1 algorithm_count][4 supported_channels]
     *         [8 client_nonce][8 timestamp_ns]
     * Total body = 1+64+8+1+8+1+4+8+8 = 103
     * With 4-byte prefix = 107
     */
    const size_t body_len = 103;
    const size_t total = 4 + body_len;

    if (out_len < total)
        return -1;

    uint8_t *p = out;
    put_be32(p, (uint32_t)body_len); p += 4;

    *p++ = h->msg_type;
    memcpy(p, h->client_id, 64); p += 64;
    memcpy(p, h->versions, 8); p += 8;
    *p++ = h->version_count;
    memcpy(p, h->algorithms, 8); p += 8;
    *p++ = h->algorithm_count;
    put_be32(p, h->supported_channels); p += 4;
    memcpy(p, h->client_nonce, 8); p += 8;
    put_be64(p, h->timestamp_ns);

    return (int)total;
}

int virp_serialize_hello_ack(const virp_session_hello_ack_t *a,
                             uint8_t *out, size_t out_len)
{
    /*
     * Layout: [4 len][1 msg_type][64 server_id][1 selected_version]
     *         [1 selected_algorithm][4 accepted_channels][16 session_id]
     *         [8 client_nonce][8 server_nonce][8 timestamp_ns]
     * Total body = 1+64+1+1+4+16+8+8+8 = 111
     * With 4-byte prefix = 115
     */
    const size_t body_len = 111;
    const size_t total = 4 + body_len;

    if (out_len < total)
        return -1;

    uint8_t *p = out;
    put_be32(p, (uint32_t)body_len); p += 4;

    *p++ = a->msg_type;
    memcpy(p, a->server_id, 64); p += 64;
    *p++ = a->selected_version;
    *p++ = a->selected_algorithm;
    put_be32(p, a->accepted_channels); p += 4;
    memcpy(p, a->session_id, 16); p += 16;
    memcpy(p, a->client_nonce, 8); p += 8;
    memcpy(p, a->server_nonce, 8); p += 8;
    put_be64(p, a->timestamp_ns);

    return (int)total;
}

int virp_serialize_session_bind(const virp_session_bind_t *b,
                                uint8_t *out, size_t out_len)
{
    /*
     * Layout: [4 len][1 msg_type][16 session_id][64 client_id][64 server_id]
     *         [8 client_nonce][8 server_nonce][8 timestamp_ns]
     * Total body = 1+16+64+64+8+8+8 = 169
     * With 4-byte prefix = 173
     */
    const size_t body_len = 169;
    const size_t total = 4 + body_len;

    if (out_len < total)
        return -1;

    uint8_t *p = out;
    put_be32(p, (uint32_t)body_len); p += 4;

    *p++ = b->msg_type;
    memcpy(p, b->session_id, 16); p += 16;
    memcpy(p, b->client_id, 64); p += 64;
    memcpy(p, b->server_id, 64); p += 64;
    memcpy(p, b->client_nonce, 8); p += 8;
    memcpy(p, b->server_nonce, 8); p += 8;
    put_be64(p, b->timestamp_ns);

    return (int)total;
}

/* =========================================================================
 * Transcript accumulation
 * ========================================================================= */

virp_error_t virp_transcript_append(virp_context_t *ctx,
                                    const uint8_t *data, size_t len)
{
    (void)ctx;
    if (ctx->session.transcript_len + len >
            sizeof(ctx->session.transcript_buf))
        return VIRP_ERR_BUFFER_TOO_SMALL;

    memcpy(ctx->session.transcript_buf + ctx->session.transcript_len,
           data, len);
    ctx->session.transcript_len += len;
    return VIRP_OK;
}

void virp_transcript_finalize(virp_context_t *ctx)
{
    (void)ctx;
    SHA256(ctx->session.transcript_buf,
           ctx->session.transcript_len,
           ctx->session.transcript_hash);
}

/* =========================================================================
 * HKDF-SHA256 (RFC 5869)
 *
 * Extract: PRK = HMAC-SHA256(salt, IKM)
 * Expand:  OKM = HMAC-SHA256(PRK, info || 0x01)   [single block, 32 bytes]
 * ========================================================================= */

virp_error_t virp_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                               const uint8_t *salt, size_t salt_len,
                               const uint8_t *info, size_t info_len,
                               uint8_t okm[32])
{
    if (!ikm || !okm)
        return VIRP_ERR_NULL_PTR;

    /* Default salt: 32 zero bytes */
    uint8_t default_salt[32];
    if (!salt || salt_len == 0) {
        memset(default_salt, 0, 32);
        salt = default_salt;
        salt_len = 32;
    }

    /* Extract: PRK = HMAC-SHA256(salt, IKM) */
    uint8_t prk[32];
    unsigned int prk_len = 32;
    if (!HMAC(EVP_sha256(), salt, (int)salt_len, ikm, ikm_len, prk, &prk_len))
        return VIRP_ERR_CRYPTO;

    /* Expand: T(1) = HMAC-SHA256(PRK, info || 0x01) */
    uint8_t expand_buf[256 + 1]; /* info + counter byte */
    size_t expand_len = 0;

    if (info && info_len > 0) {
        if (info_len > 256)
            return VIRP_ERR_BUFFER_TOO_SMALL;
        memcpy(expand_buf, info, info_len);
        expand_len = info_len;
    }
    expand_buf[expand_len] = 0x01; /* counter = 1 */
    expand_len += 1;

    unsigned int okm_len = 32;
    if (!HMAC(EVP_sha256(), prk, 32, expand_buf, expand_len, okm, &okm_len))
        return VIRP_ERR_CRYPTO;

    /* Wipe PRK */
    OPENSSL_cleanse(prk, sizeof(prk));

    return VIRP_OK;
}

/* =========================================================================
 * Session Key Derivation
 * ========================================================================= */

virp_error_t virp_session_derive_key(virp_context_t *ctx,
                                     const uint8_t master_key[32])
{
    (void)ctx;
    if (!master_key)
        return VIRP_ERR_NULL_PTR;

    if (ctx->session.state != VIRP_SESSION_BOUND)
        return VIRP_ERR_SESSION_INVALID;

    /* info = big-endian generation counter (8 bytes) */
    uint8_t info[8];
    put_be64(info, ctx->session.generation);

    virp_error_t err = virp_hkdf_sha256(
        master_key, 32,
        ctx->session.transcript_hash, 32,
        info, sizeof(info),
        ctx->session.session_key);

    if (err != VIRP_OK)
        return err;

    ctx->session.session_key_valid = 1;

    /* Transition BOUND → ACTIVE */
    ctx->session.state = VIRP_SESSION_ACTIVE;

    {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ctx->session.established_at_ns =
            (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    }

    fprintf(stderr, "[VIRP-HS] Session ACTIVE, "
            "session_key derived from transcript\n");

    return VIRP_OK;
}
