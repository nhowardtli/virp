/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cryptographic operations implementation
 *
 * Uses OpenSSL libcrypto for HMAC-SHA256.
 * No dynamic allocation. All operations on caller-provided buffers.
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime */

#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_session.h"
#include "virp_context.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

/* =========================================================================
 * Internal: compute SHA-256 fingerprint of a key
 * ========================================================================= */

static void compute_fingerprint(const uint8_t key[VIRP_KEY_SIZE],
                                uint8_t fingerprint[VIRP_HMAC_SIZE])
{
    SHA256(key, VIRP_KEY_SIZE, fingerprint);
}

/* =========================================================================
 * Key Management
 * ========================================================================= */

virp_error_t virp_key_init(virp_signing_key_t *sk,
                           virp_key_type_t type,
                           const uint8_t key_bytes[VIRP_KEY_SIZE])
{
    if (!sk || !key_bytes)
        return VIRP_ERR_NULL_PTR;

    memcpy(sk->key.key, key_bytes, VIRP_KEY_SIZE);
    sk->key.loaded = true;
    sk->type = type;
    compute_fingerprint(sk->key.key, sk->fingerprint);

    return VIRP_OK;
}

virp_error_t virp_key_load_file(virp_signing_key_t *sk,
                                virp_key_type_t type,
                                const char *path)
{
    if (!sk || !path)
        return VIRP_ERR_NULL_PTR;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return VIRP_ERR_KEY_NOT_LOADED;

    uint8_t buf[VIRP_KEY_SIZE];
    ssize_t n = read(fd, buf, VIRP_KEY_SIZE);
    close(fd);

    if (n != VIRP_KEY_SIZE)
        return VIRP_ERR_KEY_NOT_LOADED;

    return virp_key_init(sk, type, buf);
}

virp_error_t virp_key_generate(virp_signing_key_t *sk,
                               virp_key_type_t type)
{
    if (!sk)
        return VIRP_ERR_NULL_PTR;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return VIRP_ERR_KEY_NOT_LOADED;

    uint8_t buf[VIRP_KEY_SIZE];
    ssize_t n = read(fd, buf, VIRP_KEY_SIZE);
    close(fd);

    if (n != VIRP_KEY_SIZE)
        return VIRP_ERR_KEY_NOT_LOADED;

    return virp_key_init(sk, type, buf);
}

virp_error_t virp_key_save_file(const virp_signing_key_t *sk,
                                const char *path)
{
    if (!sk || !path)
        return VIRP_ERR_NULL_PTR;
    if (!sk->key.loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return VIRP_ERR_KEY_NOT_LOADED;

    ssize_t n = write(fd, sk->key.key, VIRP_KEY_SIZE);
    close(fd);

    if (n != VIRP_KEY_SIZE)
        return VIRP_ERR_KEY_NOT_LOADED;

    return VIRP_OK;
}

void virp_key_destroy(virp_signing_key_t *sk)
{
    if (!sk) return;

    /* Explicit zeroing — don't let the compiler optimize this away */
    volatile uint8_t *p = (volatile uint8_t *)sk;
    for (size_t i = 0; i < sizeof(*sk); i++)
        p[i] = 0;
}

int virp_consttime_eq(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= pa[i] ^ pb[i];
    return (diff == 0) ? 1 : 0;
}

/* =========================================================================
 * HMAC-SHA256
 * ========================================================================= */

void virp_hmac_sha256(const uint8_t key[VIRP_KEY_SIZE],
                      const uint8_t *data, size_t data_len,
                      uint8_t out[VIRP_HMAC_SIZE])
{
    unsigned int len = VIRP_HMAC_SIZE;
    HMAC(EVP_sha256(), key, VIRP_KEY_SIZE, data, data_len, out, &len);
}

/* =========================================================================
 * Channel-Key Binding Check
 *
 * This is THE critical security boundary of VIRP.
 * O-Keys can ONLY sign OC messages. R-Keys can ONLY sign IC messages.
 * ========================================================================= */

static virp_error_t check_channel_key_binding(uint8_t channel,
                                              virp_key_type_t key_type)
{
    if (channel == VIRP_CHANNEL_OC && key_type != VIRP_KEY_TYPE_OKEY)
        return VIRP_ERR_CHANNEL_VIOLATION;

    if (channel == VIRP_CHANNEL_IC && key_type != VIRP_KEY_TYPE_RKEY)
        return VIRP_ERR_CHANNEL_VIOLATION;

    return VIRP_OK;
}

/* =========================================================================
 * Signing and Verification
 * ========================================================================= */

virp_error_t virp_sign(virp_context_t *ctx,
                       uint8_t *msg, size_t msg_len,
                       const virp_signing_key_t *sk)
{
    (void)ctx;
    if (!msg || !sk)
        return VIRP_ERR_NULL_PTR;
    if (!sk->key.loaded)
        return VIRP_ERR_KEY_NOT_LOADED;
    if (msg_len < VIRP_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    /* Extract channel from the header (offset 8) */
    uint8_t channel = msg[8];

    /* ENFORCE channel-key binding */
    virp_error_t err = check_channel_key_binding(channel, sk->type);
    if (err != VIRP_OK)
        return err;

    /*
     * HMAC covers the entire message EXCEPT the HMAC field itself.
     * The HMAC field is at offset 24 (after version, type, length,
     * node_id, channel, tier, reserved, seq_num, timestamp).
     *
     * We compute HMAC over:
     *   bytes [0..23] + bytes [56..msg_len-1]
     *
     * This means the header fields before the HMAC and the entire
     * payload are authenticated. The HMAC field itself is excluded.
     */
    size_t hmac_offset = offsetof(virp_header_t, hmac);
    size_t pre_hmac_len = hmac_offset;
    size_t post_hmac_start = hmac_offset + VIRP_HMAC_SIZE;
    size_t post_hmac_len = (msg_len > post_hmac_start) ?
                           (msg_len - post_hmac_start) : 0;

    /*
     * Build signing buffer: pre-HMAC header + post-HMAC data
     * Use stack buffer for messages up to 64KB (our max)
     */
    uint8_t sign_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t sign_len = pre_hmac_len + post_hmac_len;

    if (sign_len > sizeof(sign_buf))
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    memcpy(sign_buf, msg, pre_hmac_len);
    if (post_hmac_len > 0)
        memcpy(sign_buf + pre_hmac_len, msg + post_hmac_start, post_hmac_len);

    /* Compute and write HMAC */
    virp_hmac_sha256(sk->key.key, sign_buf, sign_len,
                     msg + hmac_offset);

    return VIRP_OK;
}

virp_error_t virp_verify(virp_context_t *ctx,
                         const uint8_t *msg, size_t msg_len,
                         const virp_signing_key_t *sk)
{
    (void)ctx;
    if (!msg || !sk)
        return VIRP_ERR_NULL_PTR;
    if (!sk->key.loaded)
        return VIRP_ERR_KEY_NOT_LOADED;
    if (msg_len < VIRP_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    /* Extract channel from the header */
    uint8_t channel = msg[8];

    /* ENFORCE channel-key binding */
    virp_error_t err = check_channel_key_binding(channel, sk->type);
    if (err != VIRP_OK)
        return err;

    /* Recompute HMAC the same way as signing */
    size_t hmac_offset = offsetof(virp_header_t, hmac);
    size_t pre_hmac_len = hmac_offset;
    size_t post_hmac_start = hmac_offset + VIRP_HMAC_SIZE;
    size_t post_hmac_len = (msg_len > post_hmac_start) ?
                           (msg_len - post_hmac_start) : 0;

    uint8_t sign_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t sign_len = pre_hmac_len + post_hmac_len;

    if (sign_len > sizeof(sign_buf))
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    memcpy(sign_buf, msg, pre_hmac_len);
    if (post_hmac_len > 0)
        memcpy(sign_buf + pre_hmac_len, msg + post_hmac_start, post_hmac_len);

    uint8_t expected[VIRP_HMAC_SIZE];
    virp_hmac_sha256(sk->key.key, sign_buf, sign_len, expected);

    /* Constant-time comparison to prevent timing attacks */
    return virp_consttime_eq(msg + hmac_offset, expected, VIRP_HMAC_SIZE)
               ? VIRP_OK : VIRP_ERR_HMAC_FAILED;
}

/* =========================================================================
 * V2 Observation Signing
 * ========================================================================= */

virp_error_t virp_sign_observation_v2(
    virp_context_t *ctx,
    uint64_t       node_id,
    uint64_t       device_id,
    uint8_t        tier,
    uint64_t       seq_num,
    const char    *command,
    const uint8_t *payload,   size_t payload_len,
    virp_obs_header_v2_t *hdr_out,
    uint8_t        sig_out[32])
{
    if (!ctx || !command || !payload || !hdr_out || !sig_out)
        return VIRP_ERR_NULL_PTR;

    /* v2 observations require an active session with derived key */
    virp_error_t serr = virp_session_require_active(ctx);
    if (serr != VIRP_OK) return serr;

    if (!ctx->session.session_key_valid)
        return VIRP_ERR_KEY_NOT_LOADED;

    /* update session activity timestamp */
    {
        struct timespec ts_act;
        clock_gettime(CLOCK_REALTIME, &ts_act);
        ctx->session.last_activity_ns =
            (uint64_t)ts_act.tv_sec * 1000000000ULL + ts_act.tv_nsec;
    }

    /* build header */
    virp_obs_header_v2_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version      = VIRP_VERSION_2;
    hdr.channel      = VIRP_CHANNEL_OBS;
    hdr.tier         = tier;
    hdr.node_id      = node_id;
    hdr.device_id    = device_id;
    hdr.seq_num      = seq_num;
    hdr.payload_len  = (uint32_t)payload_len;

    /* timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    hdr.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    /* session id — always from the active session */
    memcpy(hdr.session_id, ctx->session.session_id, 16);

    /* canonicalize command and hash it */
    char canon[512];
    int canon_len = virp_canonicalize_command(command, canon, sizeof(canon));
    if (canon_len < 0) return VIRP_ERR_INVALID_LENGTH;
    SHA256((uint8_t *)canon, (size_t)canon_len, hdr.command_hash);

    /* HMAC-SHA256 over header || payload */
    size_t sign_len = sizeof(hdr) + payload_len;
    if (sign_len > VIRP_MAX_MESSAGE_SIZE)
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    uint8_t sign_buf[VIRP_MAX_MESSAGE_SIZE];
    memcpy(sign_buf, &hdr, sizeof(hdr));
    memcpy(sign_buf + sizeof(hdr), payload, payload_len);

    unsigned int sig_len = 32;
    if (!HMAC(EVP_sha256(),
              ctx->session.session_key, 32,
              sign_buf, sign_len, sig_out, &sig_len))
        return VIRP_ERR_CRYPTO;

    *hdr_out = hdr;
    return VIRP_OK;
}
