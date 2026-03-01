/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Intent Routing Protocol
 * Cryptographic operations implementation
 *
 * Uses OpenSSL libcrypto for HMAC-SHA256.
 * No dynamic allocation. All operations on caller-provided buffers.
 */

#include "virp_crypto.h"
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
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

virp_error_t virp_sign(uint8_t *msg, size_t msg_len,
                       const virp_signing_key_t *sk)
{
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

virp_error_t virp_verify(const uint8_t *msg, size_t msg_len,
                         const virp_signing_key_t *sk)
{
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
    const uint8_t *actual = msg + hmac_offset;
    uint8_t diff = 0;
    for (size_t i = 0; i < VIRP_HMAC_SIZE; i++)
        diff |= actual[i] ^ expected[i];

    return (diff == 0) ? VIRP_OK : VIRP_ERR_HMAC_FAILED;
}
