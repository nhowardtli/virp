/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Primitive 7: Trust Federation Implementation
 *
 * Ed25519 signatures via libsodium for multi-org trust.
 * Key protection: sodium_mlock() on secret key, sodium_memzero() on destroy.
 */

#include "virp_federation.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sodium.h>
#include <openssl/sha.h>

/* =========================================================================
 * Init
 * ========================================================================= */

virp_error_t virp_fed_init(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "[Federation] sodium_init() failed\n");
        return VIRP_ERR_KEY_NOT_LOADED;
    }
    return VIRP_OK;
}

/* =========================================================================
 * Key ID computation
 * ========================================================================= */

void virp_fed_compute_key_id(const uint8_t pk[VIRP_FED_PK_SIZE],
                             uint8_t key_id[VIRP_FED_KEYID_SIZE])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(pk, VIRP_FED_PK_SIZE, hash);
    memcpy(key_id, hash, VIRP_FED_KEYID_SIZE);
}

/* =========================================================================
 * Generate
 * ========================================================================= */

virp_error_t virp_fed_generate(virp_fed_keypair_t *kp, uint32_t key_version)
{
    if (!kp)
        return VIRP_ERR_NULL_PTR;

    memset(kp, 0, sizeof(*kp));

    if (crypto_sign_keypair(kp->public_key, kp->secret_key) != 0)
        return VIRP_ERR_KEY_NOT_LOADED;

    virp_fed_compute_key_id(kp->public_key, kp->key_id);
    kp->key_version = key_version;
    kp->loaded = true;

    /* Lock secret key memory */
    virp_fed_mlock_key(kp);

    return VIRP_OK;
}

/* =========================================================================
 * Load
 * ========================================================================= */

virp_error_t virp_fed_load(virp_fed_keypair_t *kp,
                           const char *pk_path,
                           const char *sk_path,
                           uint32_t key_version)
{
    if (!kp || !pk_path || !sk_path)
        return VIRP_ERR_NULL_PTR;

    memset(kp, 0, sizeof(*kp));

    /* Read public key */
    int fd = open(pk_path, O_RDONLY);
    if (fd < 0) return VIRP_ERR_KEY_NOT_LOADED;
    ssize_t n = read(fd, kp->public_key, VIRP_FED_PK_SIZE);
    close(fd);
    if (n != VIRP_FED_PK_SIZE) return VIRP_ERR_KEY_NOT_LOADED;

    /* Read secret key */
    fd = open(sk_path, O_RDONLY);
    if (fd < 0) return VIRP_ERR_KEY_NOT_LOADED;
    n = read(fd, kp->secret_key, VIRP_FED_SK_SIZE);
    close(fd);
    if (n != VIRP_FED_SK_SIZE) return VIRP_ERR_KEY_NOT_LOADED;

    virp_fed_compute_key_id(kp->public_key, kp->key_id);
    kp->key_version = key_version;
    kp->loaded = true;

    /* Lock secret key memory */
    virp_fed_mlock_key(kp);

    return VIRP_OK;
}

/* =========================================================================
 * Save
 * ========================================================================= */

virp_error_t virp_fed_save(const virp_fed_keypair_t *kp,
                           const char *pk_path,
                           const char *sk_path)
{
    if (!kp || !pk_path || !sk_path)
        return VIRP_ERR_NULL_PTR;
    if (!kp->loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    /* Write public key */
    int fd = open(pk_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return VIRP_ERR_KEY_NOT_LOADED;
    ssize_t n = write(fd, kp->public_key, VIRP_FED_PK_SIZE);
    close(fd);
    if (n != VIRP_FED_PK_SIZE) return VIRP_ERR_KEY_NOT_LOADED;

    /* Write secret key (0600 permissions) */
    fd = open(sk_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return VIRP_ERR_KEY_NOT_LOADED;
    n = write(fd, kp->secret_key, VIRP_FED_SK_SIZE);
    close(fd);
    if (n != VIRP_FED_SK_SIZE) return VIRP_ERR_KEY_NOT_LOADED;

    return VIRP_OK;
}

/* =========================================================================
 * Sign
 * ========================================================================= */

virp_error_t virp_fed_sign(const virp_fed_keypair_t *kp,
                           const uint8_t *data, size_t data_len,
                           uint8_t sig[VIRP_FED_SIG_SIZE])
{
    if (!kp || !data || !sig)
        return VIRP_ERR_NULL_PTR;
    if (!kp->loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    if (crypto_sign_detached(sig, NULL, data, data_len,
                             kp->secret_key) != 0)
        return VIRP_ERR_HMAC_FAILED;

    return VIRP_OK;
}

/* =========================================================================
 * Verify
 * ========================================================================= */

virp_error_t virp_fed_verify(const uint8_t pk[VIRP_FED_PK_SIZE],
                             const uint8_t *data, size_t data_len,
                             const uint8_t sig[VIRP_FED_SIG_SIZE])
{
    if (!pk || !data || !sig)
        return VIRP_ERR_NULL_PTR;

    if (crypto_sign_verify_detached(sig, data, data_len, pk) != 0)
        return VIRP_ERR_HMAC_FAILED;

    return VIRP_OK;
}

/* =========================================================================
 * Key Protection
 * ========================================================================= */

virp_error_t virp_fed_mlock_key(virp_fed_keypair_t *kp)
{
    if (!kp)
        return VIRP_ERR_NULL_PTR;
    if (!kp->loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    if (sodium_mlock(kp->secret_key, VIRP_FED_SK_SIZE) != 0) {
        /* mlock failure is non-fatal — log and continue */
        fprintf(stderr, "[Federation] Warning: sodium_mlock() failed "
                "(may lack permissions)\n");
    } else {
        kp->locked = true;
    }

    return VIRP_OK;
}

void virp_fed_destroy(virp_fed_keypair_t *kp)
{
    if (!kp) return;

    /* Securely zero the secret key */
    sodium_memzero(kp->secret_key, VIRP_FED_SK_SIZE);

    if (kp->locked) {
        sodium_munlock(kp->secret_key, VIRP_FED_SK_SIZE);
        kp->locked = false;
    }

    /* Zero everything else */
    sodium_memzero(kp->public_key, VIRP_FED_PK_SIZE);
    sodium_memzero(kp->key_id, VIRP_FED_KEYID_SIZE);
    kp->key_version = 0;
    kp->loaded = false;
}
