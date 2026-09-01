/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Primitive 7: Trust Federation Implementation
 *
 * Ed25519 signatures via libsodium for multi-org trust.
 * Key protection: sodium_mlock() on secret key, sodium_memzero() on destroy.
 */

#define _POSIX_C_SOURCE 200809L     /* O_NOFOLLOW, O_CLOEXEC */

#include "virp_federation.h"
#include "virp_crypto.h"            /* virp_keyfile_read */
#include <errno.h>
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

    /* Secret key first, through the shared custody gate (symlink-safe,
     * regular file, 0600-class mode, owner, exact size, read-exactly,
     * wipe-on-failure — this loader used to be a bare open()+read()
     * with none of that; crypto review 2026-08-31, finding 3). */
    uint8_t sk[VIRP_FED_SK_SIZE];
    virp_error_t err = virp_keyfile_read(sk_path,
                                         "[Fed] federation secret key",
                                         true, sk, VIRP_FED_SK_SIZE);
    if (err != VIRP_OK)
        return err;

    /* from_secret cross-checks the seed against the stored public half
     * and derives the working public key from the seed. */
    err = virp_fed_from_secret(kp, sk, key_version);
    sodium_memzero(sk, sizeof(sk));
    if (err != VIRP_OK)
        return err;

    /* The .pub file must BE the public key the seed derives to — a
     * mismatched pair advertises an identity the secret cannot sign
     * as. Public file: no mode/owner policy, everything else applies. */
    uint8_t filed_pk[VIRP_FED_PK_SIZE];
    err = virp_keyfile_read(pk_path, "[Fed] federation public key",
                            false, filed_pk, VIRP_FED_PK_SIZE);
    if (err != VIRP_OK) {
        virp_fed_destroy(kp);
        return err;
    }
    if (sodium_memcmp(filed_pk, kp->public_key, VIRP_FED_PK_SIZE) != 0) {
        fprintf(stderr, "[Fed] %s does not match the public key derived "
                        "from %s — mismatched pair, refusing to load\n",
                pk_path, sk_path);
        virp_fed_destroy(kp);
        return VIRP_ERR_CRYPTO;
    }

    virp_fed_compute_key_id(kp->public_key, kp->key_id);
    kp->key_version = key_version;
    kp->loaded = true;

    /* Lock secret key memory */
    virp_fed_mlock_key(kp);

    return VIRP_OK;
}

virp_error_t virp_fed_from_secret(virp_fed_keypair_t *kp,
                                  const uint8_t sk[VIRP_FED_SK_SIZE],
                                  uint32_t key_version)
{
    if (!kp || !sk)
        return VIRP_ERR_NULL_PTR;

    memset(kp, 0, sizeof(*kp));
    memcpy(kp->secret_key, sk, VIRP_FED_SK_SIZE);

    /* libsodium sk = seed(32) || pub(32). RE-DERIVE the public half
     * from the seed and cross-check it against the stored half — a
     * seed_A||pub_B key must not load and sign under an identity the
     * seed does not produce. crypto_sign_ed25519_sk_to_pk() would only
     * copy the stored half out, checking nothing (same defect class as
     * the obskey loader; crypto review 2026-08-31, findings 2/3). */
    uint8_t derived_pk[VIRP_FED_PK_SIZE];
    uint8_t derived_sk[VIRP_FED_SK_SIZE];
    int drc = crypto_sign_seed_keypair(derived_pk, derived_sk,
                                       kp->secret_key);
    sodium_memzero(derived_sk, VIRP_FED_SK_SIZE);
    if (drc != 0 ||
        sodium_memcmp(derived_pk,
                      kp->secret_key + VIRP_FED_SK_SIZE - VIRP_FED_PK_SIZE,
                      VIRP_FED_PK_SIZE) != 0) {
        fprintf(stderr, "[Fed] secret key: public half does not match "
                        "the seed — corrupt key, refusing to load\n");
        sodium_memzero(kp->secret_key, VIRP_FED_SK_SIZE);
        return VIRP_ERR_CRYPTO;
    }
    memcpy(kp->public_key, derived_pk, VIRP_FED_PK_SIZE);

    virp_fed_compute_key_id(kp->public_key, kp->key_id);
    kp->key_version = key_version;
    kp->loaded = true;

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

    /*
     * O_EXCL | O_NOFOLLOW on both writes — the same discipline the
     * obskey save uses (SECURITY.md P2-3 carry-over). O_NOFOLLOW refuses
     * a pre-planted symlink at the final path component; O_EXCL refuses
     * to write over an existing file at all, which closes the case where
     * an attacker pre-creates a wide-mode regular file at sk_path and our
     * O_TRUNC would have written the secret into their readable file. A
     * keypair is generated into an EMPTY prefix — regenerating over an
     * existing key is deliberately unsupported; remove both files first.
     */
    int fd = open(pk_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0) {
        fprintf(stderr, "[Federation] cannot create %s: %s "
                        "(existing files are never overwritten)\n",
                pk_path, strerror(errno));
        return VIRP_ERR_KEY_NOT_LOADED;
    }
    ssize_t n = write(fd, kp->public_key, VIRP_FED_PK_SIZE);
    close(fd);
    if (n != VIRP_FED_PK_SIZE) return VIRP_ERR_KEY_NOT_LOADED;

    /* Write secret key (0600 permissions) */
    fd = open(sk_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        fprintf(stderr, "[Federation] cannot create %s: %s "
                        "(existing files are never overwritten)\n",
                sk_path, strerror(errno));
        return VIRP_ERR_KEY_NOT_LOADED;
    }
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
