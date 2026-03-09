/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Primitive 7: Trust Federation — Ed25519 signatures for multi-org trust
 *
 * Dual mode: HMAC always present for internal. Ed25519 added alongside
 * when federation is active. Tagged with sig_alg field.
 *
 * Key protection: sodium_mlock() on secret key, sodium_memzero() on destroy.
 */

#ifndef VIRP_FEDERATION_H
#define VIRP_FEDERATION_H

#include "virp.h"
#include <stdbool.h>
#include <stdint.h>

/* Ed25519 key sizes (libsodium) */
#define VIRP_FED_PK_SIZE   32    /* crypto_sign_PUBLICKEYBYTES */
#define VIRP_FED_SK_SIZE   64    /* crypto_sign_SECRETKEYBYTES */
#define VIRP_FED_SIG_SIZE  64    /* crypto_sign_BYTES */
#define VIRP_FED_KEYID_SIZE 16   /* SHA-256(public_key)[:16] */

/* =========================================================================
 * Federation Keypair
 * ========================================================================= */

typedef struct {
    uint8_t  public_key[VIRP_FED_PK_SIZE];
    uint8_t  secret_key[VIRP_FED_SK_SIZE];
    uint8_t  key_id[VIRP_FED_KEYID_SIZE];   /* SHA-256(public_key)[:16] */
    uint32_t key_version;                     /* Monotonic version counter */
    bool     loaded;
    bool     locked;                          /* Secret key is mlock'd */
} virp_fed_keypair_t;

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/*
 * Initialize libsodium. Must be called before any other federation function.
 * Safe to call multiple times (idempotent).
 */
virp_error_t virp_fed_init(void);

/*
 * Generate a new Ed25519 keypair.
 * Computes key_id = SHA-256(public_key)[:16].
 * Calls sodium_mlock() on the secret key.
 */
virp_error_t virp_fed_generate(virp_fed_keypair_t *kp, uint32_t key_version);

/*
 * Load a keypair from files.
 *   pk_path: 32-byte public key file
 *   sk_path: 64-byte secret key file
 * Calls sodium_mlock() on loaded secret key.
 */
virp_error_t virp_fed_load(virp_fed_keypair_t *kp,
                           const char *pk_path,
                           const char *sk_path,
                           uint32_t key_version);

/*
 * Save a keypair to files (0600 permissions).
 */
virp_error_t virp_fed_save(const virp_fed_keypair_t *kp,
                           const char *pk_path,
                           const char *sk_path);

/* =========================================================================
 * Signing and Verification
 * ========================================================================= */

/*
 * Sign data with Ed25519.
 *   data/data_len: message to sign
 *   sig:           output buffer (VIRP_FED_SIG_SIZE bytes)
 */
virp_error_t virp_fed_sign(const virp_fed_keypair_t *kp,
                           const uint8_t *data, size_t data_len,
                           uint8_t sig[VIRP_FED_SIG_SIZE]);

/*
 * Verify an Ed25519 signature.
 *   pk:            32-byte public key (not necessarily from a keypair)
 *   data/data_len: signed message
 *   sig:           signature to verify (VIRP_FED_SIG_SIZE bytes)
 *
 * Returns VIRP_OK if valid, VIRP_ERR_HMAC_FAILED if not.
 */
virp_error_t virp_fed_verify(const uint8_t pk[VIRP_FED_PK_SIZE],
                             const uint8_t *data, size_t data_len,
                             const uint8_t sig[VIRP_FED_SIG_SIZE]);

/* =========================================================================
 * Key Protection
 * ========================================================================= */

/*
 * Lock the secret key memory (sodium_mlock).
 * Called automatically by generate/load.
 */
virp_error_t virp_fed_mlock_key(virp_fed_keypair_t *kp);

/*
 * Zero and unlock the secret key memory. Must be called before free.
 */
void virp_fed_destroy(virp_fed_keypair_t *kp);

/*
 * Compute key_id from a public key: SHA-256(pk)[:16]
 */
void virp_fed_compute_key_id(const uint8_t pk[VIRP_FED_PK_SIZE],
                             uint8_t key_id[VIRP_FED_KEYID_SIZE]);

#endif /* VIRP_FEDERATION_H */
