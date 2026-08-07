/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — O-Node Ed25519 observation-signing key (custody)
 *
 * The keypair that signs Ed25519 observations (wire version 3). It is
 * a THIRD key, distinct from both:
 *
 *   - the symmetric O-Key (HMAC): anyone who can verify can also forge;
 *   - the approval keypair: its SECRET lives OFF-box with a human
 *     approver and the daemon holds only the public key, so the daemon
 *     can never approve its own proposals.
 *
 * Here the custody is deliberately the other way around: the PRIVATE
 * key lives ON the daemon host, because the O-Node is the attester —
 * an observation is precisely the daemon's own signed statement of
 * what a device returned. That is not a contradiction of the approval
 * rule; the two keys answer different questions. Approval asks "did a
 * human other than the daemon authorize this?", so the daemon must not
 * hold the secret. Observation signing asks "did this daemon produce
 * this observation?", so only the daemon may hold the secret. What the
 * consumer gains over HMAC is that the PUBLIC verify key carries no
 * forge capability: a report consumer or auditor can validate an
 * observation without being able to mint one. A compromised daemon can
 * still forge — the daemon is the attester; that boundary is unchanged.
 *
 * Custody rules enforced by this module:
 *   - secret key file must be 0400/0600, owner = euid (or root),
 *     regular file, no symlink; anything group/world-accessible is
 *     REFUSED at load.
 *   - secret key bytes are sodium_mlock'd while loaded and
 *     sodium_memzero'd on destroy; never logged, never exported.
 *   - only the public key is exportable (raw or SPKI DER), with
 *     key_id = SHA-256(public_key)[:16] — the same convention the
 *     approver registry and federation keys already use.
 */

#ifndef VIRP_OBSKEY_H
#define VIRP_OBSKEY_H

#include <stdint.h>
#include <stdbool.h>
#include "virp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VIRP_OBSKEY_PK_SIZE    32   /* crypto_sign_PUBLICKEYBYTES        */
#define VIRP_OBSKEY_SK_SIZE    64   /* crypto_sign_SECRETKEYBYTES        */
#define VIRP_OBSKEY_KEYID_SIZE 16   /* SHA-256(public_key)[:16]          */
#define VIRP_OBSKEY_SPKI_SIZE  44   /* DER SubjectPublicKeyInfo, Ed25519 */

typedef struct {
    uint8_t public_key[VIRP_OBSKEY_PK_SIZE];
    uint8_t secret_key[VIRP_OBSKEY_SK_SIZE];
    uint8_t key_id[VIRP_OBSKEY_KEYID_SIZE];
    bool    loaded;
    bool    locked;      /* secret key is sodium_mlock'd */
} virp_obskey_t;

/* Generate a fresh keypair in memory (mlocks the secret). */
virp_error_t virp_obskey_generate(virp_obskey_t *kp);

/* Write secret (0600) and public (0644) key files. */
virp_error_t virp_obskey_save(const virp_obskey_t *kp,
                              const char *sk_path,
                              const char *pk_path);

/*
 * Load the secret key file and derive public key + key_id from it.
 * Refuses: symlinks, non-regular files, group/world-accessible modes,
 * wrong owner (VIRP_ERR_KEY_NOT_LOADED), and any file whose size is
 * not exactly VIRP_OBSKEY_SK_SIZE (VIRP_ERR_INVALID_LENGTH) — the two
 * failure classes return distinct errors and distinct messages.
 */
virp_error_t virp_obskey_load(virp_obskey_t *kp, const char *sk_path);

/*
 * Export the public key as DER SubjectPublicKeyInfo (44 bytes), the
 * same encoding the approver registry consumes. Never touches the
 * secret key.
 */
virp_error_t virp_obskey_spki(const virp_obskey_t *kp,
                              uint8_t out[VIRP_OBSKEY_SPKI_SIZE]);

/* Zeroize (sodium_memzero) and unlock the secret key. */
void virp_obskey_destroy(virp_obskey_t *kp);

#ifdef __cplusplus
}
#endif

#endif /* VIRP_OBSKEY_H */
