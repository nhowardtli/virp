/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — O-Node Ed25519 observation-signing key (custody)
 *
 * See include/virp_obskey.h for the custody model and why the private
 * key living ON the daemon is correct for this key (the daemon is the
 * attester) while the approval secret must live OFF-box.
 *
 * Crypto primitives are raw libsodium, the same calls the federation
 * module already uses; the SPKI encoding and key_id convention are the
 * approver registry's.
 */

#define _POSIX_C_SOURCE 200809L     /* O_NOFOLLOW, O_CLOEXEC */

#include "virp_obskey.h"
#include "virp_crypto.h"            /* virp_key_owner_ok */
#include "virp_approver_registry.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sodium.h>
#include <openssl/sha.h>

static void obskey_key_id(const uint8_t pk[VIRP_OBSKEY_PK_SIZE],
                          uint8_t key_id[VIRP_OBSKEY_KEYID_SIZE])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(pk, VIRP_OBSKEY_PK_SIZE, hash);
    memcpy(key_id, hash, VIRP_OBSKEY_KEYID_SIZE);
}

static void obskey_mlock(virp_obskey_t *kp)
{
    if (sodium_mlock(kp->secret_key, VIRP_OBSKEY_SK_SIZE) != 0) {
        /* Non-fatal, same policy as the federation keys: without
         * CAP_IPC_LOCK the key still works, it just isn't pinned. */
        fprintf(stderr, "[ObsKey] Warning: sodium_mlock() failed "
                        "(may lack permissions)\n");
    } else {
        kp->locked = true;
    }
}

virp_error_t virp_obskey_generate(virp_obskey_t *kp)
{
    if (!kp)
        return VIRP_ERR_NULL_PTR;
    if (sodium_init() < 0)
        return VIRP_ERR_CRYPTO;

    memset(kp, 0, sizeof(*kp));
    if (crypto_sign_keypair(kp->public_key, kp->secret_key) != 0)
        return VIRP_ERR_CRYPTO;

    obskey_key_id(kp->public_key, kp->key_id);
    kp->loaded = true;
    obskey_mlock(kp);
    return VIRP_OK;
}

virp_error_t virp_obskey_save(const virp_obskey_t *kp,
                              const char *sk_path,
                              const char *pk_path)
{
    if (!kp || !sk_path || !pk_path)
        return VIRP_ERR_NULL_PTR;
    if (!kp->loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    /* Secret first, 0600 from birth — never a window where it exists
     * with wider bits. O_EXCL: refuse to write over an existing key. */
    int fd = open(sk_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        fprintf(stderr, "[ObsKey] cannot create %s: %s\n",
                sk_path, strerror(errno));
        return VIRP_ERR_KEY_NOT_LOADED;
    }
    ssize_t n = write(fd, kp->secret_key, VIRP_OBSKEY_SK_SIZE);
    close(fd);
    if (n != VIRP_OBSKEY_SK_SIZE)
        return VIRP_ERR_KEY_NOT_LOADED;

    /* Same discipline as the secret: O_EXCL (never write over an
     * existing file — a keypair is generated into an EMPTY prefix,
     * and O_EXCL also refuses a pre-planted symlink) plus O_NOFOLLOW
     * as belt-and-suspenders. The content is public; the write path
     * is not. Regenerating into an existing prefix is deliberately
     * not a supported workflow — remove both files first. */
    fd = open(pk_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0) {
        fprintf(stderr, "[ObsKey] cannot create %s: %s (existing files "
                        "are never overwritten)\n",
                pk_path, strerror(errno));
        return VIRP_ERR_KEY_NOT_LOADED;
    }
    n = write(fd, kp->public_key, VIRP_OBSKEY_PK_SIZE);
    close(fd);
    if (n != VIRP_OBSKEY_PK_SIZE)
        return VIRP_ERR_KEY_NOT_LOADED;

    return VIRP_OK;
}

virp_error_t virp_obskey_load(virp_obskey_t *kp, const char *sk_path)
{
    if (!kp || !sk_path)
        return VIRP_ERR_NULL_PTR;
    if (sodium_init() < 0)
        return VIRP_ERR_CRYPTO;

    memset(kp, 0, sizeof(*kp));

    /* One shared custody gate for every key type — no symlinks,
     * regular file only, no group/world bits, owner must be us (or we
     * are root), exact size, read-exactly, wipe-on-failure. The
     * observation-signing secret is daemon-resident, which is exactly
     * why a lax mode must refuse: any other local reader has already
     * become an observation forger. */
    virp_error_t kerr = virp_keyfile_read(sk_path,
                                          "[ObsKey] observation signing key",
                                          true, kp->secret_key,
                                          VIRP_OBSKEY_SK_SIZE);
    if (kerr != VIRP_OK)
        return kerr;

    /* libsodium sk = seed(32) || pub(32). RE-DERIVE the public half from
     * the seed and cross-check it against the stored half: a file whose
     * two halves disagree is corrupt (or hand-assembled) and must not
     * sign. crypto_sign_ed25519_sk_to_pk() would NOT do this — it only
     * copies the stored half — so the derivation goes through
     * crypto_sign_seed_keypair on a scratch key, exactly as
     * virp_chainsign_load() does. */
    uint8_t derived_pk[VIRP_OBSKEY_PK_SIZE];
    uint8_t derived_sk[VIRP_OBSKEY_SK_SIZE];
    int drc = crypto_sign_seed_keypair(derived_pk, derived_sk,
                                       kp->secret_key);
    sodium_memzero(derived_sk, VIRP_OBSKEY_SK_SIZE);
    if (drc != 0 ||
        sodium_memcmp(derived_pk,
                      kp->secret_key + VIRP_OBSKEY_SK_SIZE
                                     - VIRP_OBSKEY_PK_SIZE,
                      VIRP_OBSKEY_PK_SIZE) != 0) {
        fprintf(stderr, "[ObsKey] %s: public half does not match the "
                        "seed — corrupt key file, refusing to load\n",
                sk_path);
        sodium_memzero(kp->secret_key, VIRP_OBSKEY_SK_SIZE);
        return VIRP_ERR_CRYPTO;
    }
    memcpy(kp->public_key, derived_pk, VIRP_OBSKEY_PK_SIZE);

    obskey_key_id(kp->public_key, kp->key_id);
    kp->loaded = true;
    obskey_mlock(kp);
    return VIRP_OK;
}

virp_error_t virp_obskey_spki(const virp_obskey_t *kp,
                              uint8_t out[VIRP_OBSKEY_SPKI_SIZE])
{
    if (!kp || !out)
        return VIRP_ERR_NULL_PTR;
    if (!kp->loaded)
        return VIRP_ERR_KEY_NOT_LOADED;
    virp_approver_ed25519_spki(kp->public_key, out);
    return VIRP_OK;
}

void virp_obskey_destroy(virp_obskey_t *kp)
{
    if (!kp)
        return;
    sodium_memzero(kp->secret_key, VIRP_OBSKEY_SK_SIZE);
    if (kp->locked)
        sodium_munlock(kp->secret_key, VIRP_OBSKEY_SK_SIZE);
    memset(kp, 0, sizeof(*kp));
}
