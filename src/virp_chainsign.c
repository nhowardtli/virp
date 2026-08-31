/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Chain-signing key (D-1: detached Ed25519 chain signatures)
 *
 * See include/virp_chainsign.h for the role, the domain tags and why the
 * canonical bytes this key signs are byte-identical to the pre-D-1 tree.
 *
 * Primitives are raw libsodium, the same calls the obskey and federation
 * modules use. The custody gate is the obskey's, restated here with its
 * own log prefix rather than shared through a role-agnostic helper, so
 * that an obskey can never be loaded where a chain-signing key is
 * expected (the two types are distinct on purpose).
 */

#define _POSIX_C_SOURCE 200809L     /* O_NOFOLLOW, O_CLOEXEC */

#include "virp_chainsign.h"
#include "virp_crypto.h"            /* virp_key_owner_ok */
#include "virp_approver_registry.h" /* virp_approver_ed25519_spki */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sodium.h>
#include <openssl/sha.h>

/* Largest signature input accepted: the longest canonical the chain
 * builds is 2048 bytes; the tag adds a few dozen. Anything larger is a
 * caller bug, refused rather than signed. */
#define CHAINSIGN_MAX_INPUT 4096

void virp_chainsign_key_id(const uint8_t pk[VIRP_CHAINSIGN_PK_SIZE],
                           uint8_t key_id[VIRP_CHAINSIGN_KEYID_SIZE])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(pk, VIRP_CHAINSIGN_PK_SIZE, hash);
    memcpy(key_id, hash, VIRP_CHAINSIGN_KEYID_SIZE);
}

void virp_chainsign_key_id_hex(const uint8_t pk[VIRP_CHAINSIGN_PK_SIZE],
                               char out[VIRP_CHAINSIGN_KEYID_HEX])
{
    uint8_t id[VIRP_CHAINSIGN_KEYID_SIZE];
    virp_chainsign_key_id(pk, id);
    for (int i = 0; i < VIRP_CHAINSIGN_KEYID_SIZE; i++)
        snprintf(out + i * 2, 3, "%02x", id[i]);
    out[VIRP_CHAINSIGN_KEYID_HEX - 1] = '\0';
}

static void chainsign_finish(virp_chainsign_key_t *kp)
{
    virp_chainsign_key_id(kp->public_key, kp->key_id);
    virp_chainsign_key_id_hex(kp->public_key, kp->key_id_hex);
    kp->loaded = true;
    if (sodium_mlock(kp->secret_key, VIRP_CHAINSIGN_SK_SIZE) != 0) {
        /* Non-fatal, same policy as the obskey/federation keys. */
        fprintf(stderr, "[ChainSign] Warning: sodium_mlock() failed "
                        "(may lack permissions)\n");
    } else {
        kp->locked = true;
    }
}

virp_error_t virp_chainsign_generate(virp_chainsign_key_t *kp)
{
    if (!kp) return VIRP_ERR_NULL_PTR;
    if (sodium_init() < 0) return VIRP_ERR_CRYPTO;
    memset(kp, 0, sizeof(*kp));
    if (crypto_sign_keypair(kp->public_key, kp->secret_key) != 0)
        return VIRP_ERR_CRYPTO;
    chainsign_finish(kp);
    return VIRP_OK;
}

virp_error_t virp_chainsign_from_seed(virp_chainsign_key_t *kp,
                                      const uint8_t seed[VIRP_CHAINSIGN_SEED_SIZE])
{
    if (!kp || !seed) return VIRP_ERR_NULL_PTR;
    if (sodium_init() < 0) return VIRP_ERR_CRYPTO;
    memset(kp, 0, sizeof(*kp));
    if (crypto_sign_seed_keypair(kp->public_key, kp->secret_key, seed) != 0)
        return VIRP_ERR_CRYPTO;
    chainsign_finish(kp);
    return VIRP_OK;
}

virp_error_t virp_chainsign_save(const virp_chainsign_key_t *kp,
                                 const char *sk_path,
                                 const char *pk_path)
{
    if (!kp || !sk_path || !pk_path) return VIRP_ERR_NULL_PTR;
    if (!kp->loaded) return VIRP_ERR_KEY_NOT_LOADED;

    /* Secret first, 0600 from birth, O_EXCL|O_NOFOLLOW: never a window
     * with wider bits, never over an existing file or planted link. */
    int fd = open(sk_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) {
        fprintf(stderr, "[ChainSign] cannot create %s: %s (existing files "
                        "are never overwritten)\n", sk_path, strerror(errno));
        return VIRP_ERR_KEY_NOT_LOADED;
    }
    ssize_t n = write(fd, kp->secret_key, VIRP_CHAINSIGN_SK_SIZE);
    close(fd);
    if (n != VIRP_CHAINSIGN_SK_SIZE) return VIRP_ERR_KEY_NOT_LOADED;

    fd = open(pk_path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0644);
    if (fd < 0) {
        fprintf(stderr, "[ChainSign] cannot create %s: %s (existing files "
                        "are never overwritten)\n", pk_path, strerror(errno));
        return VIRP_ERR_KEY_NOT_LOADED;
    }
    n = write(fd, kp->public_key, VIRP_CHAINSIGN_PK_SIZE);
    close(fd);
    if (n != VIRP_CHAINSIGN_PK_SIZE) return VIRP_ERR_KEY_NOT_LOADED;
    return VIRP_OK;
}

virp_error_t virp_chainsign_load(virp_chainsign_key_t *kp, const char *sk_path)
{
    if (!kp || !sk_path) return VIRP_ERR_NULL_PTR;
    if (sodium_init() < 0) return VIRP_ERR_CRYPTO;
    memset(kp, 0, sizeof(*kp));

    virp_error_t kerr = virp_keyfile_read(
        sk_path, "[ChainSign] chain-signing secret key", true,
        kp->secret_key, VIRP_CHAINSIGN_SK_SIZE);
    if (kerr != VIRP_OK)
        return kerr;

    /* libsodium sk = seed(32) || pub(32). RE-DERIVE the public half from
     * the seed and cross-check it against the stored half: a file whose
     * two halves disagree is corrupt (or hand-assembled) and must not
     * sign. Note crypto_sign_ed25519_sk_to_pk() would NOT do this — it
     * only copies the stored half — so the derivation goes through
     * crypto_sign_seed_keypair on a scratch key. */
    uint8_t derived_pk[VIRP_CHAINSIGN_PK_SIZE];
    uint8_t derived_sk[VIRP_CHAINSIGN_SK_SIZE];
    int drc = crypto_sign_seed_keypair(derived_pk, derived_sk, kp->secret_key);
    sodium_memzero(derived_sk, VIRP_CHAINSIGN_SK_SIZE);
    if (drc != 0 ||
        sodium_memcmp(derived_pk, kp->secret_key + VIRP_CHAINSIGN_SEED_SIZE,
                      VIRP_CHAINSIGN_PK_SIZE) != 0) {
        fprintf(stderr, "[ChainSign] %s: public half does not match the "
                        "seed — corrupt key file, refusing to load\n", sk_path);
        sodium_memzero(kp->secret_key, VIRP_CHAINSIGN_SK_SIZE);
        return VIRP_ERR_CRYPTO;
    }
    memcpy(kp->public_key, derived_pk, VIRP_CHAINSIGN_PK_SIZE);
    chainsign_finish(kp);
    return VIRP_OK;
}

virp_error_t virp_chainsign_load_public(const char *pk_path,
                                        uint8_t pk[VIRP_CHAINSIGN_PK_SIZE],
                                        char key_id_hex[VIRP_CHAINSIGN_KEYID_HEX])
{
    if (!pk_path || !pk) return VIRP_ERR_NULL_PTR;
    if (sodium_init() < 0) return VIRP_ERR_CRYPTO;

    virp_error_t kerr = virp_keyfile_read(
        pk_path, "[ChainSign] chain-signing public key", false,
        pk, VIRP_CHAINSIGN_PK_SIZE);
    if (kerr != VIRP_OK)
        return kerr;
    if (key_id_hex) virp_chainsign_key_id_hex(pk, key_id_hex);
    return VIRP_OK;
}

/* tag || NUL || msg into buf; returns total length or 0 on refusal. */
static size_t chainsign_input(const char *tag, const void *msg, size_t msg_len,
                              uint8_t *buf, size_t buf_max)
{
    if (!tag || !msg) return 0;
    size_t tlen = strlen(tag) + 1;           /* NUL included, signed */
    if (tlen < 2 || tlen > 64) return 0;
    if (msg_len == 0 || msg_len > buf_max - tlen) return 0;
    memcpy(buf, tag, tlen);
    memcpy(buf + tlen, msg, msg_len);
    return tlen + msg_len;
}

virp_error_t virp_chainsign_sign(const virp_chainsign_key_t *kp,
                                 const char *tag,
                                 const void *msg, size_t msg_len,
                                 uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE])
{
    if (!kp || !tag || !msg || !sig) return VIRP_ERR_NULL_PTR;
    if (!kp->loaded) return VIRP_ERR_KEY_NOT_LOADED;

    uint8_t in[CHAINSIGN_MAX_INPUT];
    size_t n = chainsign_input(tag, msg, msg_len, in, sizeof(in));
    if (n == 0) return VIRP_ERR_INVALID_LENGTH;

    if (crypto_sign_detached(sig, NULL, in, n, kp->secret_key) != 0)
        return VIRP_ERR_CRYPTO;
    return VIRP_OK;
}

bool virp_chainsign_verify(const uint8_t pk[VIRP_CHAINSIGN_PK_SIZE],
                           const char *tag,
                           const void *msg, size_t msg_len,
                           const uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE])
{
    if (!pk || !tag || !msg || !sig) return false;
    if (sodium_init() < 0) return false;

    uint8_t in[CHAINSIGN_MAX_INPUT];
    size_t n = chainsign_input(tag, msg, msg_len, in, sizeof(in));
    if (n == 0) return false;
    return crypto_sign_verify_detached(sig, in, n, pk) == 0;
}

void virp_chainsign_sig_to_hex(const uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE],
                               char out[VIRP_CHAINSIGN_SIG_HEX])
{
    for (int i = 0; i < VIRP_CHAINSIGN_SIG_SIZE; i++)
        snprintf(out + i * 2, 3, "%02x", sig[i]);
    out[VIRP_CHAINSIGN_SIG_HEX - 1] = '\0';
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool virp_chainsign_sig_from_hex(const char *hex,
                                 uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE])
{
    if (!hex || !sig) return false;
    if (strlen(hex) != VIRP_CHAINSIGN_SIG_HEX - 1) return false;
    for (int i = 0; i < VIRP_CHAINSIGN_SIG_SIZE; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        sig[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

virp_error_t virp_chainsign_spki(const virp_chainsign_key_t *kp, uint8_t out[44])
{
    if (!kp || !out) return VIRP_ERR_NULL_PTR;
    if (!kp->loaded) return VIRP_ERR_KEY_NOT_LOADED;
    virp_approver_ed25519_spki(kp->public_key, out);
    return VIRP_OK;
}

void virp_chainsign_destroy(virp_chainsign_key_t *kp)
{
    if (!kp) return;
    sodium_memzero(kp->secret_key, VIRP_CHAINSIGN_SK_SIZE);
    if (kp->locked)
        sodium_munlock(kp->secret_key, VIRP_CHAINSIGN_SK_SIZE);
    memset(kp, 0, sizeof(*kp));
}
