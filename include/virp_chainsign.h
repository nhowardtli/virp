/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Chain-signing key (D-1: detached Ed25519 chain signatures)
 *
 * The per-node Ed25519 keypair whose DETACHED signatures ride beside
 * every chain entry and head a node appends after D-1 deploys. It is
 * the SIXTH key role in the tree and is distinct from every other one:
 *
 *   O-Key / R-Key   symmetric HMAC, observation / intent channels
 *   K_chain         symmetric HMAC over the chain canonical (unchanged)
 *   approval        Ed25519/P-256, secret OFF-box with a human approver
 *   obskey          Ed25519, signs v3 OBSERVATION bodies
 *   chain-signing   Ed25519, signs chain ENTRY and HEAD canonicals (this)
 *
 * WHAT IT BUYS. K_chain's HMAC proves integrity only to a K_chain holder,
 * and a K_chain holder can mint as well as verify. A chain-signing
 * signature proves the same canonical bytes to anyone holding the PUBLIC
 * half, who cannot mint. That opens independent verification of every
 * session created after the cut-over, without handing out any secret.
 *
 * WHAT IT DOES NOT CHANGE — THE INVARIANT. The canonical bytes, the
 * SHA-256 entry hash, the K_chain HMAC, the head canonical and the
 * genesis rule are byte-identical to the pre-D-1 tree. The signature is
 * computed over the SAME canonical bytes the daemon already hashes and
 * HMACs, prefixed (in the signature input only — never stored, never
 * part of the canonical) with a domain tag, and stored in columns no
 * pre-D-1 code reads. Strip the signature columns and you have exactly
 * the old chain, not a broken one. Locked by tests/test_chain_invariant.c.
 *
 * DOMAIN SEPARATION. One key signs two object kinds, so the signature
 * input is tagged:
 *
 *     entry:  "VIRP-CHAIN-ENTRY-SIG-v1" NUL || build_canonical_json bytes
 *     head:   "VIRP-CHAIN-HEAD-SIG-v1"  NUL || head_canonical bytes
 *
 * The NUL is part of the signed input (the VIRP-TYPED-OP convention).
 * The tags differ at byte 11, so no byte string is both a tagged entry
 * and a tagged head: an entry signature can never validate as a head
 * signature or vice versa. Separation from the obskey and approval keys
 * is by distinct keys; additionally no v3 observation (byte 0 = 0x03)
 * or approval canonical starts with "VIRP-CHAIN-".
 *
 * key_id = SHA-256(public_key)[0:16] ("sha256-raw-16"), the same
 * convention as the obskey, the approver registry and the seal.
 *
 * CUSTODY mirrors the obskey (the daemon is the attester, so the secret
 * lives on the daemon host): secret file must be a regular file, mode
 * 0600/0400, owned by euid (or euid is root), exactly 64 bytes
 * (libsodium seed||pub); mlocked while loaded; zeroised on destroy;
 * never logged or exported. Only the public half is exportable.
 *
 * Golden vectors: tests/vectors/chain-signing-v1.json.
 */

#ifndef VIRP_CHAINSIGN_H
#define VIRP_CHAINSIGN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "virp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VIRP_CHAINSIGN_PK_SIZE     32   /* crypto_sign_PUBLICKEYBYTES  */
#define VIRP_CHAINSIGN_SK_SIZE     64   /* crypto_sign_SECRETKEYBYTES  */
#define VIRP_CHAINSIGN_SEED_SIZE   32   /* crypto_sign_SEEDBYTES       */
#define VIRP_CHAINSIGN_SIG_SIZE    64   /* crypto_sign_BYTES           */
#define VIRP_CHAINSIGN_KEYID_SIZE  16   /* SHA-256(public_key)[:16]    */
#define VIRP_CHAINSIGN_KEYID_HEX   33   /* 32 hex chars + NUL          */
#define VIRP_CHAINSIGN_SIG_HEX     129  /* 128 hex chars + NUL         */

/* Domain tags. sizeof() includes the NUL, and the NUL IS signed. */
#define VIRP_CHAINSIGN_TAG_ENTRY   "VIRP-CHAIN-ENTRY-SIG-v1"
#define VIRP_CHAINSIGN_TAG_HEAD    "VIRP-CHAIN-HEAD-SIG-v1"

/* Storage-level scheme label (the C tree is era-agnostic; era labels
 * belong to the bundle layer). */
#define VIRP_CHAINSIGN_SCHEME      "ed25519-detached-v1"

typedef struct {
    uint8_t public_key[VIRP_CHAINSIGN_PK_SIZE];
    uint8_t secret_key[VIRP_CHAINSIGN_SK_SIZE];
    uint8_t key_id[VIRP_CHAINSIGN_KEYID_SIZE];
    char    key_id_hex[VIRP_CHAINSIGN_KEYID_HEX];
    bool    loaded;
    bool    locked;      /* secret key is sodium_mlock'd */
} virp_chainsign_key_t;

/* Generate a fresh keypair in memory (mlocks the secret). */
virp_error_t virp_chainsign_generate(virp_chainsign_key_t *kp);

/*
 * Derive a keypair from a 32-byte seed. For TEST VECTORS and interop
 * checks only — a production key is generated, never derived from a
 * value that exists anywhere else.
 */
virp_error_t virp_chainsign_from_seed(virp_chainsign_key_t *kp,
                                      const uint8_t seed[VIRP_CHAINSIGN_SEED_SIZE]);

/*
 * Write secret (0600) and public (0644) key files, both O_EXCL|O_NOFOLLOW:
 * an existing file or planted symlink refuses the save. Regenerating into
 * an existing prefix is unsupported — remove both files first.
 */
virp_error_t virp_chainsign_save(const virp_chainsign_key_t *kp,
                                 const char *sk_path,
                                 const char *pk_path);

/*
 * Load the SECRET key file; derives public key + key_id. Refuses symlinks,
 * non-regular files, group/world-accessible modes and wrong owner
 * (VIRP_ERR_KEY_NOT_LOADED); any size other than 64 bytes
 * (VIRP_ERR_INVALID_LENGTH).
 */
virp_error_t virp_chainsign_load(virp_chainsign_key_t *kp, const char *sk_path);

/*
 * Load a PUBLIC key file (exactly 32 raw bytes) into pk[] and fill
 * key_id_hex. No secret material is touched or required — this is the
 * verifier's entry point. Refuses symlinks and non-regular files; mode
 * bits are not checked (the content is public).
 */
virp_error_t virp_chainsign_load_public(const char *pk_path,
                                        uint8_t pk[VIRP_CHAINSIGN_PK_SIZE],
                                        char key_id_hex[VIRP_CHAINSIGN_KEYID_HEX]);

/* key_id = SHA-256(pk)[0:16]; hex form is 32 lowercase chars. */
void virp_chainsign_key_id(const uint8_t pk[VIRP_CHAINSIGN_PK_SIZE],
                           uint8_t key_id[VIRP_CHAINSIGN_KEYID_SIZE]);
void virp_chainsign_key_id_hex(const uint8_t pk[VIRP_CHAINSIGN_PK_SIZE],
                               char out[VIRP_CHAINSIGN_KEYID_HEX]);

/*
 * Detached signature over  tag || NUL || msg.  `tag` is one of the
 * VIRP_CHAINSIGN_TAG_* strings; its terminating NUL is included in the
 * signed input. msg is the UNCHANGED canonical bytes. Fails closed on
 * any error (VIRP_ERR_KEY_NOT_LOADED, VIRP_ERR_INVALID_LENGTH,
 * VIRP_ERR_CRYPTO) — a caller that has signing enabled must treat a
 * failure here as an append failure, never as "store unsigned".
 */
virp_error_t virp_chainsign_sign(const virp_chainsign_key_t *kp,
                                 const char *tag,
                                 const void *msg, size_t msg_len,
                                 uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE]);

/*
 * Verify a detached signature over tag || NUL || msg under a PUBLIC key.
 * Requires no secret material. Returns true only on a valid signature;
 * every failure (bad args, oversize, mismatch) is false.
 */
bool virp_chainsign_verify(const uint8_t pk[VIRP_CHAINSIGN_PK_SIZE],
                           const char *tag,
                           const void *msg, size_t msg_len,
                           const uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE]);

/* Hex helpers for the stored (TEXT) forms. hex_decode returns false on
 * any malformed input (wrong length, non-hex). */
void virp_chainsign_sig_to_hex(const uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE],
                               char out[VIRP_CHAINSIGN_SIG_HEX]);
bool virp_chainsign_sig_from_hex(const char *hex,
                                 uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE]);

/* Export the public key as DER SubjectPublicKeyInfo (44 bytes). */
virp_error_t virp_chainsign_spki(const virp_chainsign_key_t *kp, uint8_t out[44]);

/* Zeroise (sodium_memzero) and unlock the secret key. */
void virp_chainsign_destroy(virp_chainsign_key_t *kp);

#ifdef __cplusplus
}
#endif

#endif /* VIRP_CHAINSIGN_H */
