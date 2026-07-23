/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Approver key registry — enrolled public keys that may sign approvals.
 *
 * Replaces the single approval.pub with an enrolled-key model. The
 * daemon reads /etc/virp/approvers.json at startup; approval
 * verification looks an entry up by key_id and dispatches on algorithm.
 *
 * approvers.json is a JSON array of:
 *   {
 *     "key_id":     "<32 lowercase hex>",   // SHA-256(raw pubkey)[:16]
 *     "algorithm":  "ed25519" | "ecdsa-p256",
 *     "public_key": "<base64 SubjectPublicKeyInfo (DER)>",
 *     "operator":   "<human identifier>",
 *     "enabled":    true|false
 *   }
 *
 * The stated key_id and algorithm are cross-checked against the parsed
 * public_key: an entry whose declared key_id/algorithm does not match
 * the actual SPKI is rejected at load (misconfiguration, not trusted).
 *
 * key_id is uniformly SHA-256(raw public key bytes)[:16] in hex, where
 * the raw bytes are the 32-byte Ed25519 public key or the 65-byte
 * uncompressed EC point (0x04 || X || Y). This makes an Ed25519 key's
 * registry key_id identical to the value virp_fed_compute_key_id()
 * produces, so keys enrolled from the old single-key path line up.
 *
 * Verification is verify-only: no secret material ever enters the
 * daemon. Ed25519 uses libsodium (same primitive as the signer);
 * ECDSA-P256 uses OpenSSL over a fixed raw r||s (64-byte) signature
 * encoding — see docs/APPROVAL-FLOW.md for the wire choice.
 */

#ifndef VIRP_APPROVER_REGISTRY_H
#define VIRP_APPROVER_REGISTRY_H

#include "virp.h"

#define VIRP_APPROVERS_MAX          32
#define VIRP_APPROVER_KEYID_HEX     32   /* SHA-256(pubkey)[:16] in hex */
#define VIRP_APPROVER_OPERATOR_MAX  64
#define VIRP_APPROVER_SPKI_MAX      256  /* DER SubjectPublicKeyInfo */
#define VIRP_APPROVER_SIG_SIZE      64   /* ed25519 sig; ECDSA raw r||s */

typedef enum {
    VIRP_APPROVER_ALG_NONE     = 0,
    VIRP_APPROVER_ALG_ED25519  = 1,
    VIRP_APPROVER_ALG_ECDSA_P256 = 2
} virp_approver_alg_t;

typedef struct {
    char                 key_id[VIRP_APPROVER_KEYID_HEX + 1];
    virp_approver_alg_t  alg;
    uint8_t              ed_pub[32];     /* valid iff alg == ED25519 */
    uint8_t              spki_der[VIRP_APPROVER_SPKI_MAX];
    size_t               spki_der_len;
    char                 operator[VIRP_APPROVER_OPERATOR_MAX];
    bool                 enabled;
} virp_approver_t;

typedef struct {
    virp_approver_t entries[VIRP_APPROVERS_MAX];
    size_t          count;
} virp_approver_registry_t;

/* Algorithm name <-> enum. */
const char         *virp_approver_alg_name(virp_approver_alg_t a);
virp_approver_alg_t virp_approver_alg_from_name(const char *s);

/*
 * Load approvers.json into *reg. Malformed entries (bad base64, SPKI
 * that will not parse, declared key_id/algorithm inconsistent with the
 * key material, unknown algorithm) are logged and SKIPPED — one bad
 * entry never disables the rest. Returns VIRP_OK if the file parsed as
 * a JSON array (even if zero entries survived); VIRP_ERR_CHAIN_DB if the
 * file is unreadable or not a JSON array. Duplicate key_ids: first wins,
 * later ones skipped.
 */
virp_error_t virp_approver_registry_load(virp_approver_registry_t *reg,
                                         const char *path);

/*
 * Parse a single approver from a JSON object string (used by the loader
 * and by tests to build a registry without touching disk). Fills *out.
 * Returns VIRP_OK or an error describing why the entry is unusable.
 */
virp_error_t virp_approver_parse_entry(const char *json_obj,
                                       virp_approver_t *out);

/*
 * Look up by key_id. _find returns only ENABLED entries (NULL if absent
 * or disabled); _find_any returns the entry regardless of enabled, so a
 * caller can distinguish "unenrolled" from "disabled". key_id match is
 * case-insensitive on hex.
 */
const virp_approver_t *virp_approver_registry_find(
        const virp_approver_registry_t *reg, const char *key_id);
const virp_approver_t *virp_approver_registry_find_any(
        const virp_approver_registry_t *reg, const char *key_id);

/*
 * Verify sig (VIRP_APPROVER_SIG_SIZE bytes) over data[0..len) with the
 * entry's key, dispatching on entry->alg. ECDSA-P256 signatures are the
 * raw r||s encoding (each 32 bytes). Returns VIRP_OK on a good
 * signature, VIRP_ERR_APPROVAL_BAD_SIGNATURE otherwise.
 */
virp_error_t virp_approver_verify(const virp_approver_t *e,
                                  const uint8_t *data, size_t len,
                                  const uint8_t *sig, size_t sig_len);

/* =========================================================================
 * Enrollment helpers (build registry entries from public keys)
 * ========================================================================= */

/* Wrap a raw 32-byte Ed25519 public key as its 44-byte DER SPKI. */
void virp_approver_ed25519_spki(const uint8_t pub[32], uint8_t out[44]);

/*
 * Build a one-line approvers.json entry (a JSON object) for the public
 * key given as DER SPKI. Computes key_id = SHA-256(raw pubkey)[:16] and
 * the algorithm from the key itself. Returns VIRP_OK, or an error if the
 * SPKI is not a supported key type. Used by tests and the `virp enroll`
 * helper so operators never hand-compute key_id.
 */
virp_error_t virp_approver_entry_json(const uint8_t *spki_der, size_t spki_len,
                                      const char *operator, bool enabled,
                                      char *out, size_t out_len);

#endif /* VIRP_APPROVER_REGISTRY_H */
