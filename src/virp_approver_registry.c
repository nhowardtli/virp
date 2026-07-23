/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Approver key registry (see include/virp_approver_registry.h)
 *
 * Verify-only. Ed25519 via libsodium (matches the signer's primitive);
 * ECDSA-P256 via OpenSSL over a raw r||s 64-byte signature. SPKI is
 * parsed with OpenSSL; the declared key_id/algorithm are cross-checked
 * against the actual key so a mislabeled entry cannot be trusted.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_approver_registry.h"

#include <stdio.h>
#include <string.h>

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "cJSON.h"

/* =========================================================================
 * Algorithm names
 * ========================================================================= */

const char *virp_approver_alg_name(virp_approver_alg_t a)
{
    switch (a) {
    case VIRP_APPROVER_ALG_ED25519:    return "ed25519";
    case VIRP_APPROVER_ALG_ECDSA_P256: return "ecdsa-p256";
    default:                           return "none";
    }
}

virp_approver_alg_t virp_approver_alg_from_name(const char *s)
{
    if (!s) return VIRP_APPROVER_ALG_NONE;
    if (strcmp(s, "ed25519") == 0)    return VIRP_APPROVER_ALG_ED25519;
    if (strcmp(s, "ecdsa-p256") == 0) return VIRP_APPROVER_ALG_ECDSA_P256;
    return VIRP_APPROVER_ALG_NONE;
}

/* =========================================================================
 * Small helpers
 * ========================================================================= */

static void sha256_keyid_hex(const uint8_t *raw, size_t len,
                             char out[VIRP_APPROVER_KEYID_HEX + 1])
{
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(raw, len, md);
    for (int i = 0; i < VIRP_APPROVER_KEYID_HEX / 2; i++)
        snprintf(out + i * 2, 3, "%02x", md[i]);
}

static bool keyid_eq_ci(const char *a, const char *b)
{
    if (!a || !b) return false;
    if (strlen(a) != strlen(b)) return false;
    for (size_t i = 0; a[i]; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return false;
    }
    return true;
}

/* Standard base64 decode (RFC 4648, '=' padding). Returns decoded length
 * or -1 on any invalid character / length. */
static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, uint8_t *out, size_t out_max)
{
    size_t len = strlen(in);
    if (len == 0 || (len % 4) != 0) return -1;
    size_t olen = 0;
    for (size_t i = 0; i < len; i += 4) {
        int pad = 0;
        int v[4];
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') {
                /* padding only in the last group, last one or two slots */
                if (i + 4 < len || j < 2) return -1;
                v[j] = 0; pad++;
            } else {
                int d = b64_val(c);
                if (d < 0) return -1;
                v[j] = d;
            }
        }
        uint32_t acc = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                       ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        int nbytes = 3 - pad;
        if (olen + (size_t)nbytes > out_max) return -1;
        if (nbytes > 0) out[olen++] = (acc >> 16) & 0xff;
        if (nbytes > 1) out[olen++] = (acc >> 8) & 0xff;
        if (nbytes > 2) out[olen++] = acc & 0xff;
    }
    return (int)olen;
}

/* =========================================================================
 * SPKI parsing: DER SubjectPublicKeyInfo -> algorithm + raw pubkey
 * ========================================================================= */

/*
 * Parse spki_der into *alg and raw public-key bytes (ed25519: 32-byte
 * raw key; ecdsa-p256: 65-byte uncompressed point). raw_out must hold
 * at least 65 bytes. Returns VIRP_OK or an error.
 */
static virp_error_t spki_extract(const uint8_t *spki_der, size_t spki_len,
                                 virp_approver_alg_t *alg,
                                 uint8_t *raw_out, size_t *raw_len)
{
    const unsigned char *p = spki_der;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)spki_len);
    if (!pkey)
        return VIRP_ERR_KEY_NOT_LOADED;

    virp_error_t rc = VIRP_ERR_KEY_NOT_LOADED;
    int base_id = EVP_PKEY_base_id(pkey);

    if (base_id == EVP_PKEY_ED25519) {
        size_t n = 32;
        if (EVP_PKEY_get_raw_public_key(pkey, raw_out, &n) == 1 && n == 32) {
            *alg = VIRP_APPROVER_ALG_ED25519;
            *raw_len = 32;
            rc = VIRP_OK;
        }
    } else if (base_id == EVP_PKEY_EC) {
        char grp[64] = {0};
        size_t glen = 0;
        if (EVP_PKEY_get_group_name(pkey, grp, sizeof(grp), &glen) == 1 &&
            (strcmp(grp, "prime256v1") == 0 || strcmp(grp, "P-256") == 0 ||
             strcmp(grp, "secp256r1") == 0)) {
            /* Uncompressed point encoding (0x04 || X || Y) = 65 bytes. */
            uint8_t pt[133];
            size_t ptlen = 0;
            if (EVP_PKEY_get_octet_string_param(
                    pkey, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                    pt, sizeof(pt), &ptlen) == 1 &&
                ptlen == 65 && pt[0] == 0x04) {
                memcpy(raw_out, pt, 65);
                *alg = VIRP_APPROVER_ALG_ECDSA_P256;
                *raw_len = 65;
                rc = VIRP_OK;
            }
        }
    }

    EVP_PKEY_free(pkey);
    return rc;
}

/* =========================================================================
 * Entry parsing
 * ========================================================================= */

/* Parse from a cJSON object (loader uses this directly; parse_entry wraps
 * it with a string parse). */
static virp_error_t parse_entry_cjson(cJSON *o, virp_approver_t *out)
{
    if (!o || !out)
        return VIRP_ERR_NULL_PTR;

    memset(out, 0, sizeof(*out));

    cJSON *j_kid = cJSON_GetObjectItemCaseSensitive(o, "key_id");
    cJSON *j_alg = cJSON_GetObjectItemCaseSensitive(o, "algorithm");
    cJSON *j_pk  = cJSON_GetObjectItemCaseSensitive(o, "public_key");
    cJSON *j_op  = cJSON_GetObjectItemCaseSensitive(o, "operator");
    cJSON *j_en  = cJSON_GetObjectItemCaseSensitive(o, "enabled");

    if (!cJSON_IsString(j_kid) || !cJSON_IsString(j_alg) ||
        !cJSON_IsString(j_pk))
        return VIRP_ERR_INVALID_TYPE;

    virp_approver_alg_t declared_alg =
        virp_approver_alg_from_name(j_alg->valuestring);
    if (declared_alg == VIRP_APPROVER_ALG_NONE)
        return VIRP_ERR_ALGORITHM_MISMATCH;

    uint8_t spki[VIRP_APPROVER_SPKI_MAX];
    int spki_len = b64_decode(j_pk->valuestring, spki, sizeof(spki));
    if (spki_len <= 0)
        return VIRP_ERR_KEY_NOT_LOADED;

    virp_approver_alg_t parsed_alg = VIRP_APPROVER_ALG_NONE;
    uint8_t raw[65];
    size_t raw_len = 0;
    virp_error_t perr = spki_extract(spki, (size_t)spki_len,
                                     &parsed_alg, raw, &raw_len);
    if (perr != VIRP_OK)
        return perr;

    /* Declared algorithm must match the actual key. */
    if (parsed_alg != declared_alg)
        return VIRP_ERR_ALGORITHM_MISMATCH;

    /* Derive key_id and require it match the declared one. */
    char derived[VIRP_APPROVER_KEYID_HEX + 1];
    sha256_keyid_hex(raw, raw_len, derived);
    if (!keyid_eq_ci(derived, j_kid->valuestring))
        return VIRP_ERR_CONTEXT_MISMATCH;

    snprintf(out->key_id, sizeof(out->key_id), "%s", derived);
    out->alg = parsed_alg;
    memcpy(out->spki_der, spki, (size_t)spki_len);
    out->spki_der_len = (size_t)spki_len;
    if (parsed_alg == VIRP_APPROVER_ALG_ED25519)
        memcpy(out->ed_pub, raw, 32);
    if (cJSON_IsString(j_op))
        snprintf(out->operator, sizeof(out->operator), "%s", j_op->valuestring);
    out->enabled = cJSON_IsBool(j_en) ? cJSON_IsTrue(j_en) : false;

    return VIRP_OK;
}

virp_error_t virp_approver_parse_entry(const char *json_obj,
                                       virp_approver_t *out)
{
    if (!json_obj || !out)
        return VIRP_ERR_NULL_PTR;
    cJSON *o = cJSON_Parse(json_obj);
    if (!o || !cJSON_IsObject(o)) {
        if (o) cJSON_Delete(o);
        return VIRP_ERR_INVALID_TYPE;
    }
    virp_error_t rc = parse_entry_cjson(o, out);
    cJSON_Delete(o);
    return rc;
}

/* =========================================================================
 * Load
 * ========================================================================= */

virp_error_t virp_approver_registry_load(virp_approver_registry_t *reg,
                                         const char *path)
{
    if (!reg || !path)
        return VIRP_ERR_NULL_PTR;
    memset(reg, 0, sizeof(*reg));

    FILE *f = fopen(path, "rb");
    if (!f)
        return VIRP_ERR_CHAIN_DB;
    char buf[64 * 1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    int overflow = !feof(f);
    fclose(f);
    if (overflow)
        return VIRP_ERR_MESSAGE_TOO_LARGE;
    buf[n] = '\0';

    cJSON *arr = cJSON_Parse(buf);
    if (!arr || !cJSON_IsArray(arr)) {
        if (arr) cJSON_Delete(arr);
        return VIRP_ERR_CHAIN_DB;
    }

    cJSON *item = NULL;
    cJSON_ArrayForEach(item, arr) {
        if (reg->count >= VIRP_APPROVERS_MAX) {
            fprintf(stderr, "[APPROVERS] registry full (%d) — extra entries "
                    "ignored\n", VIRP_APPROVERS_MAX);
            break;
        }
        if (!cJSON_IsObject(item))
            continue;
        virp_approver_t e;
        virp_error_t rc = parse_entry_cjson(item, &e);
        if (rc != VIRP_OK) {
            fprintf(stderr, "[APPROVERS] skipping malformed entry: %s\n",
                    virp_error_str(rc));
            continue;
        }
        if (virp_approver_registry_find_any(reg, e.key_id)) {
            fprintf(stderr, "[APPROVERS] duplicate key_id %s — later entry "
                    "ignored\n", e.key_id);
            continue;
        }
        reg->entries[reg->count++] = e;
        fprintf(stderr, "[APPROVERS] enrolled key_id=%s alg=%s operator=%s "
                "%s\n", e.key_id, virp_approver_alg_name(e.alg),
                e.operator[0] ? e.operator : "(none)",
                e.enabled ? "ENABLED" : "disabled");
    }
    cJSON_Delete(arr);
    return VIRP_OK;
}

/* =========================================================================
 * Lookup
 * ========================================================================= */

const virp_approver_t *virp_approver_registry_find_any(
        const virp_approver_registry_t *reg, const char *key_id)
{
    if (!reg || !key_id) return NULL;
    for (size_t i = 0; i < reg->count; i++)
        if (keyid_eq_ci(reg->entries[i].key_id, key_id))
            return &reg->entries[i];
    return NULL;
}

const virp_approver_t *virp_approver_registry_find(
        const virp_approver_registry_t *reg, const char *key_id)
{
    const virp_approver_t *e = virp_approver_registry_find_any(reg, key_id);
    return (e && e->enabled) ? e : NULL;
}

/* =========================================================================
 * Verify
 * ========================================================================= */

/* raw r||s (64) -> ECDSA_SIG (caller frees). NULL on failure. */
static ECDSA_SIG *raw_to_ecdsa_sig(const uint8_t *sig, size_t sig_len)
{
    if (sig_len != 64) return NULL;
    BIGNUM *r = BN_bin2bn(sig, 32, NULL);
    BIGNUM *s = BN_bin2bn(sig + 32, 32, NULL);
    if (!r || !s) { BN_free(r); BN_free(s); return NULL; }
    ECDSA_SIG *es = ECDSA_SIG_new();
    if (!es) { BN_free(r); BN_free(s); return NULL; }
    if (ECDSA_SIG_set0(es, r, s) != 1) {   /* takes ownership of r,s */
        BN_free(r); BN_free(s); ECDSA_SIG_free(es); return NULL;
    }
    return es;
}

static virp_error_t verify_ecdsa_p256(const virp_approver_t *e,
                                      const uint8_t *data, size_t len,
                                      const uint8_t *sig, size_t sig_len)
{
    const unsigned char *p = e->spki_der;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)e->spki_der_len);
    if (!pkey)
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;

    ECDSA_SIG *es = raw_to_ecdsa_sig(sig, sig_len);
    if (!es) { EVP_PKEY_free(pkey); return VIRP_ERR_APPROVAL_BAD_SIGNATURE; }

    unsigned char der[80];
    unsigned char *dp = der;
    int derlen = i2d_ECDSA_SIG(es, &dp);
    ECDSA_SIG_free(es);
    if (derlen <= 0) { EVP_PKEY_free(pkey); return VIRP_ERR_APPROVAL_BAD_SIGNATURE; }

    virp_error_t rc = VIRP_ERR_APPROVAL_BAD_SIGNATURE;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx &&
        EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerify(ctx, der, (size_t)derlen, data, len) == 1)
        rc = VIRP_OK;
    if (ctx) EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return rc;
}

virp_error_t virp_approver_verify(const virp_approver_t *e,
                                  const uint8_t *data, size_t len,
                                  const uint8_t *sig, size_t sig_len)
{
    if (!e || !data || !sig)
        return VIRP_ERR_NULL_PTR;

    switch (e->alg) {
    case VIRP_APPROVER_ALG_ED25519:
        if (sig_len != 64)
            return VIRP_ERR_APPROVAL_BAD_SIGNATURE;
        return (crypto_sign_verify_detached(sig, data, len, e->ed_pub) == 0)
               ? VIRP_OK : VIRP_ERR_APPROVAL_BAD_SIGNATURE;
    case VIRP_APPROVER_ALG_ECDSA_P256:
        return verify_ecdsa_p256(e, data, len, sig, sig_len);
    default:
        return VIRP_ERR_APPROVAL_BAD_SIGNATURE;
    }
}

/* =========================================================================
 * Enrollment helpers
 * ========================================================================= */

/* Standard Ed25519 SubjectPublicKeyInfo DER prefix (12 bytes). */
static const uint8_t ED25519_SPKI_PREFIX[12] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
};

void virp_approver_ed25519_spki(const uint8_t pub[32], uint8_t out[44])
{
    memcpy(out, ED25519_SPKI_PREFIX, 12);
    memcpy(out + 12, pub, 32);
}

static int b64_encode(const uint8_t *in, size_t len, char *out, size_t out_max)
{
    static const char A[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t need = ((len + 2) / 3) * 4 + 1;
    if (need > out_max) return -1;
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t acc = (uint32_t)in[i] << 16;
        int rem = (int)(len - i);
        if (rem > 1) acc |= (uint32_t)in[i + 1] << 8;
        if (rem > 2) acc |= (uint32_t)in[i + 2];
        out[o++] = A[(acc >> 18) & 0x3f];
        out[o++] = A[(acc >> 12) & 0x3f];
        out[o++] = rem > 1 ? A[(acc >> 6) & 0x3f] : '=';
        out[o++] = rem > 2 ? A[acc & 0x3f] : '=';
    }
    out[o] = '\0';
    return (int)o;
}

virp_error_t virp_approver_entry_json(const uint8_t *spki_der, size_t spki_len,
                                      const char *operator, bool enabled,
                                      char *out, size_t out_len)
{
    if (!spki_der || !out)
        return VIRP_ERR_NULL_PTR;

    virp_approver_alg_t alg = VIRP_APPROVER_ALG_NONE;
    uint8_t raw[65];
    size_t raw_len = 0;
    virp_error_t rc = spki_extract(spki_der, spki_len, &alg, raw, &raw_len);
    if (rc != VIRP_OK)
        return rc;

    char key_id[VIRP_APPROVER_KEYID_HEX + 1];
    sha256_keyid_hex(raw, raw_len, key_id);

    char b64[VIRP_APPROVER_SPKI_MAX * 2];
    if (b64_encode(spki_der, spki_len, b64, sizeof(b64)) < 0)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    int n = snprintf(out, out_len,
        "{\"key_id\":\"%s\",\"algorithm\":\"%s\",\"public_key\":\"%s\","
        "\"operator\":\"%s\",\"enabled\":%s}",
        key_id, virp_approver_alg_name(alg), b64,
        operator ? operator : "", enabled ? "true" : "false");
    if (n < 0 || (size_t)n >= out_len)
        return VIRP_ERR_BUFFER_TOO_SMALL;
    return VIRP_OK;
}
