/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Mock PKCS#11 module (test-only)
 *
 * A minimal Cryptoki module exporting just the entry points VIRP's
 * approval signer resolves. It holds ONE fixed P-256 key (embedded PEM
 * below) and signs with CKM_ECDSA, returning raw r||s — exactly what a
 * YubiKey PIV token returns. Built as a shared object so
 * virp_tool_sign_pkcs11() can dlopen it and exercise the full PKCS#11
 * plumbing without hardware. The corresponding public key is enrolled by
 * the test's registry (same fixed key).
 */

#include "pkcs11_min.h"

#include <stdio.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

/* Fixed P-256 private key (matches the SPKI the test enrolls). */
static const char MOCK_KEY_PEM[] =
"-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEICXrWTVj8k/PH/1+QXTdHxnxMexirtDxfvZfaCAmC1qxoAoGCCqGSM49\n"
"AwEHoUQDQgAEUlaSetRmRWfyHZV0CjHUP09tdnESvruJo7n5ZnZ8Wov7B1OMrkI0\n"
"pzOLn8WDLTown1WsdvcEi1BYbbJACMgUNg==\n"
"-----END EC PRIVATE KEY-----\n";

/* Uncompressed EC point (0x04 || X || Y), 65 bytes. */
static const uint8_t MOCK_POINT[65] = {
    0x04,0x52,0x56,0x92,0x7a,0xd4,0x66,0x45,0x67,0xf2,0x1d,0x95,0x74,0x0a,0x31,
    0xd4,0x3f,0x4f,0x6d,0x76,0x71,0x12,0xbe,0xbb,0x89,0xa3,0xb9,0xf9,0x66,0x76,
    0x7c,0x5a,0x8b,0xfb,0x07,0x53,0x8c,0xae,0x42,0x34,0xa7,0x33,0x8b,0x9f,0xc5,
    0x83,0x2d,0x3a,0x30,0x9f,0x55,0xac,0x76,0xf7,0x04,0x8b,0x50,0x58,0x6d,0xb2,
    0x40,0x08,0xc8,0x14,0x36
};
#define MOCK_ID_BYTE 0x02   /* PIV slot 9c */

#define H_PRIV 10UL
#define H_PUB  11UL

static EVP_PKEY *load_key(void)
{
    static EVP_PKEY *k = NULL;
    if (!k) {
        BIO *b = BIO_new_mem_buf(MOCK_KEY_PEM, -1);
        k = PEM_read_bio_PrivateKey(b, NULL, NULL, NULL);
        BIO_free(b);
    }
    return k;
}

CK_RV C_Initialize(CK_VOID_PTR a) { (void)a; return CKR_OK; }
CK_RV C_Finalize(CK_VOID_PTR a) { (void)a; return CKR_OK; }

CK_RV C_GetSlotList(CK_BBOOL present, CK_SLOT_ID *list, CK_ULONG *n)
{
    (void)present;
    if (list && *n >= 1) list[0] = 0;
    *n = 1;
    return CKR_OK;
}

CK_RV C_OpenSession(CK_SLOT_ID s, CK_FLAGS f, CK_VOID_PTR a,
                    CK_NOTIFY nfy, CK_SESSION_HANDLE *h)
{
    (void)s; (void)f; (void)a; (void)nfy;
    *h = 1;
    return CKR_OK;
}
CK_RV C_CloseSession(CK_SESSION_HANDLE h) { (void)h; return CKR_OK; }
CK_RV C_Login(CK_SESSION_HANDLE h, CK_USER_TYPE u, CK_BYTE_PTR p, CK_ULONG l)
{ (void)h; (void)u; (void)p; (void)l; return CKR_OK; }

/* Very small find: return the private or public key handle depending on
 * the CKA_CLASS in the template. */
static CK_OBJECT_CLASS s_find_class;
static int s_find_done;

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE h, CK_ATTRIBUTE *t, CK_ULONG n)
{
    (void)h;
    s_find_class = CKO_PRIVATE_KEY;
    s_find_done = 0;
    for (CK_ULONG i = 0; i < n; i++)
        if (t[i].type == CKA_CLASS && t[i].pValue)
            s_find_class = *(CK_OBJECT_CLASS *)t[i].pValue;
    return CKR_OK;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE *obj,
                    CK_ULONG max, CK_ULONG *count)
{
    (void)h;
    if (s_find_done || max == 0) { *count = 0; return CKR_OK; }
    obj[0] = (s_find_class == CKO_PUBLIC_KEY) ? H_PUB : H_PRIV;
    *count = 1;
    s_find_done = 1;
    return CKR_OK;
}
CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE h) { (void)h; return CKR_OK; }

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE h, CK_OBJECT_HANDLE o,
                          CK_ATTRIBUTE *t, CK_ULONG n)
{
    (void)h; (void)o;
    for (CK_ULONG i = 0; i < n; i++) {
        switch (t[i].type) {
        case CKA_ID: {
            uint8_t id = MOCK_ID_BYTE;
            if (t[i].pValue && t[i].ulValueLen >= 1)
                memcpy(t[i].pValue, &id, 1);
            t[i].ulValueLen = 1;
            break;
        }
        case CKA_KEY_TYPE: {
            CK_KEY_TYPE kt = CKK_EC;
            if (t[i].pValue && t[i].ulValueLen >= sizeof(kt))
                memcpy(t[i].pValue, &kt, sizeof(kt));
            t[i].ulValueLen = sizeof(kt);
            break;
        }
        case CKA_EC_POINT: {
            /* DER OCTET STRING wrapping the 65-byte point. */
            uint8_t der[67];
            der[0] = 0x04; der[1] = 0x41;
            memcpy(der + 2, MOCK_POINT, 65);
            if (t[i].pValue && t[i].ulValueLen >= sizeof(der))
                memcpy(t[i].pValue, der, sizeof(der));
            t[i].ulValueLen = sizeof(der);
            break;
        }
        default:
            t[i].ulValueLen = (CK_ULONG)-1;
            break;
        }
    }
    return CKR_OK;
}

static CK_MECHANISM_TYPE s_mech;

CK_RV C_SignInit(CK_SESSION_HANDLE h, CK_MECHANISM *m, CK_OBJECT_HANDLE k)
{
    (void)h; (void)k;
    s_mech = m ? m->mechanism : 0;
    return CKR_OK;
}

/* Sign the 32-byte hash with the fixed key; output raw r||s (64 bytes).
 * CKM_ECDSA takes a pre-hashed input, so sign the digest directly (no MD)
 * via the OpenSSL 3.0 EVP interface, then convert the DER result to raw
 * r||s — the encoding VIRP's wire format expects. */
CK_RV C_Sign(CK_SESSION_HANDLE h, CK_BYTE_PTR data, CK_ULONG dlen,
             CK_BYTE_PTR sig, CK_ULONG *slen)
{
    (void)h;
    if (s_mech != CKM_ECDSA) return 0x70UL;   /* CKR_MECHANISM_INVALID */
    EVP_PKEY *pk = load_key();
    if (!pk) return 0x05UL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pk, NULL);
    if (!ctx || EVP_PKEY_sign_init(ctx) <= 0) {
        if (ctx) EVP_PKEY_CTX_free(ctx);
        return 0x05UL;
    }
    unsigned char der[80];
    size_t derlen = sizeof(der);
    int ok = EVP_PKEY_sign(ctx, der, &derlen, data, dlen);
    EVP_PKEY_CTX_free(ctx);
    if (ok <= 0) return 0x05UL;

    const unsigned char *p = der;
    ECDSA_SIG *s = d2i_ECDSA_SIG(NULL, &p, (long)derlen);
    if (!s) return 0x05UL;
    const BIGNUM *r, *ss;
    ECDSA_SIG_get0(s, &r, &ss);
    memset(sig, 0, 64);
    BN_bn2binpad(r, sig, 32);
    BN_bn2binpad(ss, sig + 32, 32);
    ECDSA_SIG_free(s);
    *slen = 64;
    return CKR_OK;
}
