/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — PKCS#11 approval signer (YubiKey PIV via OpenSC, etc.)
 *
 * Compiled into virp-tool only when built with VIRP_PKCS11 (see
 * `make virp-tool-pkcs11`). Signs the 72-byte canonical approval payload
 * on a hardware token and returns the raw r||s (ECDSA-P256) or 64-byte
 * (Ed25519) signature plus the key_id, so the daemon can verify against
 * its approver registry.
 *
 * Signature encodings match the wire choice in docs/APPROVAL-FLOW.md:
 * ECDSA-P256 → raw r||s (64 bytes), which is exactly what CKM_ECDSA
 * returns. For CKM_ECDSA the client pre-hashes (SHA-256) the canonical
 * bytes; Ed25519 (CKM_EDDSA) signs the canonical bytes directly.
 *
 * The PIN is read from the terminal (getpass), NEVER from argv. The
 * client prints "touch your key" and blocks in C_Sign for the touch
 * policy (PIV slot 9c should be enrolled touch-policy ALWAYS).
 *
 * NOTE: real-hardware exercise is out of scope in the build container
 * (no token, no opensc-pkcs11.so). This path is validated with a mock
 * PKCS#11 module (tests/mock_pkcs11.c) that drives the same API.
 */

#define _GNU_SOURCE           /* getpass */
#include "pkcs11_min.h"
#include "virp_approver_registry.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

struct ck {
    void *dl;
    CK_C_Initialize        Initialize;
    CK_C_Finalize          Finalize;
    CK_C_GetSlotList       GetSlotList;
    CK_C_OpenSession       OpenSession;
    CK_C_CloseSession      CloseSession;
    CK_C_Login             Login;
    CK_C_FindObjectsInit   FindObjectsInit;
    CK_C_FindObjects       FindObjects;
    CK_C_FindObjectsFinal  FindObjectsFinal;
    CK_C_GetAttributeValue GetAttributeValue;
    CK_C_SignInit          SignInit;
    CK_C_Sign              Sign;
};

static int load_syms(struct ck *c, const char *module)
{
    c->dl = dlopen(module, RTLD_NOW | RTLD_LOCAL);
    if (!c->dl) {
        fprintf(stderr, "Error: cannot dlopen %s: %s\n", module, dlerror());
        return -1;
    }
    /* dlsym returns void*; converting to a function pointer directly trips
     * -pedantic, so copy the bits. POSIX guarantees this round-trips. */
#define SYM(field, name) do { \
        void *p_ = dlsym(c->dl, name); \
        if (!p_) { fprintf(stderr, "Error: %s missing %s\n", module, name); \
                   return -1; } \
        memcpy(&c->field, &p_, sizeof(p_)); \
    } while (0)
    SYM(Initialize, "C_Initialize");
    SYM(Finalize, "C_Finalize");
    SYM(GetSlotList, "C_GetSlotList");
    SYM(OpenSession, "C_OpenSession");
    SYM(CloseSession, "C_CloseSession");
    SYM(Login, "C_Login");
    SYM(FindObjectsInit, "C_FindObjectsInit");
    SYM(FindObjects, "C_FindObjects");
    SYM(FindObjectsFinal, "C_FindObjectsFinal");
    SYM(GetAttributeValue, "C_GetAttributeValue");
    SYM(SignInit, "C_SignInit");
    SYM(Sign, "C_Sign");
#undef SYM
    return 0;
}

/* Map a PIV slot name (9a/9c/9d/9e) to its CKA_ID byte; -1 if not a PIV
 * slot name. */
static int piv_slot_id(const char *slot)
{
    if (!slot) return -1;
    if (strcmp(slot, "9a") == 0) return 0x01;
    if (strcmp(slot, "9c") == 0) return 0x02;
    if (strcmp(slot, "9d") == 0) return 0x03;
    if (strcmp(slot, "9e") == 0) return 0x04;
    return -1;
}

/* key_id = SHA-256(raw pubkey)[:16] hex, from a CKA_EC_POINT value
 * (a DER OCTET STRING wrapping the point/key). */
static int keyid_from_ec_point(const uint8_t *der, size_t der_len,
                               char key_id_out[33])
{
    /* OCTET STRING: 0x04 <len> <bytes>. Handle short and long form. */
    if (der_len < 2 || der[0] != 0x04) return -1;
    size_t off = 2, plen = der[1];
    if (der[1] & 0x80) {
        size_t nlen = der[1] & 0x7f;
        if (nlen == 0 || nlen > 2 || der_len < 2 + nlen) return -1;
        plen = 0;
        for (size_t i = 0; i < nlen; i++) plen = (plen << 8) | der[2 + i];
        off = 2 + nlen;
    }
    if (off + plen != der_len) return -1;
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(der + off, plen, md);
    for (int i = 0; i < 16; i++)
        snprintf(key_id_out + i * 2, 3, "%02x", md[i]);
    return 0;
}

int virp_tool_sign_pkcs11(const char *module, const char *slot,
                          const char *label,
                          const uint8_t *canon, size_t len,
                          uint8_t sig[VIRP_APPROVER_SIG_SIZE],
                          char key_id_out[33])
{
    struct ck c;
    memset(&c, 0, sizeof(c));
    if (load_syms(&c, module) != 0) { if (c.dl) dlclose(c.dl); return -1; }

    int rc = -1;
    CK_SESSION_HANDLE sess = 0;
    if (c.Initialize(NULL) != CKR_OK) {
        fprintf(stderr, "Error: C_Initialize failed\n");
        goto out;
    }

    CK_SLOT_ID slots[32];
    CK_ULONG nslots = 32;
    if (c.GetSlotList(CK_TRUE, slots, &nslots) != CKR_OK || nslots == 0) {
        fprintf(stderr, "Error: no PKCS#11 token present\n");
        goto out;
    }

    /* Open a session on the first token that yields a usable private key. */
    int want_id = piv_slot_id(slot);
    CK_OBJECT_HANDLE privk = 0, pubk = 0;
    for (CK_ULONG s = 0; s < nslots && !privk; s++) {
        if (c.OpenSession(slots[s], CKF_SERIAL_SESSION, NULL, NULL, &sess)
                != CKR_OK)
            continue;

        /* PIN from the terminal (getpass), NEVER argv. VIRP_PKCS11_PIN is
         * an automation/test hook (e.g. CI, the mock module) — an env
         * var, still not a command-line argument. */
        char *pin = getenv("VIRP_PKCS11_PIN");
        if (!pin) pin = getpass("PIV PIN: ");
        if (pin && pin[0]) {
            CK_RV lr = c.Login(sess, CKU_USER, (CK_BYTE_PTR)pin, strlen(pin));
            if (lr != CKR_OK && lr != CKR_USER_ALREADY_LOGGED_IN) {
                fprintf(stderr, "Error: C_Login failed (PIN?)\n");
                c.CloseSession(sess); sess = 0; continue;
            }
        }

        /* Find the signing private key: by CKA_LABEL if given, else by the
         * PIV slot's CKA_ID, else the first private key on the token. */
        CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE tmpl[3];
        CK_ULONG nt = 0;
        tmpl[nt].type = CKA_CLASS; tmpl[nt].pValue = &cls;
        tmpl[nt].ulValueLen = sizeof(cls); nt++;
        CK_BYTE idbyte = (CK_BYTE)want_id;
        if (label) {
            tmpl[nt].type = CKA_LABEL; tmpl[nt].pValue = (void *)label;
            tmpl[nt].ulValueLen = strlen(label); nt++;
        } else if (want_id >= 0) {
            tmpl[nt].type = CKA_ID; tmpl[nt].pValue = &idbyte;
            tmpl[nt].ulValueLen = 1; nt++;
        }
        if (c.FindObjectsInit(sess, tmpl, nt) == CKR_OK) {
            CK_ULONG found = 0;
            c.FindObjects(sess, &privk, 1, &found);
            c.FindObjectsFinal(sess);
            if (found == 0) privk = 0;
        }
        if (!privk) { c.CloseSession(sess); sess = 0; }
    }
    if (!privk) {
        fprintf(stderr, "Error: no matching private key on token "
                "(slot=%s label=%s)\n", slot ? slot : "?",
                label ? label : "(none)");
        goto out;
    }

    /* Locate the matching public key (same CKA_ID) to read CKA_KEY_TYPE
     * and CKA_EC_POINT (for key_id). */
    {
        CK_BYTE keyid[64];
        CK_ATTRIBUTE idq = { CKA_ID, keyid, sizeof(keyid) };
        CK_KEY_TYPE ktype = 0;
        if (c.GetAttributeValue(sess, privk, &idq, 1) != CKR_OK) {
            fprintf(stderr, "Error: cannot read private key CKA_ID\n");
            goto out;
        }
        CK_OBJECT_CLASS pcls = CKO_PUBLIC_KEY;
        CK_ATTRIBUTE ptmpl[2] = {
            { CKA_CLASS, &pcls, sizeof(pcls) },
            { CKA_ID, keyid, idq.ulValueLen },
        };
        if (c.FindObjectsInit(sess, ptmpl, 2) == CKR_OK) {
            CK_ULONG found = 0;
            c.FindObjects(sess, &pubk, 1, &found);
            c.FindObjectsFinal(sess);
            if (found == 0) pubk = 0;
        }
        if (!pubk) {
            fprintf(stderr, "Error: no public key object for key_id\n");
            goto out;
        }
        CK_ATTRIBUTE ktq = { CKA_KEY_TYPE, &ktype, sizeof(ktype) };
        if (c.GetAttributeValue(sess, pubk, &ktq, 1) != CKR_OK) {
            fprintf(stderr, "Error: cannot read CKA_KEY_TYPE\n");
            goto out;
        }

        CK_BYTE ecp[256];
        CK_ATTRIBUTE ecq = { CKA_EC_POINT, ecp, sizeof(ecp) };
        if (c.GetAttributeValue(sess, pubk, &ecq, 1) != CKR_OK ||
            keyid_from_ec_point(ecp, ecq.ulValueLen, key_id_out) != 0) {
            fprintf(stderr, "Error: cannot derive key_id from CKA_EC_POINT\n");
            goto out;
        }

        /* Choose mechanism + input by key type. */
        CK_MECHANISM mech;
        memset(&mech, 0, sizeof(mech));
        const uint8_t *to_sign = canon;
        size_t to_sign_len = len;
        uint8_t hash[SHA256_DIGEST_LENGTH];
        if (ktype == CKK_EC) {
            mech.mechanism = CKM_ECDSA;      /* pre-hashed input */
            SHA256(canon, len, hash);
            to_sign = hash; to_sign_len = sizeof(hash);
        } else if (ktype == CKK_EC_EDWARDS) {
            mech.mechanism = CKM_EDDSA;      /* signs the message directly */
        } else {
            fprintf(stderr, "Error: unsupported CKA_KEY_TYPE %lu\n",
                    (unsigned long)ktype);
            goto out;
        }

        if (c.SignInit(sess, &mech, privk) != CKR_OK) {
            fprintf(stderr, "Error: C_SignInit failed\n");
            goto out;
        }
        fprintf(stderr, "Touch your key now to authorize the signature...\n");
        fflush(stderr);
        CK_BYTE out[128];
        CK_ULONG outlen = sizeof(out);
        if (c.Sign(sess, (CK_BYTE_PTR)to_sign, to_sign_len, out, &outlen)
                != CKR_OK) {
            fprintf(stderr, "Error: C_Sign failed\n");
            goto out;
        }
        if (outlen != VIRP_APPROVER_SIG_SIZE) {
            fprintf(stderr, "Error: token returned %lu-byte signature, "
                    "expected %d (raw r||s)\n", (unsigned long)outlen,
                    VIRP_APPROVER_SIG_SIZE);
            goto out;
        }
        memcpy(sig, out, VIRP_APPROVER_SIG_SIZE);
        rc = 0;
    }

out:
    if (sess) c.CloseSession(sess);
    if (c.Finalize) c.Finalize(NULL);
    if (c.dl) dlclose(c.dl);
    return rc;
}
