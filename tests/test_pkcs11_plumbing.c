/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — PKCS#11 approval signer plumbing test
 *
 * Drives virp_tool_sign_pkcs11() against the mock PKCS#11 module
 * (build/mock_pkcs11.so), then verifies the resulting raw r||s signature
 * with the SAME registry verify path the daemon uses — proving the
 * PKCS#11 -> canonical-sign -> daemon-verify chain end to end without
 * hardware. The mock's public key is enrolled here from its fixed SPKI.
 *
 * Real-hardware exercise (YubiKey PIV via opensc-pkcs11.so) is out of
 * scope in the build container; see docs/APPROVAL-FLOW.md.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_approval.h"
#include "virp_approver_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>

int virp_tool_sign_pkcs11(const char *module, const char *slot,
                          const char *label,
                          const uint8_t *canon, size_t len,
                          uint8_t sig[VIRP_APPROVER_SIG_SIZE],
                          char key_id_out[33]);

static int passed, failed;
#define TEST(n) printf("  [TEST] %-52s ", n)
#define OK()    do { printf("PASS\n"); passed++; } while (0)
#define BAD(m)  do { printf("FAIL: %s (line %d)\n", m, __LINE__); failed++; \
                     return; } while (0)
#define CHECK(c, m) do { if (!(c)) BAD(m); } while (0)

/* The mock module's fixed public key, as base64 SPKI (matches
 * tests/mock_pkcs11.c). */
static const char MOCK_SPKI_B64[] =
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUlaSetRmRWfyHZV0CjHUP09tdnES"
    "vruJo7n5ZnZ8Wov7B1OMrkI0pzOLn8WDLTown1WsdvcEi1BYbbJACMgUNg==";

static const char *MODULE = "build/mock_pkcs11.so";

static void test_pkcs11_sign_and_verify(void)
{
    TEST("PKCS#11 P-256 sign -> registry verify (mock token)");

    /* Enroll the mock's public key. */
    char entry[1024];
    snprintf(entry, sizeof(entry),
        "{\"key_id\":\"placeholder\",\"algorithm\":\"ecdsa-p256\","
        "\"public_key\":\"%s\",\"operator\":\"mock\",\"enabled\":true}",
        MOCK_SPKI_B64);
    /* key_id in the entry must match the derived one; build it properly by
     * decoding the SPKI through the registry's own entry-JSON helper. */
    uint8_t spki[256];
    /* crude base64 decode via the enroll helper path is not exported, so
     * reconstruct via OpenSSL-free approach: use entry_json which needs
     * DER. Instead, decode base64 here. */
    /* Minimal base64 decode. */
    static const char A[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t blen = strlen(MOCK_SPKI_B64), o = 0;
    for (size_t i = 0; i < blen; i += 4) {
        int v[4], pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = MOCK_SPKI_B64[i + j];
            if (c == '=') { v[j] = 0; pad++; }
            else { const char *q = strchr(A, c); v[j] = q ? (int)(q - A) : 0; }
        }
        uint32_t acc = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                       ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        if (pad < 3) spki[o++] = (acc >> 16) & 0xff;
        if (pad < 2) spki[o++] = (acc >> 8) & 0xff;
        if (pad < 1) spki[o++] = acc & 0xff;
    }
    CHECK(virp_approver_entry_json(spki, o, "mock", true, entry, sizeof(entry))
              == VIRP_OK, "entry build");

    const char *rpath = "/tmp/virp-test-pkcs11-reg.json";
    FILE *f = fopen(rpath, "w");
    CHECK(f != NULL, "open registry");
    fprintf(f, "[%s]\n", entry);
    fclose(f);

    virp_approver_registry_t reg;
    CHECK(virp_approver_registry_load(&reg, rpath) == VIRP_OK, "load reg");
    CHECK(reg.count == 1, "one enrolled");
    unlink(rpath);

    /* A representative canonical payload (72 bytes). */
    uint8_t canon[VIRP_APPROVAL_CANON_SIZE];
    CHECK(virp_approval_build_canonical(
              "00112233445566778899aabbccddeeff",
              "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
              0xA0A0A0A1, 1784822400000000000ULL, 300, canon) == VIRP_OK,
          "canonical");

    /* Sign on the mock token. */
    setenv("VIRP_PKCS11_PIN", "123456", 1);
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    char key_id[33];
    int rc = virp_tool_sign_pkcs11(MODULE, "9c", NULL, canon, sizeof(canon),
                                   sig, key_id);
    CHECK(rc == 0, "pkcs11 sign failed (is build/mock_pkcs11.so present?)");

    /* key_id must resolve to the enrolled entry, and the signature verify. */
    const virp_approver_t *e = virp_approver_registry_find(&reg, key_id);
    CHECK(e != NULL, "pkcs11 key_id not the enrolled key");
    CHECK(e->alg == VIRP_APPROVER_ALG_ECDSA_P256, "alg not p256");
    CHECK(virp_approver_verify(e, canon, sizeof(canon), sig, sizeof(sig))
              == VIRP_OK, "pkcs11 signature must verify");

    /* A tampered canonical must NOT verify under the same signature. */
    uint8_t bad[VIRP_APPROVAL_CANON_SIZE];
    memcpy(bad, canon, sizeof(bad));
    bad[60] ^= 0x01;   /* flip a bit of approved_at */
    CHECK(virp_approver_verify(e, bad, sizeof(bad), sig, sizeof(sig))
              == VIRP_ERR_APPROVAL_BAD_SIGNATURE, "tampered must fail");
    OK();
}

int main(void)
{
    printf("\n=== VIRP PKCS#11 Signer Plumbing Tests ===\n");
    if (sodium_init() < 0) return 1;
    test_pkcs11_sign_and_verify();
    printf("\n=== Results: %d passed, %d failed ===\n", passed, failed);
    return failed == 0 ? 0 : 1;
}
