/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Approver key registry tests
 *
 * Covers: ECDSA-P256 verification against a FIXED known-answer vector
 * (OpenSSL-generated, embedded below), Ed25519 verification (libsodium,
 * runtime key), registry load/parse, key_id/algorithm cross-check
 * rejection, and enabled/disabled lookup semantics.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_approver_registry.h"
#include "virp_federation.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sodium.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  [TEST] %-52s ", name); } while (0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(m) do { printf("FAIL: %s (line %d)\n", m, __LINE__); \
                     tests_failed++; } while (0)
#define ASSERT(c, m) do { if (!(c)) { FAIL(m); return; } } while (0)

/* -------------------------------------------------------------------------
 * Fixed ECDSA-P256 known-answer vector (generated with OpenSSL 3.0):
 *   key:  prime256v1
 *   msg:  "VIRP approval canonical test vector"
 *   sig:  raw r||s (64 bytes) derived from the DER signature
 * ------------------------------------------------------------------------- */

/* DER SubjectPublicKeyInfo of the P-256 public key (91 bytes). */
static const uint8_t KAT_SPKI[] = {
    0x30,0x59,0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,
    0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0x3e,0xe9,0xc4,
    0x25,0x0d,0x56,0x45,0x2a,0xd2,0x0e,0x50,0x61,0x2f,0xa3,0x11,0x95,0x89,0x09,
    0xa0,0xb2,0x27,0x52,0x72,0xc3,0x1f,0x4c,0xe8,0xcd,0x9e,0x34,0xb8,0x41,0xa7,
    0x9e,0xdf,0xcc,0x4a,0x9d,0x01,0x92,0x1b,0x78,0xfa,0xad,0x63,0x6a,0x4a,0xa7,
    0xc3,0x3d,0x78,0xd6,0xee,0x7c,0x13,0x5a,0x67,0xf5,0xf9,0x03,0x00,0xec,0x5c,
    0x03
};
static const char KAT_MSG[] = "VIRP approval canonical test vector";
/* raw r||s (64 bytes) */
static const uint8_t KAT_SIG[64] = {
    0x97,0x89,0xd9,0x4b,0x8d,0x0b,0x88,0x64,0xcf,0x9d,0x07,0xc9,0x99,0xf6,0xae,
    0x57,0x07,0x22,0xb9,0x4f,0x64,0xed,0x36,0x1b,0x76,0xd6,0x2e,0xfb,0x08,0x0a,
    0xf9,0xca,0x9d,0xb6,0xf0,0x73,0x42,0xb4,0x06,0xaa,0x6b,0xa2,0x95,0x3b,0x2d,
    0xda,0xef,0x98,0xc7,0x67,0xef,0x85,0x1e,0xed,0xec,0xbe,0x9a,0xef,0x15,0xb4,
    0xa7,0x50,0xfc,0x49
};

/* Build a virp_approver_t for a DER SPKI via the entry-JSON round-trip
 * (also exercises virp_approver_entry_json + parse_entry). */
static int make_entry(const uint8_t *spki, size_t spki_len, bool enabled,
                      virp_approver_t *out)
{
    char json[1024];
    if (virp_approver_entry_json(spki, spki_len, "kat-operator", enabled,
                                 json, sizeof(json)) != VIRP_OK)
        return -1;
    return virp_approver_parse_entry(json, out) == VIRP_OK ? 0 : -1;
}

static void test_ecdsa_p256_kat(void)
{
    TEST("ECDSA-P256 KAT: correct signature verifies");
    virp_approver_t e;
    ASSERT(make_entry(KAT_SPKI, sizeof(KAT_SPKI), true, &e) == 0,
           "entry build failed");
    ASSERT(e.alg == VIRP_APPROVER_ALG_ECDSA_P256, "alg not p256");
    ASSERT(virp_approver_verify(&e, (const uint8_t *)KAT_MSG, strlen(KAT_MSG),
                                KAT_SIG, sizeof(KAT_SIG)) == VIRP_OK,
           "KAT signature must verify");
    PASS();
}

static void test_ecdsa_p256_tampered_msg(void)
{
    TEST("ECDSA-P256 KAT: tampered message fails");
    virp_approver_t e;
    ASSERT(make_entry(KAT_SPKI, sizeof(KAT_SPKI), true, &e) == 0,
           "entry build failed");
    char bad[64];
    snprintf(bad, sizeof(bad), "%s", KAT_MSG);
    bad[0] ^= 0x01;   /* flip one bit */
    ASSERT(virp_approver_verify(&e, (const uint8_t *)bad, strlen(bad),
                                KAT_SIG, sizeof(KAT_SIG))
               == VIRP_ERR_APPROVAL_BAD_SIGNATURE, "tampered msg must fail");
    PASS();
}

static void test_ecdsa_p256_tampered_sig(void)
{
    TEST("ECDSA-P256 KAT: tampered signature fails");
    virp_approver_t e;
    ASSERT(make_entry(KAT_SPKI, sizeof(KAT_SPKI), true, &e) == 0,
           "entry build failed");
    uint8_t sig[64];
    memcpy(sig, KAT_SIG, 64);
    sig[10] ^= 0x80;
    ASSERT(virp_approver_verify(&e, (const uint8_t *)KAT_MSG, strlen(KAT_MSG),
                                sig, sizeof(sig))
               == VIRP_ERR_APPROVAL_BAD_SIGNATURE, "tampered sig must fail");
    /* Wrong signature length is also a clean reject, never a crash. */
    ASSERT(virp_approver_verify(&e, (const uint8_t *)KAT_MSG, strlen(KAT_MSG),
                                sig, 63) == VIRP_ERR_APPROVAL_BAD_SIGNATURE,
           "short sig must fail");
    PASS();
}

static void test_ed25519_verify(void)
{
    TEST("Ed25519: sign (libsodium) then registry verify");
    virp_fed_keypair_t kp;
    ASSERT(virp_fed_generate(&kp, 1) == VIRP_OK, "keygen");

    uint8_t spki[44];
    virp_approver_ed25519_spki(kp.public_key, spki);
    virp_approver_t e;
    ASSERT(make_entry(spki, sizeof(spki), true, &e) == 0, "entry build");
    ASSERT(e.alg == VIRP_APPROVER_ALG_ED25519, "alg not ed25519");

    const char *msg = "canonical approval bytes";
    uint8_t sig[VIRP_FED_SIG_SIZE];
    ASSERT(virp_fed_sign(&kp, (const uint8_t *)msg, strlen(msg), sig)
               == VIRP_OK, "sign");
    ASSERT(virp_approver_verify(&e, (const uint8_t *)msg, strlen(msg),
                                sig, sizeof(sig)) == VIRP_OK, "verify");
    /* One flipped payload byte fails. */
    ASSERT(virp_approver_verify(&e, (const uint8_t *)"Canonical approval bytes",
                                strlen(msg), sig, sizeof(sig))
               == VIRP_ERR_APPROVAL_BAD_SIGNATURE, "tamper must fail");
    virp_fed_destroy(&kp);
    PASS();
}

static void test_keyid_matches_fed_derivation(void)
{
    TEST("Ed25519 registry key_id == virp_fed_compute_key_id");
    virp_fed_keypair_t kp;
    ASSERT(virp_fed_generate(&kp, 1) == VIRP_OK, "keygen");
    uint8_t spki[44];
    virp_approver_ed25519_spki(kp.public_key, spki);
    virp_approver_t e;
    ASSERT(make_entry(spki, sizeof(spki), true, &e) == 0, "entry build");

    char fed_hex[33];
    for (int i = 0; i < VIRP_FED_KEYID_SIZE; i++)
        snprintf(fed_hex + i * 2, 3, "%02x", kp.key_id[i]);
    ASSERT(strcmp(e.key_id, fed_hex) == 0,
           "registry key_id must equal the fed keypair key_id");
    virp_fed_destroy(&kp);
    PASS();
}

static void test_keyid_mismatch_rejected(void)
{
    TEST("Entry with wrong key_id is rejected");
    char json[1024];
    ASSERT(virp_approver_entry_json(KAT_SPKI, sizeof(KAT_SPKI), "op", true,
                                    json, sizeof(json)) == VIRP_OK, "json");
    /* Corrupt the declared key_id: find "key_id":" and flip a hex digit. */
    char *k = strstr(json, "\"key_id\":\"");
    ASSERT(k != NULL, "key_id field");
    k += strlen("\"key_id\":\"");
    k[0] = (k[0] == 'a') ? 'b' : 'a';
    virp_approver_t e;
    ASSERT(virp_approver_parse_entry(json, &e) == VIRP_ERR_CONTEXT_MISMATCH,
           "mismatched key_id must be rejected");
    PASS();
}

static void test_algorithm_mismatch_rejected(void)
{
    TEST("Entry declaring wrong algorithm is rejected");
    char json[1024];
    /* Build a valid ECDSA entry, then relabel it ed25519. */
    ASSERT(virp_approver_entry_json(KAT_SPKI, sizeof(KAT_SPKI), "op", true,
                                    json, sizeof(json)) == VIRP_OK, "json");
    char *a = strstr(json, "\"algorithm\":\"ecdsa-p256\"");
    ASSERT(a != NULL, "algorithm field");
    memcpy(a, "\"algorithm\":\"ed25519\"   ", 24);  /* pad to same width */
    virp_approver_t e;
    ASSERT(virp_approver_parse_entry(json, &e) != VIRP_OK,
           "algorithm mismatch must be rejected");
    PASS();
}

static void test_registry_load_and_lookup(void)
{
    TEST("Registry load: enabled/disabled lookup semantics");
    /* Build a two-entry registry: one enabled ECDSA, one disabled ed25519. */
    virp_fed_keypair_t kp;
    virp_fed_generate(&kp, 1);
    uint8_t ed_spki[44];
    virp_approver_ed25519_spki(kp.public_key, ed_spki);

    char e1[1024], e2[1024];
    virp_approver_entry_json(KAT_SPKI, sizeof(KAT_SPKI), "primary", true,
                             e1, sizeof(e1));
    virp_approver_entry_json(ed_spki, sizeof(ed_spki), "backup", false,
                             e2, sizeof(e2));

    const char *path = "/tmp/virp-test-reg-lookup.json";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL, "open");
    fprintf(f, "[%s,%s]\n", e1, e2);
    fclose(f);

    virp_approver_registry_t reg;
    ASSERT(virp_approver_registry_load(&reg, path) == VIRP_OK, "load");
    ASSERT(reg.count == 2, "both entries enrolled");

    /* ECDSA entry: enabled -> find + find_any both return it. */
    virp_approver_t tmp;
    make_entry(KAT_SPKI, sizeof(KAT_SPKI), true, &tmp);
    ASSERT(virp_approver_registry_find(&reg, tmp.key_id) != NULL,
           "enabled key findable");

    /* ed25519 entry: disabled -> find_any yes, find no. */
    char ed_kid[33];
    for (int i = 0; i < VIRP_FED_KEYID_SIZE; i++)
        snprintf(ed_kid + i * 2, 3, "%02x", kp.key_id[i]);
    ASSERT(virp_approver_registry_find_any(&reg, ed_kid) != NULL,
           "disabled key present via find_any");
    ASSERT(virp_approver_registry_find(&reg, ed_kid) == NULL,
           "disabled key hidden from find");

    /* Unknown key_id: neither. */
    ASSERT(virp_approver_registry_find_any(&reg,
           "ffffffffffffffffffffffffffffffff") == NULL, "unknown absent");

    virp_fed_destroy(&kp);
    unlink(path);
    PASS();
}

static void test_registry_skips_bad_entry(void)
{
    TEST("Registry load skips a malformed entry, keeps the good one");
    char good[1024];
    virp_approver_entry_json(KAT_SPKI, sizeof(KAT_SPKI), "op", true,
                             good, sizeof(good));
    const char *path = "/tmp/virp-test-reg-bad.json";
    FILE *f = fopen(path, "w");
    ASSERT(f != NULL, "open");
    /* First entry has garbage base64; second is valid. */
    fprintf(f, "[{\"key_id\":\"00000000000000000000000000000000\","
               "\"algorithm\":\"ecdsa-p256\",\"public_key\":\"!!!!\","
               "\"operator\":\"x\",\"enabled\":true},%s]\n", good);
    fclose(f);

    virp_approver_registry_t reg;
    ASSERT(virp_approver_registry_load(&reg, path) == VIRP_OK, "load");
    ASSERT(reg.count == 1, "only the good entry survives");
    unlink(path);
    PASS();
}

int main(void)
{
    printf("\n=== VIRP Approver Registry Tests ===\n");
    if (sodium_init() < 0) { fprintf(stderr, "sodium init\n"); return 1; }

    test_ecdsa_p256_kat();
    test_ecdsa_p256_tampered_msg();
    test_ecdsa_p256_tampered_sig();
    test_ed25519_verify();
    test_keyid_matches_fed_derivation();
    test_keyid_mismatch_rejected();
    test_algorithm_mismatch_rejected();
    test_registry_load_and_lookup();
    test_registry_skips_bad_entry();

    printf("\n=== Results: %d passed, %d failed ===\n",
           tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
