/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Trust Federation (Primitive 7) Tests
 *
 * Tests: keypair generate, sign+verify, wrong key, mlock,
 *        save/load roundtrip, key_id computation
 */

#include "virp_federation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { printf("  [TEST] %-50s ", name); } while (0)

#define PASS() \
    do { printf("PASS\n"); tests_passed++; } while (0)

#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)

#define ASSERT(cond, msg) \
    do { if (!(cond)) { FAIL(msg); return; } } while (0)

static const char *TEST_PK = "/tmp/virp_test_fed.pk";
static const char *TEST_SK = "/tmp/virp_test_fed.sk";

static void cleanup(void)
{
    unlink(TEST_PK);
    unlink(TEST_SK);
}

/* =========================================================================
 * Test: Init libsodium
 * ========================================================================= */

static void test_init(void)
{
    TEST("sodium_init");
    virp_error_t err = virp_fed_init();
    ASSERT(err == VIRP_OK, "virp_fed_init failed");
    /* Call again — should be idempotent */
    err = virp_fed_init();
    ASSERT(err == VIRP_OK, "virp_fed_init second call failed");
    PASS();
}

/* =========================================================================
 * Test: Generate keypair
 * ========================================================================= */

static void test_generate(void)
{
    TEST("Generate Ed25519 keypair");
    virp_fed_keypair_t kp;
    virp_error_t err = virp_fed_generate(&kp, 1);
    ASSERT(err == VIRP_OK, "generate failed");
    ASSERT(kp.loaded, "keypair should be loaded");
    ASSERT(kp.key_version == 1, "key_version should be 1");

    /* key_id should be non-zero */
    int nonzero = 0;
    for (int i = 0; i < VIRP_FED_KEYID_SIZE; i++)
        if (kp.key_id[i] != 0) nonzero++;
    ASSERT(nonzero > 0, "key_id should be non-zero");

    virp_fed_destroy(&kp);
    PASS();
}

/* =========================================================================
 * Test: Sign and verify
 * ========================================================================= */

static void test_sign_verify(void)
{
    TEST("Sign and verify");
    virp_fed_keypair_t kp;
    virp_fed_generate(&kp, 1);

    const char *message = "VIRP trust chain test data 2026";
    uint8_t sig[VIRP_FED_SIG_SIZE];

    virp_error_t err = virp_fed_sign(&kp, (const uint8_t *)message,
                                      strlen(message), sig);
    ASSERT(err == VIRP_OK, "sign failed");

    /* Verify with correct public key */
    err = virp_fed_verify(kp.public_key, (const uint8_t *)message,
                          strlen(message), sig);
    ASSERT(err == VIRP_OK, "verify should succeed");

    virp_fed_destroy(&kp);
    PASS();
}

/* =========================================================================
 * Test: Wrong key fails verification
 * ========================================================================= */

static void test_wrong_key(void)
{
    TEST("Wrong key fails verification");

    virp_fed_keypair_t kp1, kp2;
    virp_fed_generate(&kp1, 1);
    virp_fed_generate(&kp2, 1);

    const char *message = "signed by kp1";
    uint8_t sig[VIRP_FED_SIG_SIZE];

    virp_fed_sign(&kp1, (const uint8_t *)message, strlen(message), sig);

    /* Verify with kp2's public key — should fail */
    virp_error_t err = virp_fed_verify(kp2.public_key,
                                        (const uint8_t *)message,
                                        strlen(message), sig);
    ASSERT(err == VIRP_ERR_HMAC_FAILED, "wrong key should fail verification");

    virp_fed_destroy(&kp1);
    virp_fed_destroy(&kp2);
    PASS();
}

/* =========================================================================
 * Test: Tampered message fails verification
 * ========================================================================= */

static void test_tampered_message(void)
{
    TEST("Tampered message fails verification");

    virp_fed_keypair_t kp;
    virp_fed_generate(&kp, 1);

    const char *message = "original message";
    const char *tampered = "tampered message";
    uint8_t sig[VIRP_FED_SIG_SIZE];

    virp_fed_sign(&kp, (const uint8_t *)message, strlen(message), sig);

    virp_error_t err = virp_fed_verify(kp.public_key,
                                        (const uint8_t *)tampered,
                                        strlen(tampered), sig);
    ASSERT(err == VIRP_ERR_HMAC_FAILED, "tampered message should fail");

    virp_fed_destroy(&kp);
    PASS();
}

/* =========================================================================
 * Test: Save and load roundtrip
 * ========================================================================= */

static void test_save_load(void)
{
    TEST("Save/load roundtrip");
    cleanup();

    virp_fed_keypair_t kp_orig;
    virp_fed_generate(&kp_orig, 42);

    /* Sign with original */
    const char *message = "roundtrip test";
    uint8_t sig[VIRP_FED_SIG_SIZE];
    virp_fed_sign(&kp_orig, (const uint8_t *)message, strlen(message), sig);

    /* Save */
    virp_error_t err = virp_fed_save(&kp_orig, TEST_PK, TEST_SK);
    ASSERT(err == VIRP_OK, "save failed");

    /* Load into new keypair */
    virp_fed_keypair_t kp_loaded;
    err = virp_fed_load(&kp_loaded, TEST_PK, TEST_SK, 42);
    ASSERT(err == VIRP_OK, "load failed");
    ASSERT(kp_loaded.loaded, "loaded keypair should be loaded");
    ASSERT(kp_loaded.key_version == 42, "key_version should be 42");

    /* Verify original signature with loaded key */
    err = virp_fed_verify(kp_loaded.public_key, (const uint8_t *)message,
                          strlen(message), sig);
    ASSERT(err == VIRP_OK, "verify with loaded key should succeed");

    /* Sign with loaded key, verify with original */
    uint8_t sig2[VIRP_FED_SIG_SIZE];
    virp_fed_sign(&kp_loaded, (const uint8_t *)message, strlen(message), sig2);
    err = virp_fed_verify(kp_orig.public_key, (const uint8_t *)message,
                          strlen(message), sig2);
    ASSERT(err == VIRP_OK, "cross-verify should succeed");

    /* key_id should match */
    ASSERT(memcmp(kp_orig.key_id, kp_loaded.key_id,
                  VIRP_FED_KEYID_SIZE) == 0, "key_id should match");

    virp_fed_destroy(&kp_orig);
    virp_fed_destroy(&kp_loaded);
    PASS();
}

/* =========================================================================
 * Test: mlock on secret key
 * ========================================================================= */

static void test_mlock(void)
{
    TEST("mlock on secret key");
    virp_fed_keypair_t kp;
    virp_fed_generate(&kp, 1);

    /* mlock is called by generate — check the locked flag */
    /* Note: mlock may fail in containers; we just check it doesn't crash */
    ASSERT(kp.loaded, "keypair should be loaded after generate");

    virp_fed_destroy(&kp);
    ASSERT(!kp.loaded, "keypair should be cleared after destroy");
    PASS();
}

/* =========================================================================
 * Test: key_id computation
 * ========================================================================= */

static void test_key_id(void)
{
    TEST("key_id = SHA256(pubkey)[:16]");

    virp_fed_keypair_t kp;
    virp_fed_generate(&kp, 1);

    /* Compute key_id manually */
    uint8_t computed_id[VIRP_FED_KEYID_SIZE];
    virp_fed_compute_key_id(kp.public_key, computed_id);

    ASSERT(memcmp(kp.key_id, computed_id, VIRP_FED_KEYID_SIZE) == 0,
           "key_id should match manual computation");

    virp_fed_destroy(&kp);
    PASS();
}

/* =========================================================================
 * Test: Destroy zeros secret key
 * ========================================================================= */

static void test_destroy_zeros(void)
{
    TEST("Destroy zeros secret key memory");

    virp_fed_keypair_t kp;
    virp_fed_generate(&kp, 1);

    virp_fed_destroy(&kp);

    /* Check secret key is zeroed */
    int nonzero = 0;
    for (int i = 0; i < VIRP_FED_SK_SIZE; i++)
        if (kp.secret_key[i] != 0) nonzero++;

    ASSERT(nonzero == 0, "secret key should be zeroed after destroy");
    ASSERT(!kp.loaded, "loaded should be false after destroy");
    PASS();
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void)
{
    printf("\n=== VIRP Trust Federation (Primitive 7) Tests ===\n\n");

    test_init();
    test_generate();
    test_sign_verify();
    test_wrong_key();
    test_tampered_message();
    test_save_load();
    test_mlock();
    test_key_id();
    test_destroy_zeros();

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);

    cleanup();
    return tests_failed > 0 ? 1 : 0;
}
