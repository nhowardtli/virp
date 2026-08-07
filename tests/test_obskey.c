/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — observation-signing key (obskey) custody tests
 *
 * The obskey is the Ed25519 keypair whose PRIVATE half lives on the
 * daemon (the O-Node is the attester) and whose PUBLIC half is handed
 * to consumers as a verify-only key. These tests pin the custody
 * gate:
 *
 *   1. generate → save → load round-trips (pub, key_id identical)
 *   2. malformed/truncated key file refused with a DISTINCT error
 *      (VIRP_ERR_INVALID_LENGTH, not the permission error)
 *   3. group- or world-readable secret key refused
 *      (VIRP_ERR_KEY_NOT_LOADED)
 *   4. SPKI public export round-trips to the same key_id
 */

#define _GNU_SOURCE     /* memmem, prctl */

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/prctl.h>
#include <openssl/sha.h>

#include "virp.h"
#include "virp_crypto.h"
#include "virp_obskey.h"

#define TEST_DIR    "/tmp/virp-test-obskey"
#define SK_PATH     TEST_DIR "/obskey.key"
#define PK_PATH     TEST_DIR "/obskey.pub"
#define TRUNC_PATH  TEST_DIR "/obskey-trunc.key"

static int tests_run = 0, tests_passed = 0;

#define RUN_TEST(fn) do { \
        tests_run++; \
        printf("  %-58s", #fn); \
        fflush(stdout); \
        fn(); \
        tests_passed++; \
        printf("[PASS]\n"); \
    } while (0)

static void reset_dir(void)
{
    unlink(SK_PATH);
    unlink(PK_PATH);
    unlink(TRUNC_PATH);
    rmdir(TEST_DIR);
    assert(mkdir(TEST_DIR, 0700) == 0);
}

static void test_generate_save_load_roundtrip(void)
{
    virp_obskey_t gen, loaded;
    assert(virp_obskey_generate(&gen) == VIRP_OK);
    assert(gen.loaded);
    assert(virp_obskey_save(&gen, SK_PATH, PK_PATH) == VIRP_OK);

    struct stat st;
    assert(stat(SK_PATH, &st) == 0);
    assert((st.st_mode & 07777) == 0600);

    assert(virp_obskey_load(&loaded, SK_PATH) == VIRP_OK);
    assert(loaded.loaded);
    assert(memcmp(gen.public_key, loaded.public_key,
                  VIRP_OBSKEY_PK_SIZE) == 0);
    assert(memcmp(gen.key_id, loaded.key_id,
                  VIRP_OBSKEY_KEYID_SIZE) == 0);

    /* Saving over an existing secret key must refuse (O_EXCL). */
    assert(virp_obskey_save(&gen, SK_PATH, PK_PATH) != VIRP_OK);

    virp_obskey_destroy(&gen);
    virp_obskey_destroy(&loaded);
}

static void test_truncated_key_distinct_error(void)
{
    /* 32 bytes is a plausible-looking key file (it is the size of the
     * O-Key and of an Ed25519 SEED) but not a libsodium secret key.
     * It must fail with the length error, not the permission error —
     * an operator debugging custody needs to know which gate fired. */
    FILE *f = fopen(TRUNC_PATH, "wb");
    assert(f);
    uint8_t half[32];
    memset(half, 0xAB, sizeof(half));
    assert(fwrite(half, 1, sizeof(half), f) == sizeof(half));
    fclose(f);
    assert(chmod(TRUNC_PATH, 0600) == 0);

    virp_obskey_t kp;
    assert(virp_obskey_load(&kp, TRUNC_PATH) == VIRP_ERR_INVALID_LENGTH);
    assert(!kp.loaded);

    /* Empty file: same distinct error. */
    f = fopen(TRUNC_PATH, "wb");
    assert(f);
    fclose(f);
    assert(chmod(TRUNC_PATH, 0600) == 0);
    assert(virp_obskey_load(&kp, TRUNC_PATH) == VIRP_ERR_INVALID_LENGTH);
}

static void test_lax_permissions_refused(void)
{
    virp_obskey_t kp;

    /* Group-readable: refuse. */
    assert(chmod(SK_PATH, 0640) == 0);
    assert(virp_obskey_load(&kp, SK_PATH) == VIRP_ERR_KEY_NOT_LOADED);
    assert(!kp.loaded);

    /* World-readable: refuse. */
    assert(chmod(SK_PATH, 0604) == 0);
    assert(virp_obskey_load(&kp, SK_PATH) == VIRP_ERR_KEY_NOT_LOADED);

    /* Group-writable (not even readable): still refuse — a writer can
     * substitute the key, which is forge capability too. */
    assert(chmod(SK_PATH, 0620) == 0);
    assert(virp_obskey_load(&kp, SK_PATH) == VIRP_ERR_KEY_NOT_LOADED);

    /* Back to 0600: loads again. */
    assert(chmod(SK_PATH, 0600) == 0);
    assert(virp_obskey_load(&kp, SK_PATH) == VIRP_OK);
    virp_obskey_destroy(&kp);

    /* 0400 (read-only owner) is also acceptable custody. */
    assert(chmod(SK_PATH, 0400) == 0);
    assert(virp_obskey_load(&kp, SK_PATH) == VIRP_OK);
    assert(chmod(SK_PATH, 0600) == 0);
    virp_obskey_destroy(&kp);
}

/* The hardening routine virp-tool calls before any keygen subcommand
 * must actually flip PR_SET_DUMPABLE off — a key custody claim that
 * depends on it (no core dumps / no same-UID ptrace while a secret is
 * in memory) is only as good as this bit. */
static void test_harden_process_clears_dumpable(void)
{
    /* Precondition on a normal test runner: processes start dumpable.
     * If a wrapper already cleared it, the postcondition still holds. */
    assert(virp_crypto_harden_process() == VIRP_OK);
#ifdef __linux__
    assert(prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0);
#endif
}

static void test_spki_export_roundtrip_key_id(void)
{
    virp_obskey_t kp;
    assert(virp_obskey_load(&kp, SK_PATH) == VIRP_OK);

    uint8_t spki[VIRP_OBSKEY_SPKI_SIZE];
    assert(virp_obskey_spki(&kp, spki) == VIRP_OK);

    /* DER SubjectPublicKeyInfo for Ed25519: fixed 12-byte prefix then
     * the raw 32-byte public key. */
    static const uint8_t prefix[12] = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00
    };
    assert(memcmp(spki, prefix, sizeof(prefix)) == 0);
    assert(memcmp(spki + 12, kp.public_key, VIRP_OBSKEY_PK_SIZE) == 0);

    /* key_id must be derivable from the EXPORTED form alone: a
     * consumer holding only the SPKI computes the same id the daemon
     * prints — SHA-256(raw pubkey)[:16]. */
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(spki + 12, VIRP_OBSKEY_PK_SIZE, digest);
    assert(memcmp(digest, kp.key_id, VIRP_OBSKEY_KEYID_SIZE) == 0);

    /* The export path never contains secret bytes: the 44 SPKI bytes
     * must not overlap the secret key seed. */
    assert(memmem(spki, sizeof(spki), kp.secret_key, 32) == NULL);

    virp_obskey_destroy(&kp);
}

int main(void)
{
    printf("=== VIRP Observation-Signing Key (obskey) Custody Tests ===\n");
    reset_dir();

    RUN_TEST(test_generate_save_load_roundtrip);
    RUN_TEST(test_truncated_key_distinct_error);
    RUN_TEST(test_lax_permissions_refused);
    RUN_TEST(test_spki_export_roundtrip_key_id);
    RUN_TEST(test_harden_process_clears_dumpable);

    printf("=== All %d obskey custody tests passed (%d/%d) ===\n",
           tests_run, tests_passed, tests_run);
    return 0;
}
