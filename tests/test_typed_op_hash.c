/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Typed-operation command hashing (FIX 1, 2026-08-01).
 *
 * THE BUG THIS PINS. Command hashes are the binding between an approved
 * object and an executed one. They were computed by running the command
 * through virp_canonicalize_command(), which COLLAPSES RUNS OF
 * WHITESPACE. A typed-operation parser refuses whitespace variants —
 * `pbs  op=X` is RED, `pbs op=X` is GREEN — so two commands with
 * different classifications produced the SAME hash. Anywhere that hash
 * is the binding (approval records, v2 observation headers), an approval
 * for the accepted spelling also covers the refused one.
 *
 * Latent while no typed profile has an approvable non-GREEN row; an
 * approval-substitution hole the moment one exists.
 *
 * Offline and pure — no daemon, no socket, no device.
 */

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_driver.h"
#include "virp_driver_pbs.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <openssl/evp.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

#define PROFILE "pbs/1"

/*
 * The OLD derivation, reproduced verbatim so the regression is proven
 * against the thing that actually shipped rather than against a
 * description of it.
 */
static int legacy_command_hash(const char *cmd, uint8_t out[32])
{
    char canon[512];
    int n = virp_canonicalize_command(cmd, canon, sizeof(canon));
    if (n < 0) return -1;
    unsigned int mdlen = 0;
    EVP_Digest(canon, (size_t)n, out, &mdlen, EVP_sha256(), NULL);
    return 0;
}

/* =========================================================================
 * The regression itself
 * ========================================================================= */

static void test_old_path_collided(void)
{
    printf("\n=== The defect: the OLD derivation collided ===\n");

    uint8_t a[32], b[32];

    TEST("legacy: `pbs  op=X` and `pbs op=X` hashed IDENTICALLY");
    assert(legacy_command_hash("pbs  op=backup.version.read", a) == 0);
    assert(legacy_command_hash("pbs op=backup.version.read",  b) == 0);
    assert(memcmp(a, b, 32) == 0);      /* the bug, pinned */
    PASS();

    TEST("legacy: a tab variant also collided");
    assert(legacy_command_hash("pbs\top=backup.version.read", a) == 0);
    assert(legacy_command_hash("pbs op=backup.version.read",  b) == 0);
    assert(memcmp(a, b, 32) == 0);
    PASS();

    TEST("legacy: leading/trailing space collided too");
    assert(legacy_command_hash("  pbs op=backup.version.read  ", a) == 0);
    assert(legacy_command_hash("pbs op=backup.version.read",     b) == 0);
    assert(memcmp(a, b, 32) == 0);
    PASS();
}

static void test_typed_hash_separates(void)
{
    printf("\n=== The fix: typed-op hashing separates them ===\n");

    uint8_t a[32], b[32];

    TEST("`pbs  op=X` and `pbs op=X` now hash DIFFERENTLY");
    assert(virp_typed_op_hash(PROFILE, "pbs  op=backup.version.read",
                              strlen("pbs  op=backup.version.read"), a) == VIRP_OK);
    assert(virp_typed_op_hash(PROFILE, "pbs op=backup.version.read",
                              strlen("pbs op=backup.version.read"), b) == VIRP_OK);
    assert(memcmp(a, b, 32) != 0);
    PASS();

    TEST("tab variant is distinct");
    assert(virp_typed_op_hash(PROFILE, "pbs\top=backup.version.read",
                              strlen("pbs\top=backup.version.read"), a) == VIRP_OK);
    assert(memcmp(a, b, 32) != 0);
    PASS();

    TEST("trailing space is distinct");
    assert(virp_typed_op_hash(PROFILE, "pbs op=backup.version.read ",
                              strlen("pbs op=backup.version.read "), a) == VIRP_OK);
    assert(memcmp(a, b, 32) != 0);
    PASS();

    TEST("identical octets hash identically (determinism)");
    assert(virp_typed_op_hash(PROFILE, "pbs op=backup.verify.tasks",
                              strlen("pbs op=backup.verify.tasks"), a) == VIRP_OK);
    assert(virp_typed_op_hash(PROFILE, "pbs op=backup.verify.tasks",
                              strlen("pbs op=backup.verify.tasks"), b) == VIRP_OK);
    assert(memcmp(a, b, 32) == 0);
    PASS();
}

/* =========================================================================
 * Domain separation
 * ========================================================================= */

static void test_domain_separation(void)
{
    printf("\n=== Domain separation — profile and length prefixes ===\n");

    uint8_t a[32], b[32];

    TEST("a different profile over the same command differs");
    assert(virp_typed_op_hash("pbs/1", "pbs op=backup.version.read",
                              26, a) == VIRP_OK);
    assert(virp_typed_op_hash("pbs/2", "pbs op=backup.version.read",
                              26, b) == VIRP_OK);
    assert(memcmp(a, b, 32) != 0);
    PASS();

    TEST("the typed hash never equals the legacy hash for the same text");
    {
        static const char *const CMDS[] = {
            "pbs op=backup.version.read",
            "pbs op=backup.datastore.usage",
            "pbs op=backup.snapshots.list store=colo-backups",
            "pbs op=backup.verify.tasks",
        };
        for (size_t i = 0; i < sizeof(CMDS)/sizeof(CMDS[0]); i++) {
            assert(virp_typed_op_hash(PROFILE, CMDS[i], strlen(CMDS[i]), a)
                   == VIRP_OK);
            assert(legacy_command_hash(CMDS[i], b) == 0);
            assert(memcmp(a, b, 32) != 0);
        }
    }
    PASS();

    TEST("length prefixes prevent (profile,command) re-splitting");
    /* "ab"+"cd" and "a"+"bcd" must not collide. */
    assert(virp_typed_op_hash("ab", "cd", 2, a) == VIRP_OK);
    assert(virp_typed_op_hash("a", "bcd", 3, b) == VIRP_OK);
    assert(memcmp(a, b, 32) != 0);
    PASS();

    TEST("degenerate inputs are refused, not hashed");
    assert(virp_typed_op_hash(NULL, "x", 1, a) != VIRP_OK);
    assert(virp_typed_op_hash(PROFILE, NULL, 1, a) != VIRP_OK);
    assert(virp_typed_op_hash(PROFILE, "x", 0, a) != VIRP_OK);
    assert(virp_typed_op_hash("", "x", 1, a) != VIRP_OK);
    PASS();
}

/* =========================================================================
 * The switch loses no information
 *
 * The reason it is SAFE to stop canonicalizing on the typed path: every
 * command the typed parser accepts is ALREADY in canonical form, so the
 * canonicalizer was a no-op on exactly the inputs that reach it.
 * ========================================================================= */

static void test_accepted_commands_are_already_canonical(void)
{
    printf("\n=== Accepted commands are already canonical ===\n");

    static const char *const ACCEPTED[] = {
        "pbs op=backup.version.read",
        "pbs op=backup.datastore.usage",
        "pbs op=backup.verify.tasks",
        "pbs op=backup.snapshots.list store=colo-backups",
        "pbs op=backup.snapshots.list store=vault-01",
        "pbs op=backup.snapshots.list store=a_b.c-d",
    };

    for (size_t i = 0; i < sizeof(ACCEPTED)/sizeof(ACCEPTED[0]); i++) {
        TEST(ACCEPTED[i]);
        pbs_request_t req;
        /* it really is accepted by the typed parser ... */
        assert(pbs_parse_command(ACCEPTED[i], &req, NULL) == 0);
        /* ... and the generic canonicalizer is the identity on it, so no
         * information is lost by switching derivations. */
        char canon[512];
        int n = virp_canonicalize_command(ACCEPTED[i], canon, sizeof(canon));
        assert(n > 0);
        assert(strcmp(canon, ACCEPTED[i]) == 0);
        PASS();
    }
}

/* =========================================================================
 * The driver declares the profile — nothing sniffs the command
 * ========================================================================= */

static void test_profile_is_a_driver_declaration(void)
{
    printf("\n=== Profile is declared by the driver, not sniffed ===\n");

    virp_driver_pbs_init();

    TEST("the PBS driver declares a typed profile");
    {
        const virp_driver_t *d = virp_driver_lookup(VIRP_VENDOR_PBS);
        assert(d != NULL);
        assert(d->typed_profile != NULL);
        assert(strcmp(d->typed_profile, PROFILE) == 0);
    }
    PASS();

    TEST("a CLI driver declares none (NULL keeps historic hashing)");
    {
        const virp_driver_t *d = virp_driver_lookup(VIRP_VENDOR_MOCK);
        if (d) assert(d->typed_profile == NULL);
    }
    PASS();
}

int main(void)
{
    printf("=== Typed-operation command hash tests ===\n");

    test_old_path_collided();
    test_typed_hash_separates();
    test_domain_separation();
    test_accepted_commands_are_already_canonical();
    test_profile_is_a_driver_declaration();

    printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
