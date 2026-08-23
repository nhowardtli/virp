/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Chain-signing key module tests (D-1)
 *
 * Covers the primitive beneath detached chain signatures:
 *   - generate / save / load round trip; key_id = SHA-256(pub)[:16]
 *   - public-only load (the verifier's path) yields the same pub/key_id
 *   - custody gate: insecure mode, wrong size, symlink all refused
 *   - golden vectors (tests/vectors/chain-signing-v1.json, produced by
 *     PyNaCl): seed -> pub/key_id, and every signature reproduced
 *     byte-for-byte (Ed25519 is deterministic)
 *   - negatives from the vector file: cross-domain (entry tag vs head
 *     tag), flipped message byte, wrong public key, flipped sig byte
 *   - destroy zeroises the secret
 *
 * The chain-level behaviour (columns, append, verifier tiers) is in
 * tests/test_chain_signing.c.
 */

#define _POSIX_C_SOURCE 200809L     /* symlink */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/sha.h>

#include "virp.h"
#include "virp_chainsign.h"
#include "cJSON.h"

static int tests_run = 0, tests_passed = 0;

#define RUN_TEST(fn) do { \
        tests_run++; \
        printf("  %-62s", #fn); \
        fflush(stdout); \
        fn(); \
        tests_passed++; \
        printf("[PASS]\n"); \
    } while (0)

static const char *SK = "/tmp/virp_test_chainsign.key";
static const char *PK = "/tmp/virp_test_chainsign.pub";
static const char *VECTORS = "tests/vectors/chain-signing-v1.json";

static void rm_keys(void)
{
    unlink(SK); unlink(PK);
    unlink("/tmp/virp_test_chainsign.link");
    unlink("/tmp/virp_test_chainsign.short");
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static size_t unhex(const char *hex, uint8_t *out, size_t max)
{
    size_t n = strlen(hex) / 2;
    assert(n <= max);
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(hex[2 * i]), lo = hexval(hex[2 * i + 1]);
        assert(hi >= 0 && lo >= 0);
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

static const char *jstr(const cJSON *o, const char *k)
{
    const cJSON *j = cJSON_GetObjectItemCaseSensitive(o, k);
    assert(cJSON_IsString(j) && j->valuestring);
    return j->valuestring;
}

/* ------------------------------------------------------------------ */

static void test_generate_save_load_roundtrip(void)
{
    rm_keys();
    virp_chainsign_key_t a, b;
    assert(virp_chainsign_generate(&a) == VIRP_OK);
    assert(a.loaded);
    assert(virp_chainsign_save(&a, SK, PK) == VIRP_OK);

    struct stat st;
    assert(stat(SK, &st) == 0 && (st.st_mode & 07777) == 0600);
    assert(st.st_size == VIRP_CHAINSIGN_SK_SIZE);
    assert(stat(PK, &st) == 0 && st.st_size == VIRP_CHAINSIGN_PK_SIZE);

    /* Save refuses to overwrite. */
    assert(virp_chainsign_save(&a, SK, PK) != VIRP_OK);

    assert(virp_chainsign_load(&b, SK) == VIRP_OK);
    assert(memcmp(a.public_key, b.public_key, 32) == 0);
    assert(memcmp(a.secret_key, b.secret_key, 64) == 0);
    assert(memcmp(a.key_id, b.key_id, 16) == 0);
    assert(strcmp(a.key_id_hex, b.key_id_hex) == 0);

    /* key_id scheme: SHA-256(pub)[:16] */
    unsigned char h[32];
    SHA256(a.public_key, 32, h);
    assert(memcmp(h, a.key_id, 16) == 0);
    char hex[33];
    for (int i = 0; i < 16; i++) snprintf(hex + 2 * i, 3, "%02x", h[i]);
    assert(strcmp(hex, a.key_id_hex) == 0);

    /* Public-only load: same pub + key_id, no secret needed. */
    uint8_t pk[32]; char kid[33];
    assert(virp_chainsign_load_public(PK, pk, kid) == VIRP_OK);
    assert(memcmp(pk, a.public_key, 32) == 0);
    assert(strcmp(kid, a.key_id_hex) == 0);

    virp_chainsign_destroy(&a);
    virp_chainsign_destroy(&b);
}

static void test_sign_verify_basic(void)
{
    virp_chainsign_key_t k;
    assert(virp_chainsign_generate(&k) == VIRP_OK);
    const char *msg = "{\"x\":1}";
    uint8_t sig[64];
    assert(virp_chainsign_sign(&k, VIRP_CHAINSIGN_TAG_ENTRY, msg, strlen(msg), sig) == VIRP_OK);
    assert(virp_chainsign_verify(k.public_key, VIRP_CHAINSIGN_TAG_ENTRY, msg, strlen(msg), sig));
    /* cross-domain */
    assert(!virp_chainsign_verify(k.public_key, VIRP_CHAINSIGN_TAG_HEAD, msg, strlen(msg), sig));
    /* empty message refused both ways */
    assert(virp_chainsign_sign(&k, VIRP_CHAINSIGN_TAG_ENTRY, msg, 0, sig) == VIRP_ERR_INVALID_LENGTH);
    assert(!virp_chainsign_verify(k.public_key, VIRP_CHAINSIGN_TAG_ENTRY, msg, 0, sig));
    /* oversize refused (fail closed) */
    static uint8_t big[5000];
    assert(virp_chainsign_sign(&k, VIRP_CHAINSIGN_TAG_ENTRY, big, sizeof(big), sig) == VIRP_ERR_INVALID_LENGTH);
    /* unloaded key cannot sign */
    virp_chainsign_key_t z; memset(&z, 0, sizeof(z));
    assert(virp_chainsign_sign(&z, VIRP_CHAINSIGN_TAG_ENTRY, msg, strlen(msg), sig) == VIRP_ERR_KEY_NOT_LOADED);
    /* hex round trip */
    char hex[129]; uint8_t back[64];
    virp_chainsign_sig_to_hex(sig, hex);
    assert(strlen(hex) == 128);
    assert(virp_chainsign_sig_from_hex(hex, back) && memcmp(back, sig, 64) == 0);
    hex[5] = 'g';
    assert(!virp_chainsign_sig_from_hex(hex, back));
    assert(!virp_chainsign_sig_from_hex("abcd", back));
    virp_chainsign_destroy(&k);
}

static void test_custody_gate(void)
{
    rm_keys();
    virp_chainsign_key_t k;
    assert(virp_chainsign_generate(&k) == VIRP_OK);
    assert(virp_chainsign_save(&k, SK, PK) == VIRP_OK);
    virp_chainsign_destroy(&k);

    /* group-readable: refused */
    assert(chmod(SK, 0640) == 0);
    assert(virp_chainsign_load(&k, SK) == VIRP_ERR_KEY_NOT_LOADED);
    assert(chmod(SK, 0600) == 0);
    assert(virp_chainsign_load(&k, SK) == VIRP_OK);
    virp_chainsign_destroy(&k);

    /* symlink: refused, even to a good key */
    assert(symlink(SK, "/tmp/virp_test_chainsign.link") == 0);
    assert(virp_chainsign_load(&k, "/tmp/virp_test_chainsign.link") == VIRP_ERR_KEY_NOT_LOADED);
    assert(virp_chainsign_load_public("/tmp/virp_test_chainsign.link", k.public_key, NULL)
           == VIRP_ERR_KEY_NOT_LOADED);

    /* wrong size: distinct error */
    FILE *f = fopen("/tmp/virp_test_chainsign.short", "wb");
    assert(f); fwrite("short", 1, 5, f); fclose(f);
    assert(chmod("/tmp/virp_test_chainsign.short", 0600) == 0);
    assert(virp_chainsign_load(&k, "/tmp/virp_test_chainsign.short") == VIRP_ERR_INVALID_LENGTH);
    assert(virp_chainsign_load_public("/tmp/virp_test_chainsign.short", k.public_key, NULL)
           == VIRP_ERR_INVALID_LENGTH);

    /* corrupt public half inside the secret file: refused */
    uint8_t raw[64];
    f = fopen(SK, "rb"); assert(f && fread(raw, 1, 64, f) == 64); fclose(f);
    raw[40] ^= 0x01;
    unlink(SK);
    f = fopen(SK, "wb"); assert(f && fwrite(raw, 1, 64, f) == 64); fclose(f);
    assert(chmod(SK, 0600) == 0);
    assert(virp_chainsign_load(&k, SK) == VIRP_ERR_CRYPTO);
    rm_keys();
}

static cJSON *load_vectors(void)
{
    const char *path = getenv("VIRP_CHAINSIGN_VECTORS");
    if (!path || !path[0]) path = VECTORS;
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "cannot open %s\n", path); assert(f); }
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    assert(buf && fread(buf, 1, (size_t)n, f) == (size_t)n);
    buf[n] = '\0'; fclose(f);
    cJSON *doc = cJSON_Parse(buf);
    free(buf);
    assert(doc);
    return doc;
}

static void test_golden_vectors_reproduce(void)
{
    cJSON *doc = load_vectors();
    assert(strcmp(jstr(doc, "scheme"), VIRP_CHAINSIGN_SCHEME) == 0);

    /* tags in the file are the tags in the header, NUL included */
    const cJSON *tags = cJSON_GetObjectItemCaseSensitive(doc, "tags");
    uint8_t tb[64];
    size_t tn = unhex(jstr(cJSON_GetObjectItemCaseSensitive(tags, "entry"), "bytes_hex"), tb, sizeof(tb));
    assert(tn == sizeof(VIRP_CHAINSIGN_TAG_ENTRY) && memcmp(tb, VIRP_CHAINSIGN_TAG_ENTRY, tn) == 0);
    tn = unhex(jstr(cJSON_GetObjectItemCaseSensitive(tags, "head"), "bytes_hex"), tb, sizeof(tb));
    assert(tn == sizeof(VIRP_CHAINSIGN_TAG_HEAD) && memcmp(tb, VIRP_CHAINSIGN_TAG_HEAD, tn) == 0);

    const cJSON *tk = cJSON_GetObjectItemCaseSensitive(doc, "test_key");
    uint8_t seed[32], pk[32];
    assert(unhex(jstr(tk, "seed_hex"), seed, 32) == 32);
    assert(unhex(jstr(tk, "public_key_hex"), pk, 32) == 32);

    virp_chainsign_key_t k;
    assert(virp_chainsign_from_seed(&k, seed) == VIRP_OK);
    assert(memcmp(k.public_key, pk, 32) == 0);
    assert(strcmp(k.key_id_hex, jstr(tk, "key_id_hex")) == 0);

    const cJSON *vecs = cJSON_GetObjectItemCaseSensitive(doc, "vectors");
    int count = 0;
    const cJSON *v;
    cJSON_ArrayForEach(v, vecs) {
        bool is_entry = strcmp(jstr(v, "tag"), "entry") == 0;
        const char *tag   = is_entry ? VIRP_CHAINSIGN_TAG_ENTRY : VIRP_CHAINSIGN_TAG_HEAD;
        const char *other = is_entry ? VIRP_CHAINSIGN_TAG_HEAD  : VIRP_CHAINSIGN_TAG_ENTRY;
        static uint8_t msg[4096];
        size_t mlen = unhex(jstr(v, "message_hex"), msg, sizeof(msg));
        assert(mlen == strlen(jstr(v, "message_utf8")) &&
               memcmp(msg, jstr(v, "message_utf8"), mlen) == 0);
        uint8_t want[64], got[64];
        assert(unhex(jstr(v, "signature_hex"), want, 64) == 64);

        /* deterministic: the C signature IS the PyNaCl signature */
        assert(virp_chainsign_sign(&k, tag, msg, mlen, got) == VIRP_OK);
        assert(memcmp(got, want, 64) == 0);
        assert(virp_chainsign_verify(pk, tag, msg, mlen, want));

        /* negatives from the file's expectations */
        assert(!virp_chainsign_verify(pk, other, msg, mlen, want));       /* cross-domain */
        msg[mlen / 2] ^= 0x01;
        assert(!virp_chainsign_verify(pk, tag, msg, mlen, want));         /* tampered message */
        msg[mlen / 2] ^= 0x01;
        assert(!virp_chainsign_verify(pk, tag, msg, mlen - 1, want));     /* one byte short */
        uint8_t bad[64]; memcpy(bad, want, 64); bad[0] ^= 0x80;
        assert(!virp_chainsign_verify(pk, tag, msg, mlen, bad));          /* flipped sig byte */
        virp_chainsign_key_t other_key;
        assert(virp_chainsign_generate(&other_key) == VIRP_OK);
        assert(!virp_chainsign_verify(other_key.public_key, tag, msg, mlen, want)); /* wrong key */
        virp_chainsign_destroy(&other_key);
        count++;
    }
    assert(count >= 4);
    virp_chainsign_destroy(&k);
    cJSON_Delete(doc);
}

static void test_destroy_zeroises(void)
{
    virp_chainsign_key_t k;
    assert(virp_chainsign_generate(&k) == VIRP_OK);
    uint8_t zero[64] = {0};
    assert(memcmp(k.secret_key, zero, 64) != 0);
    virp_chainsign_destroy(&k);
    assert(memcmp(k.secret_key, zero, 64) == 0);
    assert(!k.loaded && !k.locked);
    uint8_t sig[64];
    assert(virp_chainsign_sign(&k, VIRP_CHAINSIGN_TAG_ENTRY, "x", 1, sig) == VIRP_ERR_KEY_NOT_LOADED);
}

int main(void)
{
    printf("\n=== VIRP chain-signing key module (D-1) ===\n\n");
    RUN_TEST(test_generate_save_load_roundtrip);
    RUN_TEST(test_sign_verify_basic);
    RUN_TEST(test_custody_gate);
    RUN_TEST(test_golden_vectors_reproduce);
    RUN_TEST(test_destroy_zeroises);
    rm_keys();
    printf("\n=== All %d chain-signing key tests passed (%d/%d) ===\n\n",
           tests_run, tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
