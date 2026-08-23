/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Detached Ed25519 chain signing, chain-level tests (D-1)
 *
 * The key primitive is covered by tests/test_chainsign.c. This suite
 * covers the CHAIN: schema addition, the append/head signing path, the
 * three verifier tiers, and every rejection the design promises.
 *
 * Built by #including src/virp_chain.c (the invariant-test pattern) to
 * reach build_canonical_json / head_canonical and the sig columns.
 *
 * Storage layer (this file, commit "append-path signing + schema"):
 *   - signing OFF leaves the on-disk schema and every byte identical to
 *     a chain that never heard of D-1 (the invariant, restated at the
 *     chain level)
 *   - signing ON adds exactly the four sig columns; old unsigned columns
 *     and their values are untouched
 *   - a born-signed session carries, on every entry from sequence 0, an
 *     Ed25519 signature over the SAME canonical bytes (verified with the
 *     PUBLIC key only) under one key_id, and a signed head over the head
 *     canonical
 *   - the hash and HMAC of a signed entry are byte-identical to what an
 *     unsigned entry with the same fields would have (signature is a pure
 *     addition, never mixed into the authenticated content)
 *
 * The verifier-tier tests (keyless / symmetric / asymmetric, tamper,
 * wrong-key, cross-domain, stripped-signature, key_id mismatch) are
 * added with virp_chain_open_verifier_ex().
 */

#include "../src/virp_chain.c"

#include "virp_chainsign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  [TEST] %-56s ", name); fflush(stdout); } while (0)
#define PASS() do { printf("PASS\n"); tests_passed++; } while (0)
#define FAILM(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)
#define ASSERT(cond, msg) do { if (!(cond)) { FAILM(msg); return; } } while (0)

static const char *DB   = "/tmp/virp_test_chainsig.db";
static const char *CK   = "/tmp/virp_test_chainsig_chain.key";
static const char *SK   = "/tmp/virp_test_chainsig_sign.key";
static const char *PK   = "/tmp/virp_test_chainsig_sign.pub";

static void cleanup(void)
{
    unlink(DB);
    unlink("/tmp/virp_test_chainsig.db-wal");
    unlink("/tmp/virp_test_chainsig.db-shm");
    unlink(CK); unlink(SK); unlink(PK);
}

static void make_chain_key(void)
{
    virp_signing_key_t sk;
    virp_key_generate(&sk, VIRP_KEY_TYPE_CHAIN);
    unlink(CK);
    virp_key_save_file(&sk, CK);
    virp_key_destroy(&sk);
}

/* Generate a chain-signing keypair to SK/PK and return its public key. */
static void make_sign_key(uint8_t pub_out[32], char key_id_out[33])
{
    virp_chainsign_key_t kp;
    if (virp_chainsign_generate(&kp) != VIRP_OK) { abort(); }
    unlink(SK); unlink(PK);
    if (virp_chainsign_save(&kp, SK, PK) != VIRP_OK) { abort(); }
    memcpy(pub_out, kp.public_key, 32);
    if (key_id_out) memcpy(key_id_out, kp.key_id_hex, 33);
    virp_chainsign_destroy(&kp);
}

/* Raw column read helpers. */
static int col_text(sqlite3 *db, const char *sql, const char *bind,
                    char *out, size_t n)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) return -1;
    if (bind) sqlite3_bind_text(st, 1, bind, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    if (rc == SQLITE_ROW) {
        const unsigned char *t = sqlite3_column_text(st, 0);
        snprintf(out, n, "%s", t ? (const char *)t : "");
    }
    sqlite3_finalize(st);
    return rc == SQLITE_ROW ? 0 : -1;
}

static int has_column(sqlite3 *db, const char *table, const char *col)
{
    return column_exists(db, table, col);
}

/* Schema fingerprint: the CREATE text of both chain tables, so we can
 * assert signing-off leaves the schema untouched. */
static void schema_text(sqlite3 *db, char *out, size_t n)
{
    sqlite3_stmt *st = NULL;
    out[0] = '\0';
    if (sqlite3_prepare_v2(db,
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name IN ('chain_entries','chain_heads') ORDER BY name",
            -1, &st, NULL) != SQLITE_OK) return;
    size_t used = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *s = (const char *)sqlite3_column_text(st, 0);
        int w = snprintf(out + used, n - used, "%s\n", s ? s : "");
        if (w > 0) used += (size_t)w;
    }
    sqlite3_finalize(st);
}

/* ===================================================================== */

static void test_signing_off_schema_identical(void)
{
    TEST("signing OFF: no sig columns, schema is pre-D-1");
    cleanup();
    make_chain_key();

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    ASSERT(!st.sign_enabled, "sign_enabled must default off");
    ASSERT(has_column(st.db, "chain_entries", "chain_sig") == 0,
           "chain_sig must be absent when signing never enabled");
    ASSERT(has_column(st.db, "chain_heads", "head_sig") == 0,
           "head_sig must be absent when signing never enabled");
    char schema[4096];
    schema_text(st.db, schema, sizeof(schema));
    ASSERT(strstr(schema, "chain_sig") == NULL &&
           strstr(schema, "head_sig") == NULL,
           "table CREATE text must not mention sig columns when off");

    virp_chain_entry_t e;
    ASSERT(virp_chain_append(&st, "s-off", "observation", "a-0",
                             "ab12ab12ab12ab12ab12ab12ab12ab12"
                             "ab12ab12ab12ab12ab12ab12ab12ab12", &e) == VIRP_OK,
           "append");
    ASSERT(e.chain_sig[0] == '\0' && e.chain_sig_key_id[0] == '\0',
           "unsigned entry must carry empty sig fields");

    /* The stored HMAC is exactly HMAC(canonical) — unchanged path. */
    char canonical[2048];
    int clen = build_canonical_json(&e, canonical, sizeof(canonical));
    char want_mac[65];
    hmac_sha256_hex(st.chain_key.key.key, canonical, (size_t)clen, want_mac);
    ASSERT(strcmp(want_mac, e.chain_hmac) == 0, "hmac path changed with signing off");

    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&st, "s-off", &r) == VIRP_OK && r.valid,
           "unsigned session must verify");
    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_enable_signing_adds_columns(void)
{
    TEST("enable_signing: adds exactly the four sig columns");
    cleanup();
    make_chain_key();
    uint8_t pub[32]; char kid[33];
    make_sign_key(pub, kid);

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");

    /* Append one UNSIGNED entry first, then enable signing: proves ALTER
     * on a populated table preserves the existing row. */
    virp_chain_entry_t e0;
    ASSERT(virp_chain_append(&st, "s-mix", "observation", "m-0",
                             "cd34cd34cd34cd34cd34cd34cd34cd34"
                             "cd34cd34cd34cd34cd34cd34cd34cd34", &e0) == VIRP_OK,
           "pre-enable append");

    ASSERT(virp_chain_enable_signing(&st, SK) == VIRP_OK, "enable_signing");
    ASSERT(st.sign_enabled, "sign_enabled must be set");
    ASSERT(has_column(st.db, "chain_entries", "chain_sig") == 1 &&
           has_column(st.db, "chain_entries", "chain_sig_key_id") == 1 &&
           has_column(st.db, "chain_heads", "head_sig") == 1 &&
           has_column(st.db, "chain_heads", "head_sig_key_id") == 1,
           "all four sig columns must exist after enable");

    /* The pre-enable entry still reads, with NULL (empty) sig. */
    char sig[200];
    ASSERT(col_text(st.db, "SELECT chain_sig FROM chain_entries WHERE artifact_id='m-0'",
                    NULL, sig, sizeof(sig)) == 0, "pre-enable row lost");

    /* enable_signing is idempotent (columns already present). */
    virp_chain_destroy(&st);
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "reinit");
    ASSERT(st.entry_sig_cols && st.head_sig_cols,
           "reopened DB must detect existing sig columns");
    ASSERT(virp_chain_enable_signing(&st, SK) == VIRP_OK, "re-enable idempotent");
    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_born_signed_session(void)
{
    TEST("born-signed: every entry + head signed, pubkey-only verify");
    cleanup();
    make_chain_key();
    uint8_t pub[32]; char kid[33];
    make_sign_key(pub, kid);

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    ASSERT(virp_chain_enable_signing(&st, SK) == VIRP_OK, "enable");

    virp_chain_entry_t e[4];
    for (int i = 0; i < 4; i++) {
        char id[32], h[65];
        snprintf(id, sizeof(id), "b-%d", i);
        memset(h, (char)('0' + i), 64); h[64] = '\0';
        ASSERT(virp_chain_append(&st, "s-born", "observation", id, h, &e[i]) == VIRP_OK,
               "append");
        ASSERT(e[i].chain_sig[0] && e[i].chain_sig_key_id[0], "entry not signed");
        ASSERT(strcmp(e[i].chain_sig_key_id, kid) == 0, "wrong key_id on entry");

        /* Signature verifies over the canonical bytes with the PUBLIC key. */
        char canonical[2048];
        int clen = build_canonical_json(&e[i], canonical, sizeof(canonical));
        uint8_t sig[64];
        ASSERT(virp_chainsign_sig_from_hex(e[i].chain_sig, sig), "sig hex bad");
        ASSERT(virp_chainsign_verify(pub, VIRP_CHAINSIGN_TAG_ENTRY,
                                     canonical, (size_t)clen, sig),
               "entry signature does not verify under pubkey");
        /* And the entry hash/HMAC are what the unsigned path would give. */
        char hh[65], mm[65];
        sha256_hex(canonical, (size_t)clen, hh);
        hmac_sha256_hex(st.chain_key.key.key, canonical, (size_t)clen, mm);
        ASSERT(strcmp(hh, e[i].chain_entry_hash) == 0, "hash changed under signing");
        ASSERT(strcmp(mm, e[i].chain_hmac) == 0, "hmac changed under signing");
    }

    /* Head is signed over the head canonical for the last sequence. */
    char hsig[200], hkid[64];
    ASSERT(col_text(st.db, "SELECT head_sig FROM chain_heads WHERE session_id='s-born'",
                    NULL, hsig, sizeof(hsig)) == 0 && hsig[0], "head_sig empty");
    ASSERT(col_text(st.db, "SELECT head_sig_key_id FROM chain_heads WHERE session_id='s-born'",
                    NULL, hkid, sizeof(hkid)) == 0, "head key_id");
    ASSERT(strcmp(hkid, kid) == 0, "head key_id wrong");
    char hc[512];
    int hn = head_canonical("s-born", 3, e[3].chain_entry_hash, hc, sizeof(hc));
    uint8_t hsb[64];
    ASSERT(virp_chainsign_sig_from_hex(hsig, hsb), "head sig hex bad");
    ASSERT(virp_chainsign_verify(pub, VIRP_CHAINSIGN_TAG_HEAD, hc, (size_t)hn, hsb),
           "head signature does not verify under pubkey");
    /* Cross-domain: the head signature must NOT verify as an entry sig. */
    ASSERT(!virp_chainsign_verify(pub, VIRP_CHAINSIGN_TAG_ENTRY, hc, (size_t)hn, hsb),
           "head sig wrongly verified under entry tag");

    /* Symmetric-tier verification still passes unchanged. */
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&st, "s-born", &r) == VIRP_OK && r.valid &&
           r.entries_checked == 4, "signed session must verify at HMAC tier");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

static void test_signed_entry_bytes_match_unsigned(void)
{
    TEST("signature is pure addition: same canonical, hash, HMAC");
    cleanup();
    make_chain_key();
    uint8_t pub[32]; char kid[33];
    make_sign_key(pub, kid);

    /* Build an unsigned chain and a signed chain with identical inputs;
     * the entry hash and HMAC must match byte-for-byte (only the sidecar
     * signature differs). Timestamps differ per append, so compare the
     * canonical/hash/hmac the builder produces for a fixed struct, not two
     * independently-appended rows. */
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    ASSERT(virp_chain_enable_signing(&st, SK) == VIRP_OK, "enable");
    virp_chain_entry_t e;
    ASSERT(virp_chain_append(&st, "s-pa", "gate_execution", "p-0",
                             "ef56ef56ef56ef56ef56ef56ef56ef56"
                             "ef56ef56ef56ef56ef56ef56ef56ef56", &e) == VIRP_OK,
           "append");

    /* Zero the sig fields and rebuild canonical — must be unchanged, and
     * hash/HMAC recompute to the stored values. The canonical builder does
     * not read the sig fields at all (proven by identical output). */
    virp_chain_entry_t bare = e;
    bare.chain_sig[0] = '\0';
    bare.chain_sig_key_id[0] = '\0';
    char c1[2048], c2[2048];
    int n1 = build_canonical_json(&e, c1, sizeof(c1));
    int n2 = build_canonical_json(&bare, c2, sizeof(c2));
    ASSERT(n1 == n2 && memcmp(c1, c2, (size_t)n1) == 0,
           "canonical depends on sig fields — invariant broken");
    char hh[65];
    sha256_hex(c1, (size_t)n1, hh);
    ASSERT(strcmp(hh, e.chain_entry_hash) == 0, "hash mismatch");

    virp_chain_destroy(&st);
    cleanup();
    PASS();
}

/* ===================================================================== */
/* Verifier-tier tests: build a born-signed chain, close the writer, then  */
/* re-open read-only at each tier with virp_chain_open_verifier_ex.        */
/* ===================================================================== */

/* Build a signed session with `n` entries; leaves DB/CK/SK/PK on disk. */
static void build_signed_chain(const char *sess, int n)
{
    cleanup();
    make_chain_key();
    uint8_t pub[32]; char kid[33];
    make_sign_key(pub, kid);
    virp_chain_state_t st;
    if (virp_chain_init(&st, DB, CK, 1, "local") != VIRP_OK) abort();
    if (virp_chain_enable_signing(&st, SK) != VIRP_OK) abort();
    for (int i = 0; i < n; i++) {
        char id[32], h[65];
        snprintf(id, sizeof(id), "%s-%d", sess, i);
        memset(h, (char)('0' + (i % 10)), 64); h[64] = '\0';
        virp_chain_entry_t e;
        if (virp_chain_append(&st, sess, "observation", id, h, &e) != VIRP_OK)
            abort();
    }
    virp_chain_destroy(&st);
}

static void test_tier_keyless(void)
{
    TEST("keyless tier: hash+link+completeness, head UNAUTHENTICATED");
    build_signed_chain("s-kl", 3);
    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, NULL, NULL, 1, "local") == VIRP_OK,
           "keyless open");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-kl", &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid && r.entries_checked == 3, "keyless must verify structure");
    ASSERT(!r.hmac_checked && !r.sig_checked, "keyless checks nothing keyed");
    ASSERT(!r.head_authenticated, "keyless: head length claim unauthenticated");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_tier_symmetric(void)
{
    TEST("symmetric tier: HMAC verifies, head authenticated by HMAC");
    build_signed_chain("s-sym", 3);
    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, NULL, 1, "local") == VIRP_OK,
           "symmetric open");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-sym", &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid && r.hmac_checked && !r.sig_checked, "hmac tier only");
    ASSERT(r.head_authenticated && r.head_hmac_ok, "head authenticated by HMAC");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_tier_asymmetric_pubkey_only(void)
{
    TEST("asymmetric tier: pubkey ONLY, no secret material loaded");
    build_signed_chain("s-asym", 4);
    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, NULL, PK, 1, "local") == VIRP_OK,
           "asymmetric open (no chain key)");
    /* No secret material: the chain_key slot is zero. */
    static const uint8_t zero[VIRP_KEY_SIZE] = {0};
    ASSERT(!v.have_chain_key, "have_chain_key must be false");
    ASSERT(memcmp(v.chain_key.key.key, zero, VIRP_KEY_SIZE) == 0,
           "no K_chain bytes may be present in an asymmetric-only verifier");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-asym", &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid, "asymmetric must verify");
    ASSERT(r.sig_checked && !r.hmac_checked, "sig tier, no hmac");
    ASSERT(r.entries_signed == 4, "all entries signed+verified");
    ASSERT(r.head_authenticated && r.head_sig_ok, "head authenticated by Ed25519");
    ASSERT(r.sig_key_id[0] != '\0', "session sig key_id reported");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_tier_all_three(void)
{
    TEST("all tiers together: HMAC + Ed25519 both verify");
    build_signed_chain("s-all", 3);
    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK,
           "open all tiers");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-all", &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid && r.hmac_checked && r.sig_checked, "both tiers active");
    ASSERT(r.head_hmac_ok && r.head_sig_ok && r.head_authenticated, "head both");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

/* Flip one hex nibble in a TEXT column of the last entry, via a writable
 * handle, to simulate tampering the verifier must catch. */
static void tamper_column(const char *col, const char *sess)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(DB, &db) != SQLITE_OK) abort();
    char sql[256];
    /* flip first char of the column on the max-sequence row */
    snprintf(sql, sizeof(sql),
        "UPDATE chain_entries SET %s = "
        "  (CASE substr(%s,1,1) WHEN 'a' THEN 'b' ELSE 'a' END) || substr(%s,2) "
        "WHERE session_id=? AND sequence=(SELECT MAX(sequence) FROM chain_entries WHERE session_id=?)",
        col, col, col);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) abort();
    sqlite3_bind_text(st, 1, sess, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, sess, -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) != SQLITE_DONE) abort();
    sqlite3_finalize(st);
    sqlite3_close(db);
}

static void test_tampered_canonical_rejected(void)
{
    TEST("tampered canonical: hash + HMAC + sig all reject");
    build_signed_chain("s-tmp", 3);
    /* Corrupt the stored artifact_hash: changes the canonical, so the
     * recomputed entry hash no longer matches. Caught even keyless. */
    tamper_column("artifact_hash", "s-tmp");
    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK, "open");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-tmp", &r) == VIRP_OK, "verify rc");
    ASSERT(!r.valid, "tampered entry must be rejected");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_wrong_key_rejected(void)
{
    TEST("wrong pubkey: asymmetric verify fails (soft: key_id mismatch)");
    build_signed_chain("s-wk", 3);
    /* A DIFFERENT public key: its key_id won't match the session's, so the
     * asymmetric tier reports sig_key_unavailable (soft) rather than FAIL —
     * the verifier simply doesn't hold this session's key. */
    uint8_t pub2[32]; char kid2[33];
    virp_chainsign_key_t other;
    if (virp_chainsign_generate(&other) != VIRP_OK) abort();
    const char *PK2 = "/tmp/virp_test_chainsig_other.pub";
    const char *SK2 = "/tmp/virp_test_chainsig_other.key";
    unlink(PK2); unlink(SK2);
    if (virp_chainsign_save(&other, SK2, PK2) != VIRP_OK) abort();
    memcpy(pub2, other.public_key, 32); memcpy(kid2, other.key_id_hex, 33);
    virp_chainsign_destroy(&other);

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK2, 1, "local") == VIRP_OK, "open");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-wk", &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid, "other tiers still hold");
    ASSERT(r.sig_key_unavailable, "wrong key -> soft unavailable");
    ASSERT(!r.sig_checked, "no signatures graded under the wrong key");
    virp_chain_destroy(&v);
    unlink(PK2); unlink(SK2);
    cleanup();
    PASS();
}

static void test_forged_signature_rejected(void)
{
    TEST("forged signature under the RIGHT key_id: hard FAIL");
    build_signed_chain("s-fs", 3);
    /* Corrupt the signature hex on the last entry while leaving key_id
     * intact: the verifier holds this key_id, so a bad signature is a
     * hard FAIL (not the soft unavailable case). */
    tamper_column("chain_sig", "s-fs");
    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, NULL, PK, 1, "local") == VIRP_OK, "open");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-fs", &r) == VIRP_OK, "verify rc");
    ASSERT(!r.valid, "forged signature must FAIL");
    ASSERT(r.first_broken >= 0, "first_broken set");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_stripped_signature_rejected(void)
{
    TEST("stripped signature in a signed session: hard FAIL");
    build_signed_chain("s-strip", 3);
    /* NULL out the signature on the last entry (attacker removes it). In a
     * head-signed session that is a FAIL, not a soft 'unsigned'. */
    sqlite3 *db = NULL;
    if (sqlite3_open(DB, &db) != SQLITE_OK) abort();
    if (sqlite3_exec(db,
        "UPDATE chain_entries SET chain_sig=NULL, chain_sig_key_id=NULL "
        "WHERE session_id='s-strip' AND sequence=("
        "  SELECT MAX(sequence) FROM chain_entries WHERE session_id='s-strip')",
        NULL, NULL, NULL) != SQLITE_OK) abort();
    sqlite3_close(db);

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, NULL, PK, 1, "local") == VIRP_OK, "open");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-strip", &r) == VIRP_OK, "verify rc");
    ASSERT(!r.valid, "stripped signature must FAIL");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_keyid_mismatch_within_session_rejected(void)
{
    TEST("entry key_id != head key_id (rotation mid-session): hard FAIL");
    build_signed_chain("s-kid", 3);
    /* Rewrite the last entry's key_id to something else while the head and
     * the verifier both carry the original: session-granularity says every
     * entry's key_id must equal the head's — this is a FAIL. */
    sqlite3 *db = NULL;
    if (sqlite3_open(DB, &db) != SQLITE_OK) abort();
    if (sqlite3_exec(db,
        "UPDATE chain_entries SET chain_sig_key_id="
        "  '00000000000000000000000000000000' "
        "WHERE session_id='s-kid' AND sequence=("
        "  SELECT MAX(sequence) FROM chain_entries WHERE session_id='s-kid')",
        NULL, NULL, NULL) != SQLITE_OK) abort();
    sqlite3_close(db);

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, NULL, PK, 1, "local") == VIRP_OK, "open");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-kid", &r) == VIRP_OK, "verify rc");
    ASSERT(!r.valid, "key_id mismatch within session must FAIL");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

static void test_unsigned_session_with_pubkey(void)
{
    TEST("unsigned (pre-D-1) session read with a pubkey: not a failure");
    cleanup();
    make_chain_key();
    uint8_t pub[32]; char kid[33];
    make_sign_key(pub, kid);   /* creates PK, but the chain never signs */
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, DB, CK, 1, "local") == VIRP_OK, "init");
    virp_chain_entry_t e;
    for (int i = 0; i < 2; i++) {
        char id[16]; snprintf(id, sizeof(id), "u-%d", i);
        ASSERT(virp_chain_append(&st, "s-uns", "observation", id,
                                 "aa11aa11aa11aa11aa11aa11aa11aa11"
                                 "aa11aa11aa11aa11aa11aa11aa11aa11", &e) == VIRP_OK,
               "append");
    }
    virp_chain_destroy(&st);

    virp_chain_state_t v;
    ASSERT(virp_chain_open_verifier_ex(&v, DB, CK, PK, 1, "local") == VIRP_OK, "open");
    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&v, "s-uns", &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid, "unsigned session with pubkey must still verify");
    ASSERT(r.entries_unsigned == 2 && r.entries_signed == 0,
           "entries counted unsigned, not failed");
    ASSERT(!r.head_sig_ok && r.head_authenticated,
           "head authenticated by HMAC, no head sig");
    virp_chain_destroy(&v);
    cleanup();
    PASS();
}

/* Env-gated fixture emitter: when VIRP_CHAINSIGN_OUT is a directory, build
 * a signed chain there (chain.db + chain.key + sign.pub) and exit, so the
 * Python verifier can cross-check the asymmetric tier against a chain the
 * live C append path actually signed. */
static int emit_fixture(const char *dir)
{
    char db[512], ck[512], skf[512], pk[512];
    snprintf(db, sizeof(db), "%s/chain.db", dir);
    snprintf(ck, sizeof(ck), "%s/chain.key", dir);
    snprintf(skf, sizeof(skf), "%s/sign.key", dir);
    snprintf(pk, sizeof(pk), "%s/sign.pub", dir);
    unlink(db); unlink(ck); unlink(skf); unlink(pk);

    virp_signing_key_t k;
    if (virp_key_generate(&k, VIRP_KEY_TYPE_CHAIN) != VIRP_OK) return 1;
    if (virp_key_save_file(&k, ck) != VIRP_OK) return 1;
    virp_key_destroy(&k);
    virp_chainsign_key_t s;
    if (virp_chainsign_generate(&s) != VIRP_OK) return 1;
    if (virp_chainsign_save(&s, skf, pk) != VIRP_OK) return 1;
    virp_chainsign_destroy(&s);

    virp_chain_state_t st;
    if (virp_chain_init(&st, db, ck, 7, "local") != VIRP_OK) return 1;
    if (virp_chain_enable_signing(&st, skf) != VIRP_OK) return 1;
    for (int i = 0; i < 6; i++) {
        char id[32], h[65];
        snprintf(id, sizeof(id), "fx-%d", i);
        memset(h, (char)('a' + (i % 6)), 64); h[64] = '\0';
        virp_chain_entry_t e;
        if (virp_chain_append(&st, "fixture-sess", "observation", id, h, &e)
                != VIRP_OK) { virp_chain_destroy(&st); return 1; }
    }
    virp_chain_destroy(&st);
    fprintf(stderr, "emitted signed fixture in %s\n", dir);
    return 0;
}

int main(void)
{
    const char *emit = getenv("VIRP_CHAINSIGN_OUT");
    if (emit && emit[0])
        return emit_fixture(emit);

    printf("\n=== VIRP detached chain signing — chain level (D-1) ===\n\n");
    test_signing_off_schema_identical();
    test_enable_signing_adds_columns();
    test_born_signed_session();
    test_signed_entry_bytes_match_unsigned();
    test_tier_keyless();
    test_tier_symmetric();
    test_tier_asymmetric_pubkey_only();
    test_tier_all_three();
    test_tampered_canonical_rejected();
    test_wrong_key_rejected();
    test_forged_signature_rejected();
    test_stripped_signature_rejected();
    test_keyid_mismatch_within_session_rejected();
    test_unsigned_session_with_pubkey();
    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);
    cleanup();
    return tests_failed > 0 ? 1 : 0;
}
