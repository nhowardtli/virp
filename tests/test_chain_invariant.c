/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Chain canonical-bytes INVARIANT regression (D-1 gate)
 *
 * THE ONE INVARIANT: the canonical bytes do not change. Not by one byte.
 *
 * Locks the trust chain's canonical constructions to the D-0 sealing
 * ceremony's Appendix A fixtures (tools/seal/fixtures-appendix-a.json —
 * sha256 recorded in tools/seal/seal-2026-08.json evidence_files) and to
 * a second, non-self-referential set of goldens derived from the
 * independent Python verifier (report/verify.py canonical_json /
 * head_canonical; see tests/test_chain_invariant.py, which regenerates
 * them). Any change to:
 *
 *   - build_canonical_json   (twelve-field fixed-order entry canonical)
 *   - sha256(canonical)      (chain_entry_hash)
 *   - HMAC-SHA256(K_chain)   (chain_hmac, head_hmac, milestone hmac)
 *   - head_canonical         ("v":"VIRP-CHAIN-HEAD-v1")
 *   - insert_milestone's canonical
 *   - the genesis rule       sha256("VIRP_CHAIN_GENESIS:" + session_id)
 *
 * fails this test. It is built by #including src/virp_chain.c directly
 * (the tests/test_driver_linux_black.c pattern) so the STATIC builders
 * are exercised as they are, not through a copy that could drift.
 *
 * Production K_chain is not available here, so the Appendix HMAC values
 * are not reproduced (seal_verify.py --key does that on the sealing
 * host). HMAC is locked instead under a fixed test key, against goldens
 * computed by report/verify.py.
 *
 * Fixture file: tools/seal/fixtures-appendix-a.json, or $VIRP_FIXTURES.
 * If VIRP_INVARIANT_DB is set, the end-to-end section leaves its chain
 * database there for tests/test_chain_invariant.py to re-verify with the
 * Python verifier (cross-implementation lock of the live append path).
 */

#include "../src/virp_chain.c"

#include "cJSON.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { printf("  [TEST] %-60s ", name); fflush(stdout); } while (0)
#define PASS() \
    do { printf("PASS\n"); tests_passed++; } while (0)
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)
#define ASSERT(cond, msg) \
    do { if (!(cond)) { FAIL(msg); return; } } while (0)

static const char *DEFAULT_FIXTURES = "tools/seal/fixtures-appendix-a.json";

/* Fixed test key (bytes 0x01..0x20) — the key the Python half uses. */
static const uint8_t TEST_KEY[VIRP_KEY_SIZE] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
};

static const char *TEST_KEY_PATH = "/tmp/virp_test_chain_invariant.key";
static const char *TEST_DB_PATH  = "/tmp/virp_test_chain_invariant.db";

/* =========================================================================
 * Helpers
 * ========================================================================= */

static char *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)n + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)n, f);
    fclose(f);
    buf[got] = '\0';
    if (out_len) *out_len = got;
    return buf;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode hex into out; returns byte count or -1. */
static int hex_decode(const char *hex, uint8_t *out, size_t out_max)
{
    size_t n = strlen(hex);
    if (n % 2) return -1;
    if (n / 2 > out_max) return -1;
    for (size_t i = 0; i < n; i += 2) {
        int hi = hexval(hex[i]), lo = hexval(hex[i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(n / 2);
}

/*
 * Flat-canonical field extraction. The canonical string has unique,
 * known keys and NO escaping (the C producer uses snprintf), so a
 * textual scan is exact. Numbers are read with strtoull: the fixtures
 * carry 64-bit nanosecond values that a double-backed JSON parser
 * would round, which is precisely what must not happen here.
 */
static const char *find_key(const char *json, const char *key)
{
    char pat[96];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    return p ? p + strlen(pat) : NULL;
}

static int get_str(const char *json, const char *key, char *out, size_t n)
{
    const char *p = find_key(json, key);
    if (!p || *p != '"') return -1;
    p++;
    const char *e = strchr(p, '"');
    if (!e) return -1;
    size_t len = (size_t)(e - p);
    if (len >= n) return -1;
    memcpy(out, p, len);
    out[len] = '\0';
    return 0;
}

static int get_u64(const char *json, const char *key, unsigned long long *v)
{
    const char *p = find_key(json, key);
    if (!p || !isdigit((unsigned char)*p)) return -1;
    *v = strtoull(p, NULL, 10);
    return 0;
}

/* Populate a chain entry struct from a canonical string's fields. */
static int entry_from_canonical(const char *canon, virp_chain_entry_t *e)
{
    unsigned long long v;
    memset(e, 0, sizeof(*e));
    if (get_str(canon, "artifact_hash", e->artifact_hash,
                sizeof(e->artifact_hash))) return -1;
    if (get_str(canon, "artifact_hash_alg", e->artifact_hash_alg,
                sizeof(e->artifact_hash_alg))) return -1;
    if (get_str(canon, "artifact_id", e->artifact_id,
                sizeof(e->artifact_id))) return -1;
    if (get_str(canon, "artifact_schema_version", e->artifact_schema_version,
                sizeof(e->artifact_schema_version))) return -1;
    if (get_str(canon, "artifact_type", e->artifact_type,
                sizeof(e->artifact_type))) return -1;
    if (get_u64(canon, "monotonic_ns", &v)) return -1;
    e->monotonic_ns = (uint64_t)v;
    if (get_str(canon, "previous_entry_hash", e->previous_entry_hash,
                sizeof(e->previous_entry_hash))) return -1;
    if (get_u64(canon, "sequence", &v)) return -1;
    e->sequence = (int64_t)v;
    if (get_str(canon, "session_id", e->session_id,
                sizeof(e->session_id))) return -1;
    if (get_u64(canon, "signer_node_id", &v)) return -1;
    e->signer_node_id = (uint32_t)v;
    if (get_str(canon, "signer_org_id", e->signer_org_id,
                sizeof(e->signer_org_id))) return -1;
    if (get_u64(canon, "timestamp_ns", &v)) return -1;
    e->timestamp_ns = (uint64_t)v;
    return 0;
}

static const char *jstr(const cJSON *o, const char *key)
{
    const cJSON *j = cJSON_GetObjectItemCaseSensitive(o, key);
    return (cJSON_IsString(j) && j->valuestring) ? j->valuestring : NULL;
}

static int jint(const cJSON *o, const char *key, long long *out)
{
    const cJSON *j = cJSON_GetObjectItemCaseSensitive(o, key);
    if (!cJSON_IsNumber(j)) return -1;
    *out = (long long)j->valuedouble;
    return 0;
}

static void cleanup_db(void)
{
    unlink(TEST_DB_PATH);
    unlink("/tmp/virp_test_chain_invariant.db-wal");
    unlink("/tmp/virp_test_chain_invariant.db-shm");
    unlink(TEST_KEY_PATH);
}

static int write_test_key(void)
{
    virp_signing_key_t sk;
    if (virp_key_init(&sk, VIRP_KEY_TYPE_CHAIN, TEST_KEY) != VIRP_OK)
        return -1;
    unlink(TEST_KEY_PATH);
    virp_error_t err = virp_key_save_file(&sk, TEST_KEY_PATH);
    virp_key_destroy(&sk);
    return err == VIRP_OK ? 0 : -1;
}

/* =========================================================================
 * Appendix A — entries
 * ========================================================================= */

static cJSON *g_fixtures = NULL;

static void test_fixture_entry(const char *id)
{
    char name[64];
    snprintf(name, sizeof(name), "Appendix A entry %s: canonical + hash", id);
    TEST(name);

    const cJSON *entries = cJSON_GetObjectItemCaseSensitive(g_fixtures, "entries");
    const cJSON *fx = cJSON_GetObjectItemCaseSensitive(entries, id);
    ASSERT(cJSON_IsObject(fx), "fixture missing");

    const char *utf8 = jstr(fx, "canonical_utf8");
    const char *hex  = jstr(fx, "canonical_hex");
    const char *want_hash = jstr(fx, "chain_entry_hash");
    long long want_len = 0;
    ASSERT(utf8 && want_hash, "fixture fields missing");
    ASSERT(jint(fx, "canonical_len", &want_len) == 0, "canonical_len missing");

    virp_chain_entry_t e;
    ASSERT(entry_from_canonical(utf8, &e) == 0, "could not parse fixture canonical");

    /* Session/sequence in the fixture envelope must agree with the
     * canonical's own fields — guards against a mis-edited fixture. */
    long long fseq = -1;
    ASSERT(jint(fx, "sequence", &fseq) == 0 && fseq == (long long)e.sequence,
           "fixture sequence disagrees with canonical");
    ASSERT(strcmp(jstr(fx, "session_id"), e.session_id) == 0,
           "fixture session_id disagrees with canonical");

    char canonical[2048];
    int clen = build_canonical_json(&e, canonical, sizeof(canonical));
    ASSERT(clen > 0 && clen < (int)sizeof(canonical), "canonical overflow");
    ASSERT(clen == (int)want_len, "canonical length differs from Appendix");
    ASSERT(strlen(utf8) == (size_t)clen && memcmp(canonical, utf8, (size_t)clen) == 0,
           "CANONICAL BYTES DIFFER FROM APPENDIX A (utf8)");

    if (hex && hex[0]) {
        uint8_t raw[2048];
        int rn = hex_decode(hex, raw, sizeof(raw));
        ASSERT(rn == clen && memcmp(canonical, raw, (size_t)rn) == 0,
               "CANONICAL BYTES DIFFER FROM APPENDIX A (hex dump)");
    }

    char hash[65];
    sha256_hex(canonical, (size_t)clen, hash);
    ASSERT(strcmp(hash, want_hash) == 0,
           "sha256(canonical) differs from Appendix chain_entry_hash");

    /* Body binding, where the Appendix retains the body: the digest
     * helper the verifier uses must reproduce the committed hash. */
    const char *body = jstr(fx, "artifact_content");
    const char *body_hash = jstr(fx, "artifact_hash_of_body");
    if (body && body_hash && body_hash[0]) {
        char digest[65];
        ASSERT(virp_chain_artifact_digest(body, digest) == VIRP_OK,
               "artifact digest failed");
        ASSERT(strcmp(digest, body_hash) == 0 &&
               strcmp(digest, e.artifact_hash) == 0,
               "artifact body does not hash to the committed artifact_hash");
    }
    const char *decoded = jstr(fx, "decoded_hex");
    if (decoded && decoded[0]) {
        uint8_t raw[8192];
        int rn = hex_decode(decoded, raw, sizeof(raw));
        ASSERT(rn > 0, "decoded_hex undecodable");
        char digest[65];
        sha256_hex((const char *)raw, (size_t)rn, digest);
        ASSERT(strcmp(digest, e.artifact_hash) == 0,
               "decoded observation bytes do not hash to artifact_hash");
    }
    PASS();
}

static void test_fixture_links(void)
{
    TEST("Appendix A links: D -> B -> C previous_entry_hash");
    const cJSON *entries = cJSON_GetObjectItemCaseSensitive(g_fixtures, "entries");
    const cJSON *B = cJSON_GetObjectItemCaseSensitive(entries, "B");
    const cJSON *C = cJSON_GetObjectItemCaseSensitive(entries, "C");
    const cJSON *D = cJSON_GetObjectItemCaseSensitive(entries, "D");
    ASSERT(B && C && D, "fixtures missing");

    virp_chain_entry_t eb, ec;
    ASSERT(entry_from_canonical(jstr(B, "canonical_utf8"), &eb) == 0, "parse B");
    ASSERT(entry_from_canonical(jstr(C, "canonical_utf8"), &ec) == 0, "parse C");
    ASSERT(strcmp(ec.previous_entry_hash, jstr(B, "chain_entry_hash")) == 0,
           "C.previous_entry_hash != B.chain_entry_hash");
    ASSERT(strcmp(eb.previous_entry_hash, jstr(D, "chain_entry_hash")) == 0,
           "B.previous_entry_hash != D.chain_entry_hash");
    PASS();
}

static void test_fixture_genesis(void)
{
    TEST("Appendix A genesis rule");
    const cJSON *gen = cJSON_GetObjectItemCaseSensitive(g_fixtures, "genesis");
    ASSERT(cJSON_IsArray(gen), "genesis list missing");
    int checked = 0;
    const cJSON *g;
    cJSON_ArrayForEach(g, gen) {
        const char *sid = jstr(g, "session_id");
        const char *want = jstr(g, "genesis_hash");
        if (!sid || !want) continue;     /* the note-only record */
        char got[65];
        compute_genesis_hash(sid, got);
        ASSERT(strcmp(got, want) == 0, "genesis hash differs from Appendix");
        checked++;
    }
    ASSERT(checked >= 1, "no genesis record checked");

    /* Fixture A is sequence 0 of its session: its previous_entry_hash
     * IS the genesis hash of that session. */
    const cJSON *entries = cJSON_GetObjectItemCaseSensitive(g_fixtures, "entries");
    const cJSON *A = cJSON_GetObjectItemCaseSensitive(entries, "A");
    virp_chain_entry_t ea;
    ASSERT(entry_from_canonical(jstr(A, "canonical_utf8"), &ea) == 0, "parse A");
    ASSERT(ea.sequence == 0, "fixture A is not sequence 0");
    char got[65];
    compute_genesis_hash(ea.session_id, got);
    ASSERT(strcmp(got, ea.previous_entry_hash) == 0,
           "A.previous_entry_hash != genesis(session)");
    PASS();
}

static void test_fixture_head(void)
{
    TEST("Appendix A head canonical (VIRP-CHAIN-HEAD-v1)");
    const cJSON *hd = cJSON_GetObjectItemCaseSensitive(g_fixtures, "head");
    ASSERT(cJSON_IsObject(hd), "head fixture missing");
    long long seq;
    ASSERT(jint(hd, "last_sequence", &seq) == 0, "last_sequence missing");
    const char *sid = jstr(hd, "session_id");
    const char *lh = jstr(hd, "last_entry_hash");
    const char *utf8 = jstr(hd, "canonical_utf8");
    const char *hex = jstr(hd, "canonical_hex");
    ASSERT(sid && lh && utf8, "head fields missing");

    char canonical[512];
    int n = head_canonical(sid, seq, lh, canonical, sizeof(canonical));
    ASSERT(n > 0 && n < (int)sizeof(canonical), "head canonical overflow");
    ASSERT(strlen(utf8) == (size_t)n && memcmp(canonical, utf8, (size_t)n) == 0,
           "HEAD CANONICAL DIFFERS FROM APPENDIX A (utf8)");
    if (hex && hex[0]) {
        uint8_t raw[512];
        int rn = hex_decode(hex, raw, sizeof(raw));
        ASSERT(rn == n && memcmp(canonical, raw, (size_t)rn) == 0,
               "HEAD CANONICAL DIFFERS FROM APPENDIX A (hex dump)");
    }
    PASS();
}

/*
 * The milestone canonical is built inline in insert_milestone(), which
 * writes a row. Drive the real function against a scratch chain with the
 * fixed test key and check the stored HMAC equals HMAC(test key, Appendix
 * milestone canonical): the only way that holds is if insert_milestone
 * produced the Appendix bytes.
 */
static void test_fixture_milestone(void)
{
    TEST("Appendix A milestone canonical (via insert_milestone)");
    const cJSON *ms = cJSON_GetObjectItemCaseSensitive(g_fixtures, "milestone");
    ASSERT(cJSON_IsObject(ms), "milestone fixture missing");
    long long seq, covered;
    ASSERT(jint(ms, "sequence", &seq) == 0 &&
           jint(ms, "entries_covered", &covered) == 0, "milestone ints missing");
    const char *sid = jstr(ms, "session_id");
    const char *cum = jstr(ms, "cumulative_hash");
    const char *utf8 = jstr(ms, "canonical_utf8");
    ASSERT(sid && cum && utf8, "milestone fields missing");

    cleanup_db();
    ASSERT(write_test_key() == 0, "test key write failed");
    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, TEST_DB_PATH, TEST_KEY_PATH, 1, "local") == VIRP_OK,
           "chain init failed");
    ASSERT(insert_milestone(&st, sid, seq, covered, cum) == VIRP_OK,
           "insert_milestone failed");

    sqlite3_stmt *q = NULL;
    ASSERT(sqlite3_prepare_v2(st.db,
            "SELECT chain_hmac, cumulative_hash FROM chain_milestones "
            "WHERE session_id = ? AND sequence = ?", -1, &q, NULL) == SQLITE_OK,
           "prepare failed");
    sqlite3_bind_text(q, 1, sid, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(q, 2, seq);
    ASSERT(sqlite3_step(q) == SQLITE_ROW, "milestone row missing");
    char stored[65];
    snprintf(stored, sizeof(stored), "%s", (const char *)sqlite3_column_text(q, 0));
    sqlite3_finalize(q);

    char want[65];
    hmac_sha256_hex(TEST_KEY, utf8, strlen(utf8), want);
    ASSERT(strcmp(stored, want) == 0,
           "MILESTONE CANONICAL DIFFERS FROM APPENDIX A");

    virp_chain_destroy(&st);
    cleanup_db();
    PASS();
}

/* =========================================================================
 * Second lock — goldens generated by report/verify.py (see the Python
 * half; regenerate with `python3 tests/test_chain_invariant.py --print-goldens`)
 * ========================================================================= */

#define GOLD_SID "inv-lock-1"
#define GOLD_GENESIS \
    "18d2b8a84c417dc511143e5cce9d4f50313041d0ff750cd548697be7ca33e656"
#define GOLD_C0 \
    "{\"artifact_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\"," \
    "\"artifact_hash_alg\":\"sha256\",\"artifact_id\":\"obs:inv-lock:0001\"," \
    "\"artifact_schema_version\":\"1\",\"artifact_type\":\"observation\"," \
    "\"monotonic_ns\":123456789012345," \
    "\"previous_entry_hash\":\"" GOLD_GENESIS "\"," \
    "\"sequence\":0,\"session_id\":\"inv-lock-1\",\"signer_node_id\":1," \
    "\"signer_org_id\":\"local\",\"timestamp_ns\":1787000000123456789}"
#define GOLD_H0 \
    "d9278b4a17debc43c289a591b2ec6ae9a0deb0db7c8fb10ff0bbdc0cfbca0f1b"
#define GOLD_M0 \
    "a947631316dd2d2894c636603acd4cfb70012e7b3ca56127d5441b548b28bbdf"
#define GOLD_C1 \
    "{\"artifact_hash\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"," \
    "\"artifact_hash_alg\":\"sha256\",\"artifact_id\":\"cmp:inv-lock:0002\"," \
    "\"artifact_schema_version\":\"1\",\"artifact_type\":\"comparator_verd\"," \
    "\"monotonic_ns\":9223372036854775807," \
    "\"previous_entry_hash\":\"" GOLD_H0 "\"," \
    "\"sequence\":1,\"session_id\":\"inv-lock-1\",\"signer_node_id\":4294967295," \
    "\"signer_org_id\":\"test-org\",\"timestamp_ns\":18446744073709551615}"
#define GOLD_H1 \
    "707f38d352e3a0e0c9eb12f5012e86b36950e1c6fe552575a2056e869bd61bfb"
#define GOLD_M1 \
    "5b220e6f07ca95cd9a8d0068d2b3d18b38ba351d74324d9ab585946b4c2494b4"
#define GOLD_HEAD \
    "{\"last_entry_hash\":\"" GOLD_H1 "\",\"last_sequence\":1," \
    "\"session_id\":\"inv-lock-1\",\"v\":\"VIRP-CHAIN-HEAD-v1\"}"
#define GOLD_HEAD_MAC \
    "70466f7162c9c3bba8ef23d2dabc83ee3a8e7196470fc672e84a8bec567632e8"

static void check_golden(const virp_chain_entry_t *e, const char *want_c,
                         const char *want_h, const char *want_m, int *ok)
{
    char canonical[2048];
    int clen = build_canonical_json(e, canonical, sizeof(canonical));
    if (clen <= 0 || strlen(want_c) != (size_t)clen ||
        memcmp(canonical, want_c, (size_t)clen) != 0) { *ok = 0; return; }
    char h[65], m[65];
    sha256_hex(canonical, (size_t)clen, h);
    hmac_sha256_hex(TEST_KEY, canonical, (size_t)clen, m);
    if (strcmp(h, want_h) != 0 || strcmp(m, want_m) != 0) *ok = 0;
}

static void test_verifypy_goldens(void)
{
    TEST("verify.py-derived goldens: canonical, sha256, HMAC, head, genesis");
    int ok = 1;

    char gen[65];
    compute_genesis_hash(GOLD_SID, gen);
    ASSERT(strcmp(gen, GOLD_GENESIS) == 0, "genesis differs from verify.py");

    virp_chain_entry_t e0;
    memset(&e0, 0, sizeof(e0));
    snprintf(e0.session_id, sizeof(e0.session_id), GOLD_SID);
    e0.sequence = 0;
    snprintf(e0.previous_entry_hash, sizeof(e0.previous_entry_hash), GOLD_GENESIS);
    e0.timestamp_ns = 1787000000123456789ULL;
    e0.monotonic_ns = 123456789012345ULL;
    snprintf(e0.artifact_type, sizeof(e0.artifact_type), "observation");
    snprintf(e0.artifact_id, sizeof(e0.artifact_id), "obs:inv-lock:0001");
    memset(e0.artifact_hash, '0', 64);
    snprintf(e0.artifact_hash_alg, sizeof(e0.artifact_hash_alg), "sha256");
    snprintf(e0.artifact_schema_version, sizeof(e0.artifact_schema_version), "1");
    e0.signer_node_id = 1;
    snprintf(e0.signer_org_id, sizeof(e0.signer_org_id), "local");
    check_golden(&e0, GOLD_C0, GOLD_H0, GOLD_M0, &ok);
    ASSERT(ok, "entry 0 differs from verify.py goldens");

    virp_chain_entry_t e1;
    memset(&e1, 0, sizeof(e1));
    snprintf(e1.session_id, sizeof(e1.session_id), GOLD_SID);
    e1.sequence = 1;
    snprintf(e1.previous_entry_hash, sizeof(e1.previous_entry_hash), GOLD_H0);
    e1.timestamp_ns = 18446744073709551615ULL;        /* UINT64_MAX */
    e1.monotonic_ns = 9223372036854775807ULL;         /* INT64_MAX  */
    snprintf(e1.artifact_type, sizeof(e1.artifact_type), "comparator_verd");
    snprintf(e1.artifact_id, sizeof(e1.artifact_id), "cmp:inv-lock:0002");
    memset(e1.artifact_hash, 'f', 64);
    snprintf(e1.artifact_hash_alg, sizeof(e1.artifact_hash_alg), "sha256");
    snprintf(e1.artifact_schema_version, sizeof(e1.artifact_schema_version), "1");
    e1.signer_node_id = 4294967295U;                  /* UINT32_MAX */
    snprintf(e1.signer_org_id, sizeof(e1.signer_org_id), "test-org");
    check_golden(&e1, GOLD_C1, GOLD_H1, GOLD_M1, &ok);
    ASSERT(ok, "entry 1 differs from verify.py goldens");

    char hc[512];
    int n = head_canonical(GOLD_SID, 1, GOLD_H1, hc, sizeof(hc));
    ASSERT(n > 0 && strlen(GOLD_HEAD) == (size_t)n && memcmp(hc, GOLD_HEAD, (size_t)n) == 0,
           "head canonical differs from verify.py");
    char hm[65];
    hmac_sha256_hex(TEST_KEY, hc, (size_t)n, hm);
    ASSERT(strcmp(hm, GOLD_HEAD_MAC) == 0, "head HMAC differs from verify.py");
    PASS();
}

/* =========================================================================
 * End to end — the LIVE append path under the fixed key. Every stored
 * hash/HMAC/head must be what the static builders produce, and the
 * session must verify. The DB is left at $VIRP_INVARIANT_DB (if set) for
 * the Python verifier to re-verify independently.
 * ========================================================================= */

static void test_e2e_append_path(void)
{
    TEST("End-to-end append: stored hash/HMAC/head match builders");
    const char *keep = getenv("VIRP_INVARIANT_DB");
    const char *db = keep && keep[0] ? keep : TEST_DB_PATH;

    cleanup_db();
    if (keep && keep[0]) unlink(keep);
    ASSERT(write_test_key() == 0, "test key write failed");

    virp_chain_state_t st;
    ASSERT(virp_chain_init(&st, db, TEST_KEY_PATH, 7, "inv-org") == VIRP_OK,
           "chain init failed");

    virp_chain_entry_t e[3];
    static const char *types[3] = { "observation", "gate_execution", "no_drift" };
    for (int i = 0; i < 3; i++) {
        char id[64], hash[65];
        snprintf(id, sizeof(id), "inv:e2e:%04d", i);
        memset(hash, (char)('a' + i), 64);
        hash[64] = '\0';
        ASSERT(virp_chain_append_with_artifact(&st, "inv-e2e", types[i], id, hash,
                                               i == 1 ? "" : NULL, &e[i]) == VIRP_OK,
               "append failed");
        char canonical[2048];
        int clen = build_canonical_json(&e[i], canonical, sizeof(canonical));
        char h[65], m[65];
        sha256_hex(canonical, (size_t)clen, h);
        hmac_sha256_hex(TEST_KEY, canonical, (size_t)clen, m);
        ASSERT(strcmp(h, e[i].chain_entry_hash) == 0, "stored hash != sha256(canonical)");
        ASSERT(strcmp(m, e[i].chain_hmac) == 0, "stored hmac != HMAC(canonical)");
        if (i == 0) {
            char gen[65];
            compute_genesis_hash("inv-e2e", gen);
            ASSERT(strcmp(gen, e[0].previous_entry_hash) == 0, "genesis link wrong");
        } else {
            ASSERT(strcmp(e[i - 1].chain_entry_hash, e[i].previous_entry_hash) == 0,
                   "link wrong");
        }
    }

    /* Head row: HMAC over head_canonical under the same key. */
    sqlite3_stmt *q = NULL;
    ASSERT(sqlite3_prepare_v2(st.db,
            "SELECT last_sequence, last_entry_hash, head_hmac FROM chain_heads "
            "WHERE session_id = 'inv-e2e'", -1, &q, NULL) == SQLITE_OK, "prepare");
    ASSERT(sqlite3_step(q) == SQLITE_ROW, "head row missing");
    ASSERT(sqlite3_column_int64(q, 0) == 2, "head last_sequence != 2");
    ASSERT(strcmp((const char *)sqlite3_column_text(q, 1), e[2].chain_entry_hash) == 0,
           "head last_entry_hash != last entry");
    char hc[512], hm[65];
    int n = head_canonical("inv-e2e", 2, e[2].chain_entry_hash, hc, sizeof(hc));
    hmac_sha256_hex(TEST_KEY, hc, (size_t)n, hm);
    ASSERT(strcmp((const char *)sqlite3_column_text(q, 2), hm) == 0,
           "stored head_hmac != HMAC(head_canonical)");
    sqlite3_finalize(q);

    virp_chain_verify_result_t r;
    ASSERT(virp_chain_verify_session(&st, "inv-e2e", &r) == VIRP_OK, "verify rc");
    ASSERT(r.valid && r.entries_checked == 3, "session did not verify");

    virp_chain_destroy(&st);
    if (!(keep && keep[0])) cleanup_db();
    else unlink(TEST_KEY_PATH);
    PASS();
}

/* ========================================================================= */

int main(void)
{
    printf("\n=== VIRP Chain Canonical-Bytes INVARIANT (D-0 Appendix A lock) ===\n\n");

    const char *path = getenv("VIRP_FIXTURES");
    if (!path || !path[0]) path = DEFAULT_FIXTURES;
    size_t len = 0;
    char *text = read_file(path, &len);
    if (!text) {
        fprintf(stderr, "cannot read fixtures: %s (set VIRP_FIXTURES)\n", path);
        return 1;
    }
    g_fixtures = cJSON_Parse(text);
    if (!g_fixtures) {
        fprintf(stderr, "fixtures are not valid JSON: %s\n", path);
        return 1;
    }
    printf("  fixtures: %s (%zu bytes)\n\n", path, len);

    test_fixture_entry("A");
    test_fixture_entry("B");
    test_fixture_entry("C");
    test_fixture_entry("D");
    test_fixture_entry("E");
    test_fixture_links();
    test_fixture_genesis();
    test_fixture_head();
    test_fixture_milestone();
    test_verifypy_goldens();
    test_e2e_append_path();

    cJSON_Delete(g_fixtures);
    free(text);

    printf("\n=== Results: %d passed, %d failed ===\n\n",
           tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
