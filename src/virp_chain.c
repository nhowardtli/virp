/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Primitive 6: Trust Chain Implementation
 *
 * SQLite-backed, session-scoped chain with:
 *   - Canonical JSON serialization (alphabetical keys, compact separators)
 *   - Transactional sequencing (BEGIN IMMEDIATE → COMMIT)
 *   - HMAC-SHA256 via K_chain (key type 3)
 *   - Auto-milestones every 100 entries
 *   - Crash recovery: sequence assigned only at COMMIT
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime */

#include "virp_chain.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

/* =========================================================================
 * SQL Schema
 * ========================================================================= */

static const char *SCHEMA_SQL =
    "CREATE TABLE IF NOT EXISTS chain_entries ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  session_id TEXT NOT NULL,"
    "  sequence INTEGER NOT NULL,"
    "  chain_entry_hash TEXT NOT NULL,"
    "  previous_entry_hash TEXT NOT NULL,"
    "  timestamp_ns INTEGER NOT NULL,"
    "  monotonic_ns INTEGER NOT NULL,"
    "  artifact_type TEXT NOT NULL,"
    "  artifact_id TEXT NOT NULL,"
    "  artifact_hash TEXT NOT NULL,"
    "  artifact_hash_alg TEXT NOT NULL DEFAULT 'sha256',"
    "  artifact_schema_version TEXT NOT NULL DEFAULT '1',"
    "  signer_node_id INTEGER NOT NULL,"
    "  signer_org_id TEXT NOT NULL DEFAULT 'local',"
    "  chain_hmac TEXT NOT NULL,"
    "  UNIQUE(session_id, sequence)"
    ");"
    "CREATE TABLE IF NOT EXISTS chain_milestones ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  session_id TEXT NOT NULL,"
    "  sequence INTEGER NOT NULL,"
    "  entries_covered INTEGER NOT NULL,"
    "  cumulative_hash TEXT NOT NULL,"
    "  chain_hmac TEXT NOT NULL,"
    "  created_at_ns INTEGER NOT NULL,"
    "  UNIQUE(session_id, sequence)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_chain_session_seq "
    "  ON chain_entries(session_id, sequence);"
    "CREATE TABLE IF NOT EXISTS intents ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  intent_id TEXT NOT NULL UNIQUE,"
    "  intent_hash TEXT NOT NULL,"
    "  intent_json TEXT NOT NULL,"
    "  confidence TEXT NOT NULL,"
    "  expires_at_ns INTEGER NOT NULL,"
    "  max_commands INTEGER NOT NULL,"
    "  commands_executed INTEGER NOT NULL DEFAULT 0,"
    "  proposed_actions TEXT NOT NULL,"
    "  constraints TEXT NOT NULL,"
    "  signature_hmac TEXT NOT NULL,"
    "  signature_seq INTEGER NOT NULL,"
    "  signature_timestamp_ns INTEGER NOT NULL,"
    "  created_at_ns INTEGER NOT NULL"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_intents_id ON intents(intent_id);";

/* =========================================================================
 * Prepared Statement SQL
 * ========================================================================= */

static const char *SQL_INSERT =
    "INSERT INTO chain_entries "
    "(session_id, sequence, chain_entry_hash, previous_entry_hash, "
    " timestamp_ns, monotonic_ns, artifact_type, artifact_id, "
    " artifact_hash, artifact_hash_alg, artifact_schema_version, "
    " signer_node_id, signer_org_id, chain_hmac) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

static const char *SQL_GET_LAST =
    "SELECT session_id, sequence, chain_entry_hash, previous_entry_hash, "
    "  timestamp_ns, monotonic_ns, artifact_type, artifact_id, "
    "  artifact_hash, artifact_hash_alg, artifact_schema_version, "
    "  signer_node_id, signer_org_id, chain_hmac "
    "FROM chain_entries WHERE session_id = ? "
    "ORDER BY sequence DESC LIMIT 1";

static const char *SQL_GET_RANGE =
    "SELECT session_id, sequence, chain_entry_hash, previous_entry_hash, "
    "  timestamp_ns, monotonic_ns, artifact_type, artifact_id, "
    "  artifact_hash, artifact_hash_alg, artifact_schema_version, "
    "  signer_node_id, signer_org_id, chain_hmac "
    "FROM chain_entries WHERE session_id = ? "
    "AND sequence >= ? AND sequence <= ? "
    "ORDER BY sequence ASC";

static const char *SQL_INSERT_MILESTONE =
    "INSERT OR REPLACE INTO chain_milestones "
    "(session_id, sequence, entries_covered, cumulative_hash, "
    " chain_hmac, created_at_ns) "
    "VALUES (?,?,?,?,?,?)";

/* Intent store SQL */
static const char *SQL_INTENT_INSERT =
    "INSERT OR REPLACE INTO intents "
    "(intent_id, intent_hash, intent_json, confidence, expires_at_ns, "
    " max_commands, commands_executed, proposed_actions, constraints, "
    " signature_hmac, signature_seq, signature_timestamp_ns, created_at_ns) "
    "VALUES (?,?,?,?,?,?,0,?,?,?,?,?,?)";

static const char *SQL_INTENT_GET =
    "SELECT intent_id, intent_hash, intent_json, confidence, expires_at_ns, "
    "  max_commands, commands_executed, proposed_actions, constraints, "
    "  signature_hmac, signature_seq, signature_timestamp_ns, created_at_ns "
    "FROM intents WHERE intent_id = ?";

static const char *SQL_INTENT_EXECUTE =
    "UPDATE intents SET commands_executed = commands_executed + 1 "
    "WHERE intent_id = ? AND commands_executed < max_commands";

/* =========================================================================
 * Helpers
 * ========================================================================= */

static void sha256_hex(const char *data, size_t len, char out[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", hash[i]);
    out[64] = '\0';
}

static void hmac_sha256_hex(const uint8_t key[VIRP_KEY_SIZE],
                            const char *data, size_t len,
                            char out[65])
{
    uint8_t hmac_bytes[VIRP_HMAC_SIZE];
    virp_hmac_sha256(key, (const uint8_t *)data, len, hmac_bytes);
    for (int i = 0; i < VIRP_HMAC_SIZE; i++)
        snprintf(out + i * 2, 3, "%02x", hmac_bytes[i]);
    out[64] = '\0';
}

static uint64_t get_wall_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t get_mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void compute_genesis_hash(const char *session_id, char out[65])
{
    char buf[256];
    int n = snprintf(buf, sizeof(buf), "%s%s",
                     VIRP_CHAIN_GENESIS_PREFIX, session_id);
    sha256_hex(buf, (size_t)n, out);
}

/*
 * Build canonical JSON for hashing/HMAC.
 * Keys are alphabetically sorted. Compact separators (no spaces).
 * Excludes chain_entry_hash and chain_hmac (computed from this).
 */
static int build_canonical_json(const virp_chain_entry_t *e,
                                char *buf, size_t buf_len)
{
    return snprintf(buf, buf_len,
        "{\"artifact_hash\":\"%s\","
        "\"artifact_hash_alg\":\"%s\","
        "\"artifact_id\":\"%s\","
        "\"artifact_schema_version\":\"%s\","
        "\"artifact_type\":\"%s\","
        "\"monotonic_ns\":%llu,"
        "\"previous_entry_hash\":\"%s\","
        "\"sequence\":%lld,"
        "\"session_id\":\"%s\","
        "\"signer_node_id\":%u,"
        "\"signer_org_id\":\"%s\","
        "\"timestamp_ns\":%llu}",
        e->artifact_hash,
        e->artifact_hash_alg,
        e->artifact_id,
        e->artifact_schema_version,
        e->artifact_type,
        (unsigned long long)e->monotonic_ns,
        e->previous_entry_hash,
        (long long)e->sequence,
        e->session_id,
        e->signer_node_id,
        e->signer_org_id,
        (unsigned long long)e->timestamp_ns);
}

static void read_entry_from_stmt(sqlite3_stmt *stmt, virp_chain_entry_t *e)
{
    memset(e, 0, sizeof(*e));
    snprintf(e->session_id, sizeof(e->session_id), "%s",
             (const char *)sqlite3_column_text(stmt, 0));
    e->sequence = sqlite3_column_int64(stmt, 1);
    snprintf(e->chain_entry_hash, sizeof(e->chain_entry_hash), "%s",
             (const char *)sqlite3_column_text(stmt, 2));
    snprintf(e->previous_entry_hash, sizeof(e->previous_entry_hash), "%s",
             (const char *)sqlite3_column_text(stmt, 3));
    e->timestamp_ns = (uint64_t)sqlite3_column_int64(stmt, 4);
    e->monotonic_ns = (uint64_t)sqlite3_column_int64(stmt, 5);
    snprintf(e->artifact_type, sizeof(e->artifact_type), "%s",
             (const char *)sqlite3_column_text(stmt, 6));
    snprintf(e->artifact_id, sizeof(e->artifact_id), "%s",
             (const char *)sqlite3_column_text(stmt, 7));
    snprintf(e->artifact_hash, sizeof(e->artifact_hash), "%s",
             (const char *)sqlite3_column_text(stmt, 8));
    snprintf(e->artifact_hash_alg, sizeof(e->artifact_hash_alg), "%s",
             (const char *)sqlite3_column_text(stmt, 9));
    snprintf(e->artifact_schema_version, sizeof(e->artifact_schema_version),
             "%s", (const char *)sqlite3_column_text(stmt, 10));
    e->signer_node_id = (uint32_t)sqlite3_column_int(stmt, 11);
    snprintf(e->signer_org_id, sizeof(e->signer_org_id), "%s",
             (const char *)sqlite3_column_text(stmt, 12));
    snprintf(e->chain_hmac, sizeof(e->chain_hmac), "%s",
             (const char *)sqlite3_column_text(stmt, 13));
}

/* =========================================================================
 * Milestone
 * ========================================================================= */

static virp_error_t insert_milestone(virp_chain_state_t *state,
                                     const char *session_id,
                                     int64_t sequence,
                                     int64_t entries_covered,
                                     const char *cumulative_hash)
{
    /* Compute HMAC over milestone data */
    char milestone_json[512];
    int n = snprintf(milestone_json, sizeof(milestone_json),
        "{\"cumulative_hash\":\"%s\","
        "\"entries_covered\":%lld,"
        "\"sequence\":%lld,"
        "\"session_id\":\"%s\"}",
        cumulative_hash,
        (long long)entries_covered,
        (long long)sequence,
        session_id);

    char hmac_hex[65];
    hmac_sha256_hex(state->chain_key.key.key,
                    milestone_json, (size_t)n, hmac_hex);

    sqlite3_reset(state->stmt_insert_milestone);
    sqlite3_bind_text(state->stmt_insert_milestone, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(state->stmt_insert_milestone, 2, sequence);
    sqlite3_bind_int64(state->stmt_insert_milestone, 3, entries_covered);
    sqlite3_bind_text(state->stmt_insert_milestone, 4, cumulative_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert_milestone, 5, hmac_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(state->stmt_insert_milestone, 6, (int64_t)get_wall_ns());

    int rc = sqlite3_step(state->stmt_insert_milestone);
    sqlite3_reset(state->stmt_insert_milestone);

    return (rc == SQLITE_DONE) ? VIRP_OK : VIRP_ERR_CHAIN_DB;
}

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

virp_error_t virp_chain_init(virp_chain_state_t *state,
                             const char *db_path,
                             const char *chain_key_path,
                             uint32_t node_id,
                             const char *org_id)
{
    if (!state || !db_path || !chain_key_path)
        return VIRP_ERR_NULL_PTR;

    memset(state, 0, sizeof(*state));
    state->node_id = node_id;
    snprintf(state->org_id, sizeof(state->org_id), "%s",
             org_id ? org_id : "local");

    /* Load chain key (key type 3) */
    virp_error_t err = virp_key_load_file(&state->chain_key,
                                          VIRP_KEY_TYPE_CHAIN,
                                          chain_key_path);
    if (err != VIRP_OK) {
        fprintf(stderr, "[Chain] Failed to load chain key from %s: %s\n",
                chain_key_path, virp_error_str(err));
        return err;
    }

    /* Open SQLite database */
    int rc = sqlite3_open(db_path, &state->db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Chain] Failed to open DB %s: %s\n",
                db_path, sqlite3_errmsg(state->db));
        return VIRP_ERR_CHAIN_DB;
    }

    /* WAL mode for better concurrency */
    sqlite3_exec(state->db, "PRAGMA journal_mode=WAL;", NULL, NULL, NULL);
    sqlite3_exec(state->db, "PRAGMA synchronous=NORMAL;", NULL, NULL, NULL);

    /* Create schema */
    char *errmsg = NULL;
    rc = sqlite3_exec(state->db, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Chain] Schema error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(state->db);
        return VIRP_ERR_CHAIN_DB;
    }

    /* Prepare statements */
    if (sqlite3_prepare_v2(state->db, SQL_INSERT, -1,
                           &state->stmt_insert, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_GET_LAST, -1,
                           &state->stmt_get_last, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_GET_RANGE, -1,
                           &state->stmt_get_range, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_INSERT_MILESTONE, -1,
                           &state->stmt_insert_milestone, NULL) != SQLITE_OK) {
        fprintf(stderr, "[Chain] Failed to prepare statements: %s\n",
                sqlite3_errmsg(state->db));
        sqlite3_close(state->db);
        return VIRP_ERR_CHAIN_DB;
    }

    /* Prepare intent store statements */
    if (sqlite3_prepare_v2(state->db, SQL_INTENT_INSERT, -1,
                           &state->stmt_intent_insert, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_INTENT_GET, -1,
                           &state->stmt_intent_get, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_INTENT_EXECUTE, -1,
                           &state->stmt_intent_execute, NULL) != SQLITE_OK) {
        fprintf(stderr, "[Chain] Failed to prepare intent statements: %s\n",
                sqlite3_errmsg(state->db));
        sqlite3_close(state->db);
        return VIRP_ERR_CHAIN_DB;
    }

    fprintf(stderr, "[Chain] Initialized: db=%s node=%u org=%s\n",
            db_path, node_id, state->org_id);

    return VIRP_OK;
}

/* =========================================================================
 * Append
 * ========================================================================= */

virp_error_t virp_chain_append(virp_chain_state_t *state,
                               const char *session_id,
                               const char *artifact_type,
                               const char *artifact_id,
                               const char *artifact_hash,
                               virp_chain_entry_t *entry)
{
    if (!state || !session_id || !artifact_type ||
        !artifact_id || !artifact_hash || !entry)
        return VIRP_ERR_NULL_PTR;

    if (!state->db)
        return VIRP_ERR_CHAIN_DB;

    /* BEGIN IMMEDIATE — exclusive write lock */
    int rc = sqlite3_exec(state->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (rc != SQLITE_OK)
        return VIRP_ERR_CHAIN_DB;

    /* Get max sequence for this session */
    int64_t next_seq = 0;
    char prev_hash[65];

    sqlite3_reset(state->stmt_get_last);
    sqlite3_bind_text(state->stmt_get_last, 1, session_id, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(state->stmt_get_last) == SQLITE_ROW) {
        next_seq = sqlite3_column_int64(state->stmt_get_last, 1) + 1;
        snprintf(prev_hash, sizeof(prev_hash), "%s",
                 (const char *)sqlite3_column_text(state->stmt_get_last, 2));
    } else {
        /* Genesis */
        next_seq = 0;
        compute_genesis_hash(session_id, prev_hash);
    }
    sqlite3_reset(state->stmt_get_last);

    /* Populate entry */
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->session_id, sizeof(entry->session_id), "%s", session_id);
    entry->sequence = next_seq;
    snprintf(entry->previous_entry_hash, sizeof(entry->previous_entry_hash),
             "%s", prev_hash);
    entry->timestamp_ns = get_wall_ns();
    entry->monotonic_ns = get_mono_ns();
    snprintf(entry->artifact_type, sizeof(entry->artifact_type),
             "%s", artifact_type);
    snprintf(entry->artifact_id, sizeof(entry->artifact_id),
             "%s", artifact_id);
    snprintf(entry->artifact_hash, sizeof(entry->artifact_hash),
             "%s", artifact_hash);
    snprintf(entry->artifact_hash_alg, sizeof(entry->artifact_hash_alg),
             "sha256");
    snprintf(entry->artifact_schema_version,
             sizeof(entry->artifact_schema_version), "1");
    entry->signer_node_id = state->node_id;
    snprintf(entry->signer_org_id, sizeof(entry->signer_org_id),
             "%s", state->org_id);

    /* Build canonical JSON (without hash and HMAC) */
    char canonical[2048];
    int clen = build_canonical_json(entry, canonical, sizeof(canonical));

    /* Compute chain_entry_hash = sha256(canonical) */
    sha256_hex(canonical, (size_t)clen, entry->chain_entry_hash);

    /* Compute chain_hmac = hmac_sha256(K_chain, canonical) */
    hmac_sha256_hex(state->chain_key.key.key,
                    canonical, (size_t)clen, entry->chain_hmac);

    /* INSERT */
    sqlite3_reset(state->stmt_insert);
    sqlite3_bind_text(state->stmt_insert, 1, entry->session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(state->stmt_insert, 2, entry->sequence);
    sqlite3_bind_text(state->stmt_insert, 3, entry->chain_entry_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert, 4, entry->previous_entry_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(state->stmt_insert, 5, (int64_t)entry->timestamp_ns);
    sqlite3_bind_int64(state->stmt_insert, 6, (int64_t)entry->monotonic_ns);
    sqlite3_bind_text(state->stmt_insert, 7, entry->artifact_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert, 8, entry->artifact_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert, 9, entry->artifact_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert, 10, entry->artifact_hash_alg, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert, 11, entry->artifact_schema_version, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(state->stmt_insert, 12, (int)entry->signer_node_id);
    sqlite3_bind_text(state->stmt_insert, 13, entry->signer_org_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_insert, 14, entry->chain_hmac, -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(state->stmt_insert);
    sqlite3_reset(state->stmt_insert);

    if (rc != SQLITE_DONE) {
        sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
        return VIRP_ERR_CHAIN_DB;
    }

    /* COMMIT — sequence is now permanent */
    rc = sqlite3_exec(state->db, "COMMIT;", NULL, NULL, NULL);
    if (rc != SQLITE_OK) {
        return VIRP_ERR_CHAIN_DB;
    }

    /* Auto-milestone every N entries */
    if (next_seq > 0 && (next_seq % VIRP_CHAIN_MILESTONE_INTERVAL) == 0) {
        insert_milestone(state, session_id, next_seq,
                         VIRP_CHAIN_MILESTONE_INTERVAL,
                         entry->chain_entry_hash);
    }

    return VIRP_OK;
}

/* =========================================================================
 * Verify
 * ========================================================================= */

virp_error_t virp_chain_verify(virp_chain_state_t *state,
                               const char *session_id,
                               int64_t from_sequence,
                               int64_t to_sequence,
                               virp_chain_verify_result_t *result)
{
    if (!state || !session_id || !result)
        return VIRP_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));
    result->from_sequence = from_sequence;
    result->to_sequence = to_sequence;
    result->first_broken = -1;
    result->valid = true;

    /* Determine expected previous hash for from_sequence */
    char expected_prev[65];
    if (from_sequence == 0) {
        compute_genesis_hash(session_id, expected_prev);
    } else {
        /* Need to look up the entry before from_sequence */
        sqlite3_stmt *stmt_prev;
        const char *sql_prev =
            "SELECT chain_entry_hash FROM chain_entries "
            "WHERE session_id = ? AND sequence = ?";
        if (sqlite3_prepare_v2(state->db, sql_prev, -1,
                               &stmt_prev, NULL) != SQLITE_OK)
            return VIRP_ERR_CHAIN_DB;

        sqlite3_bind_text(stmt_prev, 1, session_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(stmt_prev, 2, from_sequence - 1);

        if (sqlite3_step(stmt_prev) == SQLITE_ROW) {
            snprintf(expected_prev, sizeof(expected_prev), "%s",
                     (const char *)sqlite3_column_text(stmt_prev, 0));
        } else {
            sqlite3_finalize(stmt_prev);
            result->valid = false;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Missing entry at sequence %lld",
                     (long long)(from_sequence - 1));
            return VIRP_OK;
        }
        sqlite3_finalize(stmt_prev);
    }

    /* Walk entries in range */
    sqlite3_reset(state->stmt_get_range);
    sqlite3_bind_text(state->stmt_get_range, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(state->stmt_get_range, 2, from_sequence);
    sqlite3_bind_int64(state->stmt_get_range, 3, to_sequence);

    int64_t expected_seq = from_sequence;

    while (sqlite3_step(state->stmt_get_range) == SQLITE_ROW) {
        virp_chain_entry_t e;
        read_entry_from_stmt(state->stmt_get_range, &e);

        /* Check sequence is contiguous */
        if (e.sequence != expected_seq) {
            result->valid = false;
            result->first_broken = expected_seq;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Sequence gap: expected %lld, got %lld",
                     (long long)expected_seq, (long long)e.sequence);
            break;
        }

        /* Verify previous_entry_hash linkage */
        if (strcmp(e.previous_entry_hash, expected_prev) != 0) {
            result->valid = false;
            result->first_broken = e.sequence;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Previous hash mismatch at sequence %lld",
                     (long long)e.sequence);
            break;
        }

        /* Rebuild canonical JSON and verify hash */
        char canonical[2048];
        int clen = build_canonical_json(&e, canonical, sizeof(canonical));

        char computed_hash[65];
        sha256_hex(canonical, (size_t)clen, computed_hash);

        if (strcmp(computed_hash, e.chain_entry_hash) != 0) {
            result->valid = false;
            result->first_broken = e.sequence;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Entry hash mismatch at sequence %lld",
                     (long long)e.sequence);
            break;
        }

        /* Verify HMAC */
        char computed_hmac[65];
        hmac_sha256_hex(state->chain_key.key.key,
                        canonical, (size_t)clen, computed_hmac);

        if (strcmp(computed_hmac, e.chain_hmac) != 0) {
            result->valid = false;
            result->first_broken = e.sequence;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "HMAC mismatch at sequence %lld",
                     (long long)e.sequence);
            break;
        }

        /* Advance */
        snprintf(expected_prev, sizeof(expected_prev), "%s",
                 e.chain_entry_hash);
        expected_seq++;
        result->entries_checked++;
    }

    sqlite3_reset(state->stmt_get_range);
    return VIRP_OK;
}

/* =========================================================================
 * Get Last
 * ========================================================================= */

virp_error_t virp_chain_get_last(virp_chain_state_t *state,
                                 const char *session_id,
                                 virp_chain_entry_t *entry)
{
    if (!state || !session_id || !entry)
        return VIRP_ERR_NULL_PTR;

    sqlite3_reset(state->stmt_get_last);
    sqlite3_bind_text(state->stmt_get_last, 1, session_id, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(state->stmt_get_last) == SQLITE_ROW) {
        read_entry_from_stmt(state->stmt_get_last, entry);
        sqlite3_reset(state->stmt_get_last);
        return VIRP_OK;
    }

    sqlite3_reset(state->stmt_get_last);
    return VIRP_ERR_CHAIN_SEQUENCE;
}

/* =========================================================================
 * Destroy
 * ========================================================================= */

void virp_chain_destroy(virp_chain_state_t *state)
{
    if (!state) return;

    if (state->stmt_insert)
        sqlite3_finalize(state->stmt_insert);
    if (state->stmt_get_last)
        sqlite3_finalize(state->stmt_get_last);
    if (state->stmt_get_range)
        sqlite3_finalize(state->stmt_get_range);
    if (state->stmt_insert_milestone)
        sqlite3_finalize(state->stmt_insert_milestone);
    if (state->stmt_intent_insert)
        sqlite3_finalize(state->stmt_intent_insert);
    if (state->stmt_intent_get)
        sqlite3_finalize(state->stmt_intent_get);
    if (state->stmt_intent_execute)
        sqlite3_finalize(state->stmt_intent_execute);
    if (state->db)
        sqlite3_close(state->db);

    virp_key_destroy(&state->chain_key);

    memset(state, 0, sizeof(*state));
    fprintf(stderr, "[Chain] Destroyed\n");
}

/* =========================================================================
 * Durable Intent Store
 * ========================================================================= */

static void populate_intent_from_row(sqlite3_stmt *stmt,
                                      virp_intent_entry_t *entry)
{
    snprintf(entry->intent_id, sizeof(entry->intent_id), "%s",
             (const char *)sqlite3_column_text(stmt, 0));
    snprintf(entry->intent_hash, sizeof(entry->intent_hash), "%s",
             (const char *)sqlite3_column_text(stmt, 1));
    snprintf(entry->intent_json, sizeof(entry->intent_json), "%s",
             (const char *)sqlite3_column_text(stmt, 2));
    snprintf(entry->confidence, sizeof(entry->confidence), "%s",
             (const char *)sqlite3_column_text(stmt, 3));
    entry->expires_at_ns = sqlite3_column_int64(stmt, 4);
    entry->max_commands = (int32_t)sqlite3_column_int(stmt, 5);
    entry->commands_executed = (int32_t)sqlite3_column_int(stmt, 6);
    snprintf(entry->proposed_actions, sizeof(entry->proposed_actions), "%s",
             (const char *)sqlite3_column_text(stmt, 7));
    snprintf(entry->constraints, sizeof(entry->constraints), "%s",
             (const char *)sqlite3_column_text(stmt, 8));
    snprintf(entry->signature_hmac, sizeof(entry->signature_hmac), "%s",
             (const char *)sqlite3_column_text(stmt, 9));
    entry->signature_seq = sqlite3_column_int64(stmt, 10);
    entry->signature_timestamp_ns = sqlite3_column_int64(stmt, 11);
    entry->created_at_ns = sqlite3_column_int64(stmt, 12);
}

virp_error_t virp_chain_intent_store(virp_chain_state_t *state,
                                      virp_intent_entry_t *entry)
{
    if (!state || !state->db || !entry)
        return VIRP_ERR_NULL_PTR;

    /* Compute HMAC of intent_hash using K_chain */
    hmac_sha256_hex(state->chain_key.key.key,
                    entry->intent_hash, strlen(entry->intent_hash),
                    entry->signature_hmac);

    /* Timestamps */
    entry->created_at_ns = (int64_t)get_wall_ns();
    entry->signature_timestamp_ns = entry->created_at_ns;

    sqlite3_stmt *stmt = state->stmt_intent_insert;
    sqlite3_reset(stmt);

    sqlite3_bind_text(stmt, 1, entry->intent_id, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, entry->intent_hash, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, entry->intent_json, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, entry->confidence, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 5, entry->expires_at_ns);
    sqlite3_bind_int(stmt, 6, entry->max_commands);
    sqlite3_bind_text(stmt, 7, entry->proposed_actions, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, entry->constraints, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, entry->signature_hmac, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 10, entry->signature_seq);
    sqlite3_bind_int64(stmt, 11, entry->signature_timestamp_ns);
    sqlite3_bind_int64(stmt, 12, entry->created_at_ns);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[Chain] Intent store failed: %s\n",
                sqlite3_errmsg(state->db));
        return VIRP_ERR_CHAIN_DB;
    }

    entry->commands_executed = 0;  /* Fresh intent */
    return VIRP_OK;
}

virp_error_t virp_chain_intent_get(virp_chain_state_t *state,
                                    const char *intent_id,
                                    virp_intent_entry_t *entry)
{
    if (!state || !state->db || !intent_id || !entry)
        return VIRP_ERR_NULL_PTR;

    sqlite3_stmt *stmt = state->stmt_intent_get;
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, intent_id, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        populate_intent_from_row(stmt, entry);
        return VIRP_OK;
    }

    return VIRP_ERR_INTENT_NOT_FOUND;
}

virp_error_t virp_chain_intent_execute(virp_chain_state_t *state,
                                        const char *intent_id,
                                        virp_intent_entry_t *entry)
{
    if (!state || !state->db || !intent_id || !entry)
        return VIRP_ERR_NULL_PTR;

    /* Atomically increment commands_executed (only if < max_commands) */
    sqlite3_stmt *stmt = state->stmt_intent_execute;
    sqlite3_reset(stmt);
    sqlite3_bind_text(stmt, 1, intent_id, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[Chain] Intent execute update failed: %s\n",
                sqlite3_errmsg(state->db));
        return VIRP_ERR_CHAIN_DB;
    }

    if (sqlite3_changes(state->db) == 0) {
        /* Either intent not found, or already at max_commands */
        virp_error_t err = virp_chain_intent_get(state, intent_id, entry);
        if (err != VIRP_OK)
            return VIRP_ERR_INTENT_NOT_FOUND;
        return VIRP_ERR_INTENT_EXHAUSTED;
    }

    /* Return updated entry */
    return virp_chain_intent_get(state, intent_id, entry);
}
