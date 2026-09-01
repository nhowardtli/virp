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
#include "virp_fault_inject.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>

/* =========================================================================
 * Thread safety (Item 3 hardening)
 *
 * The chain owns shared mutable state (the sqlite3 db handle + prepared
 * statements) that is NOT safe under concurrent use. Snow's cage operator
 * drives concurrent traffic, so every public entry point is a thin wrapper
 * that holds state->lock for the duration of its DB work and calls an
 * internal *_locked core. Cores call other cores directly (never the public
 * wrappers), so the lock is non-recursive and never re-entered. The lock is
 * held only inside this module — which never acquires the O-Node exec_mutex
 * — so there is no lock-ordering/deadlock risk with the execute path.
 * ========================================================================= */

static virp_error_t chain_append_locked(virp_chain_state_t *state,
                                        const char *session_id,
                                        const char *artifact_type,
                                        const char *artifact_id,
                                        const char *artifact_hash,
                                        const char *artifact_content,
                                        virp_chain_entry_t *entry);
static virp_error_t chain_verify_locked(virp_chain_state_t *state,
                                        const char *session_id,
                                        int64_t from_sequence,
                                        int64_t to_sequence,
                                        virp_chain_verify_result_t *result,
                                        char out_last_hash[65]);
static virp_error_t chain_get_last_locked(virp_chain_state_t *state,
                                          const char *session_id,
                                          virp_chain_entry_t *entry);
static virp_error_t head_hmac_hex(virp_chain_state_t *state,
                                  const char *session_id,
                                  int64_t last_sequence,
                                  const char *last_entry_hash,
                                  char out_hex[65]);
/* Constant-time hex digest/MAC comparison — see definition for why (§4.4). */
static bool hexdigest_eq(const char *a, const char *b);
static void sha256_hex(const char *data, size_t len, char out[65]);
static int table_exists(sqlite3 *db, const char *name);
static int column_exists(sqlite3 *db, const char *table, const char *col);
static void detect_sig_columns(virp_chain_state_t *state);
static int head_canonical(const char *session_id, int64_t last_sequence,
                          const char *last_entry_hash, char *out,
                          size_t out_size);
static virp_error_t head_upsert_locked(virp_chain_state_t *state,
                                       const char *session_id,
                                       int64_t last_sequence,
                                       const char *last_entry_hash);
static virp_error_t chain_intent_store_locked(virp_chain_state_t *state,
                                              virp_intent_entry_t *entry);
static virp_error_t chain_intent_get_locked(virp_chain_state_t *state,
                                            const char *intent_id,
                                            virp_intent_entry_t *entry);
static virp_error_t chain_intent_execute_locked(virp_chain_state_t *state,
                                                const char *intent_id,
                                                virp_intent_entry_t *entry);
static virp_error_t chain_artifact_store_locked(virp_chain_state_t *state,
                                                const char *artifact_id,
                                                const char *artifact_type,
                                                const char *artifact_content,
                                                const char *artifact_hash,
                                                const char *session_id);

virp_error_t virp_chain_append(virp_chain_state_t *state,
                               const char *session_id,
                               const char *artifact_type,
                               const char *artifact_id,
                               const char *artifact_hash,
                               virp_chain_entry_t *entry)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_append_locked(state, session_id, artifact_type,
                                          artifact_id, artifact_hash, NULL,
                                          entry);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_append_with_artifact(virp_chain_state_t *state,
                                             const char *session_id,
                                             const char *artifact_type,
                                             const char *artifact_id,
                                             const char *artifact_hash,
                                             const char *artifact_content,
                                             virp_chain_entry_t *entry)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_append_locked(state, session_id, artifact_type,
                                          artifact_id, artifact_hash,
                                          artifact_content, entry);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_verify(virp_chain_state_t *state,
                               const char *session_id,
                               int64_t from_sequence,
                               int64_t to_sequence,
                               virp_chain_verify_result_t *result)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_verify_locked(state, session_id, from_sequence,
                                          to_sequence, result, NULL);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

static virp_error_t chain_verify_session_locked(virp_chain_state_t *state,
                                       const char *session_id,
                                       virp_chain_verify_result_t *result)
{
    if (!state || !session_id || !result)
        return VIRP_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));
    result->first_broken = -1;

    /* Verifier handle on a pre-chain_heads database: there is no signed
     * head, so no length claim exists to verify against. Report that —
     * NOBODY may manufacture the head it would then check. (The daemon's
     * init-time trust-on-upgrade backfill that once did was removed
     * 2026-08-06, Finding A: it let a restart launder a tail+head
     * deletion. virp_chain_init now refuses heads-less entry-bearing
     * databases outright.) */
    if (state->legacy_no_heads) {
        result->valid = false;
        snprintf(result->error_detail, sizeof(result->error_detail),
                 "LEGACY_CHAIN: no chain_heads table; chain length "
                 "unauthenticated — COMPLETENESS_UNPROVABLE");
        return VIRP_OK;
    }

    /* Load the head record. The signed head_get variant (prepared when the
     * head_sig columns exist) also returns head_sig (col 3) and
     * head_sig_key_id (col 4). */
    int64_t head_seq = -1;
    char head_hash[65] = {0};
    char head_mac[65]  = {0};
    char head_sig[VIRP_CHAINSIGN_SIG_HEX] = {0};
    char head_key_id[VIRP_CHAINSIGN_KEYID_HEX] = {0};

    sqlite3_reset(state->stmt_head_get);
    sqlite3_bind_text(state->stmt_head_get, 1, session_id, -1,
                      SQLITE_TRANSIENT);
    int have_head = 0;
    if (sqlite3_step(state->stmt_head_get) == SQLITE_ROW) {
        have_head = 1;
        head_seq = sqlite3_column_int64(state->stmt_head_get, 0);
        snprintf(head_hash, sizeof(head_hash), "%s",
                 (const char *)sqlite3_column_text(state->stmt_head_get, 1));
        snprintf(head_mac, sizeof(head_mac), "%s",
                 (const char *)sqlite3_column_text(state->stmt_head_get, 2));
        if (sqlite3_column_count(state->stmt_head_get) > 4) {
            const unsigned char *hs = sqlite3_column_text(state->stmt_head_get, 3);
            const unsigned char *hk = sqlite3_column_text(state->stmt_head_get, 4);
            if (hs) snprintf(head_sig, sizeof(head_sig), "%s", hs);
            if (hk) snprintf(head_key_id, sizeof(head_key_id), "%s", hk);
        }
    }
    sqlite3_reset(state->stmt_head_get);

    if (!have_head) {
        /* Distinguish "session with entries but no head" (tail-length
         * cannot be authenticated — the deletion-of-head attack) from
         * "session unknown entirely". Both are invalid; the detail
         * differs so an operator knows which case they are in. */
        virp_chain_entry_t probe;
        virp_error_t prc = chain_get_last_locked(state, session_id, &probe);
        result->valid = false;
        if (prc == VIRP_OK) {
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Head record missing for session with entries; "
                     "chain length cannot be authenticated");
        } else {
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "No entries and no head record for session");
        }
        return VIRP_OK;
    }

    /* D-1 session-granularity key decision (before the walk; verify_locked
     * reads state->sig_key_unavailable_session). A head-signed session
     * whose signing key_id is not the one we were given cannot be checked
     * asymmetrically — that is a SOFT, whole-session outcome, never a FAIL:
     * the other tiers still apply. */
    bool head_is_signed = (state->head_sig_cols && head_sig[0] != '\0');
    bool head_sig_ok = false;
    state->sig_key_unavailable_session = false;
    if (state->verify_sig_enabled && head_is_signed &&
        strcmp(head_key_id, state->verify_key_id_hex) != 0) {
        state->sig_key_unavailable_session = true;
    }

    /* Authenticate the head itself before trusting its length claim.
     * SYMMETRIC: the head HMAC (only when K_chain was supplied — the
     * KEYLESS tier takes the head's length claim as unauthenticated input
     * and says so via head_authenticated=false). */
    if (state->have_chain_key) {
        char expect_mac[65];
        if (head_hmac_hex(state, session_id, head_seq, head_hash,
                          expect_mac) != VIRP_OK) {
            result->valid = false;
            result->to_sequence = head_seq;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Head record HMAC could not be computed");
            state->sig_key_unavailable_session = false;
            return VIRP_ERR_CRYPTO;
        }
        if (!hexdigest_eq(expect_mac, head_mac)) {
            result->valid = false;
            result->to_sequence = head_seq;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Head record HMAC mismatch");
            state->sig_key_unavailable_session = false;
            return VIRP_OK;
        }
    }

    /* ASYMMETRIC: the head Ed25519 signature, verified with the PUBLIC key.
     * A head that IS signed under our key but whose signature does not
     * verify is a FAIL (the head length claim is forged). */
    if (state->verify_sig_enabled && head_is_signed &&
        !state->sig_key_unavailable_session) {
        char head_canon[512];
        int hn = head_canonical(session_id, head_seq, head_hash,
                                head_canon, sizeof(head_canon));
        uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE];
        if (!virp_chainsign_sig_from_hex(head_sig, sig) ||
            !virp_chainsign_verify(state->verify_pub, VIRP_CHAINSIGN_TAG_HEAD,
                                   head_canon, (size_t)hn, sig)) {
            result->valid = false;
            result->to_sequence = head_seq;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Head Ed25519 signature verification failed");
            state->sig_key_unavailable_session = false;
            return VIRP_OK;
        }
        head_sig_ok = true;
    }

    /* Walk the full range the head commits to; completeness enforced.
     * NOTE: chain_verify_locked memsets *result, so every session-level
     * field below is set AFTER it returns. */
    char last_hash[65] = {0};
    virp_error_t rc = chain_verify_locked(state, session_id, 0, head_seq,
                                          result, last_hash);
    bool unavailable = state->sig_key_unavailable_session;
    state->sig_key_unavailable_session = false;   /* transient: clear always */
    if (rc != VIRP_OK || !result->valid)
        return rc;

    /* The final verified entry must be the one the head commits to */
    if (strcmp(last_hash, head_hash) != 0) {
        result->valid = false;
        result->first_broken = head_seq;
        snprintf(result->error_detail, sizeof(result->error_detail),
                 "Head record does not match final verified entry "
                 "at sequence %lld", (long long)head_seq);
        return VIRP_OK;
    }

    /* Session-level tier outcome (all pure-addition fields). */
    result->head_hmac_ok = state->have_chain_key;
    result->head_sig_ok = head_sig_ok;
    result->head_authenticated = state->have_chain_key || head_sig_ok;
    result->sig_key_unavailable = unavailable;
    snprintf(result->sig_key_id, sizeof(result->sig_key_id), "%s",
             head_is_signed ? head_key_id : "");
    return VIRP_OK;
}

virp_error_t virp_chain_verify_session(virp_chain_state_t *state,
                                       const char *session_id,
                                       virp_chain_verify_result_t *result)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_verify_session_locked(state, session_id, result);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_get_last(virp_chain_state_t *state,
                                 const char *session_id,
                                 virp_chain_entry_t *entry)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_get_last_locked(state, session_id, entry);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_artifact_exists(virp_chain_state_t *state,
                                        const char *artifact_id,
                                        bool *exists)
{
    if (!state || !artifact_id || !exists) return VIRP_ERR_NULL_PTR;
    *exists = false;

    pthread_mutex_lock(&state->lock);
    /* One-off statement (not in the shared prepared-statement set) so this
     * read-only query never contends with the append path's statements. */
    sqlite3_stmt *st = NULL;
    virp_error_t rc = VIRP_OK;
    if (sqlite3_prepare_v2(state->db,
            "SELECT 1 FROM chain_entries WHERE artifact_id = ? LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        rc = VIRP_ERR_CHAIN_DB;
    } else {
        sqlite3_bind_text(st, 1, artifact_id, -1, SQLITE_TRANSIENT);
        int step = sqlite3_step(st);
        if (step == SQLITE_ROW)
            *exists = true;
        else if (step != SQLITE_DONE)
            rc = VIRP_ERR_CHAIN_DB;
    }
    if (st) sqlite3_finalize(st);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_artifact_body_exists(virp_chain_state_t *state,
                                             const char *artifact_hash,
                                             bool *exists)
{
    if (!state || !artifact_hash || !exists) return VIRP_ERR_NULL_PTR;
    *exists = false;

    pthread_mutex_lock(&state->lock);
    /* Same one-off-statement discipline as virp_chain_artifact_exists()
     * above: a read-only probe on the append path must not contend with
     * the shared prepared statements the append itself uses.
     *
     * artifacts, NOT chain_entries. A chain entry proves an append was
     * ACCEPTED; only an artifacts row proves the BODY was retained. The
     * two came apart on this very path — the entry landed and the body
     * did not — so asking the entries table here would answer the wrong
     * question and pass exactly the case this exists to catch.
     *
     * Type-blind by design (any artifact_type), which is why it is NOT
     * a commitment check: chain_append's fed_outcome gate asks
     * virp_chain_entry_commits_to() below instead (Sep 1 review, Task 3). */
    sqlite3_stmt *st = NULL;
    virp_error_t rc = VIRP_OK;
    if (sqlite3_prepare_v2(state->db,
            "SELECT 1 FROM artifacts WHERE artifact_hash = ? LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        rc = VIRP_ERR_CHAIN_DB;
    } else {
        sqlite3_bind_text(st, 1, artifact_hash, -1, SQLITE_TRANSIENT);
        int step = sqlite3_step(st);
        if (step == SQLITE_ROW)
            *exists = true;
        else if (step != SQLITE_DONE)
            rc = VIRP_ERR_CHAIN_DB;
    }
    if (st) sqlite3_finalize(st);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

/*
 * Set *exists to true iff a chain ENTRY of an observation type commits to
 * the given artifact_hash — i.e. a signed observation with this hash was
 * appended, whether or not its body bytes were retained. This is the
 * question the fed_outcome gate must ask about a citation: an outcome
 * whose observation_sha256 names a hash the chain committed to is BACKED
 * (the observation is in the chain; a missing body only makes it
 * UNVERIFIABLE, which every reader grades honestly). Distinct from
 * virp_chain_artifact_body_exists(), which asks whether the BYTES were
 * retained — the answer that wrongly refused an oversized (commitment-
 * only) observation's outcome. Restricted to observation types so an
 * outcome cannot be "backed" by an unrelated entry that happens to share
 * a hash. Returns VIRP_OK on a successful query (whether or not it matched).
 */
virp_error_t virp_chain_entry_commits_to(virp_chain_state_t *state,
                                         const char *artifact_hash,
                                         bool *exists)
{
    if (!state || !artifact_hash || !exists) return VIRP_ERR_NULL_PTR;
    *exists = false;

    pthread_mutex_lock(&state->lock);
    /* One-off statement (not in the shared prepared-statement set), the
     * same discipline as the sibling probes: a read on the append path
     * must not contend with the append's own statements. */
    sqlite3_stmt *st = NULL;
    virp_error_t rc = VIRP_OK;
    if (sqlite3_prepare_v2(state->db,
            "SELECT 1 FROM chain_entries WHERE artifact_hash = ? "
            "AND artifact_type IN ('observation','fed_observation') LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        rc = VIRP_ERR_CHAIN_DB;
    } else {
        sqlite3_bind_text(st, 1, artifact_hash, -1, SQLITE_TRANSIENT);
        int step = sqlite3_step(st);
        if (step == SQLITE_ROW)
            *exists = true;
        else if (step != SQLITE_DONE)
            rc = VIRP_ERR_CHAIN_DB;
    }
    if (st) sqlite3_finalize(st);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_artifact_id_conflict(virp_chain_state_t *state,
                                             const char *artifact_id,
                                             const char *artifact_hash,
                                             bool *conflict)
{
    if (!state || !artifact_id || !artifact_hash || !conflict)
        return VIRP_ERR_NULL_PTR;
    *conflict = false;

    pthread_mutex_lock(&state->lock);
    /* Same authority as GATE 5 in chain_append_locked: the CHAIN, not body
     * storage. Reads chain_entries so a commitment-only prior (no artifacts
     * row) is seen; the id-equality half rides idx_chain_artifact_id, so
     * this stays a lookup, not a scan. NOTE: this exported probe is no
     * longer on the enforcement path — GATE 5 now runs inside the append's
     * own transaction (a probe here would be check-then-act). It is kept
     * correct for any external caller and covered by its own test. */
    sqlite3_stmt *st = NULL;
    virp_error_t rc = VIRP_OK;
    if (sqlite3_prepare_v2(state->db,
            "SELECT 1 FROM chain_entries "
            "WHERE artifact_id = ? AND artifact_hash <> ? LIMIT 1",
            -1, &st, NULL) != SQLITE_OK) {
        rc = VIRP_ERR_CHAIN_DB;
    } else {
        sqlite3_bind_text(st, 1, artifact_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, artifact_hash, -1, SQLITE_TRANSIENT);
        int step = sqlite3_step(st);
        if (step == SQLITE_ROW)
            *conflict = true;
        else if (step != SQLITE_DONE)
            rc = VIRP_ERR_CHAIN_DB;
    }
    if (st) sqlite3_finalize(st);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_intent_store(virp_chain_state_t *state,
                                     virp_intent_entry_t *entry)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_intent_store_locked(state, entry);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_intent_get(virp_chain_state_t *state,
                                   const char *intent_id,
                                   virp_intent_entry_t *entry)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_intent_get_locked(state, intent_id, entry);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_intent_execute(virp_chain_state_t *state,
                                       const char *intent_id,
                                       virp_intent_entry_t *entry)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_intent_execute_locked(state, intent_id, entry);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

virp_error_t virp_chain_artifact_store(virp_chain_state_t *state,
                                       const char *artifact_id,
                                       const char *artifact_type,
                                       const char *artifact_content,
                                       const char *artifact_hash,
                                       const char *session_id)
{
    if (!state) return VIRP_ERR_NULL_PTR;
    pthread_mutex_lock(&state->lock);
    virp_error_t rc = chain_artifact_store_locked(state, artifact_id,
                                                  artifact_type, artifact_content,
                                                  artifact_hash, session_id);
    pthread_mutex_unlock(&state->lock);
    return rc;
}

/* =========================================================================
 * Artifact type policy + body digest (adversarial audit 2026-08-06)
 *
 * One definition, two consumers: the external append path in
 * src/virp_onode.c refuses forgeries with it, and the verifier below
 * grades artifact binding with it. Types are compared against the
 * TRUNCATED forms the 16-byte artifact_type field can actually hold —
 * "comparator_verdict" and "chainwalk_summary" reach the daemon as
 * "comparator_verd" and "chainwalk_summa", which is also how they are
 * stored in production. Both spellings are listed so the predicate is
 * correct wherever it is called from.
 * ========================================================================= */

static bool type_in(const char *t, const char *const *set, size_t n)
{
    if (!t) return false;
    for (size_t i = 0; i < n; i++)
        if (strcmp(t, set[i]) == 0) return true;
    return false;
}

bool virp_chain_type_is_daemon_reserved(const char *artifact_type)
{
    static const char *const RESERVED[] = {
        "approval",        /* src/virp_approval.c  (submit)   */
        "proposal",        /* src/virp_approval.c  (file)     */
        "outcome",         /* src/virp_onode.c     (gate)     */
        "gate_rejection",  /* src/virp_onode.c     (gate)     */
        "gate_execution",  /* src/virp_onode.c     (gate)     */
        "gate_intent",     /* src/virp_onode.c     (gate, pre-dispatch) */
        "validation",      /* src/virp_validator.c            */
    };
    return type_in(artifact_type, RESERVED,
                   sizeof(RESERVED) / sizeof(RESERVED[0]));
}

bool virp_chain_type_is_indirect(const char *artifact_type)
{
    static const char *const INDIRECT[] = {
        "comparator_verdict", "comparator_verd",
        "chainwalk_summary",  "chainwalk_summa",
    };
    return type_in(artifact_type, INDIRECT,
                   sizeof(INDIRECT) / sizeof(INDIRECT[0]));
}

bool virp_chain_type_is_external_allowed(const char *artifact_type)
{
    static const char *const EXTERNAL[] = {
        "observation",       /* autopilot, evidence, config-backup, virp-tool */
        "evidence_item",     /* autopilot/virp_evidence.py                    */
        "no_drift",          /* autopilot/virp_config_backup.py               */
        "baseline_set",      /* autopilot/virp_config_backup.py               */
        "drift_alert",       /* autopilot/virp_config_backup.py               */
        /* Federation-bridge provenance (broker/virp_bridge_mcp.py). These
         * carry the peer + NCFED request_id that binds a federated caller
         * to the command it put to the gate — the attribution the daemon's
         * own observation/gate_rejection entries cannot record. They are
         * client-submitted COMMITMENTS (body = provenance JSON tagged
         * schema "federated_request/1" / "federated_outcome/1"; artifact_
         * hash binds it via GATE 2), NOT daemon verdicts: deliberately
         * NOT the reserved "outcome"/"proposal"/etc. names, so blessing
         * them here does not let a socket client forge a daemon-minted
         * semantic type. The signed observation stays separate (GATE 3).
         * Names kept <=15 chars so they survive artifact_type[16] intact
         * (unlike the INDIRECT entries, which need truncated aliases).
         *
         * "fed_observation" is the odd one out and is NOT a commitment:
         * its body is the signed observation wire message itself, the
         * evidence a fed_outcome's observation_sha256 points at. It
         * exists because the Item 8 narrowing in virp_onode.c reduces a
         * restricted principal's chain_append to this federation set,
         * which left the bridge unable to store the very body its
         * outcome cited — every federated read from 2026-08-11 17:44
         * UTC to 2026-08-16 recorded a hash resolving to nothing. Giving
         * the bridge its own name for the body, rather than readmitting
         * the reserved "observation", keeps a client-submitted body
         * distinguishable from a daemon-minted one while restoring the
         * link. It carries a real signature and GATE 3 verifies it here
         * exactly as it verifies "observation" — being externally
         * submittable buys it no exemption from proving what it is. */
        "fed_request",     /* broker/virp_bridge_mcp.py (request provenance) */
        "fed_observation", /* broker/virp_bridge_mcp.py (the signed body)    */
        "fed_outcome",     /* broker/virp_bridge_mcp.py (outcome record)     */
    };
    if (virp_chain_type_is_indirect(artifact_type)) return true;
    return type_in(artifact_type, EXTERNAL,
                   sizeof(EXTERNAL) / sizeof(EXTERNAL[0]));
}

bool virp_chain_type_is_federation(const char *artifact_type)
{
    static const char *const FEDERATION[] = {
        "fed_request", "fed_observation", "fed_outcome",
    };
    return type_in(artifact_type, FEDERATION,
                   sizeof(FEDERATION) / sizeof(FEDERATION[0]));
}

/* Standard base64 decode (RFC 4648, '=' padding). Returns decoded length
 * or -1. Local to this file; the approver registry has its own copy for
 * SPKI decoding and the two must not become entangled. */
static int artifact_b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int artifact_b64_decode(const char *in, size_t in_len,
                               uint8_t *out, size_t out_max)
{
    if (in_len % 4 != 0) return -1;
    size_t o = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        int v[4];
        int pad = 0;
        for (int k = 0; k < 4; k++) {
            char c = in[i + k];
            if (c == '=') {
                /* Padding is legal only in the final quantum's tail. */
                if (i + 4 != in_len || k < 2) return -1;
                v[k] = 0;
                pad++;
            } else {
                if (pad) return -1;
                v[k] = artifact_b64_val(c);
                if (v[k] < 0) return -1;
            }
        }
        uint32_t trip = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                        ((uint32_t)v[2] << 6)  | (uint32_t)v[3];
        int want = 3 - pad;
        for (int k = 0; k < want; k++) {
            if (o >= out_max) return -1;
            out[o++] = (uint8_t)((trip >> (16 - 8 * k)) & 0xFF);
        }
    }
    return (int)o;
}

virp_error_t virp_chain_artifact_digest(const char *artifact_content,
                                        char out_hex[65])
{
    if (!artifact_content || !out_hex) return VIRP_ERR_NULL_PTR;

    static const char PREFIX[] = "base64:";
    const size_t plen = sizeof(PREFIX) - 1;

    if (strncmp(artifact_content, PREFIX, plen) == 0) {
        const char *b64 = artifact_content + plen;
        size_t b64_len = strlen(b64);
        size_t max = b64_len / 4 * 3 + 3;
        uint8_t *raw = (uint8_t *)malloc(max ? max : 1);
        if (!raw) return VIRP_ERR_BUFFER_TOO_SMALL;
        int n = artifact_b64_decode(b64, b64_len, raw, max);
        if (n < 0) {
            free(raw);
            return VIRP_ERR_INVALID_LENGTH;
        }
        sha256_hex((const char *)raw, (size_t)n, out_hex);
        free(raw);
        return VIRP_OK;
    }

    sha256_hex(artifact_content, strlen(artifact_content), out_hex);
    return VIRP_OK;
}

/*
 * Produce the EXACT bytes virp_chain_artifact_digest() hashes.
 *
 * This must stay the same decoder the digest uses. A verifier that
 * decoded with its own copy could, on some malformed input, recover
 * different bytes than the ones the declared hash was checked against —
 * and then the entry's commitment would bind bytes nobody verified.
 * One decoder, two callers.
 */
virp_error_t virp_chain_artifact_bytes(const char *artifact_content,
                                       uint8_t *out, size_t out_max,
                                       size_t *out_len)
{
    if (!artifact_content || !out || !out_len) return VIRP_ERR_NULL_PTR;

    static const char PREFIX[] = "base64:";
    const size_t plen = sizeof(PREFIX) - 1;

    if (strncmp(artifact_content, PREFIX, plen) == 0) {
        const char *b64 = artifact_content + plen;
        int n = artifact_b64_decode(b64, strlen(b64), out, out_max);
        if (n < 0) return VIRP_ERR_INVALID_LENGTH;
        *out_len = (size_t)n;
        return VIRP_OK;
    }

    size_t n = strlen(artifact_content);
    if (n > out_max) return VIRP_ERR_BUFFER_TOO_SMALL;
    memcpy(out, artifact_content, n);
    *out_len = n;
    return VIRP_OK;
}

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
    /* GATE 5's federation idempotency check queries chain_entries by
     * artifact_id (a commitment-only observation has no artifacts row, so
     * the chain is the only authority on what a correlation id committed
     * to). Without this index that predicate is a full scan on every
     * federation append. IF NOT EXISTS so an existing chain.db gains it on
     * next open — no migration step. */
    "CREATE INDEX IF NOT EXISTS idx_chain_artifact_id "
    "  ON chain_entries(artifact_id);"
    /* Signed per-session head: authenticates chain LENGTH, not just links.
     * Updated in the same transaction as every append. A DB writer without
     * K_chain can neither forge a head for a truncated chain nor delete it
     * undetected (entries-without-head fails virp_chain_verify_session). */
    "CREATE TABLE IF NOT EXISTS chain_heads ("
    "  session_id TEXT PRIMARY KEY,"
    "  last_sequence INTEGER NOT NULL,"
    "  last_entry_hash TEXT NOT NULL,"
    "  head_hmac TEXT NOT NULL,"
    "  updated_at_ns INTEGER NOT NULL"
    ");"
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
    "CREATE INDEX IF NOT EXISTS idx_intents_id ON intents(intent_id);"
    /* Artifact bodies are keyed by (artifact_id, artifact_hash), NOT by
     * artifact_id alone. Production audit 2026-08-03: two distinct
     * observations minted the same second-resolution id in one second;
     * under UNIQUE(artifact_id) + OR REPLACE the second body silently
     * displaced the first, losing its evidence bytes forever while both
     * chain entries stayed valid. The chain entry commits to
     * artifact_hash, so (id, hash) is the identity readers must join on
     * — a colliding id then stores both bodies side by side, and an
     * identical (id, hash) re-store is a no-op. */
    "CREATE TABLE IF NOT EXISTS artifacts ("
    "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  artifact_id TEXT NOT NULL,"
    "  artifact_type TEXT NOT NULL,"
    "  artifact_content TEXT NOT NULL,"
    "  artifact_hash TEXT NOT NULL,"
    "  session_id TEXT NOT NULL,"
    "  created_at_ns INTEGER NOT NULL,"
    "  UNIQUE(artifact_id, artifact_hash)"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_artifacts_id ON artifacts(artifact_id);"
    /* Lookup by hash alone: chain_append's fed_outcome gate asks "is the
     * body this outcome cites actually stored?", and it knows only the
     * hash — the citing outcome carries no artifact_id for it. Without
     * this index that question is a full scan of a table that reaches
     * six figures of rows on a live node, on the append path. */
    "CREATE INDEX IF NOT EXISTS idx_artifacts_hash ON artifacts(artifact_hash);";

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

static const char *SQL_HEAD_UPSERT =
    "INSERT OR REPLACE INTO chain_heads "
    "(session_id, last_sequence, last_entry_hash, head_hmac, updated_at_ns) "
    "VALUES (?,?,?,?,?)";

static const char *SQL_HEAD_GET =
    "SELECT last_sequence, last_entry_hash, head_hmac "
    "FROM chain_heads WHERE session_id = ?";

/* =========================================================================
 * D-1 signing-path SQL. Used ONLY when signing is enabled and the sig
 * columns exist; a signing-off chain never prepares or issues these, so it
 * emits the exact pre-D-1 statements above. The column ORDER matches the
 * unsigned statement so the first N binds are identical; the sig columns
 * are appended.
 * ========================================================================= */
static const char *SQL_INSERT_SIGNED =
    "INSERT INTO chain_entries "
    "(session_id, sequence, chain_entry_hash, previous_entry_hash, "
    " timestamp_ns, monotonic_ns, artifact_type, artifact_id, "
    " artifact_hash, artifact_hash_alg, artifact_schema_version, "
    " signer_node_id, signer_org_id, chain_hmac, "
    " chain_sig, chain_sig_key_id) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

static const char *SQL_HEAD_UPSERT_SIGNED =
    "INSERT OR REPLACE INTO chain_heads "
    "(session_id, last_sequence, last_entry_hash, head_hmac, updated_at_ns, "
    " head_sig, head_sig_key_id) "
    "VALUES (?,?,?,?,?,?,?)";

/* Signature-column SELECT variants, used by the VERIFIER only (prepared
 * by virp_chain_open_verifier_ex when the columns exist). The leading
 * columns match SQL_GET_LAST/RANGE exactly, so read_entry_from_stmt reads
 * 0..13 as before and column_count>15 lets it pick up chain_sig (14) and
 * chain_sig_key_id (15). The writer path never needs these — it reads only
 * the prior entry's hash to link. */
static const char *SQL_GET_LAST_SIGNED =
    "SELECT session_id, sequence, chain_entry_hash, previous_entry_hash, "
    "  timestamp_ns, monotonic_ns, artifact_type, artifact_id, "
    "  artifact_hash, artifact_hash_alg, artifact_schema_version, "
    "  signer_node_id, signer_org_id, chain_hmac, "
    "  chain_sig, chain_sig_key_id "
    "FROM chain_entries WHERE session_id = ? "
    "ORDER BY sequence DESC LIMIT 1";

static const char *SQL_GET_RANGE_SIGNED =
    "SELECT session_id, sequence, chain_entry_hash, previous_entry_hash, "
    "  timestamp_ns, monotonic_ns, artifact_type, artifact_id, "
    "  artifact_hash, artifact_hash_alg, artifact_schema_version, "
    "  signer_node_id, signer_org_id, chain_hmac, "
    "  chain_sig, chain_sig_key_id "
    "FROM chain_entries WHERE session_id = ? "
    "AND sequence >= ? AND sequence <= ? "
    "ORDER BY sequence ASC";

static const char *SQL_HEAD_GET_SIGNED =
    "SELECT last_sequence, last_entry_hash, head_hmac, "
    "  head_sig, head_sig_key_id "
    "FROM chain_heads WHERE session_id = ?";

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

/* DO NOTHING, never REPLACE: an identical (id, hash) re-store is
 * idempotent; distinct evidence under a colliding id lands as its own
 * row via the two-column key above. Nothing can displace stored bytes. */
static const char *SQL_ARTIFACT_INSERT =
    "INSERT INTO artifacts "
    "(artifact_id, artifact_type, artifact_content, artifact_hash, "
    " session_id, created_at_ns) "
    "VALUES (?,?,?,?,?,?) "
    "ON CONFLICT(artifact_id, artifact_hash) DO NOTHING";

/* =========================================================================
 * Helpers
 * ========================================================================= */

/*
 * Constant-time equality for the hex digest/MAC fields (audit §4.4).
 *
 * These comparisons decide whether a chain entry is authentic, and two of
 * the three are against a value derived from K_chain. strcmp() returns at
 * the first differing byte, so the time it takes reveals how long a
 * common prefix the attacker guessed. That turns forging a chain_hmac
 * from a 2^256 search into a byte-at-a-time one against an oracle that
 * will happily re-verify — no key required. The chain is the audit trail
 * the whole product rests on, so this is the one comparison that must not
 * leak.
 *
 * Compared as hex rather than decoded to 32 raw bytes: hex is a bijection
 * of the digest, so a constant-time comparison over the encoding leaks
 * exactly what a constant-time comparison over the bytes would — nothing
 * beyond equal/not-equal — while avoiding a decode step with its own
 * failure paths on values read back from SQLite.
 *
 * The length check is not a timing leak: these fields are always 64 hex
 * chars, so the length is public. It is load-bearing for memory safety —
 * virp_consttime_eq() reads every byte it is given, and a short or
 * corrupt value read out of the database must not send it past the NUL
 * into the uninitialized tail of a stack-allocated entry.
 *
 * Behaviour is otherwise identical to the strcmp() it replaces: both
 * operands are lowercase hex from sha256_hex()/hmac_sha256_hex(), so the
 * case sensitivity strcmp() had is preserved.
 */
static bool hexdigest_eq(const char *a, const char *b)
{
    if (!a || !b) return false;
    size_t alen = strlen(a);
    if (alen != strlen(b)) return false;
    return virp_consttime_eq(a, b, alen) == 1;
}

static void sha256_hex(const char *data, size_t len, char out[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data, len, hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        snprintf(out + i * 2, 3, "%02x", hash[i]);
    out[64] = '\0';
}

static virp_error_t hmac_sha256_hex(const uint8_t key[VIRP_KEY_SIZE],
                                    const char *data, size_t len,
                                    char out[65])
{
    uint8_t hmac_bytes[VIRP_HMAC_SIZE];
    virp_error_t err = virp_hmac_sha256(key, (const uint8_t *)data, len,
                                        hmac_bytes);
    if (err != VIRP_OK) {
        out[0] = '\0';   /* never let a failed MAC read as a real one */
        return err;
    }
    for (int i = 0; i < VIRP_HMAC_SIZE; i++)
        snprintf(out + i * 2, 3, "%02x", hmac_bytes[i]);
    out[64] = '\0';
    return VIRP_OK;
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
    /* D-1 sig columns (14, 15) are present only in the *_SIGNED SELECTs.
     * sqlite3_column_count guards against reading past a non-signing
     * SELECT, and a NULL cell (unsigned entry in a signed DB) leaves the
     * field the empty string set by memset above. */
    if (sqlite3_column_count(stmt) > 15) {
        const unsigned char *sig = sqlite3_column_text(stmt, 14);
        const unsigned char *kid = sqlite3_column_text(stmt, 15);
        if (sig) snprintf(e->chain_sig, sizeof(e->chain_sig), "%s", sig);
        if (kid) snprintf(e->chain_sig_key_id, sizeof(e->chain_sig_key_id),
                          "%s", kid);
    }
}

/* =========================================================================
 * Head record — signed commitment to chain length
 * ========================================================================= */

/*
 * Canonical form for the head HMAC. Alphabetical keys, compact separators,
 * matching the milestone convention. The "v" field version-tags the
 * construction so a future format change cannot be confused with this one.
 */
static int head_canonical(const char *session_id,
                          int64_t last_sequence,
                          const char *last_entry_hash,
                          char *out, size_t out_size)
{
    return snprintf(out, out_size,
        "{\"last_entry_hash\":\"%s\","
        "\"last_sequence\":%lld,"
        "\"session_id\":\"%s\","
        "\"v\":\"VIRP-CHAIN-HEAD-v1\"}",
        last_entry_hash,
        (long long)last_sequence,
        session_id);
}

static virp_error_t head_hmac_hex(virp_chain_state_t *state,
                                  const char *session_id,
                                  int64_t last_sequence,
                                  const char *last_entry_hash,
                                  char out_hex[65])
{
    char canonical[512];
    int n = head_canonical(session_id, last_sequence, last_entry_hash,
                           canonical, sizeof(canonical));
    return hmac_sha256_hex(state->chain_key.key.key, canonical, (size_t)n,
                           out_hex);
}

/*
 * Write/replace the head row for a session. Caller must already be inside
 * a transaction (append path) or hold the chain lock (backfill).
 *
 * D-1: when signing is enabled, the head is Ed25519-signed over the SAME
 * head canonical bytes (with the VIRP-CHAIN-HEAD-SIG-v1 tag) and the
 * signature + key_id go into the head_sig columns via the signed upsert.
 * A signing failure fails the whole append (fail-closed) — the head can
 * never be stored HMAC'd-but-not-signed once the node has committed to
 * signing. Signing off: the exact pre-D-1 statement and bytes.
 */
static virp_error_t head_upsert_locked(virp_chain_state_t *state,
                                       const char *session_id,
                                       int64_t last_sequence,
                                       const char *last_entry_hash)
{
    char canonical[512];
    int n = head_canonical(session_id, last_sequence, last_entry_hash,
                           canonical, sizeof(canonical));
    char hmac_hex[65];
    if (hmac_sha256_hex(state->chain_key.key.key, canonical, (size_t)n,
                        hmac_hex) != VIRP_OK)
        return VIRP_ERR_CRYPTO;

    if (state->sign_enabled) {
        uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE];
        if (virp_chainsign_sign(&state->sign_key, VIRP_CHAINSIGN_TAG_HEAD,
                                canonical, (size_t)n, sig) != VIRP_OK)
            return VIRP_ERR_CRYPTO;
        char sig_hex[VIRP_CHAINSIGN_SIG_HEX];
        virp_chainsign_sig_to_hex(sig, sig_hex);

        sqlite3_stmt *st = state->stmt_head_upsert_signed;
        sqlite3_reset(st);
        sqlite3_bind_text(st, 1, session_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 2, last_sequence);
        sqlite3_bind_text(st, 3, last_entry_hash, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 4, hmac_hex, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int64(st, 5, (int64_t)get_wall_ns());
        sqlite3_bind_text(st, 6, sig_hex, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 7, state->sign_key.key_id_hex, -1, SQLITE_TRANSIENT);
        int rc = sqlite3_step(st);
        sqlite3_reset(st);
        return (rc == SQLITE_DONE) ? VIRP_OK : VIRP_ERR_CHAIN_DB;
    }

    sqlite3_reset(state->stmt_head_upsert);
    sqlite3_bind_text(state->stmt_head_upsert, 1, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(state->stmt_head_upsert, 2, last_sequence);
    sqlite3_bind_text(state->stmt_head_upsert, 3, last_entry_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(state->stmt_head_upsert, 4, hmac_hex, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(state->stmt_head_upsert, 5, (int64_t)get_wall_ns());

    int rc = sqlite3_step(state->stmt_head_upsert);
    sqlite3_reset(state->stmt_head_upsert);

    return (rc == SQLITE_DONE) ? VIRP_OK : VIRP_ERR_CHAIN_DB;
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
    if (hmac_sha256_hex(state->chain_key.key.key,
                        milestone_json, (size_t)n, hmac_hex) != VIRP_OK)
        return VIRP_ERR_CRYPTO;

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
    pthread_mutex_init(&state->lock, NULL);   /* before any error return below */
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

    /* Adversarial audit 2026-08-06 (Finding A): a database that already
     * has chain entries but no chain_heads table is NOT adopted as a
     * pre-2026-08-01 legacy upgrade candidate. The schema generation is
     * the discriminator: every database this binary has ever touched
     * carries the table (SCHEMA_SQL creates it before the first append,
     * and appends maintain it transactionally), so entries without the
     * TABLE can only mean the table was dropped to re-open the one-time
     * trust-on-upgrade window and have fresh heads signed over a
     * truncated chain. Refuse the database outright — the evidence is
     * preserved for offline inspection (virp_chain_open_verifier reads
     * such a database and reports LEGACY_CHAIN without repairing it). */
    {
        int had_heads = table_exists(state->db, "chain_heads");
        int had_entries = table_exists(state->db, "chain_entries");
        if (had_heads < 0 || had_entries < 0) {
            fprintf(stderr, "[Chain] Failed to inspect schema of %s\n",
                    db_path);
            sqlite3_close(state->db);
            return VIRP_ERR_CHAIN_DB;
        }
        if (!had_heads && had_entries) {
            int64_t n = 0;
            sqlite3_stmt *ck = NULL;
            if (sqlite3_prepare_v2(state->db,
                    "SELECT COUNT(*) FROM chain_entries",
                    -1, &ck, NULL) == SQLITE_OK &&
                sqlite3_step(ck) == SQLITE_ROW)
                n = sqlite3_column_int64(ck, 0);
            sqlite3_finalize(ck);
            if (n > 0) {
                fprintf(stderr, "[Chain] FATAL: %s has %lld chain entries "
                        "but no chain_heads table — either the table was "
                        "dropped (tampering) or this is a never-upgraded "
                        "pre-2026-08-01 database. Refusing to adopt it: "
                        "heads are never signed retroactively. Inspect it "
                        "offline with the read-only verifier.\n",
                        db_path, (long long)n);
                sqlite3_close(state->db);
                return VIRP_ERR_CHAIN_BROKEN;
            }
        }
    }

    /* Create schema */
    char *errmsg = NULL;
    rc = sqlite3_exec(state->db, SCHEMA_SQL, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Chain] Schema error: %s\n", errmsg);
        sqlite3_free(errmsg);
        sqlite3_close(state->db);
        return VIRP_ERR_CHAIN_DB;
    }

    /* MIGRATION (2026-08-04): rebuild a legacy artifacts table keyed
     * UNIQUE(artifact_id) to the two-column key above. CREATE IF NOT
     * EXISTS leaves an existing table untouched, so every database
     * created before this change still carries the constraint that let
     * one observation's body displace another's. The rebuild is one
     * transaction, preserves every stored row, and must run BEFORE the
     * statements are prepared — SQL_ARTIFACT_INSERT names the
     * (artifact_id, artifact_hash) conflict target, which fails to
     * prepare against the legacy table. Fail closed: no migrated
     * artifacts table, no chain. Detection keys on the table's stored
     * CREATE text: the legacy shape says "UNIQUE(artifact_id)" and the
     * current shape "UNIQUE(artifact_id, artifact_hash)", so the comma
     * distinguishes them. */
    {
        int legacy = 0;
        sqlite3_stmt *ck = NULL;
        if (sqlite3_prepare_v2(state->db,
                "SELECT sql FROM sqlite_master "
                "WHERE type='table' AND name='artifacts'",
                -1, &ck, NULL) == SQLITE_OK) {
            if (sqlite3_step(ck) == SQLITE_ROW) {
                const char *sql = (const char *)sqlite3_column_text(ck, 0);
                if (sql && strstr(sql, "UNIQUE(artifact_id)") &&
                    !strstr(sql, "UNIQUE(artifact_id,"))
                    legacy = 1;
            }
            sqlite3_finalize(ck);
        }
        if (legacy) {
            rc = sqlite3_exec(state->db,
                "BEGIN IMMEDIATE;"
                "ALTER TABLE artifacts RENAME TO artifacts_legacy_uid;"
                "CREATE TABLE artifacts ("
                "  id INTEGER PRIMARY KEY AUTOINCREMENT,"
                "  artifact_id TEXT NOT NULL,"
                "  artifact_type TEXT NOT NULL,"
                "  artifact_content TEXT NOT NULL,"
                "  artifact_hash TEXT NOT NULL,"
                "  session_id TEXT NOT NULL,"
                "  created_at_ns INTEGER NOT NULL,"
                "  UNIQUE(artifact_id, artifact_hash)"
                ");"
                "INSERT INTO artifacts "
                "  (artifact_id, artifact_type, artifact_content,"
                "   artifact_hash, session_id, created_at_ns)"
                "  SELECT artifact_id, artifact_type, artifact_content,"
                "         artifact_hash, session_id, created_at_ns"
                "  FROM artifacts_legacy_uid;"
                "DROP TABLE artifacts_legacy_uid;"
                "CREATE INDEX IF NOT EXISTS idx_artifacts_id "
                "  ON artifacts(artifact_id);"
                "COMMIT;", NULL, NULL, &errmsg);
            if (rc != SQLITE_OK) {
                fprintf(stderr, "[Chain] artifacts migration FAILED: %s\n",
                        errmsg ? errmsg : "unknown");
                sqlite3_free(errmsg);
                sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
                sqlite3_close(state->db);
                return VIRP_ERR_CHAIN_DB;
            }
            fprintf(stderr, "[Chain] artifacts migrated: "
                    "UNIQUE(artifact_id) -> "
                    "UNIQUE(artifact_id, artifact_hash)\n");
        }
    }

    /* Prepare statements */
    if (sqlite3_prepare_v2(state->db, SQL_INSERT, -1,
                           &state->stmt_insert, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_GET_LAST, -1,
                           &state->stmt_get_last, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_GET_RANGE, -1,
                           &state->stmt_get_range, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_INSERT_MILESTONE, -1,
                           &state->stmt_insert_milestone, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_HEAD_UPSERT, -1,
                           &state->stmt_head_upsert, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_HEAD_GET, -1,
                           &state->stmt_head_get, NULL) != SQLITE_OK) {
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

    /* Prepare artifact store statement */
    if (sqlite3_prepare_v2(state->db, SQL_ARTIFACT_INSERT, -1,
                           &state->stmt_artifact_insert, NULL) != SQLITE_OK) {
        fprintf(stderr, "[Chain] Failed to prepare artifact statement: %s\n",
                sqlite3_errmsg(state->db));
        sqlite3_close(state->db);
        return VIRP_ERR_CHAIN_DB;
    }

    /* A session with entries but no head row is tampering evidence
     * (tail+head deletion), never a repair candidate. Heads are written
     * in the same transaction as every append and the one-time legacy
     * backfill window closed with the 2026-08-01 migration (production
     * carries no headless session), so nothing legitimate looks like
     * this. Adversarial audit 2026-08-06 (Finding A): the backfill that
     * used to run here re-signed such sessions with the live K_chain on
     * restart, laundering the deletion. Log each one loudly and leave it
     * failing virp_chain_verify_session permanently. */
    {
        sqlite3_stmt *bf = NULL;
        const char *sql_bf =
            "SELECT ce.session_id, MAX(ce.sequence) "
            "FROM chain_entries ce "
            "LEFT JOIN chain_heads ch ON ch.session_id = ce.session_id "
            "WHERE ch.session_id IS NULL "
            "GROUP BY ce.session_id";
        if (sqlite3_prepare_v2(state->db, sql_bf, -1, &bf, NULL)
                == SQLITE_OK) {
            while (sqlite3_step(bf) == SQLITE_ROW) {
                fprintf(stderr,
                    "[Chain] TAMPER EVIDENCE: session=%s has entries "
                    "(max_seq=%lld) but no signed head — consistent with "
                    "tail+head deletion; the session will never verify\n",
                    (const char *)sqlite3_column_text(bf, 0),
                    (long long)sqlite3_column_int64(bf, 1));
            }
        }
        if (bf) sqlite3_finalize(bf);
    }

    /* D-1: note whether this database already carries the signature
     * columns (a previously signing-enabled chain reopened). The writer's
     * statement choice keys off sign_enabled, not this, but the read path
     * and the verifier need to know the columns exist. Default false —
     * a chain that never enabled signing is byte-identical to pre-D-1. */
    detect_sig_columns(state);
    state->have_chain_key = true;   /* init always loads K_chain */

    fprintf(stderr, "[Chain] Initialized: db=%s node=%u org=%s\n",
            db_path, node_id, state->org_id);

    return VIRP_OK;
}

/* =========================================================================
 * D-1 — enable detached Ed25519 chain signing on an init'd chain
 * ========================================================================= */

virp_error_t virp_chain_enable_signing(virp_chain_state_t *state,
                                       const char *sk_path)
{
    if (!state || !sk_path)
        return VIRP_ERR_NULL_PTR;
    if (!state->db)
        return VIRP_ERR_CHAIN_DB;
    if (state->read_only)
        return VIRP_ERR_CHAIN_READONLY;

    pthread_mutex_lock(&state->lock);

    virp_error_t err = virp_chainsign_load(&state->sign_key, sk_path);
    if (err != VIRP_OK) {
        fprintf(stderr, "[Chain] chain-signing key load failed (%s): %s\n",
                sk_path, virp_error_str(err));
        pthread_mutex_unlock(&state->lock);
        return err;
    }

    /* Add the signature columns if absent. ADD COLUMN with no default is
     * metadata-only on SQLite — no row rewrite, no data migration — and it
     * runs ONLY here, so a daemon that never enables signing leaves the
     * on-disk schema bit-for-bit the pre-D-1 shape. Each ALTER is its own
     * statement so a partially-migrated DB (columns added in a prior run)
     * is handled: skip the ones already present. */
    static const struct { const char *tbl; const char *col; } COLS[] = {
        { "chain_entries", "chain_sig" },
        { "chain_entries", "chain_sig_key_id" },
        { "chain_heads",   "head_sig" },
        { "chain_heads",   "head_sig_key_id" },
    };
    for (size_t i = 0; i < sizeof(COLS) / sizeof(COLS[0]); i++) {
        int has = column_exists(state->db, COLS[i].tbl, COLS[i].col);
        if (has < 0) {
            virp_chainsign_destroy(&state->sign_key);
            pthread_mutex_unlock(&state->lock);
            return VIRP_ERR_CHAIN_DB;
        }
        if (has == 1) continue;
        char sql[128];
        snprintf(sql, sizeof(sql), "ALTER TABLE %s ADD COLUMN %s TEXT",
                 COLS[i].tbl, COLS[i].col);
        char *errmsg = NULL;
        if (sqlite3_exec(state->db, sql, NULL, NULL, &errmsg) != SQLITE_OK) {
            fprintf(stderr, "[Chain] failed to add %s.%s: %s\n",
                    COLS[i].tbl, COLS[i].col, errmsg ? errmsg : "?");
            sqlite3_free(errmsg);
            virp_chainsign_destroy(&state->sign_key);
            pthread_mutex_unlock(&state->lock);
            return VIRP_ERR_CHAIN_DB;
        }
    }

    /* Prepare the signing statement variants. */
    if (sqlite3_prepare_v2(state->db, SQL_INSERT_SIGNED, -1,
                           &state->stmt_insert_signed, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, SQL_HEAD_UPSERT_SIGNED, -1,
                           &state->stmt_head_upsert_signed, NULL) != SQLITE_OK) {
        fprintf(stderr, "[Chain] failed to prepare signing statements: %s\n",
                sqlite3_errmsg(state->db));
        if (state->stmt_insert_signed) {
            sqlite3_finalize(state->stmt_insert_signed);
            state->stmt_insert_signed = NULL;
        }
        virp_chainsign_destroy(&state->sign_key);
        pthread_mutex_unlock(&state->lock);
        return VIRP_ERR_CHAIN_DB;
    }

    state->entry_sig_cols = true;
    state->head_sig_cols = true;
    state->sign_enabled = true;

    /* The writer handle does NOT auto-enable the asymmetric VERIFY tier.
     * The daemon holds K_chain, so its own chain_verify_session uses the
     * strictly-stronger HMAC tier (unchanged pre-D-1 behaviour); the
     * asymmetric tier's whole purpose is verification WITHOUT secrets, i.e.
     * off-box on a copy of the DB (virp-tool / report/verify.py, which open
     * read-only via virp_chain_open_verifier_ex and prepare the signed
     * SELECTs that actually read the sig columns). Enabling it here would
     * also be wrong mechanically: the writer's SELECTs do not fetch the sig
     * columns, so it would read every signature as absent. */

    fprintf(stderr, "[Chain] Detached Ed25519 chain signing ENABLED "
            "(scheme %s, key_id %s)\n",
            VIRP_CHAINSIGN_SCHEME, state->sign_key.key_id_hex);

    pthread_mutex_unlock(&state->lock);
    return VIRP_OK;
}

/* Does a table exist? Returns 1/0, or -1 on query failure. */
static int table_exists(sqlite3 *db, const char *name)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
            -1, &st, NULL) != SQLITE_OK)
        return -1;
    sqlite3_bind_text(st, 1, name, -1, SQLITE_TRANSIENT);
    int rc = sqlite3_step(st);
    sqlite3_finalize(st);
    if (rc == SQLITE_ROW) return 1;
    return (rc == SQLITE_DONE) ? 0 : -1;
}

/* Does `table` have a column named `col`? 1/0, or -1 on query failure.
 * PRAGMA table_info is the authoritative introspection; a substring scan
 * of the CREATE text would false-match a column mentioned in a comment or
 * a longer name. Used only to detect the D-1 sig columns. */
static int column_exists(sqlite3 *db, const char *table, const char *col)
{
    char sql[128];
    snprintf(sql, sizeof(sql), "PRAGMA table_info(%s)", table);
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return -1;
    int found = 0;
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(st, 1); /* "name" */
        if (name && strcmp(name, col) == 0) { found = 1; break; }
    }
    sqlite3_finalize(st);
    return found;
}

/* Detect the D-1 signature columns on an already-open database and record
 * their presence on the state. Safe on any schema: absent columns just
 * leave the flags false, and a chain that never enabled signing reads
 * exactly as it did pre-D-1. */
static void detect_sig_columns(virp_chain_state_t *state)
{
    int e = column_exists(state->db, "chain_entries", "chain_sig");
    int h = column_exists(state->db, "chain_heads", "head_sig");
    state->entry_sig_cols = (e == 1);
    state->head_sig_cols  = (h == 1);
}

/* Back-compat wrapper: HMAC tier, no public key. Unchanged behaviour for
 * every existing caller (virp-tool offline verify, the report tools). */
virp_error_t virp_chain_open_verifier(virp_chain_state_t *state,
                                      const char *db_path,
                                      const char *chain_key_path,
                                      uint32_t node_id,
                                      const char *org_id)
{
    if (!chain_key_path) return VIRP_ERR_NULL_PTR;   /* this form requires K */
    return virp_chain_open_verifier_ex(state, db_path, chain_key_path,
                                       NULL, node_id, org_id);
}

virp_error_t virp_chain_open_verifier_ex(virp_chain_state_t *state,
                                         const char *db_path,
                                         const char *chain_key_path,
                                         const char *pubkey_path,
                                         uint32_t node_id,
                                         const char *org_id)
{
    if (!state || !db_path)
        return VIRP_ERR_NULL_PTR;

    memset(state, 0, sizeof(*state));
    pthread_mutex_init(&state->lock, NULL);
    state->node_id = node_id;
    state->read_only = true;
    snprintf(state->org_id, sizeof(state->org_id), "%s",
             org_id ? org_id : "local");

    /* SYMMETRIC tier — load K_chain if given. NULL is the KEYLESS tier:
     * no secret material touched. */
    if (chain_key_path) {
        virp_error_t err = virp_key_load_file(&state->chain_key,
                                              VIRP_KEY_TYPE_CHAIN,
                                              chain_key_path);
        if (err != VIRP_OK) {
            fprintf(stderr, "[Chain] Failed to load chain key from %s: %s\n",
                    chain_key_path, virp_error_str(err));
            return err;
        }
        state->have_chain_key = true;
    }

    /* ASYMMETRIC tier — load the PUBLIC chain-signing key if given. No
     * secret material: this is exactly what a third-party verifier holds. */
    if (pubkey_path) {
        virp_error_t err = virp_chainsign_load_public(pubkey_path,
                                                      state->verify_pub,
                                                      state->verify_key_id_hex);
        if (err != VIRP_OK) {
            fprintf(stderr, "[Chain] Failed to load chain-signing public "
                    "key from %s: %s\n", pubkey_path, virp_error_str(err));
            if (state->have_chain_key) virp_key_destroy(&state->chain_key);
            return err;
        }
        state->verify_sig_enabled = true;
    }

    int rc = sqlite3_open_v2(db_path, &state->db,
                             SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "[Chain] Failed to open DB %s read-only: %s\n",
                db_path, sqlite3_errmsg(state->db));
        sqlite3_close(state->db);
        state->db = NULL;
        return VIRP_ERR_CHAIN_DB;
    }

    /* Belt over the braces: even a coding error in this module cannot
     * write through this connection. */
    sqlite3_exec(state->db, "PRAGMA query_only=ON;", NULL, NULL, NULL);

    /* No schema ensure, no migration, no backfill — inspect only. */
    int has_entries = table_exists(state->db, "chain_entries");
    if (has_entries != 1) {
        fprintf(stderr, "[Chain] %s: %s\n", db_path,
                has_entries == 0 ? "no chain_entries table — not a chain "
                                   "database"
                                 : "cannot inspect schema (WAL sidecar "
                                   "needing recovery?)");
        sqlite3_close(state->db);
        state->db = NULL;
        virp_key_destroy(&state->chain_key);
        return VIRP_ERR_CHAIN_DB;
    }

    int has_heads = table_exists(state->db, "chain_heads");
    if (has_heads == -1) {
        sqlite3_close(state->db);
        state->db = NULL;
        virp_key_destroy(&state->chain_key);
        return VIRP_ERR_CHAIN_DB;
    }
    state->legacy_no_heads = (has_heads == 0);
    if (state->legacy_no_heads)
        fprintf(stderr, "[Chain] verifier: LEGACY_CHAIN shape (no "
                "chain_heads) — sessions will report "
                "COMPLETENESS_UNPROVABLE; database left untouched\n");

    /* Legacy artifacts key shape: irrelevant to verification (which
     * never reads artifacts) and, on this handle, impossible to
     * migrate. Note it so an auditor knows what they are holding. */
    {
        sqlite3_stmt *ck = NULL;
        if (sqlite3_prepare_v2(state->db,
                "SELECT sql FROM sqlite_master "
                "WHERE type='table' AND name='artifacts'",
                -1, &ck, NULL) == SQLITE_OK) {
            if (sqlite3_step(ck) == SQLITE_ROW) {
                const char *sql = (const char *)sqlite3_column_text(ck, 0);
                if (sql && strstr(sql, "UNIQUE(artifact_id)") &&
                    !strstr(sql, "UNIQUE(artifact_id,"))
                    fprintf(stderr, "[Chain] verifier: legacy artifacts "
                            "shape (UNIQUE(artifact_id)) — left "
                            "untouched\n");
            }
            sqlite3_finalize(ck);
        }
    }

    /* D-1: does this database carry the signature columns? Drives which
     * SELECTs are prepared (so the sig can be READ) and lets the verifier
     * grade signatures only where they can exist. A pre-D-1 database has
     * these false and reads through the exact pre-D-1 SELECTs. */
    detect_sig_columns(state);

    /* Prepare ONLY what verification reads. When the sig columns exist we
     * read them too (the *_SIGNED SELECTs append chain_sig / head_sig); the
     * leading columns are identical, so a keyless/HMAC verify over a signed
     * database is byte-for-byte what it was — the extra columns are just
     * available to the asymmetric tier. Mutating statements stay NULL;
     * stmt_head_get is skipped on a legacy database (no table). */
    const char *sql_last  = state->entry_sig_cols ? SQL_GET_LAST_SIGNED  : SQL_GET_LAST;
    const char *sql_range = state->entry_sig_cols ? SQL_GET_RANGE_SIGNED : SQL_GET_RANGE;
    const char *sql_head  = state->head_sig_cols  ? SQL_HEAD_GET_SIGNED  : SQL_HEAD_GET;
    if (sqlite3_prepare_v2(state->db, sql_last, -1,
                           &state->stmt_get_last, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(state->db, sql_range, -1,
                           &state->stmt_get_range, NULL) != SQLITE_OK ||
        (!state->legacy_no_heads &&
         sqlite3_prepare_v2(state->db, sql_head, -1,
                            &state->stmt_head_get, NULL) != SQLITE_OK)) {
        fprintf(stderr, "[Chain] verifier: failed to prepare read "
                "statements: %s\n", sqlite3_errmsg(state->db));
        virp_chain_destroy(state);
        return VIRP_ERR_CHAIN_DB;
    }

    fprintf(stderr, "[Chain] Verifier open (read-only): db=%s  "
            "tiers=%s%s%s  sig_cols=%s\n", db_path,
            "keyless",
            state->have_chain_key ? "+hmac" : "",
            state->verify_sig_enabled ? "+ed25519" : "",
            state->entry_sig_cols ? "yes" : "no");
    return VIRP_OK;
}

/* =========================================================================
 * Append
 * ========================================================================= */

static virp_error_t chain_append_locked(virp_chain_state_t *state,
                               const char *session_id,
                               const char *artifact_type,
                               const char *artifact_id,
                               const char *artifact_hash,
                               const char *artifact_content,
                               virp_chain_entry_t *entry)
{
    if (!state || !session_id || !artifact_type ||
        !artifact_id || !artifact_hash || !entry)
        return VIRP_ERR_NULL_PTR;

    if (!state->db)
        return VIRP_ERR_CHAIN_DB;

    if (state->read_only)
        return VIRP_ERR_CHAIN_READONLY;

    /* BEGIN IMMEDIATE — exclusive write lock */
    int rc = sqlite3_exec(state->db, "BEGIN IMMEDIATE;", NULL, NULL, NULL);
    if (rc != SQLITE_OK)
        return VIRP_ERR_CHAIN_DB;

    /* GATE 5 — federation retry idempotency (enforcement; F4, external
     * review 2026-08-17). A federation artifact_id embeds the bridge's
     * correlation and names ONE request, ONE observation body, ONE
     * outcome; reusing such an id with DIFFERENT bytes is refused with
     * its own code. A byte-identical resubmission is NOT a conflict: the
     * retry exists because the success frame was lost, and it must be
     * able to obtain one — the store below is a no-op, the chain
     * honestly records that a retry happened. Scoped to the federation
     * types: for every other type a colliding id with distinct bodies
     * is side-by-side storage BY DESIGN (2026-08-03 audit).
     *
     * The check lives HERE, inside the append's own transaction, because
     * anywhere else it is check-then-act: the daemon used to probe via
     * virp_chain_artifact_id_conflict() before calling append, and two
     * concurrent submissions could both pass the probe and both store —
     * one correlation under two hashes, the exact corruption the gate
     * exists to refuse. Fail closed on a store that cannot answer. */
    if (virp_chain_type_is_federation(artifact_type)) {
        /* AUTHORITY IS THE CHAIN, NOT BODY STORAGE. The conflict query must
         * read chain_entries, not artifacts. An oversized (commitment-only)
         * fed_observation lands as a chain entry committing to its hash but
         * stores NO artifacts row; querying artifacts here found nothing, so
         * the same correlation id resubmitted with a DIFFERENT hash sailed
         * past the gate and the chain committed one correlation to two
         * observations — the very corruption GATE 5 exists to refuse, on the
         * exact path (oversized) that is common in production. This is the
         * body-stored-vs-chain-committed conflation the GATE 4 (-50) fix
         * corrected in the opposite direction; here the check was too lax
         * because the body it keyed on was legitimately absent. Every append
         * writes a chain_entries row, so the chain sees both the retained and
         * the commitment-only prior; idx_chain_artifact_id keeps it a lookup. */
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(state->db,
                "SELECT 1 FROM chain_entries "
                "WHERE artifact_id = ? AND artifact_hash <> ? LIMIT 1",
                -1, &st, NULL) != SQLITE_OK) {
            sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
            return VIRP_ERR_CHAIN_DB;
        }
        sqlite3_bind_text(st, 1, artifact_id, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(st, 2, artifact_hash, -1, SQLITE_TRANSIENT);
        int step = sqlite3_step(st);
        sqlite3_finalize(st);
        if (step != SQLITE_DONE) {
            sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
            return (step == SQLITE_ROW) ? VIRP_ERR_DUPLICATE_MISMATCH
                                        : VIRP_ERR_CHAIN_DB;
        }
    }

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

    /* Compute chain_hmac = hmac_sha256(K_chain, canonical). Fail-closed
     * like the signing path below: an entry is never stored with a MAC
     * we could not actually compute. */
    if (hmac_sha256_hex(state->chain_key.key.key,
                        canonical, (size_t)clen,
                        entry->chain_hmac) != VIRP_OK) {
        sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
        return VIRP_ERR_CRYPTO;
    }

    /* D-1: detached Ed25519 signature over the EXACT SAME canonical bytes
     * (domain-tagged VIRP-CHAIN-ENTRY-SIG-v1), stored beside — never inside
     * — the authenticated content. Computed here, after the hash and HMAC,
     * so it signs precisely what they cover. Fail-closed: once signing is
     * enabled, a signing failure fails the append; the entry is never
     * stored hashed-and-HMAC'd-but-unsigned. When signing is off, none of
     * this runs and the INSERT below is the pre-D-1 statement. */
    char sig_hex[VIRP_CHAINSIGN_SIG_HEX];
    if (state->sign_enabled) {
        uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE];
        if (virp_chainsign_sign(&state->sign_key, VIRP_CHAINSIGN_TAG_ENTRY,
                                canonical, (size_t)clen, sig) != VIRP_OK) {
            sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
            return VIRP_ERR_CRYPTO;
        }
        virp_chainsign_sig_to_hex(sig, sig_hex);
        snprintf(entry->chain_sig, sizeof(entry->chain_sig), "%s", sig_hex);
        snprintf(entry->chain_sig_key_id, sizeof(entry->chain_sig_key_id),
                 "%s", state->sign_key.key_id_hex);
    }

    /* INSERT — the signed variant binds two extra columns; the first 14
     * binds are identical to the unsigned statement. */
    sqlite3_stmt *ins = state->sign_enabled ? state->stmt_insert_signed
                                            : state->stmt_insert;
    sqlite3_reset(ins);
    sqlite3_bind_text(ins, 1, entry->session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 2, entry->sequence);
    sqlite3_bind_text(ins, 3, entry->chain_entry_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 4, entry->previous_entry_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(ins, 5, (int64_t)entry->timestamp_ns);
    sqlite3_bind_int64(ins, 6, (int64_t)entry->monotonic_ns);
    sqlite3_bind_text(ins, 7, entry->artifact_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 8, entry->artifact_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 9, entry->artifact_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 10, entry->artifact_hash_alg, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 11, entry->artifact_schema_version, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(ins, 12, (int)entry->signer_node_id);
    sqlite3_bind_text(ins, 13, entry->signer_org_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(ins, 14, entry->chain_hmac, -1, SQLITE_TRANSIENT);
    if (state->sign_enabled) {
        sqlite3_bind_text(ins, 15, entry->chain_sig, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(ins, 16, entry->chain_sig_key_id, -1, SQLITE_TRANSIENT);
    }

    rc = sqlite3_step(ins);
    sqlite3_reset(ins);

    if (rc != SQLITE_DONE) {
        sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
        return VIRP_ERR_CHAIN_DB;
    }

    /* Update the signed head record in the SAME transaction, so entry and
     * head commit or roll back together — the head can never lag or lead
     * the entries it authenticates. Fail closed: no head, no append. */
    if (head_upsert_locked(state, session_id, next_seq,
                           entry->chain_entry_hash) != VIRP_OK) {
        sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
        return VIRP_ERR_CHAIN_DB;
    }

    /* Store the artifact body in the SAME transaction as the entry that
     * commits to its hash. Before this the body was written by a separate
     * autocommit statement after COMMIT, so a crash between the two — or a
     * snapshot taken between them — yielded a chain entry committing to a
     * body that does not exist (adversarial test #2, `mid_outcome`; 20
     * such entries in production). Now entry, head and body land or roll
     * back together: a store failure fails the whole append, typed, and
     * can never leave a dangling commitment. The FI point keeps its name
     * and its meaning — "between entry insert and body store" — but the
     * boundary is now inside the transaction, so dying here must lose
     * both records, not one. */
    if (artifact_content && artifact_content[0] != '\0') {
        VIRP_FI("mid_outcome");
        if (chain_artifact_store_locked(state, artifact_id, artifact_type,
                                        artifact_content, artifact_hash,
                                        session_id) != VIRP_OK) {
            sqlite3_exec(state->db, "ROLLBACK;", NULL, NULL, NULL);
            return VIRP_ERR_CHAIN_DB;
        }
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

/*
 * Grade one entry's artifact binding.
 *   1  bound      — a body is stored and hashes to the entry's commitment
 *   0  unverifiable — nothing was retained that COULD be bound: no body
 *                   row, or an INDIRECT-commitment type whose hash names a
 *                   signed observation the chain does not hold, or a body
 *                   stored at the daemon's 8192-byte field limit (a prefix,
 *                   which cannot hash to the whole)
 *  -1  broken     — a body IS retained and does NOT hash to its commitment
 *
 * The body is looked up by (artifact_id, artifact_hash), the pair the
 * entry commits to and the artifacts table is keyed by — resolving by
 * artifact_id alone would pick up a colliding id's body and grade the
 * wrong bytes.
 */
static int chain_verify_binding_locked(virp_chain_state_t *state,
                                       const virp_chain_entry_t *e)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(state->db,
            "SELECT artifact_content FROM artifacts "
            "WHERE artifact_id = ? AND artifact_hash = ?",
            -1, &st, NULL) != SQLITE_OK)
        return 0;   /* cannot read the store: report unverifiable, not broken */

    sqlite3_bind_text(st, 1, e->artifact_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, e->artifact_hash, -1, SQLITE_TRANSIENT);

    int verdict = 0;
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char *body = (const char *)sqlite3_column_text(st, 0);
        size_t blen = body ? strlen(body) : 0;

        if (!body || blen == 0) {
            verdict = 0;                       /* nothing retained to bind */
        } else if (blen >= VIRP_CHAIN_ARTIFACT_CONTENT_MAX) {
            verdict = 0;                       /* stored truncated: a prefix */
        } else if (virp_chain_type_is_indirect(e->artifact_type)) {
            /* Body required and present, but artifact_hash commits to a
             * signed observation the chain does not retain — honest
             * verdict is unverifiable, never a silent pass. */
            verdict = 0;
        } else {
            char digest[65];
            if (virp_chain_artifact_digest(body, digest) != VIRP_OK)
                verdict = -1;                  /* undecodable body */
            else
                verdict = hexdigest_eq(digest, e->artifact_hash) ? 1 : -1;
        }
    }
    sqlite3_finalize(st);
    return verdict;
}

/*
 * Is the gate_intent entry with this chain_entry_hash CLOSED — does a
 * gate_execution or outcome entry, in ANY session, carry it as
 * intent_entry_hash in its stored body? The closer is found by the exact
 * token the daemon writes ("intent_entry_hash":"<64 hex>"), matched with
 * instr() against bodies joined on the (artifact_id, artifact_hash) pair
 * the closer's entry commits to — so a planted body with no entry, or a
 * body under a different commitment, does not close anything. Cross-
 * session on purpose: an approved apply's intent lives in
 * gate-enforce:<device> while its outcome lives in approval:<device>.
 * Mirrors report/verify.py grade_open_executions().
 *
 * A store that cannot be read yields "not closed": the honest direction,
 * since an intent whose closer cannot be found is exactly an open one.
 */
static bool chain_intent_closed_locked(virp_chain_state_t *state,
                                       const char *intent_hash)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(state->db,
            "SELECT 1 FROM chain_entries c "
            "JOIN artifacts a ON a.artifact_id = c.artifact_id "
            "               AND a.artifact_hash = c.artifact_hash "
            "WHERE c.artifact_type IN ('gate_execution', 'outcome') "
            "  AND instr(a.artifact_content, ?) > 0 LIMIT 1",
            -1, &st, NULL) != SQLITE_OK)
        return false;

    char needle[96];
    snprintf(needle, sizeof(needle), "\"intent_entry_hash\":\"%s\"",
             intent_hash);
    sqlite3_bind_text(st, 1, needle, -1, SQLITE_TRANSIENT);
    bool closed = (sqlite3_step(st) == SQLITE_ROW);
    sqlite3_finalize(st);
    return closed;
}

static virp_error_t chain_verify_locked(virp_chain_state_t *state,
                               const char *session_id,
                               int64_t from_sequence,
                               int64_t to_sequence,
                               virp_chain_verify_result_t *result,
                               char out_last_hash[65])
{
    if (!state || !session_id || !result)
        return VIRP_ERR_NULL_PTR;

    memset(result, 0, sizeof(*result));
    result->from_sequence = from_sequence;
    result->to_sequence = to_sequence;
    result->first_broken = -1;
    result->valid = true;
    /* Tier flags (pure addition). hmac_checked reflects whether K_chain was
     * supplied; sig_checked whether per-entry Ed25519 was actually graded
     * for this range (verify_sig_enabled, columns present, and not a
     * key-unavailable session). */
    result->hmac_checked = state->have_chain_key;
    bool check_sigs = state->verify_sig_enabled && state->entry_sig_cols &&
                      !state->sig_key_unavailable_session;
    result->sig_checked = check_sigs;

    /* The caller asserts this range exists; an inverted or negative range
     * can assert nothing, and before 2026-08-01 verified vacuously valid
     * with zero entries checked. */
    if (from_sequence < 0 || to_sequence < from_sequence) {
        result->valid = false;
        snprintf(result->error_detail, sizeof(result->error_detail),
                 "Invalid verify range %lld..%lld",
                 (long long)from_sequence, (long long)to_sequence);
        return VIRP_OK;
    }

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

        if (!hexdigest_eq(computed_hash, e.chain_entry_hash)) {
            result->valid = false;
            result->first_broken = e.sequence;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Entry hash mismatch at sequence %lld",
                     (long long)e.sequence);
            break;
        }

        /* Verify HMAC — SYMMETRIC tier only. The KEYLESS tier
         * (have_chain_key false) skips it: hash + link + completeness
         * stand on their own with no secret. When the key is present the
         * check and its verdict are byte-for-byte the pre-D-1 behaviour. */
        if (state->have_chain_key) {
            char computed_hmac[65];
            if (hmac_sha256_hex(state->chain_key.key.key,
                                canonical, (size_t)clen,
                                computed_hmac) != VIRP_OK) {
                result->valid = false;
                result->first_broken = e.sequence;
                snprintf(result->error_detail, sizeof(result->error_detail),
                         "HMAC could not be computed at sequence %lld",
                         (long long)e.sequence);
                break;
            }

            if (!hexdigest_eq(computed_hmac, e.chain_hmac)) {
                result->valid = false;
                result->first_broken = e.sequence;
                snprintf(result->error_detail, sizeof(result->error_detail),
                         "HMAC mismatch at sequence %lld",
                         (long long)e.sequence);
                break;
            }
        }

        /* ASYMMETRIC tier — Ed25519 over the SAME canonical bytes, verified
         * with the PUBLIC key only. Session-granularity key rotation: in a
         * head-signed session every entry MUST carry a signature whose
         * key_id equals the head's (which the caller has already confirmed
         * equals verify_key_id). A missing signature or a key_id that
         * differs is a FAIL at the same severity as a bad signature — the
         * sig columns sit outside the canonical, so the signature is their
         * only integrity protection, and a soft "unsigned" reading would
         * let an attacker strip a signature undetected. The whole-session
         * key-unavailable case is handled one level up (sig_checked is
         * false here); an UNSIGNED pre-D-1 session (no head sig) never
         * reaches this arm and is counted entries_unsigned instead. */
        if (check_sigs) {
            uint8_t sig[VIRP_CHAINSIGN_SIG_SIZE];
            if (e.chain_sig[0] == '\0') {
                result->valid = false;
                result->first_broken = e.sequence;
                snprintf(result->error_detail, sizeof(result->error_detail),
                         "Missing Ed25519 signature at sequence %lld in a "
                         "signed session (stripped signature)",
                         (long long)e.sequence);
                break;
            }
            if (strcmp(e.chain_sig_key_id, state->verify_key_id_hex) != 0) {
                result->valid = false;
                result->first_broken = e.sequence;
                snprintf(result->error_detail, sizeof(result->error_detail),
                         "Signature key_id mismatch at sequence %lld "
                         "(entry %s, session %s)", (long long)e.sequence,
                         e.chain_sig_key_id, state->verify_key_id_hex);
                break;
            }
            if (!virp_chainsign_sig_from_hex(e.chain_sig, sig) ||
                !virp_chainsign_verify(state->verify_pub,
                                       VIRP_CHAINSIGN_TAG_ENTRY,
                                       canonical, (size_t)clen, sig)) {
                result->valid = false;
                result->first_broken = e.sequence;
                snprintf(result->error_detail, sizeof(result->error_detail),
                         "Ed25519 signature verification failed at "
                         "sequence %lld", (long long)e.sequence);
                break;
            }
            result->entries_signed++;
        } else if (state->verify_sig_enabled && e.chain_sig[0] == '\0') {
            /* pubkey supplied, but this is an unsigned (pre-D-1) session:
             * informational count, never a failure. */
            result->entries_unsigned++;
        }

        /* ARTIFACT BINDING (2026-08-06). The checks above prove the entry
         * is internally consistent and K_chain-authenticated; none of them
         * proves the entry commits to the body the chain actually stores.
         * Default-on, with the same three-way grading report/verify.py
         * uses, because an operator CLI that prints VALID for an entry it
         * never bound is worse than one that says so: a retained body that
         * disagrees with its commitment is tampering (fatal), while a body
         * the format never retained is UNVERIFIABLE (counted, never
         * counted as verified, not fatal). */
        {
            int bind = chain_verify_binding_locked(state, &e);
            if (bind < 0) {
                result->valid = false;
                result->first_broken = e.sequence;
                snprintf(result->error_detail, sizeof(result->error_detail),
                         "Artifact binding failed at sequence %lld: stored "
                         "body does not hash to artifact_hash",
                         (long long)e.sequence);
                break;
            }
            if (bind == 0) result->artifacts_unverifiable++;
            else           result->artifacts_bound++;
        }

        /* OPEN EXECUTIONS (Sep 1 review, Task 5). A gate_intent entry
         * says the daemon was about to dispatch; its closer says what
         * came of it. No closer anywhere = the daemon never got to write
         * one = an execution whose disposition is unknown. Counted,
         * reported, and NEVER a failure: the chain is intact, the world
         * beyond its last entry is what is uncertain. */
        if (strcmp(e.artifact_type, "gate_intent") == 0) {
            if (chain_intent_closed_locked(state, e.chain_entry_hash))
                result->executions_closed++;
            else
                result->executions_open++;
        }

        /* Advance */
        snprintf(expected_prev, sizeof(expected_prev), "%s",
                 e.chain_entry_hash);
        expected_seq++;
        result->entries_checked++;
    }

    sqlite3_reset(state->stmt_get_range);

    /* COMPLETENESS: every sequence in [from, to] must have been verified.
     * Middle deletions are caught by the sequence-gap check above, but a
     * range whose TAIL is missing just ends the row walk early — before
     * 2026-08-01 that returned valid=true, so deleting the last K entries
     * of a session was undetectable (review finding N4). Nothing here
     * commits to overall chain length; that is virp_chain_verify_session's
     * job via the signed head record. This check only makes the verifier
     * honest about the range the CALLER claimed. */
    if (result->valid) {
        int64_t expected_count = to_sequence - from_sequence + 1;
        if (result->entries_checked != expected_count) {
            result->valid = false;
            result->first_broken = from_sequence + result->entries_checked;
            snprintf(result->error_detail, sizeof(result->error_detail),
                     "Chain truncated: expected %lld entries "
                     "(%lld..%lld), found %lld",
                     (long long)expected_count,
                     (long long)from_sequence,
                     (long long)to_sequence,
                     (long long)result->entries_checked);
        }
    }

    if (result->valid && out_last_hash) {
        /* expected_prev holds the hash of the last verified entry;
         * entries_checked >= 1 is guaranteed here by the completeness
         * check (expected_count >= 1 for any valid range). */
        snprintf(out_last_hash, 65, "%s", expected_prev);
    }

    return VIRP_OK;
}

/* =========================================================================
 * Get Last
 * ========================================================================= */

static virp_error_t chain_get_last_locked(virp_chain_state_t *state,
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
    if (state->stmt_head_upsert)
        sqlite3_finalize(state->stmt_head_upsert);
    if (state->stmt_head_get)
        sqlite3_finalize(state->stmt_head_get);
    if (state->stmt_intent_insert)
        sqlite3_finalize(state->stmt_intent_insert);
    if (state->stmt_intent_get)
        sqlite3_finalize(state->stmt_intent_get);
    if (state->stmt_intent_execute)
        sqlite3_finalize(state->stmt_intent_execute);
    if (state->stmt_artifact_insert)
        sqlite3_finalize(state->stmt_artifact_insert);
    if (state->stmt_insert_signed)
        sqlite3_finalize(state->stmt_insert_signed);
    if (state->stmt_head_upsert_signed)
        sqlite3_finalize(state->stmt_head_upsert_signed);
    if (state->db)
        sqlite3_close(state->db);

    virp_key_destroy(&state->chain_key);
    if (state->sign_enabled)
        virp_chainsign_destroy(&state->sign_key);

    /* Safe: destroy runs only after the worker drain (Item 2), so no thread
     * still holds the lock. Destroy before the memset zeroes it. */
    pthread_mutex_destroy(&state->lock);

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

static virp_error_t chain_intent_store_locked(virp_chain_state_t *state,
                                      virp_intent_entry_t *entry)
{
    if (!state || !state->db || !entry)
        return VIRP_ERR_NULL_PTR;

    if (state->read_only)
        return VIRP_ERR_CHAIN_READONLY;

    /* Compute HMAC of intent_hash using K_chain */
    if (hmac_sha256_hex(state->chain_key.key.key,
                        entry->intent_hash, strlen(entry->intent_hash),
                        entry->signature_hmac) != VIRP_OK)
        return VIRP_ERR_CRYPTO;

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

static virp_error_t chain_intent_get_locked(virp_chain_state_t *state,
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

static virp_error_t chain_intent_execute_locked(virp_chain_state_t *state,
                                        const char *intent_id,
                                        virp_intent_entry_t *entry)
{
    if (!state || !state->db || !intent_id || !entry)
        return VIRP_ERR_NULL_PTR;

    if (state->read_only)
        return VIRP_ERR_CHAIN_READONLY;

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
        virp_error_t err = chain_intent_get_locked(state, intent_id, entry);
        if (err != VIRP_OK)
            return VIRP_ERR_INTENT_NOT_FOUND;
        return VIRP_ERR_INTENT_EXHAUSTED;
    }

    /* Return updated entry */
    return chain_intent_get_locked(state, intent_id, entry);
}

/* =========================================================================
 * Artifact Store
 * ========================================================================= */

static virp_error_t chain_artifact_store_locked(virp_chain_state_t *state,
                                        const char *artifact_id,
                                        const char *artifact_type,
                                        const char *artifact_content,
                                        const char *artifact_hash,
                                        const char *session_id)
{
    if (!state || !state->db || !artifact_id || !artifact_type ||
        !artifact_content || !artifact_hash || !session_id)
        return VIRP_ERR_NULL_PTR;

    if (artifact_content[0] == '\0')
        return VIRP_ERR_NULL_PTR;

    if (state->read_only)
        return VIRP_ERR_CHAIN_READONLY;

    sqlite3_stmt *stmt = state->stmt_artifact_insert;
    sqlite3_reset(stmt);

    sqlite3_bind_text(stmt, 1, artifact_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, artifact_type, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, artifact_content, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, artifact_hash, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, session_id, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 6, (int64_t)get_wall_ns());

    int rc = sqlite3_step(stmt);
    sqlite3_reset(stmt);

    if (rc != SQLITE_DONE) {
        fprintf(stderr, "[Chain] Artifact store failed: %s\n",
                sqlite3_errmsg(state->db));
        return VIRP_ERR_CHAIN_DB;
    }

    return VIRP_OK;
}
