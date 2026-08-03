/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Primitive 6: Trust Chain — cryptographic audit trail
 *
 * Session-scoped chains with:
 *   - Canonical JSON serialization (sorted keys, compact separators)
 *   - Transactional sequencing (BEGIN IMMEDIATE, sequence at COMMIT)
 *   - HMAC-SHA256 via K_chain (key type 3, separate from K_obs)
 *   - Milestones every 100 entries for streaming verification
 *   - Crash recovery: no gaps (sequence assigned only at COMMIT)
 */

#ifndef VIRP_CHAIN_H
#define VIRP_CHAIN_H

#include "virp.h"
#include "virp_crypto.h"
#include <sqlite3.h>
#include <pthread.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

#define VIRP_CHAIN_MILESTONE_INTERVAL  100
#define VIRP_CHAIN_GENESIS_PREFIX      "VIRP_CHAIN_GENESIS:"

/* =========================================================================
 * Chain Entry — all stack-allocated, no dynamic memory
 * ========================================================================= */

typedef struct {
    char     session_id[64];
    int64_t  sequence;
    char     chain_entry_hash[65];      /* SHA-256 hex + NUL */
    char     previous_entry_hash[65];
    uint64_t timestamp_ns;              /* Wall clock (informational) */
    uint64_t monotonic_ns;              /* CLOCK_MONOTONIC (ordering) */
    char     artifact_type[16];         /* "observation", "intent", "outcome" */
    char     artifact_id[128];
    char     artifact_hash[65];         /* SHA-256 hex of artifact */
    char     artifact_hash_alg[8];      /* "sha256" */
    char     artifact_schema_version[8]; /* "1" */
    uint32_t signer_node_id;
    char     signer_org_id[64];
    char     chain_hmac[65];            /* HMAC-SHA256 hex of canonical entry */
} virp_chain_entry_t;

/* =========================================================================
 * Chain Verify Result
 * ========================================================================= */

typedef struct {
    bool     valid;
    int64_t  from_sequence;
    int64_t  to_sequence;
    int64_t  entries_checked;
    int64_t  first_broken;              /* -1 if none */
    char     error_detail[256];
} virp_chain_verify_result_t;

/* =========================================================================
 * Chain State — owns the SQLite database and prepared statements
 * ========================================================================= */

typedef struct {
    sqlite3            *db;
    virp_signing_key_t  chain_key;      /* K_chain, separate from K_obs */
    uint32_t            node_id;
    char                org_id[64];
    sqlite3_stmt       *stmt_insert;
    sqlite3_stmt       *stmt_get_last;
    sqlite3_stmt       *stmt_get_range;
    sqlite3_stmt       *stmt_insert_milestone;
    /* Signed per-session head record (chain_heads table) */
    sqlite3_stmt       *stmt_head_upsert;
    sqlite3_stmt       *stmt_head_get;
    /* Intent store prepared statements */
    sqlite3_stmt       *stmt_intent_insert;
    sqlite3_stmt       *stmt_intent_get;
    sqlite3_stmt       *stmt_intent_execute;
    /* Artifact store */
    sqlite3_stmt       *stmt_artifact_insert;

    /*
     * Serializes ALL chain operations. The db + prepared statements above
     * are shared mutable state; sqlite3_stmt objects are not safe to use
     * from concurrent threads. Snow's cage operator drives concurrent
     * traffic, so every public chain entry point takes this lock for the
     * duration of its DB work. Non-recursive: public wrappers lock once and
     * call an internal *_locked core; cores call other cores directly, so
     * the lock is never re-entered. Held only inside the chain module (which
     * never acquires exec_mutex), so there is no lock-ordering/deadlock risk
     * with the execute path.
     */
    pthread_mutex_t     lock;
} virp_chain_state_t;

/* =========================================================================
 * Lifecycle
 * ========================================================================= */

/*
 * Initialize the chain database.
 *   db_path:       Path to SQLite database file
 *   chain_key_path: Path to 32-byte chain key (VIRP_KEY_TYPE_CHAIN)
 *   node_id:       This node's identity
 *   org_id:        Organization identifier (e.g. "local")
 */
virp_error_t virp_chain_init(virp_chain_state_t *state,
                             const char *db_path,
                             const char *chain_key_path,
                             uint32_t node_id,
                             const char *org_id);

/*
 * Append an artifact to the chain for a given session.
 * Transactional: sequence assigned only at COMMIT.
 *
 * On success, populates *entry with the committed chain entry.
 */
virp_error_t virp_chain_append(virp_chain_state_t *state,
                               const char *session_id,
                               const char *artifact_type,
                               const char *artifact_id,
                               const char *artifact_hash,
                               virp_chain_entry_t *entry);

/*
 * Append a chain entry AND store the artifact body it commits to, in one
 * SQLite transaction. Either both are durable or neither is: a crash (or
 * a snapshot of the database) can never capture an entry whose committed
 * body is absent, and a failed body store fails the whole append with
 * VIRP_ERR_CHAIN_DB instead of being silently dropped.
 *
 * artifact_content may be NULL or empty, in which case this behaves
 * exactly like virp_chain_append() — an entry-only append (commitment
 * without retained body) remains a deliberate, caller-chosen state, not
 * something a crash can manufacture.
 *
 * Every call site that pairs virp_chain_append() with
 * virp_chain_artifact_store() for the same artifact must use this
 * instead; the split calls are only for bodies stored without a chain
 * entry of their own (e.g. the intent store).
 */
virp_error_t virp_chain_append_with_artifact(virp_chain_state_t *state,
                                             const char *session_id,
                                             const char *artifact_type,
                                             const char *artifact_id,
                                             const char *artifact_hash,
                                             const char *artifact_content,
                                             virp_chain_entry_t *entry);

/*
 * Verify chain integrity for a sequence range within a session.
 * Re-hashes each entry and verifies HMAC + previous_entry_hash linkage.
 *
 * COMPLETENESS: the caller asserts that entries from_sequence..to_sequence
 * exist. The verifier requires every sequence in that range to be present
 * and valid — a range that ends early (tail truncation), returns zero rows,
 * or is inverted (to < from) yields result->valid == false. Before
 * 2026-08-01 this function verified only the rows the query returned, so
 * deleting the last K entries of a session still verified as valid.
 */
virp_error_t virp_chain_verify(virp_chain_state_t *state,
                               const char *session_id,
                               int64_t from_sequence,
                               int64_t to_sequence,
                               virp_chain_verify_result_t *result);

/*
 * Verify an ENTIRE session against its signed head record.
 *
 * Every append updates, in the same transaction, a per-session head row
 * (chain_heads: last_sequence, last_entry_hash) authenticated by
 * HMAC-SHA256(K_chain). This function:
 *
 *   1. loads the head record and verifies its HMAC;
 *   2. walks sequences 0..head.last_sequence with the completeness rule
 *      above;
 *   3. requires the final verified entry's chain_entry_hash to equal
 *      head.last_entry_hash.
 *
 * This is the call that makes "the whole session verifies" meaningful: a
 * database writer WITHOUT K_chain cannot delete the chain tail undetected,
 * because they can neither forge a head record for the shortened chain nor
 * remove it (a session with entries but no head record fails verification).
 *
 * TRUST BOUNDARY: a holder of K_chain can still rewrite history wholesale,
 * including the head. This authenticates chain length against the same
 * adversary the per-entry HMAC targets — DB write access without the key —
 * and no stronger one. External anchoring remains future work.
 *
 * result->to_sequence is set to the head's last_sequence.
 */
virp_error_t virp_chain_verify_session(virp_chain_state_t *state,
                                       const char *session_id,
                                       virp_chain_verify_result_t *result);

/*
 * Get the last chain entry for a session.
 * Returns VIRP_ERR_CHAIN_SEQUENCE if no entries exist.
 */
virp_error_t virp_chain_get_last(virp_chain_state_t *state,
                                 const char *session_id,
                                 virp_chain_entry_t *entry);

/*
 * Set *exists to true iff any chain entry has the given artifact_id.
 * Used by the approval flow to detect an existing OUTCOME (artifact_id
 * "outcome:<proposal_id>") — the L1 enforcement point. Returns VIRP_OK
 * on a successful query (whether or not it matched), an error otherwise.
 */
virp_error_t virp_chain_artifact_exists(virp_chain_state_t *state,
                                        const char *artifact_id,
                                        bool *exists);

/*
 * Clean up all resources.
 */
void virp_chain_destroy(virp_chain_state_t *state);

/* =========================================================================
 * Durable Intent Store — intents survive process restarts
 *
 * Stored in the same chain.db. The O-Node owns the DB; the MCP server
 * (which may be a short-lived process) calls through the Unix socket.
 * ========================================================================= */

typedef struct {
    char     intent_id[128];
    char     intent_hash[65];
    char     confidence[16];
    int64_t  expires_at_ns;
    int32_t  max_commands;
    int32_t  commands_executed;
    char     signature_hmac[65];
    int64_t  signature_seq;
    int64_t  signature_timestamp_ns;
    int64_t  created_at_ns;
    /* Large text fields — caller provides buffers */
    char     intent_json[8192];
    char     proposed_actions[8192];
    char     constraints[512];
} virp_intent_entry_t;

/*
 * Store an intent in the durable DB. Returns the stored entry
 * with signature fields populated.
 */
virp_error_t virp_chain_intent_store(virp_chain_state_t *state,
                                      virp_intent_entry_t *entry);

/*
 * Retrieve an intent by ID. Returns VIRP_ERR_INTENT_NOT_FOUND if missing.
 */
virp_error_t virp_chain_intent_get(virp_chain_state_t *state,
                                    const char *intent_id,
                                    virp_intent_entry_t *entry);

/*
 * Atomically increment commands_executed. Returns updated entry.
 * Returns VIRP_ERR_INTENT_EXHAUSTED if max_commands already reached.
 */
virp_error_t virp_chain_intent_execute(virp_chain_state_t *state,
                                        const char *intent_id,
                                        virp_intent_entry_t *entry);

/* =========================================================================
 * Artifact Store — persists raw payloads alongside chain hashes
 * ========================================================================= */

/*
 * Store an artifact's raw content in the artifacts table.
 * artifact_id must match the chain_entries.artifact_id for cross-reference.
 * Returns VIRP_ERR_NULL_PTR if any parameter is NULL or content is empty.
 */
virp_error_t virp_chain_artifact_store(virp_chain_state_t *state,
                                        const char *artifact_id,
                                        const char *artifact_type,
                                        const char *artifact_content,
                                        const char *artifact_hash,
                                        const char *session_id);

#endif /* VIRP_CHAIN_H */
