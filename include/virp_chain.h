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
    /* Intent store prepared statements */
    sqlite3_stmt       *stmt_intent_insert;
    sqlite3_stmt       *stmt_intent_get;
    sqlite3_stmt       *stmt_intent_execute;
    /* Artifact store */
    sqlite3_stmt       *stmt_artifact_insert;
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
 * Verify chain integrity for a sequence range within a session.
 * Re-hashes each entry and verifies HMAC + previous_entry_hash linkage.
 */
virp_error_t virp_chain_verify(virp_chain_state_t *state,
                               const char *session_id,
                               int64_t from_sequence,
                               int64_t to_sequence,
                               virp_chain_verify_result_t *result);

/*
 * Get the last chain entry for a session.
 * Returns VIRP_ERR_CHAIN_SEQUENCE if no entries exist.
 */
virp_error_t virp_chain_get_last(virp_chain_state_t *state,
                                 const char *session_id,
                                 virp_chain_entry_t *entry);

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
