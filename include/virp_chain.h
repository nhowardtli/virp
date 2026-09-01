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
#include "virp_chainsign.h"
#include <sqlite3.h>
#include <pthread.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

#define VIRP_CHAIN_MILESTONE_INTERVAL  100

/* The daemon's request field is char artifact_content[8192], so a body at
 * or past this length reached the chain truncated: a prefix, which cannot
 * hash to the whole. Mirrors ARTIFACT_CONTENT_MAX in report/verify.py. */
#define VIRP_CHAIN_ARTIFACT_CONTENT_MAX 8191
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
    /* D-1 detached Ed25519 signature over the SAME canonical bytes (with
     * the VIRP-CHAIN-ENTRY-SIG-v1 domain tag), and the signing key_id.
     * Empty strings when the entry carries no signature (pre-D-1 session,
     * or signing-off chain). Never part of the canonical — pure sidecar. */
    char     chain_sig[129];            /* 128 hex + NUL, or "" */
    char     chain_sig_key_id[33];      /* 32 hex + NUL,  or "" */
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
    /* Artifact binding (2026-08-06). Entries whose stored body hashes to
     * the entry's artifact_hash are counted verified; entries the chain
     * format cannot bind — no body retained, or an INDIRECT-commitment
     * type whose hash commits to a signed observation the chain does not
     * hold — are counted UNVERIFIABLE and never as verified. valid stays
     * true for those: unverifiable is a retention limit, not tampering.
     * A body that IS retained and does NOT hash to its commitment is
     * tampering and clears valid. */
    int64_t  artifacts_bound;
    int64_t  artifacts_unverifiable;

    /* =====================================================================
     * D-1 asymmetric tier (Ed25519 detached signatures). All PURE-ADDITION
     * counters — the fields above keep their exact pre-D-1 meaning, and a
     * verifier run without a public key leaves everything here zero/false.
     *
     * Three independent tiers, reported together:
     *   keyless    hash + link + completeness (no secrets). head_authenticated
     *              is false: the head's length claim is unverified.
     *   symmetric  adds HMAC under K_chain. have_chain_key drives it; when
     *              set, head_hmac_ok authenticates the head length claim.
     *   asymmetric adds Ed25519 under the PUBLIC key only. sig_checked is
     *              set when a public key was supplied.
     * ===================================================================== */
    bool     hmac_checked;      /* K_chain was supplied and HMACs verified   */
    bool     sig_checked;       /* a public key was supplied and sigs graded */
    bool     head_authenticated;/* head length claim authenticated (HMAC or
                                 * Ed25519, per tier)                        */
    bool     head_hmac_ok;      /* head HMAC verified (symmetric tier)       */
    bool     head_sig_ok;       /* head Ed25519 signature verified           */

    /* Per-entry signature accounting (asymmetric tier). In a HEAD-SIGNED
     * session every entry MUST carry a signature under the head's key_id;
     * a missing signature or a key_id that differs from the head's is a
     * FAIL at the same severity as a stripped signature (the sig columns
     * sit outside the canonical, so the signature is their only integrity
     * protection). entries_signed counts entries whose Ed25519 verified;
     * a mismatch clears valid and sets first_broken. */
    int64_t  entries_signed;
    int64_t  entries_unsigned;  /* entries with no signature in an UNSIGNED
                                 * (pre-D-1) session — informational, never
                                 * a failure                                 */

    /* Whole-session soft outcome (NOT a failure): the session IS signed but
     * the verifier was not given this session's public key, so signatures
     * could not be checked. Set only when sig_checked would otherwise apply
     * and the key_id did not match verify_key_id. */
    bool     sig_key_unavailable;
    char     sig_key_id[VIRP_CHAINSIGN_KEYID_HEX]; /* the session's signing
                                 * key_id as read from the head/entries, or
                                 * "" if the session is unsigned            */
} virp_chain_verify_result_t;

/* =========================================================================
 * Artifact type policy — one definition, used by the external append path
 * (to refuse forgeries) and by the verifier (to grade binding honestly)
 * ========================================================================= */

/*
 * Types the DAEMON mints on internal paths and an external socket client
 * may never claim: "approval" and "proposal" (src/virp_approval.c),
 * "outcome", "gate_rejection" and "gate_execution" (src/virp_onode.c),
 * "validation" (src/virp_validator.c). A chain reader treats these as
 * semantic records of the approval/gate/validation flows, so accepting one
 * from a socket client makes a forged record indistinguishable from a
 * minted one.
 *
 * "gate_execution" is reserved for the same reason as "gate_rejection",
 * and more sharply: it is the record that an action WAS executed and what
 * the device returned (by digest). A client able to mint one could
 * manufacture evidence of an execution that never happened, or of a
 * response body it chooses the digest for.
 */
bool virp_chain_type_is_daemon_reserved(const char *artifact_type);

/*
 * INDIRECT-commitment types: artifact_hash commits to a SIGNED
 * OBSERVATION that the chain does not retain, while the stored body is
 * the plain JSON. sha256(body) therefore does not equal artifact_hash by
 * design, and the entry cannot be bound from within the chain. Matches
 * INDIRECT_COMMITMENT_TYPES in report/verify.py.
 *
 * DEFERRED (2026-08-06): the honest fix is an explicit commitment_mode
 * field inside the HMAC'd canonical object, so both modes are defined and
 * verifiable rather than one being UNVERIFIABLE. That changes the
 * canonical form and belongs in the same change window as the provenance
 * field and a chain format version bump.
 */
bool virp_chain_type_is_indirect(const char *artifact_type);

/*
 * Types an external client may submit at all. Anything else — including a
 * wholly invented type — is refused rather than recorded as if meaningful.
 */
bool virp_chain_type_is_external_allowed(const char *artifact_type);

/*
 * The federation-bridge provenance types (fed_request / fed_observation /
 * fed_outcome), whose correlation-keyed artifact_ids promise
 * one-id-one-body. For these — and only these — the append path refuses
 * an id reuse with different bytes (GATE 5), enforced inside the append
 * transaction itself.
 */
bool virp_chain_type_is_federation(const char *artifact_type);

/*
 * SHA-256 hex of the bytes an artifact_hash commits to. Bodies are stored
 * either as "base64:<b64>" (signed wire messages) or as literal text, and
 * the commitment is over the DECODED bytes in the first case — the same
 * rule report/verify.py decode_artifact() applies. Returns
 * VIRP_ERR_INVALID_LENGTH if a base64 body does not decode.
 */
virp_error_t virp_chain_artifact_digest(const char *artifact_content,
                                        char out_hex[65]);

/*
 * The EXACT bytes virp_chain_artifact_digest() hashes, for a caller that
 * must also verify a signature over them (chain_append's observation
 * gate). Deliberately the same decoder: verifying bytes recovered by a
 * second, independent decoder would risk binding a hash to one byte
 * string while checking a signature over another.
 */
virp_error_t virp_chain_artifact_bytes(const char *artifact_content,
                                       uint8_t *out, size_t out_max,
                                       size_t *out_len);

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

    /* =====================================================================
     * D-1 detached Ed25519 chain signing — PURE ADDITION. When disabled
     * (the default, and every pre-D-1 deployment) none of this is touched
     * and the append path, the schema on disk and every hash/HMAC are
     * byte-identical to the pre-D-1 tree.
     * ===================================================================== */

    /* Writer side: set by virp_chain_enable_signing(). When true, every
     * append also Ed25519-signs the canonical bytes and the head canonical
     * and stores the signatures + key_id in the sig columns. */
    bool                   sign_enabled;
    virp_chainsign_key_t   sign_key;
    /* Insert / head-upsert variants that also bind the sig columns. Prepared
     * only when sign_enabled; the unsigned statements above are used
     * otherwise, so a signing-off chain issues the exact pre-D-1 SQL. */
    sqlite3_stmt          *stmt_insert_signed;
    sqlite3_stmt          *stmt_head_upsert_signed;

    /* Read side: whether the sig columns exist in this database. Detected
     * at open from PRAGMA table_info; drives which SELECT is used and lets
     * the verifier grade signatures only where they can exist. A chain that
     * never enabled signing has these false and reads exactly as before. */
    bool                   entry_sig_cols;   /* chain_entries has chain_sig */
    bool                   head_sig_cols;    /* chain_heads has head_sig   */

    /* Verifier side (virp_chain_open_verifier_ex): the public key to check
     * chain/head signatures against, and whether one was supplied. No
     * secret material. */
    bool                   verify_sig_enabled;
    uint8_t                verify_pub[VIRP_CHAINSIGN_PK_SIZE];
    char                   verify_key_id_hex[VIRP_CHAINSIGN_KEYID_HEX];
    /* Transient, set by chain_verify_session_locked before it calls the
     * range walker and cleared after: this session IS signed but under a
     * key_id the verifier was not given, so per-entry signatures must be
     * SKIPPED (a soft whole-session outcome) rather than FAILED. Guarded by
     * the chain lock like every other verify field. */
    bool                   sig_key_unavailable_session;
    /* Verifier tier selection: whether K_chain was supplied (HMAC tier).
     * Keyless verification sets this false — hash+link+completeness only,
     * head length claim UNAUTHENTICATED. The writer path always has the
     * key and leaves this true. */
    bool                   have_chain_key;

    /* Set by virp_chain_open_verifier(): the connection is
     * SQLITE_OPEN_READONLY and every mutating entry point returns
     * VIRP_ERR_CHAIN_READONLY. */
    bool                read_only;
    /* Verifier-open only: the database predates the chain_heads table
     * (legacy shape). Chain length cannot be authenticated; sessions
     * report LEGACY_CHAIN / COMPLETENESS_UNPROVABLE instead of the DB
     * being migrated under the auditor. */
    bool                legacy_no_heads;

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
 * D-1: turn on detached Ed25519 chain signing for a chain opened with
 * virp_chain_init(). PURE ADDITION and OPT-IN: a daemon that never calls
 * this behaves exactly as pre-D-1 — signing off, on-disk schema untouched,
 * every hash/HMAC byte-identical. Rollback is simply not calling it.
 *
 * On success:
 *   - loads the per-node chain-signing SECRET key from sk_path (obskey
 *     custody gate: regular file, 0600/0400, owner==euid or root, 64 bytes);
 *   - adds the signature columns to chain_entries (chain_sig,
 *     chain_sig_key_id) and chain_heads (head_sig, head_sig_key_id) via
 *     ALTER TABLE ... ADD COLUMN IF the columns are absent — a metadata-only
 *     change on SQLite (no row rewrite), and NEVER touched when signing is
 *     off, so an opted-out database's schema is bit-for-bit the old one;
 *   - prepares the signing INSERT/head-upsert variants.
 *
 * From the next append on, every entry and head this node writes carries a
 * signature over the SAME canonical bytes already hashed and HMAC'd,
 * domain-separated by the VIRP-CHAIN-ENTRY-SIG-v1 / VIRP-CHAIN-HEAD-SIG-v1
 * tags. Old entries in the same database are left exactly as they are (no
 * migration, no backfill — per-session chains restart at 0, so a node born
 * dual-signed has no old entries in its new sessions).
 *
 * Refuses on a read-only handle (VIRP_ERR_CHAIN_READONLY) and on any key
 * or schema error (the caller must treat failure as fatal if it intended
 * to sign — never fall back to signing-off silently).
 */
virp_error_t virp_chain_enable_signing(virp_chain_state_t *state,
                                       const char *sk_path);

/*
 * Open an existing chain database for VERIFICATION ONLY.
 *
 * virp_chain_init() is the daemon's open: it creates schema, migrates
 * legacy shapes, sets WAL, and backfills trust-on-upgrade head records —
 * every one of which REWRITES the database. An offline verifier must
 * never do any of that: a verifier that manufactures the head record it
 * then checks has blessed the very length claim it exists to test.
 *
 * This open:
 *   - opens the file SQLITE_OPEN_READONLY (missing file is an error,
 *     never created) and additionally sets PRAGMA query_only=ON;
 *   - runs no schema ensure, no migration, no backfill;
 *   - requires chain_entries to exist (else VIRP_ERR_CHAIN_DB — not a
 *     chain database);
 *   - tolerates a legacy database with no chain_heads table: the handle
 *     opens, state->legacy_no_heads is set, and every session verifies
 *     as invalid with "LEGACY_CHAIN ... COMPLETENESS_UNPROVABLE" —
 *     reported, not migrated;
 *   - leaves a legacy UNIQUE(artifact_id) artifacts table untouched
 *     (noted on stderr; verification never reads artifacts).
 *
 * Every mutating chain call on this handle returns
 * VIRP_ERR_CHAIN_READONLY. Close with virp_chain_destroy() as usual.
 *
 * NOTE: a WAL-mode database whose -wal sidecar needs recovery cannot be
 * opened read-only by SQLite; the first query fails and this returns
 * VIRP_ERR_CHAIN_DB. That is fail-closed by design — verify a cleanly
 * copied database file.
 */
virp_error_t virp_chain_open_verifier(virp_chain_state_t *state,
                                      const char *db_path,
                                      const char *chain_key_path,
                                      uint32_t node_id,
                                      const char *org_id);

/*
 * D-1: open an existing chain database read-only for verification at one or
 * more of the three independent tiers. Same read-only, no-migration,
 * no-backfill discipline as virp_chain_open_verifier() (which is now a thin
 * wrapper: HMAC tier, no public key).
 *
 *   chain_key_path == NULL  -> KEYLESS tier: hash + link + completeness
 *                              only. No secret material is loaded. The
 *                              head's length claim is reported
 *                              UNAUTHENTICATED (head_authenticated=false)
 *                              unless a public key authenticates it.
 *   chain_key_path != NULL  -> SYMMETRIC tier: additionally verifies the
 *                              K_chain HMAC on every entry and the head.
 *   pubkey_path    != NULL  -> ASYMMETRIC tier: additionally verifies the
 *                              Ed25519 signature on every entry and the head
 *                              under the PUBLIC key (no secret needed). A
 *                              head-signed session whose signing key_id does
 *                              not match this key verifies at the other
 *                              tiers and is reported sig_key_unavailable
 *                              (a soft, whole-session outcome, never a FAIL).
 *
 * At least one of chain_key_path / pubkey_path SHOULD be given; passing
 * neither is the pure keyless tier and is allowed (the caller asked for it).
 * The tiers compose: e.g. key + pubkey verifies all three. The keyless and
 * HMAC results are byte-for-byte what the pre-D-1 verifier produced.
 */
virp_error_t virp_chain_open_verifier_ex(virp_chain_state_t *state,
                                         const char *db_path,
                                         const char *chain_key_path,
                                         const char *pubkey_path,
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
 * Set *exists to true iff a BODY with the given artifact_hash is stored
 * in the artifacts table — of ANY artifact_type. Distinct from
 * virp_chain_artifact_exists() above in both the table it reads and the
 * question it answers: that one asks whether an entry was appended, this
 * one whether the bytes it committed to were retained. NOT a commitment
 * check and no longer consulted by chain_append's fed_outcome gate (Sep
 * 1 review, Task 3): being type-blind, it let a fed_request body stand
 * in for the observation an outcome cited. GATE 4 asks
 * virp_chain_entry_commits_to() only. Retained for the atomicity fault-
 * injection test, which asks precisely the bytes-retained question.
 * Returns VIRP_OK on a successful query (whether or not it matched).
 */
virp_error_t virp_chain_artifact_body_exists(virp_chain_state_t *state,
                                             const char *artifact_hash,
                                             bool *exists);

/*
 * Set *exists to true iff a chain ENTRY of an observation type
 * ('observation'/'fed_observation') commits to the given artifact_hash —
 * i.e. the observation was appended, whether or not its body bytes were
 * retained. This is what the fed_outcome gate must ask about a citation:
 * an outcome naming a hash the chain committed to is BACKED even if the
 * body is not stored (an oversized, commitment-only observation). Distinct
 * from virp_chain_artifact_body_exists(), which asks whether the BYTES
 * were retained. Returns VIRP_OK on a successful query (matched or not).
 */
virp_error_t virp_chain_entry_commits_to(virp_chain_state_t *state,
                                         const char *artifact_hash,
                                         bool *exists);

/*
 * Set *conflict to true iff the artifacts table already holds a body
 * under the given artifact_id whose artifact_hash DIFFERS from the one
 * supplied; a byte-identical resubmission (same id, same hash) is NOT a
 * conflict. Reads only the artifacts table: a commitment-only append
 * stores no body row and so does not arm the gate. Returns VIRP_OK on a
 * successful query (whether or not it matched).
 *
 * READ-ONLY PROBE, NOT ENFORCEMENT (F4, 2026-08-17): an answer obtained
 * here is stale the moment the call returns — nothing stops a concurrent
 * append committing between this check and any act taken on it, which is
 * exactly what happened when GATE 5 relied on it. The enforcing copy of
 * this query runs INSIDE the append transaction (chain_append_locked),
 * where the answer and the act commit atomically. Both read chain_entries,
 * not artifacts: the chain is the authority on what a correlation id
 * committed to, so a commitment-only prior (no body row) is still seen.
 */
virp_error_t virp_chain_artifact_id_conflict(virp_chain_state_t *state,
                                             const char *artifact_id,
                                             const char *artifact_hash,
                                             bool *conflict);

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
 *
 * Storage is keyed by (artifact_id, artifact_hash) — the pair the chain
 * entry commits to — never by artifact_id alone. A colliding artifact_id
 * carrying DIFFERENT content stores a second row; nothing ever displaces
 * previously stored bytes (2026-08-03 production audit: a second-
 * resolution id collision under the old UNIQUE(artifact_id) + OR REPLACE
 * silently destroyed one observation's evidence). An identical
 * (artifact_id, artifact_hash) re-store is idempotent. Readers resolving
 * a chain entry to its body MUST join on both columns; an id-only lookup
 * can return a different entry's evidence.
 */
virp_error_t virp_chain_artifact_store(virp_chain_state_t *state,
                                        const char *artifact_id,
                                        const char *artifact_type,
                                        const char *artifact_content,
                                        const char *artifact_hash,
                                        const char *session_id);

#endif /* VIRP_CHAIN_H */
