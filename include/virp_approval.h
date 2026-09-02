/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Approval flow: propose → approve → apply
 *
 * A command the tier gate blocks under ENFORCE can be escalated to a
 * human instead of dying at the gate:
 *
 *   PROPOSE  — at block time the O-Node writes a proposal record
 *              (device, session, exact command, command_hash, proposer,
 *              timestamp, proposal_id) and registers a PROPOSAL entry
 *              on the trust chain. The command does not execute.
 *   APPROVE  — `virp approve <proposal-id>` (virp-tool) signs an
 *              approval record with a DEDICATED Ed25519 approval
 *              keypair (never the O-Key: the observer must not be able
 *              to approve its own escalations). The approval binds the
 *              proposal's command_hash, its device, and a 300-second
 *              TTL, and registers an APPROVAL chain entry.
 *   APPLY    — a re-submission of the same command carrying the
 *              proposal_id. The gate verifies, in order: approval
 *              signature, command_hash, device binding, TTL, and
 *              single-use (consumed via a persistent replay store —
 *              persist failure fails CLOSED, matching the seqstore
 *              contract from af92763). On pass the command executes and
 *              an OUTCOME chain entry links the PROPOSAL and APPROVAL
 *              entries. Each check failure has a distinct error code
 *              (VIRP_ERR_APPROVAL_* in virp.h).
 *
 * BLACK-tier commands are never proposable or approvable. The default
 * gate max tier is unchanged by this module.
 *
 * On-disk layout under the approval directory (default
 * /var/lib/virp/approvals):
 *   proposals/<id>.rec   line 1: proposal JSON
 *                        line 2: PROPOSAL chain entry hash (or "-")
 *   approvals/<id>.rec   line 1: approval JSON (the signed bytes)
 *                        line 2: Ed25519 signature, hex
 *                        line 3: APPROVAL chain entry hash (or "-")
 *   consumed.list        one consumed proposal_id per line; rewritten
 *                        via write-temp → fsync → rename
 *
 * Key management and rotation: docs/APPROVAL-FLOW.md.
 */

#ifndef VIRP_APPROVAL_H
#define VIRP_APPROVAL_H

#include "virp.h"
#include "virp_chain.h"
#include "virp_federation.h"
#include "virp_approver_registry.h"

#define VIRP_APPROVAL_TTL_SECONDS   300
#define VIRP_APPROVAL_ID_HEX_LEN    32      /* 16 random bytes, lowercase hex */
#define VIRP_APPROVAL_DIR_MAX       256

/*
 * Canonical approval payload — the exact bytes the approver signs.
 * Padding-free, network byte order, built by the daemon from its own
 * proposal record (never from client input). Layout:
 *   off  0  magic        "VAP1" (4 bytes)
 *   off  4  proposal_id  (16 bytes — the raw random id)
 *   off 20  command_hash (32 bytes — SHA-256 of the canonical command)
 *   off 52  device_id    (8 bytes, big-endian — device node_id)
 *   off 60  approved_at  (8 bytes, big-endian — ns since epoch)
 *   off 68  ttl_seconds  (4 bytes, big-endian)
 *   = 72 bytes
 */
#define VIRP_APPROVAL_CANON_SIZE    72
#define VIRP_APPROVAL_CANON_MAGIC   "VAP1"

typedef struct {
    char     proposal_id[VIRP_APPROVAL_ID_HEX_LEN + 1];
    char     session_id[64];
    char     device[64];
    uint32_t device_node_id;
    char     command[1024];
    char     command_hash[65];          /* SHA-256 hex of canonical command */
    char     proposer[64];
    uint64_t timestamp_ns;
    char     tier[16];                  /* classified tier name at block time */
    char     chain_entry_hash[65];      /* PROPOSAL chain entry ("" if none) */
} virp_proposal_rec_t;

typedef struct {
    char     proposal_id[VIRP_APPROVAL_ID_HEX_LEN + 1];
    char     command_hash[65];
    char     device[64];
    uint32_t device_node_id;
    uint64_t approved_at_ns;
    uint32_t ttl_seconds;
    char     approver_key_id[2 * VIRP_FED_KEYID_SIZE + 1];
    char     operator[64];              /* enrolled operator, "" if unknown */
    uint8_t  sig[VIRP_APPROVER_SIG_SIZE];  /* over the canonical payload */
    char     chain_entry_hash[65];      /* APPROVAL chain entry ("" if none) */
} virp_approval_rec_t;

/* Short slug for an approval error code ("approval_expired", ...);
 * "error" for anything that is not a VIRP_ERR_APPROVAL_* code. */
const char *virp_approval_err_name(virp_error_t err);

/*
 * PROPOSE. Generates a random proposal_id, writes the proposal record
 * under dir, and (when chain is non-NULL) appends a PROPOSAL chain
 * entry with artifact_id "proposal:<id>" for session
 * "approval:<device>". Fills *out.
 */
virp_error_t virp_approval_propose(const char *dir,
                                   virp_chain_state_t *chain,
                                   const char *session_id,
                                   const char *device,
                                   uint32_t device_node_id,
                                   const char *command,
                                   const char *typed_profile,
                                   const char *proposer,
                                   const char *tier_name,
                                   virp_proposal_rec_t *out);

/* Load a proposal record by id. VIRP_ERR_APPROVAL_NOT_FOUND if absent. */
virp_error_t virp_approval_load_proposal(const char *dir,
                                         const char *proposal_id,
                                         virp_proposal_rec_t *out);

/* Result of virp_approval_challenge() — the bytes to sign plus the
 * proposal summary fields a client shows the approver before signing. */
typedef struct {
    char     proposal_id[VIRP_APPROVAL_ID_HEX_LEN + 1];
    uint8_t  canonical[VIRP_APPROVAL_CANON_SIZE];
    char     device[64];
    char     command[1024];
    char     command_hash[65];
    char     tier[16];
    uint32_t device_node_id;
    uint64_t approved_at_ns;
    uint32_t ttl_seconds;
} virp_approval_challenge_t;

/*
 * Build the VIRP_APPROVAL_CANON_SIZE canonical payload from its fields.
 * proposal_id_hex (32 hex) and command_hash_hex (64 hex) are decoded to
 * raw bytes; device_id/approved_at/ttl are stamped big-endian. Exposed
 * so the daemon, the apply-side verifier, and tests all agree byte for
 * byte. Returns VIRP_OK or VIRP_ERR_INVALID_LENGTH on bad hex.
 */
virp_error_t virp_approval_build_canonical(const char *proposal_id_hex,
                                           const char *command_hash_hex,
                                           uint32_t device_node_id,
                                           uint64_t approved_at_ns,
                                           uint32_t ttl_seconds,
                                           uint8_t out[VIRP_APPROVAL_CANON_SIZE]);

/*
 * CHALLENGE. Builds the canonical payload to sign for proposal_id and
 * persists a pending-challenge record (so submit reconstructs the exact
 * bytes). Stamps approved_at = now_ns (0 = CLOCK_REALTIME) and
 * ttl = 300 s. Refuses with VIRP_ERR_APPROVAL_CONSUMED if the proposal
 * already has an OUTCOME chain entry (chain must be non-NULL for that
 * check; NULL skips it). VIRP_ERR_APPROVAL_NOT_FOUND if no such proposal.
 */
virp_error_t virp_approval_challenge(const char *dir,
                                     virp_chain_state_t *chain,
                                     const char *proposal_id,
                                     uint64_t now_ns,
                                     virp_approval_challenge_t *out);

/*
 * SUBMIT. Reconstructs the canonical bytes from the pending challenge,
 * verifies sig against the enrolled key_id in reg (unenrolled -> -43,
 * disabled -> -44, bad signature -> -40), then — as the SOLE chain
 * writer — appends the APPROVAL chain entry (carrying key_id + operator)
 * and writes the approval record apply will read. Refuses with
 * VIRP_ERR_APPROVAL_CONSUMED if an OUTCOME already exists. Fills *out.
 */
virp_error_t virp_approval_submit(const char *dir,
                                  const virp_approver_registry_t *reg,
                                  virp_chain_state_t *chain,
                                  const char *proposal_id,
                                  const char *key_id,
                                  const uint8_t *sig, size_t sig_len,
                                  virp_approval_rec_t *out);

/*
 * Test/administrative helper: write the approval record for
 * rec->proposal_id carrying sig (over the canonical bytes) and
 * rec->chain_entry_hash. virp_approval_submit() uses it internally;
 * negative-path tests use it to craft approvals with hostile bindings
 * (elapsed TTL, wrong hash/device) that still carry a valid signature
 * over their (hostile) canonical bytes.
 */
virp_error_t virp_approval_write_record(const char *dir,
                                        const virp_approval_rec_t *rec,
                                        const uint8_t *sig, size_t sig_len);

/*
 * APPLY-side verification. Runs the checks IN ORDER and returns the
 * first failure:
 *   1. key_id (from the record) enrolled in `reg`
 *        → VIRP_ERR_APPROVAL_KEY_UNENROLLED / _KEY_DISABLED
 *   2. signature over the approval bytes, verified with the enrolled
 *        key (dispatching on its algorithm)
 *        → VIRP_ERR_APPROVAL_BAD_SIGNATURE
 *   3. command_hash == SHA-256(canonical submitted command)
 *        → VIRP_ERR_APPROVAL_HASH_MISMATCH
 *   4. device + device_node_id binding
 *        → VIRP_ERR_APPROVAL_DEVICE_MISMATCH
 *   5. TTL unexpired at now_ns (0 = CLOCK_REALTIME)
 *        → VIRP_ERR_APPROVAL_EXPIRED
 *   6. single-use consume via consumed.list
 *        → VIRP_ERR_APPROVAL_REUSED; a failed persist of the consume
 *          record returns VIRP_ERR_CHAIN_DB and the approval is NOT
 *          treated as valid (fail closed).
 * A missing approval record returns VIRP_ERR_APPROVAL_NOT_FOUND.
 * On VIRP_OK the approval has been durably consumed and *out is filled.
 */
virp_error_t virp_approval_verify_consume(const char *dir,
                                          const virp_approver_registry_t *reg,
                                          const char *proposal_id,
                                          const char *device,
                                          uint32_t device_node_id,
                                          const char *command,
                                          const char *typed_profile,
                                          uint64_t now_ns,
                                          virp_approval_rec_t *out);

/*
 * Steps 1..5 of virp_approval_verify_consume WITHOUT step 6 (the durable
 * single-use consume). Same argument list, same error codes for the
 * checks it does run; on VIRP_OK *out is filled and NOTHING has been
 * consumed. Split out for evidence-required execution (Sep 1 review,
 * Task 5 / 1.1): the gate must verify an approval before it commits the
 * gate_intent entry, and CONSUME only after that entry is durable, so
 * that the invariant "an approval is consumed iff a committed gate_intent
 * names it" holds. A refused intent then consumes nothing.
 */
virp_error_t virp_approval_verify(const char *dir,
                                  const virp_approver_registry_t *reg,
                                  const char *proposal_id,
                                  const char *device,
                                  uint32_t device_node_id,
                                  const char *command,
                                  const char *typed_profile,
                                  uint64_t now_ns,
                                  virp_approval_rec_t *out);

/*
 * Step 6 alone: durably record proposal_id in consumed.list (temp-write,
 * fsync, rename). Returns VIRP_ERR_APPROVAL_REUSED if it was already
 * present, VIRP_OK on a fresh consume, non-OK on persist failure. The
 * consumed list is a CACHE — the authority on whether an approval was
 * spent is a committed gate_intent that names its approval entry hash
 * (see onode_execute_obs_ex). A persist failure here AFTER the intent
 * committed is therefore logged, not fatal: the chain already records
 * the consumption and the apply-time chain check will see it.
 */
virp_error_t virp_approval_commit_consume(const char *dir,
                                          const char *proposal_id);

/* Make the daemon's apply-time chain replay guard and the gate_intent
 * commit atomic against other consumers (Sep 1 review, Phase 1 item 1):
 * hold this lock across the guard query and the intent append, then commit
 * the consume with the _locked variant below before releasing. Nothing is
 * held across connect (get_connection precedes the guarded block). Lock
 * order: consume_lock -> chain lock (never the reverse).
 */
void virp_approval_consume_lock(void);
void virp_approval_consume_unlock(void);
virp_error_t virp_approval_commit_consume_locked(const char *dir,
                                                 const char *proposal_id);

#endif /* VIRP_APPROVAL_H */
