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
    uint8_t  sig[VIRP_FED_SIG_SIZE];
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
                                   const char *proposer,
                                   const char *tier_name,
                                   virp_proposal_rec_t *out);

/* Load a proposal record by id. VIRP_ERR_APPROVAL_NOT_FOUND if absent. */
virp_error_t virp_approval_load_proposal(const char *dir,
                                         const char *proposal_id,
                                         virp_proposal_rec_t *out);

/*
 * APPROVE. Loads the proposal, binds {command_hash, device,
 * device_node_id, approved_at=now, ttl=300s}, signs with kp (Ed25519
 * approval keypair), writes the approval record, and (when chain is
 * non-NULL) appends an APPROVAL chain entry with artifact_id
 * "approval:<id>". Fills *out.
 */
virp_error_t virp_approval_approve(const char *dir,
                                   const virp_fed_keypair_t *kp,
                                   const char *proposal_id,
                                   virp_chain_state_t *chain,
                                   virp_approval_rec_t *out);

/*
 * Test/administrative helper: sign rec with kp and write it as the
 * approval record for rec->proposal_id. virp_approval_approve() uses
 * this internally; negative-path tests use it to craft approvals with
 * hostile bindings (elapsed TTL, wrong hash/device) that still carry a
 * valid signature.
 */
virp_error_t virp_approval_write_signed(const char *dir,
                                        const virp_fed_keypair_t *kp,
                                        virp_approval_rec_t *rec);

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
                                          uint64_t now_ns,
                                          virp_approval_rec_t *out);

#endif /* VIRP_APPROVAL_H */
