/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Message construction, parsing, and validation
 *
 * All message builders write into caller-provided buffers.
 * No dynamic memory allocation anywhere in this library.
 */

#ifndef VIRP_MESSAGE_H
#define VIRP_MESSAGE_H

#include "virp.h"
#include "virp_crypto.h"

/* =========================================================================
 * Header Operations
 * ========================================================================= */

/*
 * Initialize a VIRP header with common fields.
 * Sets version, type, channel, tier, node_id, and timestamps.
 * Caller must set length after adding payload.
 * Sequence number is auto-incremented from the node's counter.
 */
virp_error_t virp_header_init(virp_header_t *hdr,
                              uint8_t type,
                              uint8_t channel,
                              uint8_t tier,
                              uint32_t node_id,
                              uint32_t seq_num);

/*
 * Serialize a header to network byte order (big-endian).
 * Writes exactly VIRP_HEADER_SIZE bytes to buf.
 */
virp_error_t virp_header_serialize(const virp_header_t *hdr,
                                   uint8_t *buf, size_t buf_len);

/*
 * Deserialize a header from network byte order.
 * Reads exactly VIRP_HEADER_SIZE bytes from buf.
 */
virp_error_t virp_header_deserialize(virp_header_t *hdr,
                                     const uint8_t *buf, size_t buf_len);

/*
 * Validate a deserialized header.
 * Checks: version, type, channel, tier, reserved==0, length bounds.
 * Does NOT verify HMAC (use virp_verify for that).
 */
virp_error_t virp_header_validate(const virp_header_t *hdr);

/* =========================================================================
 * Observation Messages (OC only)
 * ========================================================================= */

/*
 * Build a complete OBSERVATION message.
 *
 * buf:       Output buffer (must be >= VIRP_HEADER_SIZE + 4 + data_len)
 * buf_len:   Size of output buffer
 * out_len:   Actual bytes written
 * node_id:   Originating node
 * seq_num:   Sequence number
 * obs_type:  VIRP_OBS_*
 * obs_scope: VIRP_SCOPE_*
 * data:      Observation data (e.g., raw device output)
 * data_len:  Length of observation data
 * sk:        O-Key for signing (must be VIRP_KEY_TYPE_OKEY)
 *
 * The message is signed before returning.
 */
virp_error_t virp_build_observation(uint8_t *buf, size_t buf_len,
                                    size_t *out_len,
                                    uint32_t node_id,
                                    uint32_t seq_num,
                                    uint8_t obs_type,
                                    uint8_t obs_scope,
                                    const uint8_t *data, uint16_t data_len,
                                    const virp_signing_key_t *sk);

/*
 * Parse an OBSERVATION message payload.
 * Header must already be deserialized and validated.
 *
 * payload:     Pointer to payload (after header)
 * payload_len: Length of payload
 * obs:         Output observation structure
 * data:        Output pointer to observation data within payload
 * data_len:    Output length of observation data
 */
virp_error_t virp_parse_observation(const uint8_t *payload, size_t payload_len,
                                    virp_observation_t *obs,
                                    const uint8_t **data, uint16_t *data_len);

/* =========================================================================
 * Proposal Messages (IC only)
 * ========================================================================= */

/*
 * Build a complete PROPOSAL message.
 *
 * The proposal includes references to supporting observations.
 * A proposal with zero observation references returns VIRP_ERR_NO_EVIDENCE.
 *
 * sk: Must be VIRP_KEY_TYPE_RKEY.
 */
virp_error_t virp_build_proposal(uint8_t *buf, size_t buf_len,
                                 size_t *out_len,
                                 uint32_t node_id,
                                 uint32_t seq_num,
                                 uint32_t proposal_id,
                                 uint8_t prop_type,
                                 uint16_t blast_radius,
                                 const virp_obs_ref_t *obs_refs,
                                 uint32_t obs_ref_count,
                                 const uint8_t *prop_data,
                                 uint16_t prop_data_len,
                                 const virp_signing_key_t *sk);

/*
 * Parse a PROPOSAL message payload.
 */
virp_error_t virp_parse_proposal(const uint8_t *payload, size_t payload_len,
                                 virp_proposal_t *prop,
                                 const virp_obs_ref_t **obs_refs,
                                 const uint8_t **prop_data,
                                 uint16_t *prop_data_len);

/* =========================================================================
 * Approval Messages (IC only)
 * ========================================================================= */

virp_error_t virp_build_approval(uint8_t *buf, size_t buf_len,
                                 size_t *out_len,
                                 uint32_t node_id,
                                 uint32_t seq_num,
                                 uint32_t proposal_id,
                                 uint32_t approver_node_id,
                                 uint8_t approval_type,
                                 uint8_t approver_class,
                                 const virp_signing_key_t *sk);

virp_error_t virp_parse_approval(const uint8_t *payload, size_t payload_len,
                                 virp_approval_t *approval);

/* =========================================================================
 * Intent Messages (IC only)
 * ========================================================================= */

virp_error_t virp_build_intent_advertise(uint8_t *buf, size_t buf_len,
                                         size_t *out_len,
                                         uint32_t node_id,
                                         uint32_t seq_num,
                                         uint32_t intent_id,
                                         uint8_t intent_type,
                                         uint8_t priority,
                                         uint16_t ttl_seconds,
                                         const virp_obs_ref_t *proofs,
                                         uint32_t proof_count,
                                         const uint8_t *intent_data,
                                         uint16_t intent_data_len,
                                         const virp_signing_key_t *sk);

virp_error_t virp_build_intent_withdraw(uint8_t *buf, size_t buf_len,
                                        size_t *out_len,
                                        uint32_t node_id,
                                        uint32_t seq_num,
                                        uint32_t intent_id,
                                        const virp_signing_key_t *sk);

/* =========================================================================
 * Heartbeat Messages (OC only)
 * ========================================================================= */

virp_error_t virp_build_heartbeat(uint8_t *buf, size_t buf_len,
                                  size_t *out_len,
                                  uint32_t node_id,
                                  uint32_t seq_num,
                                  uint32_t uptime_seconds,
                                  bool onode_ok,
                                  bool rnode_ok,
                                  uint16_t active_observations,
                                  uint32_t active_proposals,
                                  const virp_signing_key_t *sk);

virp_error_t virp_parse_heartbeat(const uint8_t *payload, size_t payload_len,
                                  virp_heartbeat_t *hb);

/* =========================================================================
 * Hello Messages (OC, during INIT)
 * ========================================================================= */

virp_error_t virp_build_hello(uint8_t *buf, size_t buf_len,
                              size_t *out_len,
                              uint32_t node_id,
                              uint32_t seq_num,
                              uint8_t node_type,
                              uint8_t max_tier,
                              const virp_signing_key_t *okey,
                              const virp_signing_key_t *rkey);

virp_error_t virp_parse_hello(const uint8_t *payload, size_t payload_len,
                              virp_hello_t *hello);

/* =========================================================================
 * Teardown Messages (Both channels)
 * ========================================================================= */

/*
 * Build a TEARDOWN message.
 * Can be sent on either channel. Reason is a human-readable string.
 */
virp_error_t virp_build_teardown(uint8_t *buf, size_t buf_len,
                                 size_t *out_len,
                                 uint32_t node_id,
                                 uint32_t seq_num,
                                 uint8_t channel,
                                 const char *reason,
                                 const virp_signing_key_t *sk);

/* =========================================================================
 * TLV Extension Field
 *
 * Type-Length-Value extensions allow future intent types, vendor-specific
 * data, and protocol evolution without revving the spec.
 * ========================================================================= */

#define VIRP_TLV_MAX_VALUE_SIZE  4096

/* Well-known TLV types */
#define VIRP_TLV_PADDING         0x0000  /* Ignored by parser */
#define VIRP_TLV_VENDOR          0x0001  /* Vendor-specific extension */
#define VIRP_TLV_GEOCODE         0x0002  /* Lat/lon of observation source */
#define VIRP_TLV_PREDICTION      0x0003  /* ML-based prediction data */
#define VIRP_TLV_TRACE_ID        0x0004  /* Distributed tracing correlation */
#define VIRP_TLV_TTL_OVERRIDE    0x0005  /* Per-observation TTL */

typedef struct __attribute__((packed)) {
    uint16_t    type;
    uint16_t    length;                     /* Length of value only */
    /* Variable-length value follows */
} virp_tlv_t;

/*
 * Append a TLV to a buffer at the given offset.
 * Returns the new offset after the TLV, or negative error.
 */
int virp_tlv_append(uint8_t *buf, size_t buf_len, size_t offset,
                    uint16_t type, const uint8_t *value, uint16_t value_len);

/*
 * Parse the next TLV from a buffer at the given offset.
 * Returns the offset after this TLV, or negative error.
 */
int virp_tlv_parse(const uint8_t *buf, size_t buf_len, size_t offset,
                   virp_tlv_t *tlv, const uint8_t **value);

/* =========================================================================
 * Generic Message Validation
 * ========================================================================= */

/*
 * Full message validation pipeline:
 *   1. Deserialize header
 *   2. Validate header fields
 *   3. Check channel-type consistency (OBS only on OC, PROPOSAL only on IC, etc)
 *   4. Verify HMAC signature
 *   5. Check tier is not BLACK
 *   6. Check reserved fields are zero
 *
 * This is the single entry point for incoming message validation.
 * If this returns VIRP_OK, the message is structurally sound and
 * authentically signed.
 */
virp_error_t virp_validate_message(const uint8_t *msg, size_t msg_len,
                                   const virp_signing_key_t *sk,
                                   virp_header_t *hdr_out);

/*
 * Check that a message type is valid for a given channel.
 * Enforces the structural separation:
 *   OC: OBSERVATION, HELLO, HEARTBEAT
 *   IC: PROPOSAL, APPROVAL, INTENT_ADV, INTENT_WD
 *   Both: TEARDOWN
 */
virp_error_t virp_check_channel_type(uint8_t channel, uint8_t type);

#endif /* VIRP_MESSAGE_H */
