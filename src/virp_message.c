/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Message construction, parsing, and validation implementation
 *
 * Zero dynamic allocation. All fixed buffers. Deterministic execution.
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime */

#include "virp_message.h"
#include "virp_context.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>      /* snprintf — separator-policy reason strings */
#include <time.h>
#include <arpa/inet.h>  /* htons, htonl, ntohs, ntohl */

/* =========================================================================
 * 64-bit network byte order helpers (not in standard arpa/inet.h)
 * ========================================================================= */

static inline uint64_t htonll(uint64_t val)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl(val & 0xFFFFFFFF) << 32) | htonl(val >> 32);
#else
    return val;
#endif
}

static inline uint64_t ntohll(uint64_t val)
{
    return htonll(val); /* Symmetric operation */
}

/* =========================================================================
 * Nanosecond timestamp
 * ========================================================================= */

static uint64_t get_timestamp_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* =========================================================================
 * Header Operations
 * ========================================================================= */

virp_error_t virp_header_init(virp_header_t *hdr,
                              uint8_t type,
                              uint8_t channel,
                              uint8_t tier,
                              uint32_t node_id,
                              uint32_t seq_num)
{
    if (!hdr)
        return VIRP_ERR_NULL_PTR;

    /* BLACK tier must never be transmitted */
    if (tier == VIRP_TIER_BLACK)
        return VIRP_ERR_TIER_VIOLATION;

    memset(hdr, 0, sizeof(*hdr));
    hdr->version      = VIRP_VERSION;
    hdr->type         = type;
    hdr->length        = 0;  /* Caller sets after adding payload */
    hdr->node_id      = node_id;
    hdr->channel      = channel;
    hdr->tier         = tier;
    hdr->reserved     = 0;
    hdr->seq_num      = seq_num;
    hdr->timestamp_ns = get_timestamp_ns();

    return VIRP_OK;
}

virp_error_t virp_header_serialize(const virp_header_t *hdr,
                                   uint8_t *buf, size_t buf_len)
{
    if (!hdr || !buf)
        return VIRP_ERR_NULL_PTR;
    if (buf_len < VIRP_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    buf[0] = hdr->version;
    buf[1] = hdr->type;
    uint16_t len_n = htons(hdr->length);
    memcpy(buf + 2, &len_n, 2);
    uint32_t nid_n = htonl(hdr->node_id);
    memcpy(buf + 4, &nid_n, 4);
    buf[8] = hdr->channel;
    buf[9] = hdr->tier;
    buf[10] = 0; /* reserved */
    buf[11] = 0;
    uint32_t seq_n = htonl(hdr->seq_num);
    memcpy(buf + 12, &seq_n, 4);
    uint64_t ts_n = htonll(hdr->timestamp_ns);
    memcpy(buf + 16, &ts_n, 8);
    memcpy(buf + 24, hdr->hmac, VIRP_HMAC_SIZE);

    return VIRP_OK;
}

virp_error_t virp_header_deserialize(virp_header_t *hdr,
                                     const uint8_t *buf, size_t buf_len)
{
    if (!hdr || !buf)
        return VIRP_ERR_NULL_PTR;
    if (buf_len < VIRP_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    hdr->version = buf[0];
    hdr->type = buf[1];
    uint16_t len_n;
    memcpy(&len_n, buf + 2, 2);
    hdr->length = ntohs(len_n);
    uint32_t nid_n;
    memcpy(&nid_n, buf + 4, 4);
    hdr->node_id = ntohl(nid_n);
    hdr->channel = buf[8];
    hdr->tier = buf[9];
    hdr->reserved = (uint16_t)buf[10] << 8 | buf[11];
    uint32_t seq_n;
    memcpy(&seq_n, buf + 12, 4);
    hdr->seq_num = ntohl(seq_n);
    uint64_t ts_n;
    memcpy(&ts_n, buf + 16, 8);
    hdr->timestamp_ns = ntohll(ts_n);
    memcpy(hdr->hmac, buf + 24, VIRP_HMAC_SIZE);

    return VIRP_OK;
}

virp_error_t virp_obs_header_v2_serialize(const virp_obs_header_v2_t *hdr,
                                          uint8_t *buf, size_t buf_len)
{
    if (!hdr || !buf)
        return VIRP_ERR_NULL_PTR;
    if (buf_len < VIRP_OBS_V2_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;
    if (hdr->_reserved != 0)
        return VIRP_ERR_RESERVED_NONZERO;

    buf[0] = hdr->version;
    buf[1] = hdr->channel;
    buf[2] = hdr->tier;
    buf[3] = 0;                              /* reserved */
    uint64_t nid_n = htonll(hdr->node_id);
    memcpy(buf + 4, &nid_n, 8);
    uint64_t ts_n = htonll(hdr->timestamp_ns);
    memcpy(buf + 12, &ts_n, 8);
    uint64_t seq_n = htonll(hdr->seq_num);
    memcpy(buf + 20, &seq_n, 8);
    memcpy(buf + 28, hdr->session_id, 16);
    uint64_t did_n = htonll(hdr->device_id);
    memcpy(buf + 44, &did_n, 8);
    memcpy(buf + 52, hdr->command_hash, 32);
    uint32_t pl_n = htonl(hdr->payload_len);
    memcpy(buf + 84, &pl_n, 4);

    return VIRP_OK;
}

virp_error_t virp_obs_header_v2_deserialize(virp_obs_header_v2_t *hdr,
                                            const uint8_t *buf, size_t buf_len)
{
    if (!hdr || !buf)
        return VIRP_ERR_NULL_PTR;
    if (buf_len < VIRP_OBS_V2_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    memset(hdr, 0, sizeof(*hdr));
    hdr->version   = buf[0];
    hdr->channel   = buf[1];
    hdr->tier      = buf[2];
    hdr->_reserved = buf[3];
    uint64_t nid_n;
    memcpy(&nid_n, buf + 4, 8);
    hdr->node_id = ntohll(nid_n);
    uint64_t ts_n;
    memcpy(&ts_n, buf + 12, 8);
    hdr->timestamp_ns = ntohll(ts_n);
    uint64_t seq_n;
    memcpy(&seq_n, buf + 20, 8);
    hdr->seq_num = ntohll(seq_n);
    memcpy(hdr->session_id, buf + 28, 16);
    uint64_t did_n;
    memcpy(&did_n, buf + 44, 8);
    hdr->device_id = ntohll(did_n);
    memcpy(hdr->command_hash, buf + 52, 32);
    uint32_t pl_n;
    memcpy(&pl_n, buf + 84, 4);
    hdr->payload_len = ntohl(pl_n);

    return VIRP_OK;
}

virp_error_t virp_header_validate(const virp_header_t *hdr)
{
    if (!hdr)
        return VIRP_ERR_NULL_PTR;

    if (hdr->version != VIRP_VERSION)
        return VIRP_ERR_INVALID_VERSION;

    /* Validate message type */
    switch (hdr->type) {
    case VIRP_MSG_OBSERVATION:
    case VIRP_MSG_HELLO:
    case VIRP_MSG_PROPOSAL:
    case VIRP_MSG_APPROVAL:
    case VIRP_MSG_INTENT_ADV:
    case VIRP_MSG_INTENT_WD:
    case VIRP_MSG_HEARTBEAT:
    case VIRP_MSG_TEARDOWN:
        break;
    default:
        return VIRP_ERR_INVALID_TYPE;
    }

    /* Validate channel */
    if (hdr->channel != VIRP_CHANNEL_OC && hdr->channel != VIRP_CHANNEL_IC)
        return VIRP_ERR_INVALID_CHANNEL;

    /* BLACK tier must never appear on the wire */
    if (hdr->tier == VIRP_TIER_BLACK)
        return VIRP_ERR_TIER_VIOLATION;

    /* Validate tier range */
    if (hdr->tier > VIRP_TIER_RED)
        return VIRP_ERR_INVALID_TIER;

    /* Reserved must be zero */
    if (hdr->reserved != 0)
        return VIRP_ERR_RESERVED_NONZERO;

    /* Length must at least cover the header */
    if (hdr->length < VIRP_HEADER_SIZE)
        return VIRP_ERR_INVALID_LENGTH;

    return VIRP_OK;
}

/* =========================================================================
 * Channel-Type Consistency
 * ========================================================================= */

virp_error_t virp_check_channel_type(uint8_t channel, uint8_t type)
{
    switch (type) {
    /* OC only */
    case VIRP_MSG_OBSERVATION:
    case VIRP_MSG_HELLO:
    case VIRP_MSG_HEARTBEAT:
        if (channel != VIRP_CHANNEL_OC)
            return VIRP_ERR_CHANNEL_VIOLATION;
        break;

    /* IC only */
    case VIRP_MSG_PROPOSAL:
    case VIRP_MSG_APPROVAL:
    case VIRP_MSG_INTENT_ADV:
    case VIRP_MSG_INTENT_WD:
        if (channel != VIRP_CHANNEL_IC)
            return VIRP_ERR_CHANNEL_VIOLATION;
        break;

    /* Both channels */
    case VIRP_MSG_TEARDOWN:
        break;

    default:
        return VIRP_ERR_INVALID_TYPE;
    }

    return VIRP_OK;
}

/* =========================================================================
 * Full Message Validation
 * ========================================================================= */

virp_error_t virp_validate_message(const uint8_t *msg, size_t msg_len,
                                   const virp_signing_key_t *sk,
                                   virp_header_t *hdr_out)
{
    if (!msg || !sk || !hdr_out)
        return VIRP_ERR_NULL_PTR;

    if (msg_len < VIRP_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    /* Step 1: Deserialize header */
    virp_error_t err = virp_header_deserialize(hdr_out, msg, msg_len);
    if (err != VIRP_OK) return err;

    /* Step 2: Validate header fields */
    err = virp_header_validate(hdr_out);
    if (err != VIRP_OK) return err;

    /* Step 3: Check channel-type consistency */
    err = virp_check_channel_type(hdr_out->channel, hdr_out->type);
    if (err != VIRP_OK) return err;

    /* Step 4: Check message length matches buffer */
    if (hdr_out->length > msg_len)
        return VIRP_ERR_INVALID_LENGTH;

    /*
     * Step 5: Verify HMAC signature.
     *
     * v1 virp_verify() does not touch any session state — it HMACs the
     * message against the supplied key. It takes a virp_context_t
     * parameter for signature symmetry with v2 signing, but ignores
     * it. Passing NULL here keeps the message-builder API free of a
     * ctx parameter it would only forward and never use.
     */
    err = virp_verify(NULL, msg, hdr_out->length, sk);
    if (err != VIRP_OK) return err;

    return VIRP_OK;
}

/* =========================================================================
 * Internal: build a complete message (header + payload), sign it
 * ========================================================================= */

static virp_error_t build_and_sign(uint8_t *buf, size_t buf_len,
                                   size_t *out_len,
                                   uint8_t type,
                                   uint8_t channel,
                                   uint8_t tier,
                                   uint32_t node_id,
                                   uint32_t seq_num,
                                   const uint8_t *payload,
                                   size_t payload_len,
                                   const virp_signing_key_t *sk)
{
    size_t total = VIRP_HEADER_SIZE + payload_len;

    if (total > VIRP_MAX_MESSAGE_SIZE)
        return VIRP_ERR_MESSAGE_TOO_LARGE;
    if (buf_len < total)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    /* Build header */
    virp_header_t hdr;
    virp_error_t err = virp_header_init(&hdr, type, channel, tier,
                                        node_id, seq_num);
    if (err != VIRP_OK) return err;

    hdr.length = (uint16_t)total;

    /* Serialize header into buffer */
    err = virp_header_serialize(&hdr, buf, buf_len);
    if (err != VIRP_OK) return err;

    /* Copy payload */
    if (payload_len > 0 && payload)
        memcpy(buf + VIRP_HEADER_SIZE, payload, payload_len);

    /*
     * Sign the complete message. v1 virp_sign() is pure HMAC over the
     * supplied key and does not read session state; ctx is unused,
     * so pass NULL rather than threading a context through every
     * build_observation / build_proposal / build_approval caller.
     */
    err = virp_sign(NULL, buf, total, sk);
    if (err != VIRP_OK) return err;

    *out_len = total;
    return VIRP_OK;
}

/* =========================================================================
 * Observation Messages
 * ========================================================================= */

virp_error_t virp_build_observation_tiered(uint8_t *buf, size_t buf_len,
                                    size_t *out_len,
                                    uint32_t node_id,
                                    uint32_t seq_num,
                                    uint8_t obs_type,
                                    uint8_t obs_scope,
                                    uint8_t tier,
                                    const uint8_t *data, uint16_t data_len,
                                    const virp_signing_key_t *sk)
{
    if (!buf || !out_len || !sk)
        return VIRP_ERR_NULL_PTR;

    /* Build observation payload — cap data to max payload capacity */
    uint8_t payload[4 + VIRP_MAX_PAYLOAD_SIZE];
    if (data_len > VIRP_MAX_PAYLOAD_SIZE - 4)
        data_len = (uint16_t)(VIRP_MAX_PAYLOAD_SIZE - 4);
    payload[0] = obs_type;
    payload[1] = obs_scope;
    uint16_t dl_n = htons(data_len);
    memcpy(payload + 2, &dl_n, 2);

    size_t payload_len = 4;
    if (data && data_len > 0) {
        memcpy(payload + 4, data, data_len);
        payload_len += data_len;
    }

    return build_and_sign(buf, buf_len, out_len,
                          VIRP_MSG_OBSERVATION, VIRP_CHANNEL_OC,
                          tier,
                          node_id, seq_num,
                          payload, payload_len, sk);
}

virp_error_t virp_build_observation(uint8_t *buf, size_t buf_len,
                                    size_t *out_len,
                                    uint32_t node_id,
                                    uint32_t seq_num,
                                    uint8_t obs_type,
                                    uint8_t obs_scope,
                                    const uint8_t *data, uint16_t data_len,
                                    const virp_signing_key_t *sk)
{
    /* Backward-compatible default: GREEN. Callers that carry a real,
     * gate-classified trust tier (the O-Node command-execution path) use
     * virp_build_observation_tiered() so the observation reflects the
     * command's actual sensitivity instead of a blanket GREEN. */
    return virp_build_observation_tiered(buf, buf_len, out_len, node_id,
                                         seq_num, obs_type, obs_scope,
                                         VIRP_TIER_GREEN, data, data_len, sk);
}

virp_error_t virp_parse_observation(const uint8_t *payload, size_t payload_len,
                                    virp_observation_t *obs,
                                    const uint8_t **data, uint16_t *data_len)
{
    if (!payload || !obs)
        return VIRP_ERR_NULL_PTR;
    if (payload_len < 4)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    obs->obs_type = payload[0];
    obs->obs_scope = payload[1];
    uint16_t dl_n;
    memcpy(&dl_n, payload + 2, 2);
    obs->obs_length = ntohs(dl_n);

    /*
     * Bound the embedded length by the buffer that actually arrived.
     * obs_length comes off the wire; before this check a malformed
     * observation could claim more data than the payload carries and
     * every caller trusting *data_len (hex_dump, printf %.*s, memcpy)
     * read past the buffer.
     *
     * <= rather than ==: spec §9 (draft-howard-virp-03) says the data
     * length field "specifies the exact number of bytes of device
     * output that follow" precisely so parsers can "distinguish between
     * device output and any future trailer fields" — trailing bytes
     * after the data are an anticipated extension point, so they are
     * tolerated here. The Python evidence layer
     * (virp_bridge.parse_observation) additionally enforces exact
     * equality for v1 evidence, where no trailer is defined; that
     * stricter app-layer check is unchanged.
     */
    if ((size_t)obs->obs_length > payload_len - 4)
        return VIRP_ERR_INVALID_LENGTH;

    if (data) *data = (obs->obs_length > 0) ? payload + 4 : NULL;
    if (data_len) *data_len = obs->obs_length;

    return VIRP_OK;
}

/* =========================================================================
 * Proposal Messages
 * ========================================================================= */

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
                                 const virp_signing_key_t *sk)
{
    if (!buf || !out_len || !sk)
        return VIRP_ERR_NULL_PTR;

    /* Proposals MUST have evidence */
    if (obs_ref_count == 0)
        return VIRP_ERR_NO_EVIDENCE;

    if (obs_ref_count > VIRP_MAX_OBS_REFS)
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    /* Build proposal payload */
    uint8_t payload[VIRP_MAX_PAYLOAD_SIZE];
    size_t offset = 0;

    /* Proposal header: id(4) + type(1) + state(1) + blast(2) + refcount(4) = 12 */
    uint32_t pid_n = htonl(proposal_id);
    memcpy(payload + offset, &pid_n, 4); offset += 4;
    payload[offset++] = prop_type;
    payload[offset++] = VIRP_PSTATE_PROPOSED;
    uint16_t br_n = htons(blast_radius);
    memcpy(payload + offset, &br_n, 2); offset += 2;
    uint32_t orc_n = htonl(obs_ref_count);
    memcpy(payload + offset, &orc_n, 4); offset += 4;

    /* Observation references */
    for (uint32_t i = 0; i < obs_ref_count; i++) {
        uint32_t ref_nid = htonl(obs_refs[i].node_id);
        uint32_t ref_seq = htonl(obs_refs[i].seq_num);
        memcpy(payload + offset, &ref_nid, 4); offset += 4;
        memcpy(payload + offset, &ref_seq, 4); offset += 4;
    }

    /* Proposal data */
    if (prop_data && prop_data_len > 0) {
        memcpy(payload + offset, prop_data, prop_data_len);
        offset += prop_data_len;
    }

    /* Proposals default to YELLOW tier (require approval) */
    return build_and_sign(buf, buf_len, out_len,
                          VIRP_MSG_PROPOSAL, VIRP_CHANNEL_IC,
                          VIRP_TIER_YELLOW,
                          node_id, seq_num,
                          payload, offset, sk);
}

virp_error_t virp_parse_proposal(const uint8_t *payload, size_t payload_len,
                                 virp_proposal_t *prop,
                                 const virp_obs_ref_t **obs_refs,
                                 const uint8_t **prop_data,
                                 uint16_t *prop_data_len)
{
    if (!payload || !prop)
        return VIRP_ERR_NULL_PTR;
    if (payload_len < 12)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    uint32_t pid_n;
    memcpy(&pid_n, payload, 4);
    prop->proposal_id = ntohl(pid_n);
    prop->prop_type = payload[4];
    prop->prop_state = payload[5];
    uint16_t br_n;
    memcpy(&br_n, payload + 6, 2);
    prop->blast_radius = ntohs(br_n);
    uint32_t orc_n;
    memcpy(&orc_n, payload + 8, 4);
    prop->obs_ref_count = ntohl(orc_n);

    /*
     * obs_ref_count comes off the wire. Mirror the builder's contract
     * before handing out a refs pointer: proposals MUST carry evidence
     * (count 0 never leaves virp_build_proposal), the count is capped
     * at VIRP_MAX_OBS_REFS, and the refs array must physically fit in
     * the payload — otherwise a 12-byte payload claiming 2^32-1 refs
     * hands the caller a pointer it will walk far out of bounds.
     */
    if (prop->obs_ref_count == 0)
        return VIRP_ERR_NO_EVIDENCE;
    if (prop->obs_ref_count > VIRP_MAX_OBS_REFS)
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    size_t refs_size = prop->obs_ref_count * sizeof(virp_obs_ref_t);
    size_t refs_offset = 12;

    if (refs_size > payload_len - refs_offset)
        return VIRP_ERR_INVALID_LENGTH;

    if (obs_refs)
        *obs_refs = (const virp_obs_ref_t *)(payload + refs_offset);

    size_t data_offset = refs_offset + refs_size;
    if (prop_data) {
        *prop_data = (data_offset < payload_len) ? payload + data_offset : NULL;
    }
    if (prop_data_len) {
        *prop_data_len = (data_offset < payload_len) ?
                         (uint16_t)(payload_len - data_offset) : 0;
    }

    return VIRP_OK;
}

/* =========================================================================
 * Approval Messages
 * ========================================================================= */

virp_error_t virp_build_approval(uint8_t *buf, size_t buf_len,
                                 size_t *out_len,
                                 uint32_t node_id,
                                 uint32_t seq_num,
                                 uint32_t proposal_id,
                                 uint32_t approver_node_id,
                                 uint8_t approval_type,
                                 uint8_t approver_class,
                                 const virp_signing_key_t *sk)
{
    if (!buf || !out_len || !sk)
        return VIRP_ERR_NULL_PTR;

    uint8_t payload[12];
    uint32_t pid_n = htonl(proposal_id);
    memcpy(payload, &pid_n, 4);
    uint32_t anid_n = htonl(approver_node_id);
    memcpy(payload + 4, &anid_n, 4);
    payload[8] = approval_type;
    payload[9] = approver_class;
    payload[10] = 0;
    payload[11] = 0;

    return build_and_sign(buf, buf_len, out_len,
                          VIRP_MSG_APPROVAL, VIRP_CHANNEL_IC,
                          VIRP_TIER_YELLOW,
                          node_id, seq_num,
                          payload, 12, sk);
}

virp_error_t virp_parse_approval(const uint8_t *payload, size_t payload_len,
                                 virp_approval_t *approval)
{
    if (!payload || !approval)
        return VIRP_ERR_NULL_PTR;
    if (payload_len < 12)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    uint32_t pid_n;
    memcpy(&pid_n, payload, 4);
    approval->proposal_id = ntohl(pid_n);
    uint32_t anid_n;
    memcpy(&anid_n, payload + 4, 4);
    approval->approver_node_id = ntohl(anid_n);
    approval->approval_type = payload[8];
    approval->approver_class = payload[9];
    approval->reserved = 0;

    return VIRP_OK;
}

/* =========================================================================
 * Intent Messages
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
                                         const virp_signing_key_t *sk)
{
    if (!buf || !out_len || !sk)
        return VIRP_ERR_NULL_PTR;

    uint8_t payload[VIRP_MAX_PAYLOAD_SIZE];
    size_t offset = 0;

    uint32_t iid_n = htonl(intent_id);
    memcpy(payload + offset, &iid_n, 4); offset += 4;
    payload[offset++] = intent_type;
    payload[offset++] = priority;
    uint16_t ttl_n = htons(ttl_seconds);
    memcpy(payload + offset, &ttl_n, 2); offset += 2;
    uint32_t pc_n = htonl(proof_count);
    memcpy(payload + offset, &pc_n, 4); offset += 4;

    for (uint32_t i = 0; i < proof_count; i++) {
        uint32_t ref_nid = htonl(proofs[i].node_id);
        uint32_t ref_seq = htonl(proofs[i].seq_num);
        memcpy(payload + offset, &ref_nid, 4); offset += 4;
        memcpy(payload + offset, &ref_seq, 4); offset += 4;
    }

    if (intent_data && intent_data_len > 0) {
        memcpy(payload + offset, intent_data, intent_data_len);
        offset += intent_data_len;
    }

    return build_and_sign(buf, buf_len, out_len,
                          VIRP_MSG_INTENT_ADV, VIRP_CHANNEL_IC,
                          VIRP_TIER_YELLOW,
                          node_id, seq_num,
                          payload, offset, sk);
}

virp_error_t virp_build_intent_withdraw(uint8_t *buf, size_t buf_len,
                                        size_t *out_len,
                                        uint32_t node_id,
                                        uint32_t seq_num,
                                        uint32_t intent_id,
                                        const virp_signing_key_t *sk)
{
    if (!buf || !out_len || !sk)
        return VIRP_ERR_NULL_PTR;

    uint8_t payload[4];
    uint32_t iid_n = htonl(intent_id);
    memcpy(payload, &iid_n, 4);

    return build_and_sign(buf, buf_len, out_len,
                          VIRP_MSG_INTENT_WD, VIRP_CHANNEL_IC,
                          VIRP_TIER_YELLOW,
                          node_id, seq_num,
                          payload, 4, sk);
}

/* =========================================================================
 * Heartbeat Messages
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
                                  const virp_signing_key_t *sk)
{
    if (!buf || !out_len || !sk)
        return VIRP_ERR_NULL_PTR;

    uint8_t payload[12];
    uint32_t ut_n = htonl(uptime_seconds);
    memcpy(payload, &ut_n, 4);
    payload[4] = onode_ok ? 1 : 0;
    payload[5] = rnode_ok ? 1 : 0;
    uint16_t ao_n = htons(active_observations);
    memcpy(payload + 6, &ao_n, 2);
    uint32_t ap_n = htonl(active_proposals);
    memcpy(payload + 8, &ap_n, 4);

    return build_and_sign(buf, buf_len, out_len,
                          VIRP_MSG_HEARTBEAT, VIRP_CHANNEL_OC,
                          VIRP_TIER_GREEN,
                          node_id, seq_num,
                          payload, 12, sk);
}

virp_error_t virp_parse_heartbeat(const uint8_t *payload, size_t payload_len,
                                  virp_heartbeat_t *hb)
{
    if (!payload || !hb)
        return VIRP_ERR_NULL_PTR;
    if (payload_len < 12)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    uint32_t ut_n;
    memcpy(&ut_n, payload, 4);
    hb->uptime_seconds = ntohl(ut_n);
    hb->onode_ok = payload[4];
    hb->rnode_ok = payload[5];
    uint16_t ao_n;
    memcpy(&ao_n, payload + 6, 2);
    hb->active_observations = ntohs(ao_n);
    uint32_t ap_n;
    memcpy(&ap_n, payload + 8, 4);
    hb->active_proposals = ntohl(ap_n);

    return VIRP_OK;
}

/* =========================================================================
 * Hello Messages
 * ========================================================================= */

virp_error_t virp_build_hello(uint8_t *buf, size_t buf_len,
                              size_t *out_len,
                              uint32_t node_id,
                              uint32_t seq_num,
                              uint8_t node_type,
                              uint8_t max_tier,
                              const virp_signing_key_t *okey,
                              const virp_signing_key_t *rkey)
{
    if (!buf || !out_len || !okey)
        return VIRP_ERR_NULL_PTR;

    uint8_t payload[sizeof(virp_hello_t)];
    size_t offset = 0;

    uint32_t magic_n = htonl(VIRP_MAGIC);
    memcpy(payload + offset, &magic_n, 4); offset += 4;
    payload[offset++] = VIRP_VERSION;
    payload[offset++] = node_type;
    payload[offset++] = max_tier;
    payload[offset++] = 0; /* reserved */
    uint32_t nid_n = htonl(node_id);
    memcpy(payload + offset, &nid_n, 4); offset += 4;

    /* O-Key fingerprint */
    memcpy(payload + offset, okey->fingerprint, VIRP_HMAC_SIZE);
    offset += VIRP_HMAC_SIZE;

    /* R-Key fingerprint (zero if not present) */
    if (rkey && rkey->key.loaded) {
        memcpy(payload + offset, rkey->fingerprint, VIRP_HMAC_SIZE);
    } else {
        memset(payload + offset, 0, VIRP_HMAC_SIZE);
    }
    offset += VIRP_HMAC_SIZE;

    return build_and_sign(buf, buf_len, out_len,
                          VIRP_MSG_HELLO, VIRP_CHANNEL_OC,
                          VIRP_TIER_GREEN,
                          node_id, seq_num,
                          payload, offset, okey);
}

virp_error_t virp_parse_hello(const uint8_t *payload, size_t payload_len,
                              virp_hello_t *hello)
{
    if (!payload || !hello)
        return VIRP_ERR_NULL_PTR;
    if (payload_len < sizeof(virp_hello_t))
        return VIRP_ERR_BUFFER_TOO_SMALL;

    size_t offset = 0;
    uint32_t magic_n;
    memcpy(&magic_n, payload + offset, 4); offset += 4;
    hello->magic = ntohl(magic_n);
    hello->version = payload[offset++];
    hello->node_type = payload[offset++];
    hello->max_tier = payload[offset++];
    hello->reserved = payload[offset++];
    uint32_t nid_n;
    memcpy(&nid_n, payload + offset, 4); offset += 4;
    hello->node_id = ntohl(nid_n);
    memcpy(hello->okey_fingerprint, payload + offset, VIRP_HMAC_SIZE);
    offset += VIRP_HMAC_SIZE;
    memcpy(hello->rkey_fingerprint, payload + offset, VIRP_HMAC_SIZE);

    return VIRP_OK;
}

/* =========================================================================
 * Teardown Messages
 * ========================================================================= */

virp_error_t virp_build_teardown(uint8_t *buf, size_t buf_len,
                                 size_t *out_len,
                                 uint32_t node_id,
                                 uint32_t seq_num,
                                 uint8_t channel,
                                 const char *reason,
                                 const virp_signing_key_t *sk)
{
    if (!buf || !out_len || !sk)
        return VIRP_ERR_NULL_PTR;

    uint8_t payload[256];
    size_t reason_len = 0;

    if (reason) {
        reason_len = strlen(reason);
        if (reason_len > 252)
            reason_len = 252;  /* Cap reason string */
    }

    /* Reason length (2 bytes) + reason string */
    uint16_t rl_n = htons((uint16_t)reason_len);
    memcpy(payload, &rl_n, 2);
    if (reason_len > 0)
        memcpy(payload + 2, reason, reason_len);

    return build_and_sign(buf, buf_len, out_len,
                          VIRP_MSG_TEARDOWN, channel,
                          VIRP_TIER_GREEN,
                          node_id, seq_num,
                          payload, 2 + reason_len, sk);
}

/* =========================================================================
 * TLV Extension Field
 * ========================================================================= */

int virp_tlv_append(uint8_t *buf, size_t buf_len, size_t offset,
                    uint16_t type, const uint8_t *value, uint16_t value_len)
{
    if (!buf) return VIRP_ERR_NULL_PTR;

    size_t needed = offset + 4 + value_len;  /* type(2) + length(2) + value */
    if (needed > buf_len) return VIRP_ERR_BUFFER_TOO_SMALL;
    if (value_len > VIRP_TLV_MAX_VALUE_SIZE) return VIRP_ERR_MESSAGE_TOO_LARGE;

    uint16_t type_n = htons(type);
    uint16_t len_n = htons(value_len);
    memcpy(buf + offset, &type_n, 2);
    memcpy(buf + offset + 2, &len_n, 2);
    if (value && value_len > 0)
        memcpy(buf + offset + 4, value, value_len);

    return (int)(offset + 4 + value_len);
}

int virp_tlv_parse(const uint8_t *buf, size_t buf_len, size_t offset,
                   virp_tlv_t *tlv, const uint8_t **value)
{
    if (!buf || !tlv) return VIRP_ERR_NULL_PTR;
    if (offset + 4 > buf_len) return VIRP_ERR_BUFFER_TOO_SMALL;

    uint16_t type_n, len_n;
    memcpy(&type_n, buf + offset, 2);
    memcpy(&len_n, buf + offset + 2, 2);
    tlv->type = ntohs(type_n);
    tlv->length = ntohs(len_n);

    if (offset + 4 + tlv->length > buf_len)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    if (value)
        *value = (tlv->length > 0) ? buf + offset + 4 : NULL;

    return (int)(offset + 4 + tlv->length);
}

/* =========================================================================
 * V2 Command Canonicalization
 * ========================================================================= */

int virp_canonicalize_command(const char *cmd, char *out, size_t out_len)
{
    if (!cmd || !out || out_len == 0) return -1;

    size_t in_len = strlen(cmd);
    size_t i = 0, j = 0;

    /* skip leading whitespace */
    while (i < in_len && (cmd[i] == ' ' || cmd[i] == '\t' ||
                           cmd[i] == '\r' || cmd[i] == '\n')) {
        i++;
    }

    int last_was_space = 0;
    while (i < in_len) {
        char c = cmd[i++];

        /* strip carriage returns */
        if (c == '\r') continue;

        /* collapse spaces and tabs */
        if (c == ' ' || c == '\t') {
            if (!last_was_space && j > 0) {
                if (j >= out_len - 1) return -1;
                out[j++] = ' ';
                last_was_space = 1;
            }
            continue;
        }

        last_was_space = 0;
        if (j >= out_len - 1) return -1;
        out[j++] = c;
    }

    /* strip trailing space if any */
    while (j > 0 && out[j-1] == ' ') j--;

    out[j] = '\0';
    return (int)j;
}

/* =========================================================================
 * Command Separator Policy (see virp.h for rationale)
 * ========================================================================= */

int virp_command_check_separators(const char *cmd, char *why, size_t why_len)
{
    if (why && why_len) why[0] = '\0';
    if (!cmd) return -1;

    const unsigned char *base = (const unsigned char *)cmd;
    for (const unsigned char *p = base; *p; p++) {
        char rendered[8];
        const char *what = NULL;

        if (*p < 0x20 || *p == 0x7F) {
            /* Control byte — render escaped, never raw. */
            snprintf(rendered, sizeof(rendered), "\\x%02x", (unsigned)*p);
            what = rendered;
        } else if (*p == ';' || *p == '|' || *p == '&' || *p == '`') {
            rendered[0] = (char)*p;
            rendered[1] = '\0';
            what = rendered;
        } else if (*p == '$' && (*(p + 1) == '(' || *(p + 1) == '{')) {
            snprintf(rendered, sizeof(rendered), "$%c", (char)*(p + 1));
            what = rendered;
        }

        if (what) {
            if (why && why_len)
                snprintf(why, why_len,
                         "illegal separator '%s' at offset %zu",
                         what, (size_t)(p - base));
            return -1;
        }
    }
    return 0;
}

/* =========================================================================
 * Human-Readable Helpers
 * ========================================================================= */

const char *virp_error_str(virp_error_t err)
{
    switch (err) {
    case VIRP_OK:                    return "OK";
    case VIRP_ERR_NULL_PTR:          return "NULL pointer";
    case VIRP_ERR_NO_PROMPT:         return "Read ended without device prompt (output incomplete)";
    case VIRP_ERR_BUFFER_TOO_SMALL:  return "Buffer too small";
    case VIRP_ERR_INVALID_VERSION:   return "Invalid version";
    case VIRP_ERR_INVALID_TYPE:      return "Invalid message type";
    case VIRP_ERR_INVALID_CHANNEL:   return "Invalid channel";
    case VIRP_ERR_INVALID_TIER:      return "Invalid tier";
    case VIRP_ERR_INVALID_LENGTH:    return "Invalid length";
    case VIRP_ERR_HMAC_FAILED:       return "HMAC verification failed";
    case VIRP_ERR_CHANNEL_VIOLATION: return "Channel-key binding violation";
    case VIRP_ERR_TIER_VIOLATION:    return "BLACK tier transmitted";
    case VIRP_ERR_REPLAY_DETECTED:   return "Replay detected";
    case VIRP_ERR_NO_EVIDENCE:       return "Proposal has no supporting evidence";
    case VIRP_ERR_STALE_OBSERVATION: return "Referenced observation expired";
    case VIRP_ERR_KEY_NOT_LOADED:    return "Signing key not loaded";
    case VIRP_ERR_MESSAGE_TOO_LARGE: return "Message exceeds maximum size";
    case VIRP_ERR_RESERVED_NONZERO:  return "Reserved field is non-zero";
    case VIRP_ERR_CHAIN_DB:          return "Chain database error";
    case VIRP_ERR_CHAIN_BROKEN:      return "Chain integrity violated";
    case VIRP_ERR_CHAIN_SEQUENCE:    return "Chain sequence error";
    case VIRP_ERR_FED_KEY_VERSION:   return "Federation key version too low";
    case VIRP_ERR_FED_REVOKED:       return "Federation key revoked";
    case VIRP_ERR_FED_UNVERIFIED:    return "Unverified foreign peer";
    case VIRP_ERR_TENANT_VIOLATION:  return "Tenant isolation violation";
    case VIRP_ERR_INTENT_NOT_FOUND:  return "Intent not found in durable store";
    case VIRP_ERR_INTENT_EXPIRED:    return "Intent TTL exceeded";
    case VIRP_ERR_INTENT_EXHAUSTED:  return "Intent max_commands reached";
    case VIRP_ERR_VERSION_MISMATCH:    return "Protocol version mismatch";
    case VIRP_ERR_ALGORITHM_MISMATCH:  return "HMAC algorithm mismatch";
    case VIRP_ERR_CHANNEL_UNSUPPORTED: return "Unsupported channel type";
    case VIRP_ERR_SESSION_INVALID:     return "Invalid session ID";
    case VIRP_ERR_CONTEXT_MISMATCH:    return "Context mismatch in verification";
    case VIRP_ERR_CRYPTO:              return "Cryptographic operation failed";
    case VIRP_ERR_HOST_KEY_MISMATCH:   return "SSH host key mismatch (possible MITM)";
    case VIRP_ERR_HOST_KEY_UNKNOWN:    return "SSH host key not in known_hosts";
    case VIRP_ERR_PROTOCOL_VERSION:   return "Unframed v1 request (upgrade client)";
    case VIRP_ERR_APPROVAL_EXPIRED:         return "Approval expired (TTL elapsed)";
    case VIRP_ERR_APPROVAL_REUSED:          return "Approval already consumed (single-use)";
    case VIRP_ERR_APPROVAL_HASH_MISMATCH:   return "Approval bound to a different command";
    case VIRP_ERR_APPROVAL_DEVICE_MISMATCH: return "Approval bound to a different device";
    case VIRP_ERR_APPROVAL_BAD_SIGNATURE:   return "Approval signature invalid";
    case VIRP_ERR_APPROVAL_NOT_FOUND:       return "Proposal or approval not found";
    case VIRP_ERR_APPROVAL_CONSUMED:        return "Proposal already has an outcome";
    case VIRP_ERR_APPROVAL_KEY_UNENROLLED:  return "Approver key_id not enrolled";
    case VIRP_ERR_APPROVAL_KEY_DISABLED:    return "Approver key disabled";
    case VIRP_ERR_DUPLICATE_DEVICE:  return "Duplicate device identity (hostname/node_id/device_id)";
    case VIRP_ERR_CHAIN_READONLY:    return "Write refused on read-only verifier chain handle";
    case VIRP_ERR_OUTCOME_UNKNOWN:   return "Outcome unknown: response absent after possible dispatch; not retried";
    case VIRP_ERR_OBS_SIG_INVALID:   return "Ed25519 observation signature invalid";
    case VIRP_ERR_ACTION_FORBIDDEN:  return "Action not in the caller uid's allowed set";
    default:                         return "Unknown error";
    }
}

const char *virp_msg_type_str(uint8_t type)
{
    switch (type) {
    case VIRP_MSG_OBSERVATION: return "OBSERVATION";
    case VIRP_MSG_HELLO:       return "HELLO";
    case VIRP_MSG_PROPOSAL:    return "PROPOSAL";
    case VIRP_MSG_APPROVAL:    return "APPROVAL";
    case VIRP_MSG_INTENT_ADV:  return "INTENT-ADVERTISE";
    case VIRP_MSG_INTENT_WD:   return "INTENT-WITHDRAW";
    case VIRP_MSG_HEARTBEAT:   return "HEARTBEAT";
    case VIRP_MSG_TEARDOWN:    return "TEARDOWN";
    default:                   return "UNKNOWN";
    }
}

const char *virp_channel_str(uint8_t channel)
{
    switch (channel) {
    case VIRP_CHANNEL_OC: return "OBSERVATION";
    case VIRP_CHANNEL_IC: return "INTENT";
    default:              return "UNKNOWN";
    }
}

const char *virp_tier_str(uint8_t tier)
{
    switch (tier) {
    case VIRP_TIER_UNCLASSIFIED: return "UNCLASSIFIED";
    case VIRP_TIER_BLACK:  return "BLACK (forbidden)";
    case VIRP_TIER_GREEN:  return "GREEN (passive)";
    case VIRP_TIER_YELLOW: return "YELLOW (active)";
    case VIRP_TIER_RED:    return "RED (critical)";
    default:               return "UNKNOWN";
    }
}

const char *virp_obs_type_str(uint8_t obs_type)
{
    switch (obs_type) {
    case VIRP_OBS_PREFIX_REACHABLE: return "PREFIX_REACHABLE";
    case VIRP_OBS_LINK_STATE:       return "LINK_STATE";
    case VIRP_OBS_PEER_STATE:       return "PEER_STATE";
    case VIRP_OBS_FORWARDING_STATE: return "FORWARDING_STATE";
    case VIRP_OBS_RESOURCE_STATE:   return "RESOURCE_STATE";
    case VIRP_OBS_SECURITY_STATE:   return "SECURITY_STATE";
    case VIRP_OBS_DEVICE_OUTPUT:    return "DEVICE_OUTPUT";
    case VIRP_OBS_INTENT_SIGNED:    return "INTENT_SIGNED";
    case VIRP_OBS_OUTCOME_SIGNED:   return "OUTCOME_SIGNED";
    case VIRP_OBS_CHAIN_ENTRY:      return "CHAIN_ENTRY";
    case VIRP_OBS_CHAIN_VERIFY:     return "CHAIN_VERIFY";
    case VIRP_OBS_INTENT_STORED:    return "INTENT_STORED";
    case VIRP_OBS_INTENT_FETCHED:   return "INTENT_FETCHED";
    case VIRP_OBS_INTENT_EXECUTED:  return "INTENT_EXECUTED";
    case VIRP_OBS_ERROR:            return "ERROR";
    case VIRP_OBS_VALIDATION_DECISION: return "VALIDATION_DECISION";
    default:                        return "UNKNOWN";
    }
}

const char *virp_peer_state_str(uint8_t state)
{
    switch (state) {
    case VIRP_PEER_IDLE:         return "IDLE";
    case VIRP_PEER_INIT:         return "INIT";
    case VIRP_PEER_OBS_EXCHANGE: return "OBSERVATION_EXCHANGE";
    case VIRP_PEER_TRUST_VERIFY: return "TRUST_VERIFY";
    case VIRP_PEER_ESTABLISHED:  return "ESTABLISHED";
    case VIRP_PEER_ACTIVE:       return "ACTIVE";
    case VIRP_PEER_TEARDOWN:     return "TEARDOWN";
    default:                     return "UNKNOWN";
    }
}

const char *virp_prop_state_str(uint8_t state)
{
    switch (state) {
    case VIRP_PSTATE_PROPOSED:    return "PROPOSED";
    case VIRP_PSTATE_APPROVED:    return "APPROVED";
    case VIRP_PSTATE_ACTIVE:      return "ACTIVE";
    case VIRP_PSTATE_REJECTED:    return "REJECTED";
    case VIRP_PSTATE_ROLLED_BACK: return "ROLLED_BACK";
    case VIRP_PSTATE_EXPIRED:     return "EXPIRED";
    default:                      return "UNKNOWN";
    }
}
