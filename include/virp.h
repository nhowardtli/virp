/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Core protocol definitions
 */

#ifndef VIRP_H
#define VIRP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* =========================================================================
 * Protocol Constants
 * ========================================================================= */

#define VIRP_VERSION            1
#define VIRP_VERSION_2          2
#define VIRP_PORT               1790        /* Proposed IANA assignment */
#define VIRP_HEADER_SIZE        56          /* Fixed header: 24 bytes + 32 HMAC */
#define VIRP_HMAC_SIZE          32          /* SHA-256 = 32 bytes */
#define VIRP_HMAC_HEX_SIZE     65          /* 32 * 2 + NUL */
#define VIRP_KEY_SIZE           32          /* 256-bit signing keys */
#define VIRP_MAX_MESSAGE_SIZE   65536       /* 64KB max message */
#define VIRP_MAX_PAYLOAD_SIZE   (VIRP_MAX_MESSAGE_SIZE - VIRP_HEADER_SIZE)
/* Socket framing version — inside the length-prefixed frame, NOT before it.
 * Enables version negotiation on a bad length without losing recovery. */
#define VIRP_FRAME_VERSION      0x02        /* v2 framed protocol */

#define VIRP_MAX_OBS_REFS       64          /* Max observation references per proposal */
#define VIRP_MAX_INTENT_DATA    8192        /* Max intent payload */
#define VIRP_MAGIC              0x56495250  /* "VIRP" in ASCII */

/* =========================================================================
 * Channel Identifiers
 *
 * The two channels can NEVER cross. O-Keys sign OC messages.
 * R-Keys sign IC messages. This is structural, not policy.
 * ========================================================================= */

#define VIRP_CHANNEL_OC         0x01    /* Observation Channel — facts, signed by O-Node */
#define VIRP_CHANNEL_OBS        VIRP_CHANNEL_OC  /* Alias for v2 API */
#define VIRP_CHANNEL_IC         0x02    /* Intent Channel — proposals, signed by R-Node */
#define VIRP_CHANNEL_INTENT     VIRP_CHANNEL_IC   /* Alias for v2 API */

/* =========================================================================
 * Trust Tiers
 *
 * Mapped from TLI Ops Center command tiers:
 *   GREEN  → Tier 1 (passive, no approval)
 *   YELLOW → Tier 2 (active, single approval)
 *   RED    → Tier 3 (critical, multi-human approval)
 *   BLACK  → Tier 0 (impossible — not in message format)
 * ========================================================================= */

#define VIRP_TIER_UNCLASSIFIED  0x00    /* No classifier table matched — gate fails closed */
#define VIRP_TIER_GREEN         0x01    /* Passive — no approval required */
#define VIRP_TIER_YELLOW        0x02    /* Active — single approval required */
#define VIRP_TIER_RED           0x03    /* Critical — multi-human approval */
#define VIRP_TIER_BLACK         0xFF    /* Forbidden — never transmitted */

/* =========================================================================
 * Message Types
 * ========================================================================= */

/* Observation Channel messages (0x01 - 0x0F) */
#define VIRP_MSG_OBSERVATION    0x01    /* Signed measurement of network state */
#define VIRP_MSG_HELLO          0x02    /* Peer initialization and key exchange */

/* Intent Channel messages (0x10 - 0x2F) */
#define VIRP_MSG_PROPOSAL       0x10    /* Proposed change with evidence */
#define VIRP_MSG_APPROVAL       0x11    /* Approval/rejection of proposal */
#define VIRP_MSG_INTENT_ADV     0x20    /* Advertisement of network intent */
#define VIRP_MSG_INTENT_WD      0x21    /* Withdrawal of intent */

/* Shared messages (0x30+) */
#define VIRP_MSG_HEARTBEAT      0x30    /* Signed liveness proof — OC only */
#define VIRP_MSG_TEARDOWN       0xF0    /* Graceful session termination — both */

/* Session handshake messages (0x40 range) */
#define VIRP_MSG_SESSION_HELLO      0x40    /* Client → O-Node session initiation */
#define VIRP_MSG_SESSION_HELLO_ACK  0x41    /* O-Node → Client session acceptance */
#define VIRP_MSG_SESSION_BIND       0x42    /* Client confirms session binding */
#define VIRP_MSG_SESSION_CLOSE      0x43    /* Either peer closes session */
#define VIRP_MSG_SESSION_ERROR      0x4F    /* Session-level error */

/* Algorithm identifiers */
#define VIRP_ALG_HMAC_SHA256    0x01

/* Session close reason codes */
#define VIRP_CLOSE_NORMAL       0x00
#define VIRP_CLOSE_TIMEOUT      0x01
#define VIRP_CLOSE_ERROR        0x02
#define VIRP_CLOSE_REPLACED     0x03    /* new session displaced this one */

/* =========================================================================
 * Observation Types
 * ========================================================================= */

#define VIRP_OBS_PREFIX_REACHABLE   0x01    /* Prefix exists on this node */
#define VIRP_OBS_LINK_STATE         0x02    /* Measured link metrics */
#define VIRP_OBS_PEER_STATE         0x03    /* Adjacency state with neighbor */
#define VIRP_OBS_FORWARDING_STATE   0x04    /* Verified forwarding table entry */
#define VIRP_OBS_RESOURCE_STATE     0x05    /* CPU, memory, interface utilization */
#define VIRP_OBS_SECURITY_STATE     0x06    /* Access policy, zone, encryption */
#define VIRP_OBS_DEVICE_OUTPUT      0x07    /* Raw CLI/API output (TLI model) */
#define VIRP_OBS_INTENT_SIGNED      0x08    /* O-Node witnessed AI intent declaration */
#define VIRP_OBS_OUTCOME_SIGNED     0x09    /* O-Node witnessed outcome verification */
#define VIRP_OBS_CHAIN_ENTRY        0x0A    /* Trust chain entry appended */
#define VIRP_OBS_CHAIN_VERIFY       0x0B    /* Trust chain verification result */
#define VIRP_OBS_INTENT_STORED      0x0C    /* Intent stored in durable DB */
#define VIRP_OBS_INTENT_FETCHED     0x0D    /* Intent retrieved from DB */
#define VIRP_OBS_INTENT_EXECUTED    0x0E    /* Intent execution counter updated */
#define VIRP_OBS_ERROR              0x0F    /* Signed error: driver/transport failure */
#define VIRP_OBS_VALIDATION_DECISION 0x10   /* Response-validator decision, signed by O-Node */
#define VIRP_OBS_APPROVAL_CHALLENGE 0x11    /* Approval challenge: canonical bytes to sign */
#define VIRP_OBS_APPROVAL_RESULT    0x12    /* Approval submit result (accepted) */

/* =========================================================================
 * Observation Scope
 * ========================================================================= */

#define VIRP_SCOPE_LOCAL        0x01    /* About this node */
#define VIRP_SCOPE_ADJACENT     0x02    /* About a directly connected neighbor */
#define VIRP_SCOPE_MEASURED     0x03    /* Derived from active probing */

/* =========================================================================
 * Proposal Types
 * ========================================================================= */

#define VIRP_PROP_ROUTE_INJECT      0x01    /* Add a route */
#define VIRP_PROP_ROUTE_WITHDRAW    0x02    /* Remove a route */
#define VIRP_PROP_METRIC_CHANGE     0x03    /* Change path metric */
#define VIRP_PROP_POLICY_CHANGE     0x04    /* Change forwarding/security policy */
#define VIRP_PROP_TOPOLOGY_CHANGE   0x05    /* Change peer relationships */
#define VIRP_PROP_CONFIG_APPLY      0x06    /* Apply config block to device */

/* =========================================================================
 * Proposal States
 * ========================================================================= */

#define VIRP_PSTATE_PROPOSED        0x01
#define VIRP_PSTATE_APPROVED        0x02
#define VIRP_PSTATE_ACTIVE          0x03
#define VIRP_PSTATE_REJECTED        0x04
#define VIRP_PSTATE_ROLLED_BACK     0x05
#define VIRP_PSTATE_EXPIRED         0x06

/* =========================================================================
 * Approval Types
 * ========================================================================= */

#define VIRP_APPROVAL_APPROVE       0x01
#define VIRP_APPROVAL_REJECT        0x02
#define VIRP_APPROVAL_ESCALATE      0x03    /* Needs higher-tier approval */

/* =========================================================================
 * Approver Class
 * ========================================================================= */

#define VIRP_APPROVER_AUTOMATED     0x01    /* R-Node within policy bounds */
#define VIRP_APPROVER_HUMAN         0x02    /* Human operator */
#define VIRP_APPROVER_MULTI_HUMAN   0x03    /* Multiple human operators */

/* =========================================================================
 * Intent Types
 * ========================================================================= */

#define VIRP_INTENT_REACHABILITY    0x01    /* Prefix reachable with guarantees */
#define VIRP_INTENT_SERVICE         0x02    /* Service available (fw, lb, etc) */
#define VIRP_INTENT_CAPACITY        0x03    /* Available capacity on path */
#define VIRP_INTENT_CONSTRAINT      0x04    /* MUST/MUST NOT traverse nodes */
#define VIRP_INTENT_SLA             0x05    /* Performance guarantee */

/* =========================================================================
 * Node Types
 * ========================================================================= */

#define VIRP_NODE_OBSERVER      0x01    /* O-Node: measures and signs */
#define VIRP_NODE_REASONING     0x02    /* R-Node: reasons and proposes */
#define VIRP_NODE_HYBRID        0x03    /* H-Node: both, internally separated */

/* =========================================================================
 * Peer States (FSM)
 * ========================================================================= */

#define VIRP_PEER_IDLE              0x00
#define VIRP_PEER_INIT              0x01
#define VIRP_PEER_OBS_EXCHANGE      0x02
#define VIRP_PEER_TRUST_VERIFY      0x03
#define VIRP_PEER_ESTABLISHED       0x04
#define VIRP_PEER_ACTIVE            0x05
#define VIRP_PEER_TEARDOWN          0x06

/* =========================================================================
 * Structures
 * ========================================================================= */

/*
 * VIRP Common Header — 56 bytes fixed
 *
 * Every VIRP message starts with this header. The HMAC covers
 * the entire message (header fields + payload) excluding the
 * HMAC field itself.
 *
 * Wire format is network byte order (big-endian).
 */
typedef struct __attribute__((packed)) {
    uint8_t     version;                    /* Protocol version (1) */
    uint8_t     type;                       /* Message type */
    uint16_t    length;                     /* Total message length incl header */
    uint32_t    node_id;                    /* Originating node identifier */
    uint8_t     channel;                    /* OC (0x01) or IC (0x02) */
    uint8_t     tier;                       /* GREEN/YELLOW/RED */
    uint16_t    reserved;                   /* Must be zero */
    uint32_t    seq_num;                    /* Monotonic sequence number */
    uint64_t    timestamp_ns;               /* Nanosecond Unix timestamp */
    uint8_t     hmac[VIRP_HMAC_SIZE];       /* HMAC-SHA256 signature */
} virp_header_t;

_Static_assert(sizeof(virp_header_t) == VIRP_HEADER_SIZE,
               "VIRP header must be exactly 56 bytes");

/*
 * Observation payload
 */
typedef struct __attribute__((packed)) {
    uint8_t     obs_type;                   /* VIRP_OBS_* */
    uint8_t     obs_scope;                  /* VIRP_SCOPE_* */
    uint16_t    obs_length;                 /* Length of observation data */
    /* Variable-length observation data follows */
} virp_observation_t;

/*
 * Observation reference — used in proposals to cite evidence
 */
typedef struct __attribute__((packed)) {
    uint32_t    node_id;                    /* Node that made the observation */
    uint32_t    seq_num;                    /* Sequence number of observation */
} virp_obs_ref_t;

/*
 * Proposal payload
 */
typedef struct __attribute__((packed)) {
    uint32_t    proposal_id;                /* Unique proposal identifier */
    uint8_t     prop_type;                  /* VIRP_PROP_* */
    uint8_t     prop_state;                 /* VIRP_PSTATE_* */
    uint16_t    blast_radius;               /* Estimated affected nodes/prefixes */
    uint32_t    obs_ref_count;              /* Number of supporting observations */
    /* Array of virp_obs_ref_t follows (obs_ref_count entries) */
    /* Variable-length proposal data follows after refs */
} virp_proposal_t;

/*
 * Approval payload
 */
typedef struct __attribute__((packed)) {
    uint32_t    proposal_id;                /* Which proposal */
    uint32_t    approver_node_id;           /* Who approved */
    uint8_t     approval_type;              /* APPROVE/REJECT/ESCALATE */
    uint8_t     approver_class;             /* AUTOMATED/HUMAN/MULTI_HUMAN */
    uint16_t    reserved;                   /* Must be zero */
} virp_approval_t;

/*
 * Intent advertisement payload
 */
typedef struct __attribute__((packed)) {
    uint32_t    intent_id;                  /* Unique intent identifier */
    uint8_t     intent_type;                /* VIRP_INTENT_* */
    uint8_t     priority;                   /* 0-255, higher = more preferred */
    uint16_t    ttl_seconds;                /* Time to live */
    uint32_t    proof_count;                /* Number of proof-of-capability refs */
    /* Array of virp_obs_ref_t follows (proof_count entries) */
    /* Variable-length intent data follows after proofs */
} virp_intent_adv_t;

/*
 * Intent withdrawal payload
 */
typedef struct __attribute__((packed)) {
    uint32_t    intent_id;                  /* Which intent to withdraw */
} virp_intent_wd_t;

/*
 * Heartbeat payload — OC only
 */
typedef struct __attribute__((packed)) {
    uint32_t    uptime_seconds;             /* Node uptime */
    uint8_t     onode_ok;                   /* O-Node operational (0/1) */
    uint8_t     rnode_ok;                   /* R-Node operational (0/1) */
    uint16_t    active_observations;        /* Current observation count */
    uint32_t    active_proposals;           /* Current proposal count */
} virp_heartbeat_t;

/*
 * Hello payload — exchanged during INIT
 */
typedef struct __attribute__((packed)) {
    uint32_t    magic;                      /* VIRP_MAGIC */
    uint8_t     version;                    /* Protocol version */
    uint8_t     node_type;                  /* OBSERVER/REASONING/HYBRID */
    uint8_t     max_tier;                   /* Highest tier this node supports */
    uint8_t     reserved;
    uint32_t    node_id;                    /* This node's ID */
    uint8_t     okey_fingerprint[VIRP_HMAC_SIZE]; /* SHA-256 of O-Node public key */
    uint8_t     rkey_fingerprint[VIRP_HMAC_SIZE]; /* SHA-256 of R-Node public key */
} virp_hello_t;

/*
 * V2 Observation Header
 *
 * Extended header for v2 observations. Carries session context,
 * device identity, and a SHA-256 hash of the canonicalized command.
 *
 * This struct is the IN-MEMORY representation only. The wire format is
 * produced exclusively by virp_obs_header_v2_serialize() (explicit
 * network-byte-order field layout, VIRP_OBS_V2_HEADER_SIZE bytes) —
 * never by memcpy of the struct, whose padding is ABI-dependent.
 */
typedef struct {
    uint8_t  version;           /* VIRP_VERSION_2 */
    uint8_t  channel;           /* VIRP_CHANNEL_OBS */
    uint8_t  tier;              /* GREEN/YELLOW/RED/BLACK */
    uint8_t  _reserved;         /* must be zero */

    uint64_t node_id;           /* stable O-Node identity */
    uint64_t timestamp_ns;      /* nanoseconds since epoch */
    uint64_t seq_num;           /* monotonically increasing per session */

    uint8_t  session_id[16];    /* from SESSION_BIND, zeros if no session */
    uint64_t device_id;         /* stable device UUID from devices.json */

    uint8_t  command_hash[32];  /* SHA-256 of canonical command */
    uint32_t payload_len;       /* length of observation payload in bytes */
} virp_obs_header_v2_t;

/*
 * V2 observation wire format:
 *
 *   [ serialized header : 88 bytes ][ payload : payload_len ][ sig : 32 ]
 *
 * Serialized header layout (all multi-byte fields big-endian):
 *   off  0  version(1) channel(1) tier(1) reserved(1)
 *   off  4  node_id(8)
 *   off 12  timestamp_ns(8)
 *   off 20  seq_num(8)
 *   off 28  session_id(16)
 *   off 44  device_id(8)
 *   off 52  command_hash(32)
 *   off 84  payload_len(4)
 *   = 88 bytes, no padding.
 *
 * The signature is HMAC-SHA256(session_key, serialized_header || payload).
 */
#define VIRP_OBS_V2_HEADER_SIZE   88
#define VIRP_OBS_V2_SIG_SIZE      32
#define VIRP_OBS_V2_MIN_SIZE      (VIRP_OBS_V2_HEADER_SIZE + VIRP_OBS_V2_SIG_SIZE)

/* Freshness window for v2 observation verification: the signed
 * timestamp_ns must be within this many nanoseconds of the verifier's
 * clock (in either direction) or the observation is rejected as stale. */
#define VIRP_OBS_V2_FRESHNESS_WINDOW_NS  (300ULL * 1000000000ULL)  /* 300 s */

/*
 * VIRP signing key pair — one per key type (O-Key or R-Key)
 */
typedef struct {
    uint8_t     key[VIRP_KEY_SIZE];         /* 256-bit HMAC key */
    bool        loaded;                     /* Key is initialized */
} virp_key_t;

/* =========================================================================
 * Return codes
 * ========================================================================= */

typedef enum {
    VIRP_OK                     =  0,
    VIRP_ERR_NULL_PTR           = -1,
    VIRP_ERR_BUFFER_TOO_SMALL   = -2,
    VIRP_ERR_INVALID_VERSION    = -3,
    VIRP_ERR_INVALID_TYPE       = -4,
    VIRP_ERR_INVALID_CHANNEL    = -5,
    VIRP_ERR_INVALID_TIER       = -6,
    VIRP_ERR_INVALID_LENGTH     = -7,
    VIRP_ERR_HMAC_FAILED        = -8,
    VIRP_ERR_CHANNEL_VIOLATION  = -9,   /* R-Key on OC or O-Key on IC */
    VIRP_ERR_TIER_VIOLATION     = -10,  /* BLACK tier transmitted */
    VIRP_ERR_REPLAY_DETECTED    = -11,  /* Sequence number not monotonic */
    VIRP_ERR_NO_EVIDENCE        = -12,  /* Proposal with zero obs refs */
    VIRP_ERR_STALE_OBSERVATION  = -13,  /* Referenced observation expired */
    VIRP_ERR_KEY_NOT_LOADED     = -14,
    VIRP_ERR_MESSAGE_TOO_LARGE  = -15,
    VIRP_ERR_RESERVED_NONZERO   = -16,
    VIRP_ERR_CHAIN_DB           = -17,  /* Chain database error */
    VIRP_ERR_CHAIN_BROKEN       = -18,  /* Chain integrity violated */
    VIRP_ERR_CHAIN_SEQUENCE     = -19,  /* Chain sequence error */
    VIRP_ERR_FED_KEY_VERSION    = -20,  /* Federation key version too low */
    VIRP_ERR_FED_REVOKED        = -21,  /* Federation key revoked */
    VIRP_ERR_FED_UNVERIFIED     = -22,  /* Unverified foreign peer */
    VIRP_ERR_TENANT_VIOLATION   = -23,  /* Tenant isolation violation */
    VIRP_ERR_INTENT_NOT_FOUND   = -24,  /* Intent ID not in durable store */
    VIRP_ERR_INTENT_EXPIRED     = -25,  /* Intent TTL exceeded */
    VIRP_ERR_INTENT_EXHAUSTED   = -26,  /* Intent max_commands reached */

    /* v2 error codes */
    VIRP_ERR_VERSION_MISMATCH    = -27,  /* Protocol version mismatch */
    VIRP_ERR_ALGORITHM_MISMATCH  = -28,  /* HMAC algorithm mismatch */
    VIRP_ERR_CHANNEL_UNSUPPORTED = -29,  /* Unsupported channel type */
    VIRP_ERR_SESSION_INVALID     = -30,  /* Invalid session ID */
    VIRP_ERR_CONTEXT_MISMATCH    = -31,  /* Context mismatch in verification */
    VIRP_ERR_CRYPTO              = -32,  /* Cryptographic operation failed */
    VIRP_ERR_HOST_KEY_MISMATCH   = -33,  /* SSH host key changed (possible MITM) */
    VIRP_ERR_HOST_KEY_UNKNOWN    = -34,  /* SSH host key not in known_hosts */
    VIRP_ERR_PROTOCOL_VERSION    = -35,  /* Client sent unframed v1 request */

    /* Approval-flow error codes (propose → approve → apply). Each apply
     * check failure has its own code so rejections are unambiguous. */
    VIRP_ERR_APPROVAL_EXPIRED         = -36,  /* Approval TTL elapsed */
    VIRP_ERR_APPROVAL_REUSED          = -37,  /* Approval already consumed */
    VIRP_ERR_APPROVAL_HASH_MISMATCH   = -38,  /* command_hash does not match */
    VIRP_ERR_APPROVAL_DEVICE_MISMATCH = -39,  /* Bound to a different device */
    VIRP_ERR_APPROVAL_BAD_SIGNATURE   = -40,  /* Not signed by an enrolled key */
    VIRP_ERR_APPROVAL_NOT_FOUND       = -41,  /* No such proposal/approval */
    VIRP_ERR_APPROVAL_CONSUMED        = -42,  /* Proposal already has an OUTCOME */
    VIRP_ERR_APPROVAL_KEY_UNENROLLED  = -43,  /* key_id not in the registry */
    VIRP_ERR_APPROVAL_KEY_DISABLED    = -44,  /* enrolled key marked disabled */

    /* Interactive-shell read path (see include/virp_ssh_io.h). A read
     * that ends without the learned prompt is incomplete by definition
     * and must never be reported as command output. */
    VIRP_ERR_NO_PROMPT                = -45,  /* read ended without prompt */

    /* Device identity is the unit of authorization binding (approvals,
     * observations, chain sessions). Two devices sharing a hostname,
     * node_id, or device_id would let evidence or approvals for one be
     * read as the other's — refused at config load, fail closed. */
    VIRP_ERR_DUPLICATE_DEVICE         = -46,  /* hostname/node_id/device_id
                                                 collides with a loaded
                                                 device */

    /* A chain handle opened by virp_chain_open_verifier() can prove or
     * refute what a database says; it must never be able to change what
     * the database says. Every mutating chain entry point refuses on
     * such a handle. */
    VIRP_ERR_CHAIN_READONLY           = -47,  /* write attempted on a
                                                 read-only verifier
                                                 chain handle */

    /* Success-class status codes (> 0). Not errors: the operation's
     * postcondition holds, but not because of this call. */
    VIRP_APPROVAL_ALREADY_EXISTS      =  1,   /* Submit lost an idempotency
                                                 race (or repeated): a
                                                 canonical approval record
                                                 already exists; *out holds
                                                 the approver OF RECORD,
                                                 not the caller. */
} virp_error_t;

/* =========================================================================
 * Command separator policy
 *
 * Single source of truth for "is this ONE command?", shared by the
 * daemon's ingress boundary check and the per-driver gate classifiers so
 * the two can never disagree.
 *
 * A command carrying an embedded separator is not classifiable: every
 * classifier prefix-matches from index 0, so only the FIRST command in
 * such a string is ever tiered while the driver hands the WHOLE string
 * to the device, where the separator splits it. Anything past the first
 * separator would reach the wire ungated.
 *
 * Rejected: all control bytes (< 0x20, including newline, carriage
 * return and tab) and DEL; the CLI/shell separators ';' '|' '&' '`';
 * and the shell expansions "$(" and "${".
 *
 * Returns 0 when `cmd` is a single separator-free command, else -1. When
 * `why` is non-NULL it receives a human-readable reason naming the
 * offending byte. Control bytes are rendered as \xNN so an attacker-
 * controlled command can never smuggle raw control characters into logs
 * or into the signed error observation built from this text.
 *
 * REJECT, never strip: silently rewriting "show version\nreload" into
 * "show versionreload" would be its own hazard.
 * ========================================================================= */

int virp_command_check_separators(const char *cmd, char *why, size_t why_len);

/* =========================================================================
 * Human-readable helpers
 * ========================================================================= */

const char *virp_error_str(virp_error_t err);
const char *virp_msg_type_str(uint8_t type);
const char *virp_channel_str(uint8_t channel);
const char *virp_tier_str(uint8_t tier);
const char *virp_obs_type_str(uint8_t obs_type);
const char *virp_peer_state_str(uint8_t state);
const char *virp_prop_state_str(uint8_t state);

#endif /* VIRP_H */
