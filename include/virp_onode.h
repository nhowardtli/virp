/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Intent Routing Protocol
 * O-Node Daemon — the hardened observer process
 *
 * The O-Node is the ONLY process that holds the O-Key.
 * It is the ONLY process that can produce signed observations.
 * It listens on a Unix domain socket and accepts requests from
 * the R-Node (or any authorized client).
 *
 * Request flow:
 *   R-Node → "execute 'show ip route' on device R6" → Unix socket
 *   O-Node → SSH into R6 → get output → sign as OBSERVATION → return
 *
 * The R-Node never touches the O-Key. The R-Node never touches SSH.
 * Channel separation is enforced by process isolation.
 */

#ifndef VIRP_ONODE_H
#define VIRP_ONODE_H

#include "virp.h"
#include "virp_crypto.h"
#include "virp_driver.h"
#include "virp_chain.h"

/* =========================================================================
 * O-Node Configuration
 * ========================================================================= */

#define ONODE_MAX_DEVICES       64
#define ONODE_SOCKET_PATH       "/tmp/virp-onode.sock"
#define ONODE_HEARTBEAT_SEC     30
#define ONODE_MAX_CLIENTS       8
#define ONODE_RECV_TIMEOUT_SEC  5
#define ONODE_MAX_REQUEST_SIZE  4096

/* =========================================================================
 * Request/Response Protocol (over Unix socket)
 *
 * The R-Node sends JSON requests. The O-Node returns binary VIRP messages.
 * This is intentional — the request format is flexible (natural language
 * eventually), but the response is ALWAYS a signed VIRP message.
 *
 * Request format (JSON):
 *   {"action": "execute", "device": "R6", "command": "show ip route"}
 *   {"action": "health",  "device": "R6"}
 *   {"action": "heartbeat"}
 *   {"action": "list_devices"}
 *
 * Response format:
 *   Binary VIRP message (OBSERVATION, HEARTBEAT, etc.)
 *   On error: 4-byte error code (network byte order)
 * ========================================================================= */

typedef enum {
    ONODE_ACTION_EXECUTE    = 1,    /* Run command, return OBSERVATION */
    ONODE_ACTION_HEALTH     = 2,    /* Health check, return OBSERVATION */
    ONODE_ACTION_HEARTBEAT  = 3,    /* Return HEARTBEAT message */
    ONODE_ACTION_LIST       = 4,    /* List devices, return OBSERVATION */
    ONODE_ACTION_SIGN_INTENT = 5,   /* Sign intent hash, return OBSERVATION */
    ONODE_ACTION_SIGN_OUTCOME = 6,  /* Sign outcome hash, return OBSERVATION */
    ONODE_ACTION_CHAIN_APPEND = 7,  /* Append artifact to trust chain */
    ONODE_ACTION_CHAIN_VERIFY = 8,  /* Verify trust chain integrity */
    ONODE_ACTION_SHUTDOWN   = 99,   /* Graceful shutdown */
} onode_action_t;

/* =========================================================================
 * O-Node State
 * ========================================================================= */

typedef struct {
    /* Identity */
    uint32_t            node_id;
    virp_signing_key_t  okey;           /* THE key — never leaves this process */

    /* Devices */
    virp_device_t       devices[ONODE_MAX_DEVICES];
    virp_conn_t         *connections[ONODE_MAX_DEVICES]; /* Persistent connections */
    int                 device_count;

    /* Sequence tracking (anti-replay) */
    uint32_t            seq_num;        /* Monotonically increasing */

    /* Socket */
    int                 listen_fd;
    char                socket_path[108];  /* Must fit in sun_path */

    /* Trust chain (Primitive 6) */
    virp_chain_state_t  chain;
    bool                chain_enabled;

    /* Runtime */
    bool                running;
    uint32_t            uptime_start;   /* time(NULL) at startup */
    uint32_t            observations_sent;
    uint32_t            errors;
} onode_state_t;

/* =========================================================================
 * O-Node Lifecycle
 * ========================================================================= */

/*
 * Initialize O-Node state. Generates or loads O-Key.
 * Does NOT start listening — call onode_start() for that.
 */
virp_error_t onode_init(onode_state_t *state,
                        uint32_t node_id,
                        const char *okey_path,      /* NULL = generate new */
                        const char *socket_path);   /* NULL = default */

/*
 * Add a device to the O-Node's inventory.
 */
virp_error_t onode_add_device(onode_state_t *state,
                              const virp_device_t *device);

/*
 * Start the O-Node event loop. Blocks until shutdown.
 * Creates Unix socket, accepts connections, handles requests.
 */
virp_error_t onode_start(onode_state_t *state);

/*
 * Signal the O-Node to shut down gracefully.
 * Can be called from a signal handler.
 */
void onode_shutdown(onode_state_t *state);

/*
 * Clean up all resources.
 */
void onode_destroy(onode_state_t *state);

/* =========================================================================
 * O-Node Operations (called internally by event loop)
 * ========================================================================= */

/*
 * Execute a command on a device and return a signed OBSERVATION.
 *
 * state:       O-Node state
 * device_name: Hostname of device to execute on
 * command:     Command string to execute
 * out_buf:     Output buffer for VIRP OBSERVATION message
 * out_buf_len: Size of output buffer
 * out_len:     Actual bytes written
 */
virp_error_t onode_execute(onode_state_t *state,
                           const char *device_name,
                           const char *command,
                           uint8_t *out_buf, size_t out_buf_len,
                           size_t *out_len);

/*
 * Generate a HEARTBEAT message.
 */
virp_error_t onode_heartbeat(onode_state_t *state,
                             uint8_t *out_buf, size_t out_buf_len,
                             size_t *out_len);

/*
 * Get the next sequence number (thread-safe increment).
 */
uint32_t onode_next_seq(onode_state_t *state);

#endif /* VIRP_ONODE_H */
