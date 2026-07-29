/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
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
#include "virp_context.h"
#include "virp_approver_registry.h"
#include <pthread.h>
#include <semaphore.h>   /* sem_t for worker pool cap */
#include <stdint.h>
#include <sys/types.h>   /* uid_t for socket_allowed_uids */

/* =========================================================================
 * O-Node Configuration
 * ========================================================================= */

#define ONODE_MAX_DEVICES       64
#define ONODE_MAX_BATCH         16
#define ONODE_SOCKET_PATH       "/run/virp/onode.sock"
#define ONODE_HEARTBEAT_SEC     30
#define ONODE_MAX_CLIENTS       8
#define ONODE_RECV_TIMEOUT_SEC  5
#define ONODE_MAX_REQUEST_SIZE  24576
#define ONODE_MAX_ALLOWED_UIDS  16
#define ONODE_MAX_GATE_OVERRIDES 16   /* per-driver gate mode overrides */

/*
 * Worker pool bound. Each accepted connection is handled by its own
 * detached pthread; a counting semaphore caps how many may be live at
 * once. New connections arriving while the pool is saturated are
 * rejected (fd closed) rather than queued, so a stuck SSH session
 * cannot build an unbounded backlog. Override at build time with
 * -DONODE_MAX_WORKERS=N.
 */
#ifndef ONODE_MAX_WORKERS
#define ONODE_MAX_WORKERS       32
#endif

/*
 * Kernel accept queue. Must comfortably exceed ONODE_MAX_WORKERS so
 * that short bursts of connections don't get RST'd before the accept
 * loop can dispatch them.
 */
#ifndef ONODE_LISTEN_BACKLOG
#define ONODE_LISTEN_BACKLOG    128
#endif

/* Auto-reconnect configuration */
#define ONODE_WATCHDOG_INTERVAL_SEC  5   /* How often the watchdog checks */
#define ONODE_RECONNECT_BACKOFF_INIT 5   /* Initial backoff: 5 seconds */
#define ONODE_RECONNECT_BACKOFF_MAX  60  /* Maximum backoff: 60 seconds */

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
    ONODE_ACTION_INTENT_STORE = 9,  /* Store intent in durable DB */
    ONODE_ACTION_INTENT_GET   = 10, /* Retrieve intent by ID */
    ONODE_ACTION_INTENT_EXECUTE = 11, /* Record execution against intent */
    ONODE_ACTION_BATCH_EXECUTE = 12, /* Parallel execute on multiple devices */
    ONODE_ACTION_VALIDATE_TURN = 13, /* Response-validator: evaluate AI turn manifest */
    ONODE_ACTION_APPROVAL_CHALLENGE = 14, /* Return canonical bytes to sign for a proposal */
    ONODE_ACTION_APPROVAL_SUBMIT    = 15, /* Submit a signature; daemon appends APPROVAL */
    ONODE_ACTION_SESSION_HELLO = 20, /* Client SESSION_HELLO handshake */
    ONODE_ACTION_SESSION_BIND  = 21, /* Client SESSION_BIND confirmation */
    ONODE_ACTION_SESSION_CLOSE = 22, /* Either peer closes session */
    ONODE_ACTION_SHUTDOWN   = 99,   /* Graceful shutdown */
} onode_action_t;

/* =========================================================================
 * Per-Device Reconnect State
 * ========================================================================= */

typedef struct {
    time_t      last_attempt;       /* When we last tried to reconnect */
    time_t      last_success;       /* When the connection last came up */
    int         backoff_sec;        /* Current backoff interval (5→10→30→60) */
    int         consecutive_fails;  /* Consecutive reconnect failures */
    bool        reconnecting;       /* True while a reconnect is in progress */
} onode_reconnect_t;

/* =========================================================================
 * Tier-Enforcement Gate (Phase B)
 *
 * The gate classifies each command at the execute boundary and compares
 * its tier to a configured maximum. Two modes:
 *   SHADOW            — log the would-allow/would-block decision, then
 *                       execute anyway. Nothing is blocked.
 *   ENFORCE (default) — hard-reject commands above the max tier (and any
 *                       UNCLASSIFIED command) with a signed error
 *                       observation, before the driver runs.
 *
 * Default posture (set in onode_init, before any config is read):
 * ENFORCE mode, max tier YELLOW. Fail-closed: an absent/garbled config
 * blocks over-tier and unclassified commands rather than silently
 * observing them. Drivers without a classifier must be opted into
 * SHADOW explicitly via the gate_modes config map.
 * ========================================================================= */

typedef enum {
    GATE_MODE_SHADOW  = 0,   /* observe/log only, never block            */
    GATE_MODE_ENFORCE = 1,   /* default — hard-reject over-tier /
                                unclassified                             */
} onode_gate_mode_t;

/* =========================================================================
 * O-Node State
 * ========================================================================= */

typedef struct {
    /* Identity */
    uint32_t            node_id;
    virp_signing_key_t  okey;           /* THE key — never leaves this process */

    /*
     * Tier-enforcement gate (Phase B), per-driver scoped.
     *
     *   gate_default_mode — mode for any driver NOT named in the override
     *                       map. Default ENFORCE (fail closed).
     *   gate_overrides    — optional per-driver mode overrides, keyed by
     *                       driver name (drv->name, e.g. "fortigate",
     *                       "cisco_ios"). A driver's effective mode is its
     *                       override if present, else gate_default_mode.
     *   gate_max_tier     — one of VIRP_TIER_GREEN/YELLOW/RED. Default YELLOW.
     *
     * Configured from the JSON config's optional gate_default_mode /
     * gate_modes / gate_max_tier keys; defaults applied in onode_init().
     */
    onode_gate_mode_t   gate_default_mode;
    struct {
        char              driver[VIRP_DRIVER_NAME_MAX];
        onode_gate_mode_t mode;
    }                   gate_overrides[ONODE_MAX_GATE_OVERRIDES];
    size_t              gate_overrides_count;
    virp_trust_tier_t   gate_max_tier;

    /* Devices */
    virp_device_t       devices[ONODE_MAX_DEVICES];
    virp_conn_t         *connections[ONODE_MAX_DEVICES]; /* Persistent connections */
    onode_reconnect_t   reconnect[ONODE_MAX_DEVICES];    /* Per-device reconnect state */
    int                 device_count;

    /* Sequence tracking (anti-replay) */
    uint32_t            seq_num;        /* Monotonically increasing */

    /* Socket */
    int                 listen_fd;
    char                socket_path[108];  /* Must fit in sun_path */

    /*
     * SO_PEERCRED accept-path allowlist. Populated by the daemon's
     * main() (prod: parsed from the JSON config's socket_allowed_uids
     * array via json-c). If empty, onode_start() seeds it with the
     * daemon's own effective UID so a missing config still yields a
     * working — and self-only — default.
     */
    uid_t               socket_allowed_uids[ONODE_MAX_ALLOWED_UIDS];
    size_t              socket_allowed_uids_count;

    /* Trust chain (Primitive 6) */
    virp_chain_state_t  chain;
    bool                chain_enabled;

    /*
     * Approval flow (propose → approve → apply). Disabled until
     * onode_set_approvers() provides a store directory and an approver
     * registry (/etc/virp/approvers.json). The daemon holds ONLY public
     * keys — it verifies approvals, never signs them. Approver and
     * observer roles stay on cryptographically distinct keys: the O-Key
     * is a symmetric HMAC key this process owns; approval keys are
     * enrolled Ed25519 / ECDSA-P256 public keys whose secret halves live
     * with the humans (or their PIV hardware).
     */
    char                     approval_dir[256];
    virp_approver_registry_t approvers;
    bool                     approvers_loaded;

    /* Thread safety */
    pthread_mutex_t     state_mutex;    /* Protects seq_num, observations_sent */
    pthread_mutex_t     conn_mutex;     /* Protects connections[] and reconnect[] */
    /*
     * Serializes access to `ctx` during session handshake messages
     * (HELLO / BIND / CLOSE / DERIVE_KEY). There is exactly one
     * handshake context per daemon; concurrent worker threads that try
     * to drive a handshake would corrupt its state machine otherwise.
     * Command execution after session_derive_key is covered by the
     * per-device exec_mutex, so this lock is only held for the short
     * handshake calls — never around SSH I/O.
     */
    pthread_mutex_t     session_mutex;

    /*
     * Per-device execution mutex.
     *
     * virp_conn_t is not thread-safe: libssh2 sessions and channels
     * must not be used concurrently. batch_execute launches one thread
     * per batch item; if two items target the same device they would
     * race on the shared connection. exec_mutex[dev_idx] serializes
     * all command execution on a given device. It is held for the
     * entire execute path (get_connection → drv->execute → retry →
     * build_observation) so that exactly one thread drives the
     * connection at a time.
     *
     * The watchdog thread must also acquire exec_mutex[dev_idx] before
     * calling drv->disconnect() on an established connection; without
     * that, an in-flight onode_execute could still be inside
     * drv->execute() on a pointer the watchdog is freeing. Likewise
     * onode_destroy() takes each exec_mutex before final teardown.
     *
     * Lock ordering invariant: conn_mutex and exec_mutex[*] must never
     * be held at the same time. Each is acquired, used briefly, and
     * released before any code path attempts to acquire the other.
     * conn_mutex protects slot lookup only (connections[], reconnect[]);
     * exec_mutex protects the lifetime of the referenced virp_conn_t*
     * against concurrent execute / disconnect.
     *
     * Different devices are independent — their mutexes never contend.
     */
    pthread_mutex_t     exec_mutex[ONODE_MAX_DEVICES];

    /* Watchdog thread (auto-reconnect) */
    pthread_t           watchdog_thread;
    bool                watchdog_running;

    /*
     * Worker pool. Each accepted connection is handled on a detached
     * pthread; `worker_sem` is a counting semaphore initialized to
     * ONODE_MAX_WORKERS that caps concurrency. `workers_live` is an
     * advisory counter (under state_mutex) used only for heartbeat
     * logging and for the shutdown drain loop.
     */
    sem_t               worker_sem;
    bool                worker_sem_inited;
    uint32_t            workers_live;
    uint32_t            workers_rejected;   /* saturated-pool rejections */

    /* Runtime */
    bool                running;
    uint32_t            uptime_start;   /* time(NULL) at startup */
    uint32_t            observations_sent;
    uint32_t            errors;
    uint32_t            reconnects;     /* Total successful reconnections */

    /*
     * Protocol context (borrowed, not owned). The main() that owns
     * this onode_state_t also owns the virp_context_t and must
     * assign it here before calling onode_start(). handle_client
     * reads ctx through this pointer to drive the session handshake.
     * Lifetime: allocated with virp_context_new() in main, destroyed
     * with virp_context_destroy() after onode_destroy().
     */
    virp_context_t      *ctx;
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
 * Start the auto-reconnect watchdog thread on its own. onode_start()
 * calls this after binding; tests call it directly to exercise the
 * watchdog (health-check probes against in-flight executes, reconnect
 * backoff) without binding a socket or entering the accept loop.
 * onode_destroy() clears watchdog_running and joins the thread.
 */
virp_error_t onode_watchdog_start(onode_state_t *state);

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
 * Map a gate-computed trust tier to the tier stamped on the observation
 * header. GREEN/YELLOW/RED/UNCLASSIFIED pass through (honest audit record);
 * BLACK -> RED (BLACK is not transmittable on the wire). Exposed for the
 * hardening unit tests; the execute path uses it internally.
 */
uint8_t gate_obs_tier(virp_trust_tier_t t);

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
 * Versioned execute. obs_version selects the observation signing path:
 *
 *   1 — legacy: v1 message signed with the static master O-Key.
 *       Compatibility default for clients that predate session-bound
 *       observations (they cannot derive the session key; the
 *       handshake transcript includes server-stamped timestamps the
 *       socket protocol does not yet echo back).
 *
 *   2 — session-bound: the SUCCESS observation is a v2 wire message
 *       ([88-byte header][payload][32-byte sig]) signed with the
 *       HKDF-derived session key via virp_sign_observation_v2. The
 *       header binds session_id, device_id, seq_num, timestamp and
 *       SHA-256(canonical command). Requires an ACTIVE session; if
 *       none exists the call FAILS with VIRP_ERR_SESSION_INVALID —
 *       there is deliberately no silent fallback to v1, because a
 *       client that asked for session binding must never accept a
 *       downgraded observation.
 *
 * Scope note: error observations (device not found, connect/driver
 * failure, tier-gate rejection) are still emitted as v1 messages even
 * when obs_version == 2. They carry no device output; binding them is
 * follow-up work. A v2-requesting client must treat any v1 response as
 * unverified diagnostics, never as device truth.
 *
 * onode_execute() is exactly onode_execute_obs(..., obs_version=1).
 */
virp_error_t onode_execute_obs(onode_state_t *state,
                               const char *device_name,
                               const char *command,
                               int obs_version,
                               uint8_t *out_buf, size_t out_buf_len,
                               size_t *out_len);

/*
 * Configure the approval flow: `dir` is the approval store directory
 * (proposals/, approvals/, consumed.list) and `registry_path` the
 * approver registry (/etc/virp/approvers.json). Only public keys are
 * loaded — no secret material ever enters the daemon. Returns
 * VIRP_ERR_CHAIN_DB if the registry file is unreadable or not a JSON
 * array, or VIRP_ERR_KEY_NOT_LOADED if it parses but enrolls zero keys
 * (approval flow stays disabled in both cases; plain gate blocking is
 * unaffected).
 */
virp_error_t onode_set_approvers(onode_state_t *state,
                                 const char *dir,
                                 const char *registry_path);

/*
 * As onode_execute_obs(), plus an optional approval reference.
 *
 * proposal_id == NULL / ""  — identical to onode_execute_obs(). A
 *   gate-blocked command additionally files a PROPOSAL (when the
 *   approval store is configured) and the signed rejection carries the
 *   proposal_id.
 *
 * proposal_id set — APPLY: the gate verifies the on-disk approval
 *   (signature → command_hash → device → TTL → single-use consume) and
 *   on success executes the command and emits an OUTCOME chain entry
 *   linked to the PROPOSAL and APPROVAL entries. Any check failure
 *   returns a signed rejection whose payload names the distinct
 *   VIRP_ERR_APPROVAL_* code. BLACK-tier commands are never approvable.
 */
virp_error_t onode_execute_obs_ex(onode_state_t *state,
                                  const char *device_name,
                                  const char *command,
                                  int obs_version,
                                  const char *proposal_id,
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

/* =========================================================================
 * JSON Utilities (used by request parser, exposed for testing)
 * ========================================================================= */

/*
 * Set the SO_PEERCRED allowlist. Replaces any existing entries.
 * Returns VIRP_OK, or VIRP_ERR_MESSAGE_TOO_LARGE if `count` exceeds
 * ONODE_MAX_ALLOWED_UIDS.
 */
virp_error_t onode_set_allowed_uids(onode_state_t *state,
                                    const uid_t *uids, size_t count);

/*
 * Decode a hex string to bytes. Only accepts [0-9a-fA-F].
 * Returns number of bytes written, or -1 on error
 * (odd length, non-hex character, output buffer too small).
 */
int virp_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/*
 * Fuzz entry point for the internal JSON request parser. Intended for
 * test harnesses — production callers should not use this. Never
 * crashes regardless of input; returns true iff the input parsed into
 * a valid request.
 */
bool onode_parse_request_fuzz(const uint8_t *data, size_t n);

#endif /* VIRP_ONODE_H */
