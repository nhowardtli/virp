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
#include "virp_obskey.h"
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
#define ONODE_MAX_UID_ACTIONS   32  /* max actions per uid in the
                                       socket_uid_action_allow map —
                                       large enough to spell out the
                                       FULL wire vocabulary for a
                                       principal that legitimately has
                                       it (the operator), so no entry
                                       ever has to be "left off" to
                                       mean unrestricted */
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

/*
 * Shutdown drain hard timeout. The drain barrier normally completes as
 * soon as the last worker exits (client sockets are shutdown() first so
 * nothing stays blocked on client I/O; SSH I/O has its own 10-15s
 * timeouts). This bound only exists as a last resort for a genuinely
 * wedged worker — comfortably inside systemd's 90s stop window — and
 * hitting it means shared state is leaked, not freed (see
 * onode_destroy()).
 */
#ifndef ONODE_DRAIN_TIMEOUT_SEC
#define ONODE_DRAIN_TIMEOUT_SEC 30
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
    ONODE_ACTION_CHAIN_VERIFY_SESSION = 16, /* Verify whole session vs signed head */
    ONODE_ACTION_LIST_FLEET = 17,   /* Enumerate fleet: names + status ONLY */
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
     * Observation-signing keypair (wire version 3). OPTIONAL: absent on
     * every deployment that has not generated one, which is all of them
     * today. Its ONLY use in the daemon is verifying v3 observation
     * bodies submitted to CHAIN_APPEND; when it is not loaded, v3
     * bodies are REFUSED rather than recorded unverified.
     */
    virp_obskey_t       obskey;
    bool                obskey_loaded;

    /*
     * PREVIOUS O-Key — VERIFY-ONLY, TIME-BOUNDED. Optional.
     *
     * Registration is a separate round-trip from collection: the daemon
     * mints a signed observation, the client submits it to CHAIN_APPEND
     * moments later, and chain_append GATE 3 re-verifies it under the
     * key the daemon holds THEN. Rotate the O-Key in between and every
     * in-flight observation fails verification and loses its chain
     * entry — it is not retried. This key closes that window: when the
     * current key fails a v1 body, and only until the deadline, the
     * previous key is tried as well.
     *
     * NEVER used to sign. Nothing writes it into an observation; it is
     * read at exactly one site, the v1 arm of the GATE 3 verifier.
     *
     * NOT for compromise-driven rotation. If the reason for rotating
     * was that the old key leaked, this window keeps accepting anything
     * the holder of that key produces, for its whole duration. Rotate
     * without it in that case (the cost is the in-flight observations,
     * which is the correct trade when the key is burned).
     *
     * WHAT THE DEADLINE IS ANCHORED TO: CLOCK_REALTIME at the moment
     * onode_set_previous_okey() is called — i.e. KEY-LOAD TIME, which
     * in the daemon is process start (main() calls it right after
     * onode_init and before onode_start). It is NOT anchored to the
     * rotation event, and it is held in memory only: nothing persists
     * it across a restart.
     *
     * CONSEQUENCE, and the reason step 4 of the runbook is not
     * optional: an unrelated restart mid-rotation RE-OPENS A FULL
     * WINDOW. Restart 10 minutes into a 15-minute window and you get a
     * fresh 15 minutes, not the remaining 5. So long as -K stays on the
     * command line, every restart renews it, indefinitely — the window
     * bounds a single process run, not the rotation. Remove -K once the
     * drain is done; do not rely on expiry alone to close it.
     */
    virp_signing_key_t  prev_okey;
    bool                prev_okey_loaded;
    uint64_t            prev_okey_deadline_ns;   /* CLOCK_REALTIME */
    uint32_t            prev_okey_accepts;       /* grace-path uses */

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

    /* Config entries the loader REFUSED (no enable credential on a
     * cisco_asa, no PBS pin, unknown vendor, missing fields). Kept in
     * state and reported by list_fleet / list_devices, so whether a
     * device was governed is answerable from the fleet listing itself,
     * not only from the load-time stderr line (#14 review). */
    struct {
        char            hostname[64];
        char            host[64];
        virp_vendor_t   vendor;
        char            reason[128];
    }                   rejected[ONODE_MAX_DEVICES];
    int                 rejected_count;

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

    /*
     * Per-uid tier ceiling (optional). A socket client connecting as one
     * of these uids has its effective gate ceiling lowered to the paired
     * tier: the gate blocks anything ABOVE min(gate_max_tier, this). It
     * can only ever TIGHTEN, never raise, the global gate_max_tier.
     * Parsed from the config's `socket_uid_tier_ceilings` object (uid →
     * "green"/"yellow"/"red") via json-c. A uid absent here keeps the
     * global gate_max_tier. Used to hold a remote requester (e.g. the
     * netclaw tunnel identity) to GREEN reads while local operators keep
     * the node-wide YELLOW ceiling. The connecting uid is carried
     * explicitly into onode_execute_obs_ex() — never inferred from a
     * thread-local — because the batch path fans out onto child threads.
     */
    uid_t               uid_ceiling_uids[ONODE_MAX_ALLOWED_UIDS];
    virp_trust_tier_t   uid_ceiling_tiers[ONODE_MAX_ALLOWED_UIDS];
    size_t              uid_ceiling_count;

    /*
     * Per-uid ACTION allowlist (Item 8, optional). Parsed from the
     * config's `socket_uid_action_allow` object (uid → array of action
     * names), parallel to socket_uid_tier_ceilings. A uid present here
     * may request ONLY the listed actions — anything else is refused
     * with VIRP_ERR_ACTION_FORBIDDEN before the dispatch switch. At
     * request time a uid ABSENT from this map is unrestricted — but
     * onode_start() REFUSES TO RUN when an explicitly configured
     * socket_allowed_uids names a uid this map does not cover (Sep 1
     * review, Task 2), so for an allowlisted principal that
     * fall-through is unreachable: every principal that can connect
     * has a spelled-out action set, and a template that forgets one is
     * a boot failure naming the uid, never a silent grant. Only the
     * self-seeded default (no allowlist configured → the daemon's own
     * uid alone) is exempt. An entry with zero actions is a valid
     * deny-all — the fail-closed representation the config loader
     * installs for a malformed set. A mapped uid is additionally
     * type-narrowed on chain_append to the federation triple
     * (fed_request / fed_observation / fed_outcome). Used to hold the
     * netclaw tunnel identity (uid 993) to fleet enumeration, health,
     * chain reads and provenance appends — and, pointedly, away from
     * shutdown. fed_observation joined the set 2026-08-16: without it
     * the narrowing admitted the outcome but not the signed body that
     * outcome cites, so the bridge recorded pointers to evidence the
     * chain had refused to store.
     */
    uid_t               uid_action_uids[ONODE_MAX_ALLOWED_UIDS];
    onode_action_t      uid_action_sets[ONODE_MAX_ALLOWED_UIDS]
                                       [ONODE_MAX_UID_ACTIONS];
    size_t              uid_action_set_counts[ONODE_MAX_ALLOWED_UIDS];
    size_t              uid_action_count;

    /* Trust chain (Primitive 6) */
    virp_chain_state_t  chain;
    bool                chain_enabled;

    /*
     * EVIDENCE-REQUIRED execution (Sep 1 review, Task 5). Default TRUE
     * (onode_init; the prod loader reads the config's `evidence_required`
     * boolean). When set, every execution the gate admits is preceded by
     * a durable gate_intent chain entry — device, command, tier, uid,
     * session, proposal — committed BEFORE the driver is dispatched; if
     * that append fails (chain full, read-only, absent) the operation is
     * REFUSED with a signed ERROR observation citing evidence-unavailable
     * and nothing reaches the device. The post-execution gate_execution /
     * outcome entry then links back to the intent by chain_entry_hash,
     * so a daemon that dies between the two leaves an intent with no
     * closer, which the verifier reports as an OPEN execution — never as
     * a broken chain. When false, today's behaviour is preserved (record
     * after the fact, best-effort) and every dispatch logs a WARNING that
     * it ran without a durable record. Fail-closed by default: an absent
     * or garbled config key keeps evidence required.
     */
    bool                evidence_required;

    /*
     * EVIDENCE-DEGRADED (Sep 1 review, 1.3). Set true when an execution's
     * outcome record (gate_execution / outcome) could not be committed to
     * the chain AFTER the device had already acted — the one window the
     * pre-execution intent cannot close, because it sits between two chain
     * appends across device I/O. The command ran; its closer did not land.
     * When set, gate_emit_intent refuses every further execution at the
     * intent step (evidence-unavailable / degraded), so the daemon stops
     * dispatching rather than pile up more unchained actions. The prior
     * execution's intent stays OPEN and the verifier reports it as such.
     * Cleared only by a restart (a clean chain reopen). Guarded by
     * state_mutex.
     *
     * evidence_fail_closer_once is a TEST-ONLY injection: when set, the
     * next closer append (gate_execution / outcome) is skipped and
     * reported failed, modelling a chain that goes read-only in exactly
     * that window. Never set in production.
     */
    bool                evidence_degraded;
    bool                evidence_fail_closer_once;

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
     * ONODE_MAX_WORKERS that caps concurrency.
     *
     * Shutdown barrier (all under state_mutex): `workers_live` counts
     * live workers; `workers_cv` is broadcast when the count reaches
     * zero so the drain in onode_start() can wait instead of polling.
     * `worker_fds[slot]` holds a dup() of each live worker's client fd
     * so the drain can shutdown(SHUT_RDWR) the underlying socket and
     * unblock workers stuck in client I/O. The dup is owned by the
     * worker and closed only after its slot is cleared, so the drain
     * can never shutdown() a recycled fd number.
     * `drain_failed` is set when the drain's hard timeout expires with
     * workers still live; onode_destroy() then leaks shared state
     * instead of freeing it under live threads.
     */
    sem_t               worker_sem;
    bool                worker_sem_inited;
    pthread_cond_t      workers_cv;
    int                 worker_fds[ONODE_MAX_WORKERS];
    uint32_t            workers_live;
    uint32_t            workers_rejected;   /* saturated-pool rejections */
    bool                drain_failed;       /* drain timed out; leak, don't free */

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
 * Load a PREVIOUS O-Key for the rotation grace window — VERIFY-ONLY.
 *
 * Call after onode_init and before onode_start. `path` is subject to the
 * same custody gate as the live key (no symlinks, no group/world bits,
 * right owner, right size). `window_seconds` bounds it: the key stops
 * being tried that many seconds after this call, whatever else happens,
 * and 0 is rejected — an unbounded grace window is a second live key.
 *
 * Read at exactly one site: the v1 arm of chain_append's GATE 3, and
 * only after the CURRENT key has already failed. It cannot sign.
 *
 * DO NOT USE when rotating because the old key was compromised. The
 * window's whole function is to keep honouring that key for a while.
 */
virp_error_t onode_set_previous_okey(onode_state_t *state,
                                     const char *path,
                                     uint32_t window_seconds);

/*
 * Add a device to the O-Node's inventory.
 */
virp_error_t onode_add_device(onode_state_t *state,
                              const virp_device_t *device);

/*
 * Record a config entry the loader refused, so it shows up in the fleet
 * listings as "refused: <reason>" instead of silently not existing.
 * hostname/host may be empty (missing-field refusals). Bounded: entries
 * past ONODE_MAX_DEVICES are counted in rejected_count but not stored.
 */
void onode_note_rejected(onode_state_t *state, const char *hostname,
                         const char *host, virp_vendor_t vendor,
                         const char *reason);

/*
 * Start the O-Node event loop. Blocks until shutdown.
 * Creates Unix socket, accepts connections, handles requests.
 *
 * Refuses (VIRP_ERR_ACTION_FORBIDDEN, nothing bound, error names the
 * uid) when socket_allowed_uids was explicitly configured and any uid
 * on it has no socket_uid_action_allow entry: an unmapped-but-allowed
 * uid would be unrestricted, shutdown included, and that must be a
 * startup failure rather than a silent grant. The self-seeded default
 * (no allowlist → daemon uid only) is exempt.
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
/*
 * client_uid — the SO_PEERCRED uid of the connecting socket client, used
 * to apply a per-uid tier ceiling (onode_effective_max_tier). Pass
 * (uid_t)-1 for internal / non-socket callers, which then get only the
 * node-wide gate_max_tier. The socket handler and the batch fan-out both
 * pass the real peer uid.
 */
virp_error_t onode_execute_obs_ex(onode_state_t *state,
                                  const char *device_name,
                                  const char *command,
                                  int obs_version,
                                  const char *proposal_id,
                                  uid_t client_uid,
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
 * Set per-uid tier ceilings. `uids[i]` is capped at `tiers[i]`
 * (GREEN/YELLOW/RED only; BLACK or UNCLASSIFIED is rejected with
 * VIRP_ERR_INVALID_TYPE). A ceiling can only tighten, never raise, the
 * node-wide gate_max_tier. Replaces any existing entries. Returns
 * VIRP_ERR_MESSAGE_TOO_LARGE if `count` exceeds ONODE_MAX_ALLOWED_UIDS.
 */
virp_error_t onode_set_uid_ceilings(onode_state_t *state,
                                    const uid_t *uids,
                                    const virp_trust_tier_t *tiers,
                                    size_t count);

/*
 * Install (or replace) the per-uid action allowlist entry for `uid`
 * (Item 8). `actions`/`count` name the ONLY actions that uid may
 * request; count == 0 installs a valid deny-all entry (the fail-closed
 * form for a malformed config set). Returns VIRP_ERR_MESSAGE_TOO_LARGE
 * when count exceeds ONODE_MAX_UID_ACTIONS or the uid table is full,
 * VIRP_ERR_INVALID_TYPE for an action value that is not a known
 * onode_action_t. A uid never passed here is completely unrestricted
 * by this map.
 */
virp_error_t onode_set_uid_actions(onode_state_t *state, uid_t uid,
                                   const onode_action_t *actions,
                                   size_t count);

/* Drop every per-uid action allowlist entry (tests / config reload). */
void onode_clear_uid_actions(onode_state_t *state);

/*
 * Per-uid action-allowlist decision for a SOCKET request: true iff the
 * request MUST be refused — an unknown identity (client_uid == (uid_t)-1,
 * which must never fall through to node-wide policy) or a uid present in
 * socket_uid_action_allow whose set does not list `action`. A uid absent
 * from the map is unrestricted here; onode_start() guarantees no
 * allowlisted uid of an explicitly configured allowlist is absent (see
 * the state-field comment). Exposed so the fail-open regression can
 * drive the decision directly.
 */
bool onode_uid_request_refused(const onode_state_t *state,
                               uid_t client_uid, onode_action_t action);

/*
 * Map an action name from the wire ("list_fleet", "shutdown", …) to
 * its onode_action_t. Returns 0 (no such action) for unknown names —
 * the same names parse_request accepts, kept in ONE table so the
 * dispatch and the config loader can never disagree.
 */
onode_action_t onode_action_from_name(const char *name);

/*
 * Decode a hex string to bytes. Only accepts [0-9a-fA-F].
 * Returns number of bytes written, or -1 on error
 * (odd length, non-hex character, output buffer too small).
 */
int virp_hex_decode(const char *hex, uint8_t *out, size_t out_len);

/*
 * Autopilot hard exclusions: 10.0.10.1 and 10.0.10.10 must never appear
 * in a device config. Boundary-aware scan of raw config text (so
 * 10.0.10.12 / 10.0.10.100 do not false-positive). Returns the blocked
 * address (static string) on a hit, NULL when clean. The file variant
 * reads up to 1 MiB of `path`; unreadable files return NULL — the
 * loader's own error handling covers those. Every config loader MUST
 * call one of these and refuse to start on a hit.
 */
const char *virp_config_blocked_address(const char *text);
const char *virp_config_file_blocked(const char *path);

/*
 * Fuzz entry point for the internal JSON request parser. Intended for
 * test harnesses — production callers should not use this. Never
 * crashes regardless of input; returns true iff the input parsed into
 * a valid request.
 */
bool onode_parse_request_fuzz(const uint8_t *data, size_t n);

#endif /* VIRP_ONODE_H */
