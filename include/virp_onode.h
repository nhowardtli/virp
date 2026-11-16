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
#include "virp_policy.h"
#include "virp_chain.h"
#include "virp_context.h"
#include "virp_approver_registry.h"
#include "virp_obskey.h"
#include <pthread.h>
#include <semaphore.h>   /* sem_t for worker pool cap */
#include <stdint.h>
#include <stdatomic.h>
_Static_assert(ATOMIC_BOOL_LOCK_FREE == 2, "shutdown flag must be signal-safe");
#include <sys/types.h>   /* uid_t for socket_allowed_uids */

/* =========================================================================
 * O-Node Configuration
 * ========================================================================= */

#define ONODE_MAX_DEVICES       64

/* NULL means the class has no qualified generic health read. */
const char *onode_health_command(virp_vendor_t vendor);
#define ONODE_MAX_BATCH         16
#define ONODE_SOCKET_PATH       "/run/virp/onode.sock"
#define ONODE_HEARTBEAT_SEC     30
#define ONODE_MAX_CLIENTS       8
#define ONODE_RECV_TIMEOUT_SEC  5   /* ONE deadline for a whole request
                                       frame, header to last byte */
#define ONODE_SEND_TIMEOUT_SEC  10  /* a peer that stops reading its
                                       response is abandoned after this */
#define ONODE_MAX_REQUEST_SIZE  131072
#define ONODE_MAX_ALLOWED_UIDS  16
#define ONODE_MAX_UID_CAPP_TYPES 16 /* max chain_append types per uid (v0.2.1) */
#define ONODE_CHAIN_TYPE_MAX     16 /* artifact_type field width incl NUL   */
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
 * Per-uid share of the worker pool (security review M14). The pool cap
 * above is global, so one allowed uid could hold all of it — by design
 * or by a stuck client library — and every other principal's
 * connections were then closed at accept. No single uid may hold more
 * than this many workers at once; a connection over the cap is closed
 * at accept exactly like a saturated pool. Half the pool by default:
 * far above any legitimate client's fan-out (batch_execute multiplexes
 * inside ONE connection), and it always leaves room for someone else.
 * Override at build time with -DONODE_MAX_WORKERS_PER_UID=N.
 */
#ifndef ONODE_MAX_WORKERS_PER_UID
#define ONODE_MAX_WORKERS_PER_UID (ONODE_MAX_WORKERS / 2)
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

/*
 * chain_verify bounds (security review M15).
 *
 * A verify walks its range holding the chain lock, and every execution
 * needs that lock to commit its pre-dispatch intent while it holds the
 * device's exec_mutex — so for as long as one verify runs, no device can
 * execute anything and the watchdog cannot probe. Before these bounds a
 * single request with to_sequence = INT64_MAX held it for the whole
 * session, and nothing stopped a uid from issuing them back to back.
 *
 *   ONODE_CHAIN_VERIFY_MAX_RANGE   entries one ranged CHAIN_VERIFY may
 *       cover. Measured ~23 us per entry, so a full-size request holds
 *       the lock for about a second. A larger range is refused with
 *       VIRP_ERR_MESSAGE_TOO_LARGE; the caller pages, or asks for
 *       CHAIN_VERIFY_SESSION.
 *   ONODE_VERIFY_BUDGET_MS / ONODE_VERIFY_WINDOW_SEC   per uid: the
 *       verify time one principal may consume per window. Past it, and
 *       while that uid already has a verify in flight, further verifies
 *       are refused with VIRP_ERR_RATE_LIMITED. A third of the window by
 *       default, so no single uid can deny the chain lock to executions
 *       for more than that fraction — while a chainwalk that verifies
 *       hundreds of small sessions one after another is untouched,
 *       because what is metered is time, not request count.
 *
 * CHAIN_VERIFY_SESSION has no range to cap — covering the whole session
 * against its signed head is its purpose — so it is bounded by the
 * budget only. See REVIEW-NOTES.md for what that leaves open.
 */
#ifndef ONODE_CHAIN_VERIFY_MAX_RANGE
#define ONODE_CHAIN_VERIFY_MAX_RANGE 50000
#endif
#ifndef ONODE_VERIFY_WINDOW_SEC
#define ONODE_VERIFY_WINDOW_SEC      60
#endif
#ifndef ONODE_VERIFY_BUDGET_MS
#define ONODE_VERIFY_BUDGET_MS       20000
#endif

/*
 * Proposal bounds (security review M16).
 *
 * Every gate refusal of an approvable command filed a brand-new
 * proposal: a record on disk and a PROPOSAL chain entry, both permanent.
 * A client that simply repeated one refused command grew the approval
 * store and the chain without limit and buried the approver's queue in
 * copies of the same request.
 *
 *   ONODE_PROPOSAL_CACHE   how many recently filed proposals the daemon
 *       remembers, keyed (device, command hash, proposer). A refusal
 *       whose key matches a remembered proposal that is still OPEN is
 *       answered with that proposal's id; nothing new is filed.
 *   ONODE_PROPOSAL_BURST / ONODE_PROPOSAL_WINDOW_SEC   per uid: how many
 *       NEW proposals one principal may file per window. Past it the
 *       refusal is unchanged — still recorded, still a signed ERROR —
 *       but carries no proposal id until the window turns over. The
 *       internal caller ((uid_t)-1) is not a socket principal and is not
 *       limited.
 */
#ifndef ONODE_PROPOSAL_CACHE
#define ONODE_PROPOSAL_CACHE       128
#endif
#ifndef ONODE_PROPOSAL_BURST
#define ONODE_PROPOSAL_BURST       20
#endif
#ifndef ONODE_PROPOSAL_WINDOW_SEC
#define ONODE_PROPOSAL_WINDOW_SEC  60
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
    ONODE_ACTION_LIST_SESSIONS = 18, /* Enumerate chain sessions (read-only listing) */
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
    uint64_t    read_generation;     /* Serializes freshness against later reads */
    time_t      last_read_success;   /* Successful signed GREEN read; not login */
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
     * Observation-signing keypair (wire version 3). OPTIONAL. Loaded
     * from -O (virp-onode-prod). Two uses: verifying v3 observation
     * bodies submitted to CHAIN_APPEND — when it is not loaded, v3 bodies
     * are REFUSED rather than recorded unverified — and, under -3,
     * signing execute observations.
     *
     * It is its OWN key (security review M21). It used to have to be the
     * chain-signing key (-S): the daemon loaded it from that file and
     * refused v3 unless the two public halves matched, so one Ed25519
     * key vouched for both chain entries and device observations. -O
     * names a separate file; -3 without -O still falls back to the -S
     * key, with a warning, so an existing unit keeps starting.
     */
    virp_obskey_t       obskey;
    bool                obskey_loaded;
    bool                execute_v3; /* opt-in -3; needs a signed chain (-S)
                                       and an observation key (-O, or the
                                       -S key as a deprecated fallback) */

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

    /*
     * Persisted v1 sequence high-water (security review M20).
     *
     * seq_num is the sequence in every O-Key-signed (v1) message, and a
     * receiver's replay check is "higher than the last one I accepted
     * from this node". It started at zero on every start, so after a
     * restart the daemon re-issued numbers it had already used: a strict
     * receiver rejected fresh observations as replays, and a lenient one
     * could be handed an old observation in place of a new one bearing
     * the same number.
     *
     * When seq_store_path is set (onode_set_seq_store) the daemon keeps
     * a durable RESERVATION ahead of what it hands out: seq_reserved is
     * the highest number the file on disk covers, and it is extended by
     * ONODE_SEQ_RESERVE_BLOCK, durably, BEFORE any number above it is
     * issued. After a crash the daemon resumes above the reservation —
     * skipping at most one block, never repeating. A clean shutdown
     * writes the exact high-water, so a normal restart leaves no gap.
     * Empty path = no persistence (the mock/dev binaries): the sequence
     * then starts at zero each run, as before.
     */
    char                seq_store_path[256];
    uint32_t            seq_reserved;
    bool                seq_store_failed;   /* a reservation could not be
                                               made durable; logged once */

    /* Single-instance lock (M20): an exclusive flock on
     * "<socket_path>.lock", taken in onode_start() before the stale
     * socket is unlinked and held until onode_destroy(). -1 = not held. */
    int                 lock_fd;

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
     * Per-uid gate policy (optional). An explicit row overrides the
     * node-wide gate_max_tier and may raise or lower it. A row is GREEN,
     * YELLOW or RED. BLACK is NOT a ceiling: the per-uid BLACK
     * passthrough is retired — onode_set_uid_ceilings() rejects it, the
     * production loader refuses a config that asks for it, and BLACK is
     * refused by the gate unconditionally, whatever the ceiling.
     * Without a row, callers use the node-wide default. The production
     * config loader requires every allowed UID to have a row when this
     * map is present. This policy authenticates a Unix UID, not human
     * presence. The caller UID is passed explicitly through batch workers.
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
    virp_policy_t       *policy; /* owner-controlled production boundary */
    bool                evidence_degraded;

#ifdef VIRP_FAULT_INJECT
    /*
     * LAB-ONLY fault injection (Sep 1 review, Phase 1 item 6). Compiled
     * ONLY under -DVIRP_FAULT_INJECT, exactly like the VIRP_FI() crash
     * points (include/virp_fault_inject.h): the production daemon has no
     * such field and no way to set it. `evidence_fail_closer_once` makes
     * the next closer append (gate_execution / outcome) report failure
     * without appending, modelling a chain that goes read-only in the
     * window after the intent committed and the device acted.
     * `evidence_ttl_now_override_ns`, when non-zero, is the clock the
     * apply-time TTL re-check uses instead of CLOCK_REALTIME, so a test
     * can make an approval expire "during connect" deterministically.
     */
    bool                evidence_fail_closer_once;
    uint64_t            evidence_ttl_now_override_ns;
#endif

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
     * WHO BOUND THE SESSION (security review M19), under session_mutex.
     *
     * The daemon holds one session, and it was nobody's in particular:
     * any allowed uid could close it, and any allowed uid's v2/v3
     * execute rode on it. So uid B could end uid A's session whenever
     * it liked, and B's observations were signed under the session A
     * negotiated and counted against A's sequence numbers — A's replay
     * window advanced by requests A never made.
     *
     * SESSION_BIND records the peer uid here. While it is set, only
     * that uid may close the session or have a v2/v3 observation signed
     * under it; anyone else is told SESSION_INVALID / ACTION_FORBIDDEN
     * exactly as if they had no session, which they do not.
     *
     * `session_owner_generation` is the session generation the owner
     * record belongs to. A session that idles out and is re-established
     * by a path that does not go through the socket handler (tests bind
     * the context directly) has a different generation, and the stale
     * owner record must not be enforced against it: ownership applies
     * only while owner_set && generation matches.
     */
    bool                session_owner_set;
    uid_t               session_owner_uid;
    uint64_t            session_owner_generation;

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
    atomic_bool         watchdog_running;

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

    /*
     * Live workers per peer uid (M14), under state_mutex. A slot is
     * claimed by onode_worker_admit() at accept and returned by
     * onode_worker_release() when the worker ends; a slot whose count is
     * zero is free for another uid. Sized by the pool, not by the
     * allowlist: at most ONODE_MAX_WORKERS workers are live, so at most
     * that many distinct uids can hold one.
     */
    struct {
        uid_t       uid;
        uint32_t    live;
    }                   worker_uid_live[ONODE_MAX_WORKERS];
    uint32_t            workers_rejected_uid_cap;

    /*
     * Client I/O bounds in milliseconds (M14). onode_init() sets them
     * from ONODE_RECV_TIMEOUT_SEC / ONODE_SEND_TIMEOUT_SEC; they are
     * fields rather than constants only so a test can shorten them.
     *   request_deadline_ms  ONE absolute deadline for receiving a whole
     *                        request frame. It used to be a per-recv()
     *                        timeout, which a peer sending one byte every
     *                        few seconds never tripped.
     *   send_timeout_ms      SO_SNDTIMEO on the client socket: a peer
     *                        that stops reading is abandoned instead of
     *                        pinning its worker until restart.
     */
    uint32_t            request_deadline_ms;
    uint32_t            send_timeout_ms;

    /*
     * Per-uid verify accounting (M15), under state_mutex. `in_flight`
     * is set between onode_verify_enter() and onode_verify_leave();
     * `used_ms` is the verify time charged in the window that began at
     * `window_start_ms` (CLOCK_MONOTONIC). A slot with used_ms == 0 and
     * nothing in flight is free. Sized by the worker pool: at most that
     * many distinct uids can be mid-request.
     */
    struct {
        uid_t       uid;
        bool        in_use;
        bool        in_flight;
        int64_t     window_start_ms;
        int64_t     used_ms;
    }                   verify_uid[ONODE_MAX_WORKERS];

    /*
     * Proposal dedupe and rate limit (M16). proposal_mutex is held
     * across "is there an open proposal for this key?" and the filing
     * that follows, so two identical refusals arriving together still
     * file exactly one proposal. It is taken with no other daemon lock
     * held and only ever wraps approval-store and chain calls.
     * proposal_cache is a ring (proposal_cache_next is the slot to
     * overwrite); proposal_uid counts new proposals per uid per window.
     * In memory only: after a restart the first repeat of an open
     * proposal files one more, then dedupes again.
     */
    pthread_mutex_t     proposal_mutex;
    struct {
        bool        in_use;
        char        device[64];
        char        command_hash[65];
        char        proposer[64];
        char        proposal_id[33];
    }                   proposal_cache[ONODE_PROPOSAL_CACHE];
    size_t              proposal_cache_next;
    struct {
        uid_t       uid;
        bool        in_use;
        int64_t     window_start_ms;
        uint32_t    filed;
    }                   proposal_uid[ONODE_MAX_WORKERS];

    /*
     * Shutdown request (security review M18).
     *
     * `running` is ATOMIC: it is cleared by onode_shutdown(), which runs
     * in a signal handler (SIGINT/SIGTERM in both mains) and on a worker
     * thread (ONODE_ACTION_SHUTDOWN), and read by the accept loop on the
     * main thread. A plain bool written from a handler is a data race
     * and, for a signal handler, undefined behaviour.
     *
     * `wake_fd` is an eventfd the accept loop's select() watches.
     * Clearing a flag does not interrupt a select() that is already
     * blocked: a signal did so only when it happened to be delivered to
     * the main thread, and a shutdown REQUEST over the socket never did
     * — the loop noticed at its next heartbeat timeout, up to
     * ONODE_HEARTBEAT_SEC later. onode_shutdown() writes to the eventfd
     * (write(2) is async-signal-safe) and the loop returns at once.
     * Created in onode_init(), closed in onode_destroy(); `wake_ready`
     * guards a state that never went through onode_init().
     */
    atomic_bool         running;
    /* Latched by onode_shutdown() and never cleared: a request that
     * arrives BEFORE onode_start() has entered its loop (a signal during
     * startup) must not be lost when onode_start() then sets `running`.
     * onode_start() honours it and returns without serving. */
    atomic_bool         shutdown_requested;
    int                 wake_fd;
    bool                wake_ready;
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

    /*
     * Per-uid chain_append TYPE policy (v0.2.1). A uid that may
     * chain_append is restricted to the artifact types named here, and
     * to nothing else. This REPLACES the v0.2.0 inference that any uid
     * with an action map was a federated principal narrowed to fed_*:
     * that conflated "has an action map" (which Task 2 makes mandatory
     * for every allowlisted uid) with "is a restricted federated
     * principal", so mapping the local service accounts (999 autopilot,
     * 997 config-backup, 995 evidence) — which Task 2 requires — silently
     * refused their legitimate observation/evidence_item/no_drift
     * appends. The fed_* narrowing for the netclaw bridge (993) is now
     * one ROW of this policy, not a code path. Boot invariant
     * (onode_start): any allowlisted uid whose action set includes
     * chain_append MUST have an entry here, or the daemon refuses to
     * start naming the uid. Parsed from the config's
     * socket_uid_chain_append_types object (uid -> [type, ...]). A uid
     * absent here is unrestricted by this policy (the self-seeded default
     * only; every mapped uid is covered by the boot invariant).
     */
    uid_t               uid_capp_uids[ONODE_MAX_ALLOWED_UIDS];
    char                uid_capp_types[ONODE_MAX_ALLOWED_UIDS]
                                      [ONODE_MAX_UID_CAPP_TYPES]
                                      [ONODE_CHAIN_TYPE_MAX];
    size_t              uid_capp_type_counts[ONODE_MAX_ALLOWED_UIDS];
    size_t              uid_capp_count;
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
 * Persist the v1 sequence high-water at `path` (M20). Call after
 * onode_init and before onode_start. Loads the stored value, resumes the
 * sequence above it and makes the first reservation durable. Fails —
 * and the caller should refuse to start — if the file exists but is not
 * a number, or the reservation cannot be written: a daemon that cannot
 * remember its sequence would silently reuse numbers after the next
 * restart. A missing file is a first run and starts at zero.
 */
#define ONODE_SEQ_RESERVE_BLOCK 1024u
virp_error_t onode_set_seq_store(onode_state_t *state, const char *path);

/*
 * Add a device to the O-Node's inventory.
 *
 * Refused with VIRP_ERR_INVALID_LENGTH when the hostname fails the
 * chain's canonical-string check or is long enough that a chain session
 * id derived from it ("gate-separator:<host>", "gate-enforce:<host>
 * [@<epoch>]") would not fit virp_chain_entry_t.session_id: 48 bytes
 * with no native epoch, down to 33 with a 16-character one. onode_start()
 * repeats the length check once the epoch is final. Also refused:
 * node_id 0, the reserved hostname "_unknown", and any hostname, node_id
 * or device_id already loaded (VIRP_ERR_DUPLICATE_DEVICE).
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
 * Per-uid worker accounting (M14). onode_worker_admit() returns false —
 * and counts nothing — when `uid` already holds
 * ONODE_MAX_WORKERS_PER_UID workers; otherwise it claims one and returns
 * true, and the caller owes exactly one onode_worker_release(uid). The
 * accept loop calls admit before spawning and the worker (or the
 * spawn-failure path) calls release. Exposed so the cap can be tested
 * without a listening socket.
 */
bool onode_worker_admit(onode_state_t *state, uid_t uid);
void onode_worker_release(onode_state_t *state, uid_t uid);

/*
 * Per-uid verify limiter (M15). onode_verify_enter() returns false when
 * `uid` already has a verify in flight or has spent its budget for the
 * current window; otherwise it marks one in flight and returns true, and
 * the caller owes exactly one onode_verify_leave(uid, elapsed_ms) with
 * the time the verify took. `now_ms` is CLOCK_MONOTONIC milliseconds,
 * passed in so the window arithmetic can be tested without sleeping.
 */
bool onode_verify_enter(onode_state_t *state, uid_t uid, int64_t now_ms);
void onode_verify_leave(onode_state_t *state, uid_t uid, int64_t elapsed_ms);

/*
 * Signal the O-Node to shut down gracefully.
 *
 * ASYNC-SIGNAL-SAFE, and that is a contract, not an accident (M18): it
 * does two lock-free atomic stores and one write(2) to an eventfd, and
 * preserves errno. No stdio, no locks, no allocation. Both mains call it
 * straight from their SIGINT/SIGTERM handlers, and the handler does
 * nothing else. Also safe from any thread. Idempotent.
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
 * NOTE (2026-09-08): onode_execute() and onode_execute_obs() are GONE.
 *
 * Both were thin wrappers that forwarded to onode_execute_obs_ex() with
 * client_uid hardcoded to (uid_t)-1. onode_effective_max_tier() returns the
 * node-wide gate_max_tier immediately for that sentinel, so any caller of a
 * wrapper silently escaped the per-uid tier ceiling. That is not a property
 * you want reachable by accident: it cost a live ceiling bypass on the
 * ONODE_ACTION_HEALTH path, found on 10.0.10.211 2026-09-07.
 *
 * onode_execute_obs_ex() is now the only entry point, and it takes the uid as
 * a required argument. Pass a real one. If a caller genuinely has no client
 * identity it must say so explicitly at its own call site and justify it
 * there, not inherit it from a convenience wrapper.
 */

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
 * to select that uid's tier ceiling (onode_effective_max_tier: an explicit
 * per-uid row decides, tighter or looser; otherwise the node-wide one).
 * Pass (uid_t)-1 for internal / non-socket callers, which then get only
 * the node-wide gate_max_tier. The socket handler and the batch fan-out both
 * pass the real peer uid.
 */
/*
 * onode_apply_obs — APPLY as a daemon request (store split, 2026-09-05).
 *
 * The caller names ONLY a proposal_id. The daemon resolves `device` and
 * `command` from its OWN approval store and then runs the unchanged
 * execute path with the approval reference.
 *
 * This exists because `virp approve` reached the store through the socket
 * while `virp apply` read the directory directly, so approve succeeded as
 * uid 1000 where apply could not — the `sudo -u virp` requirement, and
 * half of why a failed apply burned an approval on 2026-09-05.
 *
 * It also removes device/command from the client's influence entirely:
 * the daemon no longer reads either field from the requester on this
 * path. Nothing else changes — signature, command-hash, device binding,
 * TTL, liveness and single-use consume all run exactly as before.
 *
 * Returns the LOAD failure directly when the proposal cannot be resolved,
 * so the three causes stay distinguishable to the operator:
 *   VIRP_ERR_APPROVAL_STORE_ABSENT     (-56) wrong host
 *   VIRP_ERR_APPROVAL_NOT_FOUND        (-41) wrong proposal id
 *   VIRP_ERR_APPROVAL_STORE_UNREADABLE (-52) wrong uid
 */
virp_error_t onode_apply_obs(onode_state_t *state,
                             const char *proposal_id,
                             uint8_t obs_version,
                             uid_t client_uid,
                             uint8_t *out_buf, size_t out_buf_len,
                             size_t *out_len);

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
 * Set per-uid tier ceilings. `uids[i]` is capped at `tiers[i]`, which
 * must be GREEN, YELLOW or RED. UNCLASSIFIED and BLACK are rejected with
 * VIRP_ERR_INVALID_TYPE and nothing is installed: the BLACK passthrough
 * is retired and no ceiling can confer BLACK authority. Explicit rows
 * override the node-wide gate_max_tier in both directions.
 * Replaces any existing entries. Returns
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
 * Per-uid chain_append TYPE allowlist (v0.2.1). `types`/`count` name the
 * ONLY artifact types this uid may chain_append; each is copied (and
 * truncated to the 16-byte artifact_type field width the wire uses).
 * count == 0 is a valid deny-all-types entry. Returns
 * VIRP_ERR_MESSAGE_TOO_LARGE when count exceeds ONODE_MAX_UID_CAPP_TYPES
 * or the table is full. A uid never passed here has NO type policy and is
 * unrestricted by it (see the onode_start boot invariant, which forbids
 * that for any allowlisted uid whose action set includes chain_append).
 */
virp_error_t onode_set_uid_chain_append_types(onode_state_t *state, uid_t uid,
                                              const char *const *types,
                                              size_t count);
void onode_clear_uid_chain_append_types(onode_state_t *state);

/* True iff `uid` has an explicit chain_append type policy. */
bool onode_uid_has_capp_policy(const onode_state_t *state, uid_t uid);
/* True iff `uid` may chain_append `artifact_type` under its policy. Only
 * meaningful when onode_uid_has_capp_policy() is true. */
bool onode_uid_capp_type_allowed(const onode_state_t *state, uid_t uid,
                                 const char *artifact_type);
/* True iff `uid`'s action set includes `action` (used by the boot
 * invariant to find uids that may chain_append). */
/* The build id this binary was compiled from, as a generated translation
 * unit (build/virp_build_id.c from scripts/gen-build-id.sh), NOT a macro.
 * v0.2.0 reported build_id="unknown" because -DVIRP_BUILD_ID was placed on
 * the prod compile line while the code that used it lived in libvirp.a,
 * compiled without the define. A function every consumer links cannot go
 * silently missing the way a per-TU macro can. */
const char *virp_build_id(void);

bool onode_uid_action_set_has(const onode_state_t *state, uid_t uid,
                              onode_action_t action);

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
 * Autopilot hard exclusions: an address on the daemon's blocklist must
 * never appear in a device config. The PRODUCTION list has been empty
 * since 2026-09-08 (it held 10.0.10.1 and 10.0.10.10; see the note on
 * ONODE_BLOCKED_ADDRS in virp_onode.c), so today this returns NULL for
 * every input — the check and its severity are kept so re-arming is a
 * one-line change. Boundary-aware scan of raw config text (so
 * 10.0.10.12 / 10.0.10.100 would not false-positive on 10.0.10.1). Returns the blocked
 * address (static string) on a hit, NULL when clean. The file variant
 * reads up to 1 MiB of `path`; unreadable files return NULL — the
 * loader's own error handling covers those. Every config loader MUST
 * call one of these and refuse to start on a hit.
 */
const char *virp_config_blocked_address(const char *text);

/* Same boundary-aware scan against a caller-supplied list. Exposed so the
 * matcher stays testable when the production list is empty; production
 * callers want virp_config_blocked_address() above. */
const char *virp_config_blocked_address_in(const char *text,
                                           const char *const *addrs,
                                           size_t n_addrs);
const char *virp_config_file_blocked(const char *path);

/*
 * Fuzz entry point for the internal JSON request parser. Intended for
 * test harnesses — production callers should not use this. Never
 * crashes regardless of input; returns true iff the input parsed into
 * a valid request.
 */
bool onode_parse_request_fuzz(const uint8_t *data, size_t n);

#endif /* VIRP_ONODE_H */
