/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Device Driver Interface
 *
 * This is the abstraction boundary between VIRP and vendor hardware.
 * The O-Node doesn't know what a FortiGate is. It doesn't know what
 * IOS is. It calls driver functions. Adding Juniper means writing a
 * JunOS driver. The protocol never changes.
 *
 * Every driver implements this interface. Nothing else.
 */

#ifndef VIRP_DRIVER_H
#define VIRP_DRIVER_H

#include "virp.h"
#include <stddef.h>
#include <stdbool.h>

/* =========================================================================
 * Driver Identification
 * ========================================================================= */

#define VIRP_DRIVER_NAME_MAX    32
#define VIRP_DRIVER_MAX         16      /* Max registered drivers */

typedef enum {
    VIRP_VENDOR_UNKNOWN     = 0,
    VIRP_VENDOR_CISCO_IOS   = 1,
    VIRP_VENDOR_FORTINET    = 2,
    VIRP_VENDOR_LINUX       = 3,
    VIRP_VENDOR_JUNIPER     = 4,
    VIRP_VENDOR_PALOALTO    = 5,
    VIRP_VENDOR_WINDOWS     = 6,
    VIRP_VENDOR_PROXMOX     = 7,
    VIRP_VENDOR_CISCO_ASA   = 8,
    VIRP_VENDOR_WAZUH       = 9,
    VIRP_VENDOR_CISCO_IOSXE = 10,  /* Cisco IOS-XE (Catalyst/ISR-XE); shares the cisco driver + gate core */
    VIRP_VENDOR_LIBRENMS    = 11,  /* LibreNMS REST API (token auth) */
    VIRP_VENDOR_PBS         = 12,  /* Proxmox Backup Server (typed ops, pinned TLS) */
    VIRP_VENDOR_ZAMMAD      = 13,  /* Zammad REST API (personal access token) */
    VIRP_VENDOR_MOCK        = 99,   /* Testing only */
} virp_vendor_t;

/*
 * Trust tier type — used by vendor-specific drivers (FortiGate, Cisco)
 * for command routing tables. Maps to VIRP_TIER_* constants in virp.h.
 */
typedef uint8_t virp_trust_tier_t;

/* =========================================================================
 * Connection Handle
 *
 * Opaque per-connection state. Each driver defines its own internal
 * structure (SSH session, API token, etc). The O-Node only sees this
 * opaque pointer.
 * ========================================================================= */

typedef struct virp_conn virp_conn_t;

/* =========================================================================
 * Device Descriptor
 *
 * Everything the O-Node needs to know about a device to connect to it.
 * Loaded from configuration (customer.yaml equivalent).
 * ========================================================================= */

typedef struct {
    char            hostname[64];
    char            host[256];          /* IP or FQDN */
    uint16_t        port;               /* SSH port, API port, etc */
    char            username[64];
    char            password[128];      /* TODO: move to vault/keyring */
    char            enable_password[128];
    virp_vendor_t   vendor;
    uint32_t        node_id;            /* VIRP node ID for this device */
    /*
     * Stable 64-bit device identity carried in v2 observation headers.
     * Loaded from devices.json ("device_id", hex string or int); when
     * the config omits it, load_devices() derives it deterministically
     * as the first 8 bytes (big-endian) of SHA-256(hostname) via
     * virp_device_id_from_hostname(). Unlike node_id (32-bit routing
     * id), device_id never collides with wire routing concerns and is
     * what virp_verify_observation_v2() binds against.
     */
    uint64_t        device_id;
    bool            enabled;
    /* Vendor-optional (FortiGate) — zero-initialized for other vendors */
    char            api_token[256];     /* REST API Bearer token */
    uint16_t        api_port;           /* REST API port (default 443) */
    char            vdom[64];           /* VDOM name (default "root") */
    bool            verify_tls;         /* Verify TLS cert on REST calls */
    bool            ssh_legacy;         /* Force legacy SSH ciphers (group14-sha1, ssh-rsa, aes256-cbc) */
    /*
     * Vendor-optional (PBS) — zero-initialized for other vendors.
     *
     * tls_fingerprint: SHA-256 fingerprint of the server's leaf
     * certificate, colon-separated or bare hex. For the PBS driver this
     * is the server's identity and is MANDATORY: pbs_connect() refuses
     * without it, and that driver has no insecure/skip-verify mode to
     * fall back to. Not a `verify_tls`-style boolean on purpose — a
     * boolean can be set to false, a fingerprint can only be right.
     *
     * datastore_allow: comma-separated datastore names accepted for
     * op=backup.snapshots.list. The typed-op grammar constrains the
     * SHAPE of a parameter; this constrains its VALUE to what the
     * operator enumerated for this device.
     */
    char            tls_fingerprint[128];
    char            datastore_allow[256];
    /*
     * Vendor-optional (Zammad) — zero-initialized for other vendors.
     *
     * write_ops_allow: comma-separated typed-operation ids this DEVICE
     * may execute as a write. Empty (the default, and the case for every
     * device that never names it) means NO write operation is permitted
     * on this device, which is why omitting the field is safe.
     *
     * Same split as PBS's datastore_allow, for the same reason: the gate
     * hook receives no device context, so it can only judge the COMMAND.
     * "is this operation allowed against this particular credential" is a
     * property of the device, not of the command bytes, so it has to be
     * enforced in the driver. Two Zammad entries point at the same host —
     * zammad-ro with a read-only token and no write_ops_allow, zammad-rw
     * with a write-capable token and exactly one op id — and the ONLY
     * thing that makes them different is this field plus the token behind
     * them.
     */
    char            write_ops_allow[256];
    /*
     * tls_servername: the name the server's certificate is issued for,
     * when that differs from `host`.
     *
     * Needed because certificate pinning does NOT subsume hostname
     * verification in libcurl. curl performs the name check separately
     * from the certificate-verify callback, so a correct pin still fails
     * with "no alternative certificate subject name matches target host
     * name" when `host` is an IP the certificate does not cover — which
     * is the normal case for a self-signed PBS certificate.
     *
     * When set, the driver connects to `host` but presents/validates
     * this name (SNI + CURLOPT_RESOLVE). Hostname verification stays ON
     * and genuinely passes, rather than being switched off to work
     * around the mismatch. Empty = use `host` unchanged.
     */
    char            tls_servername[256];
    /*
     * Vendor-optional (Proxmox-on-linux) — zero-initialized elsewhere.
     *
     * protected_vmids: comma-separated decimal VMIDs on THIS host that
     * the gate refuses to touch at any tier — in practice, the guest the
     * O-Node itself runs in. `qm stop 313` is an ordinary bounded action
     * on any other guest and is the gate switching itself off on that
     * one, and no tier arithmetic downstream can tell the two apart.
     *
     * Loaded from devices.json as a JSON array ("protected_vmids":
     * [313]) or as an equivalent comma-separated string, and normalized
     * to CSV here to match datastore_allow / write_ops_allow. Absent →
     * empty → the linux classifier refuses every VMID-bearing Proxmox
     * command rather than treating "nobody said 313 was special" as
     * "313 is not special" (see driver_linux.c's Proxmox table).
     *
     * Unlike write_ops_allow this cannot be enforced from the device
     * struct at execute time: the refusal has to happen in the
     * classifier, before a tier exists to be outranked. The loader
     * therefore registers the value into the linux gate's union registry
     * at startup — see linux_gate_set_protected_vmids().
     */
    char            protected_vmids[256];
} virp_device_t;

/* =========================================================================
 * Execution Result
 *
 * What comes back from running a command on a device.
 * The driver fills this in. The O-Node wraps it in a VIRP OBSERVATION.
 * ========================================================================= */

#define VIRP_OUTPUT_MAX     65536   /* 64KB max output per command */

/*
 * How an execution TERMINATED — the only honest basis for claiming a device
 * did or did not run a command.
 *
 * The bug this exists to kill (reproduced against a real device 2026-08-05,
 * TRANSCRIPT-05): libssh2_channel_get_exit_status() returns 0 both for a
 * genuine exit-0 AND when the peer never sent an exit-status message at all,
 * which is exactly what an abnormally-killed channel produces. Deriving
 * success from that alone signed aborted commands into the chain as
 * success=true — a false attestation.
 *
 * The discriminator is HOW the completion sequence ended, never how many
 * bytes came back. Output length must play NO part in this decision: the
 * linux driver seeds its buffer with a "<host>$ <cmd>\n" prefix before
 * reading, so an output-length test is always false and silently dead.
 */
typedef enum {
    /*
     * Driver has not been converted to the classifier. Legacy success
     * semantics apply, unchanged. This is the zero value ONLY so that
     * unconverted drivers keep their existing behaviour rather than being
     * mass-reclassified as UNKNOWN — converting the remaining drivers is
     * deliberately out of scope here. A converted driver must set a real
     * disposition on every return path.
     */
    VIRP_DISPOSITION_UNSET              = 0,
    /* Bytes provably never dispatched (pre-dispatch failure). Retryable. */
    VIRP_DISPOSITION_NOT_SENT           = 1,
    /* Clean, complete close AND a trustworthy exit status of 0. */
    VIRP_DISPOSITION_EXECUTED_CONFIRMED = 2,
    /* Clean, complete close AND a trustworthy non-zero exit (or a signal). */
    VIRP_DISPOSITION_EXECUTED_FAILED    = 3,
    /*
     * Dispatched, but the channel never closed cleanly / no exit status was
     * received. The command MAY have executed. Never success, never retried.
     */
    VIRP_DISPOSITION_EXECUTED_UNKNOWN   = 4,
} virp_disposition_t;

const char *virp_disposition_str(virp_disposition_t d);

typedef struct {
    char        output[VIRP_OUTPUT_MAX];
    size_t      output_len;
    bool        success;
    int         exit_code;              /* Meaningful for Linux, 0/1 for network */
    char        error_msg[256];         /* Human-readable error if !success */
    uint64_t    exec_time_ms;           /* Execution time in milliseconds */
    /*
     * Termination classification. success == true is permitted ONLY for
     * VIRP_DISPOSITION_EXECUTED_CONFIRMED.
     */
    virp_disposition_t disposition;
    /*
     * exit_code carries a status the peer actually reported. False means the
     * peer never reported one — do NOT read exit_code at all in that case,
     * and in particular do not treat 0 as success or non-zero as failure.
     */
    bool        exit_code_trusted;
    /*
     * Output stopped because the capture buffer filled, not because the
     * device finished. The body is a PREFIX of the real output and must
     * never be presented as a complete response.
     */
    bool        output_truncated;
    /*
     * no_dispatch — the driver PROVES that no part of the command was
     * sent toward the device: the failure happened strictly before the
     * first transport write of the command (not-connected refusal,
     * pre-I/O validation, channel that never opened, TLS pin rejected
     * before the request went out). This is the O-Node's ONLY license
     * to auto-retry a failed execute: absence of a response is not
     * absence of a side effect, so a failure the driver cannot prove
     * non-dispatched must never be re-executed (authorized once,
     * executed twice). Zero-initialized false = "cannot prove" = no
     * retry — a driver that never sets it loses retry, never safety.
     */
    bool        no_dispatch;
} virp_exec_result_t;

/* =========================================================================
 * Driver Operations
 *
 * Every driver implements these five functions. That's it.
 * No optional methods. No inheritance. Five function pointers.
 * ========================================================================= */

typedef struct virp_driver {
    /* Identity */
    char            name[VIRP_DRIVER_NAME_MAX];
    virp_vendor_t   vendor;

    /*
     * connect — establish a session to the device.
     * Returns an opaque connection handle, or NULL on failure.
     * The driver owns the connection memory.
     */
    virp_conn_t *(*connect)(const virp_device_t *device);

    /*
     * execute — run a command and return the output.
     * The command is a single string (e.g., "show ip route").
     * Result is written into the caller-provided result struct.
     * Returns VIRP_OK on success (even if the command itself failed —
     * check result->success for command-level success).
     */
    virp_error_t (*execute)(virp_conn_t *conn,
                            const char *command,
                            virp_exec_result_t *result);

    /*
     * disconnect — close the session and free all resources.
     * Must be safe to call on a NULL conn (no-op).
     */
    void (*disconnect)(virp_conn_t *conn);

    /*
     * detect — given a connection, determine if this driver can
     * handle the device. Used for auto-detection.
     * Returns true if this driver matches the device.
     */
    bool (*detect)(virp_conn_t *conn);

    /*
     * health_check — verify the device is responsive.
     * Returns VIRP_OK if healthy.
     */
    virp_error_t (*health_check)(virp_conn_t *conn);

    /*
     * route_command — OPTIONAL classifier for the O-Node's Phase-B
     * tier-enforcement gate. Given a command string, return its trust
     * tier (GREEN/YELLOW/RED, or BLACK for tables that carry it).
     *
     * Drivers that ship a classifier table set this pointer. Drivers
     * without one leave it NULL (designated initializers zero-fill it),
     * which the gate treats as VIRP_TIER_UNCLASSIFIED — i.e. fail
     * closed. Must be read-only and side-effect free.
     */
    virp_trust_tier_t (*route_command)(const char *command);

    /*
     * route_reason — OPTIONAL companion to route_command. For commands
     * whose classification carries an instructive rejection reason
     * (e.g. "configuration change — use propose/approve/apply"), return
     * a pointer to a static string; return NULL for rows that take the
     * gate's generic rejection message. The gate appends the reason to
     * the signed ERROR observation payload so a refused caller learns
     * the escalation path instead of just the tier arithmetic. Same
     * contract as route_command: read-only, side-effect free, and the
     * returned pointer must remain valid forever (string literal).
     */
    const char *(*route_reason)(const char *command);

    /*
     * route_rule — OPTIONAL companion to route_command: the identifier
     * of the classifier rule that decided this command's tier (e.g.
     * "yellow:show-running-config", "red:canon-ambiguous"). The gate
     * stamps it into the [GATE] journal line and the gate_rejection
     * chain body so every recorded decision names the rule that fired.
     * Same contract as route_reason: read-only, side-effect free,
     * static strings only. Never NULL for a driver that sets the hook —
     * a classifier that can decide a tier can always name why.
     */
    const char *(*route_rule)(const char *command);

    /*
     * canon_command — OPTIONAL command canonicalizer. When set, the
     * O-Node calls it ONCE at the request boundary, before
     * classification; on success (return >= 0, canonical string in
     * out) the canonical string REPLACES the submitted one for
     * everything downstream: classification, approval propose/apply
     * hashing, execution, and the signed v2 command hash. Two
     * spellings of one device command thus produce one classification,
     * one rule, one hash identity — and the invariant "the classified
     * bytes are the executed bytes" holds because both are the
     * canonical bytes.
     *
     * On failure (return < 0: ambiguous abbreviation, unrecognized
     * token, illegal separator) the daemon keeps the RAW bytes; the
     * driver's route_command must fail closed on them. A driver that
     * sets this hook is declaring that its device treats the canonical
     * and submitted spellings as the SAME command (IOS prefix
     * expansion): only under that property is executing the expansion
     * honest. Drivers that execute the caller's original bytes leave
     * this NULL and keep case-sensitive, abbreviation-free tables
     * (the 2026-08-09 rule).
     */
    int (*canon_command)(const char *command, char *out, size_t out_cap);

    /*
     * classifier_version — OPTIONAL static identifier of the
     * classifier rule set (e.g. "ios-canon/1"), stamped alongside
     * route_rule output in the journal and rejection records so an
     * audit can tie a decision to the table that produced it. Bump on
     * any change to classification meaning. NULL = unversioned.
     */
    const char *classifier_version;

    /*
     * typed_profile — OPTIONAL. Non-NULL declares that this driver's
     * commands are a TYPED-OPERATION PROFILE (see
     * docs/DRIVER-TYPED-OPS.md), not a CLI string, and selects the
     * exact-octet command hash instead of the generic canonicalizing
     * one.
     *
     * Why this is a driver DECLARATION and not a property sniffed from
     * the command text: sniffing would make the hash algorithm depend on
     * attacker-influenced bytes, so a crafted command could choose which
     * hash it is bound under. The driver owns the answer, statically.
     *
     * The value is the profile identifier bound into the hash; change it
     * only alongside a protocol version bump, because it changes every
     * command hash this driver produces.
     *
     * Drivers whose commands ARE CLI strings leave this NULL (designated
     * initializers zero-fill it) and keep the historic behaviour.
     */
    const char *typed_profile;

} virp_driver_t;

/* =========================================================================
 * Driver Registry
 *
 * Drivers register themselves at startup. The O-Node looks up drivers
 * by vendor type. Simple array, no dynamic allocation.
 * ========================================================================= */

/*
 * Register a driver. Call during initialization.
 */
virp_error_t virp_driver_register(const virp_driver_t *driver);

/*
 * Look up a driver by vendor type.
 * Returns NULL if no driver registered for that vendor.
 */
const virp_driver_t *virp_driver_lookup(virp_vendor_t vendor);

/*
 * Get count of registered drivers.
 */
int virp_driver_count(void);

/*
 * Deterministic fallback device identity: first 8 bytes of
 * SHA-256(hostname), big-endian. Used when devices.json carries no
 * explicit "device_id" for a device. Stable across restarts, hosts,
 * and rebuilds — it depends only on the hostname string.
 */
uint64_t virp_device_id_from_hostname(const char *hostname);

/* =========================================================================
 * Built-in Drivers (linked at compile time)
 *
 * Each driver provides an init function that registers itself.
 * The O-Node calls these during startup.
 * ========================================================================= */

/* Mock driver for testing — always available */
void virp_driver_mock_init(void);

/*
 * Mock driver test hooks. The shared-channel hook makes the mock behave
 * like a real one-channel-per-session driver: bytes another caller puts
 * on the channel during an execute() read window are read as part of
 * that command's output. Used to test serialization of the watchdog's
 * health_check against in-flight execution.
 */
#define MOCK_HEALTH_PROBE_MARKER  "<<<MOCK-HEALTH-PROBE>>>\n"
void virp_driver_mock_set_shared_channel(bool on);
/* Count health_check() calls for this hostname only (resets the count).
 * Other O-Node instances in the same process run their own watchdogs
 * against their own devices, so an unfiltered count proves nothing. */
void virp_driver_mock_watch_probes(const char *hostname);
int  virp_driver_mock_probe_count(void);
/* Possible-dispatch failure hook (success=false, no output, no_dispatch
 * =false): the O-Node must NOT retry and must report OUTCOME_UNKNOWN.
 * NULL disables. */
void virp_driver_mock_set_unknown_fail(const char *msg);
/* Total execute() invocations since the last reset; resets to zero. */
int  virp_driver_mock_exec_attempts_reset(void);
/* Enable the mock's canon_command hook ("sh ip route" -> "show ip
 * route"; everything else reports no canonical form). Disabled (the
 * default) the hook behaves exactly like an absent hook. */
void virp_driver_mock_set_canon(bool on);

/* Real drivers — conditionally compiled */
#ifdef VIRP_DRIVER_CISCO
void virp_driver_cisco_init(void);
#endif

#ifdef VIRP_DRIVER_FORTINET
void virp_driver_fortinet_init(void);
#endif

#ifdef VIRP_DRIVER_LINUX
void virp_driver_linux_init(void);
#endif

#ifdef VIRP_DRIVER_PALOALTO
void virp_driver_paloalto_init(void);
#endif

#ifdef VIRP_DRIVER_CISCO_ASA
void virp_driver_asa_init(void);
#endif

#ifdef VIRP_DRIVER_WAZUH
void virp_driver_wazuh_init(void);
#endif

#ifdef VIRP_DRIVER_JUNIPER
void virp_driver_juniper_init(void);
#endif

#endif /* VIRP_DRIVER_H */
