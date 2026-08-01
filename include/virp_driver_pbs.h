/*
 * virp_driver_pbs.h — Proxmox Backup Server driver for VIRP
 *
 * FIRST NON-NETWORK DOMAIN, and the reference implementation of TYPED
 * OPERATIONS. Read docs/DRIVER-TYPED-OPS.md before copying this shape.
 *
 * The difference from driver_librenms.c / driver_wazuh.c is the whole
 * point of this driver:
 *
 *   Those drivers take an API PATH as the command. The path is attacker-
 *   shaped input that the driver must sanitize, and the classifier has to
 *   reason about path syntax — prefixes, query strings, segment counts.
 *   The approved object and the wire request are related by parsing.
 *
 *   This driver takes a CANONICAL TYPED-OPERATION ENCODING. The command
 *   string is not a CLI and not a URL; it is an operation id plus named
 *   parameters. Method and URL are derived INSIDE the driver from a
 *   static table, never from input. The approved object therefore fully
 *   determines the request: there is no syntax left for the driver to
 *   interpret, so byte identity and semantic identity coincide by
 *   construction. What was classified, hashed, proposed and chained is
 *   exactly what determines what goes on the wire.
 *
 * GRAMMAR (exact — anything else is refused with a typed signed ERROR
 * before any network activity whatsoever):
 *
 *     pbs op=<operation.id>[ <key>=<value>]...
 *
 *   - literal leading "pbs", one single space between every token
 *   - no leading/trailing space, no runs of spaces, no tabs
 *   - no quoting, no escaping, no free-form text anywhere
 *   - "op" is the first token; remaining keys sort strictly ascending
 *     (strcmp), and every key sorts strictly after "op", so the token
 *     sequence is globally sorted. Future parameters MUST be named to
 *     preserve that (i.e. > "op").
 *   - each key appears at most once
 *   - only the keys the op table declares for that op, all of them
 *
 * Charsets are deliberately narrow. Values admit [A-Za-z0-9._-] only —
 * no '/', '?', '#', '%', ':', space, CR or LF — so a value can never
 * carry a path segment, a query, a URL fragment, a percent-escape, or a
 * header-injection sequence into the derived URL.
 *
 * TRANSPORT: GET only. v1 declares NO write operation at ANY tier. The
 * method lives in the op table as a typed enum whose only value is GET,
 * and the transport re-checks it; there is no code path that can issue
 * anything else.
 *
 * TLS: identity is PINNED to the PBS certificate's SHA-256 fingerprint,
 * supplied per-device in devices.json. The driver refuses to connect
 * without one and verifies it on every connection. There is deliberately
 * NO insecure/skip-verify option in this driver — not a flag, not an
 * environment variable, not a device field. Compare driver_wazuh.c's
 * VIRP_WAZUH_INSECURE, which this driver must never grow.
 *
 * Device config mapping (devices.json):
 *   host              — PBS host/IP
 *   api_port / port   — API port (default 8007)
 *   username          — API token id, "user@realm!tokenid"
 *   api_token         — the token SECRET (rendered from autopilot.env
 *                       into the /run tmpfs copy; never persisted)
 *   tls_fingerprint   — SHA-256 cert fingerprint, colon-separated or
 *                       bare hex, case-insensitive. REQUIRED.
 *   datastore_allow   — comma-separated allowlist of datastore names
 *                       accepted for op=backup.snapshots.list
 *
 * Auth header: Authorization: PBSAPIToken=<user@realm!tokenid>:<secret>
 *
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 */

#ifndef VIRP_DRIVER_PBS_H
#define VIRP_DRIVER_PBS_H

#include "virp_driver.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── PBS-specific error codes (extend virp_error_t range) ─────────── */
#define PBS_ERR_NOT_CONNECTED   ((virp_error_t)(-220))
#define PBS_ERR_AUTH_FAILED     ((virp_error_t)(-221))
#define PBS_ERR_CURL_INIT       ((virp_error_t)(-222))
#define PBS_ERR_CURL_PERFORM    ((virp_error_t)(-223))
#define PBS_ERR_NO_FINGERPRINT  ((virp_error_t)(-224))
#define PBS_ERR_PIN_MISMATCH    ((virp_error_t)(-225))
#define PBS_ERR_GRAMMAR         ((virp_error_t)(-226))
#define PBS_ERR_METHOD          ((virp_error_t)(-227))

/* ── Tunables ─────────────────────────────────────────────────────── */
#define PBS_API_TIMEOUT_SEC     30
#define PBS_CONNECT_TIMEOUT_SEC 10
#define PBS_DEFAULT_PORT        8007
#define PBS_RESPONSE_MAX        (VIRP_OUTPUT_MAX - 512)

#define PBS_OP_ID_MAX           64      /* operation id, incl. NUL      */
#define PBS_KEY_MAX             32      /* parameter key, incl. NUL     */
#define PBS_VALUE_MAX           64      /* parameter value, incl. NUL   */
#define PBS_MAX_PARAMS          4       /* per op, v1 uses at most 1    */
#define PBS_COMMAND_MAX         256     /* whole canonical command      */
#define PBS_FINGERPRINT_BYTES   32      /* SHA-256                      */
#define PBS_MAX_DATASTORES      16

/* ── Method ───────────────────────────────────────────────────────────
 * A typed enum with exactly one value. v1 has no write operation at any
 * tier, so there is no non-GET member for an op row to name or for a
 * bug to select. If a future version adds one, every switch on this type
 * becomes a compile-time review point.
 * ------------------------------------------------------------------- */
typedef enum {
    PBS_METHOD_GET = 1,
} pbs_method_t;

/* ── Op table row ─────────────────────────────────────────────────────
 * `path` and `query` are STATIC string literals. The only substitution
 * is the "{store}" placeholder, replaced with a parameter value that has
 * already passed both the grammar charset and the per-device datastore
 * allowlist. Nothing else about the request derives from input.
 * ------------------------------------------------------------------- */
typedef struct {
    const char        *id;          /* operation id                     */
    pbs_method_t       method;      /* GET, and only GET                */
    const char        *path;        /* may contain the "{store}" token  */
    const char        *query;       /* static query string, or NULL     */
    const char *const *params;      /* NULL-terminated allowed keys     */
    /*
     * MANDATORY, NEVER DEFAULTED. The tier this operation classifies as.
     *
     * The classifier returns THIS value; it does not assume that
     * "parsed successfully" means GREEN. A row added without an explicit
     * tier gets 0 == VIRP_TIER_UNCLASSIFIED from the designated
     * initializer, which fails closed at the gate AND is rejected at
     * driver init by pbs_op_table_validate() — so the failure is loud at
     * startup rather than a silent GREEN.
     *
     * This is the reference-pattern hazard, not a PBS-specific one: the
     * dangerous version of this driver is the one where someone adds a
     * stateful or sensitive GET and it inherits GREEN because nothing
     * made them state a tier.
     */
    virp_trust_tier_t  tier;
} pbs_op_t;

/*
 * Validate the operation table at init. Returns 0 when every row
 * declares a usable tier and method, -1 otherwise (after printing which
 * row is at fault). Exposed for the unit tests.
 */
int pbs_op_table_validate(void);

/*
 * Parse the comma-separated datastore allowlist. ATOMIC: returns the
 * entry count, or -1 loading nothing if ANY entry is malformed,
 * duplicated, over-limit, a dot segment, or carries internal whitespace.
 * A partially-loaded allowlist is a different security control than the
 * one the operator wrote, so the device is refused instead.
 */
int pbs_parse_datastores(const char *csv, char (*out)[PBS_VALUE_MAX],
                         const char *hostname, const char **reason);

/* ── Parsed request ───────────────────────────────────────────────────
 * The whole result of parsing: which op, and its validated parameters.
 * No pointers into the input, no residual syntax.
 * ------------------------------------------------------------------- */
typedef struct {
    const pbs_op_t *op;
    size_t          nparams;
    char            keys[PBS_MAX_PARAMS][PBS_KEY_MAX];
    char            values[PBS_MAX_PARAMS][PBS_VALUE_MAX];
} pbs_request_t;

/* ── Grammar / table API (pure, side-effect free, unit-testable) ───── */

/*
 * Look up an operation by exact id. NULL when the id is not in the
 * table — unknown ops are refused, never guessed at.
 */
const pbs_op_t *pbs_op_lookup(const char *id);

/*
 * Parse a canonical typed-operation command.
 *
 * Returns 0 and fills *out on success. Returns -1 on ANY grammar or
 * table violation and, when `reason` is non-NULL, sets *reason to a
 * static teaching string naming the grammar. Never partially succeeds,
 * never rewrites the input, never falls back to a permissive reading.
 *
 * This runs before any network activity, so every refusal below becomes
 * a typed signed ERROR observation rather than a request.
 */
int pbs_parse_command(const char *command, pbs_request_t *out,
                      const char **reason);

/*
 * Derive the request URL path (path + query) for an already-parsed
 * request. Input never reaches this function except as an allowlisted
 * parameter value substituted into the table's static path.
 *
 * `allow` is the per-device datastore allowlist (NULL/0 = no datastores
 * configured, which refuses any op needing one). Returns 0 on success,
 * -1 on refusal with *reason set.
 */
int pbs_build_path(const pbs_request_t *req,
                   const char (*allow)[PBS_VALUE_MAX], size_t allow_count,
                   char *out, size_t out_len, const char **reason);

/*
 * Parse a SHA-256 certificate fingerprint. Accepts colon-separated or
 * bare hex, upper or lower case. Returns 0 on success (32 bytes written
 * to `out`), -1 on anything malformed.
 */
int pbs_parse_fingerprint(const char *text,
                          unsigned char out[PBS_FINGERPRINT_BYTES]);

/*
 * The transport's method whitelist, as a pure predicate so that "no
 * method but GET can be issued" is a UNIT-TESTABLE claim rather than a
 * property a reader has to establish by inspecting call sites. The
 * transport calls exactly this; so do the tests.
 */
bool pbs_method_is_allowed(int method);

/*
 * Device preconditions, factored out of connect() so the refusals are
 * testable without opening a socket (and therefore without tripping the
 * live-contact fence). Validates that the token, token id and — the
 * important one — the TLS fingerprint are present and well-formed,
 * writing the 32 parsed pin bytes to `pin`.
 *
 * Returns 0 when the device may be connected to, -1 otherwise with
 * *reason set to a static explanation. A device without a usable
 * fingerprint is ALWAYS refused: there is no fallback path.
 */
int pbs_device_precheck(const virp_device_t *device,
                        unsigned char pin[PBS_FINGERPRINT_BYTES],
                        const char **reason);

/* ── Gate hooks ───────────────────────────────────────────────────── */

/*
 * route_command hook. The four v1 operations are GREEN by exact op id;
 * everything else — every unknown op, every grammar violation, every
 * write operation, all of which are deliberately absent from the table
 * — is VIRP_TIER_RED. Fail closed. No YELLOW rows, no BLACK rows, so
 * every RED stays approvable through propose/approve/apply.
 */
virp_trust_tier_t pbs_gate_tier(const char *command);

/*
 * route_reason hook. Returns a static teaching string naming the typed-
 * op grammar for refused commands, or NULL for rows that take the
 * daemon's generic rejection message.
 */
const char *pbs_gate_reason(const char *command);

/* Shared classifier: tier, plus the reason when `reason` is non-NULL. */
virp_trust_tier_t pbs_gate_classify(const char *command, const char **reason);

/* ── Registration ─────────────────────────────────────────────────── */
void virp_driver_pbs_init(void);

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_PBS_H */
