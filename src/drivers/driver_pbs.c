/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Proxmox Backup Server Driver — typed operations over REST
 *
 * First non-network domain through the gate, and the REFERENCE
 * IMPLEMENTATION of typed operations. See virp_driver_pbs.h for the
 * grammar and docs/DRIVER-TYPED-OPS.md for the pattern.
 *
 * The one-line statement of the design: THE APPROVED OBJECT FULLY
 * DETERMINES METHOD AND URL, AND THE DRIVER NEVER PARSES VENDOR SYNTAX.
 * Everything below exists to make that true rather than merely intended.
 *
 * Build:  make PBS=1
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_driver_pbs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

/* =========================================================================
 * Refusal reasons — static teaching strings
 *
 * Every one of these names the typed-op grammar rather than just saying
 * "no", because the caller that got refused is usually a correct caller
 * with a malformed encoding, and the ones that are not correct callers
 * learn nothing from these that the published grammar does not already
 * tell them.
 * ========================================================================= */

static const char REASON_GRAMMAR[] =
    "not a canonical typed operation — the PBS driver accepts exactly "
    "`pbs op=<operation.id> [key=value ...]`: single spaces, no quoting, "
    "no free-form text, keys sorted ascending and each used at most once";
static const char REASON_UNKNOWN_OP[] =
    "unknown operation id — the PBS operation table is closed and RED by "
    "absence; no write operation exists at any tier in v1. Use "
    "op=backup.version.read, backup.datastore.usage, backup.snapshots.list "
    "or backup.verify.tasks";
static const char REASON_UNKNOWN_PARAM[] =
    "parameter not declared for this operation — each op accepts exactly "
    "the keys the operation table names for it, no others";
static const char REASON_DUP_PARAM[] =
    "duplicate parameter — a key may appear at most once, so the canonical "
    "encoding of a request is unique";
static const char REASON_UNSORTED[] =
    "parameters not in ascending key order — the canonical encoding sorts "
    "keys so that byte identity and semantic identity coincide";
static const char REASON_MISSING_PARAM[] =
    "required parameter missing for this operation";
static const char REASON_CHARSET[] =
    "illegal byte in operation id, key or value — values admit only "
    "[A-Za-z0-9._-] so they can never carry a path segment, query, URL "
    "fragment, percent-escape or header-injection sequence";
static const char REASON_STORE_NOT_ALLOWED[] =
    "datastore not in this device's configured allowlist — "
    "op=backup.snapshots.list may only name a datastore enumerated in "
    "devices.json";
static const char REASON_NO_DATASTORES[] =
    "no datastore allowlist configured for this device — "
    "op=backup.snapshots.list cannot be served until devices.json "
    "enumerates the permitted datastores";
static const char REASON_NO_TOKEN[] =
    "no api_token configured for this PBS device";
static const char REASON_NO_TOKENID[] =
    "no username configured for this PBS device — expected the API token "
    "id in the form user@realm!tokenid";
static const char REASON_NO_FINGERPRINT[] =
    "no tls_fingerprint configured for this PBS device — the PBS driver "
    "pins the server certificate and has no insecure mode to fall back to";
static const char REASON_DOT_SEGMENT[] =
    "\".\" and \"..\" are refused as parameter values — a dot segment in a "
    "derived path is removed by the HTTP client before transmission, so the "
    "recorded path would not be the transmitted path";
static const char REASON_NO_TIER[] =
    "operation table row declares no trust tier — refusing to classify it "
    "rather than defaulting to GREEN; every row must state its tier "
    "explicitly (see pbs_op_table_validate)";
static const char REASON_BAD_FINGERPRINT[] =
    "tls_fingerprint is not a SHA-256 fingerprint — expected 32 bytes of "
    "hex, colon-separated or bare";

/* =========================================================================
 * Operation table v1 — all GREEN, exact match
 *
 * Method and URL live HERE, in static storage, and nowhere else. The op
 * id selects a row; the row supplies the method and the path. The only
 * value that flows from input into a URL is a "{store}" substitution
 * that has already passed both the grammar charset and the per-device
 * datastore allowlist.
 *
 * No write operations exist in v1 at any tier. Anything not in this
 * table is RED by absence — including every mutating PBS endpoint, which
 * is deliberately unclassified rather than classified-and-blocked, so a
 * future reviewer sees absence rather than a row to soften.
 *
 * PATHS VERIFIED AGAINST THE RUNNING PBS VERSION — see DEPLOYED.md.
 * Do not edit a path from memory or from documentation for a different
 * PBS major version; re-verify against the live API first.
 * ========================================================================= */

static const char *const PBS_PARAMS_NONE[]  = { NULL };
static const char *const PBS_PARAMS_STORE[] = { "store", NULL };

static const pbs_op_t PBS_OPS[] = {
    {
        .id     = "backup.version.read",
        .method = PBS_METHOD_GET,
        .path   = "/api2/json/version",
        .query  = NULL,
        .params = PBS_PARAMS_NONE,
        .tier   = VIRP_TIER_GREEN,   /* explicit: a read of static
                                      * version/status data */
    },
    {
        .id     = "backup.datastore.usage",
        .method = PBS_METHOD_GET,
        .path   = "/api2/json/status/datastore-usage",
        .query  = NULL,
        .params = PBS_PARAMS_NONE,
        .tier   = VIRP_TIER_GREEN,   /* explicit: a read of static
                                      * version/status data */
    },
    {
        .id     = "backup.snapshots.list",
        .method = PBS_METHOD_GET,
        .path   = "/api2/json/admin/datastore/{store}/snapshots",
        .query  = NULL,
        .params = PBS_PARAMS_STORE,
        .tier   = VIRP_TIER_GREEN,   /* explicit: a read of static
                                      * version/status data */
    },
    {
        /* The verify typefilter is part of the OPERATION, not a caller
         * parameter: "list verify tasks" is the approved thing. Making it
         * a parameter would let an approved op id reach a different task
         * class, which is exactly the input-shapes-the-request property
         * this driver exists to eliminate. */
        .id     = "backup.verify.tasks",
        .method = PBS_METHOD_GET,
        .path   = "/api2/json/nodes/localhost/tasks",
        .query  = "typefilter=verify",
        .params = PBS_PARAMS_NONE,
        .tier   = VIRP_TIER_GREEN,   /* explicit: a read of static
                                      * version/status data */
    },
};

#define PBS_OPS_COUNT (sizeof(PBS_OPS) / sizeof(PBS_OPS[0]))

/*
 * Operation-table invariants, checked at driver init.
 *
 * The point is that a row added WITHOUT an explicit tier must not reach
 * production. A designated initializer leaves .tier == 0 ==
 * VIRP_TIER_UNCLASSIFIED, which the classifier already fails closed on;
 * this makes it loud at startup instead of quietly unclassified, and it
 * also pins the "GET only" and "no BLACK rows" invariants.
 */
int pbs_op_table_validate(void)
{
    int bad = 0;
    for (size_t i = 0; i < PBS_OPS_COUNT; i++) {
        const pbs_op_t *op = &PBS_OPS[i];
        if (!op->id || !op->path || !op->params) {
            fprintf(stderr, "[PBS] op table row %zu is malformed\n", i);
            bad = 1; continue;
        }
        if (op->tier == VIRP_TIER_UNCLASSIFIED) {
            fprintf(stderr, "[PBS] op table row '%s' declares no tier — "
                            "every row must state one explicitly\n", op->id);
            bad = 1;
        }
        if (op->tier == VIRP_TIER_BLACK) {
            fprintf(stderr, "[PBS] op table row '%s' is BLACK — this table "
                            "carries no BLACK rows so every refusal stays "
                            "approvable\n", op->id);
            bad = 1;
        }
        /* (b) A dot segment in a STATIC template is the same divergence
         * as one in a value, just authored rather than submitted. */
        if (strstr(op->path, "/./") || strstr(op->path, "/../") ||
            strstr(op->path, "/.") == op->path + strlen(op->path) - 2) {
            fprintf(stderr, "[PBS] op table row '%s' has a dot segment in "
                            "its path template\n", op->id);
            bad = 1;
        }
        if (!pbs_method_is_allowed((int)op->method)) {
            fprintf(stderr, "[PBS] op table row '%s' declares a non-GET "
                            "method\n", op->id);
            bad = 1;
        }
    }
    return bad ? -1 : 0;
}

const pbs_op_t *pbs_op_lookup(const char *id)
{
    if (!id) return NULL;
    for (size_t i = 0; i < PBS_OPS_COUNT; i++)
        if (strcmp(PBS_OPS[i].id, id) == 0)
            return &PBS_OPS[i];
    return NULL;   /* unknown op: refuse, never guess */
}

/* =========================================================================
 * Charset predicates
 *
 * Narrow by construction. Note what is EXCLUDED from values: '/', '?',
 * '#', '%', ':', '@', space, and every control byte. A value therefore
 * cannot introduce a path segment, a query, a fragment, a percent-escape,
 * a userinfo section, or a CR/LF header split.
 * ========================================================================= */

static bool pbs_is_op_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.';
}

static bool pbs_is_key_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
}

static bool pbs_is_value_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
}

/*
 * A path-segment value may never be "." or "..".
 *
 * The value charset admits '.', so `store=.` and `store=..` parse
 * cleanly and get RECORDED as /api2/json/admin/datastore/./snapshots.
 * libcurl then removes dot segments before transmitting unless
 * CURLOPT_PATH_AS_IS is set — so the observation says one path and the
 * wire carries another, which is precisely the recorded-vs-transmitted
 * divergence this driver exists to eliminate.
 *
 * PATH_AS_IS is set in pbs_request(), but this check stays regardless:
 * an intermediary or the origin server may normalize no matter what the
 * client does, so the only durable fix is never to emit a dot segment.
 */
static bool pbs_is_dot_segment(const char *v)
{
    return v && (strcmp(v, ".") == 0 || strcmp(v, "..") == 0);
}

/* An op id is dotted-lowercase: no leading/trailing dot, no empty
 * segment. Belt and braces — the table lookup is exact-match anyway, but
 * a malformed id should be refused as malformed rather than as unknown,
 * so the caller gets the accurate reason. */
static bool pbs_op_id_well_formed(const char *s)
{
    if (!s || !*s) return false;
    if (*s == '.') return false;
    bool prev_dot = false;
    for (const char *p = s; *p; p++) {
        if (!pbs_is_op_char(*p)) return false;
        if (*p == '.') {
            if (prev_dot) return false;
            prev_dot = true;
        } else {
            prev_dot = false;
        }
    }
    return !prev_dot;   /* no trailing dot */
}

/* =========================================================================
 * Grammar parser
 *
 * Strict, single-pass, no rewriting. The input is either exactly a
 * canonical typed operation or it is refused. There is no normalization
 * step: normalizing would mean two different byte strings could denote
 * the same operation, and then what was signed would no longer be what
 * determines the request.
 * ========================================================================= */

static const char PBS_PREFIX[] = "pbs ";

int pbs_parse_command(const char *command, pbs_request_t *out,
                      const char **reason)
{
    if (reason) *reason = NULL;
    if (!command || !out) {
        if (reason) *reason = REASON_GRAMMAR;
        return -1;
    }

    memset(out, 0, sizeof(*out));

    size_t len = strlen(command);
    if (len == 0 || len >= PBS_COMMAND_MAX) {
        if (reason) *reason = REASON_GRAMMAR;
        return -1;
    }

    /*
     * Byte-level guards first, before any tokenization. Every one of
     * these would otherwise be a way to make two different strings mean
     * the same operation, or to smuggle bytes past a later check.
     */
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)command[i];
        if (c < 0x20 || c == 0x7F) {       /* control bytes incl. CR/LF/TAB */
            if (reason) *reason = REASON_CHARSET;
            return -1;
        }
        if (c == ' ' && i + 1 < len && command[i + 1] == ' ') {
            if (reason) *reason = REASON_GRAMMAR;   /* no space runs */
            return -1;
        }
    }
    if (command[len - 1] == ' ') {          /* no trailing space */
        if (reason) *reason = REASON_GRAMMAR;
        return -1;
    }

    /* Literal prefix. Note this also rejects a leading space. */
    if (strncmp(command, PBS_PREFIX, sizeof(PBS_PREFIX) - 1) != 0) {
        if (reason) *reason = REASON_GRAMMAR;
        return -1;
    }

    const char *p = command + sizeof(PBS_PREFIX) - 1;

    /* First token must be exactly op=<id>. */
    static const char OP_KEY[] = "op=";
    if (strncmp(p, OP_KEY, sizeof(OP_KEY) - 1) != 0) {
        if (reason) *reason = REASON_GRAMMAR;
        return -1;
    }
    p += sizeof(OP_KEY) - 1;

    char op_id[PBS_OP_ID_MAX];
    size_t n = 0;
    while (*p && *p != ' ') {
        if (n + 1 >= sizeof(op_id)) {
            if (reason) *reason = REASON_GRAMMAR;
            return -1;
        }
        op_id[n++] = *p++;
    }
    op_id[n] = '\0';

    if (!pbs_op_id_well_formed(op_id)) {
        if (reason) *reason = REASON_CHARSET;
        return -1;
    }

    const pbs_op_t *op = pbs_op_lookup(op_id);
    if (!op) {
        if (reason) *reason = REASON_UNKNOWN_OP;
        return -1;
    }
    out->op = op;

    /*
     * Remaining tokens: <key>=<value>, ascending by key, each at most
     * once, each declared by this op. "op" itself participates in the
     * ordering — every parameter key must sort strictly after "op" — so
     * the token sequence as a whole is sorted and there is exactly one
     * canonical encoding of any request.
     */
    char prev_key[PBS_KEY_MAX] = "op";

    while (*p == ' ') {
        p++;   /* exactly one space: runs were rejected above */

        char key[PBS_KEY_MAX];
        n = 0;
        while (*p && *p != '=' && *p != ' ') {
            if (n + 1 >= sizeof(key)) {
                if (reason) *reason = REASON_GRAMMAR;
                return -1;
            }
            if (!pbs_is_key_char(*p)) {
                if (reason) *reason = REASON_CHARSET;
                return -1;
            }
            key[n++] = *p++;
        }
        key[n] = '\0';

        if (n == 0 || *p != '=') {          /* bare token, or empty key */
            if (reason) *reason = REASON_GRAMMAR;
            return -1;
        }
        p++;                                 /* consume '=' */

        char value[PBS_VALUE_MAX];
        n = 0;
        while (*p && *p != ' ') {
            if (n + 1 >= sizeof(value)) {
                if (reason) *reason = REASON_GRAMMAR;
                return -1;
            }
            if (!pbs_is_value_char(*p)) {
                if (reason) *reason = REASON_CHARSET;
                return -1;
            }
            value[n++] = *p++;
        }
        value[n] = '\0';

        if (n == 0) {                        /* empty value */
            if (reason) *reason = REASON_GRAMMAR;
            return -1;
        }

        /* Dot segments never reach a derived path. */
        if (pbs_is_dot_segment(value)) {
            if (reason) *reason = REASON_DOT_SEGMENT;
            return -1;
        }

        /* Ordering — strictly ascending, which also catches duplicates,
         * but report a duplicate as a duplicate. */
        int cmp = strcmp(key, prev_key);
        if (cmp == 0) {
            if (reason) *reason = REASON_DUP_PARAM;
            return -1;
        }
        if (cmp < 0) {
            /* Could be an out-of-order key or a repeat of an earlier
             * one; distinguish so the reason is accurate. */
            for (size_t i = 0; i < out->nparams; i++) {
                if (strcmp(out->keys[i], key) == 0) {
                    if (reason) *reason = REASON_DUP_PARAM;
                    return -1;
                }
            }
            if (reason) *reason = REASON_UNSORTED;
            return -1;
        }

        /* Declared by this op? */
        bool declared = false;
        for (const char *const *a = op->params; *a; a++) {
            if (strcmp(*a, key) == 0) { declared = true; break; }
        }
        if (!declared) {
            if (reason) *reason = REASON_UNKNOWN_PARAM;
            return -1;
        }

        if (out->nparams >= PBS_MAX_PARAMS) {
            if (reason) *reason = REASON_UNKNOWN_PARAM;
            return -1;
        }

        memcpy(out->keys[out->nparams], key, sizeof(key));
        memcpy(out->values[out->nparams], value, sizeof(value));
        out->nparams++;

        memcpy(prev_key, key, sizeof(key));
    }

    if (*p != '\0') {                        /* residual bytes */
        if (reason) *reason = REASON_GRAMMAR;
        return -1;
    }

    /* Every declared parameter must be present: an op is not partially
     * applicable. Absence is a refusal, never a default. */
    for (const char *const *a = op->params; *a; a++) {
        bool found = false;
        for (size_t i = 0; i < out->nparams; i++)
            if (strcmp(out->keys[i], *a) == 0) { found = true; break; }
        if (!found) {
            if (reason) *reason = REASON_MISSING_PARAM;
            return -1;
        }
    }

    return 0;
}

/* =========================================================================
 * URL derivation
 *
 * Derived from the table row. The only input-derived bytes are a
 * "{store}" substitution, and only after the value has passed the
 * grammar charset AND the per-device allowlist.
 * ========================================================================= */

static const char *pbs_param_value(const pbs_request_t *req, const char *key)
{
    for (size_t i = 0; i < req->nparams; i++)
        if (strcmp(req->keys[i], key) == 0)
            return req->values[i];
    return NULL;
}

int pbs_build_path(const pbs_request_t *req,
                   const char (*allow)[PBS_VALUE_MAX], size_t allow_count,
                   char *out, size_t out_len, const char **reason)
{
    if (reason) *reason = NULL;
    if (!req || !req->op || !out || out_len == 0) {
        if (reason) *reason = REASON_GRAMMAR;
        return -1;
    }

    const char *store_placeholder = strstr(req->op->path, "{store}");
    char path[512];

    if (store_placeholder) {
        const char *store = pbs_param_value(req, "store");
        if (!store) {                       /* unreachable: parser enforces */
            if (reason) *reason = REASON_MISSING_PARAM;
            return -1;
        }

        if (!allow || allow_count == 0) {
            if (reason) *reason = REASON_NO_DATASTORES;
            return -1;
        }
        bool permitted = false;
        for (size_t i = 0; i < allow_count; i++)
            if (strcmp(allow[i], store) == 0) { permitted = true; break; }
        if (!permitted) {
            if (reason) *reason = REASON_STORE_NOT_ALLOWED;
            return -1;
        }

        size_t head = (size_t)(store_placeholder - req->op->path);
        const char *tail = store_placeholder + strlen("{store}");
        int w = snprintf(path, sizeof(path), "%.*s%s%s",
                         (int)head, req->op->path, store, tail);
        if (w < 0 || (size_t)w >= sizeof(path)) {
            if (reason) *reason = REASON_GRAMMAR;
            return -1;
        }
    } else {
        int w = snprintf(path, sizeof(path), "%s", req->op->path);
        if (w < 0 || (size_t)w >= sizeof(path)) {
            if (reason) *reason = REASON_GRAMMAR;
            return -1;
        }
    }

    int w = req->op->query
          ? snprintf(out, out_len, "%s?%s", path, req->op->query)
          : snprintf(out, out_len, "%s", path);
    if (w < 0 || (size_t)w >= out_len) {
        if (reason) *reason = REASON_GRAMMAR;
        return -1;
    }
    return 0;
}

/* =========================================================================
 * Certificate fingerprint pinning
 *
 * The device's SHA-256 leaf-certificate fingerprint IS the server's
 * identity for this driver. There is no CA path, no hostname fallback,
 * and — deliberately — no way to turn verification off: no flag, no
 * environment variable, no device field. A driver that can be told not
 * to check is a driver that will eventually be told not to check.
 * ========================================================================= */

static int pbs_hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int pbs_parse_fingerprint(const char *text,
                          unsigned char out[PBS_FINGERPRINT_BYTES])
{
    if (!text || !out) return -1;

    size_t n = 0;
    const char *p = text;

    while (*p && n < PBS_FINGERPRINT_BYTES) {
        if (*p == ':') { p++; continue; }   /* tolerate PBS's colon form */
        int hi = pbs_hexval(*p++);
        if (hi < 0) return -1;
        if (!*p) return -1;                 /* odd number of hex digits */
        int lo = pbs_hexval(*p++);
        if (lo < 0) return -1;
        out[n++] = (unsigned char)((hi << 4) | lo);
    }

    /* Trailing separators are fine; trailing data is not. */
    while (*p == ':') p++;
    if (*p != '\0') return -1;

    return n == PBS_FINGERPRINT_BYTES ? 0 : -1;
}

/*
 * CHAIN verification, replaced wholesale by an exact leaf-certificate
 * pin. Read the next paragraph carefully — an earlier version of this
 * comment got it wrong and the error survived until it was caught
 * against a live server.
 *
 * What this callback replaces: chain building and trust-anchor
 * validation. It checks that the peer presented exactly the certificate
 * the operator recorded. For a single pinned host that is stronger than
 * chain validation — a mis-issued certificate for the right name from
 * any trusted CA fails here — and it is why a self-signed PBS
 * certificate needs no CA bundle and no exception.
 *
 * What this callback does NOT replace: HOSTNAME verification. libcurl
 * performs the name check itself, separately from this hook, so with
 * CURLOPT_SSL_VERIFYHOST=2 a correct pin still fails when the connect
 * address is not covered by the certificate's subject/SAN. That is not
 * a bug to route around by lowering VERIFYHOST — it is why the device
 * carries tls_servername, so the driver can connect to an IP while
 * validating the name the certificate actually bears (see pbs_request).
 *
 * The cost of pinning is that certificate rotation on the PBS side is a
 * config change here; that is recorded in the runbook.
 */
static int pbs_cert_verify_cb(X509_STORE_CTX *ctx, void *arg)
{
    const unsigned char *pin = (const unsigned char *)arg;
    if (!pin) return 0;

    X509 *leaf = X509_STORE_CTX_get0_cert(ctx);
    if (!leaf) return 0;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    if (!X509_digest(leaf, EVP_sha256(), md, &mdlen))
        return 0;
    if (mdlen != PBS_FINGERPRINT_BYTES)
        return 0;

    return CRYPTO_memcmp(md, pin, PBS_FINGERPRINT_BYTES) == 0 ? 1 : 0;
}

static CURLcode pbs_ssl_ctx_cb(CURL *curl, void *sslctx, void *userptr)
{
    (void)curl;
    SSL_CTX_set_cert_verify_callback((SSL_CTX *)sslctx,
                                     pbs_cert_verify_cb, userptr);
    return CURLE_OK;
}

/* =========================================================================
 * Device preconditions
 *
 * Split out of connect() so every refusal here is reachable from a unit
 * test without opening a socket. The fingerprint requirement is the one
 * that matters: it is checked before curl is even initialized, so a
 * device without a pin cannot reach the network by any path.
 * ========================================================================= */

int pbs_device_precheck(const virp_device_t *device,
                        unsigned char pin[PBS_FINGERPRINT_BYTES],
                        const char **reason)
{
    if (reason) *reason = NULL;
    if (!device || !pin) {
        if (reason) *reason = REASON_NO_FINGERPRINT;
        return -1;
    }

    if (device->api_token[0] == '\0') {
        if (reason) *reason = REASON_NO_TOKEN;
        return -1;
    }
    if (device->username[0] == '\0') {
        if (reason) *reason = REASON_NO_TOKENID;
        return -1;
    }
    if (device->tls_fingerprint[0] == '\0') {
        if (reason) *reason = REASON_NO_FINGERPRINT;
        return -1;
    }
    if (pbs_parse_fingerprint(device->tls_fingerprint, pin) != 0) {
        if (reason) *reason = REASON_BAD_FINGERPRINT;
        return -1;
    }
    return 0;
}

/* =========================================================================
 * Connection state
 * ========================================================================= */

struct virp_conn {
    virp_device_t  device;
    CURL          *curl;
    char           base_url[512];
    /*
     * When the device names a tls_servername, base_url is built from
     * that name and this holds the CURLOPT_RESOLVE entry pinning it to
     * the configured address ("name:port:addr"). Hostname verification
     * then validates the certificate's real name while the connection
     * still goes to the address the operator configured — no DNS
     * dependency, and no lowering of VERIFYHOST.
     */
    char           resolve_entry[640];
    bool           use_resolve;
    unsigned char  pin[PBS_FINGERPRINT_BYTES];
    char           datastores[PBS_MAX_DATASTORES][PBS_VALUE_MAX];
    size_t         datastore_count;
    bool           connected;
};

/* Split the comma-separated devices.json allowlist. Entries that do not
 * satisfy the value charset are dropped loudly rather than silently:
 * a typo in the allowlist must not widen it. */
/*
 * Parse the comma-separated devices.json allowlist. ATOMIC: returns -1
 * and loads NOTHING on any malformed, duplicate, over-limit, dot-segment
 * or charset-invalid entry. On success returns the entry count.
 *
 * The previous version trimmed internal whitespace and warn-and-continued
 * past bad entries. Both were wrong in the same direction — they made a
 * typo mean something rather than fail:
 *
 *   - deleting internal spaces turned ". ." into "..", manufacturing a
 *     dot segment out of an entry that contained none;
 *   - skipping a bad entry silently narrowed the allowlist, so a
 *     mistyped datastore name became "that store is not permitted"
 *     instead of "your config is wrong".
 *
 * An allowlist is a security control; a partially-loaded one is not a
 * weaker version of the intended control, it is a DIFFERENT control that
 * nobody reviewed. Refusing the device is the honest failure.
 */
int pbs_parse_datastores(const char *csv,
                                char (*out)[PBS_VALUE_MAX],
                                const char *hostname,
                                const char **reason)
{
    const char *who = hostname ? hostname : "?";
    if (reason) *reason = NULL;
    if (!csv || !*csv) return 0;          /* absent list is not an error */

    size_t count = 0;
    const char *p = csv;

    while (*p) {
        /* one field: up to the next comma, inclusive of any spaces */
        const char *start = p;
        while (*p && *p != ',') p++;
        const char *end = p;
        if (*p == ',') p++;

        /* trim ONLY surrounding whitespace */
        while (start < end && (*start == ' ' || *start == '\t')) start++;
        while (end > start && (end[-1] == ' ' || end[-1] == '\t')) end--;

        size_t n = (size_t)(end - start);
        if (n == 0) {
            fprintf(stderr, "[PBS] %s: empty datastore allowlist entry — "
                            "refusing to load the device\n", who);
            if (reason) *reason = "empty datastore_allow entry";
            return -1;
        }
        if (n + 1 > PBS_VALUE_MAX) {
            fprintf(stderr, "[PBS] %s: datastore allowlist entry too long — "
                            "refusing to load the device\n", who);
            if (reason) *reason = "datastore_allow entry too long";
            return -1;
        }
        if (count >= PBS_MAX_DATASTORES) {
            fprintf(stderr, "[PBS] %s: datastore allowlist exceeds %d "
                            "entries — refusing to load the device rather "
                            "than truncating a security control\n",
                    who, PBS_MAX_DATASTORES);
            if (reason) *reason = "datastore_allow over limit";
            return -1;
        }

        char name[PBS_VALUE_MAX];
        memcpy(name, start, n);
        name[n] = '\0';

        /* internal whitespace is a REFUSAL, never silently joined */
        for (size_t i = 0; i < n; i++) {
            if (name[i] == ' ' || name[i] == '\t') {
                fprintf(stderr, "[PBS] %s: datastore allowlist entry '%s' "
                                "contains internal whitespace — refusing to "
                                "load the device\n", who, name);
                if (reason) *reason = "datastore_allow entry has internal whitespace";
                return -1;
            }
            if (!pbs_is_value_char(name[i])) {
                fprintf(stderr, "[PBS] %s: datastore allowlist entry '%s' "
                                "has an illegal byte — refusing to load the "
                                "device\n", who, name);
                if (reason) *reason = "datastore_allow entry has an illegal byte";
                return -1;
            }
        }
        if (pbs_is_dot_segment(name)) {
            fprintf(stderr, "[PBS] %s: datastore allowlist entry '%s' is a "
                            "dot segment — refusing to load the device\n",
                    who, name);
            if (reason) *reason = "datastore_allow entry is a dot segment";
            return -1;
        }
        for (size_t i = 0; i < count; i++) {
            if (strcmp(out[i], name) == 0) {
                fprintf(stderr, "[PBS] %s: duplicate datastore allowlist "
                                "entry '%s' — refusing to load the device\n",
                        who, name);
                if (reason) *reason = "duplicate datastore_allow entry";
                return -1;
            }
        }
        memcpy(out[count++], name, sizeof(name));
    }
    return (int)count;
}

/* =========================================================================
 * Transport — GET, and only GET
 * ========================================================================= */

/*
 * Write callback — FAILS CLOSED on overflow.
 *
 * The previous version copied only what fit and then returned
 * `size * nmemb` regardless, telling libcurl the whole body had been
 * consumed. libcurl was satisfied, the driver learned nothing, and the
 * clipped body went on to be signed as if verbatim.
 *
 * Now: if the incoming chunk does not fit, mark the response overflowed
 * and return a short count, which libcurl treats as CURLE_WRITE_ERROR
 * and ABORTS the transfer.
 *
 * Aborting was chosen over drain-and-discard for two reasons. It stops
 * pulling bytes that are only going to be thrown away — an oversized or
 * hostile body cannot make the daemon read it to the end — and it keeps
 * the callback a single branch with no second "still draining" state to
 * get wrong. The cost is that `total` undercounts the true body size, so
 * the error message says "at least N bytes" rather than claiming an
 * exact size it never measured.
 */
size_t pbs_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    pbs_response_t *resp = (pbs_response_t *)userdata;
    size_t bytes = size * nmemb;

    if (!resp || !resp->buf || resp->buf_size == 0) return 0;

    resp->total += bytes;
    size_t avail = resp->buf_size - resp->offset - 1;   /* reserve NUL */

    if (bytes > avail) {
        /*
         * Keep what fits for the diagnostic only. It is NEVER signed:
         * pbs_execute zeroes the output and reports output_len 0 on this
         * path, which is what makes the daemon emit a signed ERROR
         * rather than a DEVICE_OUTPUT observation over partial bytes.
         */
        if (avail > 0) {
            memcpy(resp->buf + resp->offset, ptr, avail);
            resp->offset += avail;
        }
        resp->buf[resp->offset] = '\0';
        resp->overflowed = true;
        return 0;                    /* short count -> abort the transfer */
    }

    memcpy(resp->buf + resp->offset, ptr, bytes);
    resp->offset += bytes;
    resp->buf[resp->offset] = '\0';
    return bytes;                    /* honest count */
}

/*
 * Format the observation payload, reporting the length ACTUALLY stored.
 *
 * snprintf returns what it WOULD have written. Storing that as
 * output_len overstates the payload whenever the format truncates, which
 * is the second truncation point in this path: the body can fit the curl
 * buffer and still not fit here once the header line is prepended. The
 * daemon clamps the length later to avoid an out-of-bounds read, but a
 * clamp is not a substitute for not lying about the length.
 */
int pbs_format_observation(char *out, size_t out_len,
                           const char *hostname, const char *command,
                           const char *path, long http_code,
                           const char *body, size_t *stored)
{
    if (stored) *stored = 0;
    if (!out || out_len == 0) return -1;

    int written = snprintf(out, out_len, "%s>%s [GET %s] [HTTP %ld]\n%s",
                           hostname ? hostname : "?",
                           command ? command : "?",
                           path ? path : "?",
                           http_code, body ? body : "");
    if (written < 0) { out[0] = '\0'; return -1; }

    if ((size_t)written >= out_len) {
        /* Truncated by the formatter — same class as a truncated body. */
        out[0] = '\0';
        return -1;
    }

    if (stored) *stored = (size_t)written;
    return 0;
}

/*
 * One request against the API. `method` is passed explicitly and
 * re-checked here even though the op table can only hold GET: the check
 * is what makes "no write operations exist" a property of the transport
 * rather than a property of the table's current contents.
 */
bool pbs_method_is_allowed(int method)
{
    return method == PBS_METHOD_GET;
}

static virp_error_t pbs_request(struct virp_conn *conn, pbs_method_t method,
                                const char *path, char *out, size_t out_len,
                                long *http_code)
{
    if (!pbs_method_is_allowed((int)method)) {
        fprintf(stderr, "[PBS] refusing non-GET method on %s\n",
                conn->device.hostname);
        return PBS_ERR_METHOD;
    }

    char url[2048];
    snprintf(url, sizeof(url), "%s%s", conn->base_url, path);

    /* Authorization: PBSAPIToken=<user@realm!tokenid>:<secret>
     * The secret lives in a stack buffer that is cleansed before return
     * and never reaches stderr, the result struct, or an observation. */
    char auth_hdr[512];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: PBSAPIToken=%s:%s",
             conn->device.username, conn->device.api_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Accept: application/json");

    /* Name-to-address override, so hostname verification validates the
     * certificate's actual name without a DNS dependency. */
    struct curl_slist *resolve = NULL;
    if (conn->use_resolve)
        resolve = curl_slist_append(resolve, conn->resolve_entry);

    pbs_response_t resp = { .buf = out, .buf_size = out_len, .offset = 0,
                            .total = 0, .overflowed = false };
    out[0] = '\0';

    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, pbs_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(conn->curl, CURLOPT_CONNECTTIMEOUT,
                     (long)PBS_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, (long)PBS_API_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_FOLLOWLOCATION, 0L);   /* no redirects:
                                     a redirect is a URL we did not derive */

    /*
     * Transmit the derived path EXACTLY as recorded. Without this libcurl
     * squashes /./ and /../ before sending, so the observation and the
     * wire could disagree. The return IS checked: an old or reduced
     * libcurl that does not know this option would silently keep
     * normalizing, and a silently-normalizing transport is the failure
     * this whole fix is about.
     *
     * Dot segments are ALSO refused at parse time and at table
     * validation — belt and braces, because an intermediary or the origin
     * may normalize regardless of what this client asks for.
     */
    /* TODO(scope: deliberate session): no on-wire test asserts the exact
     * request line. A local HTTP listener check is the only thing that
     * proves PATH_AS_IS end to end — this is the class where unit tests
     * of the string builder passed while the wire differed (cf. the
     * hostname-verification bug, 2026-07-31). */
    CURLcode pai = curl_easy_setopt(conn->curl, CURLOPT_PATH_AS_IS, 1L);
    if (pai != CURLE_OK) {
        fprintf(stderr, "[PBS] CURLOPT_PATH_AS_IS unsupported (%s) — "
                        "refusing: the transmitted path could differ from "
                        "the recorded one\n", curl_easy_strerror(pai));
        curl_slist_free_all(headers);
        if (resolve) curl_slist_free_all(resolve);
        OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));
        return PBS_ERR_CURL_PERFORM;
    }

    /* Pinned identity. VERIFYPEER stays on so the callback runs at all;
     * the callback is the actual check. */
    curl_easy_setopt(conn->curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(conn->curl, CURLOPT_SSL_VERIFYHOST, 2L);
    curl_easy_setopt(conn->curl, CURLOPT_SSL_CTX_FUNCTION, pbs_ssl_ctx_cb);
    curl_easy_setopt(conn->curl, CURLOPT_SSL_CTX_DATA, conn->pin);
    if (resolve)
        curl_easy_setopt(conn->curl, CURLOPT_RESOLVE, resolve);

    CURLcode rc = curl_easy_perform(conn->curl);

    curl_slist_free_all(headers);
    if (resolve) curl_slist_free_all(resolve);
    OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));

    /*
     * Overflow is checked BEFORE the generic curl-error branch, because
     * aborting the transfer is exactly what produces CURLE_WRITE_ERROR
     * here. Reporting it as a generic transport failure would lose the
     * one fact that matters: the response was real, we simply could not
     * capture all of it, so nothing about it may be signed as complete.
     */
    if (resp.overflowed) {
        fprintf(stderr, "[PBS] %s: response exceeds the evidence buffer "
                        "(at least %zu bytes, limit %zu) — refusing to "
                        "record a truncated observation\n",
                conn->device.hostname, resp.total, out_len - 1);
        return PBS_ERR_RESPONSE_TOO_LARGE;
    }

    if (rc != CURLE_OK) {
        /* Report the class, not the raw string, for TLS failures: a
         * pin mismatch and a chain failure both surface as
         * CURLE_PEER_FAILED_VERIFICATION and both mean "not our host". */
        if (rc == CURLE_PEER_FAILED_VERIFICATION ||
            rc == CURLE_SSL_CACERT_BADFILE) {
            fprintf(stderr, "[PBS] certificate pin mismatch on %s — "
                            "refusing\n", conn->device.hostname);
            conn->connected = false;
            return PBS_ERR_PIN_MISMATCH;
        }
        fprintf(stderr, "[PBS] curl error on %s: %s\n",
                conn->device.hostname, curl_easy_strerror(rc));
        if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_OPERATION_TIMEDOUT ||
            rc == CURLE_SSL_CONNECT_ERROR)
            conn->connected = false;
        return PBS_ERR_CURL_PERFORM;
    }

    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, http_code);
    return VIRP_OK;
}

/* =========================================================================
 * Driver: connect
 * ========================================================================= */

/* TODO(scope: deliberate session): the connect and health probes issue
 * "/api2/json/version" as a literal rather than going through the op
 * table. It is the same string a GREEN row derives, but a literal can
 * drift from the table it is supposed to mirror. Route both probes
 * through table-only transport. See "out of scope" list, 2026-08-01. */
static virp_conn_t *pbs_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    /* Preconditions — including the mandatory certificate pin — are
     * checked before curl is initialized, so a device that fails them
     * cannot reach the network by any path. */
    unsigned char pin[PBS_FINGERPRINT_BYTES];
    const char *why = NULL;
    if (pbs_device_precheck(device, pin, &why) != 0) {
        fprintf(stderr, "[PBS] %s: refusing to connect — %s\n",
                device->hostname, why ? why : "device precondition failed");
        return NULL;
    }

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    memcpy(conn->pin, pin, sizeof(pin));
    OPENSSL_cleanse(pin, sizeof(pin));
    conn->connected = false;

    const char *ds_reason = NULL;
    int ds_n = pbs_parse_datastores(device->datastore_allow,
                                    conn->datastores, device->hostname,
                                    &ds_reason);
    if (ds_n < 0) {
        fprintf(stderr, "[PBS] %s: refusing to connect — %s\n",
                device->hostname, ds_reason ? ds_reason : "bad datastore_allow");
        OPENSSL_cleanse(conn->device.api_token,
                        sizeof(conn->device.api_token));
        OPENSSL_cleanse(conn->pin, sizeof(conn->pin));
        free(conn);
        return NULL;
    }
    conn->datastore_count = (size_t)ds_n;

    uint16_t port = device->api_port ? device->api_port :
                    (device->port ? device->port : PBS_DEFAULT_PORT);

    /*
     * PBS is TLS-only; no http fallback. When the operator supplied the
     * certificate's name, address the request to THAT name and pin the
     * name to the configured address with CURLOPT_RESOLVE — hostname
     * verification then has something true to check, instead of being
     * turned off because an IP is not in the certificate's SAN.
     */
    if (device->tls_servername[0] != '\0') {
        snprintf(conn->base_url, sizeof(conn->base_url), "https://%.255s:%u",
                 device->tls_servername, port);
        snprintf(conn->resolve_entry, sizeof(conn->resolve_entry),
                 "%.255s:%u:%.255s", device->tls_servername, port,
                 device->host);
        conn->use_resolve = true;
    } else {
        snprintf(conn->base_url, sizeof(conn->base_url), "https://%.255s:%u",
                 device->host, port);
        conn->use_resolve = false;
    }

    conn->curl = curl_easy_init();
    if (!conn->curl) {
        fprintf(stderr, "[PBS] curl_easy_init() failed\n");
        OPENSSL_cleanse(conn->device.api_token,
                        sizeof(conn->device.api_token));
        free(conn);
        return NULL;
    }

    fprintf(stderr, "[PBS] Connecting to %s%s%s (pinned cert, hostname "
                    "verification on, %zu datastore%s allowlisted)\n",
            conn->base_url,
            conn->use_resolve ? " via " : "",
            conn->use_resolve ? device->host : "",
            conn->datastore_count,
            conn->datastore_count == 1 ? "" : "s");

    /*
     * Token probe. The probe is one of the GREEN table rows — the same
     * discipline as driver_librenms.c: the daemon must never touch an
     * endpoint its own classifier calls RED, and the least-privileged
     * token is granted nothing outside the enumerated set.
     */
    char probe[1024];
    long http_code = 0;
    virp_error_t err = pbs_request(conn, PBS_METHOD_GET,
                                   "/api2/json/version",
                                   probe, sizeof(probe), &http_code);
    if (err != VIRP_OK || http_code != 200) {
        fprintf(stderr, "[PBS] Token probe failed on %s: HTTP %ld\n",
                device->hostname, http_code);
        curl_easy_cleanup(conn->curl);
        OPENSSL_cleanse(conn->device.api_token,
                        sizeof(conn->device.api_token));
        OPENSSL_cleanse(conn->pin, sizeof(conn->pin));
        free(conn);
        return NULL;
    }

    conn->connected = true;
    fprintf(stderr, "[PBS] Connected: %s:%u\n", device->host, port);
    return (virp_conn_t *)conn;
}

/* =========================================================================
 * Driver: execute
 *
 * Order matters and is deliberate: GRAMMAR FIRST, before the connected
 * check and before anything touches the network. A malformed or
 * unknown-op command is refused as a typed signed ERROR whether or not
 * the device is reachable, so the refusal is a property of the request,
 * not of the moment.
 * ========================================================================= */

/* TODO(scope: deliberate session): the daemon connects BEFORE it
 * classifies, so an unclassifiable command still costs a connection, and
 * a transport failure is not distinguished from a refusal in the
 * caller-visible disposition (VIRP_EXEC_REFUSED vs _TRANSPORT_FAILURE).
 * Reorder to classify-before-connect and split the disposition.
 * See "out of scope" list, 2026-08-01. */
/*
 * The fail-closed result shape, in one place.
 *
 * output_len MUST be 0. The daemon emits a signed typed ERROR only when
 * (!success && output_len == 0 && error_msg[0]); with a non-zero length
 * it takes the DEVICE_OUTPUT path instead and signs whatever bytes are
 * in the buffer — which on this path is a TRUNCATED body, i.e. exactly
 * the thing being refused. Getting this wrong turns the fix into the
 * bug, so it is a single function with a single test.
 */
void pbs_result_evidence_limit(virp_exec_result_t *result,
                               const char *hostname, const char *detail)
{
    if (!result) return;
    memset(result->output, 0, sizeof(result->output));
    result->output_len = 0;
    result->success    = false;
    result->exit_code  = 1;
    snprintf(result->error_msg, sizeof(result->error_msg),
             "response exceeded evidence limit on %.64s — %s; no complete "
             "observation exists to sign, so nothing was recorded",
             hostname ? hostname : "?",
             detail ? detail : "capture incomplete");
}

static virp_error_t pbs_execute(virp_conn_t *base_conn, const char *command,
                                virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    pbs_request_t req;
    const char *reason = NULL;
    if (pbs_parse_command(command, &req, &reason) != 0) {
        result->success = false;
        result->exit_code = 1;
        result->no_dispatch = true;   /* refused before any request went out */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Refused before any network activity: %s",
                 reason ? reason : REASON_GRAMMAR);
        return VIRP_OK;      /* typed ERROR observation, not a transport error */
    }

    char path[640];
    /* The cast adds only const; ISO C before C2X will not do that
     * implicitly for a pointer-to-array, so it is spelled out. */
    if (pbs_build_path(&req,
                       (const char (*)[PBS_VALUE_MAX])conn->datastores,
                       conn->datastore_count,
                       path, sizeof(path), &reason) != 0) {
        result->success = false;
        result->exit_code = 1;
        result->no_dispatch = true;   /* refused before any request went out */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Refused before any network activity: %s",
                 reason ? reason : REASON_GRAMMAR);
        return VIRP_OK;
    }

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return PBS_ERR_NOT_CONNECTED;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    char api_response[PBS_RESPONSE_MAX];
    long http_code = 0;
    virp_error_t err = pbs_request(conn, req.op->method, path,
                                   api_response, sizeof(api_response),
                                   &http_code);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                      (end.tv_nsec - start.tv_nsec) / 1000000);

    /*
     * FAIL CLOSED. output_len MUST be 0 here: the daemon emits a signed
     * ERROR observation only when (!success && output_len == 0 &&
     * error_msg[0]). Leaving partial bytes with a non-zero length would
     * send this down the DEVICE_OUTPUT path instead — signing the very
     * truncation this branch exists to refuse.
     */
    if (err == PBS_ERR_RESPONSE_TOO_LARGE) {
        pbs_result_evidence_limit(result, conn->device.hostname,
                                  "the body did not fit the capture buffer");
        return VIRP_OK;      /* signed typed ERROR, not a transport failure */
    }

    if (err == PBS_ERR_PIN_MISMATCH) {
        result->success = false;
        result->exit_code = 1;
        result->no_dispatch = true;   /* TLS verify aborted the connection
                                         before the request was sent */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "TLS certificate pin mismatch on %s — the peer is not the "
                 "recorded PBS certificate", conn->device.hostname);
        return VIRP_OK;
    }
    if (err != VIRP_OK) {
        result->success = false;
        result->exit_code = 1;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "transport error on %.64s%.160s",
                 conn->device.hostname, path);
        return VIRP_OK;
    }

    /*
     * Observation payload: the operation as approved, the URL the table
     * derived from it, and the JSON body verbatim. Recording the derived
     * path next to the op is what lets a later reader confirm the
     * derivation without re-running the driver.
     */
    size_t stored = 0;
    if (pbs_format_observation(result->output, sizeof(result->output),
                               conn->device.hostname, command, path,
                               http_code, api_response, &stored) != 0) {
        /* Second truncation point: the body fit the capture buffer but
         * the formatted payload does not fit the observation buffer.
         * Same rule — refuse rather than sign a clipped payload. */
        pbs_result_evidence_limit(result, conn->device.hostname,
                                  "the formatted observation did not fit");
        return VIRP_OK;
    }
    result->output_len = stored;   /* bytes STORED, never would-have-written */

    if (http_code == 401 || http_code == 403) {
        result->success = false;
        result->exit_code = (int)http_code;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "HTTP %ld auth failure on %s", http_code,
                 conn->device.hostname);
    } else if (http_code >= 400) {
        result->success = false;
        result->exit_code = (int)http_code;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "HTTP %ld from %.64s%.160s", http_code,
                 conn->device.hostname, path);
    } else {
        result->success = true;
        result->exit_code = 0;
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect / detect / health_check
 * ========================================================================= */

static void pbs_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
        conn->curl = NULL;
    }

    conn->connected = false;
    fprintf(stderr, "[PBS] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.api_token, sizeof(conn->device.api_token));
    OPENSSL_cleanse(conn->pin, sizeof(conn->pin));
    free(conn);
}

static bool pbs_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;
    return conn->device.vendor == VIRP_VENDOR_PBS;
}

static virp_error_t pbs_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->connected) return PBS_ERR_NOT_CONNECTED;

    /* Health probe stays inside the GREEN read set — see connect(). */
    char probe[1024];
    long http_code = 0;
    virp_error_t err = pbs_request(conn, PBS_METHOD_GET, "/api2/json/version",
                                   probe, sizeof(probe), &http_code);
    if (err != VIRP_OK) return err;
    return http_code == 200 ? VIRP_OK : PBS_ERR_AUTH_FAILED;
}

/* =========================================================================
 * Gate classifier
 *
 * Because the command IS the typed operation, classification is a table
 * lookup on a fully validated parse — there is no vendor syntax to
 * reason about, no prefix matching, and therefore no prefix creep. A
 * command classifies GREEN only if it parses exactly and names a v1 op;
 * everything else is RED.
 * ========================================================================= */

virp_trust_tier_t pbs_gate_classify(const char *command, const char **reason)
{
    if (reason) *reason = NULL;
    if (!command) return VIRP_TIER_RED;          /* fail closed */

    pbs_request_t req;
    const char *why = NULL;
    if (pbs_parse_command(command, &req, &why) != 0) {
        if (reason) *reason = why ? why : REASON_GRAMMAR;
        return VIRP_TIER_RED;
    }

    /*
     * Return the row's DECLARED tier. There is deliberately no
     * "parsed successfully => GREEN" fallback: that fallback is how a
     * future sensitive or stateful GET becomes GREEN without anyone
     * making a gate decision about it. A row with no explicit tier holds
     * VIRP_TIER_UNCLASSIFIED (0), which fails closed here and is
     * rejected outright by pbs_op_table_validate() at init.
     */
    if (req.op->tier == VIRP_TIER_UNCLASSIFIED) {
        if (reason) *reason = REASON_NO_TIER;
        return VIRP_TIER_RED;
    }
    return req.op->tier;
}

virp_trust_tier_t pbs_gate_tier(const char *command)
{
    return pbs_gate_classify(command, NULL);
}

const char *pbs_gate_reason(const char *command)
{
    const char *reason = NULL;
    (void)pbs_gate_classify(command, &reason);
    return reason;
}

/* =========================================================================
 * Driver registration
 * ========================================================================= */

static virp_driver_t pbs_driver = {
    .name          = "pbs",
    .vendor        = VIRP_VENDOR_PBS,
    .connect       = pbs_connect,
    .execute       = pbs_execute,
    .disconnect    = pbs_disconnect,
    .detect        = pbs_detect,
    .health_check  = pbs_health_check,
    .route_command = pbs_gate_tier,
    .route_reason  = pbs_gate_reason,
    /*
     * Typed-operation profile. Selects the exact-octet command hash
     * (virp_typed_op_hash) instead of the canonicalizing one, so a
     * spelling this parser REFUSES cannot share a hash with one it
     * accepts. Bump alongside a protocol version change only — the value
     * is bound into every command hash this driver produces.
     */
    .typed_profile = "pbs/1",
};

void virp_driver_pbs_init(void)
{
    /*
     * Fail loudly rather than register a table with an unclassified row.
     * Registering anyway would leave the row failing closed at the gate,
     * which is safe but silent — and silence is how a missing tier
     * survives to the next reader.
     */
    if (pbs_op_table_validate() != 0) {
        fprintf(stderr, "[PBS] FATAL: operation table failed validation — "
                        "driver NOT registered\n");
        return;
    }
    virp_driver_register(&pbs_driver);
}
