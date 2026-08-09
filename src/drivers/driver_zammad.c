/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Zammad Device Driver — REST API via libcurl + personal access token
 *
 * Third REST-based driver, structured after driver_librenms.c (static
 * token, no lifecycle) with driver_pbs.c's transport discipline (no
 * redirects, no path normalization, no way to weaken TLS).
 *
 * Handles:
 *   - Token auth: "Authorization: Token token=<value>" — Zammad's
 *     personal-access-token scheme, NOT Bearer. Never logged.
 *   - GET-only transport; non-GET method prefixes refused outright
 *   - HTTPS always, verification always on, no config knob to disable
 *   - Command routing table for trust tier classification
 *
 * Design mirrors the other REST drivers:
 *   - The "command" parameter to execute() is a Zammad API path.
 *   - One CURL easy handle per connection, reused across requests.
 *   - Fixed buffers only; response lands in virp_exec_result_t.
 *
 * Credential path (unchanged from every other device): the token lives
 * in /etc/virp/autopilot.env (0600 root), is substituted into
 * /run/virp/devices.json by deploy/render-devices.sh at daemon start,
 * and reaches this driver only as device.api_token. It is never
 * written to a persistent file and never reaches a log line: the one
 * place it is formatted is the stack header buffer in zm_get(), which
 * is OPENSSL_cleanse()d before that function returns, and the copy in
 * conn->device is cleansed at disconnect.
 *
 * Build:  make ZAMMAD=1
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_driver_zammad.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/crypto.h>

/* =========================================================================
 * Command Routing — the autopilot GREEN read set, nothing else
 *
 * Same discipline as the Wazuh and LibreNMS tables, tightened in two
 * places where those two are loose:
 *
 *   1. The query string is CLASSIFIED, not stripped. Both older REST
 *      drivers cut the path at '?' and match only what precedes it, so
 *      every parameter a caller invents rides along unclassified.
 *      Here the query is part of what is being judged: only "page" and
 *      "per_page" exist, only digit values exist, and everything else
 *      is RED.
 *
 *   2. Nothing is prefix-matched. The recorded gap in the Wazuh driver
 *      was longest-prefix matching, which let "/agents_evil" and
 *      "/agents/001/restart" inherit the GREEN "/agents" row. The two
 *      rows here that end in a variable <id> are not prefixes in that
 *      sense either: the bytes after the base must be a digit run all
 *      the way to the end of the path, so "/api/v1/tickets/1/merge"
 *      and "/api/v1/tickets_evil" both fall through to RED.
 *
 * No YELLOW rows, no BLACK rows, so every RED stays approvable through
 * propose/approve/apply.
 * ========================================================================= */

/* Fixed GREEN paths — byte-exact, no wildcards. */
static const char *const ZM_GREEN_EXACT[] = {
    ZM_API_PREFIX "/tickets",         /* ticket list          */
    ZM_API_PREFIX "/ticket_states",   /* state catalogue      */
    ZM_API_PREFIX "/groups",          /* group catalogue      */
};

/*
 * GREEN paths that end in a numeric object id. The base includes its
 * trailing slash, and the ENTIRE remainder must be digits — see
 * zm_route_path(); this is an anchored full-path rule, not a prefix.
 */
static const char *const ZM_GREEN_ID_BASE[] = {
    ZM_API_PREFIX "/tickets/",                    /* ticket detail   */
    ZM_API_PREFIX "/ticket_articles/by_ticket/",  /* ticket articles */
};

/*
 * A digit run: 1..ZM_DIGITS_MAX ASCII digits, nothing else. No sign,
 * no whitespace, no '+', no separators, no percent-encoding, no
 * locale-dependent isdigit() (which admits other bytes under some
 * locales and takes a signed char as a negative index).
 */
static bool zm_digits(const char *s, size_t len)
{
    if (len == 0 || len > ZM_DIGITS_MAX) return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < '0' || c > '9') return false;
    }
    return true;
}

/*
 * Query-string policy: only "page" and "per_page", each at most once,
 * each with a digits-only value.
 *
 * `q` points just past '?', `len` runs to the end of the string.
 * RED (false) for: a bare "?", an empty pair ("&&", a trailing "&"), a
 * pair with no '=', an unlisted name, an empty or non-numeric value, a
 * repeated name. Duplicates are refused rather than last-one-wins
 * because "which one counts" is a property of the server's parser, not
 * of the bytes we classified — two answers to that question is one too
 * many for something the gate signs.
 */
static bool zm_query_ok(const char *q, size_t len)
{
    if (len == 0) return false;                  /* path ended in a bare '?' */

    bool seen_page = false, seen_per_page = false;
    size_t i = 0;

    while (i < len) {
        size_t start = i;
        while (i < len && q[i] != '&') i++;
        size_t pair_len = i - start;

        /* Step over the separator. A '&' with nothing after it ends the
         * loop, so the empty pair it introduces has to be caught here —
         * checking pair_len alone lets "page=1&" through. */
        if (i < len) {
            i++;
            if (i == len) return false;          /* trailing '&' */
        }

        if (pair_len == 0) return false;         /* "", "&page=1", "a&&b" */

        const char *pair = q + start;
        const char *eq = memchr(pair, '=', pair_len);
        if (!eq) return false;                   /* bare flag, e.g. "?expand" */

        size_t name_len = (size_t)(eq - pair);
        size_t val_len  = pair_len - name_len - 1;
        const char *val = eq + 1;

        if (name_len == 4 && memcmp(pair, "page", 4) == 0) {
            if (seen_page) return false;
            seen_page = true;
        } else if (name_len == 8 && memcmp(pair, "per_page", 8) == 0) {
            if (seen_per_page) return false;
            seen_per_page = true;
        } else {
            return false;                        /* unlisted parameter name */
        }

        /* A second '=' lands inside val and fails the digit test, which
         * is the intended answer: "page=1=2" is not a number. */
        if (!zm_digits(val, val_len)) return false;
    }

    return true;
}

virp_trust_tier_t zm_route_path(const char *path)
{
    if (!path) return VIRP_TIER_RED;                     /* fail closed */

    size_t total = strlen(path);
    if (total == 0 || total > ZM_PATH_MAX) return VIRP_TIER_RED;

    /* Split off the query string and classify it. Unlike the Wazuh and
     * LibreNMS drivers, the query is NOT ignored. */
    size_t plen = total;
    const char *qmark = memchr(path, '?', total);
    if (qmark) {
        plen = (size_t)(qmark - path);
        if (!zm_query_ok(qmark + 1, total - plen - 1))
            return VIRP_TIER_RED;
    }

    /* Byte-exact rows. Case variants are unlisted spellings, not the
     * listed row: the bytes that were classified are the bytes that get
     * requested, so a case-folded compare here would classify one
     * string and dispatch another. */
    for (size_t i = 0;
         i < sizeof(ZM_GREEN_EXACT) / sizeof(ZM_GREEN_EXACT[0]); i++) {
        size_t glen = strlen(ZM_GREEN_EXACT[i]);
        if (glen == plen && memcmp(path, ZM_GREEN_EXACT[i], glen) == 0)
            return VIRP_TIER_GREEN;
    }

    /* Rows ending in <id>: base must match byte-exactly AND the whole
     * remainder must be a digit run. Anchored at both ends — there is
     * no trailing context a caller can append. */
    for (size_t i = 0;
         i < sizeof(ZM_GREEN_ID_BASE) / sizeof(ZM_GREEN_ID_BASE[0]); i++) {
        size_t blen = strlen(ZM_GREEN_ID_BASE[i]);
        if (plen > blen &&
            memcmp(path, ZM_GREEN_ID_BASE[i], blen) == 0 &&
            zm_digits(path + blen, plen - blen))
            return VIRP_TIER_GREEN;
    }

    return VIRP_TIER_RED;                                /* RED by absence */
}

/*
 * The one place a submitted command becomes a request path — used by
 * BOTH the gate hook and execute(), so the bytes that were classified
 * are provably the bytes that get requested. Returns NULL for a non-GET
 * method prefix or anything that is not a rooted path.
 *
 * "GET " is matched case-exactly, like every other row in this driver:
 * "get /api/v1/tickets" is an unlisted spelling and falls through RED.
 */
static const char *zm_command_path(const char *command)
{
    if (!command) return NULL;

    const char *p = command;
    while (*p == ' ') p++;
    if (strncmp(p, "GET ", 4) == 0) {
        p += 4;
        while (*p == ' ') p++;
    }
    if (p[0] != '/') return NULL;   /* non-GET method, or unrooted path */
    return p;
}

virp_trust_tier_t zammad_gate_tier(const char *command)
{
    const char *path = zm_command_path(command);
    if (!path) return VIRP_TIER_RED;
    return zm_route_path(path);
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    CURL               *curl;
    char                base_url[512];      /* https://host:port */
    bool                connected;
};

/* =========================================================================
 * CURL write callback — accumulate response into a fixed buffer
 * ========================================================================= */

typedef struct {
    char   *buf;
    size_t  buf_size;
    size_t  offset;
} zm_response_t;

static size_t zm_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    zm_response_t *resp = (zm_response_t *)userdata;
    size_t bytes = size * nmemb;
    size_t avail = resp->buf_size - resp->offset - 1;   /* reserve NUL */

    if (bytes > avail)
        bytes = avail;

    if (bytes > 0) {
        memcpy(resp->buf + resp->offset, ptr, bytes);
        resp->offset += bytes;
        resp->buf[resp->offset] = '\0';
    }

    return size * nmemb;   /* always report full consumption to curl */
}

/*
 * TLS is not configurable.
 *
 * The Wazuh driver has VIRP_WAZUH_INSECURE and the LibreNMS driver
 * picks plain http for any port that is not 443 — both are config
 * knobs whose value can mean "do not check". This driver has neither:
 * the scheme is always https, VERIFYPEER/VERIFYHOST are always on, and
 * there is no CA-bundle override, so the only trust anchors are the
 * host's CA store — where the Zammad certificate already lives.
 * Rotating to a certificate outside that store is therefore a host
 * trust-store change, which is the intended cost.
 */
static void zm_configure_tls(CURL *curl)
{
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
}

/*
 * One GET against the API. Internal transport helper shared by the
 * connect probe, execute, and health_check.
 *
 * `path` must already have passed zm_command_path(); it is sent
 * verbatim. The token goes into a stack header buffer and is cleansed
 * before return — it must never reach a log line, an error_msg, or an
 * observation payload.
 */
static virp_error_t zm_get(struct virp_conn *conn, const char *path,
                           char *out, size_t out_len, long *http_code)
{
    /*
     * The classifier caps a GREEN path at ZM_PATH_MAX, so a longer one
     * cannot have been approved as GREEN — but the transport refuses
     * independently rather than trusting that, and it checks the
     * snprintf return: a silently truncated URL is a request for a
     * DIFFERENT resource than the one that was classified.
     */
    if (strlen(path) > ZM_PATH_MAX) {
        fprintf(stderr, "[Zammad] path exceeds %d bytes — refusing\n",
                ZM_PATH_MAX);
        return ZM_ERR_CURL_PERFORM;
    }

    char url[2048];
    int url_len = snprintf(url, sizeof(url), "%s%s", conn->base_url, path);
    if (url_len < 0 || (size_t)url_len >= sizeof(url)) {
        fprintf(stderr, "[Zammad] URL would truncate — refusing\n");
        return ZM_ERR_CURL_PERFORM;
    }

    /* Zammad personal access token — "Token token=<value>", not Bearer. */
    char auth_hdr[ZM_TOKEN_MAX + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Token token=%s",
             conn->device.api_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    zm_response_t resp = { .buf = out, .buf_size = out_len, .offset = 0 };
    out[0] = '\0';

    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, zm_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(conn->curl, CURLOPT_CONNECTTIMEOUT,
                     (long)ZM_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, (long)ZM_API_TIMEOUT_SEC);
    /* No redirects: a redirect is a URL we did not classify, and
     * following one would carry the Authorization header to whatever
     * host the response named. */
    curl_easy_setopt(conn->curl, CURLOPT_FOLLOWLOCATION, 0L);

    /*
     * Transmit the classified path EXACTLY as classified. Without this
     * libcurl squashes /./ and /../ before sending, so a path the gate
     * called RED could be normalized into one it calls GREEN — or the
     * reverse. The return IS checked: a libcurl that does not know this
     * option would silently keep normalizing, and silent normalization
     * is exactly the divergence being prevented.
     *
     * Dot segments cannot survive zm_route_path() either (an <id> is
     * digits, so "." and ".." are RED) — belt and braces, because an
     * intermediary may normalize regardless of what this client asks.
     */
    CURLcode pai = curl_easy_setopt(conn->curl, CURLOPT_PATH_AS_IS, 1L);
    if (pai != CURLE_OK) {
        fprintf(stderr, "[Zammad] CURLOPT_PATH_AS_IS unsupported (%s) — "
                        "refusing: the transmitted path could differ from "
                        "the classified one\n", curl_easy_strerror(pai));
        curl_slist_free_all(headers);
        OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));
        return ZM_ERR_CURL_PERFORM;
    }

    zm_configure_tls(conn->curl);

    CURLcode rc = curl_easy_perform(conn->curl);

    curl_slist_free_all(headers);
    OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));

    if (rc != CURLE_OK) {
        /* curl_easy_strerror() describes the class of failure and never
         * echoes the request headers, so this cannot leak the token. */
        fprintf(stderr, "[Zammad] curl error on %s: %s\n",
                conn->device.hostname, curl_easy_strerror(rc));
        if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_OPERATION_TIMEDOUT ||
            rc == CURLE_SSL_CONNECT_ERROR || rc == CURLE_PEER_FAILED_VERIFICATION)
            conn->connected = false;
        return ZM_ERR_CURL_PERFORM;
    }

    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, http_code);
    return VIRP_OK;
}

/*
 * Zammad signals an application error with a top-level envelope:
 *   {"error":"...", "error_human":"..."}
 *
 * Matched ONLY at the head of the body — leading whitespace, '{', then
 * the "error" key — deliberately not with a strstr() over the whole
 * response the way the Wazuh and LibreNMS drivers do. Ticket titles and
 * article bodies are attacker-supplied text that this driver returns
 * verbatim, so a customer who opens a ticket titled  "error"  would
 * otherwise flip every ticket-list read to failed. The narrow match
 * cannot be forged from inside a nested string value.
 *
 * The tradeoff: an error object whose "error" key is not first is
 * missed. That costs nothing in practice — a real Zammad failure also
 * carries a 4xx/5xx status, which is checked separately and first.
 */
static bool zm_body_is_error(const char *body)
{
    const char *p = body;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != '{') return false;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return strncmp(p, "\"error\"", 7) == 0;
}

/* =========================================================================
 * Driver: connect — init CURL, validate the token with one probe
 * ========================================================================= */

static virp_conn_t *zammad_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    if (device->api_token[0] == '\0') {
        fprintf(stderr, "[Zammad] No api_token configured for %s\n",
                device->hostname);
        return NULL;
    }

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->connected = false;

    /*
     * Always https. The port is configurable; the scheme is not. (The
     * LibreNMS driver derives http from a non-443 port — a Zammad
     * instance on 8443 must not get plaintext because of a port
     * number.)
     */
    uint16_t port = device->api_port ? device->api_port :
                    (device->port ? device->port : ZM_DEFAULT_PORT);
    snprintf(conn->base_url, sizeof(conn->base_url), "https://%s:%u",
             device->host, port);

    conn->curl = curl_easy_init();
    if (!conn->curl) {
        fprintf(stderr, "[Zammad] curl_easy_init() failed\n");
        OPENSSL_cleanse(conn->device.api_token,
                        sizeof(conn->device.api_token));
        free(conn);
        return NULL;
    }

    fprintf(stderr, "[Zammad] Connecting to %s\n", conn->base_url);

    /*
     * Validate the token with an internal probe. The probe path is one
     * of the GREEN rows (/api/v1/ticket_states — the smallest of them):
     * the daemon must never touch an endpoint its own classifier calls
     * RED, and a least-privileged token may not be granted anything
     * outside the enumerated set.
     */
    char probe[1024];
    long http_code = 0;
    virp_error_t err = zm_get(conn, ZM_EP_TICKET_STATES,
                              probe, sizeof(probe), &http_code);
    if (err != VIRP_OK || http_code != 200) {
        fprintf(stderr, "[Zammad] Token probe failed on %s: HTTP %ld\n",
                device->hostname, http_code);
        curl_easy_cleanup(conn->curl);
        OPENSSL_cleanse(conn->device.api_token,
                        sizeof(conn->device.api_token));
        OPENSSL_cleanse(probe, sizeof(probe));
        free(conn);
        return NULL;
    }

    conn->connected = true;
    fprintf(stderr, "[Zammad] Connected: %s:%u\n", device->host, port);
    return (virp_conn_t *)conn;
}

/* =========================================================================
 * Driver: execute — one GET, response wrapped like the other drivers
 * ========================================================================= */

static virp_error_t zammad_execute(virp_conn_t *base_conn,
                                   const char *command,
                                   virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    /*
     * GET-only transport honesty — same rule, same ordering, and the
     * same helper the classifier used, so a command can never be
     * classified as one thing and dispatched as another.
     *
     * Checked BEFORE the connectivity test so the refusal is
     * deterministic and offline-testable. This driver can only issue
     * GETs; a command carrying a non-GET method prefix (or anything
     * that is not a rooted path) is refused outright as a soft failure,
     * which the O-Node wraps as a signed ERROR observation
     * (executed=no).
     *
     * The path goes straight to libcurl's CURLOPT_URL as a C string —
     * no shell interpretation, no fork/exec. Bytes like ; | & ` $ ( )
     * are ordinary URL characters here, not shell operators; they are
     * nonetheless RED at the gate because they cannot occur in any
     * listed row.
     */
    const char *path = zm_command_path(command);
    if (!path) {
        result->success = false;
        result->no_dispatch = true;   /* refused before any request went out */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Refused: GET-only REST driver cannot honor '%.64s' "
                 "(non-GET method or unrooted path)", command);
        return VIRP_OK;
    }

    /*
     * NOTE: execute() deliberately does NOT re-check the tier. The gate
     * decides, and a RED path that a human approved through
     * propose/approve/apply must still run. What execute() enforces is
     * the transport contract — GET, this path, verbatim.
     */

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return ZM_ERR_NOT_CONNECTED;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    char api_response[ZM_RESPONSE_MAX];
    long http_code = 0;
    virp_error_t err = zm_get(conn, path, api_response,
                              sizeof(api_response), &http_code);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                      (end.tv_nsec - start.tv_nsec) / 1000000);

    if (err != VIRP_OK) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "curl error on %s%s", conn->device.hostname, path);
        return VIRP_OK;
    }

    int written = snprintf(result->output, sizeof(result->output),
                           "%s>%s [HTTP %ld]\n%s",
                           conn->device.hostname, path,
                           http_code, api_response);
    result->output_len = (written > 0) ? (size_t)written : 0;

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
                 "HTTP %ld from %s%s", http_code,
                 conn->device.hostname, path);
    } else {
        result->success = true;
        result->exit_code = 0;

        if (zm_body_is_error(api_response)) {
            result->success = false;
            result->exit_code = 1;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Zammad API error in response from %s",
                     conn->device.hostname);
        }
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect / detect / health_check
 * ========================================================================= */

static void zammad_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
        conn->curl = NULL;
    }

    conn->connected = false;
    fprintf(stderr, "[Zammad] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.api_token, sizeof(conn->device.api_token));
    free(conn);
}

static bool zammad_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;
    return conn->device.vendor == VIRP_VENDOR_ZAMMAD;
}

static virp_error_t zammad_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->connected) return ZM_ERR_NOT_CONNECTED;

    /* Health probe stays inside the GREEN read set — see connect(). */
    char probe[1024];
    long http_code = 0;
    virp_error_t err = zm_get(conn, ZM_EP_TICKET_STATES,
                              probe, sizeof(probe), &http_code);
    if (err != VIRP_OK) return err;
    return http_code == 200 ? VIRP_OK : ZM_ERR_AUTH_FAILED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t zammad_driver = {
    .name       = "zammad",
    .vendor     = VIRP_VENDOR_ZAMMAD,
    .connect    = zammad_connect,
    .execute    = zammad_execute,
    .disconnect = zammad_disconnect,
    .detect     = zammad_detect,
    .health_check = zammad_health_check,
    .route_command = zammad_gate_tier,
};

const virp_driver_t *virp_driver_zammad(void)
{
    return &zammad_driver;
}

void virp_driver_zammad_init(void)
{
    virp_driver_register(&zammad_driver);
}
