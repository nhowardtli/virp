/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * LibreNMS Device Driver — REST API via libcurl + static token
 *
 * Second REST-based driver, generalized from the Wazuh driver. Where
 * Wazuh needs a JWT dance (basic-auth POST → bearer token → refresh),
 * LibreNMS authenticates every request with a static X-Auth-Token
 * header, so there is no token lifecycle at all.
 *
 * Handles:
 *   - Token auth (X-Auth-Token from device.api_token — never logged)
 *   - GET-only transport; non-GET method prefixes refused outright
 *   - http/https selection by port (443 → https, else http)
 *   - Command routing table for trust tier classification
 *
 * Design mirrors driver_wazuh.c:
 *   - The "command" parameter to execute() is a LibreNMS API path.
 *   - One CURL easy handle per connection, reused across requests.
 *   - Fixed buffers only; response lands in virp_exec_result_t.
 *
 * Build:  make LIBRENMS=1
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_driver_librenms.h"
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
 * Same discipline as the Wazuh table: enumerate the exact read-only
 * GETs the monitoring battery uses; every other path — including all
 * write endpoints, which are deliberately unclassified — is RED by
 * absence. No YELLOW rows, no BLACK rows, so every RED stays
 * approvable through propose/approve/apply.
 * ========================================================================= */

#define LN_API_PREFIX "/api/v0"

/* Exact-match GREEN paths (query strings ignored for matching). */
static const char *const LN_GREEN_EXACT[] = {
    LN_API_PREFIX "/devices",   /* device list + availability */
    LN_API_PREFIX "/alerts",    /* alert list / count          */
};

virp_trust_tier_t ln_route_path(const char *path)
{
    if (!path) return VIRP_TIER_RED;                 /* fail closed */

    /* Strip query string for matching */
    size_t plen = strlen(path);
    const char *qmark = strchr(path, '?');
    if (qmark)
        plen = (size_t)(qmark - path);

    for (size_t i = 0;
         i < sizeof(LN_GREEN_EXACT) / sizeof(LN_GREEN_EXACT[0]); i++) {
        size_t glen = strlen(LN_GREEN_EXACT[i]);
        if (glen == plen && strncmp(path, LN_GREEN_EXACT[i], glen) == 0)
            return VIRP_TIER_GREEN;
    }

    /*
     * Health is per-device: /api/v0/devices/<one segment>/health.
     * Exactly one path segment between "devices/" and "/health" —
     * "<a>/<b>/health" or an empty segment falls through RED.
     */
    static const char dev_prefix[] = LN_API_PREFIX "/devices/";
    static const char health_suffix[] = "/health";
    size_t dplen = sizeof(dev_prefix) - 1;
    size_t hslen = sizeof(health_suffix) - 1;
    if (plen > dplen + hslen &&
        strncmp(path, dev_prefix, dplen) == 0 &&
        strncmp(path + plen - hslen, health_suffix, hslen) == 0) {
        const char *seg = path + dplen;
        size_t seg_len = plen - dplen - hslen;
        if (seg_len > 0 && memchr(seg, '/', seg_len) == NULL)
            return VIRP_TIER_GREEN;
    }

    return VIRP_TIER_RED;                            /* RED by absence */
}

virp_trust_tier_t librenms_gate_tier(const char *command)
{
    if (!command) return VIRP_TIER_RED;
    while (*command == ' ') command++;
    if (strncmp(command, "GET ", 4) == 0) {
        command += 4;
        while (*command == ' ') command++;
    }
    if (command[0] != '/') return VIRP_TIER_RED;
    return ln_route_path(command);
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    CURL               *curl;
    char                base_url[512];      /* http(s)://host:port      */
    bool                connected;
};

/* =========================================================================
 * CURL write callback — accumulate response into a fixed buffer
 * ========================================================================= */

typedef struct {
    char   *buf;
    size_t  buf_size;
    size_t  offset;
} ln_response_t;

static size_t ln_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    ln_response_t *resp = (ln_response_t *)userdata;
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

static void ln_configure_tls(CURL *curl)
{
    const char *insecure = getenv("VIRP_LIBRENMS_INSECURE");
    if (insecure && strcmp(insecure, "1") == 0) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        return;
    }

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    const char *ca_bundle = getenv("VIRP_CA_BUNDLE");
    if (ca_bundle && ca_bundle[0] != '\0')
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
}

/*
 * One GET against the API. Internal transport helper shared by
 * connect-probe, execute, and health_check. The token goes into a
 * stack header buffer and is cleansed before return — it must never
 * reach a log line or an observation payload.
 */
static virp_error_t ln_get(struct virp_conn *conn, const char *path,
                           char *out, size_t out_len, long *http_code)
{
    char url[2048];
    snprintf(url, sizeof(url), "%s%s", conn->base_url, path);

    char auth_hdr[LN_TOKEN_MAX + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "X-Auth-Token: %s",
             conn->device.api_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);

    ln_response_t resp = { .buf = out, .buf_size = out_len, .offset = 0 };
    out[0] = '\0';

    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, ln_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(conn->curl, CURLOPT_CONNECTTIMEOUT,
                     (long)LN_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, (long)LN_API_TIMEOUT_SEC);
    ln_configure_tls(conn->curl);

    CURLcode rc = curl_easy_perform(conn->curl);

    curl_slist_free_all(headers);
    OPENSSL_cleanse(auth_hdr, sizeof(auth_hdr));

    if (rc != CURLE_OK) {
        fprintf(stderr, "[LibreNMS] curl error on %s: %s\n",
                conn->device.hostname, curl_easy_strerror(rc));
        if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_OPERATION_TIMEDOUT ||
            rc == CURLE_SSL_CONNECT_ERROR)
            conn->connected = false;
        return LN_ERR_CURL_PERFORM;
    }

    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, http_code);
    return VIRP_OK;
}

/* =========================================================================
 * Driver: connect — init CURL, validate the token with one probe
 * ========================================================================= */

static virp_conn_t *librenms_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    if (device->api_token[0] == '\0') {
        fprintf(stderr, "[LibreNMS] No api_token configured for %s\n",
                device->hostname);
        return NULL;
    }

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->connected = false;

    /* Port 443 → https; anything else → http (LibreNMS commonly runs
     * plain http on a management VLAN; 443 is the TLS convention). */
    uint16_t port = device->api_port ? device->api_port :
                    (device->port ? device->port : 80);
    snprintf(conn->base_url, sizeof(conn->base_url), "%s://%s:%u",
             port == 443 ? "https" : "http", device->host, port);

    conn->curl = curl_easy_init();
    if (!conn->curl) {
        fprintf(stderr, "[LibreNMS] curl_easy_init() failed\n");
        free(conn);
        return NULL;
    }

    fprintf(stderr, "[LibreNMS] Connecting to %s\n", conn->base_url);

    /* Validate the token with an internal probe (driver-internal, not
     * a gated command — same category as the Wazuh auth POST). */
    char probe[1024];
    long http_code = 0;
    virp_error_t err = ln_get(conn, LN_API_PREFIX "/system",
                              probe, sizeof(probe), &http_code);
    if (err != VIRP_OK || http_code != 200) {
        fprintf(stderr, "[LibreNMS] Token probe failed on %s: HTTP %ld\n",
                device->hostname, http_code);
        curl_easy_cleanup(conn->curl);
        OPENSSL_cleanse(conn->device.api_token,
                        sizeof(conn->device.api_token));
        free(conn);
        return NULL;
    }

    conn->connected = true;
    fprintf(stderr, "[LibreNMS] Connected: %s:%u\n", device->host, port);
    return (virp_conn_t *)conn;
}

/* =========================================================================
 * Driver: execute — one GET, response wrapped like the other drivers
 * ========================================================================= */

static virp_error_t librenms_execute(virp_conn_t *base_conn,
                                     const char *command,
                                     virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    /* GET-only transport honesty — same rule and same ordering as the
     * Wazuh driver: refuse non-GET method prefixes before anything
     * else, so a non-GET command can never be silently GETted. */
    const char *path = command;
    while (*path == ' ') path++;
    if (strncmp(path, "GET ", 4) == 0) {
        path += 4;
        while (*path == ' ') path++;
    }
    if (path[0] != '/') {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Refused: GET-only REST driver cannot honor '%.64s' "
                 "(non-GET method or unrooted path)", command);
        return VIRP_OK;
    }

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return LN_ERR_NOT_CONNECTED;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    char api_response[LN_RESPONSE_MAX];
    long http_code = 0;
    virp_error_t err = ln_get(conn, path, api_response,
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

        /* LibreNMS envelope: {"status":"ok",...} on success. */
        if (strstr(api_response, "\"status\"") &&
            !strstr(api_response, "\"status\":\"ok\"") &&
            !strstr(api_response, "\"status\": \"ok\"")) {
            result->success = false;
            result->exit_code = 1;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "LibreNMS API error in response from %s",
                     conn->device.hostname);
        }
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect / detect / health_check
 * ========================================================================= */

static void librenms_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
        conn->curl = NULL;
    }

    conn->connected = false;
    fprintf(stderr, "[LibreNMS] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.api_token, sizeof(conn->device.api_token));
    free(conn);
}

static bool librenms_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;
    return conn->device.vendor == VIRP_VENDOR_LIBRENMS;
}

static virp_error_t librenms_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->connected) return LN_ERR_NOT_CONNECTED;

    char probe[1024];
    long http_code = 0;
    virp_error_t err = ln_get(conn, LN_API_PREFIX "/system",
                              probe, sizeof(probe), &http_code);
    if (err != VIRP_OK) return err;
    return http_code == 200 ? VIRP_OK : LN_ERR_AUTH_FAILED;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t librenms_driver = {
    .name       = "librenms",
    .vendor     = VIRP_VENDOR_LIBRENMS,
    .connect    = librenms_connect,
    .execute    = librenms_execute,
    .disconnect = librenms_disconnect,
    .detect     = librenms_detect,
    .health_check = librenms_health_check,
    .route_command = librenms_gate_tier,
};

void virp_driver_librenms_init(void)
{
    virp_driver_register(&librenms_driver);
}
