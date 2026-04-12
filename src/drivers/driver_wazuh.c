/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Wazuh Manager Device Driver — REST API via libcurl + JWT
 *
 * First REST-based VIRP driver. All other drivers use SSH via libssh2.
 *
 * Handles:
 *   - JWT authentication (POST /security/user/authenticate with basic auth)
 *   - Token lifecycle (auto-refresh before 15-minute expiry)
 *   - HTTPS GET to collector endpoints (agents, alerts, vuln, syscheck)
 *   - Self-signed TLS (verify off — lab environment)
 *   - Output scrubbing (HTTP envelope stripped, raw JSON payload kept)
 *   - Command routing table for trust tier classification
 *
 * Design:
 *   - The "command" parameter to execute() is a Wazuh API endpoint path.
 *   - Polling intervals are NOT managed by this driver — the caller
 *     (O-Node collector loop, cron, or batch_execute) controls timing.
 *   - One CURL easy handle per connection, reused across requests.
 *   - No dynamic allocation outside of CURL internals — result goes
 *     into the fixed virp_exec_result_t buffer.
 *
 * Dependencies:
 *   - libcurl (HTTPS transport + basic auth)
 *   - libssl  (already a VIRP dependency)
 *
 * Build:  make WAZUH=1
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_driver_wazuh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/crypto.h>

/* =========================================================================
 * Command Routing Table — Wazuh API endpoints → trust tiers
 *
 * All endpoints in this driver are read-only. Tier classification:
 *   GREEN  — agent status, health checks (passive monitoring)
 *   YELLOW — alerts, vulnerability, syscheck (security-sensitive data)
 *
 * Prefix-matched, longest match wins. Unmapped defaults to GREEN
 * (Wazuh API user is read-only, role ID 2).
 * ========================================================================= */

const wz_command_route_t WZ_ROUTE_TABLE[] = {
    /* ── Tier 1: GREEN — Passive monitoring (no approval) ──────── */
    { "/agents",                    VIRP_TIER_GREEN  },
    { "/manager/status",            VIRP_TIER_GREEN  },
    { "/manager/info",              VIRP_TIER_GREEN  },
    { "/manager/configuration",     VIRP_TIER_GREEN  },
    { "/manager/logs",              VIRP_TIER_GREEN  },
    { "/cluster/status",            VIRP_TIER_GREEN  },
    { "/cluster/nodes",             VIRP_TIER_GREEN  },
    { "/syscollector",              VIRP_TIER_GREEN  },
    { "/overview/agents",           VIRP_TIER_GREEN  },

    /* ── Tier 2: YELLOW — Security telemetry (single approval) ── */
    { "/vulnerability",             VIRP_TIER_YELLOW },
    { "/syscheck",                  VIRP_TIER_YELLOW },
    { "/security/users",            VIRP_TIER_YELLOW },
    { "/security/roles",            VIRP_TIER_YELLOW },
    { "/security/rules",            VIRP_TIER_YELLOW },
    { "/security/actions",          VIRP_TIER_YELLOW },
    { "/rootcheck",                 VIRP_TIER_YELLOW },
    { "/ciscat",                    VIRP_TIER_YELLOW },

    /* ── BLACK — Destructive (never transmitted) ─────────────── */
    { "/security/user/authenticate", VIRP_TIER_BLACK },  /* Auth endpoint — internal only */
    { "/active-response",           VIRP_TIER_BLACK },   /* Can trigger actions on agents */
    { "/manager/restart",           VIRP_TIER_BLACK },   /* Restarts the manager */
    { "/agents/restart",            VIRP_TIER_BLACK },   /* Restarts agents */
};

const size_t WZ_ROUTE_TABLE_SIZE =
    sizeof(WZ_ROUTE_TABLE) / sizeof(WZ_ROUTE_TABLE[0]);

/* =========================================================================
 * Endpoint Routing — prefix match, longest wins
 * ========================================================================= */

virp_trust_tier_t wz_route_endpoint(const char *endpoint)
{
    if (!endpoint) return VIRP_TIER_GREEN;

    /* Strip query string for matching */
    size_t ep_len = strlen(endpoint);
    const char *qmark = strchr(endpoint, '?');
    if (qmark)
        ep_len = (size_t)(qmark - endpoint);

    const wz_command_route_t *best = NULL;
    size_t best_len = 0;

    for (size_t i = 0; i < WZ_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(WZ_ROUTE_TABLE[i].endpoint_pattern);
        if (plen <= ep_len &&
            strncmp(endpoint, WZ_ROUTE_TABLE[i].endpoint_pattern, plen) == 0) {
            if (plen > best_len) {
                best = &WZ_ROUTE_TABLE[i];
                best_len = plen;
            }
        }
    }

    return best ? best->tier : VIRP_TIER_GREEN;
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    CURL               *curl;               /* Reusable CURL handle         */
    char                base_url[512];       /* https://host:port            */
    char                jwt_token[WZ_TOKEN_MAX]; /* Current Bearer token     */
    time_t              token_obtained;      /* When we got the token        */
    time_t              token_expiry;        /* When to refresh              */
    bool                connected;
    bool                authenticated;
};

/* =========================================================================
 * CURL Write Callback — accumulate response into a fixed buffer
 *
 * userdata points to a wz_response_t which tracks the write position.
 * ========================================================================= */

typedef struct {
    char   *buf;
    size_t  buf_size;
    size_t  offset;
} wz_response_t;

static size_t wz_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    wz_response_t *resp = (wz_response_t *)userdata;
    size_t bytes = size * nmemb;
    size_t avail = resp->buf_size - resp->offset - 1;  /* Reserve NUL */

    if (bytes > avail)
        bytes = avail;

    if (bytes > 0) {
        memcpy(resp->buf + resp->offset, ptr, bytes);
        resp->offset += bytes;
        resp->buf[resp->offset] = '\0';
    }

    return size * nmemb;  /* Always report full consumption to curl */
}

/* =========================================================================
 * JWT Authentication
 *
 * POST /security/user/authenticate
 * Authorization: Basic base64(username:password)
 *
 * Response: {"data": {"token": "eyJ..."}}
 *
 * CURL handles basic auth natively via CURLOPT_USERPWD.
 * ========================================================================= */

static virp_error_t wz_authenticate(struct virp_conn *conn)
{
    if (!conn || !conn->curl)
        return WZ_ERR_CURL_INIT;

    char url[1024];
    snprintf(url, sizeof(url), "%s%s", conn->base_url, WZ_EP_AUTH);

    /* Response buffer for the JWT JSON */
    char resp_buf[WZ_TOKEN_MAX * 2];
    wz_response_t resp = {
        .buf = resp_buf,
        .buf_size = sizeof(resp_buf),
        .offset = 0,
    };

    /* Credentials for basic auth */
    char userpwd[256];
    snprintf(userpwd, sizeof(userpwd), "%s:%s",
             conn->device.username, conn->device.password);

    /* Configure CURL for auth request */
    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(conn->curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, wz_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(conn->curl, CURLOPT_CONNECTTIMEOUT, (long)WZ_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, (long)WZ_API_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_SSL_VERIFYPEER, 0L);  /* Self-signed */
    curl_easy_setopt(conn->curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode rc = curl_easy_perform(conn->curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "[Wazuh] Auth curl_easy_perform failed: %s (%s)\n",
                curl_easy_strerror(rc), url);
        return WZ_ERR_CURL_PERFORM;
    }

    long http_code = 0;
    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        fprintf(stderr, "[Wazuh] Auth failed: HTTP %ld from %s\n"
                        "[Wazuh] Response: %.256s\n",
                http_code, url, resp_buf);
        return WZ_ERR_AUTH_FAILED;
    }

    /*
     * Extract JWT from: {"data": {"token": "eyJ..."}}
     *
     * Minimal JSON parse — find "token" key, extract value.
     * Same approach as the O-Node's json_extract_string, but
     * we need to handle Wazuh's nested response shape.
     */
    const char *tok_key = "\"token\"";
    const char *tok_pos = strstr(resp_buf, tok_key);
    if (!tok_pos) {
        fprintf(stderr, "[Wazuh] Auth response has no 'token' field\n"
                        "[Wazuh] Response: %.512s\n", resp_buf);
        return WZ_ERR_AUTH_FAILED;
    }

    /* Skip past "token" and find the colon, then the opening quote */
    tok_pos += strlen(tok_key);
    while (*tok_pos == ' ' || *tok_pos == ':' || *tok_pos == '\t')
        tok_pos++;
    if (*tok_pos != '"') {
        fprintf(stderr, "[Wazuh] Malformed token value in auth response\n");
        return WZ_ERR_AUTH_FAILED;
    }
    tok_pos++;  /* Skip opening quote */

    /* Copy token until closing quote */
    size_t ti = 0;
    while (*tok_pos && *tok_pos != '"' && ti < WZ_TOKEN_MAX - 1)
        conn->jwt_token[ti++] = *tok_pos++;
    conn->jwt_token[ti] = '\0';

    if (ti == 0) {
        fprintf(stderr, "[Wazuh] Empty token in auth response\n");
        return WZ_ERR_AUTH_FAILED;
    }

    conn->token_obtained = time(NULL);
    conn->token_expiry = conn->token_obtained + WZ_TOKEN_REFRESH_SEC;
    conn->authenticated = true;

    fprintf(stderr, "[Wazuh] Authenticated: %s@%s (token %zu bytes, "
                    "refresh in %ds)\n",
            conn->device.username, conn->device.host,
            ti, WZ_TOKEN_REFRESH_SEC);

    return VIRP_OK;
}

/* =========================================================================
 * Token Refresh — re-authenticate if token is near expiry
 * ========================================================================= */

static virp_error_t wz_ensure_token(struct virp_conn *conn)
{
    if (!conn->authenticated || time(NULL) >= conn->token_expiry) {
        fprintf(stderr, "[Wazuh] Token expired or missing, re-authenticating\n");
        return wz_authenticate(conn);
    }
    return VIRP_OK;
}

/* =========================================================================
 * Driver: connect
 *
 * Initializes CURL handle, builds base URL, authenticates.
 * ========================================================================= */

static virp_conn_t *wazuh_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->connected = false;
    conn->authenticated = false;

    /* Build base URL — Wazuh API default port is 55000 */
    uint16_t port = device->api_port ? device->api_port :
                    (device->port ? device->port : 55000);
    snprintf(conn->base_url, sizeof(conn->base_url),
             "https://%s:%u", device->host, port);

    /* Initialize CURL */
    conn->curl = curl_easy_init();
    if (!conn->curl) {
        fprintf(stderr, "[Wazuh] curl_easy_init() failed\n");
        free(conn);
        return NULL;
    }

    fprintf(stderr, "[Wazuh] Connecting to %s as %s\n",
            conn->base_url, device->username);

    /* Authenticate — get JWT */
    virp_error_t err = wz_authenticate(conn);
    if (err != VIRP_OK) {
        fprintf(stderr, "[Wazuh] Authentication failed: %d\n", err);
        curl_easy_cleanup(conn->curl);
        free(conn);
        return NULL;
    }

    conn->connected = true;

    fprintf(stderr, "[Wazuh] Connected: %s@%s:%u\n",
            device->username, device->host, port);

    return (virp_conn_t *)conn;
}

/* =========================================================================
 * Driver: execute
 *
 * The "command" is a Wazuh API endpoint path, e.g.:
 *   /agents?select=id,name,status,ip
 *   /alerts?limit=100&sort=-timestamp
 *
 * Steps:
 *   1. Ensure JWT token is fresh (refresh if near expiry)
 *   2. Build full URL: base_url + endpoint
 *   3. GET with Authorization: Bearer <token>
 *   4. Copy JSON response into result buffer
 *   5. Check for API-level errors
 * ========================================================================= */

static virp_error_t wazuh_execute(virp_conn_t *base_conn,
                                  const char *command,
                                  virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return WZ_ERR_NOT_CONNECTED;
    }

    /*
     * Strip HTTP method prefix if present.
     *
     * IronClaw (R-Node AI) may send commands like "GET /agents?status=active&limit=20".
     * The Wazuh driver only needs the endpoint path — the HTTP method is always GET
     * (all endpoints are read-only). The method prefix would corrupt the URL if
     * concatenated directly (e.g. "https://host:55000GET /agents?...").
     *
     * The endpoint path (with query string) goes straight to libcurl's CURLOPT_URL
     * as a C string — no shell interpretation, no fork/exec. Characters like & in
     * the query string are URL parameter separators, not shell operators.
     */
    const char *endpoint = command;
    if (strncmp(command, "GET ",     4) == 0) endpoint = command + 4;
    else if (strncmp(command, "POST ",    5) == 0) endpoint = command + 5;
    else if (strncmp(command, "PUT ",     4) == 0) endpoint = command + 4;
    else if (strncmp(command, "DELETE ",  7) == 0) endpoint = command + 7;
    else if (strncmp(command, "PATCH ",   6) == 0) endpoint = command + 6;

    /* Ensure endpoint starts with '/' */
    if (endpoint[0] != '/') {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Invalid endpoint (must start with /): %.64s", command);
        return VIRP_OK;
    }

    /* Check trust tier — refuse BLACK-tier endpoints */
    virp_trust_tier_t tier = wz_route_endpoint(endpoint);
    if (tier == VIRP_TIER_BLACK) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Endpoint blocked (BLACK tier): %s", endpoint);
        return VIRP_OK;
    }

    /* Step 1: Ensure token is fresh */
    virp_error_t err = wz_ensure_token(conn);
    if (err != VIRP_OK) {
        conn->connected = false;
        conn->authenticated = false;
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Token refresh failed on %s", conn->device.hostname);
        return VIRP_OK;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Step 2: Build URL — base_url + endpoint path, passed directly to libcurl */
    char url[2048];
    snprintf(url, sizeof(url), "%s%s", conn->base_url, endpoint);

    /* Step 3: Build Authorization header */
    char auth_hdr[WZ_TOKEN_MAX + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s",
             conn->jwt_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Response buffer — write after the hostname prefix */
    char api_response[WZ_RESPONSE_MAX];
    wz_response_t resp = {
        .buf = api_response,
        .buf_size = sizeof(api_response),
        .offset = 0,
    };

    /* Configure CURL for API request */
    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, wz_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(conn->curl, CURLOPT_CONNECTTIMEOUT, (long)WZ_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, (long)WZ_API_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(conn->curl, CURLOPT_SSL_VERIFYHOST, 0L);

    CURLcode rc = curl_easy_perform(conn->curl);

    curl_slist_free_all(headers);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

    if (rc != CURLE_OK) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "curl error on %s: %s", conn->device.hostname,
                 curl_easy_strerror(rc));
        /* Connection-level failures mark session stale */
        if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_OPERATION_TIMEDOUT ||
            rc == CURLE_SSL_CONNECT_ERROR) {
            conn->connected = false;
        }
        return VIRP_OK;
    }

    long http_code = 0;
    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);

    /* Step 4: Format output like other drivers: hostname>endpoint\nresponse */
    int written = snprintf(result->output, sizeof(result->output),
                           "%s>%s [HTTP %ld]\n%s",
                           conn->device.hostname, endpoint,
                           http_code, api_response);
    result->output_len = (written > 0) ? (size_t)written : 0;

    /* Step 5: Check for errors */
    if (http_code == 401) {
        /* Token expired server-side — force re-auth on next call */
        conn->authenticated = false;
        result->success = false;
        result->exit_code = 401;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "HTTP 401 Unauthorized — token invalidated on %s",
                 conn->device.hostname);
    } else if (http_code >= 400) {
        result->success = false;
        result->exit_code = (int)http_code;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "HTTP %ld from %s%s", http_code,
                 conn->device.hostname, endpoint);
    } else {
        result->success = true;
        result->exit_code = 0;

        /* Check for Wazuh API error in JSON body */
        if (strstr(api_response, "\"error\"") &&
            !strstr(api_response, "\"error\":0") &&
            !strstr(api_response, "\"error\": 0")) {
            result->success = false;
            result->exit_code = 1;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Wazuh API error in response from %s",
                     conn->device.hostname);
        }
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect
 * ========================================================================= */

static void wazuh_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
        conn->curl = NULL;
    }

    /* Zero the token in memory */
    volatile char *p = (volatile char *)conn->jwt_token;
    for (size_t i = 0; i < WZ_TOKEN_MAX; i++)
        p[i] = '\0';

    conn->connected = false;
    conn->authenticated = false;

    fprintf(stderr, "[Wazuh] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
    free(conn);
}

/* =========================================================================
 * Driver: detect
 * ========================================================================= */

static bool wazuh_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;
    return conn->device.vendor == VIRP_VENDOR_WAZUH;
}

/* =========================================================================
 * Driver: health_check — GET /manager/status
 * ========================================================================= */

static virp_error_t wazuh_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->connected) return WZ_ERR_NOT_CONNECTED;

    virp_exec_result_t result;
    virp_error_t err = wazuh_execute(base_conn, WZ_EP_MANAGER_STATUS, &result);
    if (err != VIRP_OK) return err;

    return result.success ? VIRP_OK : WZ_ERR_API_ERROR;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t wazuh_driver = {
    .name       = "wazuh",
    .vendor     = VIRP_VENDOR_WAZUH,
    .connect    = wazuh_connect,
    .execute    = wazuh_execute,
    .disconnect = wazuh_disconnect,
    .detect     = wazuh_detect,
    .health_check = wazuh_health_check,
};

const virp_driver_t *virp_driver_wazuh(void)
{
    return &wazuh_driver;
}

void virp_driver_wazuh_init(void)
{
    virp_driver_register(&wazuh_driver);
}
