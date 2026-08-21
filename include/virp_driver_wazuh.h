/*
 * virp_driver_wazuh.h — Wazuh Manager REST API driver for VIRP
 *
 * First REST-based driver. Uses libcurl + JWT auth instead of libssh2.
 *
 * Wazuh API flow:
 *   1. POST /security/user/authenticate (basic auth) → JWT token
 *   2. GET /endpoint (Bearer token) → JSON response
 *   3. Token refresh before expiry (default 15 min)
 *
 * Polling endpoints (collector intervals managed by caller):
 *   /agents?select=id,name,status,ip          — every 600s
 *   /alerts?limit=100&sort=-timestamp          — every 300s
 *   /vulnerability                             — every 3600s
 *   /syscheck                                  — every 1800s
 *
 * All responses are wrapped in VIRP OBSERVATIONs via the standard
 * driver execute() path. The "command" parameter is the API endpoint.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef VIRP_DRIVER_WAZUH_H
#define VIRP_DRIVER_WAZUH_H

#include "virp_driver.h"
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Wazuh-specific error codes (extend virp_error_t range) ───── */
#define WZ_ERR_NOT_CONNECTED    ((virp_error_t)(-200))
#define WZ_ERR_AUTH_FAILED      ((virp_error_t)(-201))
#define WZ_ERR_TOKEN_EXPIRED    ((virp_error_t)(-202))
#define WZ_ERR_API_ERROR        ((virp_error_t)(-203))
#define WZ_ERR_CURL_INIT        ((virp_error_t)(-204))
#define WZ_ERR_CURL_PERFORM     ((virp_error_t)(-205))

/* ── Collector endpoint definitions ───────────────────────────── */
#define WZ_EP_AGENTS         "/agents?select=id,name,status,ip"
#define WZ_EP_AGENT_SUMMARY  "/agents/summary/status"
#define WZ_EP_LOGS_SUMMARY   "/manager/logs/summary"
#define WZ_EP_SYSCHECK       "/syscheck/001?limit=100"
#define WZ_EP_VULNERABILITY  "/vulnerability/001/last_scan"
#define WZ_EP_AUTH           "/security/user/authenticate"
#define WZ_EP_MANAGER_STATUS "/manager/status"
#define WZ_EP_MANAGER_INFO   "/manager/info"

/* ── Recommended polling intervals (seconds) ──────────────────── */
#define WZ_INTERVAL_AGENTS      600
#define WZ_INTERVAL_ALERTS      300
#define WZ_INTERVAL_VULN        3600
#define WZ_INTERVAL_SYSCHECK    1800

/* ── Token / connection tunables ──────────────────────────────── */
#define WZ_TOKEN_MAX            4096    /* Max JWT token length         */
#define WZ_TOKEN_REFRESH_SEC    840     /* Refresh 1 min before 15m expiry */
#define WZ_API_TIMEOUT_SEC      30      /* Per-request timeout          */
#define WZ_CONNECT_TIMEOUT_SEC  10      /* TCP connect timeout          */
#define WZ_RESPONSE_MAX         (VIRP_OUTPUT_MAX - 256)  /* Leave room for prefix */

/* ── Command routing table entry ──────────────────────────────── */
typedef struct {
    const char            *endpoint_pattern;  /* API endpoint prefix         */
    virp_trust_tier_t      tier;              /* GREEN/YELLOW/RED/BLACK      */
} wz_command_route_t;

/* ── Public API ───────────────────────────────────────────────── */
void              virp_driver_wazuh_init(void);
const virp_driver_t *virp_driver_wazuh(void);

/*
 * Route an API endpoint to its trust tier. EXACT path match (query
 * string ignored) against the enumerated GREEN read set; everything
 * else is VIRP_TIER_RED (fail closed). The table carries no YELLOW,
 * BLACK, or write rows.
 */
virp_trust_tier_t wz_route_endpoint(const char *endpoint);

/*
 * route_command hook for the O-Node tier gate: accepts an optional
 * "GET " prefix, REDs any other method prefix or unrooted path, then
 * defers to wz_route_endpoint.
 */
virp_trust_tier_t wazuh_gate_tier(const char *command);

extern const size_t          WZ_ROUTE_TABLE_SIZE;
extern const wz_command_route_t WZ_ROUTE_TABLE[];

/* ── BLACK tier: protected agents + never-dispatch endpoints ─────
 *
 * Separate from the tier table on purpose, exactly as FortiGate keeps
 * FG_BLACK_COMMANDS separate from FG_ROUTE_TABLE. BLACK is not a tier
 * a request can hold and then out-rank with an approval — it is a
 * refusal inside execute(), before anything reaches the wire.
 */
#define WZ_PROTECTED_AGENT_MAX  64

/*
 * Register protected agent ids from a comma-separated decimal list.
 * Accumulates across calls (the union over every wazuh device) and
 * de-duplicates. Returns 0 on success, -1 if the list does not parse —
 * in which case NOTHING from that list is registered, so a half-parsed
 * list can never leave a partial protection in force. The loader treats
 * -1 as fatal rather than running without a declared protection.
 */
int  wazuh_gate_set_protected_agents(const char *csv);

/* Test-only reset — the daemon never calls this. */
void wazuh_gate_clear_protected_agents(void);

/* Number of registered protected agents (test/introspection). */
size_t wazuh_gate_protected_agent_count(void);

/*
 * True if this command must never be dispatched. Checked at the top of
 * wazuh_execute(). Denies, independent of HTTP method:
 *   - any endpoint naming a registered protected agent, in a path
 *     segment or in an agent-selecting query parameter
 *   - agent deletion (DELETE against /agents)
 *   - the manager's / cluster's own configuration
 *   - active-response dispatch
 * Deliberately over-matching: this is a deny list, so a false positive
 * costs a read and a false negative costs the SIEM.
 */
bool wz_is_black_endpoint(const char *command);

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_WAZUH_H */
