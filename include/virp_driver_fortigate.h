/*
 * virp_driver_fortigate.h — FortiGate device driver for VIRP
 *
 * Dual-transport driver: REST API (primary) + SSH (fallback)
 *
 * Ported to appliance type system from tli-ops-center stub.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef VIRP_DRIVER_FORTIGATE_H
#define VIRP_DRIVER_FORTIGATE_H

#include "virp_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Transport mode ─────────────────────────────────────────────── */
typedef enum {
    FG_TRANSPORT_REST,      /* HTTPS REST API (Bearer token auth)   */
    FG_TRANSPORT_SSH,       /* SSH CLI (keyboard-interactive)        */
    FG_TRANSPORT_AUTO       /* Driver decides based on command type  */
} fg_transport_t;

/* ── REST API namespace ─────────────────────────────────────────── */
typedef enum {
    FG_API_MONITOR,         /* /api/v2/monitor/ — runtime state     */
    FG_API_CMDB             /* /api/v2/cmdb/    — configuration     */
} fg_api_namespace_t;

/* ── Command routing table entry ────────────────────────────────── */
typedef struct {
    const char         *command_pattern;
    const char         *api_endpoint;
    const char         *api_params;
    fg_api_namespace_t  ns;
    virp_trust_tier_t   tier;
} fg_command_route_t;

/* ── FortiGate-specific error codes (extend virp_error_t range) ── */
#define FG_ERR_NOT_CONNECTED    ((virp_error_t)(-100))
#define FG_ERR_TRANSPORT        ((virp_error_t)(-101))
#define FG_ERR_AUTH             ((virp_error_t)(-102))
#define FG_ERR_RATE_LIMITED     ((virp_error_t)(-103))
#define FG_ERR_NOT_FOUND        ((virp_error_t)(-104))

/* ── REST API response ──────────────────────────────────────────── */
typedef struct {
    int                  http_status;
    char                *body;
    size_t               body_len;
    char                *results_json;
    size_t               results_len;
    bool                 success;
    char                *error_msg;
} fg_api_response_t;

/* ── Public API ─────────────────────────────────────────────────── */

/* Driver init — call once at startup to register with driver registry */
void virp_driver_fortinet_init(void);

/* Command routing — maps CLI command to REST endpoint + trust tier */
virp_error_t fg_route_command(const char *command,
                              fg_transport_t *transport,
                              virp_trust_tier_t *tier,
                              const char **endpoint,
                              const char **params);

/* Extended routing — also returns API namespace (MONITOR vs CMDB) */
virp_error_t fg_route_command_ns(const char *command,
                                 fg_transport_t *transport,
                                 virp_trust_tier_t *tier,
                                 const char **endpoint,
                                 const char **params,
                                 fg_api_namespace_t *ns);

/* Exported for tests */
extern const size_t FG_ROUTE_TABLE_SIZE;
extern const fg_command_route_t FG_ROUTE_TABLE[];

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_FORTIGATE_H */
