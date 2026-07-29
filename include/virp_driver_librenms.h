/*
 * virp_driver_librenms.h — LibreNMS REST API driver for VIRP
 *
 * Second REST-based driver, generalized from the Wazuh driver's
 * libcurl approach. Simpler auth: LibreNMS uses a static API token
 * (X-Auth-Token header) — no JWT lifecycle.
 *
 * Device config mapping (devices.json):
 *   host       — LibreNMS host/IP
 *   api_token  — the read-only API token (X-Auth-Token)
 *   api_port / port — API port; 443 selects https, anything else http
 *
 * The "command" parameter to execute() is a LibreNMS API path, e.g.
 *   /api/v0/devices
 *   /api/v0/alerts?state=1
 *
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 */

#ifndef VIRP_DRIVER_LIBRENMS_H
#define VIRP_DRIVER_LIBRENMS_H

#include "virp_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── LibreNMS-specific error codes (extend virp_error_t range) ── */
#define LN_ERR_NOT_CONNECTED    ((virp_error_t)(-210))
#define LN_ERR_AUTH_FAILED      ((virp_error_t)(-211))
#define LN_ERR_CURL_INIT        ((virp_error_t)(-212))
#define LN_ERR_CURL_PERFORM     ((virp_error_t)(-213))

/* ── Tunables ─────────────────────────────────────────────────── */
#define LN_API_TIMEOUT_SEC      30
#define LN_CONNECT_TIMEOUT_SEC  10
#define LN_TOKEN_MAX            256
#define LN_RESPONSE_MAX         (VIRP_OUTPUT_MAX - 256)

/* ── Public API ───────────────────────────────────────────────── */
void virp_driver_librenms_init(void);

/*
 * Route an API path to its trust tier. The GREEN set is exactly the
 * autopilot read battery: /api/v0/devices, /api/v0/alerts, and the
 * per-device /api/v0/devices/<one-segment>/health. Query strings are
 * ignored for matching. Everything else — including every write
 * endpoint, which is deliberately unclassified — is VIRP_TIER_RED
 * (fail closed). No YELLOW rows, no BLACK rows.
 */
virp_trust_tier_t ln_route_path(const char *path);

/*
 * route_command hook for the O-Node tier gate: accepts an optional
 * "GET " prefix, REDs any other method prefix or unrooted path, then
 * defers to ln_route_path.
 */
virp_trust_tier_t librenms_gate_tier(const char *command);

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_LIBRENMS_H */
