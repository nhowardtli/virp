/*
 * virp_driver_zammad.h — Zammad REST API driver for VIRP
 *
 * Third token-auth REST driver, same shape as the LibreNMS one: a
 * static personal access token in a header, no token lifecycle,
 * GET-only transport.
 *
 * Device config mapping (devices.json):
 *   host       — Zammad host/FQDN (must match the certificate)
 *   api_token  — Zammad personal access token, sent as
 *                "Authorization: Token token=<value>" (NOT Bearer)
 *   api_port / port — API port; default 443. The scheme is ALWAYS
 *                https regardless of port — see the TLS note below.
 *
 * TLS: verification is unconditional. There is no VIRP_ZAMMAD_INSECURE
 * escape hatch (unlike the Wazuh driver's lab drop-in), no CA-bundle
 * override, and no plaintext scheme selection (unlike the LibreNMS
 * driver, where a non-443 port silently means http). The Zammad
 * certificate is in the host CA store; anything that would make this
 * driver accept a different identity is a config knob that disables
 * TLS, so none exists.
 *
 * The "command" parameter to execute() is a Zammad API path, e.g.
 *   /api/v1/tickets?per_page=50
 *   /api/v1/ticket_articles/by_ticket/1234
 *
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 */

#ifndef VIRP_DRIVER_ZAMMAD_H
#define VIRP_DRIVER_ZAMMAD_H

#include "virp_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Zammad-specific error codes (extend virp_error_t range) ───── */
#define ZM_ERR_NOT_CONNECTED    ((virp_error_t)(-230))
#define ZM_ERR_AUTH_FAILED      ((virp_error_t)(-231))
#define ZM_ERR_CURL_INIT        ((virp_error_t)(-232))
#define ZM_ERR_CURL_PERFORM     ((virp_error_t)(-233))
#define ZM_ERR_API_ERROR        ((virp_error_t)(-234))

/* ── Tunables ─────────────────────────────────────────────────── */
#define ZM_API_TIMEOUT_SEC      30
#define ZM_CONNECT_TIMEOUT_SEC  10
#define ZM_DEFAULT_PORT         443
#define ZM_TOKEN_MAX            256
#define ZM_RESPONSE_MAX         (VIRP_OUTPUT_MAX - 256)

/*
 * LOAD-BEARING INVARIANT — these two caps are not tidiness, and
 * removing or raising either one silently breaks a security property.
 *
 * The property: a path that classifies GREEN can never be long enough
 * to truncate in the URL buffer, so the request that goes on the wire
 * is always the request that was classified and signed.
 *
 * How the two caps produce it:
 *
 *   ZM_DIGITS_MAX bounds every variable-length element a GREEN path
 *   can contain. There are only two — the <id> segment and a
 *   page/per_page value — and both are digit runs. With the fixed row
 *   text (longest base 34 bytes) plus at most one id and two query
 *   values, a GREEN path cannot exceed 110 bytes. 20 digits holds any
 *   value a uint64 can express, so no real Zammad object id is
 *   excluded; the cap costs nothing and buys the bound.
 *
 *   ZM_PATH_MAX is the backstop for everything else, and is checked in
 *   BOTH places that matter: zm_route_path() refuses a longer path
 *   outright, and zm_get() refuses it again before building the URL.
 *   512 + the longest base_url ("https://" + 255-byte host + ":65535")
 *   stays far inside the 2048-byte url[] buffer, and zm_get() also
 *   checks the snprintf return, so truncation is caught even if these
 *   bounds are later wrong.
 *
 * Why the CLASSIFIER carries the cap and not just the transport: if
 * only the transport enforced it, an over-long path could classify
 * GREEN, be approved and signed, and then be refused at dispatch — the
 * gate would have blessed a request the driver cannot make. Classifier
 * and transport must agree on what is issuable, so the bound lives in
 * both.
 *
 * If a future Zammad row needs a non-numeric variable segment, this
 * argument does NOT carry over: the new element has to come with its
 * own length bound, or the truncation property is gone.
 */
#define ZM_DIGITS_MAX           20      /* see invariant above — load-bearing */
#define ZM_PATH_MAX             512     /* see invariant above — load-bearing */

/* ── Collector endpoints (the GREEN read set, verbatim) ───────── */
#define ZM_API_PREFIX           "/api/v1"
#define ZM_EP_TICKETS           ZM_API_PREFIX "/tickets"
#define ZM_EP_TICKET_STATES     ZM_API_PREFIX "/ticket_states"
#define ZM_EP_GROUPS            ZM_API_PREFIX "/groups"

/* ── Public API ───────────────────────────────────────────────── */
void                 virp_driver_zammad_init(void);
const virp_driver_t *virp_driver_zammad(void);

/*
 * Route an API path (with optional query string) to its trust tier.
 *
 * GREEN is exactly five shapes, matched byte-exact:
 *   /api/v1/tickets
 *   /api/v1/tickets/<id>
 *   /api/v1/ticket_articles/by_ticket/<id>
 *   /api/v1/ticket_states
 *   /api/v1/groups
 * where <id> is 1..ZM_DIGITS_MAX ASCII digits and nothing else.
 *
 * A query string, if present, may carry only "page" and "per_page",
 * each at most once, each with a digits-only value. Any other
 * parameter name, any non-numeric or empty value, a repeated
 * parameter, a bare "?", or a malformed pair is RED.
 *
 * Everything else — every write endpoint, every unlisted read — is
 * VIRP_TIER_RED by absence (fail closed). No YELLOW rows, no BLACK
 * rows, so every RED stays approvable through propose/approve/apply.
 */
virp_trust_tier_t zm_route_path(const char *path);

/*
 * route_command hook for the O-Node tier gate: accepts an optional
 * "GET " prefix, REDs any other method prefix or unrooted path, then
 * defers to zm_route_path.
 */
virp_trust_tier_t zammad_gate_tier(const char *command);

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_ZAMMAD_H */
