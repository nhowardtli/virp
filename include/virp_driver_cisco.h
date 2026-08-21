/*
 * virp_driver_cisco.h — Cisco IOS/IOS-XE device driver for VIRP
 *
 * Dual-transport driver: RESTCONF (primary) + SSH (fallback)
 *
 * RESTCONF handles structured monitoring via YANG models:
 *   - Interface stats, routing tables, ARP, MAC tables
 *   - Returns JSON (YANG-modeled) → structured observation payload
 *
 * SSH handles CLI-only commands:
 *   - show tech-support
 *   - debug commands
 *   - Any command not mapped to a YANG model
 *
 * Cisco IOS-XE RESTCONF base path:
 *   /restconf/data/Cisco-IOS-XE-*
 *   /restconf/data/ietf-*
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef VIRP_DRIVER_CISCO_H
#define VIRP_DRIVER_CISCO_H

#include "virp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Transport mode ─────────────────────────────────────────────── */
typedef enum {
    CISCO_TRANSPORT_RESTCONF,   /* RESTCONF over HTTPS (YANG models) */
    CISCO_TRANSPORT_SSH,        /* SSH CLI                           */
    CISCO_TRANSPORT_AUTO        /* Driver decides based on command   */
} cisco_transport_t;

/* ── RESTCONF data source ───────────────────────────────────────── */
typedef enum {
    CISCO_DS_OPERATIONAL,       /* Operational state data            */
    CISCO_DS_RUNNING            /* Running configuration             */
} cisco_datastore_t;

/* ── Cisco connection context ───────────────────────────────────── */
typedef struct {
    virp_conn_t             base;

    /* RESTCONF transport */
    void                   *curl_handle;
    char                   *base_url;         /* https://host:443         */
    char                   *username;
    char                   *password;
    int                     restconf_port;
    bool                    verify_tls;

    /* SSH transport */
    void                   *ssh_session;
    void                   *ssh_channel;
    int                     ssh_socket;
    int                     ssh_port;
    char                   *enable_password;

    /* State */
    cisco_transport_t       preferred;
    bool                    restconf_connected;
    bool                    ssh_connected;
    char                   *ios_version;
    char                   *hostname;
    char                   *serial_number;
    char                   *model;
    bool                    is_iosxe;        /* IOS-XE supports RESTCONF */
} cisco_conn_t;

/* ── Cisco device config ────────────────────────────────────────── */
typedef struct {
    virp_device_t           base;
    char                   *enable_password;
    int                     restconf_port;
    bool                    verify_tls;
    cisco_transport_t       transport;
} cisco_device_config_t;

/* ── Public API ─────────────────────────────────────────────────── */
const virp_driver_t       *virp_driver_cisco(void);
virp_error_t               virp_driver_cisco_register(void);

/*
 * Gate-facing command classifier (VIRP tier-enforcement gate).
 *
 * Matches the gate's route_command(const char*) contract. Shared CORE
 * for BOTH classic IOS and IOS-XE. Now defined in
 * src/drivers/cisco_canon.c: canonicalizer (all prefix/abbreviation
 * logic, ambiguity fails closed) + exact-match tier table on canonical
 * strings only. FAIL-CLOSED: any command without a canonical, tabled
 * form returns RED. See virp_driver_cisco_canon.h.
 */
virp_trust_tier_t cisco_gate_tier(const char *command);

/*
 * BLACK tier check — returns true if the command is destructive
 * and must never be transmitted to the device.
 */
bool cisco_is_black_tier(const char *command);

/*
 * Credential scrub for config-bearing reads (2026-08-10).
 *
 * cisco_scrub_config rewrites IOS config text so credential material
 * (enable secrets, password 7 strings, SNMP communities, ISAKMP
 * pre-shared keys, MD5 auth keys, key-strings) is replaced with
 * "<removed>" BEFORE the observation body reaches the signer. Pure
 * function, exposed for the unit suite (same precedent as
 * fg_scrub_reply). Fail-closed: on VIRP_ERR_BUFFER_TOO_SMALL the
 * caller must not use — and must not sign — any partial output.
 *
 * cisco_command_returns_config identifies the commands whose replies
 * embed configuration; cisco_execute applies the scrub to exactly
 * those. All config-bearing reads classify YELLOW (the 2026-08-10
 * GREEN reclassification was reverted 2026-08-11 — the scrub misses
 * secret classes); the scrub still runs on every approved read.
 */
/*
 * Compose hostname#command\nbody into result->output with honest
 * length accounting (Item 5): output_len is the actual stored byte
 * count; a clamped scrubbed body is withheld typed; a clamped raw
 * body is marked output_truncated. Exposed for the unit suite.
 */
virp_error_t cisco_store_output(virp_exec_result_t *result,
                                const char *hostname,
                                const char *command,
                                const char *body,
                                bool scrubbed_body);

virp_error_t cisco_scrub_config(const char *in, size_t in_len,
                                char *out, size_t out_cap,
                                size_t *out_len);
bool cisco_command_returns_config(const char *command);

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_CISCO_H */
