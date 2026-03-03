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

/* ── Command routing table entry ────────────────────────────────── */
typedef struct {
    const char            *command_pattern;   /* CLI command prefix       */
    const char            *restconf_path;     /* RESTCONF URI path        */
    const char            *yang_module;       /* YANG module name         */
    cisco_datastore_t      datastore;
    virp_trust_tier_t      tier;
} cisco_command_route_t;

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

virp_error_t cisco_route_command(const char *command,
                                 cisco_transport_t *transport,
                                 virp_trust_tier_t *tier,
                                 const char **restconf_path,
                                 const char **yang_module);

extern const size_t CISCO_ROUTE_TABLE_SIZE;
extern const cisco_command_route_t CISCO_ROUTE_TABLE[];

#ifdef __cplusplus
}
#endif
#endif /* VIRP_DRIVER_CISCO_H */
