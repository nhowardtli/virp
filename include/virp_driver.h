/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Device Driver Interface
 *
 * This is the abstraction boundary between VIRP and vendor hardware.
 * The O-Node doesn't know what a FortiGate is. It doesn't know what
 * IOS is. It calls driver functions. Adding Juniper means writing a
 * JunOS driver. The protocol never changes.
 *
 * Every driver implements this interface. Nothing else.
 */

#ifndef VIRP_DRIVER_H
#define VIRP_DRIVER_H

#include "virp.h"
#include <stddef.h>
#include <stdbool.h>

/* =========================================================================
 * Driver Identification
 * ========================================================================= */

#define VIRP_DRIVER_NAME_MAX    32
#define VIRP_DRIVER_MAX         16      /* Max registered drivers */

typedef enum {
    VIRP_VENDOR_UNKNOWN     = 0,
    VIRP_VENDOR_CISCO_IOS   = 1,
    VIRP_VENDOR_FORTINET    = 2,
    VIRP_VENDOR_LINUX       = 3,
    VIRP_VENDOR_JUNIPER     = 4,
    VIRP_VENDOR_PALOALTO    = 5,
    VIRP_VENDOR_WINDOWS     = 6,
    VIRP_VENDOR_PROXMOX     = 7,
    VIRP_VENDOR_CISCO_ASA   = 8,
    VIRP_VENDOR_WAZUH       = 9,
    VIRP_VENDOR_MOCK        = 99,   /* Testing only */
} virp_vendor_t;

/*
 * Trust tier type — used by vendor-specific drivers (FortiGate, Cisco)
 * for command routing tables. Maps to VIRP_TIER_* constants in virp.h.
 */
typedef uint8_t virp_trust_tier_t;

/* =========================================================================
 * Connection Handle
 *
 * Opaque per-connection state. Each driver defines its own internal
 * structure (SSH session, API token, etc). The O-Node only sees this
 * opaque pointer.
 * ========================================================================= */

typedef struct virp_conn virp_conn_t;

/* =========================================================================
 * Device Descriptor
 *
 * Everything the O-Node needs to know about a device to connect to it.
 * Loaded from configuration (customer.yaml equivalent).
 * ========================================================================= */

typedef struct {
    char            hostname[64];
    char            host[256];          /* IP or FQDN */
    uint16_t        port;               /* SSH port, API port, etc */
    char            username[64];
    char            password[128];      /* TODO: move to vault/keyring */
    char            enable_password[128];
    virp_vendor_t   vendor;
    uint32_t        node_id;            /* VIRP node ID for this device */
    bool            enabled;
    /* Vendor-optional (FortiGate) — zero-initialized for other vendors */
    char            api_token[256];     /* REST API Bearer token */
    uint16_t        api_port;           /* REST API port (default 443) */
    char            vdom[64];           /* VDOM name (default "root") */
    bool            verify_tls;         /* Verify TLS cert on REST calls */
    bool            ssh_legacy;         /* Force legacy SSH ciphers (group14-sha1, ssh-rsa, aes256-cbc) */
} virp_device_t;

/* =========================================================================
 * Execution Result
 *
 * What comes back from running a command on a device.
 * The driver fills this in. The O-Node wraps it in a VIRP OBSERVATION.
 * ========================================================================= */

#define VIRP_OUTPUT_MAX     65536   /* 64KB max output per command */

typedef struct {
    char        output[VIRP_OUTPUT_MAX];
    size_t      output_len;
    bool        success;
    int         exit_code;              /* Meaningful for Linux, 0/1 for network */
    char        error_msg[256];         /* Human-readable error if !success */
    uint64_t    exec_time_ms;           /* Execution time in milliseconds */
} virp_exec_result_t;

/* =========================================================================
 * Driver Operations
 *
 * Every driver implements these five functions. That's it.
 * No optional methods. No inheritance. Five function pointers.
 * ========================================================================= */

typedef struct virp_driver {
    /* Identity */
    char            name[VIRP_DRIVER_NAME_MAX];
    virp_vendor_t   vendor;

    /*
     * connect — establish a session to the device.
     * Returns an opaque connection handle, or NULL on failure.
     * The driver owns the connection memory.
     */
    virp_conn_t *(*connect)(const virp_device_t *device);

    /*
     * execute — run a command and return the output.
     * The command is a single string (e.g., "show ip route").
     * Result is written into the caller-provided result struct.
     * Returns VIRP_OK on success (even if the command itself failed —
     * check result->success for command-level success).
     */
    virp_error_t (*execute)(virp_conn_t *conn,
                            const char *command,
                            virp_exec_result_t *result);

    /*
     * disconnect — close the session and free all resources.
     * Must be safe to call on a NULL conn (no-op).
     */
    void (*disconnect)(virp_conn_t *conn);

    /*
     * detect — given a connection, determine if this driver can
     * handle the device. Used for auto-detection.
     * Returns true if this driver matches the device.
     */
    bool (*detect)(virp_conn_t *conn);

    /*
     * health_check — verify the device is responsive.
     * Returns VIRP_OK if healthy.
     */
    virp_error_t (*health_check)(virp_conn_t *conn);

} virp_driver_t;

/* =========================================================================
 * Driver Registry
 *
 * Drivers register themselves at startup. The O-Node looks up drivers
 * by vendor type. Simple array, no dynamic allocation.
 * ========================================================================= */

/*
 * Register a driver. Call during initialization.
 */
virp_error_t virp_driver_register(const virp_driver_t *driver);

/*
 * Look up a driver by vendor type.
 * Returns NULL if no driver registered for that vendor.
 */
const virp_driver_t *virp_driver_lookup(virp_vendor_t vendor);

/*
 * Get count of registered drivers.
 */
int virp_driver_count(void);

/* =========================================================================
 * Built-in Drivers (linked at compile time)
 *
 * Each driver provides an init function that registers itself.
 * The O-Node calls these during startup.
 * ========================================================================= */

/* Mock driver for testing — always available */
void virp_driver_mock_init(void);

/* Real drivers — conditionally compiled */
#ifdef VIRP_DRIVER_CISCO
void virp_driver_cisco_init(void);
#endif

#ifdef VIRP_DRIVER_FORTINET
void virp_driver_fortinet_init(void);
#endif

#ifdef VIRP_DRIVER_LINUX
void virp_driver_linux_init(void);
#endif

#ifdef VIRP_DRIVER_PALOALTO
void virp_driver_paloalto_init(void);
#endif

#ifdef VIRP_DRIVER_CISCO_ASA
void virp_driver_asa_init(void);
#endif

#ifdef VIRP_DRIVER_WAZUH
void virp_driver_wazuh_init(void);
#endif

#endif /* VIRP_DRIVER_H */
