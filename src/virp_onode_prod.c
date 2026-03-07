/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Intent Routing Protocol
 * O-Node Production Main — loads devices from JSON config
 *
 * Usage:
 *   virp-onode-prod [options]
 *     -k <okey_path>      Path to O-Key file (generates if absent)
 *     -s <socket_path>    Unix socket path (default: /tmp/virp-onode.sock)
 *     -d <devices_json>   Path to devices.json config
 *     -n <node_id_hex>    Node ID in hex (default: 0x00000001)
 *     -h                  Show help
 *
 * Compiled separately against libvirp.a. Does NOT modify existing sources.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_onode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <json-c/json.h>

static onode_state_t g_state;

/* Forward declare drivers */
extern void virp_driver_mock_init(void);
#ifdef VIRP_DRIVER_CISCO
extern void virp_driver_cisco_init(void);
#endif
#ifdef VIRP_DRIVER_FORTINET
extern void virp_driver_fortinet_init(void);
#endif
#ifdef VIRP_DRIVER_LINUX
extern void virp_driver_linux_init(void);
#endif
#ifdef VIRP_DRIVER_PALOALTO
extern void virp_driver_paloalto_init(void);
#endif

static void signal_handler(int sig)
{
    (void)sig;
    fprintf(stderr, "\n[O-Node] Signal received, shutting down...\n");
    onode_shutdown(&g_state);
}

/* =========================================================================
 * Load devices from JSON config file
 *
 * Format:
 * {
 *   "devices": [
 *     {
 *       "hostname": "R1",
 *       "host": "10.0.0.50",
 *       "port": 22,
 *       "vendor": "cisco_ios",
 *       "username": "aiops-svc",
 *       "password": "secret",
 *       "enable": "secret",
 *       "node_id": "01010101"
 *     }
 *   ]
 * }
 * ========================================================================= */

static virp_vendor_t vendor_from_string(const char *s)
{
    if (!s) return VIRP_VENDOR_UNKNOWN;
    if (strcmp(s, "cisco_ios") == 0) return VIRP_VENDOR_CISCO_IOS;
    if (strcmp(s, "fortinet") == 0)  return VIRP_VENDOR_FORTINET;
    if (strcmp(s, "linux") == 0)     return VIRP_VENDOR_LINUX;
    if (strcmp(s, "juniper") == 0)   return VIRP_VENDOR_JUNIPER;
    if (strcmp(s, "paloalto") == 0)  return VIRP_VENDOR_PALOALTO;
    if (strcmp(s, "panos") == 0)     return VIRP_VENDOR_PALOALTO;
    if (strcmp(s, "windows") == 0)   return VIRP_VENDOR_WINDOWS;
    if (strcmp(s, "proxmox") == 0)   return VIRP_VENDOR_PROXMOX;
    if (strcmp(s, "mock") == 0)      return VIRP_VENDOR_MOCK;
    return VIRP_VENDOR_UNKNOWN;
}

static int load_devices(onode_state_t *state, const char *path)
{
    struct json_object *root = json_object_from_file(path);
    if (!root) {
        fprintf(stderr, "[O-Node] Failed to parse device config: %s\n", path);
        return -1;
    }

    struct json_object *devices_arr;
    if (!json_object_object_get_ex(root, "devices", &devices_arr) ||
        !json_object_is_type(devices_arr, json_type_array)) {
        fprintf(stderr, "[O-Node] Config missing 'devices' array\n");
        json_object_put(root);
        return -1;
    }

    int count = (int)json_object_array_length(devices_arr);
    int loaded = 0;

    for (int i = 0; i < count; i++) {
        struct json_object *dev_obj = json_object_array_get_idx(devices_arr, i);
        if (!dev_obj) continue;

        virp_device_t device;
        memset(&device, 0, sizeof(device));
        device.enabled = true;

        struct json_object *val;

        if (json_object_object_get_ex(dev_obj, "hostname", &val))
            snprintf(device.hostname, sizeof(device.hostname), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(dev_obj, "host", &val))
            snprintf(device.host, sizeof(device.host), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(dev_obj, "port", &val))
            device.port = (uint16_t)json_object_get_int(val);
        else
            device.port = 22;

        if (json_object_object_get_ex(dev_obj, "vendor", &val))
            device.vendor = vendor_from_string(json_object_get_string(val));

        if (json_object_object_get_ex(dev_obj, "username", &val))
            snprintf(device.username, sizeof(device.username), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(dev_obj, "password", &val))
            snprintf(device.password, sizeof(device.password), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(dev_obj, "enable", &val))
            snprintf(device.enable_password, sizeof(device.enable_password),
                     "%s", json_object_get_string(val));

        if (json_object_object_get_ex(dev_obj, "node_id", &val))
            device.node_id = (uint32_t)strtoul(
                json_object_get_string(val), NULL, 16);

        /* FortiGate-specific fields (ignored for other vendors) */
        if (json_object_object_get_ex(dev_obj, "api_token", &val))
            snprintf(device.api_token, sizeof(device.api_token), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(dev_obj, "api_port", &val))
            device.api_port = (uint16_t)json_object_get_int(val);

        if (json_object_object_get_ex(dev_obj, "vdom", &val))
            snprintf(device.vdom, sizeof(device.vdom), "%s",
                     json_object_get_string(val));

        if (json_object_object_get_ex(dev_obj, "verify_tls", &val))
            device.verify_tls = json_object_get_boolean(val);

        if (device.hostname[0] == '\0' || device.host[0] == '\0') {
            fprintf(stderr, "[O-Node] Skipping device %d: missing hostname/host\n", i);
            continue;
        }

        if (device.vendor == VIRP_VENDOR_UNKNOWN) {
            fprintf(stderr, "[O-Node] Skipping %s: unknown vendor\n",
                    device.hostname);
            continue;
        }

        virp_error_t err = onode_add_device(state, &device);
        if (err != VIRP_OK) {
            fprintf(stderr, "[O-Node] Failed to add %s: %s\n",
                    device.hostname, virp_error_str(err));
            continue;
        }

        loaded++;
    }

    json_object_put(root);

    fprintf(stderr, "[O-Node] Loaded %d/%d devices from %s\n",
            loaded, count, path);

    return loaded;
}

static void usage(const char *prog)
{
    printf("\nVIRP O-Node Daemon (Production)\n");
    printf("Copyright (c) 2026 Third Level IT LLC\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -k <path>   O-Key file path (generates new key if file doesn't exist)\n");
    printf("  -s <path>   Unix socket path (default: %s)\n", ONODE_SOCKET_PATH);
    printf("  -d <path>   Device config JSON file (required)\n");
    printf("  -n <hex>    Node ID in hex (default: 0x00000001)\n");
    printf("  -c <path>   Chain database path (enables Primitive 6 trust chain)\n");
    printf("  -C <path>   Chain key path (32-byte key file, required with -c)\n");
    printf("  -h          Show this help\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *okey_path = NULL;
    const char *socket_path = NULL;
    const char *devices_path = NULL;
    const char *chain_db_path = NULL;
    const char *chain_key_path = NULL;
    uint32_t node_id = 0x00000001;

    int opt;
    while ((opt = getopt(argc, argv, "k:s:d:n:c:C:h")) != -1) {
        switch (opt) {
        case 'k':
            okey_path = optarg;
            break;
        case 's':
            socket_path = optarg;
            break;
        case 'd':
            devices_path = optarg;
            break;
        case 'n':
            node_id = (uint32_t)strtoul(optarg, NULL, 16);
            break;
        case 'c':
            chain_db_path = optarg;
            break;
        case 'C':
            chain_key_path = optarg;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    if (!devices_path) {
        fprintf(stderr, "[O-Node] Error: -d <devices.json> is required\n");
        usage(argv[0]);
        return 1;
    }

    printf("\n");
    printf("================================================================\n");
    printf("  VIRP O-Node Daemon (Production) v0.2\n");
    printf("  Copyright (c) 2026 Third Level IT LLC\n");
    printf("================================================================\n\n");

    /* Register drivers */
    virp_driver_mock_init();
#ifdef VIRP_DRIVER_CISCO
    virp_driver_cisco_init();
#endif
#ifdef VIRP_DRIVER_FORTINET
    virp_driver_fortinet_init();
#endif
#ifdef VIRP_DRIVER_LINUX
    virp_driver_linux_init();
#endif
#ifdef VIRP_DRIVER_PALOALTO
    virp_driver_paloalto_init();
#endif
    fprintf(stderr, "[O-Node] Registered %d driver(s)\n", virp_driver_count());

    /* Initialize O-Node */
    virp_error_t err = onode_init(&g_state, node_id, okey_path, socket_path);
    if (err != VIRP_OK) {
        fprintf(stderr, "[O-Node] Initialization failed: %s\n",
                virp_error_str(err));
        return 1;
    }

    /* Load devices from JSON config */
    int loaded = load_devices(&g_state, devices_path);
    if (loaded <= 0) {
        fprintf(stderr, "[O-Node] No devices loaded. Exiting.\n");
        onode_destroy(&g_state);
        return 1;
    }

    /* Initialize trust chain (Primitive 6) if configured */
    if (chain_db_path && chain_key_path) {
        virp_error_t chain_err = virp_chain_init(&g_state.chain,
                                                  chain_db_path,
                                                  chain_key_path,
                                                  node_id, "local");
        if (chain_err == VIRP_OK) {
            g_state.chain_enabled = true;
            fprintf(stderr, "[O-Node] Trust chain enabled: db=%s\n",
                    chain_db_path);
        } else {
            fprintf(stderr, "[O-Node] Trust chain init failed: %s "
                    "(continuing without chain)\n",
                    virp_error_str(chain_err));
        }
    }

    /* Install signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Start event loop (blocks) */
    err = onode_start(&g_state);

    /* Cleanup */
    onode_destroy(&g_state);

    return (err == VIRP_OK) ? 0 : 1;
}
