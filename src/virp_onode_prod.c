/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
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
#include "virp_crypto.h"   /* virp_crypto_harden_process */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <json-c/json.h>

/*
 * Everything between here and the end of main() is the daemon's process
 * entry point. The issue-#7 regression test links the parser (above) into
 * the test binary by compiling this same source with
 * -DVIRP_ONODE_PROD_NO_MAIN, which excludes the daemon scaffolding so
 * there's no duplicate main()/g_state and no unused-static warnings.
 */
#ifndef VIRP_ONODE_PROD_NO_MAIN

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
#ifdef VIRP_DRIVER_CISCO_ASA
extern void virp_driver_asa_init(void);
#endif
#ifdef VIRP_DRIVER_WAZUH
extern void virp_driver_wazuh_init(void);
#include <curl/curl.h>
#endif
#ifdef VIRP_DRIVER_JUNIPER
extern void virp_driver_juniper_init(void);
#endif

static void signal_handler(int sig)
{
    (void)sig;
    fprintf(stderr, "\n[O-Node] Signal received, shutting down...\n");
    onode_shutdown(&g_state);
}

#endif  /* !VIRP_ONODE_PROD_NO_MAIN — end of daemon scaffolding */

/* =========================================================================
 * Load devices from JSON config file
 *
 * Format:
 * {
 *   "devices": [
 *     {
 *       "hostname": "R1",
 *       "host": "198.51.100.1",
 *       "port": 22,
 *       "vendor": "cisco_ios",
 *       "username": "virp-agent",
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
    if (strcmp(s, "cisco") == 0)     return VIRP_VENDOR_CISCO_IOS;
    if (strcmp(s, "fortinet") == 0)  return VIRP_VENDOR_FORTINET;
    if (strcmp(s, "linux") == 0)     return VIRP_VENDOR_LINUX;
    if (strcmp(s, "juniper") == 0)   return VIRP_VENDOR_JUNIPER;
    if (strcmp(s, "paloalto") == 0)  return VIRP_VENDOR_PALOALTO;
    if (strcmp(s, "panos") == 0)     return VIRP_VENDOR_PALOALTO;
    if (strcmp(s, "windows") == 0)   return VIRP_VENDOR_WINDOWS;
    if (strcmp(s, "proxmox") == 0)   return VIRP_VENDOR_PROXMOX;
    if (strcmp(s, "cisco_asa") == 0) return VIRP_VENDOR_CISCO_ASA;
    if (strcmp(s, "wazuh") == 0)     return VIRP_VENDOR_WAZUH;
    if (strcmp(s, "mock") == 0)      return VIRP_VENDOR_MOCK;
    return VIRP_VENDOR_UNKNOWN;
}

/*
 * Type-checked JSON accessors. Each returns true only when the key is
 * present AND the value has the expected type. Wrong-type values are
 * reported as absent so the caller's destination is left untouched.
 *
 * Why: bare json_object_get_string(val) returns NULL when val is not a
 * JSON string, and snprintf("%s", NULL) is undefined behaviour — on glibc
 * it segfaults. A config with e.g. "enable": 0 took the daemon down at
 * startup before this guard existed (issue #7).
 *
 * Mirrors json_get_string() in virp_onode_main.c and the safe pattern
 * already used by load_socket_path_override() above.
 */
static bool json_get_string(struct json_object *obj, const char *key,
                            char *out, size_t out_sz)
{
    struct json_object *val;
    if (!json_object_object_get_ex(obj, key, &val)) return false;
    if (!json_object_is_type(val, json_type_string)) return false;
    const char *s = json_object_get_string(val);
    if (!s) return false;
    snprintf(out, out_sz, "%s", s);
    return true;
}

static bool json_get_int(struct json_object *obj, const char *key, int *out)
{
    struct json_object *val;
    if (!json_object_object_get_ex(obj, key, &val)) return false;
    if (!json_object_is_type(val, json_type_int)) return false;
    *out = json_object_get_int(val);
    return true;
}

static bool json_get_bool(struct json_object *obj, const char *key, bool *out)
{
    struct json_object *val;
    if (!json_object_object_get_ex(obj, key, &val)) return false;
    if (!json_object_is_type(val, json_type_boolean)) return false;
    *out = json_object_get_boolean(val);
    return true;
}

/*
 * Parse the top-level `socket_allowed_uids` array from the config and
 * install it on the O-Node state. Absent array → state is left untouched
 * and onode_start() will self-seed with geteuid().
 */
static void load_socket_allowed_uids(onode_state_t *state,
                                     struct json_object *root)
{
    struct json_object *arr;
    if (!json_object_object_get_ex(root, "socket_allowed_uids", &arr) ||
        !json_object_is_type(arr, json_type_array)) {
        return;  /* optional */
    }

    int n = (int)json_object_array_length(arr);
    if (n <= 0) return;
    if (n > ONODE_MAX_ALLOWED_UIDS) {
        fprintf(stderr, "[O-Node] socket_allowed_uids has %d entries, "
                        "truncating to %d\n", n, ONODE_MAX_ALLOWED_UIDS);
        n = ONODE_MAX_ALLOWED_UIDS;
    }

    uid_t uids[ONODE_MAX_ALLOWED_UIDS];
    int parsed = 0;
    for (int i = 0; i < n; i++) {
        struct json_object *el = json_object_array_get_idx(arr, i);
        if (!el) continue;
        if (json_object_is_type(el, json_type_int)) {
            uids[parsed++] = (uid_t)json_object_get_int(el);
        } else if (json_object_is_type(el, json_type_string)) {
            uids[parsed++] = (uid_t)strtoul(json_object_get_string(el),
                                            NULL, 10);
        }
    }
    if (parsed > 0)
        onode_set_allowed_uids(state, uids, (size_t)parsed);
}

/*
 * Parse the optional top-level `socket_path` override. If present, it
 * takes precedence over the -s CLI argument. This lets operators move
 * the socket (e.g. when redirecting the socat bridge) by editing the
 * config file only.
 *
 * Returns a malloc'd copy the caller must free, or NULL.
 */
static char *load_socket_path_override(struct json_object *root)
{
    struct json_object *val;
    if (!json_object_object_get_ex(root, "socket_path", &val) ||
        !json_object_is_type(val, json_type_string))
        return NULL;
    const char *s = json_object_get_string(val);
    return (s && *s) ? strdup(s) : NULL;
}

/*
 * Not static: the issue #7 regression test in tests/test_onode.c links
 * against the prod parser (via the *_lib.o object compiled with
 * VIRP_ONODE_PROD_NO_MAIN) and calls this directly.
 */
int load_devices(onode_state_t *state, const char *path)
{
    struct json_object *root = json_object_from_file(path);
    if (!root) {
        fprintf(stderr, "[O-Node] Failed to parse device config: %s\n", path);
        return -1;
    }

    /* Socket access gate: install allowlist before onode_start(). */
    load_socket_allowed_uids(state, root);

    /*
     * Optional socket_path override from config. Takes precedence over
     * the -s CLI flag so operators can move the socket (for the socat
     * bridge in particular) by editing the JSON alone.
     */
    char *sock_override = load_socket_path_override(root);
    if (sock_override) {
        snprintf(state->socket_path, sizeof(state->socket_path), "%s",
                 sock_override);
        fprintf(stderr, "[O-Node] socket_path from config: %s\n",
                state->socket_path);
        free(sock_override);
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
        if (!dev_obj || !json_object_is_type(dev_obj, json_type_object))
            continue;

        virp_device_t device;
        memset(&device, 0, sizeof(device));
        device.enabled = true;
        device.port = 22;

        json_get_string(dev_obj, "hostname", device.hostname,
                        sizeof(device.hostname));
        json_get_string(dev_obj, "host",     device.host,
                        sizeof(device.host));
        json_get_string(dev_obj, "username", device.username,
                        sizeof(device.username));
        json_get_string(dev_obj, "password", device.password,
                        sizeof(device.password));
        json_get_string(dev_obj, "enable",   device.enable_password,
                        sizeof(device.enable_password));

        int port_val;
        if (json_get_int(dev_obj, "port", &port_val))
            device.port = (uint16_t)port_val;

        char vendor_str[32] = {0};
        if (json_get_string(dev_obj, "vendor", vendor_str, sizeof(vendor_str)))
            device.vendor = vendor_from_string(vendor_str);

        /*
         * node_id accepts either a hex string ("0A0000FD") or a JSON int,
         * matching virp_onode_main.c's dev parser. Other JSON types are
         * silently ignored (treated as absent) — pre-fix code dereferenced
         * a NULL string here when the value was an int/bool/null.
         */
        struct json_object *nid_val;
        if (json_object_object_get_ex(dev_obj, "node_id", &nid_val)) {
            if (json_object_is_type(nid_val, json_type_string)) {
                const char *s = json_object_get_string(nid_val);
                if (s) device.node_id = (uint32_t)strtoul(s, NULL, 16);
            } else if (json_object_is_type(nid_val, json_type_int)) {
                device.node_id = (uint32_t)json_object_get_int64(nid_val);
            }
        }

        /* FortiGate-specific fields (ignored for other vendors) */
        json_get_string(dev_obj, "api_token", device.api_token,
                        sizeof(device.api_token));

        int api_port_val;
        if (json_get_int(dev_obj, "api_port", &api_port_val))
            device.api_port = (uint16_t)api_port_val;

        json_get_string(dev_obj, "vdom", device.vdom, sizeof(device.vdom));

        bool bool_val;
        if (json_get_bool(dev_obj, "verify_tls", &bool_val))
            device.verify_tls = bool_val;

        if (json_get_bool(dev_obj, "ssh_legacy", &bool_val))
            device.ssh_legacy = bool_val;

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

#ifndef VIRP_ONODE_PROD_NO_MAIN

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

#ifdef VIRP_DRIVER_WAZUH
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

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
#ifdef VIRP_DRIVER_CISCO_ASA
    virp_driver_asa_init();
#endif
#ifdef VIRP_DRIVER_WAZUH
    virp_driver_wazuh_init();
#endif
#ifdef VIRP_DRIVER_JUNIPER
    virp_driver_juniper_init();
#endif
    fprintf(stderr, "[O-Node] Registered %d driver(s)\n", virp_driver_count());

    /*
     * Harden the process before loading the key (see virp_onode_main.c
     * for rationale).
     */
    virp_crypto_harden_process();

    /* Initialize O-Node */
    virp_error_t err = onode_init(&g_state, node_id, okey_path, socket_path);
    if (err != VIRP_OK) {
        fprintf(stderr, "[O-Node] Initialization failed: %s\n",
                virp_error_str(err));
        return 1;
    }

    /*
     * Allocate the protocol context. main() owns it for the lifetime
     * of the process. virp_context_destroy() below will OPENSSL_cleanse
     * session_key / transcript state before freeing.
     */
    virp_context_t *ctx = virp_context_new();
    if (!ctx) {
        fprintf(stderr, "[O-Node] Failed to allocate protocol context\n");
        onode_destroy(&g_state);
        return 1;
    }
    g_state.ctx = ctx;

    /* Load devices from JSON config */
    int loaded = load_devices(&g_state, devices_path);
    if (loaded <= 0) {
        fprintf(stderr, "[O-Node] No devices loaded. Exiting.\n");
        onode_destroy(&g_state);
        virp_context_destroy(ctx);
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
    virp_context_destroy(ctx);
    g_state.ctx = NULL;

    return (err == VIRP_OK) ? 0 : 1;
}

#endif  /* !VIRP_ONODE_PROD_NO_MAIN */
