/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * O-Node Main — daemon entry point
 *
 * Usage:
 *   virp-onode [options]
 *     -k <okey_path>    Path to O-Key file (generates if absent)
 *     -s <socket_path>  Unix socket path (default: /run/virp/onode.sock)
 *     -n <node_id_hex>  Node ID in hex (default: 0x00000001)
 *     -m                Use mock driver with test devices
 *     -h                Show help
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_onode.h"
#include "virp_driver.h"
#include "virp_session.h"
#include "virp_context.h"
#include "virp_crypto.h"   /* virp_crypto_harden_process */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <json-c/json.h>

/*
 * Parse VIRP_ALLOWED_UIDS ("uid1,uid2,...") into the daemon's socket
 * allowlist. Invalid entries are logged and skipped; an empty or unset
 * variable leaves the allowlist at count=0 so onode_start() can fall
 * back to the daemon's own effective UID.
 */
static void load_allowed_uids_from_env(onode_state_t *state)
{
    const char *env = getenv("VIRP_ALLOWED_UIDS");
    if (!env || env[0] == '\0')
        return;

    uid_t uids[ONODE_MAX_ALLOWED_UIDS];
    size_t count = 0;

    char buf[256];
    snprintf(buf, sizeof(buf), "%s", env);

    char *save = NULL;
    for (char *tok = strtok_r(buf, ",", &save);
         tok != NULL;
         tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t') tok++;
        if (*tok == '\0') continue;

        if (count >= ONODE_MAX_ALLOWED_UIDS) {
            fprintf(stderr,
                    "[O-Node] VIRP_ALLOWED_UIDS: too many entries "
                    "(max %d) — extras ignored\n",
                    ONODE_MAX_ALLOWED_UIDS);
            break;
        }

        errno = 0;
        char *end = NULL;
        unsigned long v = strtoul(tok, &end, 10);
        if (errno != 0 || end == tok || (*end != '\0' && *end != ' ' && *end != '\t')) {
            fprintf(stderr,
                    "[O-Node] VIRP_ALLOWED_UIDS: skipping invalid entry '%s'\n",
                    tok);
            continue;
        }
        uids[count++] = (uid_t)v;
    }

    if (count > 0)
        onode_set_allowed_uids(state, uids, count);
}

static onode_state_t g_state;

/* Forward declare drivers */
extern void virp_driver_mock_init(void);
#ifdef VIRP_DRIVER_CISCO
extern void virp_driver_cisco_init(void);
#endif
#ifdef VIRP_DRIVER_LINUX
extern void virp_driver_linux_init(void);
#endif
#ifdef VIRP_DRIVER_FORTINET
extern void virp_driver_fortinet_init(void);
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
#ifdef VIRP_DRIVER_LIBRENMS
extern void virp_driver_librenms_init(void);
#ifndef VIRP_DRIVER_WAZUH
#include <curl/curl.h>
#endif
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

/* =========================================================================
 * Dev/mock device loader
 *
 * Parses a devices.json file via json-c and adds each entry to the O-Node
 * state. Shares vendor-string semantics with src/virp_onode_prod.c's
 * load_devices; the dev binary supports only the SSH device fields (no
 * socket_allowed_uids / socket_path override / FortiGate REST fields),
 * since those are prod-deployment concerns. Returns the number of
 * successfully-loaded devices, or -1 on parse failure.
 * ========================================================================= */

static virp_vendor_t vendor_from_string(const char *s)
{
    if (!s) return VIRP_VENDOR_UNKNOWN;
    if (strcmp(s, "cisco_ios") == 0) return VIRP_VENDOR_CISCO_IOS;
    if (strcmp(s, "cisco") == 0)     return VIRP_VENDOR_CISCO_IOS;
    if (strcmp(s, "cisco_iosxe") == 0) return VIRP_VENDOR_CISCO_IOSXE;
    if (strcmp(s, "fortinet") == 0)  return VIRP_VENDOR_FORTINET;
    if (strcmp(s, "linux") == 0)     return VIRP_VENDOR_LINUX;
    if (strcmp(s, "juniper") == 0)   return VIRP_VENDOR_JUNIPER;
    if (strcmp(s, "paloalto") == 0)  return VIRP_VENDOR_PALOALTO;
    if (strcmp(s, "panos") == 0)     return VIRP_VENDOR_PALOALTO;
    if (strcmp(s, "windows") == 0)   return VIRP_VENDOR_WINDOWS;
    if (strcmp(s, "proxmox") == 0)   return VIRP_VENDOR_PROXMOX;
    if (strcmp(s, "cisco_asa") == 0) return VIRP_VENDOR_CISCO_ASA;
    if (strcmp(s, "wazuh") == 0)     return VIRP_VENDOR_WAZUH;
    if (strcmp(s, "librenms") == 0)  return VIRP_VENDOR_LIBRENMS;
    if (strcmp(s, "mock") == 0)      return VIRP_VENDOR_MOCK;
    return VIRP_VENDOR_UNKNOWN;
}

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

static int load_devices_json(onode_state_t *state, const char *path)
{
    /* Autopilot hard exclusion — non-negotiable: refuse the entire
     * config if it mentions a blocked address anywhere. */
    const char *blocked = virp_config_file_blocked(path);
    if (blocked) {
        fprintf(stderr, "[O-Node] FATAL: device config %s contains "
                "hard-excluded address %s — refusing to load\n",
                path, blocked);
        return -1;
    }

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
        if (!dev_obj || !json_object_is_type(dev_obj, json_type_object))
            continue;

        virp_device_t device;
        memset(&device, 0, sizeof(device));
        device.enabled = true;
        device.port = 22;

        json_get_string(dev_obj, "hostname", device.hostname, sizeof(device.hostname));
        json_get_string(dev_obj, "host",     device.host,     sizeof(device.host));
        json_get_string(dev_obj, "username", device.username, sizeof(device.username));
        json_get_string(dev_obj, "password", device.password, sizeof(device.password));
        json_get_string(dev_obj, "enable",   device.enable_password,
                        sizeof(device.enable_password));

        struct json_object *val;
        if (json_object_object_get_ex(dev_obj, "port", &val) &&
            json_object_is_type(val, json_type_int))
            device.port = (uint16_t)json_object_get_int(val);

        char vendor_str[32] = {0};
        if (json_get_string(dev_obj, "vendor", vendor_str, sizeof(vendor_str)))
            device.vendor = vendor_from_string(vendor_str);
        else
            device.vendor = VIRP_VENDOR_UNKNOWN;

        /*
         * node_id accepts either a quoted hex string ("0A0000FD") or an
         * unquoted JSON number. Legacy dev configs used hex strings; newer
         * configs may use plain integers.
         */
        if (json_object_object_get_ex(dev_obj, "node_id", &val)) {
            if (json_object_is_type(val, json_type_string)) {
                const char *s = json_object_get_string(val);
                if (s) device.node_id = (uint32_t)strtoul(s, NULL, 16);
            } else if (json_object_is_type(val, json_type_int)) {
                device.node_id = (uint32_t)json_object_get_int64(val);
            }
        }

        if (device.hostname[0] == '\0' || device.host[0] == '\0') {
            fprintf(stderr, "[O-Node] Skipping device %d: missing hostname/host\n", i);
            continue;
        }

        if (device.vendor == VIRP_VENDOR_UNKNOWN) {
            fprintf(stderr, "[O-Node] Skipping %s: unknown vendor '%s'\n",
                    device.hostname, vendor_str);
            continue;
        }

        /* device_id — hex string or int, like node_id; derived from the
         * hostname when the config omits it (see virp_driver.h). */
        if (json_object_object_get_ex(dev_obj, "device_id", &val)) {
            if (json_object_is_type(val, json_type_string)) {
                const char *s = json_object_get_string(val);
                if (s) device.device_id = (uint64_t)strtoull(s, NULL, 16);
            } else if (json_object_is_type(val, json_type_int)) {
                device.device_id = (uint64_t)json_object_get_int64(val);
            }
        }
        /* device_id == 0 (absent/unparseable) is derived from the
         * hostname inside onode_add_device — the single choke point. */
        virp_error_t err = onode_add_device(state, &device);
        if (err == VIRP_ERR_DUPLICATE_DEVICE) {
            /* Config error, not a device to skip — refuse the whole
             * config (add_device already named both devices). */
            fprintf(stderr, "[O-Node] FATAL: refusing device config %s "
                    "with duplicate identities\n", path);
            json_object_put(root);
            return -1;
        }
        if (err != VIRP_OK) {
            fprintf(stderr, "[O-Node] Failed to add %s: %s\n",
                    device.hostname, virp_error_str(err));
            continue;
        }
        loaded++;
    }

    json_object_put(root);
    fprintf(stderr, "[O-Node] Loaded %d/%d devices from %s\n", loaded, count, path);
    return loaded;
}

static void add_mock_devices(onode_state_t *state)
{
    virp_device_t devices[] = {
        {
            .hostname = "R5", .host = "10.0.0.5", .port = 22,
            .username = "admin", .password = "admin",
            .vendor = VIRP_VENDOR_MOCK, .node_id = 0x05050505,
            .enabled = true,
        },
        {
            .hostname = "R6", .host = "10.0.0.6", .port = 22,
            .username = "admin", .password = "admin",
            .vendor = VIRP_VENDOR_MOCK, .node_id = 0x06060606,
            .enabled = true,
        },
        {
            .hostname = "R7", .host = "10.0.0.7", .port = 22,
            .username = "admin", .password = "admin",
            .vendor = VIRP_VENDOR_MOCK, .node_id = 0x07070707,
            .enabled = true,
        },
        {
            .hostname = "R8", .host = "10.0.0.8", .port = 22,
            .username = "admin", .password = "admin",
            .vendor = VIRP_VENDOR_MOCK, .node_id = 0x08080808,
            .enabled = true,
        },
    };

    for (size_t i = 0; i < sizeof(devices) / sizeof(devices[0]); i++)
        onode_add_device(state, &devices[i]);
}

static void usage(const char *prog)
{
    printf("\nVIRP O-Node Daemon\n");
    printf("Copyright (c) 2026 Third Level IT LLC\n\n");
    printf("Usage: %s [options]\n\n", prog);
    printf("Options:\n");
    printf("  -d <path>   Device JSON file path\n");
    printf("  -k <path>   O-Key file path (generates new key if file doesn't exist)\n");
    printf("  -s <path>   Unix socket path (default: %s)\n", ONODE_SOCKET_PATH);
    printf("  -n <hex>    Node ID in hex (default: 0x00000001)\n");
    printf("  -m          Load mock devices for testing\n");
    printf("  -h          Show this help\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *okey_path = NULL;
    const char *devices_path = NULL;
    const char *socket_path = NULL;
    uint32_t node_id = 0x00000001;
    bool use_mock = false;

    int opt;
    while ((opt = getopt(argc, argv, "d:k:s:n:mh")) != -1) {
        switch (opt) {
        case 'd':
            devices_path = optarg;
            break;
        case 'k':
            okey_path = optarg;
            break;
        case 's':
            socket_path = optarg;
            break;
        case 'n':
            node_id = (uint32_t)strtoul(optarg, NULL, 16);
            break;
        case 'm':
            use_mock = true;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return (opt == 'h') ? 0 : 1;
        }
    }

    printf("\n");
    printf("================================================================\n");
    printf("  VIRP O-Node Daemon v0.2\n");
    printf("  Copyright (c) 2026 Third Level IT LLC\n");
    printf("================================================================\n\n");

#ifdef VIRP_DRIVER_WAZUH
    /* curl_global_init must be called before any CURL easy handles.
     * Must happen before driver init since connect() creates handles. */
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

    /* Register drivers */
    virp_driver_mock_init();
#ifdef VIRP_DRIVER_CISCO
    virp_driver_cisco_init();
#endif
#ifdef VIRP_DRIVER_LINUX
    virp_driver_linux_init();
#endif
#ifdef VIRP_DRIVER_FORTINET
    virp_driver_fortinet_init();
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
#ifdef VIRP_DRIVER_LIBRENMS
    virp_driver_librenms_init();
#endif
    fprintf(stderr, "[O-Node] Registered %d driver(s)\n", virp_driver_count());

    /*
     * Harden the process BEFORE the key is loaded:
     *  - PR_SET_DUMPABLE=0 → no core dumps, no ptrace from the same UID.
     *  - Warn if /proc/self/coredump_filter would include anon pages.
     * Doing this pre-load means there is no window in which the key
     * sits in RAM of a dumpable process.
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
     * Allocate the protocol context. main owns the lifetime: it is
     * destroyed after onode_destroy() below, and the OPENSSL_cleanse
     * inside virp_context_destroy() wipes session_key, transcript
     * state, and nonces before the allocation is released.
     */
    virp_context_t *ctx = virp_context_new();
    if (!ctx) {
        fprintf(stderr, "[O-Node] Failed to allocate protocol context\n");
        onode_destroy(&g_state);
        return 1;
    }
    g_state.ctx = ctx;

    /* Load devices. A negative return is a refused config (duplicate
     * identities) — startup must fail closed, not run with a partial
     * device list. */
    if (devices_path) {
        if (load_devices_json(&g_state, devices_path) < 0) {
            fprintf(stderr, "[O-Node] Startup aborted: device config "
                    "refused. Exiting.\n");
            onode_destroy(&g_state);
            virp_context_destroy(ctx);
            return 1;
        }
    } else if (use_mock) {
        add_mock_devices(&g_state);
    }

    /*
     * Populate the socket peer-credential allowlist from the environment.
     * If VIRP_ALLOWED_UIDS is unset, onode_start() defaults the list to
     * the daemon's own effective UID. JSON-config prod builds set the
     * list earlier via load_socket_allowed_uids(); the env var is a
     * lightweight escape hatch for mock/dev and container overrides.
     */
    load_allowed_uids_from_env(&g_state);

    /* Install signal handlers */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    /* A client closing before reading its response must not kill the
     * daemon: default SIGPIPE terminates the process. Sends also pass
     * MSG_NOSIGNAL (belt and suspenders). */
    signal(SIGPIPE, SIG_IGN);

    /* Start event loop (blocks) */
    err = onode_start(&g_state);

    /* Cleanup — destroy onode state, then wipe+free the context */
    onode_destroy(&g_state);
    virp_context_destroy(ctx);
    g_state.ctx = NULL;

    return (err == VIRP_OK) ? 0 : 1;
}
