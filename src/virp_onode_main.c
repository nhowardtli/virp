/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * O-Node Main — daemon entry point
 *
 * Usage:
 *   virp-onode [options]
 *     -k <okey_path>    Path to O-Key file (generates if absent)
 *     -s <socket_path>  Unix socket path (default: /tmp/virp-onode.sock)
 *     -n <node_id_hex>  Node ID in hex (default: 0x00000001)
 *     -m                Use mock driver with test devices
 *     -h                Show help
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_onode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>

static onode_state_t g_state;

/* Forward declare drivers */
extern void virp_driver_mock_init(void);
#ifdef VIRP_DRIVER_CISCO
extern void virp_driver_cisco_init(void);
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

/* JSON device loader (virp_onode_json.c) */
extern int onode_load_devices_json(onode_state_t *state, const char *path);

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

    /* Register drivers */
    virp_driver_mock_init();
#ifdef VIRP_DRIVER_CISCO
    virp_driver_cisco_init();
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

    /* Load devices */
    if (devices_path) {
        onode_load_devices_json(&g_state, devices_path);
    } else if (use_mock) {
        add_mock_devices(&g_state);
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
