/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * O-Node Main — daemon entry point
 *
 * Usage:
 *   virp-onode -m [options]
 *     -m                Required: serve the built-in mock devices. This
 *                       binary has no other mode.
 *     -k <okey_path>    Path to an existing O-Key file. Omitted: a key is
 *                       generated in memory for this run only.
 *     -s <socket_path>  Unix socket path (default: /run/virp/onode.sock)
 *     -n <node_id_hex>  Node ID, 1..8 hex digits (default: 00000001)
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
#ifdef VIRP_DRIVER_ZAMMAD
extern void virp_driver_zammad_init(void);
#if !defined(VIRP_DRIVER_WAZUH) && !defined(VIRP_DRIVER_LIBRENMS)
#include <curl/curl.h>
#endif
#endif
#ifdef VIRP_DRIVER_JUNIPER
extern void virp_driver_juniper_init(void);
#endif

/*
 * SIGINT / SIGTERM. Nothing but onode_shutdown(), which is
 * async-signal-safe by contract (two atomic stores and an eventfd
 * write). This used to fprintf() first — stdio is not async-signal-safe,
 * and a signal landing while another thread held the stderr lock could
 * deadlock the handler inside the very path meant to stop the daemon
 * (security review M18). The "shutting down" line is printed by
 * onode_start() once its loop has actually exited.
 */
static void signal_handler(int sig)
{
    (void)sig;
    onode_shutdown(&g_state);
}

/*
 * This binary is MOCK-ONLY. It used to carry a devices.json loader
 * (load_devices_json) and a VIRP_ALLOWED_UIDS environment override.
 * Neither could do anything:
 *
 *  - main() refuses to run unless -m is given and -d is not, so the
 *    loader was unreachable — a second, laxer copy of the production
 *    parser that no test exercised and no run could reach.
 *  - VIRP_ALLOWED_UIDS installed an explicit socket allowlist, and
 *    onode_start() refuses an explicit allowlist with no per-uid action
 *    map, which this binary has no way to supply. Setting the variable
 *    therefore made the daemon fail to start. It was also parsed with a
 *    bare strtoul() cast to uid_t (see M24 for what that lets through).
 *
 * Both are removed rather than repaired: real devices and real
 * allowlists are virp-onode-prod's job. The mock daemon serves the four
 * built-in mock devices to its own uid, which is what onode_start()
 * seeds when no allowlist is configured.
 */

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
    printf("  -m          REQUIRED: serve the built-in mock devices. This is\n");
    printf("              the mock-only demonstration daemon; real devices\n");
    printf("              are virp-onode-prod's job.\n");
    printf("  -k <path>   Existing O-Key file. Without it a key is generated\n");
    printf("              in memory for this run only.\n");
    printf("  -s <path>   Unix socket path (default: %s)\n", ONODE_SOCKET_PATH);
    printf("  -n <hex>    Node ID, 1..8 hex digits, non-zero (default: 00000001)\n");
    printf("  -h          Show this help\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    const char *okey_path = NULL;
    const char *socket_path = NULL;
    uint32_t node_id = 0x00000001;
    bool use_mock = false;

    int opt;
    while ((opt = getopt(argc, argv, "k:s:n:mh")) != -1) {
        switch (opt) {
        case 'k':
            okey_path = optarg;
            break;
        case 's':
            socket_path = optarg;
            break;
        case 'n': {
            /* 1..8 hex digits, non-zero — unparseable input used to
             * become node id 0. */
            size_t len = strlen(optarg);
            char *end = NULL;
            errno = 0;
            unsigned long v = strtoul(optarg, &end, 16);
            if (len == 0 || len > 8 ||
                strspn(optarg, "0123456789abcdefABCDEF") != len ||
                errno != 0 || !end || *end != '\0' || v == 0) {
                fprintf(stderr, "-n %s: the node id must be 1..8 hex digits "
                        "(no 0x) and not zero\n", optarg);
                return 1;
            }
            node_id = (uint32_t)v;
            break;
        }
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

#if defined(VIRP_DRIVER_WAZUH) || defined(VIRP_DRIVER_LIBRENMS) || \
    defined(VIRP_DRIVER_ZAMMAD)
    /* curl_global_init must be called before any CURL easy handles.
     * Must happen before driver init since connect() creates handles.
     * Guarded on EVERY libcurl-backed driver, not just Wazuh — a
     * LIBRENMS=1 or ZAMMAD=1 build without WAZUH=1 was leaving libcurl
     * to initialize itself lazily on the first curl_easy_init(). */
    curl_global_init(CURL_GLOBAL_DEFAULT);
#endif

    if (!use_mock) {
        fprintf(stderr, "Demo daemon is mock-only (pass -m); use virp-onode-prod with owner policy for real targets.\n");
        return 1;
    }

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
#ifdef VIRP_DRIVER_ZAMMAD
    virp_driver_zammad_init();
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

    /* The four built-in mock devices. No socket allowlist is configured,
     * so onode_start() seeds it with this process's own uid. */
    add_mock_devices(&g_state);

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
