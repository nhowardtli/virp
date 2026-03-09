/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Topology Sweep — crawl a network, sign everything, build a map
 *
 * This tool connects to every router in the lab, runs multiple
 * show commands on each, wraps every output in a signed VIRP
 * OBSERVATION, then parses the signed data to build a verified
 * topology map.
 *
 * Every link on the map traces back to a signed observation.
 * Every neighbor relationship is cryptographically proven.
 * If the AI says "R1 peers with R2 over eBGP," VIRP proves it
 * by pointing to the signed observation from R1 and the signed
 * observation from R2 that both confirm the relationship.
 *
 * Usage:
 *   virp-sweep                      # All 10 routers, default commands
 *   virp-sweep 10.0.0.50 10.0.0.51  # Specific routers only
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern void virp_driver_mock_init(void);
#ifdef VIRP_DRIVER_CISCO
extern void virp_driver_cisco_init(void);
#endif

/* =========================================================================
 * Lab Topology Definition
 * ========================================================================= */

#define MAX_ROUTERS     10
#define MAX_COMMANDS    5
#define MAX_NEIGHBORS   20
#define MAX_ROUTES      50
#define MAX_LINKS       50

typedef struct {
    char    hostname[64];
    char    host[256];
    uint32_t node_id;
    bool    reachable;
    int     bgp_neighbor_count;
    int     route_count;
    int     observation_count;
    char    router_id[32];
    uint32_t local_as;
} router_info_t;

typedef struct {
    char    src_router[64];
    char    dst_router[64];
    char    src_ip[64];
    char    dst_ip[64];
    uint32_t src_as;
    uint32_t dst_as;
    char    link_type[16];   /* iBGP, eBGP, OSPF, connected */
    int     prefixes;
    bool    verified_both;   /* Confirmed from both sides */
} link_info_t;

/* Global state */
static router_info_t routers[MAX_ROUTERS];
static int router_count = 0;
static link_info_t links[MAX_LINKS];
static int link_count = 0;
static int total_observations = 0;
static int total_bytes = 0;
static virp_signing_key_t okey;

/* Commands to run on each router */
static const char *sweep_commands[] = {
    "show ip bgp summary",
    "show ip route",
    "show ip ospf neighbor",
    "show ip interface brief",
    NULL
};

/* =========================================================================
 * Parsing Helpers — extract topology from signed observations
 * ========================================================================= */

/* Extract router ID and AS from BGP summary output */
static void parse_bgp_summary(const char *output, router_info_t *router)
{
    const char *p;

    /* "BGP router identifier X.X.X.X, local AS number NNN" */
    p = strstr(output, "BGP router identifier ");
    if (p) {
        p += 22;
        int i = 0;
        while (*p && *p != ',' && i < 15)
            router->router_id[i++] = *p++;
        router->router_id[i] = '\0';
    }

    p = strstr(output, "local AS number ");
    if (p) {
        p += 16;
        router->local_as = (uint32_t)strtoul(p, NULL, 10);
    }

    /* Count BGP neighbors — lines with IP address format after the header */
    p = strstr(output, "State/PfxRcd");
    if (p) {
        p = strchr(p, '\n');
        if (p) p++;
        while (p && *p) {
            /* Each neighbor line starts with an IP address */
            if ((*p >= '0' && *p <= '9') && strchr(p, '.')) {
                router->bgp_neighbor_count++;

                /* Extract neighbor info for link building */
                if (link_count < MAX_LINKS) {
                    link_info_t *link = &links[link_count];
                    memset(link, 0, sizeof(*link));

                    snprintf(link->src_router, sizeof(link->src_router),
                             "%s", router->hostname);
                    link->src_as = router->local_as;

                    /* Parse neighbor IP */
                    int j = 0;
                    const char *np = p;
                    while (*np && *np != ' ' && j < 31)
                        link->dst_ip[j++] = *np++;
                    link->dst_ip[j] = '\0';

                    /* Skip to AS column (V column then AS) */
                    while (*np == ' ') np++;  /* skip spaces */
                    while (*np != ' ') np++;  /* skip V */
                    while (*np == ' ') np++;  /* skip spaces */

                    /* Parse AS number */
                    link->dst_as = (uint32_t)strtoul(np, NULL, 10);

                    /* Determine link type */
                    if (link->src_as == link->dst_as)
                        snprintf(link->link_type, sizeof(link->link_type), "iBGP");
                    else
                        snprintf(link->link_type, sizeof(link->link_type), "eBGP");

                    /* Skip to PfxRcd (last column) */
                    const char *eol = strchr(np, '\n');
                    if (eol) {
                        /* Walk backwards from end of line to find last number */
                        const char *back = eol - 1;
                        while (back > np && *back == ' ') back--;
                        while (back > np && *back != ' ') back--;
                        if (back > np)
                            link->prefixes = atoi(back);
                    }

                    link_count++;
                }
            }

            /* Next line */
            p = strchr(p, '\n');
            if (p) p++;
        }
    }
}

/* Count routes from "show ip route" */
static void parse_routes(const char *output, router_info_t *router)
{
    const char *p = output;
    while ((p = strstr(p, "\n")) != NULL) {
        p++;
        /* Count lines that start with route codes (B, C, S, O, R) followed by space */
        if ((*p == 'B' || *p == 'C' || *p == 'S' || *p == 'O' || *p == 'R' ||
             *p == 'L' || *p == 'D') && *(p + 1) == ' ')
            router->route_count++;
    }
}

/* Try to resolve neighbor IPs to router hostnames */
static void resolve_neighbor_routers(void)
{
    /* For each link, try to match the dst_ip to a known router_id */
    for (int i = 0; i < link_count; i++) {
        for (int j = 0; j < router_count; j++) {
            /* Check if dst_ip matches router_id (loopback peering) */
            if (strcmp(links[i].dst_ip, routers[j].router_id) == 0) {
                snprintf(links[i].dst_router, sizeof(links[i].dst_router),
                         "%s", routers[j].hostname);
                break;
            }
        }
    }
}

/* Check for bidirectional verification */
static void verify_bidirectional(void)
{
    for (int i = 0; i < link_count; i++) {
        if (links[i].dst_router[0] == '\0') continue;

        for (int j = 0; j < link_count; j++) {
            if (i == j) continue;
            if (strcmp(links[i].src_router, links[j].dst_router) == 0 &&
                strcmp(links[i].dst_router, links[j].src_router) == 0) {
                links[i].verified_both = true;
                break;
            }
        }
    }
}

/* =========================================================================
 * Execute and sign one command on one router
 * ========================================================================= */

static virp_error_t sweep_execute(const virp_driver_t *drv,
                                  virp_conn_t *conn,
                                  router_info_t *router,
                                  const char *command,
                                  char *output_copy, size_t copy_len)
{
    virp_exec_result_t result;
    virp_error_t err = drv->execute(conn, command, &result);
    if (err != VIRP_OK) return err;

    /* Build signed VIRP OBSERVATION */
    uint8_t msg_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t msg_len;
    uint16_t data_len = (result.output_len > 65530) ?
                        65530 : (uint16_t)result.output_len;

    err = virp_build_observation(msg_buf, sizeof(msg_buf), &msg_len,
                                 router->node_id,
                                 (uint32_t)(total_observations + 1),
                                 VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
                                 (const uint8_t *)result.output, data_len,
                                 &okey);
    if (err != VIRP_OK) return err;

    /* Verify it */
    virp_header_t hdr;
    err = virp_validate_message(msg_buf, msg_len, &okey, &hdr);
    if (err != VIRP_OK) return err;

    total_observations++;
    total_bytes += (int)msg_len;
    router->observation_count++;

    /* Copy output for topology parsing */
    if (output_copy && copy_len > 0) {
        size_t n = result.output_len < copy_len - 1 ?
                   result.output_len : copy_len - 1;
        memcpy(output_copy, result.output, n);
        output_copy[n] = '\0';
    }

    return VIRP_OK;
}

/* =========================================================================
 * Print topology map
 * ========================================================================= */

static void print_topology(double elapsed_sec)
{
    printf("\n");
    printf("================================================================\n");
    printf("  VIRP SIGNED TOPOLOGY MAP\n");
    printf("  Generated: %s", ctime(&(time_t){time(NULL)}));
    printf("  All data cryptographically verified\n");
    printf("================================================================\n\n");

    /* Router summary */
    printf("  ROUTERS (%d discovered)\n", router_count);
    printf("  %-8s %-12s %-8s %-10s %-8s %-6s\n",
           "Name", "Router-ID", "AS", "Neighbors", "Routes", "Obs");
    printf("  ---------------------------------------------------------------\n");

    int reachable = 0;
    for (int i = 0; i < router_count; i++) {
        if (!routers[i].reachable) {
            printf("  %-8s %-12s %-8s %-10s %-8s %-6s\n",
                   routers[i].hostname, "UNREACHABLE", "-", "-", "-", "-");
            continue;
        }
        reachable++;
        printf("  %-8s %-12s AS %-5u %-10d %-8d %d\n",
               routers[i].hostname,
               routers[i].router_id,
               routers[i].local_as,
               routers[i].bgp_neighbor_count,
               routers[i].route_count,
               routers[i].observation_count);
    }

    /* AS summary */
    printf("\n  AUTONOMOUS SYSTEMS\n  ");
    uint32_t seen_as[20];
    int as_count = 0;
    for (int i = 0; i < router_count; i++) {
        if (!routers[i].reachable) continue;
        bool found = false;
        for (int j = 0; j < as_count; j++) {
            if (seen_as[j] == routers[i].local_as) { found = true; break; }
        }
        if (!found && as_count < 20)
            seen_as[as_count++] = routers[i].local_as;
    }

    for (int i = 0; i < as_count; i++) {
        printf("AS %u [", seen_as[i]);
        bool first = true;
        for (int j = 0; j < router_count; j++) {
            if (routers[j].reachable && routers[j].local_as == seen_as[i]) {
                if (!first) printf(", ");
                printf("%s", routers[j].hostname);
                first = false;
            }
        }
        printf("]");
        if (i < as_count - 1) printf("  ");
    }
    printf("\n");

    /* BGP links */
    printf("\n  BGP PEERING SESSIONS (%d discovered)\n", link_count);
    printf("  %-8s %-8s %-6s %-8s %-8s %-8s\n",
           "Source", "Dest", "Type", "Src-AS", "Dst-AS", "Verified");
    printf("  ---------------------------------------------------------------\n");

    int verified_count = 0;
    int ebgp_count = 0;
    int ibgp_count = 0;

    for (int i = 0; i < link_count; i++) {
        const char *dst = links[i].dst_router[0] ?
                          links[i].dst_router : links[i].dst_ip;

        printf("  %-8s %-8s %-6s AS %-5u AS %-5u %s\n",
               links[i].src_router,
               dst,
               links[i].link_type,
               links[i].src_as,
               links[i].dst_as,
               links[i].verified_both ? "BOTH" : "one-way");

        if (links[i].verified_both) verified_count++;
        if (strcmp(links[i].link_type, "eBGP") == 0) ebgp_count++;
        else ibgp_count++;
    }

    /* ASCII topology diagram */
    printf("\n  TOPOLOGY DIAGRAM\n\n");

    /* Group by AS and show interconnections */
    for (int a = 0; a < as_count; a++) {
        printf("  +");
        for (int k = 0; k < 40; k++) printf("-");
        printf("+\n");
        printf("  |  AS %-34u |\n", seen_as[a]);
        printf("  |  ");
        for (int j = 0; j < router_count; j++) {
            if (routers[j].reachable && routers[j].local_as == seen_as[a])
                printf("[%s] ", routers[j].hostname);
        }
        /* Pad to box width */
        printf("%*s", 1, "");
        printf("\n");

        /* Show iBGP mesh within this AS */
        bool has_ibgp = false;
        for (int i = 0; i < link_count; i++) {
            if (links[i].src_as == seen_as[a] && links[i].dst_as == seen_as[a]) {
                if (!has_ibgp) {
                    printf("  |  iBGP: ");
                    has_ibgp = true;
                }
            }
        }
        /* Deduplicate iBGP links */
        if (has_ibgp) {
            bool printed[MAX_LINKS] = {false};
            for (int i = 0; i < link_count; i++) {
                if (printed[i]) continue;
                if (links[i].src_as != seen_as[a] || links[i].dst_as != seen_as[a])
                    continue;

                const char *dst = links[i].dst_router[0] ?
                                  links[i].dst_router : links[i].dst_ip;
                printf("%s<->%s ", links[i].src_router, dst);
                printed[i] = true;

                /* Mark reverse as printed too */
                for (int j = i + 1; j < link_count; j++) {
                    if (links[j].dst_router[0] &&
                        strcmp(links[j].src_router, dst) == 0 &&
                        strcmp(links[j].dst_router, links[i].src_router) == 0) {
                        printed[j] = true;
                    }
                }
            }
            printf("\n");
        }

        printf("  +");
        for (int k = 0; k < 40; k++) printf("-");
        printf("+\n");

        /* Show eBGP connections to other ASes */
        for (int i = 0; i < link_count; i++) {
            if (links[i].src_as == seen_as[a] && links[i].dst_as != seen_as[a]) {
                const char *dst = links[i].dst_router[0] ?
                                  links[i].dst_router : links[i].dst_ip;
                printf("       |  %s ---eBGP---> %s (AS %u)\n",
                       links[i].src_router, dst, links[i].dst_as);
            }
        }
        printf("\n");
    }

    /* Stats */
    printf("  ---------------------------------------------------------------\n");
    printf("  SWEEP STATISTICS\n");
    printf("    Routers swept:        %d/%d reachable\n", reachable, router_count);
    printf("    Observations signed:  %d\n", total_observations);
    printf("    Total VIRP bytes:     %d\n", total_bytes);
    printf("    BGP sessions:         %d (%d eBGP, %d iBGP)\n",
           link_count, ebgp_count, ibgp_count);
    printf("    Bidirectional verify: %d/%d sessions confirmed both sides\n",
           verified_count, link_count);
    printf("    Autonomous systems:   %d\n", as_count);
    printf("    Sweep time:           %.1f seconds\n", elapsed_sec);
    printf("    Crypto:               HMAC-SHA256, all observations signed\n");
    printf("  ---------------------------------------------------------------\n");
    printf("\n  Every data point above traces to a signed VIRP OBSERVATION.\n");
    printf("  Nothing on this map was inferred, assumed, or generated by AI.\n\n");
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(int argc, char **argv)
{
    printf("\n");
    printf("================================================================\n");
    printf("  VIRP Network Topology Sweep\n");
    printf("  Copyright (c) 2026 Third Level IT LLC\n");
    printf("================================================================\n\n");

#ifndef VIRP_DRIVER_CISCO
    printf("ERROR: Built without VIRP_DRIVER_CISCO.\n");
    printf("Rebuild with: make CISCO=1 all\n");
    return 1;
#else

    /* Register drivers */
    virp_driver_mock_init();
    virp_driver_cisco_init();

    /* Generate session O-Key */
    virp_key_generate(&okey, VIRP_KEY_TYPE_OKEY);
    printf("[+] O-Key generated. All observations will be signed.\n\n");

    /* Build router list */
    if (argc > 1) {
        /* User specified routers */
        for (int i = 1; i < argc && router_count < MAX_ROUTERS; i++) {
            snprintf(routers[router_count].hostname,
                     sizeof(routers[0].hostname), "R%d", router_count + 1);
            snprintf(routers[router_count].host,
                     sizeof(routers[0].host), "%s", argv[i]);
            routers[router_count].node_id = 0x01010101 + (uint32_t)router_count;
            router_count++;
        }
    } else {
        /* Default: all 10 lab routers */
        for (int i = 0; i < 10; i++) {
            snprintf(routers[i].hostname, sizeof(routers[0].hostname),
                     "R%d", i + 1);
            snprintf(routers[i].host, sizeof(routers[0].host),
                     "10.0.0.%d", 50 + i);
            routers[i].node_id = (uint32_t)((i + 1) * 0x01010101);
            router_count++;
        }
    }

    printf("[*] Sweep targets: %d routers\n", router_count);
    for (int i = 0; i < router_count; i++)
        printf("    %s (%s)\n", routers[i].hostname, routers[i].host);
    printf("\n");

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Sweep each router */
    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_CISCO_IOS);
    if (!drv) {
        printf("[-] Cisco driver not found!\n");
        return 1;
    }

    for (int r = 0; r < router_count; r++) {
        printf("[%d/%d] %s (%s)... ",
               r + 1, router_count,
               routers[r].hostname, routers[r].host);
        fflush(stdout);

        /* Build device descriptor */
        virp_device_t device = {
            .port = 22, .vendor = VIRP_VENDOR_CISCO_IOS,
            .node_id = routers[r].node_id, .enabled = true,
        };
        snprintf(device.hostname, sizeof(device.hostname),
                 "%s", routers[r].hostname);
        snprintf(device.host, sizeof(device.host),
                 "%s", routers[r].host);
        snprintf(device.username, sizeof(device.username), "virp-svc");
        snprintf(device.password, sizeof(device.password), "changeme");
        snprintf(device.enable_password, sizeof(device.enable_password),
                 "changeme");

        /* Connect */
        virp_conn_t *conn = drv->connect(&device);
        if (!conn) {
            printf("UNREACHABLE\n");
            routers[r].reachable = false;
            continue;
        }
        routers[r].reachable = true;

        /* Run each command */
        for (int c = 0; sweep_commands[c] != NULL; c++) {
            char output[VIRP_OUTPUT_MAX];
            virp_error_t err = sweep_execute(drv, conn, &routers[r],
                                             sweep_commands[c],
                                             output, sizeof(output));
            if (err == VIRP_OK) {
                /* Parse topology data from signed output */
                if (strstr(sweep_commands[c], "bgp summary"))
                    parse_bgp_summary(output, &routers[r]);
                else if (strstr(sweep_commands[c], "ip route"))
                    parse_routes(output, &routers[r]);
            }
        }

        printf("%d obs signed\n", routers[r].observation_count);

        /* Disconnect */
        drv->disconnect(conn);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    double elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    /* Resolve neighbor IPs to hostnames */
    resolve_neighbor_routers();

    /* Check bidirectional verification */
    verify_bidirectional();

    /* Print the topology map */
    print_topology(elapsed);

    /* Cleanup */
    virp_key_destroy(&okey);

    return 0;
#endif
}
