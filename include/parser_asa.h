/*
 * parser_asa.h — Output parsers for Cisco ASA CLI commands
 *
 * Each parser extracts structured fields from raw CLI output.
 * Parsers are stateless — they take a string in and fill a struct out.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef PARSER_ASA_H
#define PARSER_ASA_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── show version ──────────────────────────────────────────────── */
typedef struct {
    char        version[32];        /* e.g. "9.8(3)21"            */
    char        model[32];          /* e.g. "ASA5525"             */
    uint32_t    ram_mb;
    uint8_t     cpu_cores;
    char        image[128];         /* e.g. "asa983-21-smp-k8.bin"*/
    char        serial[32];
    uint32_t    uptime_days;
    uint32_t    uptime_hours;
    bool        parsed;
} asa_version_t;

int asa_parse_version(const char *output, asa_version_t *result);

/* ── show interface ip brief ───────────────────────────────────── */
#define ASA_MAX_INTERFACES  64

typedef struct {
    char        name[48];           /* GigabitEthernet0/0          */
    char        ip_address[16];     /* 10.0.0.253 or "unassigned"  */
    char        status[32];         /* up / administratively down   */
    char        protocol[16];       /* up / down                    */
} asa_interface_t;

typedef struct {
    asa_interface_t interfaces[ASA_MAX_INTERFACES];
    int             count;
    bool            parsed;
} asa_interfaces_t;

int asa_parse_interfaces(const char *output, asa_interfaces_t *result);

/* ── show route ────────────────────────────────────────────────── */
#define ASA_MAX_ROUTES  256

typedef struct {
    char        code;               /* S, C, L, O, B, D, R, etc.  */
    char        network[20];        /* 10.0.0.0                    */
    char        mask[20];           /* 255.255.255.0               */
    char        next_hop[20];       /* 10.0.0.1 or empty           */
    char        nameif[32];         /* management, inside, outside */
    uint16_t    ad;                 /* Administrative distance     */
    uint32_t    metric;
    bool        is_default;         /* Default route (S*)          */
} asa_route_t;

typedef struct {
    asa_route_t routes[ASA_MAX_ROUTES];
    int         count;
    char        gateway_of_last_resort[64];
    bool        parsed;
} asa_routes_t;

int asa_parse_routes(const char *output, asa_routes_t *result);

/* ── show conn count ───────────────────────────────────────────── */
typedef struct {
    uint32_t    current;
    uint32_t    peak;
    bool        parsed;
} asa_conn_count_t;

int asa_parse_conn_count(const char *output, asa_conn_count_t *result);

/* ── show failover ─────────────────────────────────────────────── */
typedef struct {
    char        state[32];          /* Active, Standby, Disabled   */
    char        peer_state[32];     /* Active, Standby, Failed     */
    bool        failover_on;
    bool        parsed;
} asa_failover_t;

int asa_parse_failover(const char *output, asa_failover_t *result);

/* ── show cpu usage ────────────────────────────────────────────── */
typedef struct {
    uint8_t     five_sec;
    uint8_t     one_min;
    uint8_t     five_min;
    bool        parsed;
} asa_cpu_t;

int asa_parse_cpu(const char *output, asa_cpu_t *result);

/* ── show memory ───────────────────────────────────────────────── */
typedef struct {
    uint64_t    total;
    uint64_t    used;
    uint64_t    free;
    bool        parsed;
} asa_memory_t;

int asa_parse_memory(const char *output, asa_memory_t *result);

/* ── show access-list ──────────────────────────────────────────── */
#define ASA_MAX_ACL_ENTRIES  512

typedef struct {
    char        acl_name[64];
    char        line[256];          /* Full ACE text               */
    uint64_t    hitcnt;
} asa_acl_entry_t;

typedef struct {
    asa_acl_entry_t entries[ASA_MAX_ACL_ENTRIES];
    int             count;
    bool            parsed;
} asa_acl_t;

int asa_parse_access_list(const char *output, asa_acl_t *result);

#ifdef __cplusplus
}
#endif
#endif /* PARSER_ASA_H */
