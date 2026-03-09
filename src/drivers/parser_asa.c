/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cisco ASA Output Parsers
 *
 * Each parser is stateless: raw CLI output in, structured data out.
 * Returns 0 on success, -1 on parse failure.
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "parser_asa.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* =========================================================================
 * Helpers
 * ========================================================================= */

/* Skip all whitespace including newlines */
static const char *skip_ws(const char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    return s;
}

/* Skip spaces and tabs only (not newlines) — for line-level parsing */
static const char *skip_hws(const char *s)
{
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

/* =========================================================================
 * Helper: find next line
 * ========================================================================= */

static const char *next_line(const char *s)
{
    while (*s && *s != '\n') s++;
    if (*s == '\n') s++;
    return s;
}

/* =========================================================================
 * show version
 *
 * Sample:
 *   Cisco Adaptive Security Appliance Software Version 9.8(3)21
 *   ...
 *   Hardware:   ASA5525, 8192 MB RAM, CPU Lynnfield 2394 MHz, 1 CPU (4 cores)
 *   ...
 *   System image file is "disk0:/asa983-21-smp-k8.bin"
 *   ...
 *   Serial Number: FCH12345678
 * ========================================================================= */

int asa_parse_version(const char *output, asa_version_t *result)
{
    if (!output || !result) return -1;

    memset(result, 0, sizeof(*result));

    const char *line = output;
    while (*line) {
        /* Version line */
        const char *p = strstr(line, "Software Version ");
        if (p) {
            p += 17; /* strlen("Software Version ") */
            const char *end = p;
            while (*end && !isspace((unsigned char)*end))
                end++;
            size_t vlen = (size_t)(end - p);
            if (vlen < sizeof(result->version)) {
                memcpy(result->version, p, vlen);
                result->version[vlen] = '\0';
            }
        }

        /* Hardware line: "Hardware:   ASA5525, 8192 MB RAM, ..." */
        p = strstr(line, "Hardware:");
        if (p) {
            p += 9;
            p = skip_ws(p);

            /* Model — up to comma */
            const char *comma = strchr(p, ',');
            if (comma) {
                size_t mlen = (size_t)(comma - p);
                if (mlen < sizeof(result->model)) {
                    memcpy(result->model, p, mlen);
                    result->model[mlen] = '\0';
                }

                /* RAM — "NNNN MB RAM" */
                const char *ram = strstr(comma, ", ");
                if (ram) {
                    ram += 2;
                    result->ram_mb = (uint32_t)strtoul(ram, NULL, 10);
                }

                /* CPU cores — "(N cores)" */
                const char *cores = strstr(comma, "(");
                if (cores) {
                    cores++;
                    result->cpu_cores = (uint8_t)strtoul(cores, NULL, 10);
                }
            }
        }

        /* Image file */
        p = strstr(line, "System image file is \"");
        if (p) {
            p += 22; /* strlen("System image file is \"") */
            const char *end = strchr(p, '"');
            if (end) {
                /* Extract just the filename after last / */
                const char *slash = p;
                for (const char *s = p; s < end; s++) {
                    if (*s == '/' || *s == ':')
                        slash = s + 1;
                }
                size_t flen = (size_t)(end - slash);
                if (flen < sizeof(result->image)) {
                    memcpy(result->image, slash, flen);
                    result->image[flen] = '\0';
                }
            }
        }

        /* Serial number */
        p = strstr(line, "Serial Number:");
        if (!p) p = strstr(line, "serial number:");
        if (p) {
            p = strchr(p, ':');
            if (p) {
                p++;
                p = skip_ws(p);
                const char *end = p;
                while (*end && !isspace((unsigned char)*end))
                    end++;
                size_t slen = (size_t)(end - p);
                if (slen < sizeof(result->serial)) {
                    memcpy(result->serial, p, slen);
                    result->serial[slen] = '\0';
                }
            }
        }

        /* Uptime — "up X days Y hours" */
        p = strstr(line, "up ");
        if (p && (strstr(p, "day") || strstr(p, "hour"))) {
            p += 3;
            result->uptime_days = (uint32_t)strtoul(p, NULL, 10);
            const char *h = strstr(p, "hour");
            if (h) {
                /* Walk back to find the number */
                const char *hn = h - 1;
                while (hn > p && isspace((unsigned char)*hn)) hn--;
                while (hn > p && isdigit((unsigned char)*(hn-1))) hn--;
                result->uptime_hours = (uint32_t)strtoul(hn, NULL, 10);
            }
        }

        line = next_line(line);
    }

    result->parsed = (result->version[0] != '\0');
    return result->parsed ? 0 : -1;
}

/* =========================================================================
 * show interface ip brief
 *
 * Interface                  IP-Address      OK? Method Status                Protocol
 * GigabitEthernet0/0         unassigned      YES unset  administratively down down
 * Management0/0              10.0.0.253      YES unset  up                    up
 * ========================================================================= */

int asa_parse_interfaces(const char *output, asa_interfaces_t *result)
{
    if (!output || !result) return -1;

    memset(result, 0, sizeof(*result));

    const char *line = output;
    bool header_found = false;

    while (*line) {
        /* Skip until we find the header line */
        if (!header_found) {
            if (strstr(line, "Interface") && strstr(line, "IP-Address")) {
                header_found = true;
                line = next_line(line);
                continue;
            }
            line = next_line(line);
            continue;
        }

        /* Parse data lines */
        if (result->count >= ASA_MAX_INTERFACES)
            break;

        /* Skip blank lines */
        const char *trimmed = skip_ws(line);
        if (*trimmed == '\n' || *trimmed == '\0') {
            line = next_line(line);
            continue;
        }

        asa_interface_t *iface = &result->interfaces[result->count];

        /*
         * Fixed-width columns. Parse by position:
         *   Interface: col 0-26
         *   IP-Address: col 27-42
         *   OK?: col 43-46
         *   Method: col 47-53
         *   Status: col 54-75 (can be "administratively down")
         *   Protocol: col 76+
         */
        const char *eol = line;
        while (*eol && *eol != '\n') eol++;
        size_t line_len = (size_t)(eol - line);

        if (line_len < 50) {
            line = next_line(line);
            continue;
        }

        /* Interface name */
        size_t name_end = 27;
        if (name_end > line_len) name_end = line_len;
        size_t nlen = name_end;
        while (nlen > 0 && isspace((unsigned char)line[nlen - 1]))
            nlen--;
        if (nlen >= sizeof(iface->name))
            nlen = sizeof(iface->name) - 1;
        memcpy(iface->name, line, nlen);
        iface->name[nlen] = '\0';

        /* IP address */
        if (line_len > 27) {
            const char *ip_start = skip_ws(line + 27);
            const char *ip_end = ip_start;
            while (*ip_end && !isspace((unsigned char)*ip_end))
                ip_end++;
            size_t ilen = (size_t)(ip_end - ip_start);
            if (ilen >= sizeof(iface->ip_address))
                ilen = sizeof(iface->ip_address) - 1;
            memcpy(iface->ip_address, ip_start, ilen);
            iface->ip_address[ilen] = '\0';
        }

        /* Status — after "Method" column, before "Protocol" */
        if (line_len > 54) {
            const char *stat = line + 54;
            /* Status can be multi-word: "administratively down" */
            const char *proto_start = eol;
            /* Protocol is the last word on the line */
            const char *last_word = eol - 1;
            while (last_word > stat && isspace((unsigned char)*last_word))
                last_word--;
            while (last_word > stat && !isspace((unsigned char)*(last_word - 1)))
                last_word--;
            proto_start = last_word;

            /* Everything from col 54 to proto_start is status */
            size_t slen = (size_t)(proto_start - stat);
            while (slen > 0 && isspace((unsigned char)stat[slen - 1]))
                slen--;
            if (slen >= sizeof(iface->status))
                slen = sizeof(iface->status) - 1;
            memcpy(iface->status, stat, slen);
            iface->status[slen] = '\0';

            /* Protocol */
            const char *pend = eol;
            while (pend > proto_start &&
                   isspace((unsigned char)*(pend - 1)))
                pend--;
            size_t plen = (size_t)(pend - proto_start);
            if (plen >= sizeof(iface->protocol))
                plen = sizeof(iface->protocol) - 1;
            memcpy(iface->protocol, proto_start, plen);
            iface->protocol[plen] = '\0';
        }

        if (iface->name[0] != '\0')
            result->count++;

        line = next_line(line);
    }

    result->parsed = (result->count > 0);
    return result->parsed ? 0 : -1;
}

/* =========================================================================
 * show route
 *
 * S*    0.0.0.0 0.0.0.0 [1/0] via 10.0.0.1, management
 * C     10.0.0.0 255.255.255.0 is directly connected, management
 * L     10.0.0.253 255.255.255.255 is directly connected, management
 * ========================================================================= */

int asa_parse_routes(const char *output, asa_routes_t *result)
{
    if (!output || !result) return -1;

    memset(result, 0, sizeof(*result));

    /* Gateway of last resort */
    const char *gw = strstr(output, "Gateway of last resort");
    if (gw) {
        const char *is = strstr(gw, " is ");
        if (is) {
            is += 4;
            const char *eol = is;
            while (*eol && *eol != '\n') eol++;
            size_t glen = (size_t)(eol - is);
            if (glen >= sizeof(result->gateway_of_last_resort))
                glen = sizeof(result->gateway_of_last_resort) - 1;
            memcpy(result->gateway_of_last_resort, is, glen);
            result->gateway_of_last_resort[glen] = '\0';
        }
    }

    const char *line = output;
    while (*line) {
        if (result->count >= ASA_MAX_ROUTES)
            break;

        /* Skip blank lines */
        if (*line == '\n' || *line == '\r') {
            line = next_line(line);
            continue;
        }

        const char *trimmed = skip_hws(line);

        /*
         * Route lines start with a code letter (S, C, L, O, B, D, R)
         * followed by optional '*' then spaces then an IP address (digit).
         * This distinguishes route entries from the "Codes:" header.
         */
        if (*trimmed && *trimmed != '\n' &&
            strchr("SCLOBIDRME", *trimmed) &&
            (trimmed[1] == ' ' || trimmed[1] == '*')) {
            /* Verify there's an IP address (digit) after the code + spaces */
            const char *check = trimmed + 1;
            if (*check == '*') check++;
            while (*check == ' ') check++;
            if (!isdigit((unsigned char)*check)) {
                line = next_line(line);
                continue;
            }

            asa_route_t *r = &result->routes[result->count];
            r->code = *trimmed;
            r->is_default = (trimmed[1] == '*');

            /* Advance past code and * */
            const char *p = trimmed + 1;
            if (*p == '*') p++;
            p = skip_ws(p);

            /* Network address */
            const char *net = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t nlen = (size_t)(p - net);
            if (nlen < sizeof(r->network)) {
                memcpy(r->network, net, nlen);
                r->network[nlen] = '\0';
            }
            p = skip_ws(p);

            /* Mask */
            const char *mask = p;
            while (*p && !isspace((unsigned char)*p)) p++;
            size_t mlen = (size_t)(p - mask);
            if (mlen < sizeof(r->mask)) {
                memcpy(r->mask, mask, mlen);
                r->mask[mlen] = '\0';
            }

            /* Find end of current line — all searches bounded to this */
            const char *eol = line;
            while (*eol && *eol != '\n') eol++;
            size_t remaining = (size_t)(eol - p);

            /* Copy current line segment for bounded searches */
            char line_seg[512];
            if (remaining >= sizeof(line_seg))
                remaining = sizeof(line_seg) - 1;
            memcpy(line_seg, p, remaining);
            line_seg[remaining] = '\0';

            /* [AD/metric] */
            const char *bracket = strchr(line_seg, '[');
            if (bracket) {
                bracket++;
                r->ad = (uint16_t)strtoul(bracket, NULL, 10);
                const char *slash = strchr(bracket, '/');
                if (slash) {
                    slash++;
                    r->metric = (uint32_t)strtoul(slash, NULL, 10);
                }
            }

            /* "via X.X.X.X" */
            const char *via = strstr(line_seg, "via ");
            if (via) {
                via += 4;
                const char *vend = via;
                while (*vend && *vend != ',' && !isspace((unsigned char)*vend))
                    vend++;
                size_t vlen = (size_t)(vend - via);
                if (vlen < sizeof(r->next_hop)) {
                    memcpy(r->next_hop, via, vlen);
                    r->next_hop[vlen] = '\0';
                }
            }

            /* Nameif — last word after comma (e.g. ", management") */
            const char *last_comma = NULL;
            for (const char *s = line_seg; *s; s++) {
                if (*s == ',') last_comma = s;
            }
            if (last_comma) {
                const char *nif = last_comma + 1;
                while (*nif == ' ' || *nif == '\t') nif++;
                const char *nend = nif;
                while (*nend && !isspace((unsigned char)*nend))
                    nend++;
                size_t niflen = (size_t)(nend - nif);
                if (niflen < sizeof(r->nameif)) {
                    memcpy(r->nameif, nif, niflen);
                    r->nameif[niflen] = '\0';
                }
            }

            /* "is directly connected" — no next_hop */
            if (strstr(line_seg, "is directly connected"))
                r->next_hop[0] = '\0';

            result->count++;
        }

        line = next_line(line);
    }

    result->parsed = (result->count > 0);
    return result->parsed ? 0 : -1;
}

/* =========================================================================
 * show conn count
 *
 * 12345 in use, 23456 most used
 * ========================================================================= */

int asa_parse_conn_count(const char *output, asa_conn_count_t *result)
{
    if (!output || !result) return -1;

    memset(result, 0, sizeof(*result));

    const char *p = strstr(output, "in use");
    if (p) {
        /* Walk back to find the number */
        const char *num = p - 1;
        while (num > output && isspace((unsigned char)*num)) num--;
        while (num > output && isdigit((unsigned char)*(num - 1))) num--;
        result->current = (uint32_t)strtoul(num, NULL, 10);
    }

    p = strstr(output, "most used");
    if (p) {
        const char *num = p - 1;
        while (num > output && isspace((unsigned char)*num)) num--;
        while (num > output && isdigit((unsigned char)*(num - 1))) num--;
        result->peak = (uint32_t)strtoul(num, NULL, 10);
    }

    result->parsed = (result->current > 0 || result->peak > 0 ||
                      strstr(output, "0 in use") != NULL);
    return result->parsed ? 0 : -1;
}

/* =========================================================================
 * show failover
 *
 * Failover On
 * ...
 * This host: Primary - Active
 * Other host: Secondary - Standby Ready
 *
 * or:
 * Failover Off
 * ========================================================================= */

int asa_parse_failover(const char *output, asa_failover_t *result)
{
    if (!output || !result) return -1;

    memset(result, 0, sizeof(*result));

    if (strstr(output, "Failover Off") || strstr(output, "failover off")) {
        result->failover_on = false;
        snprintf(result->state, sizeof(result->state), "Disabled");
        result->parsed = true;
        return 0;
    }

    if (strstr(output, "Failover On") || strstr(output, "failover on")) {
        result->failover_on = true;
    }

    const char *this_host = strstr(output, "This host:");
    if (this_host) {
        /* "This host: Primary - Active" */
        const char *dash = strchr(this_host, '-');
        if (dash) {
            dash++;
            const char *state = skip_ws(dash);
            const char *eol = state;
            while (*eol && *eol != '\n' && *eol != '\r')
                eol++;
            size_t slen = (size_t)(eol - state);
            while (slen > 0 && isspace((unsigned char)state[slen - 1]))
                slen--;
            if (slen >= sizeof(result->state))
                slen = sizeof(result->state) - 1;
            memcpy(result->state, state, slen);
            result->state[slen] = '\0';
        }
    }

    const char *other_host = strstr(output, "Other host:");
    if (other_host) {
        const char *dash = strchr(other_host, '-');
        if (dash) {
            dash++;
            const char *state = skip_ws(dash);
            const char *eol = state;
            while (*eol && *eol != '\n' && *eol != '\r')
                eol++;
            size_t slen = (size_t)(eol - state);
            while (slen > 0 && isspace((unsigned char)state[slen - 1]))
                slen--;
            if (slen >= sizeof(result->peer_state))
                slen = sizeof(result->peer_state) - 1;
            memcpy(result->peer_state, state, slen);
            result->peer_state[slen] = '\0';
        }
    }

    result->parsed = (result->state[0] != '\0' || !result->failover_on);
    return result->parsed ? 0 : -1;
}

/* =========================================================================
 * show cpu usage
 *
 * CPU utilization for 5 seconds = 1%; 1 minute: 2%; 5 minutes: 1%
 * ========================================================================= */

int asa_parse_cpu(const char *output, asa_cpu_t *result)
{
    if (!output || !result) return -1;

    memset(result, 0, sizeof(*result));

    const char *p = strstr(output, "5 seconds");
    if (p) {
        p = strchr(p, '=');
        if (p) {
            p++;
            p = skip_ws(p);
            result->five_sec = (uint8_t)strtoul(p, NULL, 10);
        }
    }

    p = strstr(output, "1 minute");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            p = skip_ws(p);
            result->one_min = (uint8_t)strtoul(p, NULL, 10);
        }
    }

    p = strstr(output, "5 minutes");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            p++;
            p = skip_ws(p);
            result->five_min = (uint8_t)strtoul(p, NULL, 10);
        }
    }

    result->parsed = (strstr(output, "CPU utilization") != NULL ||
                      strstr(output, "5 seconds") != NULL);
    return result->parsed ? 0 : -1;
}

/* =========================================================================
 * show memory
 *
 * Free memory:         1063498752 bytes (49%)
 * Used memory:         1084067840 bytes (51%)
 * Total memory:        2147566592 bytes (100%)
 * ========================================================================= */

int asa_parse_memory(const char *output, asa_memory_t *result)
{
    if (!output || !result) return -1;

    memset(result, 0, sizeof(*result));

    const char *p = strstr(output, "Free memory:");
    if (p) {
        p += 12;
        p = skip_ws(p);
        result->free = strtoull(p, NULL, 10);
    }

    p = strstr(output, "Used memory:");
    if (p) {
        p += 12;
        p = skip_ws(p);
        result->used = strtoull(p, NULL, 10);
    }

    p = strstr(output, "Total memory:");
    if (p) {
        p += 13;
        p = skip_ws(p);
        result->total = strtoull(p, NULL, 10);
    }

    /* If we only got free + used, compute total */
    if (result->total == 0 && (result->free > 0 || result->used > 0))
        result->total = result->free + result->used;

    result->parsed = (result->total > 0);
    return result->parsed ? 0 : -1;
}

/* =========================================================================
 * show access-list
 *
 * access-list OUTSIDE_IN; 5 elements; name hash: 0x12345678
 * access-list OUTSIDE_IN line 1 extended permit tcp any host 10.0.0.1 eq https (hitcnt=12345)
 * access-list OUTSIDE_IN line 2 extended deny ip any any (hitcnt=0)
 * ========================================================================= */

int asa_parse_access_list(const char *output, asa_acl_t *result)
{
    if (!output || !result) return -1;

    memset(result, 0, sizeof(*result));

    const char *line = output;
    while (*line) {
        if (result->count >= ASA_MAX_ACL_ENTRIES)
            break;

        /* Find end of current line */
        const char *eol = line;
        while (*eol && *eol != '\n') eol++;

        /* Only parse lines starting with "access-list " that contain " line " */
        if (strncmp(line, "access-list ", 12) == 0) {
            /* Search for " line " within current line only */
            const char *line_marker = NULL;
            for (const char *s = line; s < eol - 5; s++) {
                if (s[0] == ' ' && s[1] == 'l' && s[2] == 'i' &&
                    s[3] == 'n' && s[4] == 'e' && s[5] == ' ') {
                    line_marker = s;
                    break;
                }
            }

            if (line_marker) {
                asa_acl_entry_t *e = &result->entries[result->count];

                /* ACL name — between "access-list " and " line" */
                const char *name_start = line + 12;
                const char *name_end = line_marker;
                size_t nlen = (size_t)(name_end - name_start);
                if (nlen >= sizeof(e->acl_name))
                    nlen = sizeof(e->acl_name) - 1;
                memcpy(e->acl_name, name_start, nlen);
                e->acl_name[nlen] = '\0';

                /* Full line text (from "line N" onward) */
                const char *ace_start = line_marker + 1;
                size_t llen = (size_t)(eol - ace_start);
                if (llen >= sizeof(e->line))
                    llen = sizeof(e->line) - 1;
                memcpy(e->line, ace_start, llen);
                e->line[llen] = '\0';

                /* Hit count — "(hitcnt=N)" within current line */
                const char *hit = NULL;
                for (const char *s = line; s < eol - 6; s++) {
                    if (strncmp(s, "hitcnt=", 7) == 0) {
                        hit = s + 7;
                        break;
                    }
                }
                if (hit)
                    e->hitcnt = strtoull(hit, NULL, 10);

                result->count++;
            }
        }

        line = next_line(line);
    }

    result->parsed = (result->count > 0);
    return result->parsed ? 0 : -1;
}
