/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Wazuh Manager Device Driver — REST API via libcurl + JWT
 *
 * First REST-based VIRP driver. All other drivers use SSH via libssh2.
 *
 * Handles:
 *   - JWT authentication (POST /security/user/authenticate with basic auth)
 *   - Token lifecycle (auto-refresh before 15-minute expiry)
 *   - HTTPS GET to collector endpoints (agents, alerts, vuln, syscheck)
 *   - TLS verification on by default; VIRP_WAZUH_INSECURE=1 to disable
 *   - Output scrubbing (HTTP envelope stripped, raw JSON payload kept)
 *   - Command routing table for trust tier classification
 *
 * Design:
 *   - The "command" parameter to execute() is a Wazuh API endpoint path.
 *   - Polling intervals are NOT managed by this driver — the caller
 *     (O-Node collector loop, cron, or batch_execute) controls timing.
 *   - One CURL easy handle per connection, reused across requests.
 *   - No dynamic allocation outside of CURL internals — result goes
 *     into the fixed virp_exec_result_t buffer.
 *
 * Dependencies:
 *   - libcurl (HTTPS transport + basic auth)
 *   - libssl  (already a VIRP dependency)
 *
 * Build:  make WAZUH=1
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_driver.h"
#include "virp_driver_wazuh.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/crypto.h>

/* =========================================================================
 * Command Routing Table — Wazuh API endpoints → trust tiers
 *
 * All endpoints in this driver are read-only. Tier classification:
 *   GREEN  — the three autopilot read endpoints (passive monitoring)
 *
 * EXACT-matched (plen == ep_len in wz_route_endpoint, after the query
 * string is stripped). FAIL-CLOSED: any unmapped endpoint is RED.
 * Exact match — not longest-prefix — is deliberate: prefix matching let
 * "/agents_evil" and "/agents/001/restart" inherit the GREEN "/agents"
 * row (see the comment above wz_route_endpoint).
 *
 * This table IS wired to a route_command hook — wazuh_driver below sets
 * .route_command = wazuh_gate_tier, and gate_classify() consults it, so
 * an unmapped Wazuh endpoint classifies RED (a signed rejection plus a
 * filed proposal under ENFORCE), not UNCLASSIFIED. It previously
 * defaulted to GREEN — the most permissive tier there is — on the
 * rationale that the API user is read-only, which is a property of the
 * deployed credential, not of the endpoint being classified.
 * ========================================================================= */

const wz_command_route_t WZ_ROUTE_TABLE[] = {
    /*
     * Autopilot GREEN set (2026-07-29) — the exact read-only GETs the
     * monitoring battery uses, and NOTHING else. No YELLOW rows, no
     * write endpoints classified at all: everything unlisted is RED by
     * absence, which under the ENFORCE gate is a signed rejection plus
     * a filed proposal. The old table carried YELLOW telemetry rows and
     * BLACK write rows, but it only ever ran in SHADOW and was not even
     * wired to route_command — it never gated anything. With no BLACK
     * rows every RED here stays approvable (propose/approve/apply).
     */
    { "/agents",                  VIRP_TIER_GREEN },  /* agent list      */
    { "/agents/summary/status",   VIRP_TIER_GREEN },  /* summary/status  */
    { "/manager/stats/analysisd", VIRP_TIER_GREEN },  /* alerts summary  */

    /*
     * ── GREEN — read-only governance set (2026-08-19) ───────────
     *
     * Added so the reasoning tier can read the SIEM through the gate
     * rather than around it. Every row is an enumerated GET that
     * returns posture, not content: agent inventory, manager health,
     * event-pipeline counters, and the rule/decoder corpus.
     *
     * Still no YELLOW rows and still no write rows. This driver is
     * GET-only — wazuh_execute() refuses a non-GET method before it
     * dispatches — so classifying a restart or a config PUT as YELLOW
     * would advertise a tier the transport cannot honor. Writes stay
     * RED by absence, which under ENFORCE is a signed rejection plus a
     * filed proposal: reviewable, approvable, and honest about the
     * fact that nothing would execute.
     *
     * /manager/logs is deliberately NOT here while /manager/logs/summary
     * is: the summary returns counts by level, the full log returns
     * message bodies, and a SIEM's own log is the one place the
     * evidence of tampering with it would show up.
     */
    { "/manager/status",          VIRP_TIER_GREEN },  /* daemon up/down   */
    { "/manager/info",            VIRP_TIER_GREEN },  /* version/build    */
    { "/manager/stats",           VIRP_TIER_GREEN },  /* hourly counters  */
    { "/manager/stats/remoted",   VIRP_TIER_GREEN },  /* event reception  */
    { "/manager/logs/summary",    VIRP_TIER_GREEN },  /* counts by level  */
    { "/agents/summary/os",       VIRP_TIER_GREEN },  /* os breakdown     */
    { "/rules",                   VIRP_TIER_GREEN },  /* rule corpus      */
    { "/rules/groups",            VIRP_TIER_GREEN },  /* rule groups      */
    { "/decoders",                VIRP_TIER_GREEN },  /* decoder corpus   */
};

const size_t WZ_ROUTE_TABLE_SIZE =
    sizeof(WZ_ROUTE_TABLE) / sizeof(WZ_ROUTE_TABLE[0]);

/* =========================================================================
 * Endpoint Routing — EXACT path match (query string ignored)
 *
 * Exact matching closes the recorded prefix-boundary gap: with prefix
 * matching, "/agents_evil" and "/agents/001/restart" both inherited the
 * GREEN "/agents" row. A URL path either IS an enumerated read or it is
 * RED — there is no boundary rule subtle enough to be worth auditing.
 * ========================================================================= */

virp_trust_tier_t wz_route_endpoint(const char *endpoint)
{
    if (!endpoint) return VIRP_TIER_RED;             /* fail closed */

    /* Strip query string for matching */
    size_t ep_len = strlen(endpoint);
    const char *qmark = strchr(endpoint, '?');
    if (qmark)
        ep_len = (size_t)(qmark - endpoint);

    for (size_t i = 0; i < WZ_ROUTE_TABLE_SIZE; i++) {
        size_t plen = strlen(WZ_ROUTE_TABLE[i].endpoint_pattern);
        if (plen == ep_len &&
            strncmp(endpoint, WZ_ROUTE_TABLE[i].endpoint_pattern, plen) == 0)
            return WZ_ROUTE_TABLE[i].tier;
    }

    /* Fail-closed: an unmapped endpoint is RED, not GREEN. */
    return VIRP_TIER_RED;
}

/*
 * route_command hook for the tier gate. Accepts an optional "GET "
 * prefix (the transport is GET-only); any other method prefix — or
 * anything that is not a rooted path — is RED: write intents are
 * deliberately unclassified, so they fall to absence.
 */
virp_trust_tier_t wazuh_gate_tier(const char *command)
{
    if (!command) return VIRP_TIER_RED;

    /*
     * BLACK first, on the FULL command — before the query string is
     * stripped and before any method prefix is consumed.
     *
     * This is the driver_linux precedent, not the fortigate one, and
     * the difference matters. FortiGate keeps BLACK entirely inside
     * execute() because its deny list is destructive-command shaped:
     * "execute reboot" also classifies RED by absence, so the two
     * mechanisms already agree. Here they would NOT: the tier table
     * matches on the path with the query string stripped, so
     * "/agents?agents_list=004" is indistinguishable from the GREEN
     * "/agents" to wz_route_endpoint(). Leaving BLACK to the driver
     * alone would mean the gate classified a request to enumerate the
     * protected agent as a passive GREEN read, recorded it as such, and
     * only the driver would object.
     *
     * Returning BLACK here instead makes gate_classify() itself refuse:
     * VIRP_ERR_TIER_VIOLATION, and — unlike RED — no proposal is filed,
     * so the refusal is not approvable by anyone. That is the property
     * the protected set needs. The check inside wazuh_execute() stays
     * as defence in depth, exactly as driver_linux keeps both.
     */
    if (wz_is_black_endpoint(command)) return VIRP_TIER_BLACK;

    while (*command == ' ') command++;
    if (strncmp(command, "GET ", 4) == 0) {
        command += 4;
        while (*command == ' ') command++;
    }
    if (command[0] != '/') return VIRP_TIER_RED;
    return wz_route_endpoint(command);
}

/* =========================================================================
 * BLACK Tier — endpoints that must never reach the wire.
 *
 * Kept separate from WZ_ROUTE_TABLE for the same reason FortiGate keeps
 * FG_BLACK_COMMANDS separate from FG_ROUTE_TABLE: a tier is something a
 * request HOLDS and an approval can out-rank. BLACK is not a tier — it
 * is a refusal inside execute(), before any request is issued, that no
 * approval reaches.
 *
 * Two kinds of denial live here:
 *
 *   1. STATIC — shapes that are forbidden regardless of who is named:
 *      the manager's own configuration, active-response dispatch, and
 *      agent deletion. These are hardcoded because they are properties
 *      of the Wazuh API, not of this deployment.
 *
 *   2. CONFIGURED — the protected agent set, supplied by devices.json
 *      ("protected_agents": ["004","313"]) and registered by the loader.
 *      NOT hardcoded: which agent watches the reasoning tier and which
 *      watches the O-Node's own host are facts about a deployment, and
 *      burning them into the binary would make a fleet change a rebuild.
 *
 * Why this is enforced here and not by the API credential's RBAC:
 * Wazuh has TWO denial shapes and only one of them is visible. An
 * endpoint-level denial is a real HTTP 403, but a resource-level RBAC
 * filter returns HTTP 200 with the protected agent simply ABSENT from
 * affected_items. A caller cannot distinguish "agent 004 is healthy and
 * excluded" from "agent 004 does not exist" from "agent 004 was
 * deleted". Leaning on RBAC would also make a permission edit on the
 * manager silently become a policy change here. So the driver refuses,
 * on bytes it can see, before it asks.
 * ========================================================================= */

static uint32_t wz_protected_agents[WZ_PROTECTED_AGENT_MAX];
static size_t   wz_protected_agent_count = 0;

/*
 * Parse a run of decimal digits into *out. Returns the number of digits
 * consumed, 0 if the span is not entirely digits or overflows. Leading
 * zeros are fine and are exactly why this exists: Wazuh spells agent
 * ids zero-padded in URLs ("/agents/004") but a devices.json author
 * writes 4 or "004" interchangeably, and both must mean one agent.
 */
static size_t wz_parse_u32(const char *p, size_t len, uint32_t *out)
{
    if (len == 0) return 0;
    uint64_t v = 0;
    for (size_t i = 0; i < len; i++) {
        if (p[i] < '0' || p[i] > '9') return 0;
        v = v * 10 + (uint64_t)(p[i] - '0');
        if (v > 0xFFFFFFFFull) return 0;
    }
    *out = (uint32_t)v;
    return len;
}

int wazuh_gate_set_protected_agents(const char *csv)
{
    if (!csv || !*csv) return 0;

    /* Parse into scratch first: a list that fails halfway must not
     * leave half of itself registered. Same contract as
     * linux_gate_set_protected_vmids(). */
    uint32_t parsed[WZ_PROTECTED_AGENT_MAX];
    size_t   n = 0;

    for (const char *p = csv; *p; ) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;

        const char *start = p;
        while (*p >= '0' && *p <= '9') p++;
        size_t digits = (size_t)(p - start);

        uint32_t v = 0;
        if (digits == 0 || wz_parse_u32(start, digits, &v) == 0)
            return -1;                          /* non-numeric or overflow */

        while (*p == ' ') p++;
        if (*p && *p != ',') return -1;         /* trailing junk */

        if (n >= WZ_PROTECTED_AGENT_MAX) return -1;
        parsed[n++] = v;
    }

    for (size_t i = 0; i < n; i++) {
        bool dup = false;
        for (size_t j = 0; j < wz_protected_agent_count; j++)
            if (wz_protected_agents[j] == parsed[i]) { dup = true; break; }
        if (dup) continue;
        if (wz_protected_agent_count >= WZ_PROTECTED_AGENT_MAX) return -1;
        wz_protected_agents[wz_protected_agent_count++] = parsed[i];
    }

    return 0;
}

void wazuh_gate_clear_protected_agents(void)
{
    wz_protected_agent_count = 0;
}

size_t wazuh_gate_protected_agent_count(void)
{
    return wz_protected_agent_count;
}

static bool wz_agent_is_protected(uint32_t id)
{
    for (size_t i = 0; i < wz_protected_agent_count; i++)
        if (wz_protected_agents[i] == id) return true;
    return false;
}

/* Case-insensitive substring search — needle is ASCII lowercase. */
static bool wz_contains_ci(const char *hay, size_t hay_len, const char *needle)
{
    size_t nlen = strlen(needle);
    if (nlen == 0 || hay_len < nlen) return false;
    for (size_t i = 0; i + nlen <= hay_len; i++) {
        size_t j = 0;
        while (j < nlen) {
            char c = hay[i + j];
            if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
            if (c != needle[j]) break;
            j++;
        }
        if (j == nlen) return true;
    }
    return false;
}

/*
 * Scan every '/'-separated segment of the path for a purely-numeric
 * segment naming a protected agent. Generic on purpose: it catches
 * /agents/004, /syscheck/004, /vulnerability/004/last_scan,
 * /rootcheck/004, /sca/004 and any endpoint Wazuh adds later that
 * follows the same /<collection>/<agent-id> shape, with no new code.
 *
 * It also means a NON-agent numeric segment that happens to equal a
 * protected id — a rule id of 313, say — is refused. That is the
 * intended direction of error for a deny list: the cost is one read
 * that has to be asked for differently, against a miss that costs the
 * SIEM's view of the machine asking.
 */
static bool wz_path_names_protected_agent(const char *path, size_t len)
{
    size_t i = 0;
    while (i < len) {
        while (i < len && path[i] == '/') i++;
        size_t start = i;
        while (i < len && path[i] != '/') i++;
        size_t seg_len = i - start;
        uint32_t id = 0;
        if (seg_len > 0 && wz_parse_u32(path + start, seg_len, &id) != 0 &&
            wz_agent_is_protected(id))
            return true;
    }
    return false;
}

/*
 * Scan the query string for agent-selecting parameters. Any parameter
 * whose NAME contains "agent" (agents_list, agent_id, agent_list, ...)
 * has its comma-separated value list checked.
 *
 * The literal value "all" is refused outright: on any agent-selecting
 * parameter it means "including the protected ones", and it is the one
 * spelling that names a protected agent without containing its id.
 *
 * Only agent-named parameters are scanned, not every value in the query
 * — otherwise "?limit=313" would be refused as if it named agent 313.
 * The path scan above is the generic net; this is the precise one.
 */
static bool wz_query_names_protected_agent(const char *q, size_t len)
{
    size_t i = 0;
    while (i < len) {
        size_t k_start = i;
        while (i < len && q[i] != '=' && q[i] != '&') i++;
        size_t k_len = i - k_start;

        size_t v_start = i, v_len = 0;
        if (i < len && q[i] == '=') {
            i++;
            v_start = i;
            while (i < len && q[i] != '&') i++;
            v_len = i - v_start;
        }
        while (i < len && q[i] == '&') i++;

        if (!wz_contains_ci(q + k_start, k_len, "agent"))
            continue;

        /* Walk the comma-separated value list. */
        size_t j = 0;
        while (j < v_len) {
            while (j < v_len && q[v_start + j] == ',') j++;
            size_t t_start = j;
            while (j < v_len && q[v_start + j] != ',') j++;
            size_t t_len = j - t_start;
            if (t_len == 0) continue;

            const char *tok = q + v_start + t_start;
            if (wz_contains_ci(tok, t_len, "all"))
                return true;

            uint32_t id = 0;
            if (wz_parse_u32(tok, t_len, &id) != 0 && wz_agent_is_protected(id))
                return true;
        }
    }
    return false;
}

/*
 * Percent-decode into dst. Returns the decoded length, or (size_t)-1 if
 * the result would not fit.
 *
 * This exists because the endpoint string is handed to libcurl's
 * CURLOPT_URL verbatim and the MANAGER does the decoding. Without this
 * pass, "/agents/%30%30%34" scans as a non-numeric path segment here and
 * arrives at Wazuh as "/agents/004" — the protected agent, reached by
 * spelling it differently. Any deny list that matches on bytes the peer
 * will transform has to apply the same transform first.
 *
 * A single pass is correct, not a loop to a fixed point: an HTTP server
 * decodes the path once, so "%2530" reaches Wazuh as the literal text
 * "%30" and never becomes "0". Decoding twice here would refuse
 * endpoints the manager would never resolve to a protected agent.
 *
 * A malformed escape (trailing "%", non-hex digits) is copied through
 * literally, which is what curl and the server both do with it.
 */
static size_t wz_percent_decode(const char *src, size_t len,
                                char *dst, size_t dstsz)
{
    size_t o = 0;
    for (size_t i = 0; i < len; i++) {
        char c = src[i];
        if (c == '%' && i + 2 < len) {
            int hi = -1, lo = -1;
            char a1 = src[i + 1], a2 = src[i + 2];
            if (a1 >= '0' && a1 <= '9') hi = a1 - '0';
            else if (a1 >= 'a' && a1 <= 'f') hi = a1 - 'a' + 10;
            else if (a1 >= 'A' && a1 <= 'F') hi = a1 - 'A' + 10;
            if (a2 >= '0' && a2 <= '9') lo = a2 - '0';
            else if (a2 >= 'a' && a2 <= 'f') lo = a2 - 'a' + 10;
            else if (a2 >= 'A' && a2 <= 'F') lo = a2 - 'A' + 10;
            if (hi >= 0 && lo >= 0) {
                c = (char)((hi << 4) | lo);
                i += 2;
            }
        }
        if (o + 1 >= dstsz) return (size_t)-1;
        dst[o++] = c;
    }
    if (o >= dstsz) return (size_t)-1;
    dst[o] = '\0';
    return o;
}

/*
 * The scan proper, run over one spelling of the path+query. Called
 * twice by wz_is_black_endpoint — once on the bytes as given, once on
 * their percent-decoded form — because either spelling reaching a
 * protected agent is a reason to refuse.
 */
static bool wz_scan_black(const char *p, size_t total, bool is_delete)
{
    const char *qmark = memchr(p, '?', total);
    size_t path_len = qmark ? (size_t)(qmark - p) : total;
    const char *query = qmark ? qmark + 1 : NULL;
    size_t query_len = query ? total - path_len - 1 : 0;

    /*
     * STATIC 1 — the manager's (or a cluster node's) own configuration.
     * Substring, not prefix: it covers /manager/configuration and
     * /cluster/<node>/configuration in one rule. This is the SIEM's own
     * ruleset and output settings — the switch that decides what it
     * watches and where it reports.
     */
    if (wz_contains_ci(p, path_len, "/configuration"))
        return true;

    /*
     * STATIC 2 — active-response dispatch. Makes the manager run a
     * configured command ON an agent. Nothing about the payload is
     * observable from here, and "which agent" is caller-supplied.
     */
    if (wz_contains_ci(p, path_len, "/active-response"))
        return true;

    /*
     * STATIC 3 — agent deletion. DELETE /agents?agents_list=... removes
     * agents wholesale; the path alone is the GREEN "/agents" read, so
     * the method is what separates them. Other writes (restart, config
     * PUT) are deliberately NOT here: they stay RED by absence, which
     * keeps them proposable. Deletion is not proposable — an agent that
     * is gone takes its history with it.
     */
    if (is_delete && wz_contains_ci(p, path_len, "/agents"))
        return true;

    /* CONFIGURED — the protected agent set. */
    if (wz_path_names_protected_agent(p, path_len))
        return true;
    if (query && wz_query_names_protected_agent(query, query_len))
        return true;

    return false;
}

bool wz_is_black_endpoint(const char *command)
{
    /*
     * Answers exactly one question: "is this FORBIDDEN BY POLICY?" —
     * not "is this well-formed?" and not "should this be dispatched?"
     *
     * That distinction is why malformed input returns FALSE here rather
     * than fail-closed TRUE. BLACK is not merely a refusal; it is a
     * refusal that no approval can reach and that files no proposal. A
     * command that is null or not a rooted path is a typo, and a typo
     * should surface as the ordinary RED-by-absence rejection an
     * operator can read and re-file, not as a tier violation implying
     * someone tried to touch the protected set.
     *
     * Nothing is weakened by this: both callers already refuse
     * malformed input on their own paths — wazuh_gate_tier() returns
     * RED for a null or unrooted command, and wazuh_execute() refuses
     * any non-rooted path with no_dispatch before it builds a URL. This
     * function never has to be the thing that catches garbage.
     */
    if (!command) return false;

    const char *p = command;
    while (*p == ' ' || *p == '\t') p++;

    /*
     * Take the HTTP method if one is spelled. Matching is
     * case-insensitive here even though the tier table is
     * case-sensitive: over-matching a deny list is fail-closed, so
     * "delete /agents" must be caught as surely as "DELETE /agents".
     */
    bool is_delete = false;
    static const char *methods[] = { "GET ", "POST ", "PUT ", "PATCH ",
                                     "DELETE ", "HEAD ", "OPTIONS " };
    for (size_t m = 0; m < sizeof(methods) / sizeof(methods[0]); m++) {
        size_t mlen = strlen(methods[m]);
        if (strncasecmp(p, methods[m], mlen) == 0) {
            is_delete = (strncasecmp(p, "DELETE ", 7) == 0);
            p += mlen;
            while (*p == ' ') p++;
            break;
        }
    }

    if (p[0] != '/') return false;          /* malformed, not forbidden — see above */

    size_t total = strlen(p);

    /* Pass 1 — the bytes exactly as the caller wrote them. */
    if (wz_scan_black(p, total, is_delete))
        return true;

    /*
     * Pass 2 — the same bytes as the MANAGER will read them. If the
     * endpoint is too long to decode into the scratch buffer, refuse:
     * an endpoint this driver cannot analyse is one it cannot vouch
     * for, and at 4 KB it is far past anything the GREEN read set needs
     * (wazuh_execute builds its URL in 2 KB and would truncate it
     * anyway).
     */
    char decoded[4096];
    size_t dlen = wz_percent_decode(p, total, decoded, sizeof(decoded));
    if (dlen == (size_t)-1)
        return true;
    if (dlen != total && wz_scan_black(decoded, dlen, is_delete))
        return true;

    return false;
}

/* =========================================================================
 * Connection State
 * ========================================================================= */

struct virp_conn {
    virp_device_t       device;
    CURL               *curl;               /* Reusable CURL handle         */
    char                base_url[512];       /* https://host:port            */
    char                jwt_token[WZ_TOKEN_MAX]; /* Current Bearer token     */
    time_t              token_obtained;      /* When we got the token        */
    time_t              token_expiry;        /* When to refresh              */
    bool                connected;
    bool                authenticated;
};

/* =========================================================================
 * TLS Verification Configuration
 *
 * Default: verification ON. Override with VIRP_WAZUH_INSECURE=1.
 * Custom CA bundle: set VIRP_CA_BUNDLE to path.
 * ========================================================================= */

static void wz_configure_tls(CURL *curl)
{
    const char *insecure = getenv("VIRP_WAZUH_INSECURE");
    if (insecure && strcmp(insecure, "1") == 0) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        return;
    }

    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    const char *ca_bundle = getenv("VIRP_CA_BUNDLE");
    if (ca_bundle && ca_bundle[0] != '\0')
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
}

/* =========================================================================
 * CURL Write Callback — accumulate response into a fixed buffer
 *
 * userdata points to a wz_response_t which tracks the write position.
 * ========================================================================= */

typedef struct {
    char   *buf;
    size_t  buf_size;
    size_t  offset;
} wz_response_t;

static size_t wz_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    wz_response_t *resp = (wz_response_t *)userdata;
    size_t bytes = size * nmemb;
    size_t avail = resp->buf_size - resp->offset - 1;  /* Reserve NUL */

    if (bytes > avail)
        bytes = avail;

    if (bytes > 0) {
        memcpy(resp->buf + resp->offset, ptr, bytes);
        resp->offset += bytes;
        resp->buf[resp->offset] = '\0';
    }

    return size * nmemb;  /* Always report full consumption to curl */
}

/* =========================================================================
 * JWT Authentication
 *
 * POST /security/user/authenticate
 * Authorization: Basic base64(username:password)
 *
 * Response: {"data": {"token": "eyJ..."}}
 *
 * CURL handles basic auth natively via CURLOPT_USERPWD.
 * ========================================================================= */

static virp_error_t wz_authenticate(struct virp_conn *conn)
{
    if (!conn || !conn->curl)
        return WZ_ERR_CURL_INIT;

    char url[1024];
    snprintf(url, sizeof(url), "%s%s", conn->base_url, WZ_EP_AUTH);

    /* Response buffer for the JWT JSON */
    char resp_buf[WZ_TOKEN_MAX * 2];
    wz_response_t resp = {
        .buf = resp_buf,
        .buf_size = sizeof(resp_buf),
        .offset = 0,
    };

    /* Credentials for basic auth */
    char userpwd[256];
    snprintf(userpwd, sizeof(userpwd), "%s:%s",
             conn->device.username, conn->device.password);

    /* Configure CURL for auth request */
    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_POST, 1L);
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDS, "");
    curl_easy_setopt(conn->curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
    curl_easy_setopt(conn->curl, CURLOPT_USERPWD, userpwd);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, wz_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(conn->curl, CURLOPT_CONNECTTIMEOUT, (long)WZ_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, (long)WZ_API_TIMEOUT_SEC);
    wz_configure_tls(conn->curl);

    CURLcode rc = curl_easy_perform(conn->curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "[Wazuh] Auth curl_easy_perform failed: %s (%s)\n",
                curl_easy_strerror(rc), url);
        return WZ_ERR_CURL_PERFORM;
    }

    long http_code = 0;
    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (http_code != 200) {
        fprintf(stderr, "[Wazuh] Auth failed: HTTP %ld from %s\n"
                        "[Wazuh] Response: %.256s\n",
                http_code, url, resp_buf);
        return WZ_ERR_AUTH_FAILED;
    }

    /*
     * Extract JWT from: {"data": {"token": "eyJ..."}}
     *
     * Minimal JSON parse — find "token" key, extract value.
     * Same approach as the O-Node's json_extract_string, but
     * we need to handle Wazuh's nested response shape.
     */
    const char *tok_key = "\"token\"";
    const char *tok_pos = strstr(resp_buf, tok_key);
    if (!tok_pos) {
        fprintf(stderr, "[Wazuh] Auth response has no 'token' field\n"
                        "[Wazuh] Response: %.512s\n", resp_buf);
        return WZ_ERR_AUTH_FAILED;
    }

    /* Skip past "token" and find the colon, then the opening quote */
    tok_pos += strlen(tok_key);
    while (*tok_pos == ' ' || *tok_pos == ':' || *tok_pos == '\t')
        tok_pos++;
    if (*tok_pos != '"') {
        fprintf(stderr, "[Wazuh] Malformed token value in auth response\n");
        return WZ_ERR_AUTH_FAILED;
    }
    tok_pos++;  /* Skip opening quote */

    /* Copy token until closing quote */
    size_t ti = 0;
    while (*tok_pos && *tok_pos != '"' && ti < WZ_TOKEN_MAX - 1)
        conn->jwt_token[ti++] = *tok_pos++;
    conn->jwt_token[ti] = '\0';

    if (ti == 0) {
        fprintf(stderr, "[Wazuh] Empty token in auth response\n");
        return WZ_ERR_AUTH_FAILED;
    }

    conn->token_obtained = time(NULL);
    conn->token_expiry = conn->token_obtained + WZ_TOKEN_REFRESH_SEC;
    conn->authenticated = true;

    fprintf(stderr, "[Wazuh] Authenticated: %s@%s (token %zu bytes, "
                    "refresh in %ds)\n",
            conn->device.username, conn->device.host,
            ti, WZ_TOKEN_REFRESH_SEC);

    return VIRP_OK;
}

/* =========================================================================
 * Token Refresh — re-authenticate if token is near expiry
 * ========================================================================= */

static virp_error_t wz_ensure_token(struct virp_conn *conn)
{
    if (!conn->authenticated || time(NULL) >= conn->token_expiry) {
        fprintf(stderr, "[Wazuh] Token expired or missing, re-authenticating\n");
        return wz_authenticate(conn);
    }
    return VIRP_OK;
}

/* =========================================================================
 * Driver: connect
 *
 * Initializes CURL handle, builds base URL, authenticates.
 * ========================================================================= */

static virp_conn_t *wazuh_connect(const virp_device_t *device)
{
    if (!device) return NULL;

    struct virp_conn *conn = calloc(1, sizeof(struct virp_conn));
    if (!conn) return NULL;

    memcpy(&conn->device, device, sizeof(*device));
    conn->connected = false;
    conn->authenticated = false;

    /* Build base URL — Wazuh API default port is 55000 */
    uint16_t port = device->api_port ? device->api_port :
                    (device->port ? device->port : 55000);
    snprintf(conn->base_url, sizeof(conn->base_url),
             "https://%s:%u", device->host, port);

    /* Initialize CURL */
    conn->curl = curl_easy_init();
    if (!conn->curl) {
        fprintf(stderr, "[Wazuh] curl_easy_init() failed\n");
        free(conn);
        return NULL;
    }

    /* Log TLS posture at connect time */
    {
        const char *insecure = getenv("VIRP_WAZUH_INSECURE");
        if (insecure && strcmp(insecure, "1") == 0) {
            fprintf(stderr, "[WARN] Wazuh TLS verification DISABLED "
                    "(VIRP_WAZUH_INSECURE=1) — MITM risk\n");
        }
    }

    fprintf(stderr, "[Wazuh] Connecting to %s as %s\n",
            conn->base_url, device->username);

    /* Authenticate — get JWT */
    virp_error_t err = wz_authenticate(conn);
    if (err != VIRP_OK) {
        fprintf(stderr, "[Wazuh] Authentication failed: %d\n", err);
        curl_easy_cleanup(conn->curl);
        free(conn);
        return NULL;
    }

    conn->connected = true;

    fprintf(stderr, "[Wazuh] Connected: %s@%s:%u\n",
            device->username, device->host, port);

    return (virp_conn_t *)conn;
}

/* =========================================================================
 * Driver: execute
 *
 * The "command" is a Wazuh API endpoint path, e.g.:
 *   /agents?select=id,name,status,ip
 *   /alerts?limit=100&sort=-timestamp
 *
 * Steps:
 *   1. Ensure JWT token is fresh (refresh if near expiry)
 *   2. Build full URL: base_url + endpoint
 *   3. GET with Authorization: Bearer <token>
 *   4. Copy JSON response into result buffer
 *   5. Check for API-level errors
 * ========================================================================= */

static virp_error_t wazuh_execute(virp_conn_t *base_conn,
                                  const char *command,
                                  virp_exec_result_t *result)
{
    if (!base_conn || !command || !result)
        return VIRP_ERR_NULL_PTR;

    struct virp_conn *conn = (struct virp_conn *)base_conn;
    memset(result, 0, sizeof(*result));

    /*
     * ── BLACK tier: never dispatch ──────────────────────────────
     *
     * FIRST, before the transport check, before the connectivity check,
     * before the token is touched. A BLACK refusal must not depend on
     * being connected, on the token being fresh, or on the manager
     * being reachable — it is a property of the request, so it is
     * decided offline and is deterministically testable.
     *
     * no_dispatch is set: nothing went out, so the O-Node can record
     * this as a refusal rather than an unknown-outcome error.
     */
    if (wz_is_black_endpoint(command)) {
        result->success = false;
        result->exit_code = 1;
        result->no_dispatch = true;
        result->disposition = VIRP_DISPOSITION_NOT_SENT;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "BLACK tier: endpoint forbidden on %s",
                 conn->device.hostname);
        fprintf(stderr, "[Wazuh] BLACK tier blocked: '%.128s' on %s\n",
                command, conn->device.hostname);
        int wr = snprintf(result->output, sizeof(result->output),
                          "%s>%.256s\nBLACK tier: endpoint forbidden",
                          conn->device.hostname, command);
        result->output_len = (wr > 0) ? (size_t)wr : 0;
        return VIRP_OK;
    }

    /*
     * GET-only transport honesty — checked BEFORE the connectivity test
     * so the refusal is deterministic and offline-testable.
     *
     * This driver can only issue GETs. The old code stripped ANY method
     * prefix and GETted the path, so an approved "POST /agents/restart"
     * would silently execute something other than what was classified
     * and approved. A command carrying a non-GET method prefix (or
     * anything that is not a rooted path) is refused outright as a
     * soft-failure, which the O-Node wraps as a signed ERROR
     * observation (executed=no).
     *
     * The endpoint path (with query string) goes straight to libcurl's
     * CURLOPT_URL as a C string — no shell interpretation, no
     * fork/exec. Characters like & in the query string are URL
     * parameter separators, not shell operators.
     */
    const char *endpoint = command;
    while (*endpoint == ' ') endpoint++;
    if (strncmp(endpoint, "GET ", 4) == 0) {
        endpoint += 4;
        while (*endpoint == ' ') endpoint++;
    }
    if (endpoint[0] != '/') {
        result->success = false;
        result->no_dispatch = true;   /* refused before any request went out */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Refused: GET-only REST driver cannot honor '%.64s' "
                 "(non-GET method or unrooted path)", command);
        return VIRP_OK;
    }

    if (!conn->connected) {
        result->success = false;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Not connected to %s", conn->device.hostname);
        return WZ_ERR_NOT_CONNECTED;
    }

    /* Step 1: Ensure token is fresh */
    virp_error_t err = wz_ensure_token(conn);
    if (err != VIRP_OK) {
        conn->connected = false;
        conn->authenticated = false;
        result->success = false;
        result->no_dispatch = true;   /* the command request was never issued */
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "Token refresh failed on %s", conn->device.hostname);
        return VIRP_OK;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    /* Step 2: Build URL — base_url + endpoint path, passed directly to libcurl */
    char url[2048];
    snprintf(url, sizeof(url), "%s%s", conn->base_url, endpoint);

    /* Step 3: Build Authorization header */
    char auth_hdr[WZ_TOKEN_MAX + 32];
    snprintf(auth_hdr, sizeof(auth_hdr), "Authorization: Bearer %s",
             conn->jwt_token);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_hdr);
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* Response buffer — write after the hostname prefix */
    char api_response[WZ_RESPONSE_MAX];
    wz_response_t resp = {
        .buf = api_response,
        .buf_size = sizeof(api_response),
        .offset = 0,
    };

    /* Configure CURL for API request */
    curl_easy_reset(conn->curl);
    curl_easy_setopt(conn->curl, CURLOPT_URL, url);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(conn->curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEFUNCTION, wz_write_cb);
    curl_easy_setopt(conn->curl, CURLOPT_WRITEDATA, &resp);
    curl_easy_setopt(conn->curl, CURLOPT_CONNECTTIMEOUT, (long)WZ_CONNECT_TIMEOUT_SEC);
    curl_easy_setopt(conn->curl, CURLOPT_TIMEOUT, (long)WZ_API_TIMEOUT_SEC);
    wz_configure_tls(conn->curl);

    CURLcode rc = curl_easy_perform(conn->curl);

    curl_slist_free_all(headers);

    clock_gettime(CLOCK_MONOTONIC, &end);
    result->exec_time_ms = (uint64_t)((end.tv_sec - start.tv_sec) * 1000 +
                                       (end.tv_nsec - start.tv_nsec) / 1000000);

    if (rc != CURLE_OK) {
        result->success = false;
        /* Connect-class failures prove the request never went out; a
         * timeout or mid-transfer death proves nothing — the server
         * may have processed the request. */
        result->no_dispatch = (rc == CURLE_COULDNT_CONNECT ||
                               rc == CURLE_COULDNT_RESOLVE_HOST ||
                               rc == CURLE_SSL_CONNECT_ERROR);
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "curl error on %s: %s", conn->device.hostname,
                 curl_easy_strerror(rc));
        /* Connection-level failures mark session stale */
        if (rc == CURLE_COULDNT_CONNECT || rc == CURLE_OPERATION_TIMEDOUT ||
            rc == CURLE_SSL_CONNECT_ERROR) {
            conn->connected = false;
        }
        return VIRP_OK;
    }

    long http_code = 0;
    curl_easy_getinfo(conn->curl, CURLINFO_RESPONSE_CODE, &http_code);

    /* Step 4: Format output like other drivers: hostname>endpoint\nresponse */
    int written = snprintf(result->output, sizeof(result->output),
                           "%s>%s [HTTP %ld]\n%s",
                           conn->device.hostname, endpoint,
                           http_code, api_response);
    result->output_len = (written > 0) ? (size_t)written : 0;

    /* Step 5: Check for errors */
    if (http_code == 401) {
        /* Token expired server-side — force re-auth on next call */
        conn->authenticated = false;
        result->success = false;
        result->exit_code = 401;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "HTTP 401 Unauthorized — token invalidated on %s",
                 conn->device.hostname);
    } else if (http_code >= 400) {
        result->success = false;
        result->exit_code = (int)http_code;
        snprintf(result->error_msg, sizeof(result->error_msg),
                 "HTTP %ld from %s%s", http_code,
                 conn->device.hostname, endpoint);
    } else {
        result->success = true;
        result->exit_code = 0;

        /* Check for Wazuh API error in JSON body */
        if (strstr(api_response, "\"error\"") &&
            !strstr(api_response, "\"error\":0") &&
            !strstr(api_response, "\"error\": 0")) {
            result->success = false;
            result->exit_code = 1;
            snprintf(result->error_msg, sizeof(result->error_msg),
                     "Wazuh API error in response from %s",
                     conn->device.hostname);
        }
    }

    return VIRP_OK;
}

/* =========================================================================
 * Driver: disconnect
 * ========================================================================= */

static void wazuh_disconnect(virp_conn_t *base_conn)
{
    if (!base_conn) return;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (conn->curl) {
        curl_easy_cleanup(conn->curl);
        conn->curl = NULL;
    }

    /* Zero the token in memory */
    volatile char *p = (volatile char *)conn->jwt_token;
    for (size_t i = 0; i < WZ_TOKEN_MAX; i++)
        p[i] = '\0';

    conn->connected = false;
    conn->authenticated = false;

    fprintf(stderr, "[Wazuh] Disconnected: %s\n", conn->device.hostname);

    OPENSSL_cleanse(conn->device.password, sizeof(conn->device.password));
    free(conn);
}

/* =========================================================================
 * Driver: detect
 * ========================================================================= */

static bool wazuh_detect(virp_conn_t *base_conn)
{
    if (!base_conn) return false;
    struct virp_conn *conn = (struct virp_conn *)base_conn;
    return conn->device.vendor == VIRP_VENDOR_WAZUH;
}

/* =========================================================================
 * Driver: health_check — GET /manager/status
 * ========================================================================= */

static virp_error_t wazuh_health_check(virp_conn_t *base_conn)
{
    if (!base_conn) return VIRP_ERR_NULL_PTR;
    struct virp_conn *conn = (struct virp_conn *)base_conn;

    if (!conn->connected) return WZ_ERR_NOT_CONNECTED;

    /*
     * Health probe MUST be an endpoint from the GREEN read set.
     *
     * This used to probe /manager/status, which is (a) not in the
     * enumerated GREEN set and (b) not readable by a properly
     * least-privileged API credential: virp-lab's account happens to be
     * allowed it, but virp-node2's tighter account gets HTTP 403
     * (error 4000), so the watchdog health-checked, failed, dropped the
     * connection and reconnected in a loop — churn caused entirely by
     * the daemon probing outside its own policy. /agents/summary/status
     * is GREEN, is what the battery already reads, and works for both.
     *
     * Note both Wazuh denial shapes exist and differ: endpoint-level
     * permission denial is a real 403, while resource-level RBAC
     * filtering is HTTP 200 with an empty affected_items set.
     */
    virp_exec_result_t result;
    virp_error_t err = wazuh_execute(base_conn, WZ_EP_AGENT_SUMMARY, &result);
    if (err != VIRP_OK) return err;

    return result.success ? VIRP_OK : WZ_ERR_API_ERROR;
}

/* =========================================================================
 * Driver Registration
 * ========================================================================= */

static virp_driver_t wazuh_driver = {
    .name       = "wazuh",
    .vendor     = VIRP_VENDOR_WAZUH,
    .connect    = wazuh_connect,
    .execute    = wazuh_execute,
    .disconnect = wazuh_disconnect,
    .detect     = wazuh_detect,
    .health_check = wazuh_health_check,
    .route_command = wazuh_gate_tier,
};

const virp_driver_t *virp_driver_wazuh(void)
{
    return &wazuh_driver;
}

void virp_driver_wazuh_init(void)
{
    virp_driver_register(&wazuh_driver);
}
