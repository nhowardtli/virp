/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Zammad REST gate-classifier unit tests (zammad_gate_tier / zm_route_path).
 *
 * The Zammad driver is GET-only over libcurl, so there is no shell to
 * escape — but the classifier is still guard-first: the method prefix
 * and the rooted-path form are checked before any row, the five GREEN
 * shapes are matched byte-exact, and the query string is CLASSIFIED
 * rather than stripped. FAIL-CLOSED: anything not explicitly GREEN is
 * RED, and nothing is prefix-matched — the gap that bit the Wazuh
 * driver, where longest-prefix matching let "/agents_evil" and
 * "/agents/001/restart" inherit the GREEN "/agents" row.
 *
 * Offline-only: this binary classifies strings and never originates
 * network contact, so it needs no VIRP_LIVE_* fence.
 *
 * Build:  make ZAMMAD=1 test-zammad-gate
 */

#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_driver.h"
#include "virp_driver_zammad.h"
#include "virp_message.h"   /* virp_command_check_separators */
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

/*
 * Gate-level mirror of gate_tier_blocks() in virp_onode.c under the
 * deployed threshold (max tier YELLOW): UNCLASSIFIED and BLACK always
 * block, otherwise anything above YELLOW blocks. Every RED assertion
 * below also asserts the gate DECISION, so a classifier regression that
 * returns a passing tier fails here, not on the wire.
 */
static int gate_blocks_at_yellow(virp_trust_tier_t t)
{
    if (t == VIRP_TIER_UNCLASSIFIED) return 1;
    if (t == VIRP_TIER_BLACK)        return 1;
    return t > VIRP_TIER_YELLOW;
}

/*
 * A command is RED and blocked, and RED (not BLACK) so it stays
 * approvable. Asserted through the gate hook — the entry point the
 * O-Node actually calls.
 */
static void assert_red_blocked(const char *cmd)
{
    virp_trust_tier_t t = zammad_gate_tier(cmd);
    assert(t == VIRP_TIER_RED);
    assert(gate_blocks_at_yellow(t));
    assert(t != VIRP_TIER_BLACK);   /* RED stays approvable */
}

/*
 * A GREEN read, asserted BOTH ways it can be submitted: bare path and
 * "GET <path>". The two must agree — the driver strips the method with
 * the same helper the classifier uses, so a disagreement here would
 * mean the gate judges one byte string and the transport sends another.
 */
static void assert_green(const char *path)
{
    char with_method[600];
    assert(zm_route_path(path) == VIRP_TIER_GREEN);
    assert(zammad_gate_tier(path) == VIRP_TIER_GREEN);
    snprintf(with_method, sizeof(with_method), "GET %s", path);
    assert(zammad_gate_tier(with_method) == VIRP_TIER_GREEN);
    assert(!gate_blocks_at_yellow(zammad_gate_tier(with_method)));
}

/* ========================================================================
 * Guards — method prefix and path form, evaluated before any row
 * ======================================================================== */

static void test_guard_non_get_methods(void)
{
    printf("\n=== Guards — non-GET methods (transport is GET-only) ===\n");

    TEST("POST on a GREEN path -> RED");
    assert_red_blocked("POST /api/v1/tickets");
    PASS();

    TEST("PUT on a GREEN path -> RED");
    assert_red_blocked("PUT /api/v1/tickets/42");
    PASS();

    TEST("PATCH on a GREEN path -> RED");
    assert_red_blocked("PATCH /api/v1/tickets/42");
    PASS();

    TEST("DELETE on a GREEN path -> RED");
    assert_red_blocked("DELETE /api/v1/tickets/42");
    PASS();

    TEST("HEAD -> RED (unlisted method, not a cheap GET)");
    assert_red_blocked("HEAD /api/v1/tickets");
    PASS();

    TEST("OPTIONS -> RED");
    assert_red_blocked("OPTIONS /api/v1/tickets");
    PASS();

    TEST("lowercase 'get' -> RED (method match is case-exact)");
    assert_red_blocked("get /api/v1/tickets");
    PASS();

    TEST("mixed-case 'Get' -> RED");
    assert_red_blocked("Get /api/v1/tickets");
    PASS();

    TEST("GET with no space before the path -> RED");
    assert_red_blocked("GET/api/v1/tickets");
    PASS();

    TEST("tab after GET -> RED (only a space is the separator)");
    assert_red_blocked("GET\t/api/v1/tickets");
    PASS();

    TEST("bare GET with no path -> RED");
    assert_red_blocked("GET ");
    PASS();

    TEST("method smuggled after a GREEN path -> RED");
    assert_red_blocked("GET /api/v1/tickets POST /api/v1/tickets");
    PASS();

    TEST("double method prefix -> RED (only one strip, then form fails)");
    assert_red_blocked("GET GET /api/v1/tickets");
    PASS();

    TEST("CRLF header injection after the path -> RED");
    assert_red_blocked("GET /api/v1/tickets\r\nX-On-Behalf-Of: admin");
    PASS();
}

static void test_guard_path_form(void)
{
    printf("\n=== Guards — rooted-path form ===\n");

    TEST("NULL -> RED");
    assert(zammad_gate_tier(NULL) == VIRP_TIER_RED);
    assert(zm_route_path(NULL) == VIRP_TIER_RED);
    PASS();

    TEST("empty string -> RED");
    assert_red_blocked("");
    PASS();

    TEST("whitespace only -> RED");
    assert_red_blocked("   ");
    PASS();

    TEST("unrooted path -> RED");
    assert_red_blocked("api/v1/tickets");
    PASS();

    TEST("absolute URL -> RED (host is device config, never caller input)");
    assert_red_blocked("https://evil.example/api/v1/tickets");
    PASS();

    TEST("GET + absolute URL -> RED");
    assert_red_blocked("GET https://evil.example/api/v1/tickets");
    PASS();

    TEST("protocol-relative //host -> RED");
    assert_red_blocked("//evil.example/api/v1/tickets");
    PASS();

    TEST("scheme-less authority prefix -> RED");
    assert_red_blocked("GET evil.example/api/v1/tickets");
    PASS();

    TEST("trailing bytes after a GREEN path -> RED");
    assert_red_blocked("/api/v1/tickets extra");
    PASS();

    TEST("trailing space after a GREEN path -> RED (bytes are the row)");
    assert_red_blocked("/api/v1/tickets ");
    PASS();

    TEST("fragment appended -> RED");
    assert_red_blocked("/api/v1/tickets#/api/v1/tickets");
    PASS();

    TEST("path longer than ZM_PATH_MAX -> RED");
    {
        char big[ZM_PATH_MAX + 64];
        size_t base = strlen("/api/v1/tickets/");
        memcpy(big, "/api/v1/tickets/", base);
        memset(big + base, '1', sizeof(big) - base - 1);
        big[sizeof(big) - 1] = '\0';
        assert_red_blocked(big);
    }
    PASS();
}

/* ========================================================================
 * Path traversal
 * ======================================================================== */

static void test_path_traversal(void)
{
    printf("\n=== Path traversal (no dot segment can reach a GREEN row) ===\n");

    TEST("../ escape from the id position -> RED");
    assert_red_blocked("/api/v1/tickets/../../users");
    PASS();

    TEST("dot segment inside the prefix -> RED");
    assert_red_blocked("/api/v1/./tickets");
    PASS();

    TEST("parent segment inside the prefix -> RED");
    assert_red_blocked("/api/v1/../api/v1/tickets");
    PASS();

    TEST("id is '..' -> RED");
    assert_red_blocked("/api/v1/tickets/..");
    PASS();

    TEST("id is '.' -> RED");
    assert_red_blocked("/api/v1/tickets/.");
    PASS();

    TEST("percent-encoded ../ -> RED");
    assert_red_blocked("/api/v1/tickets/%2e%2e/%2e%2e/users");
    PASS();

    TEST("percent-encoded slash after a numeric id -> RED");
    assert_red_blocked("/api/v1/tickets/1%2fmerge");
    PASS();

    TEST("double-encoded traversal -> RED");
    assert_red_blocked("/api/v1/tickets/%252e%252e/users");
    PASS();

    TEST("backslash traversal -> RED");
    assert_red_blocked("/api/v1/tickets\\..\\users");
    PASS();

    TEST("traversal into an admin endpoint via by_ticket -> RED");
    assert_red_blocked("/api/v1/ticket_articles/by_ticket/../../users");
    PASS();

    TEST("traversal in the query string -> RED");
    assert_red_blocked("/api/v1/tickets?page=../../users");
    PASS();
}

/* ========================================================================
 * <id> is digits, and nothing else
 * ======================================================================== */

static void test_non_numeric_id(void)
{
    printf("\n=== <id> — digits only ===\n");

    TEST("alphabetic id -> RED");
    assert_red_blocked("/api/v1/tickets/abc");
    PASS();

    TEST("alphanumeric id -> RED");
    assert_red_blocked("/api/v1/tickets/1a");
    PASS();

    TEST("leading-letter id -> RED");
    assert_red_blocked("/api/v1/tickets/a1");
    PASS();

    TEST("negative id -> RED");
    assert_red_blocked("/api/v1/tickets/-1");
    PASS();

    TEST("signed id -> RED");
    assert_red_blocked("/api/v1/tickets/+1");
    PASS();

    TEST("decimal id -> RED");
    assert_red_blocked("/api/v1/tickets/1.0");
    PASS();

    TEST("hex id -> RED");
    assert_red_blocked("/api/v1/tickets/0x10");
    PASS();

    TEST("space inside the id -> RED");
    assert_red_blocked("/api/v1/tickets/1 2");
    PASS();

    TEST("leading space in the id -> RED");
    assert_red_blocked("/api/v1/tickets/ 1");
    PASS();

    TEST("empty id (trailing slash) -> RED");
    assert_red_blocked("/api/v1/tickets/");
    PASS();

    TEST("wildcard id -> RED");
    assert_red_blocked("/api/v1/tickets/*");
    PASS();

    TEST("SQL-ish id -> RED");
    assert_red_blocked("/api/v1/tickets/1' OR '1'='1");
    PASS();

    TEST("high-byte id -> RED (no locale-dependent digit classes)");
    assert_red_blocked("/api/v1/tickets/\xd9\xa1");
    PASS();

    TEST("sub-resource after a numeric id -> RED");
    assert_red_blocked("/api/v1/tickets/42/merge");
    PASS();

    TEST("second id segment -> RED");
    assert_red_blocked("/api/v1/tickets/42/1");
    PASS();

    TEST("by_ticket with a non-numeric id -> RED");
    assert_red_blocked("/api/v1/ticket_articles/by_ticket/abc");
    PASS();

    TEST("by_ticket with no id -> RED");
    assert_red_blocked("/api/v1/ticket_articles/by_ticket/");
    PASS();

    TEST("by_ticket base without a trailing slash -> RED");
    assert_red_blocked("/api/v1/ticket_articles/by_ticket");
    PASS();

    TEST("id at the digit cap (20) -> GREEN");
    assert_green("/api/v1/tickets/12345678901234567890");
    PASS();

    TEST("id one digit over the cap (21) -> RED");
    assert_red_blocked("/api/v1/tickets/123456789012345678901");
    PASS();
}

/* ========================================================================
 * Query string — page and per_page, digits only, nothing else
 * ======================================================================== */

static void test_query_names(void)
{
    printf("\n=== Query string — unlisted parameter names ===\n");

    TEST("state_id -> RED");
    assert_red_blocked("/api/v1/tickets?state_id=1");
    PASS();

    TEST("query (the search parameter) -> RED");
    assert_red_blocked("/api/v1/tickets?query=password");
    PASS();

    TEST("expand -> RED");
    assert_red_blocked("/api/v1/tickets?expand=true");
    PASS();

    TEST("full -> RED");
    assert_red_blocked("/api/v1/tickets?full=true");
    PASS();

    TEST("order_by -> RED");
    assert_red_blocked("/api/v1/tickets?order_by=id");
    PASS();

    TEST("listed name plus an unlisted one -> RED");
    assert_red_blocked("/api/v1/tickets?page=1&expand=true");
    PASS();

    TEST("unlisted name first -> RED");
    assert_red_blocked("/api/v1/tickets?expand=true&page=1");
    PASS();

    TEST("uppercase Page -> RED (names are case-exact)");
    assert_red_blocked("/api/v1/tickets?Page=1");
    PASS();

    TEST("PER_PAGE -> RED");
    assert_red_blocked("/api/v1/tickets?PER_PAGE=10");
    PASS();

    TEST("prefix creep on a name: page_size -> RED");
    assert_red_blocked("/api/v1/tickets?page_size=10");
    PASS();

    TEST("prefix creep on a name: pages -> RED");
    assert_red_blocked("/api/v1/tickets?pages=1");
    PASS();

    TEST("suffix creep on a name: perpage -> RED");
    assert_red_blocked("/api/v1/tickets?perpage=10");
    PASS();

    TEST("truncated name: per_pag -> RED");
    assert_red_blocked("/api/v1/tickets?per_pag=10");
    PASS();

    TEST("leading-space name -> RED");
    assert_red_blocked("/api/v1/tickets? page=1");
    PASS();

    TEST("array-style name -> RED");
    assert_red_blocked("/api/v1/tickets?page[]=1");
    PASS();

    TEST("bare flag with no '=' -> RED");
    assert_red_blocked("/api/v1/tickets?expand");
    PASS();

    TEST("bare listed name with no '=' -> RED");
    assert_red_blocked("/api/v1/tickets?page");
    PASS();

    TEST("semicolon-separated pairs -> RED (only '&' separates)");
    assert_red_blocked("/api/v1/tickets?page=1;per_page=10");
    PASS();

    TEST("repeated page -> RED (which one counts is the server's answer)");
    assert_red_blocked("/api/v1/tickets?page=1&page=2");
    PASS();

    TEST("repeated per_page -> RED");
    assert_red_blocked("/api/v1/tickets?per_page=10&per_page=500");
    PASS();
}

static void test_query_values(void)
{
    printf("\n=== Query string — non-numeric or malformed values ===\n");

    TEST("alphabetic value -> RED");
    assert_red_blocked("/api/v1/tickets?page=abc");
    PASS();

    TEST("empty value -> RED");
    assert_red_blocked("/api/v1/tickets?page=");
    PASS();

    TEST("negative value -> RED");
    assert_red_blocked("/api/v1/tickets?page=-1");
    PASS();

    TEST("decimal value -> RED");
    assert_red_blocked("/api/v1/tickets?per_page=1.5");
    PASS();

    TEST("exponent value -> RED");
    assert_red_blocked("/api/v1/tickets?per_page=1e3");
    PASS();

    TEST("trailing space in a value -> RED");
    assert_red_blocked("/api/v1/tickets?page=1 ");
    PASS();

    TEST("second '=' in a value -> RED");
    assert_red_blocked("/api/v1/tickets?page=1=2");
    PASS();

    TEST("value over the digit cap -> RED");
    assert_red_blocked("/api/v1/tickets?page=123456789012345678901");
    PASS();

    TEST("bare '?' -> RED");
    assert_red_blocked("/api/v1/tickets?");
    PASS();

    TEST("trailing '&' -> RED");
    assert_red_blocked("/api/v1/tickets?page=1&");
    PASS();

    TEST("empty pair '&&' -> RED");
    assert_red_blocked("/api/v1/tickets?page=1&&per_page=10");
    PASS();

    TEST("leading '&' -> RED");
    assert_red_blocked("/api/v1/tickets?&page=1");
    PASS();

    TEST("second '?' -> RED");
    assert_red_blocked("/api/v1/tickets?page=1?per_page=10");
    PASS();

    TEST("percent-encoded digit -> RED (the bytes are not digits)");
    assert_red_blocked("/api/v1/tickets?page=%31");
    PASS();

    TEST("query on a state/group row is still classified -> RED");
    assert_red_blocked("/api/v1/ticket_states?expand=true");
    PASS();

    TEST("query on an id row is still classified -> RED");
    assert_red_blocked("/api/v1/tickets/42?expand=true");
    PASS();
}

/* ========================================================================
 * Prefix creep — the recorded Wazuh gap
 * ======================================================================== */

static void test_prefix_creep(void)
{
    printf("\n=== Prefix creep — nothing inherits a GREEN row ===\n");

    TEST("/api/v1/tickets_evil -> RED");
    assert_red_blocked("/api/v1/tickets_evil");
    PASS();

    TEST("/api/v1/ticketsX -> RED");
    assert_red_blocked("/api/v1/ticketsX");
    PASS();

    TEST("/api/v1/groups_evil -> RED");
    assert_red_blocked("/api/v1/groups_evil");
    PASS();

    TEST("/api/v1/ticket_states_evil -> RED");
    assert_red_blocked("/api/v1/ticket_states_evil");
    PASS();

    TEST("/api/v1/ticket_articles (the parent collection) -> RED");
    assert_red_blocked("/api/v1/ticket_articles");
    PASS();

    TEST("/api/v1/ticket_articles/1 (article by id, unlisted) -> RED");
    assert_red_blocked("/api/v1/ticket_articles/1");
    PASS();

    TEST("/api/v1/ticket_articles/by_ticket_evil/1 -> RED");
    assert_red_blocked("/api/v1/ticket_articles/by_ticket_evil/1");
    PASS();

    TEST("shortened prefix /api/v1/ticket -> RED");
    assert_red_blocked("/api/v1/ticket");
    PASS();

    TEST("wrong API version /api/v2/tickets -> RED");
    assert_red_blocked("/api/v2/tickets");
    PASS();

    TEST("no version /api/tickets -> RED");
    assert_red_blocked("/api/tickets");
    PASS();

    TEST("doubled slash inside the prefix -> RED");
    assert_red_blocked("/api//v1/tickets");
    PASS();

    TEST("leading doubled slash -> RED");
    assert_red_blocked("//api/v1/tickets");
    PASS();

    TEST("uppercase path -> RED (rows are byte-exact)");
    assert_red_blocked("/API/V1/TICKETS");
    PASS();

    TEST("mixed-case row -> RED");
    assert_red_blocked("/api/v1/Tickets");
    PASS();

    TEST("percent-encoded row spelling -> RED");
    assert_red_blocked("/api/v1/%74ickets");
    PASS();

    TEST("write endpoints are unclassified, so RED");
    assert_red_blocked("/api/v1/users");
    assert_red_blocked("/api/v1/users/1");
    assert_red_blocked("/api/v1/organizations");
    assert_red_blocked("/api/v1/ticket_articles/1/attachment/1/1");
    assert_red_blocked("/api/v1/settings");
    PASS();
}

/* ========================================================================
 * Shell-composition bytes — no shell here, RED anyway
 * ======================================================================== */

static void test_shell_composition_bytes(void)
{
    printf("\n=== Shell-composition bytes (no shell exists; still RED) ===\n");

    TEST("semicolon chain -> RED");
    assert_red_blocked("GET /api/v1/tickets; rm -rf /etc/virp");
    PASS();

    TEST("pipe -> RED");
    assert_red_blocked("GET /api/v1/tickets | tee /tmp/x");
    PASS();

    TEST("ampersand background -> RED");
    assert_red_blocked("GET /api/v1/tickets & wget evil");
    PASS();

    TEST("&& chain -> RED");
    assert_red_blocked("GET /api/v1/tickets && curl evil");
    PASS();

    TEST("backtick substitution -> RED");
    assert_red_blocked("/api/v1/tickets/`id`");
    PASS();

    TEST("$( ) substitution -> RED");
    assert_red_blocked("/api/v1/tickets/$(id)");
    PASS();

    TEST("$VAR expansion -> RED");
    assert_red_blocked("/api/v1/tickets/$TICKET");
    PASS();

    TEST("output redirection -> RED");
    assert_red_blocked("GET /api/v1/tickets > /etc/virp/devices.json");
    PASS();

    TEST("newline command -> RED");
    assert_red_blocked("/api/v1/tickets\nrm -rf /");
    PASS();

    TEST("carriage return -> RED");
    assert_red_blocked("/api/v1/tickets\rGET /api/v1/users");
    PASS();

    TEST("null-adjacent bytes: backslash escape -> RED");
    assert_red_blocked("/api/v1/tickets\\;id");
    PASS();

    TEST("shell bytes inside a query value -> RED");
    assert_red_blocked("/api/v1/tickets?page=1;id");
    PASS();

    TEST("shell bytes as a query name -> RED");
    assert_red_blocked("/api/v1/tickets?`id`=1");
    PASS();
}

/* ========================================================================
 * GREEN — the read set, exactly
 * ======================================================================== */

static void test_green(void)
{
    printf("\n=== GREEN — the autopilot read set, exactly ===\n");

    TEST("/api/v1/tickets");
    assert_green("/api/v1/tickets");
    PASS();

    TEST("/api/v1/tickets/42");
    assert_green("/api/v1/tickets/42");
    PASS();

    TEST("/api/v1/tickets/0 (zero is a digit run)");
    assert_green("/api/v1/tickets/0");
    PASS();

    TEST("/api/v1/ticket_articles/by_ticket/42");
    assert_green("/api/v1/ticket_articles/by_ticket/42");
    PASS();

    TEST("/api/v1/ticket_states");
    assert_green("/api/v1/ticket_states");
    PASS();

    TEST("/api/v1/groups");
    assert_green("/api/v1/groups");
    PASS();

    TEST("page only");
    assert_green("/api/v1/tickets?page=1");
    PASS();

    TEST("per_page only");
    assert_green("/api/v1/tickets?per_page=50");
    PASS();

    TEST("page and per_page");
    assert_green("/api/v1/tickets?page=2&per_page=50");
    PASS();

    TEST("per_page and page (order does not matter)");
    assert_green("/api/v1/tickets?per_page=50&page=2");
    PASS();

    TEST("paging on an id row");
    assert_green("/api/v1/ticket_articles/by_ticket/42?per_page=100");
    PASS();

    TEST("paging on the state catalogue");
    assert_green("/api/v1/ticket_states?page=1");
    PASS();

    TEST("leading spaces before GET are tolerated");
    assert(zammad_gate_tier("  GET /api/v1/tickets") == VIRP_TIER_GREEN);
    PASS();

    TEST("extra spaces between GET and the path are tolerated");
    assert(zammad_gate_tier("GET   /api/v1/tickets") == VIRP_TIER_GREEN);
    PASS();
}

/* ========================================================================
 * Whole-corpus invariants
 * ======================================================================== */

static const char *const corpus[] = {
    /* GREEN */
    "/api/v1/tickets",
    "GET /api/v1/tickets",
    "/api/v1/tickets/42",
    "/api/v1/ticket_articles/by_ticket/42",
    "/api/v1/ticket_states",
    "/api/v1/groups",
    "/api/v1/tickets?page=2&per_page=50",
    /* refused method / form */
    "POST /api/v1/tickets",
    "DELETE /api/v1/tickets/42",
    "get /api/v1/tickets",
    "api/v1/tickets",
    "https://evil.example/api/v1/tickets",
    "",
    /* traversal */
    "/api/v1/tickets/../../users",
    "/api/v1/tickets/%2e%2e/users",
    /* bad id */
    "/api/v1/tickets/abc",
    "/api/v1/tickets/42/merge",
    "/api/v1/tickets/",
    /* bad query */
    "/api/v1/tickets?expand=true",
    "/api/v1/tickets?page=abc",
    "/api/v1/tickets?page=1&page=2",
    "/api/v1/tickets?",
    /* prefix creep */
    "/api/v1/tickets_evil",
    "/api/v2/tickets",
    "/api/v1/users",
    /* shell bytes */
    "GET /api/v1/tickets; rm -rf /etc/virp",
    "/api/v1/tickets/$(id)",
    "/api/v1/tickets\nrm -rf /",
};

static void test_never_returns_black(void)
{
    printf("\n=== Tier hygiene — never BLACK, always wire-carryable ===\n");

    TEST("no command classifies BLACK (every RED stays approvable)");
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        virp_trust_tier_t t = zammad_gate_tier(corpus[i]);
        assert(t != VIRP_TIER_BLACK);
        assert(t == VIRP_TIER_GREEN || t == VIRP_TIER_RED);
    }
    assert(zammad_gate_tier(NULL) != VIRP_TIER_BLACK);
    PASS();

    TEST("every blocked command is RED, never UNCLASSIFIED");
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++) {
        virp_trust_tier_t t = zammad_gate_tier(corpus[i]);
        if (gate_blocks_at_yellow(t))
            assert(t == VIRP_TIER_RED);
    }
    PASS();

    TEST("the table carries no YELLOW row");
    for (size_t i = 0; i < sizeof(corpus) / sizeof(corpus[0]); i++)
        assert(zammad_gate_tier(corpus[i]) != VIRP_TIER_YELLOW);
    PASS();
}

static void test_registration(void)
{
    printf("\n=== Registration ===\n");

    TEST("driver registered with the gate hook wired");
    virp_driver_zammad_init();
    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_ZAMMAD);
    assert(drv != NULL);
    assert(strcmp(drv->name, "zammad") == 0);
    assert(drv->connect && drv->execute && drv->disconnect &&
           drv->detect && drv->health_check);
    assert(drv->route_command == zammad_gate_tier);
    PASS();

    /* virp_driver_register() COPIES the struct into the registry, so the
     * accessor and the lookup are different addresses by design — the
     * invariant is that they describe the same driver. */
    TEST("virp_driver_zammad() describes the registered driver");
    {
        const virp_driver_t *direct = virp_driver_zammad();
        assert(direct != NULL);
        assert(direct->vendor == drv->vendor);
        assert(strcmp(direct->name, drv->name) == 0);
        assert(direct->route_command == drv->route_command);
        assert(direct->execute == drv->execute);
    }
    PASS();
}

static void test_gate_decisions(void)
{
    printf("\n=== Gate-level decisions at threshold YELLOW ===\n");

    TEST("GREEN read passes the gate");
    assert(!gate_blocks_at_yellow(zammad_gate_tier("GET /api/v1/tickets")));
    PASS();

    TEST("unlisted read blocks at the gate");
    assert(gate_blocks_at_yellow(zammad_gate_tier("GET /api/v1/users")));
    PASS();

    TEST("write method blocks at the gate");
    assert(gate_blocks_at_yellow(zammad_gate_tier("POST /api/v1/tickets")));
    PASS();

    TEST("unlisted query parameter blocks at the gate");
    assert(gate_blocks_at_yellow(
        zammad_gate_tier("GET /api/v1/tickets?query=password")));
    PASS();
}


/* ========================================================================
 * TYPED WRITE OPERATION — zammad op=ticket.article.create
 *
 * The write is the only place this driver accepts free-form text and the
 * only place it can issue a non-GET. Both properties get their own
 * bypass suites below.
 * ======================================================================== */

/*
 * The per-identity ceiling, modelled exactly as onode_effective_max_tier()
 * + gate_tier_blocks() compute it for uid 993 (virp-netclaw): the
 * node-wide YELLOW ceiling TIGHTENED to GREEN. This is what makes the
 * write proposal-only for the remote requester, so it is asserted here
 * rather than assumed from the config file.
 */
static int gate_blocks_at_green(virp_trust_tier_t t)
{
    if (t == VIRP_TIER_UNCLASSIFIED) return 1;
    if (t == VIRP_TIER_BLACK)        return 1;
    return t > VIRP_TIER_GREEN;
}

#define WRITE_OK "zammad op=ticket.article.create id=42 body=\"deploy note\""

static void assert_write_red(const char *cmd)
{
    virp_trust_tier_t t = zammad_gate_tier(cmd);
    assert(t == VIRP_TIER_RED);
    assert(gate_blocks_at_yellow(t));
    assert(t != VIRP_TIER_BLACK);      /* stays approvable */
}

static void test_write_row_tier(void)
{
    printf("\n=== Write op — tier and ceiling behaviour ===\n");

    TEST("the one write row classifies YELLOW");
    assert(zammad_gate_tier(WRITE_OK) == VIRP_TIER_YELLOW);
    PASS();

    TEST("YELLOW passes the node-wide ceiling (local operator executes)");
    assert(!gate_blocks_at_yellow(zammad_gate_tier(WRITE_OK)));
    PASS();

    TEST("YELLOW is BLOCKED under the uid-993 GREEN ceiling (proposal-only)");
    assert(gate_blocks_at_green(zammad_gate_tier(WRITE_OK)));
    PASS();

    TEST("reads still pass under the uid-993 GREEN ceiling");
    assert(!gate_blocks_at_green(zammad_gate_tier("GET /api/v1/tickets")));
    PASS();

    TEST("the write row is never BLACK (stays approvable)");
    assert(zammad_gate_tier(WRITE_OK) != VIRP_TIER_BLACK);
    PASS();

    TEST("op table validates (tier declared, only the one POST row)");
    assert(zm_op_table_validate() == 0);
    PASS();

    TEST("op lookup is exact");
    assert(zm_op_lookup(ZM_OP_ARTICLE_CREATE) != NULL);
    assert(zm_op_lookup("ticket.article.creat") == NULL);
    assert(zm_op_lookup("ticket.article.createx") == NULL);
    assert(zm_op_lookup("Ticket.Article.Create") == NULL);
    assert(zm_op_lookup("") == NULL);
    assert(zm_op_lookup(NULL) == NULL);
    PASS();
}

static void test_write_method_smuggling(void)
{
    printf("\n=== Write op — method smuggling ===\n");

    TEST("raw POST path is RED (the write is not reachable as a path)");
    assert_write_red("POST /api/v1/ticket_articles");
    PASS();

    TEST("the write row's own path as a GET read is RED (unlisted row)");
    assert_write_red("/api/v1/ticket_articles");
    PASS();

    TEST("method smuggled as an extra parameter -> RED");
    assert_write_red("zammad op=ticket.article.create id=42 "
                     "body=\"x\" method=POST");
    PASS();

    TEST("method prefix before the operation -> RED");
    assert_write_red("POST zammad op=ticket.article.create id=42 body=\"x\"");
    PASS();

    TEST("GET prefix before the operation -> RED");
    assert_write_red("GET zammad op=ticket.article.create id=42 body=\"x\"");
    PASS();

    TEST("uppercase driver prefix -> RED (byte-exact)");
    assert_write_red("ZAMMAD op=ticket.article.create id=42 body=\"x\"");
    PASS();

    TEST("leading space before the prefix -> RED");
    assert_write_red(" zammad op=ticket.article.create id=42 body=\"x\"");
    PASS();

    TEST("second operation appended -> RED");
    assert_write_red("zammad op=ticket.article.create id=42 body=\"x\" "
                     "op=ticket.article.create");
    PASS();

    TEST("shell separator after a valid operation -> RED");
    assert_write_red("zammad op=ticket.article.create id=42 body=\"x\"; id");
    PASS();

    TEST("unknown write op (state change) -> RED by absence");
    assert_write_red("zammad op=ticket.state.update id=42 body=\"x\"");
    assert_write_red("zammad op=ticket.close id=42 body=\"x\"");
    assert_write_red("zammad op=ticket.assign id=42 body=\"x\"");
    assert_write_red("zammad op=user.create id=42 body=\"x\"");
    assert_write_red("zammad op=group.update id=42 body=\"x\"");
    PASS();

    TEST("method predicate: GET always, POST only for the write row");
    assert(zm_method_is_allowed(ZM_METHOD_GET, false));
    assert(zm_method_is_allowed(ZM_METHOD_GET, true));
    assert(!zm_method_is_allowed(ZM_METHOD_POST, false));
    assert(zm_method_is_allowed(ZM_METHOD_POST, true));
    assert(!zm_method_is_allowed(99, true));
    assert(!zm_method_is_allowed(0, true));
    PASS();
}

static void test_write_body_encoding(void)
{
    printf("\n=== Write op — body encoding violations ===\n");

    TEST("double quote inside the body -> RED (no escape mechanism)");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a\"b\"");
    PASS();

    TEST("backslash -> RED (JSON escape introducer)");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a\\b\"");
    PASS();

    TEST("attempted JSON break-out -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 "
                     "body=\"x\",\"internal\":false,\"y\":\"\"");
    PASS();

    TEST("newline in the body -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a\nb\"");
    PASS();

    TEST("carriage return -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a\rb\"");
    PASS();

    TEST("tab -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a\tb\"");
    PASS();

    TEST("angle brackets -> RED (rendering defence in depth)");
    assert_write_red("zammad op=ticket.article.create id=1 "
                     "body=\"<script>alert(1)</script>\"");
    PASS();

    TEST("non-ASCII UTF-8 -> RED (normalization would break byte identity)");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"caf\xc3\xa9\"");
    PASS();

    TEST("DEL byte -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a\x7f" "b\"");
    PASS();

    TEST("missing opening quote -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=hello");
    PASS();

    TEST("missing closing quote -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"hello");
    PASS();

    TEST("bytes after the closing quote -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"hello\" x");
    PASS();

    TEST("empty body -> RED (an empty note is not a note)");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"\"");
    PASS();

    TEST("body parameter missing entirely -> RED");
    assert_write_red("zammad op=ticket.article.create id=1");
    PASS();

    TEST("parameters out of declared order -> RED (one canonical encoding)");
    assert_write_red("zammad op=ticket.article.create body=\"x\" id=1");
    PASS();

    TEST("duplicate body -> RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"x\" "
                     "body=\"y\"");
    PASS();

    TEST("space run between tokens -> RED");
    assert_write_red("zammad op=ticket.article.create  id=1 body=\"x\"");
    PASS();

    TEST("spaces INSIDE the body are fine (prose, not a separator)");
    assert(zammad_gate_tier("zammad op=ticket.article.create id=1 "
                            "body=\"two  spaces and one sentence.\"")
           == VIRP_TIER_YELLOW);
    PASS();

    TEST("the permitted punctuation really is permitted");
    assert(zammad_gate_tier("zammad op=ticket.article.create id=1 "
                            "body=\"OSPF adj down on frr2 (10.0.10.2) "
                            "@ 19:04 -- see chain seq #531, ~5m.\"")
           == VIRP_TIER_YELLOW);
    PASS();

    TEST("body charset predicate matches the policy exactly");
    assert(zm_is_body_char('a') && zm_is_body_char(' ') &&
           zm_is_body_char('~') && zm_is_body_char('!'));
    assert(!zm_is_body_char('"') && !zm_is_body_char('\\'));
    assert(!zm_is_body_char('<') && !zm_is_body_char('>'));
    assert(!zm_is_body_char('\n') && !zm_is_body_char('\r') &&
           !zm_is_body_char('\t') && !zm_is_body_char(0x00) &&
           !zm_is_body_char(0x1F) && !zm_is_body_char(0x7F) &&
           !zm_is_body_char(0x80) && !zm_is_body_char(0xFF));
    PASS();
}

static void test_write_body_size(void)
{
    printf("\n=== Write op — oversize bodies ===\n");

    char cmd[ZM_COMMAND_MAX + 256];
    char body[ZM_BODY_MAX + 64];

    TEST("body at exactly the cap -> YELLOW");
    memset(body, 'a', ZM_BODY_MAX);
    body[ZM_BODY_MAX] = '\0';
    snprintf(cmd, sizeof(cmd),
             "zammad op=ticket.article.create id=1 body=\"%s\"", body);
    assert(zammad_gate_tier(cmd) == VIRP_TIER_YELLOW);
    PASS();

    TEST("body one byte over the cap -> RED");
    memset(body, 'a', ZM_BODY_MAX + 1);
    body[ZM_BODY_MAX + 1] = '\0';
    snprintf(cmd, sizeof(cmd),
             "zammad op=ticket.article.create id=1 body=\"%s\"", body);
    assert_write_red(cmd);
    PASS();

    TEST("whole command over ZM_COMMAND_MAX -> RED");
    {
        char big[ZM_COMMAND_MAX + 512];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        memcpy(big, "zammad op=ticket.article.create id=1 body=\"", 42);
        big[sizeof(big) - 2] = '"';
        assert_write_red(big);
    }
    PASS();

    TEST("cap is enforced by the CLASSIFIER, not only the transport");
    {
        zm_request_t req;
        const char *reason = NULL;
        memset(body, 'a', ZM_BODY_MAX + 1);
        body[ZM_BODY_MAX + 1] = '\0';
        snprintf(cmd, sizeof(cmd),
                 "zammad op=ticket.article.create id=1 body=\"%s\"", body);
        assert(zm_parse_command(cmd, &req, &reason) == -1);
        assert(reason != NULL);
    }
    PASS();
}

static void test_write_id_injection(void)
{
    printf("\n=== Write op — id injection ===\n");

    TEST("non-numeric id -> RED");
    assert_write_red("zammad op=ticket.article.create id=abc body=\"x\"");
    PASS();

    TEST("alphanumeric id -> RED");
    assert_write_red("zammad op=ticket.article.create id=1a body=\"x\"");
    PASS();

    TEST("negative id -> RED");
    assert_write_red("zammad op=ticket.article.create id=-1 body=\"x\"");
    PASS();

    TEST("empty id -> RED");
    assert_write_red("zammad op=ticket.article.create id= body=\"x\"");
    PASS();

    TEST("leading zero -> RED (two encodings of one ticket, invalid JSON)");
    assert_write_red("zammad op=ticket.article.create id=007 body=\"x\"");
    assert_write_red("zammad op=ticket.article.create id=01 body=\"x\"");
    PASS();

    TEST("bare zero is still valid");
    assert(zammad_gate_tier("zammad op=ticket.article.create id=0 body=\"x\"")
           == VIRP_TIER_YELLOW);
    PASS();

    TEST("JSON injection through the id -> RED");
    assert_write_red("zammad op=ticket.article.create id=1,\"internal\":false "
                     "body=\"x\"");
    PASS();

    TEST("path traversal through the id -> RED");
    assert_write_red("zammad op=ticket.article.create id=../../users "
                     "body=\"x\"");
    PASS();

    TEST("quoted id -> RED");
    assert_write_red("zammad op=ticket.article.create id=\"1\" body=\"x\"");
    PASS();

    TEST("id over the digit cap -> RED");
    assert_write_red("zammad op=ticket.article.create "
                     "id=123456789012345678901 body=\"x\"");
    PASS();

    TEST("id parameter missing -> RED");
    assert_write_red("zammad op=ticket.article.create body=\"x\"");
    PASS();
}

static void test_write_device_scope(void)
{
    printf("\n=== Write op — device scope (ro cannot reach the write) ===\n");

    TEST("read-only device (no write_ops_allow) refuses the op");
    assert(!zm_device_allows_op("", ZM_OP_ARTICLE_CREATE));
    assert(!zm_device_allows_op(NULL, ZM_OP_ARTICLE_CREATE));
    PASS();

    TEST("read-write device naming the op permits it");
    assert(zm_device_allows_op(ZM_OP_ARTICLE_CREATE, ZM_OP_ARTICLE_CREATE));
    PASS();

    TEST("op inside a multi-entry allowlist is found");
    assert(zm_device_allows_op("a.b,ticket.article.create,c.d",
                               ZM_OP_ARTICLE_CREATE));
    assert(zm_device_allows_op("ticket.article.create,other",
                               ZM_OP_ARTICLE_CREATE));
    PASS();

    TEST("prefix of the op id does NOT match");
    assert(!zm_device_allows_op("ticket.article", ZM_OP_ARTICLE_CREATE));
    assert(!zm_device_allows_op("ticket", ZM_OP_ARTICLE_CREATE));
    PASS();

    TEST("superstring of the op id does NOT match");
    assert(!zm_device_allows_op("ticket.article.createX",
                                ZM_OP_ARTICLE_CREATE));
    assert(!zm_device_allows_op("ticket.article.create.more",
                                ZM_OP_ARTICLE_CREATE));
    PASS();

    TEST("stray whitespace is a misconfiguration, not a match");
    assert(!zm_device_allows_op(" ticket.article.create",
                                ZM_OP_ARTICLE_CREATE));
    assert(!zm_device_allows_op("ticket.article.create ",
                                ZM_OP_ARTICLE_CREATE));
    PASS();

    TEST("no wildcard spelling exists");
    assert(!zm_device_allows_op("*", ZM_OP_ARTICLE_CREATE));
    assert(!zm_device_allows_op("all", ZM_OP_ARTICLE_CREATE));
    assert(!zm_device_allows_op("ticket.*", ZM_OP_ARTICLE_CREATE));
    PASS();

    TEST("an unrelated allowlist does not permit this op");
    assert(!zm_device_allows_op("some.other.op", ZM_OP_ARTICLE_CREATE));
    PASS();
}

static void test_write_bytes_identity(void)
{
    printf("\n=== Write op — classified bytes are the transmitted bytes ===\n");

    TEST("the body appears in the JSON verbatim, unescaped, untransformed");
    {
        zm_request_t req;
        const char *reason = NULL;
        const char *cmd = "zammad op=ticket.article.create id=42 "
                          "body=\"OSPF adj down on frr2%3B see seq #531\"";
        char json[ZM_BODY_MAX + 256];

        assert(zm_parse_command(cmd, &req, &reason) == 0);
        assert(reason == NULL);
        assert(strcmp(req.id, "42") == 0);
        assert(strcmp(req.body, "OSPF adj down on frr2; see seq #531") == 0);
        assert(req.body_len == strlen("OSPF adj down on frr2; see seq #531"));

        assert(zm_build_article_json(&req, json, sizeof(json)) == 0);
        assert(strcmp(json,
            "{\"ticket_id\":42,"
            "\"body\":\"OSPF adj down on frr2; see seq #531\","
            "\"type\":\"note\","
            "\"internal\":true,"
            "\"content_type\":\"text/plain\"}") == 0);
    }
    PASS();

    TEST("the operation fixes type/internal/content_type, not the caller");
    {
        zm_request_t req;
        char json[ZM_BODY_MAX + 256];
        assert(zm_parse_command("zammad op=ticket.article.create id=7 "
                                "body=\"x\"", &req, NULL) == 0);
        assert(zm_build_article_json(&req, json, sizeof(json)) == 0);
        assert(strstr(json, "\"internal\":true") != NULL);
        assert(strstr(json, "\"content_type\":\"text/plain\"") != NULL);
        assert(strstr(json, "\"type\":\"note\"") != NULL);
    }
    PASS();

    TEST("a maximum-length body still builds valid JSON (fails closed if not)");
    {
        zm_request_t req;
        char cmd[ZM_COMMAND_MAX + 128];
        char body[ZM_BODY_MAX + 1];
        char json[ZM_BODY_MAX + 256];
        memset(body, 'z', ZM_BODY_MAX);
        body[ZM_BODY_MAX] = '\0';
        snprintf(cmd, sizeof(cmd),
                 "zammad op=ticket.article.create id=1 body=\"%s\"", body);
        assert(zm_parse_command(cmd, &req, NULL) == 0);
        assert(zm_build_article_json(&req, json, sizeof(json)) == 0);
        assert(strstr(json, body) != NULL);
    }
    PASS();

    TEST("json builder fails closed on a short buffer");
    {
        zm_request_t req;
        char small[16];
        assert(zm_parse_command("zammad op=ticket.article.create id=1 "
                                "body=\"hello\"", &req, NULL) == 0);
        assert(zm_build_article_json(&req, small, sizeof(small)) == -1);
    }
    PASS();

    TEST("a refused command yields a teaching reason");
    {
        const char *why = zammad_gate_reason(
            "zammad op=ticket.article.create id=1 body=\"a\nb\"");
        assert(why != NULL);
        why = zammad_gate_reason("zammad op=ticket.state.update id=1 body=\"x\"");
        assert(why != NULL);
    }
    PASS();

    TEST("a GREEN read has no typed-op reason attached");
    assert(zammad_gate_reason("GET /api/v1/tickets") == NULL);
    PASS();
}

static void test_write_does_not_loosen_reads(void)
{
    printf("\n=== Write op — the read path is not loosened ===\n");

    TEST("non-GET on a read path is still RED");
    assert_write_red("POST /api/v1/tickets");
    assert_write_red("PUT /api/v1/tickets/42");
    assert_write_red("DELETE /api/v1/tickets/42");
    PASS();

    TEST("the GREEN read set is unchanged");
    assert(zammad_gate_tier("GET /api/v1/tickets") == VIRP_TIER_GREEN);
    assert(zammad_gate_tier("/api/v1/ticket_states") == VIRP_TIER_GREEN);
    assert(zammad_gate_tier("/api/v1/tickets/42") == VIRP_TIER_GREEN);
    PASS();

    TEST("the driver prefix is not a path and a path is not an operation");
    assert_write_red("zammad /api/v1/tickets");
    assert_write_red("/zammad op=ticket.article.create id=1 body=\"x\"");
    assert_write_red("zammad");
    assert_write_red("zammad ");
    PASS();
}


/*
 * THE ENCODING BOUNDARY.
 *
 * The daemon's ingress filter (virp_command_check_separators) refuses
 * ';' '|' '&' '`' "$(" "${" in any command, before any driver sees it.
 * That rule is right for a command and wrong for prose, so the body
 * travels percent-encoded and is decoded at the transport.
 *
 * This suite pins the boundary from BOTH sides, because the encoding is
 * only worth anything if the two layers agree about which bytes are
 * unsafe: every byte this driver insists on escaping must be a byte
 * ingress would have refused, and the escaped form must survive ingress
 * intact. If the ingress policy ever changes, these assertions fail
 * rather than the encoding quietly becoming wrong.
 */
static void test_write_body_ingress_intersection(void)
{
    printf("\n=== Write op — the encoding boundary (ingress vs driver) ===\n");

    /* The six bytes that must be escaped, and their canonical escapes. */
    static const struct { char raw; const char *esc; } SIX[] = {
        { ';', "%3B" }, { '|', "%7C" }, { '&', "%26" },
        { '`', "%60" }, { '$', "%24" }, { '%', "%25" },
    };

    /*
     * The driver's escape set is NOT identical to the ingress refusal
     * set, and pretending otherwise is how this test first failed. The
     * exact relationship, asserted in three groups:
     */
    TEST("group 1: ; | & ` — ingress refuses a bare occurrence");
    {
        static const char BARE[] = { ';', '|', '&', '`' };
        for (size_t i = 0; i < sizeof(BARE); i++) {
            char probe[64];
            assert(zm_must_escape((unsigned char)BARE[i]));
            snprintf(probe, sizeof(probe), "zammad op=x id=1 body=\"a%cb\"",
                     BARE[i]);
            assert(virp_command_check_separators(probe, NULL, 0) != 0);
        }
    }
    PASS();

    TEST("group 2: $ — ingress refuses only \"$(\" and \"${\", not a bare $");
    {
        /* The driver escapes '$' unconditionally anyway: a per-byte rule
         * is decidable without lookahead and keeps the encoding
         * canonical. A context-dependent rule would make "$x" literal
         * and "$(" escaped — two rules for one byte, two encodings for
         * some bodies. */
        assert(zm_must_escape('$'));
        assert(virp_command_check_separators(
                   "zammad op=x id=1 body=\"a$b\"", NULL, 0) == 0);
        assert(virp_command_check_separators(
                   "zammad op=x id=1 body=\"a$(b\"", NULL, 0) != 0);
        assert(virp_command_check_separators(
                   "zammad op=x id=1 body=\"a${b\"", NULL, 0) != 0);
    }
    PASS();

    TEST("group 3: %% — not an ingress concern; escaped for unambiguity");
    {
        assert(zm_must_escape('%'));
        assert(virp_command_check_separators(
                   "zammad op=x id=1 body=\"a%b\"", NULL, 0) == 0);
        /* but the driver still refuses a literal '%' — it is the escape
         * introducer, so admitting it literally would make "%26"
         * ambiguous between an escape and three characters. */
        assert(zammad_gate_tier("zammad op=ticket.article.create id=1 "
                                "body=\"a%b\"") == VIRP_TIER_RED);
    }
    PASS();

    TEST("raw form is refused by BOTH layers now (ingress AND classifier)");
    for (size_t i = 0; i < sizeof(SIX) / sizeof(SIX[0]); i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd),
                 "zammad op=ticket.article.create id=1 body=\"a%cb\"",
                 SIX[i].raw);
        /* The CLASSIFIER refuses every one of the six as a literal —
         * that is this driver's own rule and does not depend on ingress.
         * Ingress independently refuses four of them (see the groups
         * above); the classifier is what covers '$' and '%'. */
        assert(zammad_gate_tier(cmd) == VIRP_TIER_RED);
        if (SIX[i].raw != '%' && SIX[i].raw != '$')
            assert(virp_command_check_separators(cmd, NULL, 0) != 0);
    }
    PASS();

    TEST("encoded form survives ingress AND classifies YELLOW");
    for (size_t i = 0; i < sizeof(SIX) / sizeof(SIX[0]); i++) {
        char cmd[128], why[160];
        snprintf(cmd, sizeof(cmd),
                 "zammad op=ticket.article.create id=1 body=\"a%sb\"",
                 SIX[i].esc);
        assert(virp_command_check_separators(cmd, why, sizeof(why)) == 0);
        assert(zammad_gate_tier(cmd) == VIRP_TIER_YELLOW);
    }
    PASS();

    TEST("the prose that motivated the encoding now works end to end");
    {
        const char *cmd = "zammad op=ticket.article.create id=42 "
                          "body=\"R%26D spend %2410k%3B see seq #531\"";
        zm_request_t req;
        char why[160];
        assert(virp_command_check_separators(cmd, why, sizeof(why)) == 0);
        assert(zammad_gate_tier(cmd) == VIRP_TIER_YELLOW);
        assert(zm_parse_command(cmd, &req, NULL) == 0);
        assert(strcmp(req.body, "R&D spend $10k; see seq #531") == 0);
    }
    PASS();

    TEST("control bytes are refused literally AND as escapes");
    {
        assert(zammad_gate_tier("zammad op=ticket.article.create id=1 "
                                "body=\"a\nb\"") == VIRP_TIER_RED);
        assert(zammad_gate_tier("zammad op=ticket.article.create id=1 "
                                "body=\"a%0Ab\"") == VIRP_TIER_RED);
        assert(zammad_gate_tier("zammad op=ticket.article.create id=1 "
                                "body=\"a%00b\"") == VIRP_TIER_RED);
        assert(zammad_gate_tier("zammad op=ticket.article.create id=1 "
                                "body=\"a%09b\"") == VIRP_TIER_RED);
    }
    PASS();
}

static void test_write_body_encoding_canonical(void)
{
    printf("\n=== Write op — the encoding is canonical (one body, one string) ===\n");

    TEST("an unnecessary escape is RED (%41 for 'A')");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"%41BC\"");
    PASS();

    TEST("escaping a space is RED (it is a literal byte)");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%20b\"");
    PASS();

    TEST("lowercase hex is RED (%3b and %3B must not both be legal)");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%3bb\"");
    PASS();

    TEST("mixed-case hex is RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%3Bb\" x");
    assert(zammad_gate_tier("zammad op=ticket.article.create id=1 "
                            "body=\"a%2Cb\"") == VIRP_TIER_RED);  /* ',' literal */
    PASS();

    TEST("truncated escape is RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%3\"");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%\"");
    PASS();

    TEST("non-hex escape is RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%GGb\"");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%ZZb\"");
    PASS();

    TEST("forbidden decoded bytes stay forbidden when escaped");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%22b\"");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%5Cb\"");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%3Cb\"");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%3Eb\"");
    PASS();

    TEST("UTF-8 smuggled through escapes is RED");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"caf%C3%A9\"");
    assert_write_red("zammad op=ticket.article.create id=1 body=\"a%FFb\"");
    PASS();

    TEST("double-encoding does not reach a forbidden byte");
    /* "%2522" would decode once to "%22"; it must not decode twice. */
    {
        zm_request_t req;
        assert(zm_parse_command("zammad op=ticket.article.create id=1 "
                                "body=\"a%2522b\"", &req, NULL) == 0);
        assert(strcmp(req.body, "a%22b") == 0);   /* one pass, not two */
    }
    PASS();

    TEST("decode is injective: distinct legal strings, distinct bodies");
    {
        zm_request_t a, b;
        assert(zm_parse_command("zammad op=ticket.article.create id=1 "
                                "body=\"x%26y\"", &a, NULL) == 0);
        assert(zm_parse_command("zammad op=ticket.article.create id=1 "
                                "body=\"x%3By\"", &b, NULL) == 0);
        assert(strcmp(a.body, b.body) != 0);
        assert(strcmp(a.body, "x&y") == 0);
        assert(strcmp(b.body, "x;y") == 0);
    }
    PASS();

    TEST("must_escape and is_body_char agree on the six");
    {
        const char *six = ";|&`$%";
        for (const char *c = six; *c; c++) {
            assert(zm_must_escape((unsigned char)*c));
            assert(zm_is_body_char((unsigned char)*c));  /* legal, once decoded */
        }
        assert(!zm_must_escape('a'));
        assert(!zm_must_escape(' '));
        assert(!zm_must_escape('#'));
        assert(!zm_must_escape('"'));   /* forbidden outright, not escapable */
    }
    PASS();

    TEST("decoder rejects a decoded body over the cap");
    {
        /* 513 decoded bytes, all escaped: 1539 encoded characters. */
        char enc[ZM_BODY_ENC_MAX + 64];
        char out[ZM_BODY_MAX + 8];
        size_t n = 0;
        for (int i = 0; i < ZM_BODY_MAX + 1; i++) {
            memcpy(enc + n, "%26", 3);
            n += 3;
        }
        const char *why = NULL;
        assert(zm_decode_body(enc, n, out, sizeof(out), NULL, &why) == -1);
        assert(why != NULL);
    }
    PASS();

    TEST("decoded body at exactly the cap is accepted");
    {
        char enc[ZM_BODY_ENC_MAX + 8];
        char out[ZM_BODY_MAX + 8];
        size_t n = 0, decoded = 0;
        for (int i = 0; i < ZM_BODY_MAX; i++) { memcpy(enc + n, "%26", 3); n += 3; }
        assert(zm_decode_body(enc, n, out, sizeof(out), &decoded, NULL) == 0);
        assert(decoded == ZM_BODY_MAX);
    }
    PASS();

    TEST("the cap counts DECODED bytes, not typed characters");
    {
        /* 200 escapes = 600 encoded chars but only 200 in the ticket. */
        char cmd[ZM_COMMAND_MAX];
        char enc[ZM_BODY_ENC_MAX];
        size_t n = 0;
        for (int i = 0; i < 200; i++) { memcpy(enc + n, "%26", 3); n += 3; }
        enc[n] = '\0';
        snprintf(cmd, sizeof(cmd),
                 "zammad op=ticket.article.create id=1 body=\"%s\"", enc);
        assert(zammad_gate_tier(cmd) == VIRP_TIER_YELLOW);
    }
    PASS();
}


/*
 * Leading zeros, converged across BOTH command shapes.
 *
 * The typed op rejected "id=007" from the day it was written while the
 * GET row "/api/v1/tickets/007" classified GREEN — the same
 * canonicality argument reaching opposite conclusions inside one
 * driver. These assertions exist so the two cannot drift apart again.
 */
static void test_canonical_numbers_everywhere(void)
{
    printf("\n=== Canonical numbers — no leading zeros, in every shape ===\n");

    TEST("read row: /api/v1/tickets/007 -> RED (was GREEN)");
    assert_red_blocked("/api/v1/tickets/007");
    PASS();

    TEST("read row: /api/v1/tickets/01 -> RED");
    assert_red_blocked("/api/v1/tickets/01");
    PASS();

    TEST("read row: by_ticket/007 -> RED");
    assert_red_blocked("/api/v1/ticket_articles/by_ticket/007");
    PASS();

    TEST("read row: a bare 0 is canonical and stays GREEN");
    assert_green("/api/v1/tickets/0");
    assert_green("/api/v1/ticket_articles/by_ticket/0");
    PASS();

    TEST("read row: ordinary ids are unaffected");
    assert_green("/api/v1/tickets/42");
    assert_green("/api/v1/tickets/1");
    assert_green("/api/v1/tickets/1000");
    PASS();

    TEST("query value: ?page=007 -> RED");
    assert_red_blocked("/api/v1/tickets?page=007");
    PASS();

    TEST("query value: ?per_page=050 -> RED");
    assert_red_blocked("/api/v1/tickets?per_page=050");
    PASS();

    TEST("query value: a bare 0 is canonical");
    assert_green("/api/v1/tickets?page=0");
    PASS();

    TEST("typed op: id=007 -> RED (unchanged, now by the shared rule)");
    assert_write_red("zammad op=ticket.article.create id=007 body=\"x\"");
    PASS();

    TEST("all three shapes agree on 007 and on 7");
    assert(zm_route_path("/api/v1/tickets/007") == VIRP_TIER_RED);
    assert(zm_route_path("/api/v1/tickets?page=007") == VIRP_TIER_RED);
    assert(zammad_gate_tier("zammad op=ticket.article.create id=007 "
                            "body=\"x\"") == VIRP_TIER_RED);
    assert(zm_route_path("/api/v1/tickets/7") == VIRP_TIER_GREEN);
    assert(zm_route_path("/api/v1/tickets?page=7") == VIRP_TIER_GREEN);
    assert(zammad_gate_tier("zammad op=ticket.article.create id=7 "
                            "body=\"x\"") == VIRP_TIER_YELLOW);
    PASS();
}

int main(void)
{
    printf("=== Zammad REST Gate Classifier Tests ===\n");

    test_guard_non_get_methods();
    test_guard_path_form();
    test_path_traversal();
    test_non_numeric_id();
    test_query_names();
    test_query_values();
    test_prefix_creep();
    test_shell_composition_bytes();
    test_green();
    test_never_returns_black();
    test_registration();
    test_gate_decisions();
    test_write_row_tier();
    test_write_method_smuggling();
    test_write_body_encoding();
    test_write_body_size();
    test_write_id_injection();
    test_write_device_scope();
    test_write_bytes_identity();
    test_write_body_ingress_intersection();
    test_write_body_encoding_canonical();
    test_write_does_not_loosen_reads();
    test_canonical_numbers_everywhere();

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
