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

    printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
