/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * PBS typed-operation gate-classifier unit tests (pbs_gate_classify).
 *
 * Modeled on test_driver_linux_gate.c, but the thing under test is
 * structurally different and that difference is the point.
 *
 * The linux classifier has to reason about vendor syntax: it guards
 * separators, anchors an exact `vtysh -c "<arg>"` scaffold, then
 * prefix-matches command words. Prefix matching is where creep lives,
 * so that suite spends most of its effort proving that neighbouring
 * spellings do NOT classify.
 *
 * The PBS classifier has no syntax to reason about. A command is GREEN
 * iff it parses as a canonical typed operation whose id is in a closed
 * table, with exactly the declared parameters. There is no prefix
 * matching anywhere in the path, so prefix creep is not mitigated here
 * — it is absent by construction. These tests exist to prove that claim
 * rather than to assume it.
 *
 * FAIL-CLOSED: anything not exactly GREEN is RED. The table never
 * returns BLACK, so every RED stays approvable through
 * propose/approve/apply.
 */

#include "virp.h"
#include "virp_driver.h"
#include "virp_driver_pbs.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

/*
 * Gate-level mirror of gate_tier_blocks() in virp_onode.c under the
 * deployed threshold (max tier YELLOW). Every RED assertion below also
 * asserts the gate DECISION, so a classifier regression that returns a
 * passing tier fails here rather than on the wire.
 */
static int gate_blocks_at_yellow(virp_trust_tier_t t)
{
    if (t == VIRP_TIER_UNCLASSIFIED) return 1;
    if (t == VIRP_TIER_BLACK)        return 1;
    return t > VIRP_TIER_YELLOW;
}

static void assert_green(const char *cmd)
{
    virp_trust_tier_t t = pbs_gate_tier(cmd);
    assert(t == VIRP_TIER_GREEN);
    assert(!gate_blocks_at_yellow(t));
    assert(pbs_gate_reason(cmd) == NULL);   /* nothing to teach */
}

static void assert_red_blocked(const char *cmd)
{
    virp_trust_tier_t t = pbs_gate_tier(cmd);
    assert(t == VIRP_TIER_RED);
    assert(gate_blocks_at_yellow(t));
    assert(t != VIRP_TIER_BLACK);           /* RED stays approvable */

    /* Every refusal carries teaching text naming the grammar. */
    const char *why = pbs_gate_reason(cmd);
    assert(why != NULL && why[0] != '\0');
}

/* =========================================================================
 * The GREEN set is exactly four operations
 * ========================================================================= */

static void test_green_set(void)
{
    printf("\n=== GREEN — the four v1 read operations ===\n");

    TEST("backup.version.read");
    assert_green("pbs op=backup.version.read");
    PASS();

    TEST("backup.datastore.usage");
    assert_green("pbs op=backup.datastore.usage");
    PASS();

    TEST("backup.snapshots.list store=vault");
    assert_green("pbs op=backup.snapshots.list store=vault");
    PASS();

    TEST("backup.verify.tasks");
    assert_green("pbs op=backup.verify.tasks");
    PASS();

    TEST("no GREEN row carries a rejection reason");
    assert(pbs_gate_reason("pbs op=backup.version.read") == NULL);
    assert(pbs_gate_reason("pbs op=backup.verify.tasks") == NULL);
    PASS();

    TEST("the GREEN set is closed — a fifth plausible read is RED");
    assert_red_blocked("pbs op=backup.datastore.list");
    assert_red_blocked("pbs op=backup.tasks.list");
    assert_red_blocked("pbs op=backup.status.read");
    PASS();
}

/* =========================================================================
 * RED by absence — every write, and everything unenumerated
 * ========================================================================= */

static void test_red_by_absence(void)
{
    printf("\n=== RED by absence — no write op exists at any tier ===\n");

    static const char *const WRITES[] = {
        "pbs op=backup.verify.run",
        "pbs op=backup.snapshots.delete store=vault",
        "pbs op=backup.datastore.prune store=vault",
        "pbs op=backup.datastore.create",
        "pbs op=backup.gc.start store=vault",
        "pbs op=backup.sync.run",
        "pbs op=backup.user.create",
        "pbs op=backup.acl.update",
        "pbs op=backup.token.create",
        "pbs op=backup.datastore.delete store=vault",
    };

    for (size_t i = 0; i < sizeof(WRITES) / sizeof(WRITES[0]); i++) {
        TEST(WRITES[i]);
        assert_red_blocked(WRITES[i]);
        PASS();
    }

    TEST("a RED write is never BLACK (stays approvable)");
    assert(pbs_gate_tier("pbs op=backup.verify.run") != VIRP_TIER_BLACK);
    PASS();
}

/* =========================================================================
 * Prefix creep — absent by construction, asserted anyway
 * ========================================================================= */

static void test_prefix_creep(void)
{
    printf("\n=== Prefix creep — exact match only, both directions ===\n");

    TEST("suffix creep: backup.snapshots.listX");
    assert_red_blocked("pbs op=backup.snapshots.listX store=vault");
    PASS();

    TEST("suffix creep: backup.snapshots.list2");
    assert_red_blocked("pbs op=backup.snapshots.list2 store=vault");
    PASS();

    TEST("suffix creep: backup.version.readable");
    assert_red_blocked("pbs op=backup.version.readable");
    PASS();

    TEST("truncation: backup.snapshots.lis");
    assert_red_blocked("pbs op=backup.snapshots.lis store=vault");
    PASS();

    TEST("truncation: backup.version.rea");
    assert_red_blocked("pbs op=backup.version.rea");
    PASS();

    TEST("truncation to a dotted prefix: backup.snapshots");
    assert_red_blocked("pbs op=backup.snapshots store=vault");
    PASS();

    TEST("dotted extension: backup.version.read.all");
    assert_red_blocked("pbs op=backup.version.read.all");
    PASS();

    TEST("a GREEN id embedded in a longer id does not classify");
    assert_red_blocked("pbs op=x.backup.version.read");
    PASS();

    TEST("separator swap: backup-version-read");
    assert_red_blocked("pbs op=backup-version-read");
    PASS();
}

/* =========================================================================
 * Case and whitespace variants
 * ========================================================================= */

static void test_case_and_whitespace(void)
{
    printf("\n=== Case and whitespace — one canonical encoding only ===\n");

    TEST("uppercase op id");
    assert_red_blocked("pbs op=BACKUP.VERSION.READ");
    PASS();

    TEST("mixed-case op id");
    assert_red_blocked("pbs op=Backup.Version.Read");
    PASS();

    TEST("uppercase 'PBS' literal");
    assert_red_blocked("PBS op=backup.version.read");
    PASS();

    TEST("uppercase key");
    assert_red_blocked("pbs op=backup.snapshots.list STORE=vault");
    PASS();

    TEST("uppercase 'OP' key");
    assert_red_blocked("pbs OP=backup.version.read");
    PASS();

    TEST("double space after the literal");
    assert_red_blocked("pbs  op=backup.version.read");
    PASS();

    TEST("double space before a parameter");
    assert_red_blocked("pbs op=backup.snapshots.list  store=vault");
    PASS();

    TEST("leading space");
    assert_red_blocked(" pbs op=backup.version.read");
    PASS();

    TEST("trailing space");
    assert_red_blocked("pbs op=backup.version.read ");
    PASS();

    TEST("tab instead of space");
    assert_red_blocked("pbs\top=backup.version.read");
    PASS();

    TEST("tab inside the parameter list");
    assert_red_blocked("pbs op=backup.snapshots.list\tstore=vault");
    PASS();

    TEST("trailing newline");
    assert_red_blocked("pbs op=backup.version.read\n");
    PASS();

    TEST("trailing CRLF");
    assert_red_blocked("pbs op=backup.version.read\r\n");
    PASS();
}

/* =========================================================================
 * op-in-param smuggling
 * ========================================================================= */

static void test_op_smuggling(void)
{
    printf("\n=== op-in-param smuggling — a GREEN id cannot carry a RED one ===\n");

    TEST("second op= after a GREEN op");
    assert_red_blocked("pbs op=backup.version.read op=backup.verify.run");
    PASS();

    TEST("RED op first, GREEN op second");
    assert_red_blocked("pbs op=backup.verify.run op=backup.version.read");
    PASS();

    TEST("a RED op id as a parameter value");
    assert_red_blocked("pbs op=backup.version.read store=backup.verify.run");
    PASS();

    /*
     * The one case where the gate is deliberately NOT the whole answer.
     *
     * `store=backup.verify.run` is a well-SHAPED request: the op is a
     * GREEN read and the value satisfies the parameter charset, so the
     * classifier returns GREEN — correctly. A datastore name that looks
     * like an op id is still just a datastore name; it cannot become an
     * operation, because the op is selected by the `op=` token alone and
     * values never reach the op table.
     *
     * What refuses it is the per-device datastore allowlist, enforced in
     * pbs_build_path() before any request is issued. The gate hook's
     * signature is route_command(const char *) — it receives no device
     * context and therefore CANNOT consult a per-device allowlist. That
     * is an architectural boundary, not an oversight, and the split is:
     *
     *     the gate classifies the SHAPE of a request;
     *     the driver enforces the VALUE against device config.
     *
     * Both are asserted here together so the division of labour is
     * visible in one place rather than inferred from two files.
     */
    TEST("op-shaped store value: GREEN by shape, refused by allowlist");
    {
        static const char *const CMD =
            "pbs op=backup.snapshots.list store=backup.verify.run";
        assert_green(CMD);

        char allow_buf[PBS_MAX_DATASTORES][PBS_VALUE_MAX];
        memset(allow_buf, 0, sizeof(allow_buf));
        snprintf(allow_buf[0], PBS_VALUE_MAX, "vault");
        const char (*allow)[PBS_VALUE_MAX] =
            (const char (*)[PBS_VALUE_MAX])allow_buf;

        pbs_request_t req;
        char path[640];
        const char *why = NULL;
        assert(pbs_parse_command(CMD, &req, NULL) == 0);
        assert(pbs_build_path(&req, allow, 1, path, sizeof(path), &why) != 0);
        assert(why != NULL);
    }
    PASS();

    TEST("op= embedded in an otherwise GREEN value");
    assert_red_blocked("pbs op=backup.snapshots.list store=vault op=x");
    PASS();

    TEST("a second op= with no space (single token)");
    assert_red_blocked("pbs op=backup.version.readop=backup.verify.run");
    PASS();
}

/* =========================================================================
 * Parameters
 * ========================================================================= */

static void test_parameters(void)
{
    printf("\n=== Parameters — declared, unique, sorted, complete ===\n");

    TEST("undeclared parameter on a no-param op");
    assert_red_blocked("pbs op=backup.version.read store=vault");
    PASS();

    TEST("undeclared extra parameter alongside a declared one");
    assert_red_blocked("pbs op=backup.snapshots.list store=vault limit=1");
    PASS();

    TEST("caller-supplied typefilter on backup.verify.tasks");
    assert_red_blocked("pbs op=backup.verify.tasks typefilter=all");
    PASS();

    TEST("duplicate parameter");
    assert_red_blocked("pbs op=backup.snapshots.list store=a store=b");
    PASS();

    TEST("keys out of ascending order (before op)");
    assert_red_blocked("pbs op=backup.snapshots.list abc=1 store=vault");
    PASS();

    TEST("keys out of ascending order (after a param)");
    assert_red_blocked("pbs op=backup.snapshots.list store=vault abc=1");
    PASS();

    TEST("required parameter missing");
    assert_red_blocked("pbs op=backup.snapshots.list");
    PASS();

    TEST("empty parameter value");
    assert_red_blocked("pbs op=backup.snapshots.list store=");
    PASS();

    TEST("bare token with no '='");
    assert_red_blocked("pbs op=backup.version.read extra");
    PASS();
}

/* =========================================================================
 * The daemon-boundary separator check covers this path too
 *
 * virp_onode.c rejects separator-carrying commands at ingress, BEFORE any
 * driver classifier runs. That check is shared, so it already covers PBS
 * — but "already covered" is exactly the kind of claim that rots. These
 * assertions pin both halves: the boundary rejects the command, AND the
 * PBS classifier independently REDs it. Neither is load-bearing alone.
 * ========================================================================= */

static void test_separator_boundary(void)
{
    printf("\n=== Daemon-boundary separator policy covers PBS ===\n");

    static const char *const SEPARATORS[] = {
        "pbs op=backup.version.read; rm -rf /",
        "pbs op=backup.version.read | cat /etc/shadow",
        "pbs op=backup.version.read & sleep 60",
        "pbs op=backup.snapshots.list store=`id`",
        "pbs op=backup.snapshots.list store=$(id)",
        "pbs op=backup.snapshots.list store=${HOME}",
        "pbs op=backup.version.read\nop=backup.verify.run",
        "pbs op=backup.version.read\r\nX-Injected: 1",
        "pbs op=backup.version.read\top=backup.verify.run",
    };

    for (size_t i = 0; i < sizeof(SEPARATORS) / sizeof(SEPARATORS[0]); i++) {
        char why[256];

        TEST("daemon boundary rejects, and PBS classifier REDs");
        /* Half one: the shared ingress check refuses it. */
        assert(virp_command_check_separators(SEPARATORS[i], why,
                                             sizeof(why)) != 0);
        assert(why[0] != '\0');
        /* Half two: the driver classifier refuses it independently, so
         * the driver is safe even if reached by another path. */
        assert_red_blocked(SEPARATORS[i]);
        PASS();
    }

    TEST("a canonical GREEN command passes the boundary check");
    assert(virp_command_check_separators("pbs op=backup.version.read",
                                         NULL, 0) == 0);
    assert(virp_command_check_separators(
        "pbs op=backup.snapshots.list store=vault", NULL, 0) == 0);
    PASS();

    TEST("control bytes are rendered escaped, never raw, in the reason");
    {
        char why[256];
        assert(virp_command_check_separators(
            "pbs op=backup.version.read\nx", why, sizeof(why)) != 0);
        assert(strstr(why, "\\x0a") != NULL);
        assert(strchr(why, '\n') == NULL);
    }
    PASS();
}

/* =========================================================================
 * Degenerate input
 * ========================================================================= */

static void test_degenerate(void)
{
    printf("\n=== Degenerate input — fail closed ===\n");

    TEST("NULL command -> RED");
    assert(pbs_gate_tier(NULL) == VIRP_TIER_RED);
    PASS();

    TEST("empty command -> RED");
    assert_red_blocked("");
    PASS();

    TEST("bare 'pbs' -> RED");
    assert_red_blocked("pbs");
    PASS();

    TEST("a raw API path -> RED");
    assert_red_blocked("/api2/json/version");
    PASS();

    TEST("a raw API path with the pbs literal -> RED");
    assert_red_blocked("pbs /api2/json/version");
    PASS();

    TEST("an HTTP request line -> RED");
    assert_red_blocked("GET /api2/json/version HTTP/1.1");
    PASS();

    TEST("a full URL -> RED");
    assert_red_blocked("https://pbs.local:8007/api2/json/version");
    PASS();

    TEST("another driver's command shape -> RED");
    assert_red_blocked("vtysh -c \"show ip ospf neighbor\"");
    PASS();

    TEST("classify and tier hooks agree");
    {
        static const char *const CASES[] = {
            "pbs op=backup.version.read",
            "pbs op=backup.verify.run",
            "pbs op=backup.snapshots.list store=vault",
            "garbage",
        };
        for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) {
            const char *why = NULL;
            virp_trust_tier_t a = pbs_gate_classify(CASES[i], &why);
            virp_trust_tier_t b = pbs_gate_tier(CASES[i]);
            assert(a == b);
            /* reason is set iff the command was refused */
            assert((why != NULL) == (a != VIRP_TIER_GREEN));
        }
    }
    PASS();
}

int main(void)
{
    printf("=== PBS typed-operation gate classifier tests ===\n");

    test_green_set();
    test_red_by_absence();
    test_prefix_creep();
    test_case_and_whitespace();
    test_op_smuggling();
    test_parameters();
    test_separator_boundary();
    test_degenerate();

    printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
