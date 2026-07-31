/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * PBS typed-operation driver unit tests.
 *
 * Entirely offline: the grammar parser, op table, URL derivation,
 * fingerprint parsing, method predicate and device precheck are all pure
 * functions. Nothing here opens a socket, so this suite carries no
 * VIRP_LIVE_* guard and runs in the default battery.
 *
 * DIFFERENTIAL TESTING (house style)
 * ----------------------------------
 * A negative test that passes against a permissive implementation is not
 * testing anything. Every refusal below is therefore asserted TWICE:
 *
 *   1. the real parser must REFUSE it, and
 *   2. `broken_parse()` — a deliberately broken variant that omits the
 *      charset, ordering, duplicate, declared-parameter and table checks
 *      — must ACCEPT it.
 *
 * (2) is what gives (1) teeth: if a guard were removed from the real
 * parser it would start behaving like broken_parse(), and the
 * corresponding assertion in (1) would fail. A negative case that both
 * implementations reject proves only that the input is degenerate, so
 * those few are marked explicitly with refuse_only().
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

/* =========================================================================
 * The deliberately broken variant
 *
 * This is what a reasonable-looking, wrong implementation of the same
 * grammar looks like: find "op=", take the id, split the rest on spaces
 * into key=value pairs. No charset validation, no ordering rule, no
 * duplicate detection, no check that a parameter is declared for the op,
 * no check that the op is in the table at all. It accepts everything the
 * real parser is supposed to refuse.
 * ========================================================================= */

static int broken_parse(const char *command, pbs_request_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!command) return -1;

    const char *p = strstr(command, "op=");
    if (!p) return -1;
    p += 3;

    char id[128];
    size_t n = 0;
    while (*p && *p != ' ' && n + 1 < sizeof(id)) id[n++] = *p++;
    id[n] = '\0';
    if (n == 0) return -1;

    out->op = pbs_op_lookup(id);   /* may be NULL — the broken variant
                                    * does not care whether the op exists */

    while (*p) {
        while (*p == ' ') p++;
        if (!*p) break;

        char k[128], v[128];
        size_t kn = 0, vn = 0;
        while (*p && *p != '=' && *p != ' ' && kn + 1 < sizeof(k)) k[kn++] = *p++;
        k[kn] = '\0';
        if (*p == '=') p++;
        while (*p && *p != ' ' && vn + 1 < sizeof(v)) v[vn++] = *p++;
        v[vn] = '\0';

        if (kn > 0 && out->nparams < PBS_MAX_PARAMS) {
            snprintf(out->keys[out->nparams], PBS_KEY_MAX,
                     "%.*s", PBS_KEY_MAX - 1, k);
            snprintf(out->values[out->nparams], PBS_VALUE_MAX,
                     "%.*s", PBS_VALUE_MAX - 1, v);
            out->nparams++;
        }
    }
    return 0;
}

/* Real parser refuses (with a reason) AND the broken variant accepts. */
static void refuse_diff(const char *cmd)
{
    pbs_request_t req;
    const char *reason = NULL;

    assert(pbs_parse_command(cmd, &req, &reason) != 0);
    assert(reason != NULL && reason[0] != '\0');

    pbs_request_t loose;
    assert(broken_parse(cmd, &loose) == 0);   /* the differential teeth */
}

/* Real parser refuses; the input is degenerate enough that the broken
 * variant refuses too, so this case carries no differential signal. */
static void refuse_only(const char *cmd)
{
    pbs_request_t req;
    const char *reason = NULL;
    assert(pbs_parse_command(cmd, &req, &reason) != 0);
    assert(reason != NULL && reason[0] != '\0');
}

static void accept_op(const char *cmd, const char *expect_id)
{
    pbs_request_t req;
    const char *reason = NULL;
    assert(pbs_parse_command(cmd, &req, &reason) == 0);
    assert(reason == NULL);
    assert(req.op != NULL);
    assert(strcmp(req.op->id, expect_id) == 0);
}

/* =========================================================================
 * Grammar — positive
 * ========================================================================= */

static void test_grammar_accepts(void)
{
    printf("\n=== Grammar — the four v1 operations parse ===\n");

    TEST("op=backup.version.read");
    accept_op("pbs op=backup.version.read", "backup.version.read");
    PASS();

    TEST("op=backup.datastore.usage");
    accept_op("pbs op=backup.datastore.usage", "backup.datastore.usage");
    PASS();

    TEST("op=backup.snapshots.list store=vault");
    accept_op("pbs op=backup.snapshots.list store=vault",
              "backup.snapshots.list");
    PASS();

    TEST("op=backup.verify.tasks");
    accept_op("pbs op=backup.verify.tasks", "backup.verify.tasks");
    PASS();

    TEST("parameter value is captured verbatim");
    {
        pbs_request_t req;
        assert(pbs_parse_command("pbs op=backup.snapshots.list store=vault-01",
                                 &req, NULL) == 0);
        assert(req.nparams == 1);
        assert(strcmp(req.keys[0], "store") == 0);
        assert(strcmp(req.values[0], "vault-01") == 0);
    }
    PASS();
}

/* =========================================================================
 * Grammar — the op table is closed
 * ========================================================================= */

static void test_unknown_ops(void)
{
    printf("\n=== Unknown operations — RED by absence, no write ops exist ===\n");

    TEST("op=backup.verify.run (a write op) -> refused");
    refuse_diff("pbs op=backup.verify.run");
    PASS();

    TEST("op=backup.datastore.prune -> refused");
    refuse_diff("pbs op=backup.datastore.prune");
    PASS();

    TEST("op=backup.snapshots.delete store=vault -> refused");
    refuse_diff("pbs op=backup.snapshots.delete store=vault");
    PASS();

    TEST("prefix creep: op=backup.snapshots.listX -> refused");
    refuse_diff("pbs op=backup.snapshots.listX store=vault");
    PASS();

    TEST("prefix creep: op=backup.version.readX -> refused");
    refuse_diff("pbs op=backup.version.readX");
    PASS();

    TEST("truncation: op=backup.snapshots.lis -> refused");
    refuse_diff("pbs op=backup.snapshots.lis store=vault");
    PASS();

    TEST("empty op id -> refused");
    refuse_only("pbs op=");
    PASS();
}

/* =========================================================================
 * Grammar — parameters
 * ========================================================================= */

static void test_parameters(void)
{
    printf("\n=== Parameters — declared, unique, sorted, complete ===\n");

    TEST("undeclared parameter on a no-param op -> refused");
    refuse_diff("pbs op=backup.version.read store=vault");
    PASS();

    TEST("undeclared parameter alongside a declared one -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=vault zzz=1");
    PASS();

    TEST("duplicate parameter -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=a store=b");
    PASS();

    TEST("op-in-param smuggling: a second op= -> refused");
    refuse_diff("pbs op=backup.version.read op=backup.verify.run");
    PASS();

    TEST("key sorting before op (abc < op) -> refused");
    refuse_diff("pbs op=backup.snapshots.list abc=1 store=vault");
    PASS();

    TEST("key sorting after a param (abc < store) -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=vault abc=1");
    PASS();

    TEST("required parameter missing -> refused");
    refuse_diff("pbs op=backup.snapshots.list");
    PASS();

    TEST("empty parameter value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=");
    PASS();

    TEST("bare token with no '=' -> refused");
    refuse_diff("pbs op=backup.version.read extra");
    PASS();
}

/* =========================================================================
 * Grammar — injection and syntax smuggling
 * ========================================================================= */

static void test_injection(void)
{
    printf("\n=== Injection — separators, URLs, headers, quoting ===\n");

    TEST("semicolon command chain -> refused");
    refuse_diff("pbs op=backup.version.read; rm -rf /");
    PASS();

    TEST("pipe -> refused");
    refuse_diff("pbs op=backup.version.read | cat /etc/shadow");
    PASS();

    TEST("backtick substitution -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=`id`");
    PASS();

    TEST("shell expansion $( ) -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=$(id)");
    PASS();

    TEST("URL fragment in a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=vault#frag");
    PASS();

    TEST("query smuggling in a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=vault?typefilter=all");
    PASS();

    TEST("path traversal in a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=../../../etc/passwd");
    PASS();

    TEST("path segment in a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=vault/snapshots");
    PASS();

    TEST("percent-escape in a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=vault%2f");
    PASS();

    TEST("CRLF header injection in a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=v\r\nX-Injected: 1");
    PASS();

    TEST("bare LF in a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=v\nX-Injected: 1");
    PASS();

    TEST("tab as a separator -> refused");
    refuse_diff("pbs\top=backup.version.read");
    PASS();

    TEST("NUL-adjacent control byte in a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store=v\x01x");
    PASS();

    TEST("double quotes around the op id -> refused");
    refuse_diff("pbs op=\"backup.version.read\"");
    PASS();

    TEST("single quotes around a value -> refused");
    refuse_diff("pbs op=backup.snapshots.list store='vault'");
    PASS();

    TEST("absolute URL as the op id -> refused");
    refuse_diff("pbs op=https://pbs.local/api2/json/version");
    PASS();

    TEST("raw API path instead of a typed op -> refused");
    refuse_only("pbs /api2/json/version");
    PASS();

    TEST("HTTP verb prefix -> refused");
    refuse_only("GET /api2/json/version");
    PASS();
}

/* =========================================================================
 * Grammar — canonical form (one encoding per request)
 * ========================================================================= */

static void test_canonical_form(void)
{
    printf("\n=== Canonical form — exactly one encoding per request ===\n");

    TEST("double space between tokens -> refused");
    refuse_diff("pbs  op=backup.version.read");
    PASS();

    TEST("double space before a parameter -> refused");
    refuse_diff("pbs op=backup.snapshots.list  store=vault");
    PASS();

    TEST("trailing space -> refused");
    refuse_diff("pbs op=backup.version.read ");
    PASS();

    TEST("leading space -> refused");
    refuse_diff(" pbs op=backup.version.read");
    PASS();

    TEST("missing 'pbs' prefix -> refused");
    refuse_diff("op=backup.version.read");
    PASS();

    TEST("wrong prefix -> refused");
    refuse_diff("pve op=backup.version.read");
    PASS();

    TEST("prefix creep on the literal: 'pbsx' -> refused");
    refuse_diff("pbsx op=backup.version.read");
    PASS();

    TEST("uppercase op id -> refused (no case folding)");
    refuse_diff("pbs op=Backup.Version.Read");
    PASS();

    TEST("uppercase key -> refused");
    refuse_diff("pbs op=backup.snapshots.list STORE=vault");
    PASS();

    TEST("malformed op id: leading dot -> refused");
    refuse_diff("pbs op=.backup.version.read");
    PASS();

    TEST("malformed op id: trailing dot -> refused");
    refuse_diff("pbs op=backup.version.read.");
    PASS();

    TEST("malformed op id: empty segment -> refused");
    refuse_diff("pbs op=backup..version.read");
    PASS();

    TEST("empty command -> refused");
    refuse_only("");
    PASS();

    TEST("bare 'pbs' -> refused");
    refuse_only("pbs");
    PASS();

    TEST("overlong command -> refused");
    {
        char big[PBS_COMMAND_MAX + 64];
        memset(big, 'a', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        memcpy(big, "pbs op=backup.snapshots.list store=", 35);
        refuse_only(big);
    }
    PASS();
}

/* =========================================================================
 * URL derivation — from the table, never from input
 * ========================================================================= */

static void test_url_derivation(void)
{
    printf("\n=== URL derivation — method and path come from the table ===\n");

    char allow_buf[PBS_MAX_DATASTORES][PBS_VALUE_MAX];
    memset(allow_buf, 0, sizeof(allow_buf));
    snprintf(allow_buf[0], PBS_VALUE_MAX, "vault");
    snprintf(allow_buf[1], PBS_VALUE_MAX, "vault-01");
    /* Adding const to a pointer-to-array is not implicit in ISO C
     * before C2X, so it is spelled out here as it is in the driver. */
    const char (*allow)[PBS_VALUE_MAX] =
        (const char (*)[PBS_VALUE_MAX])allow_buf;
    size_t allow_n = 2;

    char path[640];
    pbs_request_t req;
    const char *reason = NULL;

    TEST("backup.version.read -> /api2/json/version");
    assert(pbs_parse_command("pbs op=backup.version.read", &req, NULL) == 0);
    assert(pbs_build_path(&req, allow, allow_n, path, sizeof(path), NULL) == 0);
    assert(strcmp(path, "/api2/json/version") == 0);
    PASS();

    TEST("backup.datastore.usage -> /api2/json/status/datastore-usage");
    assert(pbs_parse_command("pbs op=backup.datastore.usage", &req, NULL) == 0);
    assert(pbs_build_path(&req, allow, allow_n, path, sizeof(path), NULL) == 0);
    assert(strcmp(path, "/api2/json/status/datastore-usage") == 0);
    PASS();

    TEST("backup.snapshots.list store=vault -> substituted path");
    assert(pbs_parse_command("pbs op=backup.snapshots.list store=vault",
                             &req, NULL) == 0);
    assert(pbs_build_path(&req, allow, allow_n, path, sizeof(path), NULL) == 0);
    assert(strcmp(path, "/api2/json/admin/datastore/vault/snapshots") == 0);
    PASS();

    TEST("backup.verify.tasks -> path + hardcoded typefilter");
    assert(pbs_parse_command("pbs op=backup.verify.tasks", &req, NULL) == 0);
    assert(pbs_build_path(&req, allow, allow_n, path, sizeof(path), NULL) == 0);
    assert(strcmp(path, "/api2/json/nodes/localhost/tasks?typefilter=verify") == 0);
    PASS();

    TEST("the typefilter is not caller-settable");
    refuse_diff("pbs op=backup.verify.tasks typefilter=all");
    PASS();

    TEST("datastore outside the allowlist -> refused");
    assert(pbs_parse_command("pbs op=backup.snapshots.list store=secret",
                             &req, NULL) == 0);
    assert(pbs_build_path(&req, allow, allow_n, path, sizeof(path),
                          &reason) != 0);
    assert(reason != NULL);
    PASS();

    TEST("no allowlist configured -> refused");
    assert(pbs_parse_command("pbs op=backup.snapshots.list store=vault",
                             &req, NULL) == 0);
    assert(pbs_build_path(&req, NULL, 0, path, sizeof(path), &reason) != 0);
    assert(reason != NULL);
    PASS();

    TEST("allowlist match is exact, not prefix");
    assert(pbs_parse_command("pbs op=backup.snapshots.list store=vault-0",
                             &req, NULL) == 0);
    assert(pbs_build_path(&req, allow, allow_n, path, sizeof(path),
                          &reason) != 0);
    PASS();

    TEST("derived path never contains an unsubstituted placeholder");
    {
        const char *ids[] = { "backup.version.read", "backup.datastore.usage",
                              "backup.verify.tasks" };
        for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            char cmd[128];
            snprintf(cmd, sizeof(cmd), "pbs op=%s", ids[i]);
            assert(pbs_parse_command(cmd, &req, NULL) == 0);
            assert(pbs_build_path(&req, allow, allow_n, path,
                                  sizeof(path), NULL) == 0);
            assert(strstr(path, "{") == NULL);
        }
        assert(pbs_parse_command("pbs op=backup.snapshots.list store=vault",
                                 &req, NULL) == 0);
        assert(pbs_build_path(&req, allow, allow_n, path,
                              sizeof(path), NULL) == 0);
        assert(strstr(path, "{") == NULL);
    }
    PASS();
}

/* =========================================================================
 * Method — no write operation exists at any tier
 * ========================================================================= */

static void test_method(void)
{
    printf("\n=== Method — GET, and nothing else, is issuable ===\n");

    TEST("GET is allowed");
    assert(pbs_method_is_allowed(PBS_METHOD_GET));
    PASS();

    TEST("every other method value is refused by the transport predicate");
    for (int m = -8; m <= 16; m++) {
        if (m == PBS_METHOD_GET) continue;
        assert(!pbs_method_is_allowed(m));
    }
    PASS();

    TEST("every v1 table row is GET");
    {
        const char *ids[] = { "backup.version.read", "backup.datastore.usage",
                              "backup.snapshots.list", "backup.verify.tasks" };
        for (size_t i = 0; i < sizeof(ids) / sizeof(ids[0]); i++) {
            const pbs_op_t *op = pbs_op_lookup(ids[i]);
            assert(op != NULL);
            assert(op->method == PBS_METHOD_GET);
            assert(pbs_method_is_allowed(op->method));
        }
    }
    PASS();

    TEST("op table lookup is exact");
    assert(pbs_op_lookup("backup.version.rea") == NULL);
    assert(pbs_op_lookup("backup.version.readX") == NULL);
    assert(pbs_op_lookup("BACKUP.VERSION.READ") == NULL);
    assert(pbs_op_lookup("") == NULL);
    assert(pbs_op_lookup(NULL) == NULL);
    PASS();
}

/* =========================================================================
 * Certificate pinning
 * ========================================================================= */

static void test_fingerprint(void)
{
    printf("\n=== TLS fingerprint parsing ===\n");

    unsigned char a[PBS_FINGERPRINT_BYTES], b[PBS_FINGERPRINT_BYTES];

    static const char COLON_UPPER[] =
        "5A:9F:1C:2E:4B:7D:80:11:22:33:44:55:66:77:88:99:"
        "AA:BB:CC:DD:EE:FF:00:12:34:56:78:9A:BC:DE:F0:11";
    static const char BARE_LOWER[] =
        "5a9f1c2e4b7d80112233445566778899"
        "aabbccddeeff0012 3456789abcdef011";   /* space is NOT tolerated */
    static const char BARE_LOWER_OK[] =
        "5a9f1c2e4b7d80112233445566778899aabbccddeeff00123456789abcdef011";

    TEST("colon-separated uppercase parses");
    assert(pbs_parse_fingerprint(COLON_UPPER, a) == 0);
    PASS();

    TEST("bare lowercase parses to the same 32 bytes");
    assert(pbs_parse_fingerprint(BARE_LOWER_OK, b) == 0);
    assert(memcmp(a, b, sizeof(a)) == 0);
    PASS();

    TEST("embedded space -> refused");
    assert(pbs_parse_fingerprint(BARE_LOWER, a) != 0);
    PASS();

    TEST("too short -> refused");
    assert(pbs_parse_fingerprint("5a9f1c2e", a) != 0);
    PASS();

    TEST("too long -> refused");
    assert(pbs_parse_fingerprint(
        "5a9f1c2e4b7d80112233445566778899aabbccddeeff00123456789abcdef011ff",
        a) != 0);
    PASS();

    TEST("odd digit count -> refused");
    assert(pbs_parse_fingerprint(
        "5a9f1c2e4b7d80112233445566778899aabbccddeeff00123456789abcdef01",
        a) != 0);
    PASS();

    TEST("non-hex byte -> refused");
    assert(pbs_parse_fingerprint(
        "5a9f1c2e4b7d80112233445566778899aabbccddeeff00123456789abcdefzz",
        a) != 0);
    PASS();

    TEST("empty -> refused");
    assert(pbs_parse_fingerprint("", a) != 0);
    PASS();

    TEST("NULL -> refused");
    assert(pbs_parse_fingerprint(NULL, a) != 0);
    PASS();

    TEST("an SHA-1 length fingerprint -> refused");
    assert(pbs_parse_fingerprint("5a9f1c2e4b7d80112233445566778899aabbccdd",
                                 a) != 0);
    PASS();
}

/* =========================================================================
 * Device preconditions — the pin is mandatory
 * ========================================================================= */

static virp_device_t good_device(void)
{
    virp_device_t d;
    memset(&d, 0, sizeof(d));
    snprintf(d.hostname, sizeof(d.hostname), "pbs01");
    snprintf(d.host, sizeof(d.host), "10.0.10.99");
    d.vendor = VIRP_VENDOR_PBS;
    d.api_port = PBS_DEFAULT_PORT;
    snprintf(d.username, sizeof(d.username), "virp-ro@pbs!virp");
    snprintf(d.api_token, sizeof(d.api_token),
             "00000000-1111-2222-3333-444444444444");
    snprintf(d.tls_fingerprint, sizeof(d.tls_fingerprint),
             "5a9f1c2e4b7d80112233445566778899"
             "aabbccddeeff00123456789abcdef011");
    snprintf(d.datastore_allow, sizeof(d.datastore_allow), "vault,vault-01");
    return d;
}

static void test_device_precheck(void)
{
    printf("\n=== Device preconditions — no pin, no connection ===\n");

    unsigned char pin[PBS_FINGERPRINT_BYTES];
    const char *reason = NULL;

    TEST("a fully configured device passes");
    {
        virp_device_t d = good_device();
        assert(pbs_device_precheck(&d, pin, &reason) == 0);
        assert(reason == NULL);
    }
    PASS();

    TEST("missing tls_fingerprint -> refused");
    {
        virp_device_t d = good_device();
        d.tls_fingerprint[0] = '\0';
        assert(pbs_device_precheck(&d, pin, &reason) != 0);
        assert(reason != NULL);
    }
    PASS();

    TEST("malformed tls_fingerprint -> refused");
    {
        virp_device_t d = good_device();
        snprintf(d.tls_fingerprint, sizeof(d.tls_fingerprint), "not-a-hash");
        assert(pbs_device_precheck(&d, pin, &reason) != 0);
        assert(reason != NULL);
    }
    PASS();

    TEST("SHA-1 length fingerprint -> refused");
    {
        virp_device_t d = good_device();
        snprintf(d.tls_fingerprint, sizeof(d.tls_fingerprint),
                 "5a9f1c2e4b7d80112233445566778899aabbccdd");
        assert(pbs_device_precheck(&d, pin, &reason) != 0);
    }
    PASS();

    TEST("missing api_token -> refused");
    {
        virp_device_t d = good_device();
        d.api_token[0] = '\0';
        assert(pbs_device_precheck(&d, pin, &reason) != 0);
    }
    PASS();

    TEST("missing username (token id) -> refused");
    {
        virp_device_t d = good_device();
        d.username[0] = '\0';
        assert(pbs_device_precheck(&d, pin, &reason) != 0);
    }
    PASS();

    TEST("NULL device -> refused");
    assert(pbs_device_precheck(NULL, pin, &reason) != 0);
    PASS();

    TEST("the parsed pin matches the configured fingerprint");
    {
        virp_device_t d = good_device();
        unsigned char expect[PBS_FINGERPRINT_BYTES];
        assert(pbs_parse_fingerprint(d.tls_fingerprint, expect) == 0);
        assert(pbs_device_precheck(&d, pin, &reason) == 0);
        assert(memcmp(pin, expect, sizeof(pin)) == 0);
    }
    PASS();
}

/* =========================================================================
 * The differential harness must itself be honest
 * ========================================================================= */

static void test_differential_harness(void)
{
    printf("\n=== Differential harness sanity ===\n");

    TEST("the broken variant accepts what the real parser accepts");
    {
        pbs_request_t loose;
        assert(broken_parse("pbs op=backup.version.read", &loose) == 0);
        assert(loose.op != NULL);
    }
    PASS();

    TEST("the broken variant accepts an unknown op (that is its flaw)");
    {
        pbs_request_t loose;
        assert(broken_parse("pbs op=backup.verify.run", &loose) == 0);
        assert(loose.op == NULL);   /* accepted despite not being in the table */
    }
    PASS();

    TEST("the broken variant accepts injected bytes (that is its flaw)");
    {
        pbs_request_t loose;
        assert(broken_parse("pbs op=backup.snapshots.list "
                            "store=../../etc/passwd", &loose) == 0);
    }
    PASS();
}

int main(void)
{
    printf("=== PBS typed-operation driver tests ===\n");

    test_grammar_accepts();
    test_unknown_ops();
    test_parameters();
    test_injection();
    test_canonical_form();
    test_url_derivation();
    test_method();
    test_fingerprint();
    test_device_precheck();
    test_differential_harness();

    printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
