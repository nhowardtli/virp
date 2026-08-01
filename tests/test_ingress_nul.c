/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Ingress rejection of encoded NULs (FIX 2, 2026-08-01).
 *
 * THE DIVERGENCE. cJSON decodes \u0000 into a real zero byte and keeps
 * parsing, so a JSON string value can continue PAST a NUL. Every
 * extractor in the daemon copies with snprintf("%s"), which stops AT the
 * NUL. So this single JSON value:
 *
 *     "pbs op=backup.version.read\u0000 op=backup.verify.run"
 *
 * arrives as one submitted object, is copied as
 * `pbs op=backup.version.read`, and the remainder is discarded silently.
 * The submitted command and the executed command are then not the same
 * object — and classification, hashing and the chain all see only the
 * truncated form. Exactly the class the separator policy exists to stop,
 * arriving through a different door.
 *
 * This is the FOURTH parser-length divergence in this codebase, which is
 * why the check lives at the ingress boundary and covers every key of
 * every request rather than one driver's parameter.
 *
 * Offline: onode_parse_request_fuzz() is a thin wrapper over the real
 * parse_request(), so nothing here opens a socket.
 */

#include "virp.h"
#include "virp_onode.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

static bool parse(const char *json)
{
    return onode_parse_request_fuzz((const uint8_t *)json, strlen(json));
}

/* =========================================================================
 * The smuggle itself
 * ========================================================================= */

static void test_single_ingress(void)
{
    printf("\n=== Single ingress — encoded NUL refused ===\n");

    TEST("baseline: the same request WITHOUT a NUL parses");
    assert(parse("{\"action\":\"execute\",\"device\":\"R6\","
                 "\"command\":\"pbs op=backup.version.read\"}"));
    PASS();

    TEST("command with an embedded \\u0000 -> whole request REFUSED");
    assert(!parse("{\"action\":\"execute\",\"device\":\"R6\","
                  "\"command\":\"pbs op=backup.version.read\\u0000"
                  " op=backup.verify.run\"}"));
    PASS();

    TEST("refused, NOT truncated-then-accepted");
    /* If the check were missing, this parses and yields the truncated
     * command — indistinguishable, to everything downstream, from a
     * caller who submitted only the first half. The assertion that it is
     * REFUSED is the whole point. */
    assert(!parse("{\"action\":\"execute\",\"device\":\"R6\","
                  "\"command\":\"show version\\u0000reload\"}"));
    PASS();

    TEST("a value whose ONLY defect is a TRAILING NUL is refused");
    assert(!parse("{\"action\":\"execute\",\"device\":\"R6\","
                  "\"command\":\"show version\\u0000\"}"));
    PASS();

    TEST("a NUL in the DEVICE field is refused too");
    assert(!parse("{\"action\":\"execute\",\"device\":\"R6\\u0000X\","
                  "\"command\":\"show version\"}"));
    PASS();

    TEST("a NUL in the ACTION field is refused too");
    assert(!parse("{\"action\":\"execute\\u0000x\",\"device\":\"R6\","
                  "\"command\":\"show version\"}"));
    PASS();

    TEST("uppercase \\U0000 is not an escape and must not false-positive");
    /* JSON escapes are lowercase \\u; \\U is invalid JSON, so cJSON
     * rejects the document anyway. Asserting refusal either way. */
    assert(!parse("{\"action\":\"execute\",\"device\":\"R6\","
                  "\"command\":\"show\\U0000version\"}"));
    PASS();
}

/* =========================================================================
 * The scan must not over-reject
 *
 * A syntactic scan that fired on any "u0000" would refuse legitimate
 * traffic. The check counts preceding backslashes so an ESCAPED
 * backslash followed by literal "u0000" is left alone.
 * ========================================================================= */

static void test_no_false_positives(void)
{
    printf("\n=== The scan does not over-reject ===\n");

    TEST("a literal backslash then u0000 (i.e. \\\\u0000) is ACCEPTED");
    /* JSON \\\\ is one literal backslash; the following u0000 is plain
     * text, not an escape, and decodes to no NUL. */
    assert(parse("{\"action\":\"execute\",\"device\":\"R6\","
                 "\"command\":\"show \\\\u0000 version\"}"));
    PASS();

    TEST("the text 'u0000' with no backslash is ACCEPTED");
    assert(parse("{\"action\":\"execute\",\"device\":\"R6\","
                 "\"command\":\"show u0000 version\"}"));
    PASS();

    TEST("an unrelated unicode escape is ACCEPTED");
    assert(parse("{\"action\":\"execute\",\"device\":\"R6\","
                 "\"command\":\"show \\u0041 version\"}"));
    PASS();

    TEST("a MALFORMED \\u000 escape is refused");
    /*
     * Written expecting cJSON to reject this as invalid JSON. It does
     * not: it feeds the partial digits to parse_hex4, decodes codepoint
     * 0, and the value silently truncates ("show \\u000 version" became
     * "show "). So a NUL is reachable through a MALFORMED escape too,
     * and the boundary check refuses any \\u that is not four hex digits
     * as well as any that encodes U+0000.
     */
    assert(!parse("{\"action\":\"execute\",\"device\":\"R6\","
                  "\"command\":\"show \\u000 version\"}"));
    PASS();
}

/* =========================================================================
 * Batch ingress — a second, independent parse path
 * ========================================================================= */

static void test_batch_ingress(void)
{
    printf("\n=== Batch ingress — the second door ===\n");

    /*
     * parse_batch_commands() never runs through parse_request(), so a
     * check installed only on the single path would leave the batch
     * array wide open — the same reasoning the multicommand-newline
     * tests record for the separator policy. The batch envelope itself
     * goes through parse_request() first, so the NUL is caught at that
     * boundary; parse_batch_commands() carries its own identical check
     * for any caller that reaches it directly.
     */

    TEST("baseline: a clean batch envelope parses");
    assert(parse("{\"action\":\"batch_execute\",\"commands\":["
                 "{\"device\":\"R6\",\"command\":\"show version\"}]}"));
    PASS();

    TEST("batch item with an encoded NUL -> whole batch REFUSED");
    assert(!parse("{\"action\":\"batch_execute\",\"commands\":["
                  "{\"device\":\"R6\","
                  "\"command\":\"show version\\u0000reload\"}]}"));
    PASS();

    TEST("NUL in a LATER batch item still refuses the whole batch");
    assert(!parse("{\"action\":\"batch_execute\",\"commands\":["
                  "{\"device\":\"R6\",\"command\":\"show version\"},"
                  "{\"device\":\"R6\","
                  "\"command\":\"show clock\\u0000reload\"}]}"));
    PASS();

    TEST("NUL in a batch item's DEVICE refuses the whole batch");
    assert(!parse("{\"action\":\"batch_execute\",\"commands\":["
                  "{\"device\":\"R6\\u0000X\",\"command\":\"show version\"}]}"));
    PASS();
}

/* =========================================================================
 * Degenerate input must not crash (the fuzz contract)
 * ========================================================================= */

static void test_degenerate(void)
{
    printf("\n=== Degenerate input ===\n");

    TEST("empty / truncated / garbage do not crash");
    (void)parse("");
    (void)parse("{");
    (void)parse("\\u0000");
    (void)parse("{\"command\":\"\\u0000\"}");
    (void)onode_parse_request_fuzz((const uint8_t *)"", 0);
    PASS();

    TEST("a bare \\u0000 value is refused");
    assert(!parse("{\"action\":\"execute\",\"device\":\"R6\","
                  "\"command\":\"\\u0000\"}"));
    PASS();
}

int main(void)
{
    printf("=== Ingress encoded-NUL rejection tests ===\n");

    test_single_ingress();
    test_no_false_positives();
    test_batch_ingress();
    test_degenerate();

    printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
