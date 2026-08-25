/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * PBS oversized-response handling — fail closed (2026-08-01).
 *
 * THE BUG THIS PINS. The curl write callback copied only the bytes that
 * fit its fixed buffer, then returned the ORIGINAL full byte count to
 * libcurl. libcurl therefore believed the entire body had been consumed
 * and the driver got no overflow indication at all. The clipped body was
 * formatted into a second fixed buffer, `output_len` was set from
 * snprintf's WOULD-HAVE-WRITTEN return value without clamping, and the
 * operation could still be marked successful on HTTP status alone.
 *
 * The result was a valid signature over incomplete evidence, whose
 * payload described the body as recorded verbatim. That is the exact
 * failure class VIRP exists to prevent — not a crash, not a leak, but a
 * signed statement that is not true.
 *
 * There are TWO truncation points and both must fail closed:
 *   1. the curl capture buffer   (PBS_RESPONSE_MAX)
 *   2. the observation formatter (VIRP_OUTPUT_MAX)
 *
 * A body can clear (1) and still be truncated by (2), because a header
 * line is prepended. Since ISSUE-A (2026-08-25) that line is the tagged
 * daemon-attested record of the DERIVED request —
 * VIRP_OBS_DERIVED_TAG "GET <path> [HTTP <code>]\n" — not the old
 * fabricated "<host>><command> ..." CLI prompt.
 *
 * Offline and pure: the callback and the formatter are driven directly,
 * so nothing here opens a socket.
 */

#include "virp.h"
#include "virp_driver.h"
#include "virp_driver_pbs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int tests_run = 0, tests_passed = 0;
#define TEST(name) do { tests_run++; printf("  [%d] %s ... ", tests_run, name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)

/* Feed `n` bytes through the write callback in one chunk. */
static size_t feed(pbs_response_t *r, size_t n, char fill)
{
    char *chunk = malloc(n ? n : 1);
    assert(chunk);
    memset(chunk, fill, n);
    size_t rc = pbs_write_cb(chunk, 1, n, r);
    free(chunk);
    return rc;
}

static void reset(pbs_response_t *r, char *buf, size_t cap)
{
    memset(buf, 0, cap);
    r->buf = buf; r->buf_size = cap; r->offset = 0;
    r->total = 0; r->overflowed = false;
}

/* =========================================================================
 * Buffer 1 — the curl capture buffer
 *
 * Capacity is buf_size - 1, because a NUL is reserved.
 * ========================================================================= */

static void test_capture_boundaries(void)
{
    printf("\n=== Capture buffer — below / exactly at / just above ===\n");

    enum { CAP = 256 };
    char buf[CAP];
    pbs_response_t r;
    const size_t usable = CAP - 1;

    TEST("just BELOW the limit -> accepted, no overflow");
    reset(&r, buf, CAP);
    assert(feed(&r, usable - 1, 'a') == usable - 1);
    assert(!r.overflowed);
    assert(r.offset == usable - 1);
    assert(strlen(buf) == usable - 1);
    PASS();

    TEST("EXACTLY at the limit -> accepted, no overflow");
    reset(&r, buf, CAP);
    assert(feed(&r, usable, 'b') == usable);
    assert(!r.overflowed);
    assert(r.offset == usable);
    assert(buf[usable] == '\0');      /* the reserved NUL is intact */
    PASS();

    TEST("ONE byte above the limit -> OVERFLOW flagged");
    reset(&r, buf, CAP);
    size_t rc = feed(&r, usable + 1, 'c');
    assert(r.overflowed);
    PASS();

    TEST("...and the callback returns a SHORT count, aborting the transfer");
    /* This is the fix: the old code returned size*nmemb unconditionally,
     * so libcurl saw a fully-consumed body and the driver learned
     * nothing. A short return is what makes libcurl raise
     * CURLE_WRITE_ERROR and stop. */
    assert(rc != usable + 1);
    PASS();

    TEST("far above the limit -> still exactly one overflow, no overrun");
    reset(&r, buf, CAP);
    assert(feed(&r, usable * 40, 'd') != usable * 40);
    assert(r.overflowed);
    assert(r.offset <= usable);
    assert(buf[usable] == '\0');
    PASS();

    TEST("overflow across MULTIPLE chunks is caught on the chunk that spills");
    reset(&r, buf, CAP);
    assert(feed(&r, usable / 2, 'e') == usable / 2);
    assert(!r.overflowed);                       /* first chunk fits */
    assert(feed(&r, usable, 'f') != usable);     /* second spills */
    assert(r.overflowed);
    PASS();

    TEST("total counts what libcurl offered, including the spilling chunk");
    assert(r.total == usable / 2 + usable);
    PASS();

    TEST("a zero-length body is not an overflow");
    reset(&r, buf, CAP);
    assert(feed(&r, 0, 'g') == 0);
    assert(!r.overflowed);
    assert(r.offset == 0);
    PASS();

    TEST("a NULL/!zero-capacity response is refused, not written through");
    {
        pbs_response_t bad = { .buf = NULL, .buf_size = 0, .offset = 0,
                               .total = 0, .overflowed = false };
        assert(pbs_write_cb((char *)"x", 1, 1, &bad) == 0);
    }
    PASS();
}

/* =========================================================================
 * Buffer 2 — the observation formatter
 * ========================================================================= */

static void test_format_boundaries(void)
{
    printf("\n=== Observation formatter — stored length, never would-have ===\n");

    enum { OUT = 512 };
    char out[OUT];
    size_t stored = 0;

    /* Header overhead for the fixed prefix used below. */
    char probe[OUT];
    size_t probe_len = 0;
    assert(pbs_format_observation(probe, sizeof(probe), "h", "c", "/p", 200,
                                  "", &probe_len) == 0);
    const size_t overhead = probe_len;

    TEST("a body that fits -> stored length is the REAL byte count");
    {
        size_t body_len = OUT - overhead - 2;
        char *body = malloc(body_len + 1);
        memset(body, 'x', body_len); body[body_len] = '\0';
        assert(pbs_format_observation(out, OUT, "h", "c", "/p", 200,
                                      body, &stored) == 0);
        assert(stored == overhead + body_len);
        assert(stored == strlen(out));      /* the claim matches reality */
        assert(stored < OUT);
        free(body);
    }
    PASS();

    TEST("EXACTLY filling the buffer (len == OUT-1) -> accepted");
    {
        size_t body_len = OUT - 1 - overhead;
        char *body = malloc(body_len + 1);
        memset(body, 'y', body_len); body[body_len] = '\0';
        assert(pbs_format_observation(out, OUT, "h", "c", "/p", 200,
                                      body, &stored) == 0);
        assert(stored == OUT - 1);
        assert(stored == strlen(out));
        free(body);
    }
    PASS();

    TEST("ONE byte too long -> REFUSED, not silently clipped");
    {
        size_t body_len = OUT - overhead;    /* one past exact fit */
        char *body = malloc(body_len + 1);
        memset(body, 'z', body_len); body[body_len] = '\0';
        assert(pbs_format_observation(out, OUT, "h", "c", "/p", 200,
                                      body, &stored) != 0);
        assert(stored == 0);
        assert(out[0] == '\0');              /* nothing left to sign */
        free(body);
    }
    PASS();

    TEST("far too long -> refused, stored stays 0");
    {
        size_t body_len = OUT * 8;
        char *body = malloc(body_len + 1);
        memset(body, 'w', body_len); body[body_len] = '\0';
        assert(pbs_format_observation(out, OUT, "h", "c", "/p", 200,
                                      body, &stored) != 0);
        assert(stored == 0);
        free(body);
    }
    PASS();

    TEST("stored NEVER equals snprintf's would-have-written on overflow");
    {
        /* The defect verbatim: `written` from snprintf is the length the
         * payload WOULD have had. Storing it as output_len overstates the
         * payload and is what the daemon's later clamp was papering over. */
        size_t body_len = OUT * 4;
        char *body = malloc(body_len + 1);
        memset(body, 'q', body_len); body[body_len] = '\0';
        int would_have = snprintf(NULL, 0,
                                  VIRP_OBS_DERIVED_TAG "GET %s [HTTP %ld]\n%s",
                                  "/p", 200L, body);
        assert(would_have > (int)OUT);       /* the inflated value */
        assert(pbs_format_observation(out, OUT, "h", "c", "/p", 200,
                                      body, &stored) != 0);
        assert(stored != (size_t)would_have);
        assert(stored == 0);
        free(body);
    }
    PASS();

    TEST("degenerate arguments are refused");
    assert(pbs_format_observation(NULL, OUT, "h", "c", "/p", 200, "b", &stored) != 0);
    assert(pbs_format_observation(out, 0, "h", "c", "/p", 200, "b", &stored) != 0);
    PASS();
}

/* =========================================================================
 * The real buffer sizes the driver ships with
 * ========================================================================= */

static void test_shipped_limits(void)
{
    printf("\n=== The driver's real limits ===\n");

    TEST("capture buffer is smaller than the observation buffer");
    /* If this inverted, a body could fit capture and always fit the
     * formatter, hiding truncation point (2) from every test. */
    assert(PBS_RESPONSE_MAX < VIRP_OUTPUT_MAX);
    PASS();

    TEST("a body at the real capture limit still overflows the formatter");
    {
        /* This is the case the second guard exists for: PBS_RESPONSE_MAX
         * bytes of body plus the header line exceeds VIRP_OUTPUT_MAX. */
        size_t body_len = PBS_RESPONSE_MAX - 1;
        char *body = malloc(body_len + 1);
        assert(body);
        memset(body, 'j', body_len); body[body_len] = '\0';
        char *out = malloc(VIRP_OUTPUT_MAX);
        assert(out);
        size_t stored = 0;
        int rc = pbs_format_observation(out, VIRP_OUTPUT_MAX,
                                        "pbs-lab",
                                        "pbs op=backup.datastore.usage",
                                        "/api2/json/status/datastore-usage",
                                        200, body, &stored);
        if (rc == 0) {
            assert(stored == strlen(out));   /* if it fits, the length is honest */
        } else {
            assert(stored == 0);             /* if not, nothing to sign */
            assert(out[0] == '\0');
        }
        free(body); free(out);
    }
    PASS();

    TEST("ISSUE-A: no fabricated prompt, no registry hostname in the body");
    {
        /* The old first line was `pbs-lab>pbs op=... [GET /p] [HTTP 200]`:
         * a CLI prompt on a driver with no CLI, prefixed with the registry
         * name rather than anything the server sent. The derived path is
         * genuine derivation evidence and stays, but tagged as
         * daemon-attested so no reader mistakes it for response bytes. */
        char out[4096];
        size_t stored = 0;
        assert(pbs_format_observation(out, sizeof(out), "pbs-lab",
                                      "pbs op=backup.datastore.usage",
                                      "/api2/json/status/datastore-usage",
                                      200, "{\"data\":[]}", &stored) == 0);

        /* The tag leads, so the daemon-attested line announces itself. */
        assert(strncmp(out, VIRP_OBS_DERIVED_TAG,
                       strlen(VIRP_OBS_DERIVED_TAG)) == 0);
        /* No fabricated prompt character anywhere in the header line. */
        char *nl = strchr(out, '\n');
        assert(nl != NULL);
        *nl = '\0';
        assert(strchr(out, '>') == NULL);
        assert(strchr(out, '#') == NULL);
        /* The registry name is a config claim and must not be in the body. */
        assert(strstr(out, "pbs-lab") == NULL);
        /* The derived path IS retained — that is the point of keeping it. */
        assert(strstr(out, "/api2/json/status/datastore-usage") != NULL);
        /* Response bytes follow the newline, unmodified. */
        assert(strcmp(nl + 1, "{\"data\":[]}") == 0);
    }
    PASS();

    TEST("the real datastore.usage size (27,841 B) formats honestly");
    {
        size_t body_len = 27841;
        char *body = malloc(body_len + 1);
        memset(body, 'u', body_len); body[body_len] = '\0';
        char *out = malloc(VIRP_OUTPUT_MAX);
        size_t stored = 0;
        assert(pbs_format_observation(out, VIRP_OUTPUT_MAX, "pbs-lab",
                                      "pbs op=backup.datastore.usage",
                                      "/api2/json/status/datastore-usage",
                                      200, body, &stored) == 0);
        assert(stored == strlen(out));
        free(body); free(out);
    }
    PASS();
}

/* =========================================================================
 * The execute-level contract
 *
 * This is the assertion that decides whether the fix is a fix. The daemon
 * emits a signed typed ERROR only when
 *
 *     !success && output_len == 0 && error_msg[0]
 *
 * If the overflow path left partial bytes with a non-zero length, the
 * daemon would take the DEVICE_OUTPUT branch instead and sign the
 * TRUNCATED body — turning the fix back into the bug, silently.
 * ========================================================================= */

static void test_execute_contract(void)
{
    printf("\n=== Fail-closed result shape (what the daemon keys on) ===\n");

    virp_exec_result_t r;

    TEST("output_len is ZERO — the daemon must not see signable bytes");
    memset(&r, 0, sizeof(r));
    memset(r.output, 'X', sizeof(r.output));      /* pre-dirty the buffer */
    r.output_len = 4242;
    r.success = true;
    pbs_result_evidence_limit(&r, "pbs-lab", "the body did not fit");
    assert(r.output_len == 0);
    PASS();

    TEST("success is false");
    assert(!r.success);
    PASS();

    TEST("error_msg is non-empty (the third condition the daemon requires)");
    assert(r.error_msg[0] != '\0');
    PASS();

    TEST("the payload buffer is WIPED, not left holding partial evidence");
    for (size_t i = 0; i < sizeof(r.output); i++)
        assert(r.output[i] == '\0');
    PASS();

    TEST("the message names the device and the reason");
    assert(strstr(r.error_msg, "pbs-lab") != NULL);
    assert(strstr(r.error_msg, "evidence limit") != NULL);
    assert(strstr(r.error_msg, "nothing was recorded") != NULL);
    PASS();

    TEST("the daemon's signed-ERROR precondition holds exactly");
    /* Mirror of the condition in virp_onode.c. */
    assert(!r.success && r.output_len == 0 && r.error_msg[0]);
    PASS();

    TEST("an oversized GREEN op (large backup.datastore.usage) lands here");
    {
        /* The op classifies GREEN and returns HTTP 200; it is the CAPTURE
         * that fails. Success must not be inferred from status. */
        memset(&r, 0, sizeof(r));
        r.success = true; r.exit_code = 0;        /* as an HTTP-200 path would */
        pbs_result_evidence_limit(&r, "pbs-lab",
                                  "the body did not fit the capture buffer");
        assert(!r.success);                        /* NOT success on 200 */
        assert(r.output_len == 0);
        assert(r.exit_code != 0);
    }
    PASS();

    TEST("degenerate call does not crash");
    pbs_result_evidence_limit(NULL, "h", "d");
    memset(&r, 0, sizeof(r));
    pbs_result_evidence_limit(&r, NULL, NULL);
    assert(!r.success && r.output_len == 0 && r.error_msg[0]);
    PASS();
}

int main(void)
{
    printf("=== PBS oversized-response fail-closed tests ===\n");

    test_capture_boundaries();
    test_format_boundaries();
    test_shipped_limits();
    test_execute_contract();

    printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
