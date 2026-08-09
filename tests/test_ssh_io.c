/*
 * test_ssh_io.c — shared SSH read path (finding N1, part 2a)
 *
 * Drives src/virp_ssh_io.c through a scripted mock PTY, per driver
 * profile (Cisco, ASA, JunOS, PAN-OS), proving for each:
 *
 *   (i)   residue left by command N does not appear in command N+1's body
 *   (ii)  a device line ending in '>' (or '#') mid-output does not
 *         terminate the read early
 *   (iii) a read that never sees the prompt is an ERROR, not a short
 *         success with a truncated body
 *
 * These cannot "fail against the current code" by simply being run
 * against it — the module they test did not exist. So each case is a
 * DIFFERENTIAL test: the legacy per-driver algorithm is frozen below,
 * copied from the drivers as they stood at hardening-2026-07-29, and
 * every case asserts that the legacy algorithm gets it WRONG and the
 * shared helper gets it RIGHT against byte-identical input. If the
 * legacy assertion ever stops failing, the case has stopped being a
 * regression test and the test itself fails.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "virp_ssh_io.h"

/* Buffer a driver would give the keepalive read (PAN-OS uses
 * VIRP_OUTPUT_MAX; the size only needs to exceed the reply). */
#define VIRP_SSH_KEEPALIVE_TEST_BUF  8192

static int tests_run = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(fn) do {                             \
    printf("  %-58s", #fn);                           \
    fflush(stdout);                                   \
    int before = tests_failed;                        \
    tests_run++;                                      \
    fn();                                             \
    if (tests_failed == before) printf(" [PASS]\n");  \
} while (0)

#define FAIL(...) do {                                             \
    printf(" [FAIL]\n    ");                                       \
    printf(__VA_ARGS__);                                           \
    printf("\n");                                                  \
    tests_failed++;                                                \
    return;                                                        \
} while (0)

#define CHECK(cond, ...) do {                                      \
    if (!(cond)) FAIL(__VA_ARGS__);                                \
} while (0)

/* =========================================================================
 * Scripted mock PTY
 *
 * Serves a fixed byte script in small chunks, so the helper sees the
 * same partial-read behavior a real channel produces. Writes are
 * recorded; after `deliver_len` bytes it reports EAGAIN forever, which
 * is how a device that never sends a prompt behaves.
 * ========================================================================= */

/*
 * '\x01' in a script marks a DELIVERY BOUNDARY: the mock never returns
 * bytes across one in a single read. Real channels fragment wherever the
 * network happens to split, and the legacy defect only fires when a
 * fragment happens to END on the trap character — so the boundary has to
 * be expressible, not left to a fixed chunk size.
 */
#define SEG '\x01'

typedef struct {
    char        pending[32768];   /* bytes the device has queued for us */
    size_t      pending_len;
    size_t      pos;
    size_t      chunk;            /* max bytes per read */
    const char *reply_on_write;   /* queued on the first write */
    const char *reply_on_write2;  /* queued on the second and later writes */
    const char *late_reply;       /* queued after late_after_reads EAGAINs */
    int         late_after_reads; /* re-armed on every write */
    int         late_countdown;
    int         writes;
    char        written[4096];
    size_t      written_len;
} mock_pty_t;

static void mock_queue(mock_pty_t *m, const char *data)
{
    size_t len = strlen(data);
    if (m->pending_len + len >= sizeof(m->pending))
        return;
    memcpy(m->pending + m->pending_len, data, len);
    m->pending_len += len;
    m->pending[m->pending_len] = '\0';
}

static ssize_t mock_read(void *ctx, char *buf, size_t len)
{
    mock_pty_t *m = (mock_pty_t *)ctx;

    /* Consume a boundary marker without returning it. */
    while (m->pos < m->pending_len && m->pending[m->pos] == SEG)
        m->pos++;

    if (m->pos >= m->pending_len) {
        /* A device that answers, but only after the channel has sat
         * quiet for a while — each EAGAIN the caller sees costs it one
         * poll interval of real waiting. */
        if (m->late_countdown > 0 && --m->late_countdown == 0)
            mock_queue(m, m->late_reply);
        return VIRP_SSH_IO_EAGAIN;
    }

    size_t avail = m->pending_len - m->pos;
    size_t n = avail < len ? avail : len;
    if (m->chunk && n > m->chunk) n = m->chunk;

    /* Never cross a delivery boundary in one read. */
    const char *seg = memchr(m->pending + m->pos, SEG, n);
    if (seg)
        n = (size_t)(seg - (m->pending + m->pos));

    if (n == 0)
        return VIRP_SSH_IO_EAGAIN;

    memcpy(buf, m->pending + m->pos, n);
    m->pos += n;
    return (ssize_t)n;
}

static ssize_t mock_write(void *ctx, const char *buf, size_t len)
{
    mock_pty_t *m = (mock_pty_t *)ctx;
    if (m->written_len + len < sizeof(m->written)) {
        memcpy(m->written + m->written_len, buf, len);
        m->written_len += len;
        m->written[m->written_len] = '\0';
    }
    /* The device answers what we just sent. */
    m->writes++;
    if (m->writes == 1 && m->reply_on_write)
        mock_queue(m, m->reply_on_write);
    else if (m->writes > 1)
        mock_queue(m, m->reply_on_write2 ? m->reply_on_write2
                                         : m->reply_on_write);
    if (m->late_reply)
        m->late_countdown = m->late_after_reads;
    return (ssize_t)len;
}

static void mock_init(mock_pty_t *m, const char *script, size_t chunk)
{
    memset(m, 0, sizeof(*m));
    m->chunk = chunk;
    if (script && *script)
        mock_queue(m, script);
}

/* =========================================================================
 * FROZEN legacy algorithm — copied from the four drivers as of
 * hardening-2026-07-29. Do NOT "fix" this: its job is to reproduce the
 * defect so the differential assertions stay meaningful.
 *
 * `require_at` mirrors the JunOS/PAN-OS variant, which additionally
 * required an '@' in the candidate prompt line.
 * ========================================================================= */

static ssize_t legacy_read_until_prompt(mock_pty_t *m, char *buf,
                                        size_t buf_len, int timeout_polls,
                                        bool require_at)
{
    size_t total = 0;
    int elapsed = 0;

    while (total < buf_len - 1 && elapsed < timeout_polls) {
        ssize_t n = mock_read(m, buf + total, buf_len - total - 1);
        if (n > 0) {
            total += (size_t)n;
            buf[total] = '\0';
            if (total >= 1) {
                char last = buf[total - 1];
                if (last == '#' || last == '>') {
                    char *last_nl = strrchr(buf, '\n');
                    const char *prompt_start = last_nl ? last_nl + 1 : buf;
                    size_t plen = strlen(prompt_start);
                    bool at_ok = !require_at ||
                                 (memchr(prompt_start, '@', plen) != NULL);
                    if (plen > 0 && plen < 128 && at_ok)
                        break;              /* "got a prompt" */
                }
            }
            elapsed = 0;
        } else if (n == VIRP_SSH_IO_EAGAIN) {
            elapsed++;
        } else {
            break;
        }
    }
    buf[total] = '\0';
    return (ssize_t)total;
}

/* =========================================================================
 * Driver profiles
 * ========================================================================= */

typedef struct {
    const char *name;
    const char *prompt;        /* the real prompt for this vendor */
    bool        legacy_needs_at;
    const char *cmd;
    /* Output containing a line that ENDS in '>' or '#' but is not the
     * prompt — the trap that ended legacy reads early. */
    const char *body_with_trap;
} driver_profile_t;

static const driver_profile_t PROFILES[] = {
    {
        "cisco", "R6#", false, "show ip route",
        "Codes: C - connected, S - static\n"
        "Gateway of last resort is 10.0.0.1 to network 0.0.0.0\n"
        "S*    0.0.0.0/0 [1/0] via 10.0.0.1>\x01\n"      /* trap: ends '>' */
        "C     10.0.56.0/24 is directly connected, Gi0/1\n",
    },
    {
        "asa", "ASA-5525#", false, "show route",
        "Codes: L - local, C - connected, S - static\n"
        "Gateway of last resort is 203.0.113.1 to network 0.0.0.0>\x01\n"
        "C     192.168.1.0 255.255.255.0 is directly connected, inside\n",
    },
    {
        "junos", "aiops-svc@SRX300>", true, "show interfaces terse",
        "Interface               Admin Link Proto    Local\n"
        "ge-0/0/0                up    up   inet     10.0.0.1/24\n"
        "note: peer reachable via aiops-svc@SRX300>\x01\n" /* trap w/ '@' */
        "ge-0/0/1                up    down\n",
    },
    {
        "panos", "aiops-svc@pa-850>", true, "show system resources",
        "top - 14:30:22 up 12 days,  3:11,  1 user\n"
        "Tasks: 187 total,   1 running, 186 sleeping\n"
        "admin@pa-850>\x01\n"                             /* trap w/ '@' */
        "Mem: 8123456k total,  4231234k used\n",
    },
};
static const size_t N_PROFILES = sizeof(PROFILES) / sizeof(PROFILES[0]);

/* Build "<echo>\n<body><prompt> " as a device would send it. */
static void build_reply(char *out, size_t cap, const driver_profile_t *p,
                        const char *body)
{
    snprintf(out, cap, "%s\r\n%s%s ", p->cmd, body, p->prompt);
}

/* Body text as the driver would see it — boundary markers removed. */
static void strip_markers(char *s)
{
    char *w = s;
    for (const char *r = s; *r; r++)
        if (*r != SEG) *w++ = *r;
    *w = '\0';
}

static virp_ssh_prompt_t known_prompt(const driver_profile_t *p)
{
    virp_ssh_prompt_t pr;
    memset(&pr, 0, sizeof(pr));
    snprintf(pr.prompt, sizeof(pr.prompt), "%s", p->prompt);
    pr.prompt_len = strlen(p->prompt);
    pr.learned = true;
    return pr;
}

/* =========================================================================
 * (i) Residue from command N must not appear in command N+1's body
 * ========================================================================= */

TEST(test_residue_does_not_enter_next_body)
{
    for (size_t i = 0; i < N_PROFILES; i++) {
        const driver_profile_t *p = &PROFILES[i];
        virp_ssh_prompt_t pr = known_prompt(p);

        /*
         * The channel opens with the tail of a PREVIOUS command still
         * buffered (this is the pa-850 shape: leftover output from an
         * earlier command sitting in front of the next reply).
         */
        char residue[512];
        snprintf(residue, sizeof(residue),
                 "LEFTOVER-FROM-PREVIOUS-COMMAND: hostname 10.9.9.9\n%s ",
                 p->prompt);

        char reply[4096];
        build_reply(reply, sizeof(reply), p, p->body_with_trap);

        /* --- new helper: drain first, then read --- */
        mock_pty_t m;
        mock_init(&m, residue, 64);
        m.reply_on_write = reply;

        virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

        size_t drained = virp_ssh_drain(&io, p->name);
        CHECK(drained == strlen(residue),
              "%s: drain took %zu of %zu residue bytes",
              p->name, drained, strlen(residue));

        char buf[8192];
        size_t out_len = 0;
        virp_error_t rc = virp_ssh_exec(&io, &pr, p->cmd, buf, sizeof(buf),
                                        &out_len, 2000, p->name);
        CHECK(rc == VIRP_OK, "%s: exec returned %d", p->name, (int)rc);
        CHECK(strstr(buf, "LEFTOVER-FROM-PREVIOUS-COMMAND") == NULL,
              "%s: residue leaked into the body: %.80s", p->name, buf);

        /* --- frozen legacy: same bytes, no drain --- */
        char legacy_script[8192];
        snprintf(legacy_script, sizeof(legacy_script), "%s%s", residue, reply);
        mock_pty_t lm;
        mock_init(&lm, legacy_script, 64);
        char lbuf[8192];
        legacy_read_until_prompt(&lm, lbuf, sizeof(lbuf), 40,
                                 p->legacy_needs_at);
        CHECK(strstr(lbuf, "LEFTOVER-FROM-PREVIOUS-COMMAND") != NULL,
              "%s: legacy path no longer shows the defect — this case has "
              "stopped being a regression test", p->name);
    }
}

/* =========================================================================
 * (ii) A device line ending in '>' must not terminate the read
 * ========================================================================= */

TEST(test_trap_line_does_not_terminate_read)
{
    for (size_t i = 0; i < N_PROFILES; i++) {
        const driver_profile_t *p = &PROFILES[i];
        virp_ssh_prompt_t pr = known_prompt(p);

        char reply[4096];
        build_reply(reply, sizeof(reply), p, p->body_with_trap);

        /* --- new helper --- */
        mock_pty_t m;
        mock_init(&m, reply, 48);
        virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

        char buf[8192];
        size_t out_len = 0;
        virp_error_t rc = virp_ssh_read_until_prompt(&io, &pr, buf, sizeof(buf),
                                                     &out_len, 2000, p->name);
        CHECK(rc == VIRP_OK, "%s: read returned %d", p->name, (int)rc);

        /* The whole body must be present — including the line AFTER the
         * trap, which is exactly what an early termination would cut. */
        const char *last_line = strrchr(p->body_with_trap, '\n');
        /* find the final non-empty line of the body */
        char tail[256];
        {
            const char *b = p->body_with_trap;
            size_t blen = strlen(b);
            while (blen > 0 && b[blen - 1] == '\n') blen--;
            size_t st = blen;
            while (st > 0 && b[st - 1] != '\n') st--;
            snprintf(tail, sizeof(tail), "%.*s", (int)(blen - st), b + st);
            strip_markers(tail);
        }
        (void)last_line;
        CHECK(strstr(buf, tail) != NULL,
              "%s: output truncated at the trap line — '%s' missing",
              p->name, tail);

        /* --- frozen legacy: terminates early on the trap --- */
        mock_pty_t lm;
        mock_init(&lm, reply, 48);
        char lbuf[8192];
        legacy_read_until_prompt(&lm, lbuf, sizeof(lbuf), 40,
                                 p->legacy_needs_at);
        CHECK(strstr(lbuf, tail) == NULL,
              "%s: legacy path no longer truncates at the trap — this case "
              "has stopped being a regression test", p->name);
    }
}

/* =========================================================================
 * (iii) A promptless read is an ERROR, not a truncated success
 * ========================================================================= */

TEST(test_promptless_read_is_error)
{
    for (size_t i = 0; i < N_PROFILES; i++) {
        const driver_profile_t *p = &PROFILES[i];
        virp_ssh_prompt_t pr = known_prompt(p);

        /* Device sends a partial body and then goes silent — no prompt. */
        char reply[4096];
        snprintf(reply, sizeof(reply), "%s\r\n%s", p->cmd, p->body_with_trap);

        mock_pty_t m;
        mock_init(&m, reply, 64);
        virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

        char buf[8192];
        size_t out_len = 0;
        virp_error_t rc = virp_ssh_read_until_prompt(&io, &pr, buf, sizeof(buf),
                                                     &out_len, 300, p->name);
        CHECK(rc == VIRP_ERR_NO_PROMPT,
              "%s: promptless read returned %d, expected VIRP_ERR_NO_PROMPT",
              p->name, (int)rc);

        /* --- frozen legacy: reports it as a successful short read --- */
        mock_pty_t lm;
        mock_init(&lm, reply, 64);
        char lbuf[8192];
        ssize_t ln = legacy_read_until_prompt(&lm, lbuf, sizeof(lbuf), 12,
                                              p->legacy_needs_at);
        CHECK(ln > 0,
              "%s: legacy path no longer returns a nonzero short read — this "
              "case has stopped being a regression test", p->name);
    }
}

/* =========================================================================
 * Prompt learning
 * ========================================================================= */

TEST(test_learn_prompt_confirms_across_two_probes)
{
    for (size_t i = 0; i < N_PROFILES; i++) {
        const driver_profile_t *p = &PROFILES[i];

        char probe[256];
        snprintf(probe, sizeof(probe), "\r\n%s ", p->prompt);

        /* Every probe newline gets the prompt back — the confirming shape. */
        mock_pty_t m;
        mock_init(&m, "", 32);
        m.reply_on_write = probe;
        virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

        virp_ssh_prompt_t pr;
        virp_error_t rc = virp_ssh_learn_prompt(&io, p->name, NULL, &pr);

        CHECK(rc == VIRP_OK, "%s: learn failed (%d)", p->name, (int)rc);
        CHECK(pr.learned, "%s: prompt not marked learned", p->name);
        CHECK(strcmp(pr.prompt, p->prompt) == 0,
              "%s: learned '%s', expected '%s'", p->name, pr.prompt, p->prompt);
    }
}

TEST(test_learn_prompt_refuses_when_unconfirmed)
{
    /*
     * Probe 1 answers with output, probe 2 with a different line. Two
     * different answers means what came back was not a prompt — learning
     * must refuse rather than guess, so the driver fails the connect.
     */
    mock_pty_t m;
    mock_init(&m, "", 32);
    /* Probe 1 sees "first-answer", probe 2 sees "second-answer": the two
     * rounds disagree, so nothing may be learned. */
    m.reply_on_write  = "\r\nfirst-answer\r\n";
    m.reply_on_write2 = "\r\nsecond-answer\r\n";
    virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

    virp_ssh_prompt_t pr;
    virp_error_t rc = virp_ssh_learn_prompt(&io, "unconfirmed", NULL, &pr);
    CHECK(rc == VIRP_ERR_NO_PROMPT, "expected refusal, got %d", (int)rc);
    CHECK(!pr.learned, "prompt must not be marked learned on refusal");
}

TEST(test_learn_prompt_waits_out_blank_echo_then_learns)
{
    /*
     * The pa-850 shape (2026-08-09): the device echoes the probe CRLF
     * within one poll, then stalls past VIRP_SSH_QUIESCENT_MS before
     * printing its prompt. The idle-only gate treated the echo as the
     * whole answer and refused; the content-aware gate must keep
     * listening and learn the prompt.
     */
    mock_pty_t m;
    mock_init(&m, "", 32);
    m.reply_on_write = "\r\n";                       /* echo, immediately */
    m.late_reply = "\r\naiops-svc@pa-850> ";
    m.late_after_reads = 16;      /* 16 polls ≈ 400 ms of dead air, well
                                     past the 250 ms quiescence window */
    virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

    virp_ssh_prompt_t pr;
    virp_error_t rc = virp_ssh_learn_prompt(&io, "pa-850-slow", NULL, &pr);
    CHECK(rc == VIRP_OK, "slow-prompt device must learn, got %d", (int)rc);
    CHECK(strcmp(pr.prompt, "aiops-svc@pa-850>") == 0,
          "learned '%s', expected 'aiops-svc@pa-850>'", pr.prompt);
}

TEST(test_learn_prompt_refuses_permanently_silent_device)
{
    /*
     * A device that authenticates but never sends a byte must still be
     * refused with VIRP_ERR_NO_PROMPT — the content-aware gate loosened
     * WHEN a read may end, never WHETHER a failed learn refuses. Budgets
     * are injected so the test does not sit through the real 20 s.
     */
    mock_pty_t m;
    mock_init(&m, "", 32);                           /* no replies, ever */
    virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

    virp_ssh_learn_opts_t lo = { .first_byte_ms = 100, .total_ms = 300 };
    virp_ssh_prompt_t pr;
    virp_error_t rc = virp_ssh_learn_prompt(&io, "mute", &lo, &pr);
    CHECK(rc == VIRP_ERR_NO_PROMPT, "expected refusal, got %d", (int)rc);
    CHECK(!pr.learned, "prompt must not be marked learned for a mute device");
}

TEST(test_learn_prompt_refuses_blank_echo_at_total_budget)
{
    /*
     * A device that echoes CRLF but never follows with a line must be
     * cut off by the TOTAL budget, not wait forever: blank bytes disarm
     * the silence exit, so the ceiling is what bounds this read.
     */
    mock_pty_t m;
    mock_init(&m, "", 32);
    m.reply_on_write = "\r\n";                       /* echo and nothing else */
    virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

    virp_ssh_learn_opts_t lo = { .total_ms = 400 };
    virp_ssh_prompt_t pr;
    virp_error_t rc = virp_ssh_learn_prompt(&io, "echo-only", &lo, &pr);
    CHECK(rc == VIRP_ERR_NO_PROMPT, "expected refusal, got %d", (int)rc);
    CHECK(!pr.learned, "prompt must not be marked learned from a blank echo");
}

TEST(test_read_refuses_without_learned_prompt)
{
    /* Fails closed: no learned prompt means no way to bound a read. */
    mock_pty_t m;
    mock_init(&m, "some output\nR6# ", 32);
    virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

    virp_ssh_prompt_t pr;
    memset(&pr, 0, sizeof(pr));   /* learned == false */

    char buf[1024];
    size_t out_len = 0;
    virp_error_t rc = virp_ssh_read_until_prompt(&io, &pr, buf, sizeof(buf),
                                                 &out_len, 300, "nolearn");
    CHECK(rc == VIRP_ERR_NO_PROMPT, "expected refusal, got %d", (int)rc);
}

/* =========================================================================
 * Echo stripping by text, not position
 * ========================================================================= */

TEST(test_strip_echo_matches_command_text)
{
    char buf[256];

    snprintf(buf, sizeof(buf), "show version\r\nCisco IOS Software\nline2");
    char *out = virp_ssh_strip_echo(buf, "show version");
    CHECK(strncmp(out, "Cisco IOS Software", 18) == 0,
          "echo not stripped: '%.30s'", out);

    /*
     * No echo present (it was consumed as residue). A positional strip
     * would eat the first real line; matching by text must not.
     */
    snprintf(buf, sizeof(buf), "Cisco IOS Software\nline2");
    out = virp_ssh_strip_echo(buf, "show version");
    CHECK(strncmp(out, "Cisco IOS Software", 18) == 0,
          "first output line was eaten: '%.30s'", out);
}

/* =========================================================================
 * Drain accounting
 * ========================================================================= */

TEST(test_drain_reports_byte_count)
{
    const char *residue = "0123456789ABCDEF";
    mock_pty_t m;
    mock_init(&m, residue, 4);
    virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

    size_t n = virp_ssh_drain(&io, "drain-test");
    CHECK(n == strlen(residue), "drained %zu, expected %zu",
          n, strlen(residue));

    /* A clean channel reports zero (and logs nothing). */
    mock_pty_t m2;
    mock_init(&m2, "", 4);
    virp_ssh_io_t io2 = { .ctx = &m2, .read = mock_read, .write = mock_write };
    CHECK(virp_ssh_drain(&io2, "drain-test") == 0,
          "clean channel reported residue");
}


/* =========================================================================
 * Keepalive window (finding N1 / 2b)
 *
 * PAN-OS holds ONE channel for the life of the connection and runs a
 * background keepalive on it. The keepalive is shaped exactly like a
 * command — send a newline, read the prompt back — so it runs through
 * virp_ssh_exec. What matters is that its read window cannot end with
 * unread bytes still on the channel, because this driver's next read is
 * a real command whose body gets signed.
 * ========================================================================= */

TEST(test_keepalive_exchange_leaves_channel_clean)
{
    const char *PROMPT = "aiops-svc@pa-850>";
    virp_ssh_prompt_t pr;
    memset(&pr, 0, sizeof(pr));
    snprintf(pr.prompt, sizeof(pr.prompt), "%s", PROMPT);
    pr.prompt_len = strlen(PROMPT);
    pr.learned = true;

    /*
     * A reply bigger than the keepalive's old 1024-byte discard buffer.
     * PAN-OS emits a banner ahead of the prompt after a reconnect, which
     * is how the real one overflowed.
     */
    char reply[4096];
    size_t off = 0;
    off += (size_t)snprintf(reply + off, sizeof(reply) - off, "\r\n");
    for (int i = 0; i < 40 && off < sizeof(reply) - 128; i++)
        off += (size_t)snprintf(reply + off, sizeof(reply) - off,
                                "banner line %02d: system message of the day\n", i);
    snprintf(reply + off, sizeof(reply) - off, "%s ", PROMPT);

    /* --- new path: exec to the learned prompt --- */
    mock_pty_t m;
    mock_init(&m, "", 64);
    m.reply_on_write = reply;
    virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

    char buf[VIRP_SSH_KEEPALIVE_TEST_BUF];
    size_t got = 0;
    virp_error_t rc = virp_ssh_exec(&io, &pr, "", buf, sizeof(buf), &got,
                                    2000, "pa-850");
    CHECK(rc == VIRP_OK, "keepalive exchange failed (%d)", (int)rc);

    /* The defining assertion: nothing is left for the next command. */
    size_t leftover = virp_ssh_drain(&io, "pa-850-after-keepalive");
    CHECK(leftover == 0,
          "keepalive left %zu bytes on the channel for the next command",
          leftover);

    /* --- frozen legacy: 1024-byte quiescent discard --- */
    mock_pty_t lm;
    mock_init(&lm, "", 64);
    lm.reply_on_write = reply;
    virp_ssh_io_t lio = { .ctx = &lm, .read = mock_read, .write = mock_write };
    mock_write(&lm, "\n", 1);

    char ldiscard[1024];
    virp_ssh_read_quiescent(&lio, ldiscard, sizeof(ldiscard), 2000);
    size_t lleftover = virp_ssh_drain(&lio, "pa-850-legacy");
    CHECK(lleftover > 0,
          "legacy keepalive window no longer leaves residue — this case has "
          "stopped being a regression test");
}

TEST(test_keepalive_without_prompt_is_error)
{
    /*
     * Device answers the keepalive with something that never terminates.
     * Reporting OK here would leave an unterminated read on the channel;
     * the driver needs a distinguishable failure so it can mark the
     * session stale instead.
     */
    const char *PROMPT = "aiops-svc@pa-850>";
    virp_ssh_prompt_t pr;
    memset(&pr, 0, sizeof(pr));
    snprintf(pr.prompt, sizeof(pr.prompt), "%s", PROMPT);
    pr.prompt_len = strlen(PROMPT);
    pr.learned = true;

    mock_pty_t m;
    mock_init(&m, "", 64);
    m.reply_on_write = "\r\npartial output with no prompt\r\n";
    virp_ssh_io_t io = { .ctx = &m, .read = mock_read, .write = mock_write };

    char buf[4096];
    size_t got = 0;
    virp_error_t rc = virp_ssh_exec(&io, &pr, "", buf, sizeof(buf), &got,
                                    300, "pa-850");
    CHECK(rc == VIRP_ERR_NO_PROMPT,
          "expected VIRP_ERR_NO_PROMPT, got %d", (int)rc);
    CHECK(got > 0, "expected the partial bytes to be reported, got %zu", got);
}

/* ========================================================================= */

int main(void)
{
    printf("\n=== VIRP Shared SSH Read Path Tests (finding N1 / 2a) ===\n\n");

    printf("--- Per-driver: residue, trap lines, promptless reads ---\n");
    RUN_TEST(test_residue_does_not_enter_next_body);
    RUN_TEST(test_trap_line_does_not_terminate_read);
    RUN_TEST(test_promptless_read_is_error);

    printf("\n--- Prompt learning ---\n");
    RUN_TEST(test_learn_prompt_confirms_across_two_probes);
    RUN_TEST(test_learn_prompt_refuses_when_unconfirmed);
    RUN_TEST(test_learn_prompt_waits_out_blank_echo_then_learns);
    RUN_TEST(test_learn_prompt_refuses_permanently_silent_device);
    RUN_TEST(test_learn_prompt_refuses_blank_echo_at_total_budget);
    RUN_TEST(test_read_refuses_without_learned_prompt);

    printf("\n--- PAN-OS keepalive window (2b) ---\n");
    RUN_TEST(test_keepalive_exchange_leaves_channel_clean);
    RUN_TEST(test_keepalive_without_prompt_is_error);

    printf("\n--- Scrubbing and drain accounting ---\n");
    RUN_TEST(test_strip_echo_matches_command_text);
    RUN_TEST(test_drain_reports_byte_count);

    printf("\n================================================================\n");
    printf("  Results: %d/%d passed%s\n", tests_run - tests_failed, tests_run,
           tests_failed ? "  (FAILED)" : "");
    printf("================================================================\n\n");
    return tests_failed ? 1 : 0;
}
