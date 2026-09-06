/*
 * test_driver_cisco_reconnect.c — defect C: stale-session dispatch
 *
 * Observed 2026-09-05 against SW-3850 (vty exec-timeout 10). The first
 * command after more than ~10 minutes idle ALWAYS failed with a
 * transport error. The daemon's liveness model is "assume connected
 * until a write fails or the watchdog sweeps", so the cached connection
 * was handed out, the write hit a channel the switch had already closed,
 * and the command failed. Deterministic, not flaky.
 *
 * The fix: on a write that fails because the PEER CLOSED (defect B's
 * VIRP_ERR_TRANSPORT_CLOSED), reconnect ONCE and retry the same literal.
 * One retry, never a loop. A reconnect that itself fails returns the
 * error.
 *
 * What must NOT retry:
 *   - a genuine command error (the device answered, it just said no)
 *   - an incomplete read (VIRP_ERR_NO_PROMPT)
 *   - a hard transport error that is not a closed peer
 *   - anything issued while we were inside config mode, where a silent
 *     reconnect would drop us back to exec mode and the same literal
 *     would no longer mean the same thing
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#include "../src/drivers/driver_cisco.c"

#include <stdio.h>
#include <string.h>

static int tests_run, tests_failed;

#define TEST(name) static void name(void)
#define RUN(name) do {                                              \
    tests_run++; printf("  %-58s", #name); name();                  \
} while (0)
#define FAIL(...) do {                                              \
    tests_failed++; printf("[FAIL]\n    "); printf(__VA_ARGS__);     \
    printf("\n"); return;                                           \
} while (0)
#define CHECK(cond, ...) do { if (!(cond)) FAIL(__VA_ARGS__); } while (0)
#define DONE() printf("[PASS]\n")

/* ── A scriptable stand-in for the channel ─────────────────────────── */
typedef struct {
    int   writes;
    int   fail_writes;      /* first N writes fail ... */
    ssize_t fail_code;      /* ... with this adapter code */
    const char *reply;      /* served after a successful write */
    char  pending[4096];
    size_t pending_len, pos;
} fake_chan_t;

static void fake_queue(fake_chan_t *f, const char *s)
{
    size_t n = strlen(s);
    if (f->pending_len + n >= sizeof(f->pending)) return;
    memcpy(f->pending + f->pending_len, s, n);
    f->pending_len += n;
}

static ssize_t fake_read(void *ctx, char *buf, size_t len)
{
    fake_chan_t *f = (fake_chan_t *)ctx;
    if (f->pos >= f->pending_len) return VIRP_SSH_IO_EAGAIN;
    size_t avail = f->pending_len - f->pos;
    size_t n = avail < len ? avail : len;
    memcpy(buf, f->pending + f->pos, n);
    f->pos += n;
    return (ssize_t)n;
}

static ssize_t fake_write(void *ctx, const char *buf, size_t len)
{
    fake_chan_t *f = (fake_chan_t *)ctx;
    (void)buf;
    f->writes++;
    if (f->fail_writes > 0) {
        f->fail_writes--;
        return f->fail_code;
    }
    if (f->reply) fake_queue(f, f->reply);
    return (ssize_t)len;
}

/* ── Reconnect stub ────────────────────────────────────────────────── */
static int   stub_reconnects;
static bool  stub_reconnect_succeeds;
static fake_chan_t *stub_chan;

static bool stub_reconnect(virp_conn_t *conn)
{
    stub_reconnects++;
    if (!stub_reconnect_succeeds)
        return false;
    /* A fresh session: the channel answers again, and we are back in
     * exec mode with a learned prompt. */
    stub_chan->fail_writes = 0;
    stub_chan->pending_len = stub_chan->pos = 0;
    conn->connected = true;
    conn->current_mode = CISCO_MODE_EXEC;
    return true;
}

static void setup(virp_conn_t *conn, fake_chan_t *f, const char *reply)
{
    memset(conn, 0, sizeof(*conn));
    memset(f, 0, sizeof(*f));
    f->reply = reply;
    stub_chan = f;
    stub_reconnects = 0;
    stub_reconnect_succeeds = true;

    snprintf(conn->device.hostname, sizeof(conn->device.hostname), "SW-3850");
    conn->sock_fd = -1;
    conn->connected = true;
    conn->current_mode = CISCO_MODE_EXEC;
    conn->io.ctx = f;
    conn->io.read = fake_read;
    conn->io.write = fake_write;
    snprintf(conn->prompt.prompt, sizeof(conn->prompt.prompt), "SW-3850#");
    conn->prompt.prompt_len = strlen(conn->prompt.prompt);
    conn->prompt.learned = true;

    cisco_reconnect_fn = stub_reconnect;
}

/* ── The defect ────────────────────────────────────────────────────── */

TEST(test_closed_peer_reconnects_once_and_completes)
{
    virp_conn_t conn; fake_chan_t f;
    setup(&conn, &f, "show clock\r\n12:00:00 UTC\r\nSW-3850#");
    f.fail_writes = 1;                   /* the idled-out session */
    f.fail_code   = VIRP_SSH_IO_CLOSED;

    virp_exec_result_t r;
    virp_error_t rc = cisco_execute(&conn, "show clock", &r);

    CHECK(rc == VIRP_OK,
          "a closed peer must be recovered by one reconnect, got %s (%d)",
          virp_error_str(rc), (int)rc);
    CHECK(stub_reconnects == 1,
          "expected exactly 1 reconnect, got %d", stub_reconnects);
    CHECK(r.success, "result must report success after the retry");
    CHECK(strstr(r.output, "12:00:00") != NULL,
          "the retried command's output must be returned, got '%s'",
          r.output);
    DONE();
}

TEST(test_reconnect_failure_returns_error_and_does_not_loop)
{
    virp_conn_t conn; fake_chan_t f;
    setup(&conn, &f, "SW-3850#");
    f.fail_writes = 99;                  /* stays dead */
    f.fail_code   = VIRP_SSH_IO_CLOSED;
    stub_reconnect_succeeds = false;

    virp_exec_result_t r;
    virp_error_t rc = cisco_execute(&conn, "show clock", &r);

    CHECK(rc != VIRP_OK, "a failed reconnect must surface an error");
    CHECK(stub_reconnects == 1,
          "one retry, never a loop — got %d reconnect attempts",
          stub_reconnects);
    DONE();
}

TEST(test_non_close_transport_error_does_not_reconnect)
{
    virp_conn_t conn; fake_chan_t f;
    setup(&conn, &f, "SW-3850#");
    f.fail_writes = 99;
    f.fail_code   = VIRP_SSH_IO_ERROR;   /* hard, but not a closed peer */

    virp_exec_result_t r;
    virp_error_t rc = cisco_execute(&conn, "show clock", &r);

    CHECK(rc != VIRP_OK, "a hard transport error must still be an error");
    CHECK(stub_reconnects == 0,
          "only a CLOSED peer warrants a reconnect; got %d attempts for a "
          "non-close error", stub_reconnects);
    DONE();
}

TEST(test_command_error_does_not_reconnect)
{
    virp_conn_t conn; fake_chan_t f;
    /* The device answered — it just did not like the command. That is a
     * command error, not a transport one: retrying would execute it twice. */
    setup(&conn, &f, "bogus\r\n% Invalid input detected at '^'.\r\nSW-3850#");

    virp_exec_result_t r;
    virp_error_t rc = cisco_execute(&conn, "bogus", &r);

    CHECK(rc == VIRP_OK, "a device-level rejection is a normal read");
    CHECK(stub_reconnects == 0,
          "a command error must never trigger a reconnect; got %d",
          stub_reconnects);
    DONE();
}

TEST(test_config_mode_is_not_silently_reconnected)
{
    /*
     * A reconnect drops us back to exec mode. Re-sending the same literal
     * would then mean something different (or nothing). Refuse the retry
     * and report the transport error honestly instead.
     */
    virp_conn_t conn; fake_chan_t f;
    setup(&conn, &f, "SW-3850(config)#");
    conn.current_mode = CISCO_MODE_CONFIG;
    f.fail_writes = 1;
    f.fail_code   = VIRP_SSH_IO_CLOSED;

    virp_exec_result_t r;
    virp_error_t rc = cisco_execute(&conn, "description uplink", &r);

    CHECK(rc != VIRP_OK,
          "a dropped config session must surface as an error, not a silent "
          "retry in the wrong mode");
    CHECK(stub_reconnects == 0,
          "must not silently reconnect out of config mode; got %d",
          stub_reconnects);
    DONE();
}

int main(void)
{
    printf("\n=== Cisco stale-session reconnect (defect C) ===\n\n");
    RUN(test_closed_peer_reconnects_once_and_completes);
    RUN(test_reconnect_failure_returns_error_and_does_not_loop);
    RUN(test_non_close_transport_error_does_not_reconnect);
    RUN(test_command_error_does_not_reconnect);
    RUN(test_config_mode_is_not_silently_reconnected);
    printf("\n=== Results: %d/%d passed ===\n\n",
           tests_run - tests_failed, tests_run);
    return tests_failed ? 1 : 0;
}
