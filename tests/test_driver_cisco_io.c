/*
 * test_driver_cisco_io.c — defect B: the libssh2 error code must survive
 *
 * Observed 2026-09-05 against SW-3850. cisco_io_write collapsed every
 * non-EAGAIN libssh2 error to a bare -1:
 *
 *     else
 *         return -1;
 *
 * So the one fact that would have explained the failure — the peer had
 * closed the channel after the vty session-timeout — was thrown away at
 * the adapter boundary. The O-Node saw "write failed", could not tell a
 * closed session from a broken one, and burned an approval retrying
 * nothing (defect D).
 *
 * Raw libssh2 codes must NOT be returned through the adapter: the shared
 * read path reads negatives in VIRP sentinel space, where EAGAIN is -2,
 * while libssh2's EAGAIN is -37 and libssh2's -2 is a banner error.
 * Returning raw would make a banner failure read as "retry forever". So
 * the adapter CLASSIFIES into VIRP space and PRESERVES the raw code on
 * the connection for the log and for defect C's reconnect decision.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#include "../src/drivers/driver_cisco.c"

#include <stdio.h>
#include <string.h>

static int tests_run, tests_failed;

#define TEST(name) static void name(void)
#define RUN(name) do {                                              \
    tests_run++;                                                    \
    printf("  %-58s", #name);                                       \
    name();                                                         \
} while (0)
#define FAIL(...) do {                                              \
    tests_failed++; printf("[FAIL]\n    "); printf(__VA_ARGS__);     \
    printf("\n"); return;                                           \
} while (0)
#define CHECK(cond, ...) do { if (!(cond)) FAIL(__VA_ARGS__); } while (0)
#define DONE() printf("[PASS]\n")

/*
 * The peer-closed family. Each of these means "this session is gone,
 * a reconnect is the correct response" — as opposed to a protocol or
 * allocation failure, where reconnecting would just fail again.
 */
TEST(test_peer_closed_codes_survive_as_closed)
{
    static const int closed[] = {
        LIBSSH2_ERROR_CHANNEL_CLOSED,
        LIBSSH2_ERROR_CHANNEL_EOF_SENT,
        LIBSSH2_ERROR_SOCKET_DISCONNECT,
        LIBSSH2_ERROR_SOCKET_SEND,
        LIBSSH2_ERROR_SOCKET_RECV,
    };
    for (size_t i = 0; i < sizeof(closed) / sizeof(closed[0]); i++) {
        virp_conn_t conn;
        memset(&conn, 0, sizeof(conn));

        ssize_t rc = cisco_io_write_error(&conn, closed[i]);

        CHECK(rc != -1,
              "libssh2 code %d collapsed to -1 — the peer-closed fact is "
              "lost and no caller can decide to reconnect", closed[i]);
        CHECK(rc == VIRP_SSH_IO_CLOSED,
              "libssh2 code %d must classify as VIRP_SSH_IO_CLOSED (%d), "
              "got %d", closed[i], (int)VIRP_SSH_IO_CLOSED, (int)rc);
        CHECK(conn.last_io_error == closed[i],
              "raw libssh2 code %d was not preserved on the connection "
              "(last_io_error=%d)", closed[i], conn.last_io_error);
    }
    DONE();
}

/*
 * A failure that is NOT the peer closing must stay distinguishable, or
 * defect C's reconnect would fire on everything and turn one honest
 * error into two.
 */
TEST(test_non_close_error_is_not_reported_as_closed)
{
    virp_conn_t conn;
    memset(&conn, 0, sizeof(conn));

    ssize_t rc = cisco_io_write_error(&conn, LIBSSH2_ERROR_ALLOC);

    CHECK(rc != VIRP_SSH_IO_CLOSED,
          "LIBSSH2_ERROR_ALLOC must not be reported as peer-closed — "
          "reconnecting cannot fix it");
    CHECK(rc == VIRP_SSH_IO_ERROR,
          "expected VIRP_SSH_IO_ERROR (%d), got %d",
          (int)VIRP_SSH_IO_ERROR, (int)rc);
    CHECK(conn.last_io_error == LIBSSH2_ERROR_ALLOC,
          "raw code must be preserved even when unclassified "
          "(last_io_error=%d)", conn.last_io_error);
    DONE();
}

/*
 * The adapter must never hand a raw libssh2 code back to the shared read
 * path. libssh2's EAGAIN is -37; VIRP's is -2. If the raw code leaked,
 * a genuine close could be read as "retry".
 */
TEST(test_classifier_never_returns_raw_libssh2_eagain)
{
    virp_conn_t conn;
    memset(&conn, 0, sizeof(conn));

    ssize_t rc = cisco_io_write_error(&conn, LIBSSH2_ERROR_EAGAIN);

    CHECK(rc != LIBSSH2_ERROR_EAGAIN,
          "raw LIBSSH2_ERROR_EAGAIN (%d) escaped into VIRP sentinel space",
          (int)LIBSSH2_ERROR_EAGAIN);
    CHECK(rc == VIRP_SSH_IO_CLOSED || rc == VIRP_SSH_IO_ERROR,
          "classifier must return a VIRP sentinel, got %d", (int)rc);
    DONE();
}

int main(void)
{
    printf("\n=== Cisco transport adapter: error preservation (defect B) ===\n\n");
    RUN(test_peer_closed_codes_survive_as_closed);
    RUN(test_non_close_error_is_not_reported_as_closed);
    RUN(test_classifier_never_returns_raw_libssh2_eagain);
    printf("\n=== Results: %d/%d passed ===\n\n",
           tests_run - tests_failed, tests_run);
    return tests_failed ? 1 : 0;
}
