/*
 * test_driver_linux_connect.c — device connect must be time-bounded
 *
 * Item 6 (2026-08-11): the AF_UNSPEC fix (89905908) made dual-stack
 * hosts reachable, but a blocking connect(2) to an address whose SYNs
 * are silently dropped holds the caller for ~130 s per address
 * (tcp_syn_retries), on the single serial watchdog thread everything
 * else queues behind. SO_RCVTIMEO/SO_SNDTIMEO do not bound connect(2).
 *
 * This suite pins the bound: a connect toward a SYN-blackholed address
 * must return within the driver's connect timeout (plus slack), never
 * the kernel's retry horizon. The assertion is on TIME, not on the
 * outcome — on a network where the probe address answers or refuses,
 * the bound still holds trivially.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#include "virp_driver.h"

/* Defined in driver_linux.c, exposed for this suite. */
int linux_tcp_connect(const char *host, uint16_t port);

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

#define FAIL(...) do {                                \
    printf(" [FAIL]\n    ");                          \
    printf(__VA_ARGS__);                              \
    printf("\n");                                     \
    tests_failed++;                                   \
    return;                                           \
} while (0)

#define CHECK(cond, ...) do { if (!(cond)) FAIL(__VA_ARGS__); } while (0)

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

/* Driver bound is SSH_CONNECT_TIMEOUT_SEC (10 s) per address family;
 * allow one A + one AAAA candidate plus scheduling slack. */
#define CONNECT_BOUND_MS 25000

TEST(test_blackhole_connect_is_bounded)
{
    /* RFC1918 address routed at the default gateway and silently
     * dropped there (verified SYN blackhole in this lab). A blocking
     * connect sits in tcp_syn_retries for ~130 s; the bounded connect
     * must give up at the driver timeout. */
    uint64_t t0 = now_ms();
    int fd = linux_tcp_connect("172.31.255.1", 22);
    uint64_t elapsed = now_ms() - t0;
    if (fd >= 0) close(fd);

    CHECK(elapsed < CONNECT_BOUND_MS,
          "connect not time-bounded: %llu ms (watchdog-stalling)",
          (unsigned long long)elapsed);
}

TEST(test_reachable_connect_still_works)
{
    /* Loopback SSH on this host — the bound must not break the
     * ordinary fast path. If nothing listens on 22, a fast refusal
     * is equally fine; only a stall is a failure. */
    uint64_t t0 = now_ms();
    int fd = linux_tcp_connect("127.0.0.1", 22);
    uint64_t elapsed = now_ms() - t0;
    if (fd >= 0) close(fd);

    CHECK(elapsed < 5000,
          "loopback connect took %llu ms", (unsigned long long)elapsed);
}

int main(void)
{
    printf("test_driver_linux_connect:\n");

    RUN_TEST(test_blackhole_connect_is_bounded);
    RUN_TEST(test_reachable_connect_still_works);

    printf("\n%d tests, %d failures\n", tests_run, tests_failed);
    return tests_failed ? 1 : 0;
}
