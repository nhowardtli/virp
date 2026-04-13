/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * O-Node Integration Test
 *
 * Tests the FULL pipeline:
 *   1. Start O-Node with mock devices
 *   2. Connect as client over Unix socket
 *   3. Send JSON request
 *   4. Receive binary VIRP message
 *   5. Verify HMAC signature
 *   6. Parse observation payload
 *   7. Confirm device output is present and signed
 *
 * This proves the entire O-Node works end-to-end.
 */

#define _DEFAULT_SOURCE         /* usleep */
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_onode.h"
#include "virp_driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <arpa/inet.h>

/* =========================================================================
 * Test infrastructure
 * ========================================================================= */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(name) do { \
    printf("  %-60s", #name); \
    fflush(stdout); \
    name(); \
    tests_run++; \
    tests_passed++; \
    printf(" [PASS]\n"); \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf(" [FAIL]\n    Expected %d, got %d at line %d\n", \
               (int)(b), (int)(a), __LINE__); \
        tests_run++; tests_failed++; return; \
    } \
} while(0)

#define ASSERT_TRUE(x) ASSERT_EQ(!!(x), 1)
#define ASSERT_OK(x) ASSERT_EQ((x), VIRP_OK)

/* =========================================================================
 * Shared state
 * ========================================================================= */

#define TEST_SOCKET "/tmp/virp-onode-test.sock"
#define TEST_OKEY   "/tmp/virp-onode-test-okey.bin"

static onode_state_t g_state;
static pthread_t server_thread;

/* =========================================================================
 * O-Node server thread
 * ========================================================================= */

static void *onode_thread(void *arg)
{
    (void)arg;
    onode_start(&g_state);
    return NULL;
}

/* =========================================================================
 * Client helper — send request, receive VIRP message
 * ========================================================================= */

static int client_connect(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", TEST_SOCKET);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/*
 * Send a v2 framed request: [4-byte len][0x02 version][JSON]
 * Receive a v2 framed response: [4-byte len][payload]
 */
static ssize_t client_request(const char *json,
                              uint8_t *resp, size_t resp_len)
{
    int fd = client_connect();
    if (fd < 0) return -1;

    /* Send v2 framed request */
    size_t json_len = strlen(json);
    uint32_t frame_len = htonl((uint32_t)(1 + json_len));  /* version byte + JSON */
    send(fd, &frame_len, 4, 0);
    uint8_t version = VIRP_FRAME_VERSION;
    send(fd, &version, 1, 0);
    send(fd, json, json_len, 0);

    /* Brief pause to let O-Node process */
    usleep(50000);

    /* Read framed response: 4-byte length prefix + payload */
    uint32_t net_rlen;
    ssize_t nr = recv(fd, &net_rlen, 4, 0);
    if (nr != 4) { close(fd); return -1; }
    uint32_t rlen = ntohl(net_rlen);
    if (rlen > resp_len) { close(fd); return -1; }

    /* Read exact payload */
    size_t got = 0;
    while (got < rlen) {
        ssize_t n = recv(fd, resp + got, rlen - got, 0);
        if (n <= 0) { close(fd); return (ssize_t)got; }
        got += (size_t)n;
    }

    close(fd);
    return (ssize_t)rlen;
}

/* =========================================================================
 * Tests
 * ========================================================================= */

TEST(test_execute_show_ip_route)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", \"command\": \"show ip route\"}",
        resp, sizeof(resp));

    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    /* Verify the response is a valid signed VIRP OBSERVATION */
    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_OK(err);

    ASSERT_EQ(hdr.type, VIRP_MSG_OBSERVATION);
    ASSERT_EQ(hdr.channel, VIRP_CHANNEL_OC);
    ASSERT_EQ(hdr.tier, VIRP_TIER_GREEN);
    ASSERT_EQ(hdr.node_id, 0x06060606);    /* R6's node ID */

    /* Parse the observation payload */
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    err = virp_parse_observation(resp + VIRP_HEADER_SIZE,
                                 (size_t)n - VIRP_HEADER_SIZE,
                                 &obs, &data, &data_len);
    ASSERT_OK(err);
    ASSERT_EQ(obs.obs_type, VIRP_OBS_DEVICE_OUTPUT);
    ASSERT_EQ(obs.obs_scope, VIRP_SCOPE_LOCAL);
    ASSERT_TRUE(data_len > 0);

    /* Verify device output contains expected content */
    ASSERT_TRUE(strstr((const char *)data, "R6#show ip route") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "6.6.6.6") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "10.0.56.0") != NULL);
}

TEST(test_execute_show_bgp_summary)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", \"command\": \"show ip bgp summary\"}",
        resp, sizeof(resp));

    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_OBSERVATION);

    /* Verify BGP data is in the signed output */
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    virp_parse_observation(resp + VIRP_HEADER_SIZE,
                           (size_t)n - VIRP_HEADER_SIZE,
                           &obs, &data, &data_len);
    ASSERT_TRUE(strstr((const char *)data, "AS number 300") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "10.0.56.5") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "10.0.67.7") != NULL);
}

TEST(test_execute_different_devices)
{
    /* R5 */
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"R5\", \"command\": \"show version\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    virp_header_t hdr;
    virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_EQ(hdr.node_id, 0x05050505);    /* R5's node ID! */

    /* R7 */
    n = client_request(
        "{\"action\": \"execute\", \"device\": \"R7\", \"command\": \"show version\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_EQ(hdr.node_id, 0x07070707);    /* R7's node ID! */
}

TEST(test_device_not_found)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"FAKE\", \"command\": \"show version\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    /* Should still be a valid signed observation (error message) */
    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_OK(err);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    virp_parse_observation(resp + VIRP_HEADER_SIZE,
                           (size_t)n - VIRP_HEADER_SIZE,
                           &obs, &data, &data_len);
    ASSERT_TRUE(strstr((const char *)data, "not found") != NULL);
}

TEST(test_heartbeat)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"heartbeat\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_HEARTBEAT);
    ASSERT_EQ(hdr.channel, VIRP_CHANNEL_OC);

    virp_heartbeat_t hb;
    virp_parse_heartbeat(resp + VIRP_HEADER_SIZE,
                         (size_t)n - VIRP_HEADER_SIZE, &hb);
    ASSERT_EQ(hb.onode_ok, 1);
    ASSERT_EQ(hb.rnode_ok, 1);
}

TEST(test_list_devices)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"list_devices\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_OK(err);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    virp_parse_observation(resp + VIRP_HEADER_SIZE,
                           (size_t)n - VIRP_HEADER_SIZE,
                           &obs, &data, &data_len);
    ASSERT_TRUE(strstr((const char *)data, "R5") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "R6") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "R7") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "R8") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "4 devices") != NULL);
}

TEST(test_sequence_numbers_increment)
{
    uint8_t resp1[VIRP_MAX_MESSAGE_SIZE];
    uint8_t resp2[VIRP_MAX_MESSAGE_SIZE];

    ssize_t n1 = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", \"command\": \"show version\"}",
        resp1, sizeof(resp1));
    ssize_t n2 = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", \"command\": \"show version\"}",
        resp2, sizeof(resp2));

    ASSERT_TRUE(n1 > 0);
    ASSERT_TRUE(n2 > 0);

    virp_header_t hdr1, hdr2;
    virp_validate_message(resp1, (size_t)n1, &g_state.okey, &hdr1);
    virp_validate_message(resp2, (size_t)n2, &g_state.okey, &hdr2);

    /* Sequence numbers must be strictly increasing */
    ASSERT_TRUE(hdr2.seq_num > hdr1.seq_num);
}

TEST(test_tampered_response_fails_verify)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", \"command\": \"show version\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    /* Verify original is valid */
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr));

    /* Tamper with the payload */
    resp[VIRP_HEADER_SIZE + 10] ^= 0xFF;

    /* Must fail verification */
    virp_error_t err = virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_EQ(err, VIRP_ERR_HMAC_FAILED);
}

TEST(test_wrong_key_fails_verify)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", \"command\": \"show version\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    /* Create a different key */
    virp_signing_key_t fake_key;
    virp_key_generate(&fake_key, VIRP_KEY_TYPE_OKEY);

    /* Must fail with wrong key */
    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n, &fake_key, &hdr);
    ASSERT_EQ(err, VIRP_ERR_HMAC_FAILED);

    virp_key_destroy(&fake_key);
}

/* =========================================================================
 * Batch execution helpers
 * ========================================================================= */

/* Mock driver hooks (defined in driver_mock.c) */
extern void virp_driver_mock_set_delay(int ms);
extern void virp_driver_mock_set_forced_error(virp_error_t err);

static int recv_all(int fd, void *buf, size_t len)
{
    size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, (uint8_t *)buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    return 0;
}

/*
 * Send batch request and receive all results.
 * Returns count of results, fills resp[] and resp_len[].
 */
static int client_batch_request(const char *json,
                                 uint8_t resp[][VIRP_MAX_MESSAGE_SIZE],
                                 size_t resp_len[],
                                 int max_results)
{
    int fd = client_connect();
    if (fd < 0) return -1;

    /* Send v2 framed request */
    size_t json_len = strlen(json);
    uint32_t frame_len = htonl((uint32_t)(1 + json_len));
    send(fd, &frame_len, 4, 0);
    uint8_t version = VIRP_FRAME_VERSION;
    send(fd, &version, 1, 0);
    send(fd, json, json_len, 0);
    usleep(200000); /* Let threads complete */

    /* Read framed response: [4-byte outer len][batch payload] */
    uint32_t net_outer;
    if (recv_all(fd, &net_outer, 4) < 0) { close(fd); return -1; }
    uint32_t outer_len = ntohl(net_outer);

    /* Read entire batch payload */
    uint8_t *batch = malloc(outer_len);
    if (!batch) { close(fd); return -1; }
    if (recv_all(fd, batch, outer_len) < 0) { free(batch); close(fd); return -1; }

    /* Parse batch: 4-byte count, then per-result (4-byte len + data) */
    if (outer_len < 4) { free(batch); close(fd); return -1; }
    uint32_t net_count;
    memcpy(&net_count, batch, 4);
    int count = (int)ntohl(net_count);
    if (count > max_results) count = max_results;

    size_t off = 4;
    for (int i = 0; i < count; i++) {
        if (off + 4 > outer_len) { free(batch); close(fd); return i; }
        uint32_t net_len;
        memcpy(&net_len, batch + off, 4); off += 4;
        uint32_t msg_len = ntohl(net_len);
        if (msg_len > VIRP_MAX_MESSAGE_SIZE || off + msg_len > outer_len) {
            free(batch); close(fd); return i;
        }
        memcpy(resp[i], batch + off, msg_len); off += msg_len;
        resp_len[i] = msg_len;
    }

    free(batch);
    close(fd);
    return count;
}

static double time_ms(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

/* =========================================================================
 * Batch execution tests
 * ========================================================================= */

TEST(test_batch_execute_two_devices)
{
    uint8_t resp[4][VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len[4];

    int count = client_batch_request(
        "{\"action\":\"batch_execute\",\"commands\":["
        "{\"device\":\"R5\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show ip route\"}"
        "]}",
        resp, resp_len, 4);

    ASSERT_EQ(count, 2);

    /* Both results must be valid signed VIRP observations */
    virp_header_t hdr;
    virp_error_t err;

    err = virp_validate_message(resp[0], resp_len[0], &g_state.okey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_OBSERVATION);
    ASSERT_EQ(hdr.node_id, 0x05050505);  /* R5 */

    err = virp_validate_message(resp[1], resp_len[1], &g_state.okey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_OBSERVATION);
    ASSERT_EQ(hdr.node_id, 0x06060606);  /* R6 */

    /* Verify payload content */
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;

    virp_parse_observation(resp[0] + VIRP_HEADER_SIZE,
                           resp_len[0] - VIRP_HEADER_SIZE,
                           &obs, &data, &data_len);
    ASSERT_TRUE(strstr((const char *)data, "R5") != NULL);

    virp_parse_observation(resp[1] + VIRP_HEADER_SIZE,
                           resp_len[1] - VIRP_HEADER_SIZE,
                           &obs, &data, &data_len);
    ASSERT_TRUE(strstr((const char *)data, "10.0.56.0") != NULL);
}

TEST(test_batch_execute_four_devices)
{
    uint8_t resp[4][VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len[4];

    int count = client_batch_request(
        "{\"action\":\"batch_execute\",\"commands\":["
        "{\"device\":\"R5\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show version\"},"
        "{\"device\":\"R7\",\"command\":\"show version\"},"
        "{\"device\":\"R8\",\"command\":\"show version\"}"
        "]}",
        resp, resp_len, 4);

    ASSERT_EQ(count, 4);

    /* All four must have correct node IDs */
    uint32_t expected_ids[] = { 0x05050505, 0x06060606, 0x07070707, 0x08080808 };
    for (int i = 0; i < 4; i++) {
        virp_header_t hdr;
        ASSERT_OK(virp_validate_message(resp[i], resp_len[i], &g_state.okey, &hdr));
        ASSERT_EQ(hdr.node_id, expected_ids[i]);
    }
}

TEST(test_batch_execute_not_found_device)
{
    uint8_t resp[4][VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len[4];

    int count = client_batch_request(
        "{\"action\":\"batch_execute\",\"commands\":["
        "{\"device\":\"R5\",\"command\":\"show version\"},"
        "{\"device\":\"FAKE\",\"command\":\"show version\"}"
        "]}",
        resp, resp_len, 4);

    ASSERT_EQ(count, 2);

    /* R5 should succeed */
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(resp[0], resp_len[0], &g_state.okey, &hdr));
    ASSERT_EQ(hdr.node_id, 0x05050505);

    /* FAKE should still be a valid signed observation (error message) */
    ASSERT_OK(virp_validate_message(resp[1], resp_len[1], &g_state.okey, &hdr));

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    virp_parse_observation(resp[1] + VIRP_HEADER_SIZE,
                           resp_len[1] - VIRP_HEADER_SIZE,
                           &obs, &data, &data_len);
    ASSERT_TRUE(strstr((const char *)data, "not found") != NULL);
}

TEST(test_batch_execute_parallel_timing)
{
    /* Set 150ms delay per mock command */
    virp_driver_mock_set_delay(150);

    uint8_t resp[4][VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len[4];

    double t0 = time_ms();

    int count = client_batch_request(
        "{\"action\":\"batch_execute\",\"commands\":["
        "{\"device\":\"R5\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show version\"}"
        "]}",
        resp, resp_len, 4);

    double elapsed = time_ms() - t0;

    /* Reset delay */
    virp_driver_mock_set_delay(0);

    ASSERT_EQ(count, 2);

    /* Both devices take 150ms each. Parallel: ~150ms total.
     * Sequential would be ~300ms. Allow generous margin but
     * require less than 280ms to prove parallelism. */
    ASSERT_TRUE(elapsed < 280.0);

    /* Verify results are valid */
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(resp[0], resp_len[0], &g_state.okey, &hdr));
    ASSERT_OK(virp_validate_message(resp[1], resp_len[1], &g_state.okey, &hdr));
}

TEST(test_batch_sequence_numbers_unique)
{
    uint8_t resp[4][VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len[4];

    int count = client_batch_request(
        "{\"action\":\"batch_execute\",\"commands\":["
        "{\"device\":\"R5\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show version\"},"
        "{\"device\":\"R7\",\"command\":\"show version\"}"
        "]}",
        resp, resp_len, 4);

    ASSERT_EQ(count, 3);

    /* All sequence numbers must be unique */
    uint32_t seqs[3];
    for (int i = 0; i < 3; i++) {
        virp_header_t hdr;
        ASSERT_OK(virp_validate_message(resp[i], resp_len[i], &g_state.okey, &hdr));
        seqs[i] = hdr.seq_num;
    }
    ASSERT_TRUE(seqs[0] != seqs[1]);
    ASSERT_TRUE(seqs[0] != seqs[2]);
    ASSERT_TRUE(seqs[1] != seqs[2]);
}

TEST(test_batch_same_device_concurrent)
{
    /*
     * Send 8 parallel commands to the SAME device (R6) with a mock delay.
     * The per-device exec_mutex serializes access so that libssh2 is
     * never driven concurrently. All 8 results must be valid signed
     * observations with the correct node_id and non-empty payload.
     */
    virp_driver_mock_set_delay(20);  /* 20ms per command */

    uint8_t resp[8][VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len[8];

    int count = client_batch_request(
        "{\"action\":\"batch_execute\",\"commands\":["
        "{\"device\":\"R6\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show ip route\"},"
        "{\"device\":\"R6\",\"command\":\"show ip bgp summary\"},"
        "{\"device\":\"R6\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show ip route\"},"
        "{\"device\":\"R6\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show ip route\"},"
        "{\"device\":\"R6\",\"command\":\"show version\"}"
        "]}",
        resp, resp_len, 8);

    virp_driver_mock_set_delay(0);

    ASSERT_EQ(count, 8);

    /* Every response must be a valid signed observation for R6 */
    for (int i = 0; i < 8; i++) {
        virp_header_t hdr;
        virp_error_t err = virp_validate_message(resp[i], resp_len[i],
                                                  &g_state.okey, &hdr);
        ASSERT_OK(err);
        ASSERT_EQ(hdr.type, VIRP_MSG_OBSERVATION);
        ASSERT_EQ(hdr.node_id, 0x06060606);  /* R6 */

        /* Parse payload — must be non-empty */
        virp_observation_t obs;
        const uint8_t *data;
        uint16_t data_len;
        err = virp_parse_observation(resp[i] + VIRP_HEADER_SIZE,
                                      resp_len[i] - VIRP_HEADER_SIZE,
                                      &obs, &data, &data_len);
        ASSERT_OK(err);
        ASSERT_TRUE(data_len > 0);
    }

    /* All sequence numbers must be unique (no races on seq_num) */
    uint32_t seqs[8];
    for (int i = 0; i < 8; i++) {
        virp_header_t hdr;
        virp_validate_message(resp[i], resp_len[i], &g_state.okey, &hdr);
        seqs[i] = hdr.seq_num;
    }
    for (int i = 0; i < 8; i++) {
        for (int j = i + 1; j < 8; j++) {
            ASSERT_TRUE(seqs[i] != seqs[j]);
        }
    }
}

TEST(test_v1_unframed_client_rejected)
{
    /*
     * A v1 client sends raw JSON (starts with '{' = 0x7B).
     * The server should respond with unframed VIRP_ERR_PROTOCOL_VERSION
     * and close the connection.
     */
    int fd = client_connect();
    ASSERT_TRUE(fd >= 0);

    /* Send raw JSON (v1 style — no frame prefix) */
    const char *v1_json = "{\"action\":\"heartbeat\"}";
    send(fd, v1_json, strlen(v1_json), 0);
    usleep(50000);

    /* Should receive a raw 4-byte error code (not framed) */
    uint32_t net_err;
    ssize_t n = recv(fd, &net_err, 4, 0);
    ASSERT_EQ((int)n, 4);

    int32_t err = (int32_t)ntohl(net_err);
    ASSERT_EQ(err, VIRP_ERR_PROTOCOL_VERSION);

    /* Connection should be closed by server */
    char extra;
    ssize_t more = recv(fd, &extra, 1, 0);
    ASSERT_TRUE(more <= 0);  /* EOF */

    close(fd);
}

/* =========================================================================
 * Signed error observation tests
 * ========================================================================= */

TEST(test_driver_error_returns_signed_observation)
{
    /*
     * When drv->execute() returns a non-VIRP_OK error (not just
     * result.success=false), the O-Node MUST still emit a signed
     * VIRP_OBS_ERROR observation — never an unsigned 4-byte error code.
     * This ensures the R-Node receives a verifiable failure receipt.
     */

    /* Arm mock driver to return VIRP_ERR_CRYPTO on next execute */
    virp_driver_mock_set_forced_error(VIRP_ERR_CRYPTO);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", \"command\": \"show version\"}",
        resp, sizeof(resp));

    /* Disarm so subsequent tests aren't affected */
    virp_driver_mock_set_forced_error(VIRP_OK);

    /* Response must be a full VIRP message, not a 4-byte error code */
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    /* Must be a valid, signed observation */
    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.type, VIRP_MSG_OBSERVATION);
    ASSERT_EQ(hdr.channel, VIRP_CHANNEL_OC);

    /* Parse observation — must be VIRP_OBS_ERROR with descriptive text */
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    err = virp_parse_observation(resp + VIRP_HEADER_SIZE,
                                 (size_t)n - VIRP_HEADER_SIZE,
                                 &obs, &data, &data_len);
    ASSERT_OK(err);
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(data_len > 0);
    ASSERT_TRUE(strstr((const char *)data, "driver execute failed") != NULL);
}

/* =========================================================================
 * hex_decode unit tests
 * ========================================================================= */

TEST(test_hex_decode_empty_string)
{
    uint8_t out[16];
    ASSERT_EQ(virp_hex_decode("", out, sizeof(out)), 0);
}

TEST(test_hex_decode_odd_length)
{
    uint8_t out[16];
    ASSERT_EQ(virp_hex_decode("abc", out, sizeof(out)), -1);
}

TEST(test_hex_decode_valid_lowercase)
{
    uint8_t out[4];
    ASSERT_EQ(virp_hex_decode("deadbeef", out, sizeof(out)), 4);
    ASSERT_EQ(out[0], 0xde);
    ASSERT_EQ(out[1], 0xad);
    ASSERT_EQ(out[2], 0xbe);
    ASSERT_EQ(out[3], 0xef);
}

TEST(test_hex_decode_valid_uppercase)
{
    uint8_t out[4];
    ASSERT_EQ(virp_hex_decode("DEADBEEF", out, sizeof(out)), 4);
    ASSERT_EQ(out[0], 0xde);
    ASSERT_EQ(out[1], 0xad);
    ASSERT_EQ(out[2], 0xbe);
    ASSERT_EQ(out[3], 0xef);
}

TEST(test_hex_decode_mixed_case)
{
    uint8_t out[3];
    ASSERT_EQ(virp_hex_decode("aAbBcC", out, sizeof(out)), 3);
    ASSERT_EQ(out[0], 0xaa);
    ASSERT_EQ(out[1], 0xbb);
    ASSERT_EQ(out[2], 0xcc);
}

TEST(test_hex_decode_embedded_space)
{
    uint8_t out[16];
    ASSERT_EQ(virp_hex_decode("de ad", out, sizeof(out)), -1);
}

TEST(test_hex_decode_embedded_plus)
{
    uint8_t out[16];
    ASSERT_EQ(virp_hex_decode("de+d", out, sizeof(out)), -1);
}

TEST(test_hex_decode_embedded_0x)
{
    uint8_t out[16];
    ASSERT_EQ(virp_hex_decode("0xab", out, sizeof(out)), -1);
}

TEST(test_hex_decode_oversized_input)
{
    uint8_t out[2];
    /* 6 hex chars = 3 bytes, but out only holds 2 */
    ASSERT_EQ(virp_hex_decode("aabbcc", out, sizeof(out)), -1);
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(void)
{
    printf("\n");
    printf("================================================================\n");
    printf("  VIRP O-Node Integration Tests\n");
    printf("  Copyright (c) 2026 Third Level IT LLC\n");
    printf("================================================================\n\n");

    /* Initialize drivers */
    virp_driver_mock_init();

    /* Initialize O-Node */
    unlink(TEST_OKEY);
    virp_error_t err = onode_init(&g_state, 0x00000001, NULL, TEST_SOCKET);
    if (err != VIRP_OK) {
        fprintf(stderr, "Failed to init O-Node: %s\n", virp_error_str(err));
        return 1;
    }

    /* Allocate the protocol context owned by this test process. */
    g_state.ctx = virp_context_new();
    if (!g_state.ctx) {
        fprintf(stderr, "Failed to allocate virp_context_t\n");
        return 1;
    }

    /* Add mock devices */
    virp_device_t devices[] = {
        { .hostname = "R5", .host = "10.0.0.5", .port = 22,
          .vendor = VIRP_VENDOR_MOCK, .node_id = 0x05050505, .enabled = true },
        { .hostname = "R6", .host = "10.0.0.6", .port = 22,
          .vendor = VIRP_VENDOR_MOCK, .node_id = 0x06060606, .enabled = true },
        { .hostname = "R7", .host = "10.0.0.7", .port = 22,
          .vendor = VIRP_VENDOR_MOCK, .node_id = 0x07070707, .enabled = true },
        { .hostname = "R8", .host = "10.0.0.8", .port = 22,
          .vendor = VIRP_VENDOR_MOCK, .node_id = 0x08080808, .enabled = true },
    };
    for (size_t i = 0; i < 4; i++)
        onode_add_device(&g_state, &devices[i]);

    /* Start O-Node in background thread */
    pthread_create(&server_thread, NULL, onode_thread, NULL);
    usleep(200000);  /* Wait for socket to be ready */

    printf("[hex_decode Unit Tests]\n");
    RUN_TEST(test_hex_decode_empty_string);
    RUN_TEST(test_hex_decode_odd_length);
    RUN_TEST(test_hex_decode_valid_lowercase);
    RUN_TEST(test_hex_decode_valid_uppercase);
    RUN_TEST(test_hex_decode_mixed_case);
    RUN_TEST(test_hex_decode_embedded_space);
    RUN_TEST(test_hex_decode_embedded_plus);
    RUN_TEST(test_hex_decode_embedded_0x);
    RUN_TEST(test_hex_decode_oversized_input);

    printf("\n[O-Node Pipeline Tests]\n");
    RUN_TEST(test_execute_show_ip_route);
    RUN_TEST(test_execute_show_bgp_summary);
    RUN_TEST(test_execute_different_devices);
    RUN_TEST(test_device_not_found);
    RUN_TEST(test_heartbeat);
    RUN_TEST(test_list_devices);
    RUN_TEST(test_sequence_numbers_increment);
    RUN_TEST(test_tampered_response_fails_verify);
    RUN_TEST(test_wrong_key_fails_verify);

    printf("\n[O-Node Batch Execution Tests]\n");
    RUN_TEST(test_batch_execute_two_devices);
    RUN_TEST(test_batch_execute_four_devices);
    RUN_TEST(test_batch_execute_not_found_device);
    RUN_TEST(test_batch_execute_parallel_timing);
    RUN_TEST(test_batch_sequence_numbers_unique);
    RUN_TEST(test_batch_same_device_concurrent);

    printf("\n[v2 Framing Tests]\n");
    RUN_TEST(test_v1_unframed_client_rejected);

    printf("\n[Signed Error Observation Tests]\n");
    RUN_TEST(test_driver_error_returns_signed_observation);

    /* Shutdown */
    onode_shutdown(&g_state);
    pthread_join(server_thread, NULL);
    onode_destroy(&g_state);
    virp_context_destroy(g_state.ctx);
    g_state.ctx = NULL;

    printf("\n================================================================\n");
    printf("  Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (%d FAILED)", tests_failed);
    printf("\n================================================================\n\n");

    return (tests_failed > 0) ? 1 : 0;
}
