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
#include <fcntl.h>

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
    /* Item 1 audit-honesty: the observation records the ACTUAL
     * gate-classified tier. The mock driver's classifier routes
     * "show ip route" to GREEN, so GREEN must appear on the wire.
     * (UNCLASSIFIED honesty is asserted end-to-end by
     * test_gate_enforce_blocks_unclassified below, where the ENFORCE
     * default rejects an unclassifiable command.) */
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

/*
 * ENFORCE-default gate: a command the classifier cannot place
 * (UNCLASSIFIED) must be hard-rejected before the driver runs, and the
 * signed error observation must record UNCLASSIFIED honestly.
 */
TEST(test_gate_enforce_blocks_unclassified)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", "
        "\"command\": \"frobnicate the flux capacitor\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n,
                                             &g_state.okey, &hdr);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.tier, VIRP_TIER_UNCLASSIFIED);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    err = virp_parse_observation(resp + VIRP_HEADER_SIZE,
                                 (size_t)n - VIRP_HEADER_SIZE,
                                 &obs, &data, &data_len);
    ASSERT_OK(err);
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(strstr((const char *)data, "tier gate blocked") != NULL);
}

/*
 * v2 observations are session-bound: an execute with obs_version 2 and
 * no ACTIVE session must fail with SESSION_INVALID — never silently
 * fall back to master-key signing.
 */
TEST(test_execute_v2_without_session_fails)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", "
        "\"command\": \"show version\", \"obs_version\": 2}",
        resp, sizeof(resp));

    /* Framed error: exactly 4 bytes, big-endian error code */
    ASSERT_EQ((int)n, 4);
    uint32_t code_n;
    memcpy(&code_n, resp, 4);
    ASSERT_EQ((int32_t)ntohl(code_n), (int32_t)VIRP_ERR_SESSION_INVALID);
}

/* Tiny JSON string extractor for the handshake responses (test-only). */
static bool json_find_str(const char *json, const char *key,
                          char *out, size_t out_sz)
{
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    const char *p = strstr(json, pat);
    if (!p) return false;
    p += strlen(pat);
    size_t i = 0;
    while (p[i] && p[i] != '"' && i < out_sz - 1) {
        out[i] = p[i];
        i++;
    }
    out[i] = '\0';
    return p[i] == '"';
}

/*
 * Full v2 round trip over the socket: JSON handshake to ACTIVE, execute
 * with obs_version 2, verify the returned wire message with
 * virp_verify_observation_v2 (same-process ctx doubles as the verifier
 * context), then demonstrate the negative properties end-to-end:
 * replay, command substitution, device substitution.
 */
TEST(test_execute_v2_session_bound_roundtrip)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];

    /* 1 — SESSION_HELLO */
    ssize_t n = client_request(
        "{\"action\": \"session_hello\", \"client_id\": \"test-onode-v2\", "
        "\"client_nonce\": \"0011223344556677\"}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > 0);
    resp[n] = '\0';

    char sid[64], cn[32], sn[32];
    ASSERT_TRUE(json_find_str((const char *)resp, "session_id",
                              sid, sizeof(sid)));
    ASSERT_TRUE(json_find_str((const char *)resp, "client_nonce",
                              cn, sizeof(cn)));
    ASSERT_TRUE(json_find_str((const char *)resp, "server_nonce",
                              sn, sizeof(sn)));

    /* 2 — SESSION_BIND (daemon derives the session key → ACTIVE) */
    char bind_req[512];
    snprintf(bind_req, sizeof(bind_req),
             "{\"action\": \"session_bind\", \"client_id\": \"test-onode-v2\", "
             "\"session_id\": \"%s\", \"client_nonce\": \"%s\", "
             "\"server_nonce\": \"%s\"}", sid, cn, sn);
    n = client_request(bind_req, resp, sizeof(resp));
    ASSERT_TRUE(n > 0);
    resp[n] = '\0';
    ASSERT_TRUE(strstr((const char *)resp, "\"bound\"") != NULL);

    /* 3 — execute with obs_version 2 */
    n = client_request(
        "{\"action\": \"execute\", \"device\": \"R6\", "
        "\"command\": \"show ip route\", \"obs_version\": 2}",
        resp, sizeof(resp));
    ASSERT_TRUE(n >= (ssize_t)VIRP_OBS_V2_MIN_SIZE);

    /* 4 — verify with the session context */
    virp_seqstore_t store;
    ASSERT_OK(virp_seqstore_init(&store, NULL));

    uint64_t r6_id = virp_device_id_from_hostname("R6");
    virp_obs_header_v2_t hdr;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    virp_error_t err = virp_verify_observation_v2(
        g_state.ctx, r6_id, "show ip route",
        resp, (size_t)n, 0, &store, &hdr, &payload, &payload_len);
    ASSERT_OK(err);
    ASSERT_EQ(hdr.version, VIRP_VERSION_2);
    ASSERT_EQ(hdr.tier, VIRP_TIER_GREEN);
    ASSERT_TRUE(hdr.device_id == r6_id);
    ASSERT_TRUE(payload != NULL && payload_len > 0);
    ASSERT_TRUE(payload != NULL &&
                memmem(payload, payload_len, "6.6.6.6", 7) != NULL);

    /* 5 — REPLAY: the identical bytes must be rejected */
    err = virp_verify_observation_v2(
        g_state.ctx, r6_id, "show ip route",
        resp, (size_t)n, 0, &store, NULL, NULL, NULL);
    ASSERT_EQ(err, VIRP_ERR_REPLAY_DETECTED);

    /* 6 — COMMAND SUBSTITUTION: a validly signed observation for
     * command A must not verify against a request for command B */
    virp_seqstore_t store2;
    ASSERT_OK(virp_seqstore_init(&store2, NULL));
    err = virp_verify_observation_v2(
        g_state.ctx, r6_id, "show running-config",
        resp, (size_t)n, 0, &store2, NULL, NULL, NULL);
    ASSERT_EQ(err, VIRP_ERR_CONTEXT_MISMATCH);

    /* 7 — DEVICE SUBSTITUTION: same bytes, wrong expected device */
    err = virp_verify_observation_v2(
        g_state.ctx, virp_device_id_from_hostname("R7"), "show ip route",
        resp, (size_t)n, 0, &store2, NULL, NULL, NULL);
    ASSERT_EQ(err, VIRP_ERR_CONTEXT_MISMATCH);

    virp_seqstore_destroy(&store);
    virp_seqstore_destroy(&store2);

    /* 8 — close the session so later tests see no active session */
    n = client_request("{\"action\": \"session_close\"}", resp, sizeof(resp));
    ASSERT_TRUE(n > 0);
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

/*
 * Batch must honor obs_version: a batch that asked for session binding
 * gets v2 observations for every item — and with no session, every
 * item fails with SESSION_INVALID instead of silently downgrading to
 * master-key v1 signing.
 */
TEST(test_batch_execute_v2_honors_obs_version)
{
    uint8_t resp[4][VIRP_MAX_MESSAGE_SIZE];
    size_t resp_len[4];

    /* No session yet: every item must be a 4-byte SESSION_INVALID */
    int count = client_batch_request(
        "{\"action\":\"batch_execute\",\"obs_version\":2,\"commands\":["
        "{\"device\":\"R5\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show ip route\"}"
        "]}",
        resp, resp_len, 4);
    ASSERT_EQ(count, 2);
    for (int i = 0; i < 2; i++) {
        ASSERT_EQ((int)resp_len[i], 4);
        uint32_t code_n;
        memcpy(&code_n, resp[i], 4);
        ASSERT_EQ((int32_t)ntohl(code_n), (int32_t)VIRP_ERR_SESSION_INVALID);
    }

    /* Handshake, then the same batch must yield verifiable v2 wire
     * messages for both items */
    uint8_t hs[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"session_hello\", \"client_id\": \"batch-v2\", "
        "\"client_nonce\": \"8899aabbccddeeff\"}", hs, sizeof(hs));
    ASSERT_TRUE(n > 0);
    hs[n] = '\0';
    char sid[64], cn[32], sn[32];
    ASSERT_TRUE(json_find_str((const char *)hs, "session_id", sid, sizeof(sid)));
    ASSERT_TRUE(json_find_str((const char *)hs, "client_nonce", cn, sizeof(cn)));
    ASSERT_TRUE(json_find_str((const char *)hs, "server_nonce", sn, sizeof(sn)));
    char bind_req[512];
    snprintf(bind_req, sizeof(bind_req),
             "{\"action\": \"session_bind\", \"client_id\": \"batch-v2\", "
             "\"session_id\": \"%s\", \"client_nonce\": \"%s\", "
             "\"server_nonce\": \"%s\"}", sid, cn, sn);
    n = client_request(bind_req, hs, sizeof(hs));
    ASSERT_TRUE(n > 0);

    count = client_batch_request(
        "{\"action\":\"batch_execute\",\"obs_version\":2,\"commands\":["
        "{\"device\":\"R5\",\"command\":\"show version\"},"
        "{\"device\":\"R6\",\"command\":\"show ip route\"}"
        "]}",
        resp, resp_len, 4);
    ASSERT_EQ(count, 2);

    virp_seqstore_t store;
    ASSERT_OK(virp_seqstore_init(&store, NULL));
    virp_obs_header_v2_t hdr;

    ASSERT_OK(virp_verify_observation_v2(g_state.ctx,
        virp_device_id_from_hostname("R5"), "show version",
        resp[0], resp_len[0], 0, &store, &hdr, NULL, NULL));
    ASSERT_EQ(hdr.version, VIRP_VERSION_2);

    ASSERT_OK(virp_verify_observation_v2(g_state.ctx,
        virp_device_id_from_hostname("R6"), "show ip route",
        resp[1], resp_len[1], 0, &store, &hdr, NULL, NULL));
    ASSERT_EQ(hdr.version, VIRP_VERSION_2);

    virp_seqstore_destroy(&store);

    /* Over-long command pre-flight: must fail BEFORE device I/O with
     * INVALID_LENGTH (canonical form exceeds the 512-byte hash buffer) */
    {
        char long_cmd[700];
        memset(long_cmd, 'x', sizeof(long_cmd) - 1);
        long_cmd[sizeof(long_cmd) - 1] = '\0';
        char req_buf[1200];
        snprintf(req_buf, sizeof(req_buf),
                 "{\"action\":\"execute\",\"device\":\"R6\","
                 "\"command\":\"%s\",\"obs_version\":2}", long_cmd);
        uint8_t r2[64];
        ssize_t rn = client_request(req_buf, r2, sizeof(r2));
        ASSERT_EQ((int)rn, 4);
        uint32_t code_n;
        memcpy(&code_n, r2, 4);
        ASSERT_EQ((int32_t)ntohl(code_n), (int32_t)VIRP_ERR_INVALID_LENGTH);
    }

    n = client_request("{\"action\": \"session_close\"}", hs, sizeof(hs));
    ASSERT_TRUE(n > 0);
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

TEST(test_framed_request_split_across_three_sends)
{
    /*
     * Exercise the recv_exact loop in handle_client by splitting a
     * single framed request across three send() calls with jittered
     * delays. A correct implementation must accumulate partial reads
     * and parse the full request; a buggy one that treats each recv()
     * as a complete frame will error or hang.
     *
     * Wire layout sent:
     *   [4-byte BE length][0x02 version][JSON]
     *
     * Split points:
     *   send 1: 2 of 4 prefix bytes
     *   send 2: remaining 2 prefix bytes + version byte
     *   send 3: JSON payload
     */
    int fd = client_connect();
    ASSERT_TRUE(fd >= 0);

    const char *json = "{\"action\":\"heartbeat\"}";
    size_t json_len = strlen(json);
    uint32_t frame_len = (uint32_t)(1 + json_len);  /* version + JSON */
    uint8_t prefix[4] = {
        (uint8_t)(frame_len >> 24),
        (uint8_t)(frame_len >> 16),
        (uint8_t)(frame_len >>  8),
        (uint8_t)(frame_len),
    };
    uint8_t version = VIRP_FRAME_VERSION;

    /* Jittered delays between 10–40ms to force the server through the
     * partial-read branch of recv_exact(). Deterministic seed keeps
     * the test reproducible. */
    srand(0xA77);
    useconds_t d1 = 10000 + (useconds_t)(rand() % 30000);
    useconds_t d2 = 10000 + (useconds_t)(rand() % 30000);

    ASSERT_EQ((int)send(fd, prefix, 2, 0), 2);
    usleep(d1);
    uint8_t mid[3] = { prefix[2], prefix[3], version };
    ASSERT_EQ((int)send(fd, mid, 3, 0), 3);
    usleep(d2);
    ASSERT_EQ((int)send(fd, json, json_len, 0), (ssize_t)json_len);

    /* Read framed response and verify it is a valid signed HEARTBEAT */
    uint32_t net_rlen;
    ASSERT_EQ((int)recv(fd, &net_rlen, 4, MSG_WAITALL), 4);
    uint32_t rlen = ntohl(net_rlen);
    ASSERT_TRUE(rlen >= VIRP_HEADER_SIZE);
    ASSERT_TRUE(rlen <= VIRP_MAX_MESSAGE_SIZE);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    size_t got = 0;
    while (got < rlen) {
        ssize_t n = recv(fd, resp + got, rlen - got, 0);
        ASSERT_TRUE(n > 0);
        got += (size_t)n;
    }
    close(fd);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(resp, rlen, &g_state.okey, &hdr));
    ASSERT_EQ(hdr.type, VIRP_MSG_HEARTBEAT);
}

TEST(test_framed_oversize_length_rejected)
{
    /*
     * An attacker-controlled length prefix that exceeds
     * ONODE_MAX_REQUEST_SIZE must be rejected before any payload
     * bytes are read. Expect a framed VIRP_ERR_MESSAGE_TOO_LARGE and
     * an immediate server-side close.
     */
    int fd = client_connect();
    ASSERT_TRUE(fd >= 0);

    uint32_t huge = (uint32_t)ONODE_MAX_REQUEST_SIZE + 1024;
    uint8_t prefix[4] = {
        (uint8_t)(huge >> 24),
        (uint8_t)(huge >> 16),
        (uint8_t)(huge >>  8),
        (uint8_t)(huge),
    };
    ASSERT_EQ((int)send(fd, prefix, 4, 0), 4);

    /* Expect framed error: 4-byte length prefix = 4, then int32 error */
    uint32_t net_rlen;
    ASSERT_EQ((int)recv(fd, &net_rlen, 4, MSG_WAITALL), 4);
    ASSERT_EQ((int)ntohl(net_rlen), 4);

    uint32_t net_err;
    ASSERT_EQ((int)recv(fd, &net_err, 4, MSG_WAITALL), 4);
    int32_t err = (int32_t)ntohl(net_err);
    ASSERT_EQ(err, VIRP_ERR_MESSAGE_TOO_LARGE);

    /* Server should close — no payload bytes were ever read. */
    uint8_t extra;
    ssize_t more = recv(fd, &extra, 1, 0);
    ASSERT_TRUE(more <= 0);

    close(fd);
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
 * Worker pool / head-of-line-blocking test
 *
 * Confirms that a slow command on one connection does NOT block other
 * connections. With the old synchronous accept loop, 9 heartbeats
 * queued behind a 400ms-slow execute would complete over ~3.6s (serial).
 * With the worker pool, they overlap and finish in ~500ms total.
 * ========================================================================= */

typedef struct {
    int          slot;
    double       start_ms;
    double       end_ms;
    int          ok;
    uint8_t      msg_type;
} hol_result_t;

typedef struct {
    hol_result_t *result;
    const char   *json;
} hol_client_arg_t;

static void *hol_client_thread(void *raw)
{
    hol_client_arg_t *ca = (hol_client_arg_t *)raw;
    hol_result_t *r = ca->result;

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    r->start_ms = time_ms();
    ssize_t n = client_request(ca->json, resp, sizeof(resp));
    r->end_ms = time_ms();

    if (n <= (ssize_t)VIRP_HEADER_SIZE) {
        r->ok = 0;
        return NULL;
    }

    virp_header_t hdr;
    if (virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr) != VIRP_OK) {
        r->ok = 0;
        return NULL;
    }
    r->msg_type = (uint8_t)hdr.type;
    r->ok = 1;
    return NULL;
}

TEST(test_concurrent_clients_no_head_of_line)
{
    /*
     * Ten parallel clients:
     *   - slot 0 sends an execute on R6 that sleeps 400ms inside the
     *     mock driver.
     *   - slots 1-9 send heartbeats (no driver, fast path).
     *
     * Expected: all succeed, and the slow execute runs concurrently
     * with the heartbeats — the median heartbeat latency must be far
     * below the slow-command latency.
     */
    const int N = 10;
    const int SLOW_MS = 400;

    virp_driver_mock_set_delay(SLOW_MS);

    pthread_t     threads[N];
    hol_result_t  results[N];
    hol_client_arg_t args[N];
    memset(results, 0, sizeof(results));

    for (int i = 0; i < N; i++) {
        results[i].slot = i;
        args[i].result = &results[i];
        args[i].json = (i == 0)
            ? "{\"action\":\"execute\",\"device\":\"R6\",\"command\":\"show version\"}"
            : "{\"action\":\"heartbeat\"}";
    }

    double batch_start = time_ms();
    for (int i = 0; i < N; i++)
        pthread_create(&threads[i], NULL, hol_client_thread, &args[i]);
    for (int i = 0; i < N; i++)
        pthread_join(threads[i], NULL);
    double batch_end = time_ms();

    virp_driver_mock_set_delay(0);

    /* All 10 must have succeeded. */
    for (int i = 0; i < N; i++) {
        if (!results[i].ok) {
            printf(" [FAIL]\n    slot %d request failed\n", i);
            tests_run++; tests_failed++; return;
        }
    }

    /* slot 0 was the slow execute; expect duration ≥ SLOW_MS. */
    double slow_dur = results[0].end_ms - results[0].start_ms;
    ASSERT_TRUE(slow_dur >= (double)SLOW_MS * 0.9);

    /*
     * The 9 heartbeats must finish WAY before the slow execute does.
     * Under serialization each would wait for the slow one (~400ms+);
     * with the worker pool they should complete in well under 200ms.
     * Use 250ms as a generous ceiling that still proves concurrency.
     */
    for (int i = 1; i < N; i++) {
        double hb_dur = results[i].end_ms - results[i].start_ms;
        if (hb_dur >= 250.0) {
            printf(" [FAIL]\n    heartbeat slot %d took %.1fms "
                   "(slow execute took %.1fms) — accept loop likely "
                   "serialized\n", i, hb_dur, slow_dur);
            tests_run++; tests_failed++; return;
        }
    }

    /*
     * Total elapsed must be dominated by the slow command, not the sum
     * of all requests. Cap at 2× SLOW_MS to allow scheduler jitter.
     */
    double total = batch_end - batch_start;
    ASSERT_TRUE(total < (double)SLOW_MS * 2.0);
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
 * Error-path observation regressions
 *
 * Live reproductions (2026-07): error observations were built with the
 * same constructor as executed device output (VIRP_OBS_DEVICE_OUTPUT /
 * the v2 session-bound success path), so the AI layer rendered them as
 * "[YELLOW-tier change — logged]" regardless of actual tier and even
 * when nothing executed. Each test below pins one repro case: the
 * observation must be a signed VIRP_OBS_ERROR carrying the command's
 * true classified tier, and must not look like executed output.
 * ========================================================================= */

extern void virp_driver_mock_set_connect_fail(int fail);
extern void virp_driver_mock_set_soft_fail(const char *msg);

/* Stand up a private, socketless onode with one mock device so the
 * error-path tests don't disturb g_state's connection cache. */
static int errobs_setup(onode_state_t *tmp, const char *hostname,
                        uint32_t node_id)
{
    if (onode_init(tmp, node_id, NULL, "/tmp/virp-onode-errobs.sock") != VIRP_OK)
        return -1;
    tmp->ctx = virp_context_new();
    if (!tmp->ctx)
        return -1;
    /* compiled-in defaults: ENFORCE, max_tier=YELLOW — the live posture */

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "%s", hostname);
    snprintf(dev.host, sizeof(dev.host), "10.255.0.1");
    dev.port = 22;
    dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0E220001;
    dev.enabled = true;
    return (onode_add_device(tmp, &dev) == VIRP_OK) ? 0 : -1;
}

static void errobs_teardown(onode_state_t *tmp)
{
    virp_context_destroy(tmp->ctx);
    onode_destroy(tmp);
}

/* (a) Connection failure to an unreachable device, GREEN read: the error
 * observation must be VIRP_OBS_ERROR at tier GREEN (the read's true
 * tier) — not a DEVICE_OUTPUT observation the consumer logs as a change. */
TEST(test_error_obs_connect_failure_is_error_with_true_tier)
{
    onode_state_t tmp;
    ASSERT_EQ(errobs_setup(&tmp, "R-UNREACH", 0xE220000A), 0);

    virp_driver_mock_set_connect_fail(1);
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    virp_error_t err = onode_execute(&tmp, "R-UNREACH", "show version",
                                     buf, sizeof(buf), &len);
    virp_driver_mock_set_connect_fail(0);
    ASSERT_OK(err);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(buf, len, &tmp.okey, &hdr));
    ASSERT_EQ(hdr.tier, VIRP_TIER_GREEN);          /* true tier of the read */

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(buf + VIRP_HEADER_SIZE,
                                     len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);       /* was DEVICE_OUTPUT */
    ASSERT_TRUE(strstr((const char *)data, "cannot connect") != NULL);

    errobs_teardown(&tmp);
}

/* (b) Driver soft-refusal (VIRP_OK + success=false + error_msg, the shape
 * the Wazuh driver uses for an invalid / BLACK-tier endpoint): nothing
 * executed, so the observation must be VIRP_OBS_ERROR at the command's
 * true tier — before the fix it fell through to the success constructor
 * and went out as DEVICE_OUTPUT. */
TEST(test_error_obs_driver_refusal_is_error_not_output)
{
    onode_state_t tmp;
    ASSERT_EQ(errobs_setup(&tmp, "R-WZ", 0xE220000B), 0);

    virp_driver_mock_set_soft_fail(
        "Endpoint blocked (BLACK tier): /manager/restart");
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    /* "clear counters" is YELLOW for the mock classifier: allowed through
     * the gate (max=YELLOW), refused by the driver. */
    virp_error_t err = onode_execute(&tmp, "R-WZ", "clear counters",
                                     buf, sizeof(buf), &len);
    virp_driver_mock_set_soft_fail(NULL);
    ASSERT_OK(err);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(buf, len, &tmp.okey, &hdr));
    ASSERT_EQ(hdr.tier, VIRP_TIER_YELLOW);         /* true tier, honest */

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(buf + VIRP_HEADER_SIZE,
                                     len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);       /* was DEVICE_OUTPUT */
    ASSERT_TRUE(strstr((const char *)data,
                       "Endpoint blocked (BLACK tier)") != NULL);
    /* Must not look like executed CLI output (mock echoes hostname#cmd) */
    ASSERT_TRUE(strstr((const char *)data, "R-WZ#") == NULL);

    errobs_teardown(&tmp);
}

/* (c) Gate-blocked RED command under ENFORCE max=YELLOW (live repro:
 * "clear counters" on R1 while it was RED-classified): the observation
 * must be VIRP_OBS_ERROR at tier RED, nothing may execute, and the gate
 * log must state what it DID ("decision=block") — not the shadow-era
 * "would-block", which read as a logged-but-executed change. */
TEST(test_error_obs_gate_block_logs_as_error_not_change)
{
    onode_state_t tmp;
    ASSERT_EQ(errobs_setup(&tmp, "R-GATE", 0xE220000C), 0);

    /* Capture the daemon's stderr log for the duration of the call. */
    const char *log_path = "/tmp/virp-onode-errobs-gate.log";
    fflush(stderr);
    int saved_fd = dup(fileno(stderr));
    ASSERT_TRUE(saved_fd >= 0);
    int log_fd = open(log_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    ASSERT_TRUE(log_fd >= 0);
    dup2(log_fd, fileno(stderr));
    close(log_fd);

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    /* "reload" is RED for the mock classifier — blocked under max=YELLOW */
    virp_error_t err = onode_execute(&tmp, "R-GATE", "reload",
                                     buf, sizeof(buf), &len);

    fflush(stderr);
    dup2(saved_fd, fileno(stderr));
    close(saved_fd);

    ASSERT_OK(err);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(buf, len, &tmp.okey, &hdr));
    ASSERT_EQ(hdr.tier, VIRP_TIER_RED);            /* true tier, not YELLOW */

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(buf + VIRP_HEADER_SIZE,
                                     len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(strstr((const char *)data, "tier gate blocked") != NULL);
    /* Nothing executed: no mock CLI echo in the payload */
    ASSERT_TRUE(strstr((const char *)data, "R-GATE#") == NULL);

    /* Log-line regression: ENFORCE states its decision; the error is
     * logged as an error, never as a change. */
    FILE *lf = fopen(log_path, "r");
    ASSERT_TRUE(lf != NULL);
    char logbuf[4096];
    size_t got = fread(logbuf, 1, sizeof(logbuf) - 1, lf);
    fclose(lf);
    unlink(log_path);
    logbuf[got] = '\0';

    ASSERT_TRUE(strstr(logbuf, "decision=block") != NULL);
    ASSERT_TRUE(strstr(logbuf, "would-block") == NULL);
    ASSERT_TRUE(strstr(logbuf, "[ERROR-OBS] device=R-GATE tier=RED "
                               "executed=no") != NULL);

    errobs_teardown(&tmp);
}

/* =========================================================================
 * SO_PEERCRED allowlist tests
 *
 * The daemon's default allowlist (set in onode_start()) is the daemon's
 * own effective UID — which is the test process's UID in this harness.
 * The "allowed" test confirms that baseline; the "rejected" test flips
 * the allowlist to a different UID, proves the daemon drops the
 * connection without reading, then restores the original allowlist so
 * later tests keep working.
 * ========================================================================= */

TEST(test_peer_uid_allowed)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request("{\"action\": \"heartbeat\"}",
                               resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr));
    ASSERT_EQ(hdr.type, VIRP_MSG_HEARTBEAT);
}

TEST(test_peer_uid_rejected)
{
    uid_t saved[ONODE_MAX_ALLOWED_UIDS];
    size_t saved_count = g_state.socket_allowed_uids_count;
    for (size_t i = 0; i < saved_count; i++)
        saved[i] = g_state.socket_allowed_uids[i];

    /*
     * Pick any UID that is not the caller's. 0 works as long as the
     * test is not run as root; if it is, fall back to nobody (65534).
     * All we need is a value that differs from geteuid().
     */
    uid_t wrong = (geteuid() == 0) ? 65534 : 0;
    ASSERT_OK(onode_set_allowed_uids(&g_state, &wrong, 1));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request("{\"action\": \"heartbeat\"}",
                               resp, sizeof(resp));

    /* Restore before any further assertions so a failure still leaves
     * the daemon in a usable state for subsequent tests. */
    onode_set_allowed_uids(&g_state, saved, saved_count);

    /* client_request returns -1 when the length prefix cannot be read,
     * which is exactly what we expect when the daemon closes without
     * sending anything. */
    ASSERT_EQ((int)(n < 0), 1);
}

/* =========================================================================
 * Issue #7: wrong-type values in devices.json must not crash the parser
 *
 * Pre-fix, the prod load_devices() called json_object_get_string(val)
 * unconditionally and fed the result to snprintf("%s", ...). When val
 * was a JSON int/bool/null (e.g. an operator typed "enable": 0), the
 * get_string returned NULL and snprintf hit undefined behaviour —
 * segfault on glibc. P. Snowacki (NCIA) hit this during external impl
 * testing against Cisco gear.
 *
 * The fix: type-checked accessors that treat wrong-type values as
 * absent. This test loads a config where five different fields have
 * wrong types and asserts the parser keeps loading instead of dying.
 * ========================================================================= */

extern int load_devices(onode_state_t *state, const char *path);

#define WRONG_TYPE_CFG  "/tmp/virp-onode-wrongtype.json"

/*
 * SHADOW-mode audit honesty on the SUCCESS path (Item 1 hardening):
 * an unclassifiable command that EXECUTES under SHADOW must be stamped
 * UNCLASSIFIED on the wire — not clamped to GREEN. This coverage moved
 * here when the mock driver gained a classifier and the daemon default
 * became ENFORCE (where unclassified commands are blocked instead).
 */
TEST(test_shadow_executes_unclassified_with_honest_tier)
{
    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0003, NULL,
                         "/tmp/virp-onode-shadow.sock"));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);
    tmp.gate_default_mode = GATE_MODE_SHADOW;    /* explicit opt-in */

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "R-SHADOW");
    snprintf(dev.host, sizeof(dev.host), "10.0.0.98");
    dev.port = 22;
    dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0BADCAFE;
    dev.enabled = true;
    ASSERT_OK(onode_add_device(&tmp, &dev));

    /* "frobnicate ..." is UNCLASSIFIED for the mock classifier; under
     * SHADOW it must still execute (mock returns an IOS-style error
     * output) and the observation must record UNCLASSIFIED honestly */
    uint8_t obs_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t obs_len = 0;
    ASSERT_OK(onode_execute(&tmp, "R-SHADOW", "frobnicate the widget",
                            obs_buf, sizeof(obs_buf), &obs_len));

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs_buf, obs_len, &tmp.okey, &hdr));
    ASSERT_EQ(hdr.tier, VIRP_TIER_UNCLASSIFIED);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(obs_buf + VIRP_HEADER_SIZE,
                                     obs_len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));
    /* the command actually ran (mock echoes hostname#command) */
    ASSERT_TRUE(strstr((const char *)data, "R-SHADOW#frobnicate") != NULL);

    virp_context_destroy(tmp.ctx);
    onode_destroy(&tmp);
}

TEST(test_load_devices_wrong_type_does_not_crash)
{
    FILE *f = fopen(WRONG_TYPE_CFG, "w");
    ASSERT_TRUE(f != NULL);
    /* Five wrong-type fields + a couple of well-typed ones, so the
     * device still has enough to be added (hostname/host/vendor). */
    fprintf(f,
        "{\n"
        "  \"devices\": [\n"
        "    {\n"
        "      \"hostname\":   \"R-WRONGTYPE\",\n"
        "      \"host\":       \"10.0.0.99\",\n"
        "      \"vendor\":     \"mock\",\n"
        "      \"port\":       22,\n"
        "      \"username\":   \"u\",\n"
        "      \"password\":   \"p\",\n"
        "      \"enable\":     0,\n"
        "      \"node_id\":    null,\n"
        "      \"api_token\":  true,\n"
        "      \"vdom\":       1234,\n"
        "      \"verify_tls\": \"yes\"\n"
        "    }\n"
        "  ]\n"
        "}\n");
    fclose(f);

    /* Stand up a throwaway onode_state_t so load_devices can call
     * onode_add_device(). Not started — we never bind a socket. */
    onode_state_t tmp;
    const char *tmp_sock = "/tmp/virp-onode-wrongtype.sock";
    /* NULL okey_path → generate a fresh in-memory O-Key. We never start
     * the event loop so the socket path is just a placeholder. */
    ASSERT_OK(onode_init(&tmp, 0xDEAD0001, NULL, tmp_sock));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);

    /* The crash bug: this call segfaulted pre-fix. */
    int loaded = load_devices(&tmp, WRONG_TYPE_CFG);
    ASSERT_EQ(loaded, 1);
    ASSERT_EQ(tmp.device_count, 1);

    /* Well-typed fields must come through intact. */
    ASSERT_EQ(strcmp(tmp.devices[0].hostname, "R-WRONGTYPE"), 0);
    ASSERT_EQ(strcmp(tmp.devices[0].host, "10.0.0.99"), 0);
    ASSERT_EQ((int)tmp.devices[0].port, 22);
    ASSERT_EQ((int)tmp.devices[0].vendor, (int)VIRP_VENDOR_MOCK);
    ASSERT_EQ(strcmp(tmp.devices[0].username, "u"), 0);
    ASSERT_EQ(strcmp(tmp.devices[0].password, "p"), 0);

    /* Wrong-type fields must be treated as absent — zeroed by memset. */
    ASSERT_EQ((int)tmp.devices[0].enable_password[0], 0);  /* "enable": int */
    ASSERT_EQ((int)tmp.devices[0].node_id, 0);             /* "node_id": null */
    ASSERT_EQ((int)tmp.devices[0].api_token[0], 0);        /* "api_token": bool */
    ASSERT_EQ((int)tmp.devices[0].vdom[0], 0);             /* "vdom": int */
    ASSERT_EQ((int)tmp.devices[0].verify_tls, 0);          /* "verify_tls": str */

    onode_destroy(&tmp);
    virp_context_destroy(tmp.ctx);
    unlink(WRONG_TYPE_CFG);
}

TEST(test_load_devices_skips_missing_required_fields)
{
    /* hostname-as-int means hostname is treated as absent, which means
     * the device is skipped — loaded must be 0, not a crash. */
    FILE *f = fopen(WRONG_TYPE_CFG, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f,
        "{\n"
        "  \"devices\": [\n"
        "    { \"hostname\": 42, \"host\": \"1.2.3.4\", \"vendor\": \"mock\" }\n"
        "  ]\n"
        "}\n");
    fclose(f);

    onode_state_t tmp;
    const char *tmp_sock = "/tmp/virp-onode-wrongtype.sock";
    ASSERT_OK(onode_init(&tmp, 0xDEAD0002, NULL, tmp_sock));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);

    int loaded = load_devices(&tmp, WRONG_TYPE_CFG);
    ASSERT_EQ(loaded, 0);
    ASSERT_EQ(tmp.device_count, 0);

    onode_destroy(&tmp);
    virp_context_destroy(tmp.ctx);
    unlink(WRONG_TYPE_CFG);
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
 * Startup invariant: approval mode requires a working trust chain
 *
 * The shipped deploy unit once omitted -c/-C while the default approver
 * registry path existed on the host, so the daemon came up in approval
 * mode with NO chain: challenges were issued and approvals accepted with
 * no PROPOSAL/APPROVAL/OUTCOME history and a vacuous L1 consumed-
 * proposal check. onode_setup_chain_and_approvals() now refuses that
 * combination: approval mode + no chain (or chain init failure) must
 * return non-VIRP_OK so main() exits non-zero. Non-approval startups
 * keep the historical "continuing without chain" tolerance.
 * ========================================================================= */

extern virp_error_t onode_setup_chain_and_approvals(onode_state_t *state,
                                                    uint32_t node_id,
                                                    const char *chain_db_path,
                                                    const char *chain_key_path,
                                                    const char *approval_dir,
                                                    const char *approvers_path);

#define AP_REGISTRY  "/tmp/virp-onode-test-approvers.json"
#define AP_DIR       "/tmp/virp-onode-test-approvals"
#define AP_CHAIN_DB  "/tmp/virp-onode-test-apchain.db"
#define AP_CHAIN_KEY "/tmp/virp-onode-test-apchain.key"
#define AP_MISSING   "/tmp/virp-onode-test-no-such-file"

/* One enabled ECDSA-P256 key (the KAT vector from
 * docs/approvers.example.json) — enough to flip approval mode on. */
static int write_test_registry(void)
{
    FILE *f = fopen(AP_REGISTRY, "w");
    if (!f) return -1;
    fprintf(f,
        "[{\"key_id\":\"e6d67937b0a11c446e166ddc8f157ba9\","
        "\"algorithm\":\"ecdsa-p256\","
        "\"public_key\":\"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPunEJQ1WRSrS"
        "DlBhL6MRlYkJoLInUnLDH0zozZ40uEGnnt/MSp0Bkht4+q1jakqnwz141u58E1pn"
        "9fkDAOxcAw==\","
        "\"operator\":\"test-operator\",\"enabled\":true}]\n");
    fclose(f);
    return 0;
}

static void ap_cleanup_files(void)
{
    unlink(AP_REGISTRY);
    unlink(AP_CHAIN_DB);
    unlink(AP_CHAIN_DB "-wal");
    unlink(AP_CHAIN_DB "-shm");
    unlink(AP_CHAIN_KEY);
}

TEST(test_approval_mode_without_chain_refuses_start)
{
    ASSERT_EQ(write_test_registry(), 0);

    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0004, NULL,
                         "/tmp/virp-onode-apchain.sock"));

    /* Approver registry loads, but no -c/-C: startup must be refused. */
    virp_error_t rc = onode_setup_chain_and_approvals(&tmp, 0xDEAD0004,
                                                      NULL, NULL,
                                                      AP_DIR, AP_REGISTRY);
    ASSERT_TRUE(rc != VIRP_OK);
    ASSERT_EQ((int)tmp.chain_enabled, 0);

    onode_destroy(&tmp);
    ap_cleanup_files();
}

TEST(test_approval_mode_chain_init_failure_refuses_start)
{
    ASSERT_EQ(write_test_registry(), 0);

    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0005, NULL,
                         "/tmp/virp-onode-apchain.sock"));

    /* Chain configured but uninitializable (key file doesn't exist):
     * approval mode must refuse to start — no silent continue. */
    virp_error_t rc = onode_setup_chain_and_approvals(&tmp, 0xDEAD0005,
                                                      AP_CHAIN_DB, AP_MISSING,
                                                      AP_DIR, AP_REGISTRY);
    ASSERT_TRUE(rc != VIRP_OK);
    ASSERT_EQ((int)tmp.chain_enabled, 0);

    onode_destroy(&tmp);
    ap_cleanup_files();
}

TEST(test_approval_mode_with_chain_starts)
{
    ASSERT_EQ(write_test_registry(), 0);

    /* A real 32-byte chain key + a fresh SQLite db path. */
    virp_signing_key_t ck;
    ASSERT_OK(virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN));
    ASSERT_OK(virp_key_save_file(&ck, AP_CHAIN_KEY));
    virp_key_destroy(&ck);

    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0006, NULL,
                         "/tmp/virp-onode-apchain.sock"));

    virp_error_t rc = onode_setup_chain_and_approvals(&tmp, 0xDEAD0006,
                                                      AP_CHAIN_DB,
                                                      AP_CHAIN_KEY,
                                                      AP_DIR, AP_REGISTRY);
    ASSERT_OK(rc);
    ASSERT_EQ((int)tmp.chain_enabled, 1);
    ASSERT_EQ((int)tmp.approvers_loaded, 1);

    onode_destroy(&tmp);   /* destroys the chain (chain_enabled) */
    ap_cleanup_files();
}

TEST(test_no_approvers_no_chain_still_starts)
{
    /* Registry absent → approval mode disabled → chainless startup is
     * still allowed (unchanged non-approval behavior). */
    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0007, NULL,
                         "/tmp/virp-onode-apchain.sock"));

    virp_error_t rc = onode_setup_chain_and_approvals(&tmp, 0xDEAD0007,
                                                      NULL, NULL,
                                                      AP_DIR, AP_MISSING);
    ASSERT_OK(rc);
    ASSERT_EQ((int)tmp.approvers_loaded, 0);
    ASSERT_EQ((int)tmp.chain_enabled, 0);

    onode_destroy(&tmp);
}

TEST(test_no_approvers_chain_failure_still_starts)
{
    /* Chain init fails but approval mode is off: historical
     * "continuing without chain" tolerance must be preserved. */
    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0008, NULL,
                         "/tmp/virp-onode-apchain.sock"));

    virp_error_t rc = onode_setup_chain_and_approvals(&tmp, 0xDEAD0008,
                                                      AP_CHAIN_DB, AP_MISSING,
                                                      AP_DIR, AP_MISSING);
    ASSERT_OK(rc);
    ASSERT_EQ((int)tmp.approvers_loaded, 0);
    ASSERT_EQ((int)tmp.chain_enabled, 0);

    onode_destroy(&tmp);
    ap_cleanup_files();
}

/* =========================================================================
 * gate_obs_tier — audit-honesty mapping (Item 1 hardening)
 * ========================================================================= */

TEST(test_gate_obs_tier_honesty)
{
    /* Real tiers pass through; UNCLASSIFIED is preserved (NOT clamped to
     * GREEN) so a blocked/unclassified op records honestly in the chain. */
    ASSERT_EQ(gate_obs_tier(VIRP_TIER_GREEN),        VIRP_TIER_GREEN);
    ASSERT_EQ(gate_obs_tier(VIRP_TIER_YELLOW),       VIRP_TIER_YELLOW);
    ASSERT_EQ(gate_obs_tier(VIRP_TIER_RED),          VIRP_TIER_RED);
    ASSERT_EQ(gate_obs_tier(VIRP_TIER_UNCLASSIFIED), VIRP_TIER_UNCLASSIFIED);
    /* BLACK is untransmittable -> over-reported as RED, never GREEN. */
    ASSERT_EQ(gate_obs_tier(VIRP_TIER_BLACK),        VIRP_TIER_RED);
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

    printf("[Device Config Parser Robustness (issue #7)]\n");
    RUN_TEST(test_load_devices_wrong_type_does_not_crash);
    RUN_TEST(test_load_devices_skips_missing_required_fields);

    printf("\n[Gate observation-tier honesty (Item 1 hardening)]\n");
    RUN_TEST(test_gate_obs_tier_honesty);
    RUN_TEST(test_shadow_executes_unclassified_with_honest_tier);

    printf("\n[hex_decode Unit Tests]\n");
    RUN_TEST(test_hex_decode_empty_string);
    RUN_TEST(test_hex_decode_odd_length);
    RUN_TEST(test_hex_decode_valid_lowercase);
    RUN_TEST(test_hex_decode_valid_uppercase);
    RUN_TEST(test_hex_decode_mixed_case);
    RUN_TEST(test_hex_decode_embedded_space);
    RUN_TEST(test_hex_decode_embedded_plus);
    RUN_TEST(test_hex_decode_embedded_0x);
    RUN_TEST(test_hex_decode_oversized_input);

    printf("\n[Approval-Mode-Requires-Chain Startup Tests]\n");
    RUN_TEST(test_approval_mode_without_chain_refuses_start);
    RUN_TEST(test_approval_mode_chain_init_failure_refuses_start);
    RUN_TEST(test_approval_mode_with_chain_starts);
    RUN_TEST(test_no_approvers_no_chain_still_starts);
    RUN_TEST(test_no_approvers_chain_failure_still_starts);

    printf("\n[O-Node Pipeline Tests]\n");
    RUN_TEST(test_execute_show_ip_route);
    RUN_TEST(test_gate_enforce_blocks_unclassified);
    RUN_TEST(test_execute_v2_without_session_fails);
    RUN_TEST(test_execute_v2_session_bound_roundtrip);
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
    RUN_TEST(test_batch_execute_v2_honors_obs_version);
    RUN_TEST(test_batch_execute_four_devices);
    RUN_TEST(test_batch_execute_not_found_device);
    RUN_TEST(test_batch_execute_parallel_timing);
    RUN_TEST(test_batch_sequence_numbers_unique);
    RUN_TEST(test_batch_same_device_concurrent);

    printf("\n[v2 Framing Tests]\n");
    RUN_TEST(test_v1_unframed_client_rejected);
    RUN_TEST(test_framed_request_split_across_three_sends);
    RUN_TEST(test_framed_oversize_length_rejected);

    printf("\n[Worker Pool / Concurrency Tests]\n");
    RUN_TEST(test_concurrent_clients_no_head_of_line);

    printf("\n[Signed Error Observation Tests]\n");
    RUN_TEST(test_driver_error_returns_signed_observation);
    RUN_TEST(test_error_obs_connect_failure_is_error_with_true_tier);
    RUN_TEST(test_error_obs_driver_refusal_is_error_not_output);
    RUN_TEST(test_error_obs_gate_block_logs_as_error_not_change);

    printf("\n[SO_PEERCRED Allowlist Tests]\n");
    RUN_TEST(test_peer_uid_allowed);
    RUN_TEST(test_peer_uid_rejected);

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
