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

static ssize_t client_request(const char *json,
                              uint8_t *resp, size_t resp_len)
{
    int fd = client_connect();
    if (fd < 0) return -1;

    send(fd, json, strlen(json), 0);

    /* Brief pause to let O-Node process */
    usleep(50000);

    ssize_t n = recv(fd, resp, resp_len, 0);
    close(fd);
    return n;
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

    printf("[O-Node Pipeline Tests]\n");
    RUN_TEST(test_execute_show_ip_route);
    RUN_TEST(test_execute_show_bgp_summary);
    RUN_TEST(test_execute_different_devices);
    RUN_TEST(test_device_not_found);
    RUN_TEST(test_heartbeat);
    RUN_TEST(test_list_devices);
    RUN_TEST(test_sequence_numbers_increment);
    RUN_TEST(test_tampered_response_fails_verify);
    RUN_TEST(test_wrong_key_fails_verify);

    /* Shutdown */
    onode_shutdown(&g_state);
    pthread_join(server_thread, NULL);
    onode_destroy(&g_state);

    printf("\n================================================================\n");
    printf("  Results: %d/%d passed", tests_passed, tests_run);
    if (tests_failed > 0)
        printf("  (%d FAILED)", tests_failed);
    printf("\n================================================================\n\n");

    return (tests_failed > 0) ? 1 : 0;
}
