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
#include "virp_obskey.h"
#include "virp_scrub.h"
#include <sodium.h>
#include "virp_driver.h"
#include <signal.h>
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
#include <sqlite3.h>
#include <openssl/evp.h>

/* =========================================================================
 * Test infrastructure
 * ========================================================================= */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int tests_pending = 0;
static int pending_unexpected_pass = 0;

/*
 * current_test_failed replaces the old accounting, which was wrong in a
 * way that mattered (2026-08-26). ASSERT_EQ used to do
 * `tests_run++; tests_failed++; return;` and RUN_TEST then did
 * `tests_run++; tests_passed++; printf(" [PASS]")` unconditionally when
 * the function returned — so a FAILING test printed [FAIL], its detail,
 * and then [PASS], was counted in tests_passed, and inflated tests_run by
 * one. "135/137 passed (2 FAILED)" actually meant 133 passed of 135. The
 * exit status was still correct, so this never lost a red build; it made
 * the summary line overstate the pass count and print a pass label on a
 * failed test. Found while adding PENDING_TEST below, which cannot be
 * trusted on top of accounting that reports failures as passes.
 */
static int current_test_failed = 0;

#define TEST(name) static void name(void)
#define RUN_TEST(name) do { \
    printf("  %-60s", #name); \
    fflush(stdout); \
    current_test_failed = 0; \
    name(); \
    tests_run++; \
    if (current_test_failed) { \
        tests_failed++; \
    } else { \
        tests_passed++; \
        printf(" [PASS]\n"); \
    } \
} while(0)

/*
 * PENDING_TEST — a test that is known-failing BY DESIGN because the code
 * to satisfy it has not been written yet.
 *
 * It must never roll up as green. A pending test is counted in its own
 * bucket, never in tests_passed, and the summary refuses to print a clean
 * line while any exist. The failing suite that reports success is the
 * pattern check-test-deps.sh exists to prevent; this is the same hazard
 * one layer in.
 *
 * If a pending test unexpectedly PASSES, that is a hard FAILURE. The
 * acceptance criterion has been met and the marker is now a lie about the
 * state of the code — a pending marker that silently becomes correct is
 * how stale markers accumulate. Remove the marker in the same commit that
 * makes it pass.
 */
#define PENDING_TEST(name, criterion) do { \
    printf("  %-60s", #name); \
    fflush(stdout); \
    current_test_failed = 0; \
    name(); \
    tests_run++; \
    if (current_test_failed) { \
        tests_pending++; \
        printf("    ^^ [PENDING] known-failing by design; NOT a pass\n"); \
        printf("       acceptance criterion: %s\n", (criterion)); \
    } else { \
        tests_failed++; \
        pending_unexpected_pass++; \
        printf(" [PENDING BUT PASSED]\n"); \
        printf("    This test is marked PENDING but now passes. The\n"); \
        printf("    acceptance criterion is met — remove the marker.\n"); \
    } \
} while(0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf(" [FAIL]\n    Expected %d, got %d at line %d\n", \
               (int)(b), (int)(a), __LINE__); \
        current_test_failed = 1; return; \
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
 * L1 (2026-08-18): an over-tier command under ENFORCE must be refused by
 * the gate BEFORE any device connection — no auth attempt, no session, no
 * connect audit noise. Arm the mock to FAIL every connect: pre-L1 the
 * daemon connected first, so the refused command would come back "cannot
 * connect"; refusing first yields "tier gate blocked" with the connect
 * never attempted. The control shows an ADMITTED (GREEN) command DOES
 * still connect — the reorder does not change admitted behaviour.
 */
extern void virp_driver_mock_set_connect_fail(int fail);   /* driver_mock.c */

TEST(test_over_tier_enforce_refused_without_connecting)
{
    /* Isolated LOCAL daemon state + a FRESH mock device: no other test's
     * cached connection can mask (or fake) the connect attempt, and the
     * global mock connect-fail is reset before any assertion can return
     * early. Drive onode_execute() directly — the same gate/connect path a
     * socket request takes. */
    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD00A1, NULL,
                         "/tmp/virp-onode-l1gate.sock"));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);
    tmp.gate_default_mode = GATE_MODE_ENFORCE;   /* default; max_tier=YELLOW */

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "R-L1G");
    snprintf(dev.host, sizeof(dev.host), "10.0.0.201");
    dev.port = 22;
    dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0A0000C9;   /* unique, non-zero (see node_id-0 reject) */
    dev.enabled = true;
    ASSERT_OK(onode_add_device(&tmp, &dev));

    uint8_t over[VIRP_MAX_MESSAGE_SIZE];
    uint8_t adm[VIRP_MAX_MESSAGE_SIZE];
    size_t over_len = 0, adm_len = 0;

    virp_driver_mock_set_connect_fail(1);   /* every connect now fails */
    /* Over-tier: UNCLASSIFIED under the YELLOW ceiling, ENFORCE. */
    virp_error_t e_over = onode_execute(&tmp, "R-L1G",
                            "frobnicate the flux capacitor",
                            over, sizeof(over), &over_len);
    /* Control: an ADMITTED (GREEN) command must still reach the device. */
    virp_error_t e_adm = onode_execute(&tmp, "R-L1G", "show version",
                            adm, sizeof(adm), &adm_len);
    virp_driver_mock_set_connect_fail(0);   /* reset before asserting */

    virp_header_t hdr;
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;

    /* THE FIX: over-tier is refused at the gate BEFORE any connect — the
     * response is a tier-block, NOT a connect failure. Pre-L1 the daemon
     * connected first, so an armed-to-fail connect produced "cannot
     * connect" instead. */
    ASSERT_OK(e_over);
    ASSERT_OK(virp_validate_message(over, over_len, &tmp.okey, &hdr));
    ASSERT_OK(virp_parse_observation(over + VIRP_HEADER_SIZE,
                                     over_len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(strstr((const char *)data, "tier gate blocked") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "cannot connect") == NULL);

    /* Control: the admitted GREEN command DID try to connect (armed to
     * fail) — "cannot connect", proving admitted requests still reach the
     * device exactly as before the reorder. */
    ASSERT_OK(e_adm);
    ASSERT_OK(virp_validate_message(adm, adm_len, &tmp.okey, &hdr));
    ASSERT_OK(virp_parse_observation(adm + VIRP_HEADER_SIZE,
                                     adm_len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(strstr((const char *)data, "cannot connect") != NULL);

    onode_destroy(&tmp);
    virp_context_destroy(tmp.ctx);
}

/* =========================================================================
 * Multi-command gate bypass (REPRODUCTION — expected to FAIL pre-fix)
 *
 * The request parser applies no character validation to "command", so a
 * JSON \n escape decodes to a real embedded newline. Every classifier
 * (mock, cisco, asa, panos, juniper) prefix-matches from index 0 only,
 * so "show version\nreload" classifies on its FIRST line and returns
 * GREEN. The gate then allows it and the driver sends the WHOLE string
 * to the device, where the newline is a command separator — so `reload`
 * reaches the wire having never been classified or gated.
 *
 * Exercised through the socket (not the in-process onode_execute
 * harness) deliberately: the newline enters at the JSON parse stage,
 * which only the socket path exercises.
 *
 * Asserted behavior: the request must be BLOCKED. Pre-fix this fails
 * because the command is allowed and executed.
 * ========================================================================= */

/* The JSON "\\n" below is a two-character escape in the JSON text that
 * cJSON decodes into one real newline byte in req.command. */
#define MULTICMD_JSON \
    "{\"action\": \"execute\", \"device\": \"R6\", " \
    "\"command\": \"show version\\nreload\"}"

TEST(test_multicommand_newline_is_blocked)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(MULTICMD_JSON, resp, sizeof(resp));
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);

    virp_header_t hdr;
    virp_error_t err = virp_validate_message(resp, (size_t)n,
                                             &g_state.okey, &hdr);
    ASSERT_OK(err);

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    err = virp_parse_observation(resp + VIRP_HEADER_SIZE,
                                 (size_t)n - VIRP_HEADER_SIZE,
                                 &obs, &data, &data_len);
    ASSERT_OK(err);

    /* Must be a signed refusal, NOT executed device output. */
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);

    /* And the second command must never have reached the driver: the
     * mock echoes "<host>#<command>" on execute, so an echo containing
     * "reload" proves it went to the wire. */
    ASSERT_TRUE(strstr((const char *)data, "R6#show version") == NULL);
}

/*
 * Same bypass via the BATCH ingress. parse_batch_commands() is a second,
 * independent parse path — batch items never pass through
 * parse_request(), so a boundary check installed there would not cover
 * this case. Both paths do converge on onode_execute_obs_ex().
 *
 * Batch response framing: [4-byte count][4-byte len][obs]...
 */
TEST(test_multicommand_newline_is_blocked_batch)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"batch_execute\", \"commands\": ["
        "{\"device\": \"R6\", \"command\": \"show version\\nreload\"}]}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > 8);

    uint32_t count, item_len;
    memcpy(&count, resp, 4);
    count = ntohl(count);
    ASSERT_EQ((int)count, 1);
    memcpy(&item_len, resp + 4, 4);
    item_len = ntohl(item_len);
    ASSERT_TRUE(item_len > VIRP_HEADER_SIZE);
    ASSERT_TRUE(8 + (size_t)item_len <= (size_t)n);

    const uint8_t *item = resp + 8;
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(item, item_len, &g_state.okey, &hdr));

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(item + VIRP_HEADER_SIZE,
                                     (size_t)item_len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));

    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(strstr((const char *)data, "R6#show version") == NULL);
}

/*
 * Layer 1 unit coverage for the shared separator policy itself. Each
 * rejected class is pinned here so a future edit to the policy has to
 * face them individually.
 */
TEST(test_separator_policy_accepts_single_commands)
{
    ASSERT_EQ(virp_command_check_separators("show version", NULL, 0), 0);
    ASSERT_EQ(virp_command_check_separators(
                  "show interfaces GigabitEthernet0/0", NULL, 0), 0);
    ASSERT_EQ(virp_command_check_separators("", NULL, 0), 0);
    /* '$' alone is not an expansion and must stay legal (IOS regex). */
    ASSERT_EQ(virp_command_check_separators("show ip route 10$", NULL, 0), 0);
}

TEST(test_separator_policy_rejects_every_class)
{
    ASSERT_EQ(virp_command_check_separators("show version\nreload", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show version\rreload", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show version\treload", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show version;reload", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show version|reload", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show version&reload", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show version&&reload", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show `reload`", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show $(reload)", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show ${x}", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators("show \x7fversion", NULL, 0), -1);
    ASSERT_EQ(virp_command_check_separators(NULL, NULL, 0), -1);
}

/* Control bytes must be escaped in the reason text — it is copied
 * verbatim into logs and into the signed error observation. */
TEST(test_separator_policy_escapes_control_bytes_in_reason)
{
    char why[160];
    ASSERT_EQ(virp_command_check_separators("show version\nreload",
                                            why, sizeof(why)), -1);
    ASSERT_TRUE(strstr(why, "\\x0a") != NULL);   /* escaped, not raw */
    ASSERT_TRUE(strchr(why, '\n') == NULL);      /* no raw newline */
    ASSERT_TRUE(strstr(why, "offset 12") != NULL);

    ASSERT_EQ(virp_command_check_separators("show;reload", why, sizeof(why)), -1);
    ASSERT_TRUE(strstr(why, "';'") != NULL);
}

/* =========================================================================
 * SHADOW-mode refusal (production posture for linux and wazuh)
 *
 * The layer-1 rejection is a hard return, NOT a gate verdict: it never
 * reaches gate_effective_mode or gate_tier_blocks. If it were ever
 * converted into a tier decision, SHADOW would log-and-proceed and the
 * bypass would still be open on every SHADOW-override driver.
 *
 * Each test below first proves the state really is permissive (an
 * UNCLASSIFIED command EXECUTES under SHADOW) and only then asserts the
 * separator-carrying command is refused — so a passing result cannot be
 * an artifact of ENFORCE quietly doing the work.
 * ========================================================================= */

/* Stand up a throwaway SHADOW-mode daemon state with one mock device. */
static int shadow_state_init(onode_state_t *tmp, uint32_t node_id,
                             const char *sock, const char *hostname)
{
    if (onode_init(tmp, node_id, NULL, sock) != VIRP_OK) return -1;
    tmp->ctx = virp_context_new();
    if (!tmp->ctx) return -1;

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "%s", hostname);
    snprintf(dev.host, sizeof(dev.host), "10.255.0.7");
    dev.port = 22;
    dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0BADBEEF;
    dev.enabled = true;
    return onode_add_device(tmp, &dev) == VIRP_OK ? 0 : -1;
}

/* Returns the observation type, and reports whether the mock echoed the
 * command (proof it reached the driver). */
static int shadow_exec_obs_type(onode_state_t *tmp, const char *host,
                                const char *cmd, bool *echoed)
{
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    *echoed = false;
    if (onode_execute(tmp, host, cmd, buf, sizeof(buf), &len) != VIRP_OK)
        return -1;

    virp_header_t hdr;
    if (virp_validate_message(buf, len, &tmp->okey, &hdr) != VIRP_OK)
        return -1;

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    if (virp_parse_observation(buf + VIRP_HEADER_SIZE,
                               len - VIRP_HEADER_SIZE,
                               &obs, &data, &data_len) != VIRP_OK)
        return -1;

    char needle[96];
    snprintf(needle, sizeof(needle), "%s#", host);
    *echoed = (strstr((const char *)data, needle) != NULL);
    return obs.obs_type;
}

TEST(test_shadow_default_mode_still_refuses_separator_command)
{
    onode_state_t tmp;
    ASSERT_EQ(shadow_state_init(&tmp, 0xDEAD0009,
                                "/tmp/virp-onode-shadow-sep.sock", "R-SH1"), 0);
    tmp.gate_default_mode = GATE_MODE_SHADOW;

    /* Precondition: SHADOW really does let an unclassified command run. */
    bool echoed = false;
    ASSERT_EQ(shadow_exec_obs_type(&tmp, "R-SH1", "frobnicate the widget",
                                   &echoed), VIRP_OBS_DEVICE_OUTPUT);
    ASSERT_TRUE(echoed);

    /* The separator command must still be refused, unexecuted. */
    ASSERT_EQ(shadow_exec_obs_type(&tmp, "R-SH1", "show version\nreload",
                                   &echoed), VIRP_OBS_ERROR);
    ASSERT_TRUE(!echoed);

    virp_context_destroy(tmp.ctx);
    onode_destroy(&tmp);
}

TEST(test_shadow_driver_override_still_refuses_separator_command)
{
    /* Mirrors the production posture: a per-driver SHADOW override
     * (gate_modes) rather than a SHADOW default — how linux and wazuh
     * are actually configured. */
    onode_state_t tmp;
    ASSERT_EQ(shadow_state_init(&tmp, 0xDEAD000A,
                                "/tmp/virp-onode-shadow-ovr.sock", "R-SH2"), 0);
    tmp.gate_default_mode = GATE_MODE_ENFORCE;      /* default stays strict */
    snprintf(tmp.gate_overrides[0].driver,
             sizeof(tmp.gate_overrides[0].driver), "mock");
    tmp.gate_overrides[0].mode = GATE_MODE_SHADOW;
    tmp.gate_overrides_count = 1;

    bool echoed = false;
    ASSERT_EQ(shadow_exec_obs_type(&tmp, "R-SH2", "frobnicate the widget",
                                   &echoed), VIRP_OBS_DEVICE_OUTPUT);
    ASSERT_TRUE(echoed);

    ASSERT_EQ(shadow_exec_obs_type(&tmp, "R-SH2", "show version;reload",
                                   &echoed), VIRP_OBS_ERROR);
    ASSERT_TRUE(!echoed);

    virp_context_destroy(tmp.ctx);
    onode_destroy(&tmp);
}

/*
 * Per-item batch contract (af92763): a rejected item must not kill the
 * batch, and a good sibling must still be examined and executed on its
 * own merits.
 */
TEST(test_multicommand_batch_rejects_per_item_not_whole_batch)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"batch_execute\", \"commands\": ["
        "{\"device\": \"R6\", \"command\": \"show version\\nreload\"},"
        "{\"device\": \"R6\", \"command\": \"show ip route\"}]}",
        resp, sizeof(resp));
    ASSERT_TRUE(n > 8);

    uint32_t count;
    memcpy(&count, resp, 4);
    ASSERT_EQ((int)ntohl(count), 2);

    /* Walk both items; each is [4-byte len][observation]. */
    size_t off = 4;
    int obs_types[2] = { -1, -1 };
    for (int i = 0; i < 2; i++) {
        uint32_t item_len;
        ASSERT_TRUE(off + 4 <= (size_t)n);
        memcpy(&item_len, resp + off, 4);
        item_len = ntohl(item_len);
        off += 4;
        ASSERT_TRUE(off + item_len <= (size_t)n);
        ASSERT_TRUE(item_len > VIRP_HEADER_SIZE);

        virp_header_t hdr;
        ASSERT_OK(virp_validate_message(resp + off, item_len,
                                        &g_state.okey, &hdr));
        virp_observation_t obs;
        const uint8_t *data;
        uint16_t data_len;
        ASSERT_OK(virp_parse_observation(resp + off + VIRP_HEADER_SIZE,
                                         (size_t)item_len - VIRP_HEADER_SIZE,
                                         &obs, &data, &data_len));
        obs_types[i] = obs.obs_type;
        off += item_len;
    }

    /* Item 0 rejected, item 1 executed normally. */
    ASSERT_EQ(obs_types[0], VIRP_OBS_ERROR);
    ASSERT_EQ(obs_types[1], VIRP_OBS_DEVICE_OUTPUT);
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
        NULL,
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
        NULL,
        resp, (size_t)n, 0, &store, NULL, NULL, NULL);
    ASSERT_EQ(err, VIRP_ERR_REPLAY_DETECTED);

    /* 6 — COMMAND SUBSTITUTION: a validly signed observation for
     * command A must not verify against a request for command B */
    virp_seqstore_t store2;
    ASSERT_OK(virp_seqstore_init(&store2, NULL));
    err = virp_verify_observation_v2(
        g_state.ctx, r6_id, "show running-config",
        NULL,
        resp, (size_t)n, 0, &store2, NULL, NULL, NULL);
    ASSERT_EQ(err, VIRP_ERR_CONTEXT_MISMATCH);

    /* 7 — DEVICE SUBSTITUTION: same bytes, wrong expected device */
    err = virp_verify_observation_v2(
        g_state.ctx, virp_device_id_from_hostname("R7"), "show ip route",
        NULL,
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

/* Item 8: list_fleet is enumeration ONLY — names, vendor class, status.
 * No host addresses, no node ids, no config bodies. The class column is
 * the gate's own dispatch metadata (the same vendor field that selects
 * the per-class allowlist). Pinned so the fleet view a restricted
 * principal gets can never quietly widen beyond name+class+status. */
TEST(test_list_fleet_names_class_and_status_only)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request(
        "{\"action\": \"list_fleet\"}",
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
    /* class column present, from the gate's own vendor metadata */
    ASSERT_TRUE(strstr((const char *)data, "Class") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "mock") != NULL);
    /* names, class and status only */
    ASSERT_TRUE(strstr((const char *)data, "10.0.0.5") == NULL);
    ASSERT_TRUE(strstr((const char *)data, "05050505") == NULL);
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
        NULL,
        resp[0], resp_len[0], 0, &store, &hdr, NULL, NULL));
    ASSERT_EQ(hdr.version, VIRP_VERSION_2);

    ASSERT_OK(virp_verify_observation_v2(g_state.ctx,
        virp_device_id_from_hostname("R6"), "show ip route",
        NULL,
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
 * send_all unit tests (socketpair, no daemon needed)
 *
 * send_all is the send-side counterpart of recv_exact: it must deliver
 * every byte across partial writes and EINTR, and report a dead peer
 * as -1 instead of raising SIGPIPE. Exercised directly over a
 * socketpair; a reader thread drains slowly through a shrunken send
 * buffer while bombarding the sender with SIGUSR1 (installed WITHOUT
 * SA_RESTART) so send() actually observes interruptions mid-frame.
 * ========================================================================= */

extern int send_all(int fd, const void *buf, size_t len);

#define SENDALL_TOTAL (256 * 1024)

typedef struct {
    int        fd;
    size_t     got;
    int        pattern_ok;
    pthread_t  sender;
    volatile int bombard;
} sendall_reader_arg_t;

static void sendall_sigusr1_handler(int sig) { (void)sig; }

static void *sendall_reader_thread(void *argp)
{
    sendall_reader_arg_t *a = argp;
    uint8_t chunk[3000];
    a->pattern_ok = 1;
    while (a->got < SENDALL_TOTAL) {
        if (a->bombard)
            pthread_kill(a->sender, SIGUSR1);
        ssize_t n = recv(a->fd, chunk, sizeof(chunk), 0);
        if (n <= 0)
            break;
        for (ssize_t i = 0; i < n; i++)
            if (chunk[i] != (uint8_t)((a->got + (size_t)i) & 0xFF))
                a->pattern_ok = 0;
        a->got += (size_t)n;
        usleep(1000);   /* drain slowly — keep the send buffer full */
    }
    return NULL;
}

TEST(test_send_all_survives_partial_writes_and_eintr)
{
    int sv[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    int sndbuf = 4096;   /* kernel clamps to its minimum; small is enough */
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sendall_sigusr1_handler;   /* no SA_RESTART on purpose */
    sigaction(SIGUSR1, &sa, &old_sa);

    uint8_t *buf = malloc(SENDALL_TOTAL);
    ASSERT_TRUE(buf != NULL);
    for (size_t i = 0; i < SENDALL_TOTAL; i++)
        buf[i] = (uint8_t)(i & 0xFF);

    sendall_reader_arg_t arg;
    memset(&arg, 0, sizeof(arg));
    arg.fd = sv[1];
    arg.sender = pthread_self();
    arg.bombard = 1;
    pthread_t reader;
    pthread_create(&reader, NULL, sendall_reader_thread, &arg);

    int rc = send_all(sv[0], buf, SENDALL_TOTAL);

    arg.bombard = 0;
    pthread_join(reader, NULL);
    sigaction(SIGUSR1, &old_sa, NULL);
    free(buf);
    close(sv[0]);
    close(sv[1]);

    ASSERT_EQ(rc, 0);
    ASSERT_EQ((int)arg.got, SENDALL_TOTAL);
    ASSERT_TRUE(arg.pattern_ok);
}

TEST(test_send_all_reports_dead_peer)
{
    int sv[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
    close(sv[1]);   /* peer gone before we send a byte */

    uint8_t junk[512];
    memset(junk, 0xAB, sizeof(junk));

    /* MSG_NOSIGNAL inside send_all: EPIPE must surface as -1, not as
     * SIGPIPE killing this test binary. */
    ASSERT_EQ(send_all(sv[0], junk, sizeof(junk)), -1);
    close(sv[0]);
}

/* send_framed itself under forced short writes: two frames through a
 * shrunken send buffer while SIGUSR1 (no SA_RESTART) bombards the
 * sender. The reader must recover EXACT framing — [len][payload] twice,
 * lengths and every payload byte intact, no trailing bytes. With the
 * old unlooped send() pair, a mid-frame short write drops bytes and
 * permanently desynchronizes the stream. */

extern int send_framed(int fd, const void *buf, size_t len);

#define SF_LEN1 (96 * 1024)
#define SF_LEN2 (32 * 1024 + 7)

typedef struct {
    int          fd;
    uint8_t     *buf;        /* collects everything until EOF */
    size_t       cap;
    size_t       got;
    pthread_t    sender;
    volatile int bombard;
} sf_reader_arg_t;

static void *sf_reader_thread(void *argp)
{
    sf_reader_arg_t *a = argp;
    uint8_t chunk[3000];
    for (;;) {
        if (a->bombard)
            pthread_kill(a->sender, SIGUSR1);
        ssize_t n = recv(a->fd, chunk, sizeof(chunk), 0);
        if (n <= 0)
            break;              /* EOF after the sender's SHUT_WR */
        if (a->got + (size_t)n <= a->cap)
            memcpy(a->buf + a->got, chunk, (size_t)n);
        a->got += (size_t)n;
        usleep(1000);           /* drain slowly — keep the buffer full */
    }
    return NULL;
}

TEST(test_send_framed_short_write_no_desync)
{
    int sv[2];
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

    int sndbuf = 4096;   /* kernel clamps to its minimum; small is enough */
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sendall_sigusr1_handler;   /* no SA_RESTART on purpose */
    sigaction(SIGUSR1, &sa, &old_sa);

    uint8_t *p1 = malloc(SF_LEN1), *p2 = malloc(SF_LEN2);
    ASSERT_TRUE(p1 != NULL && p2 != NULL);
    for (size_t i = 0; i < SF_LEN1; i++) p1[i] = (uint8_t)(i * 7 & 0xFF);
    for (size_t i = 0; i < SF_LEN2; i++) p2[i] = (uint8_t)(i * 13 & 0xFF);

    size_t expect = 4 + SF_LEN1 + 4 + SF_LEN2;
    sf_reader_arg_t arg;
    memset(&arg, 0, sizeof(arg));
    arg.fd = sv[1];
    arg.cap = expect + 4096;    /* room to detect surplus bytes */
    arg.buf = malloc(arg.cap);
    ASSERT_TRUE(arg.buf != NULL);
    arg.sender = pthread_self();
    arg.bombard = 1;
    pthread_t reader;
    pthread_create(&reader, NULL, sf_reader_thread, &arg);

    int rc1 = send_framed(sv[0], p1, SF_LEN1);
    int rc2 = send_framed(sv[0], p2, SF_LEN2);

    arg.bombard = 0;
    /* Aug 2 lesson: EOF the reader BEFORE joining, so a regression
     * hangs the write (visible failure), not the test harness. */
    shutdown(sv[0], SHUT_WR);
    pthread_join(reader, NULL);
    sigaction(SIGUSR1, &old_sa, NULL);

    ASSERT_EQ(rc1, 0);
    ASSERT_EQ(rc2, 0);
    ASSERT_EQ((long)arg.got, (long)expect);   /* nothing lost, nothing extra */

    /* Frame 1: length prefix intact, every payload byte intact. */
    uint32_t l1_n;
    memcpy(&l1_n, arg.buf, 4);
    ASSERT_EQ((long)ntohl(l1_n), (long)SF_LEN1);
    ASSERT_EQ(memcmp(arg.buf + 4, p1, SF_LEN1), 0);

    /* Frame 2 starts exactly where frame 1 ends — the desync check. */
    uint32_t l2_n;
    memcpy(&l2_n, arg.buf + 4 + SF_LEN1, 4);
    ASSERT_EQ((long)ntohl(l2_n), (long)SF_LEN2);
    ASSERT_EQ(memcmp(arg.buf + 4 + SF_LEN1 + 4, p2, SF_LEN2), 0);

    free(p1); free(p2); free(arg.buf);
    close(sv[0]);
    close(sv[1]);
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
 * SIGPIPE regression: peer closes before reading its response
 *
 * Pre-fix, every daemon send used flags=0 and neither entry path
 * ignored SIGPIPE, so an allowlisted client that disconnected before
 * reading its response killed the whole daemon (default SIGPIPE action
 * terminates the process). These tests run the server in-process: a
 * regression re-raises SIGPIPE and takes down this test binary — we
 * deliberately do NOT ignore SIGPIPE here, so the fix under test is the
 * daemon's own MSG_NOSIGNAL sends.
 * ========================================================================= */

/* One v2 framed request in a single send(), then close WITHOUT reading
 * the response. Retries connect briefly (accept-queue pressure under the
 * storm test). Returns 0 once the request left the socket. */
static int fire_and_close_framed(const char *json)
{
    int fd = -1;
    for (int tries = 0; tries < 5 && fd < 0; tries++) {
        fd = client_connect();
        if (fd < 0) usleep(1000);
    }
    if (fd < 0) return -1;

    uint8_t req[512];
    size_t json_len = strlen(json);
    if (5 + json_len > sizeof(req)) { close(fd); return -1; }
    uint32_t frame_len = htonl((uint32_t)(1 + json_len));
    memcpy(req, &frame_len, 4);
    req[4] = VIRP_FRAME_VERSION;
    memcpy(req + 5, json, json_len);
    ssize_t n = send(fd, req, 5 + json_len, 0);
    close(fd);   /* gone before the daemon can respond */
    return (n == (ssize_t)(5 + json_len)) ? 0 : -1;
}

/* v1-style client: raw unframed JSON, closed immediately. The daemon's
 * unframed reject send fires BEFORE the client is trusted — this send
 * site must also be SIGPIPE-safe. */
static int fire_and_close_v1(void)
{
    int fd = -1;
    for (int tries = 0; tries < 5 && fd < 0; tries++) {
        fd = client_connect();
        if (fd < 0) usleep(1000);
    }
    if (fd < 0) return -1;

    const char *json = "{\"action\":\"heartbeat\"}";
    ssize_t n = send(fd, json, strlen(json), 0);
    close(fd);   /* daemon's v1-reject hits a dead peer */
    return (n == (ssize_t)strlen(json)) ? 0 : -1;
}

/* Daemon must still answer a well-behaved client. */
static int daemon_still_serves(void)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = client_request("{\"action\": \"heartbeat\"}",
                               resp, sizeof(resp));
    if (n <= (ssize_t)VIRP_HEADER_SIZE) return 0;
    virp_header_t hdr;
    return virp_validate_message(resp, (size_t)n, &g_state.okey,
                                 &hdr) == VIRP_OK;
}

TEST(test_close_before_read_does_not_kill_daemon)
{
    ASSERT_EQ(fire_and_close_framed(
        "{\"action\":\"execute\",\"device\":\"R6\","
        "\"command\":\"show version\"}"), 0);
    usleep(150000);   /* let the daemon execute and hit the dead socket */
    ASSERT_TRUE(daemon_still_serves());
}

TEST(test_v1_reject_close_before_read_does_not_kill_daemon)
{
    ASSERT_EQ(fire_and_close_v1(), 0);
    usleep(100000);   /* let the unframed reject hit the dead socket */
    ASSERT_TRUE(daemon_still_serves());
}

/* 800-call storm: same 16×50 shape as the onode concurrency harness,
 * but over real sockets, every client closing before reading. Every
 * third call is a v1-reject client so the pre-trust send site stays
 * covered under contention. */
#define SP_WORKERS 16
#define SP_ITERS   50

typedef struct { int tid; int fired; } sp_arg_t;

static void *sigpipe_storm_thread(void *p)
{
    sp_arg_t *arg = (sp_arg_t *)p;
    for (int i = 0; i < SP_ITERS; i++) {
        int rc = ((i + arg->tid) % 3 == 0)
            ? fire_and_close_v1()
            : fire_and_close_framed(
                  "{\"action\":\"execute\",\"device\":\"R6\","
                  "\"command\":\"show version\"}");
        if (rc == 0) arg->fired++;
    }
    return NULL;
}

TEST(test_close_before_read_800_call_storm)
{
    pthread_t th[SP_WORKERS];
    sp_arg_t  args[SP_WORKERS];
    memset(args, 0, sizeof(args));

    for (int i = 0; i < SP_WORKERS; i++) {
        args[i].tid = i;
        ASSERT_EQ(pthread_create(&th[i], NULL, sigpipe_storm_thread,
                                 &args[i]), 0);
    }
    int fired = 0;
    for (int i = 0; i < SP_WORKERS; i++) {
        pthread_join(th[i], NULL);
        fired += args[i].fired;
    }

    /* All 800 hostile disconnects must have gone out... */
    ASSERT_EQ(fired, SP_WORKERS * SP_ITERS);

    /* ...and the daemon must have survived every one of them. */
    usleep(300000);   /* drain in-flight workers hitting dead sockets */
    ASSERT_TRUE(daemon_still_serves());
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

/* Per-uid tier ceiling (2026-08-09): a uid capped at GREEN has YELLOW
 * blocked (proposal-only), while the same YELLOW command from an
 * uncapped caller (client_uid == (uid_t)-1) executes under the node-wide
 * YELLOW ceiling. Proves the ceiling only TIGHTENS, is keyed on the
 * passed uid, and reports the effective ceiling in payload + log. */
static const uid_t CEIL_UID = 4242;

static int ceil_capture(onode_state_t *tmp, const char *cmd, uid_t uid,
                        uint8_t *buf, size_t bufsz, size_t *len,
                        char *logbuf, size_t logsz)
{
    const char *log_path = "/tmp/virp-onode-uidceil.log";
    fflush(stderr);
    int saved_fd = dup(fileno(stderr));
    if (saved_fd < 0) return -1;
    int log_fd = open(log_path, O_CREAT | O_TRUNC | O_WRONLY, 0600);
    if (log_fd < 0) { close(saved_fd); return -1; }
    dup2(log_fd, fileno(stderr));
    close(log_fd);

    virp_error_t err = onode_execute_obs_ex(tmp, "R-CEIL", cmd, 1, NULL,
                                            uid, buf, bufsz, len);

    fflush(stderr);
    dup2(saved_fd, fileno(stderr));
    close(saved_fd);

    FILE *lf = fopen(log_path, "r");
    if (!lf) return -1;
    size_t got = fread(logbuf, 1, logsz - 1, lf);
    fclose(lf);
    unlink(log_path);
    logbuf[got] = '\0';
    return (err == VIRP_OK) ? 0 : -1;
}

TEST(test_per_uid_ceiling_caps_yellow_but_not_uncapped)
{
    onode_state_t tmp;
    ASSERT_EQ(errobs_setup(&tmp, "R-CEIL", 0xE220000D), 0);
    /* node-wide ceiling is YELLOW (errobs_setup default); cap CEIL_UID at GREEN */
    uid_t cu[1] = { CEIL_UID };
    virp_trust_tier_t ct[1] = { VIRP_TIER_GREEN };
    ASSERT_OK(onode_set_uid_ceilings(&tmp, cu, ct, 1));

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    char logbuf[4096];

    /* 1. YELLOW ("clear counters") from the CAPPED uid → blocked, and the
     *    effective ceiling reported as GREEN in both payload and log. */
    ceil_capture(&tmp, "clear counters", CEIL_UID, buf, sizeof(buf), &len,
                 logbuf, sizeof(logbuf));
    {
        virp_observation_t obs; const uint8_t *data; uint16_t dl;
        ASSERT_OK(virp_parse_observation(buf + VIRP_HEADER_SIZE,
                                         len - VIRP_HEADER_SIZE, &obs, &data, &dl));
        ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
        ASSERT_TRUE(strstr((const char *)data, "tier gate blocked") != NULL);
        ASSERT_TRUE(strstr((const char *)data, "max=GREEN") != NULL);
    }
    ASSERT_TRUE(strstr(logbuf, "threshold=GREEN") != NULL);
    ASSERT_TRUE(strstr(logbuf, "decision=block") != NULL);
    ASSERT_TRUE(strstr(logbuf, "uid=4242") != NULL);

    /* 2. SAME YELLOW command from an UNCAPPED caller ((uid_t)-1) → allowed
     *    under the node-wide YELLOW ceiling: not tier-blocked. */
    len = 0;
    ceil_capture(&tmp, "clear counters", (uid_t)-1, buf, sizeof(buf), &len,
                 logbuf, sizeof(logbuf));
    ASSERT_TRUE(strstr(logbuf, "threshold=YELLOW") != NULL);
    ASSERT_TRUE(strstr(logbuf, "decision=allow") != NULL);

    /* 3. GREEN ("show version") from the capped uid → allowed (reads pass
     *    any ceiling). */
    len = 0;
    ceil_capture(&tmp, "show version", CEIL_UID, buf, sizeof(buf), &len,
                 logbuf, sizeof(logbuf));
    ASSERT_TRUE(strstr(logbuf, "threshold=GREEN") != NULL);
    ASSERT_TRUE(strstr(logbuf, "decision=allow") != NULL);

    errobs_teardown(&tmp);
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

extern void virp_driver_mock_set_unknown_fail(const char *msg);
extern int  virp_driver_mock_exec_attempts_reset(void);

/* (b2) Failure with no output and NO proof of non-dispatch (SSH write
 * completed but the response was lost; REST timeout after send): the
 * O-Node must execute EXACTLY ONCE — re-executing turns one
 * authorization into two executions — and must report a typed
 * OUTCOME_UNKNOWN, never executed=no and never executed output. */
TEST(test_unprovable_dispatch_unknown_not_retried)
{
    onode_state_t tmp;
    ASSERT_EQ(errobs_setup(&tmp, "R-UNK", 0xE220000E), 0);

    virp_driver_mock_exec_attempts_reset();
    virp_driver_mock_set_unknown_fail(
        "response lost after write on R-UNK");
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    virp_error_t err = onode_execute(&tmp, "R-UNK", "show version",
                                     buf, sizeof(buf), &len);
    virp_driver_mock_set_unknown_fail(NULL);
    int attempts = virp_driver_mock_exec_attempts_reset();
    ASSERT_OK(err);

    /* The load-bearing assertion: one authorization, one dispatch. */
    ASSERT_EQ(attempts, 1);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(buf, len, &tmp.okey, &hdr));
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(buf + VIRP_HEADER_SIZE,
                                     len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(strstr((const char *)data, "outcome UNKNOWN") != NULL);
    ASSERT_TRUE(strstr((const char *)data, "may have executed") != NULL);
    /* Must carry the driver's detail and not look like executed output */
    ASSERT_TRUE(strstr((const char *)data, "response lost after write")
                != NULL);
    ASSERT_TRUE(strstr((const char *)data, "R-UNK#") == NULL);

    errobs_teardown(&tmp);
}

/* (b3) PROVABLY non-dispatched failure (driver refusal with
 * no_dispatch=true): the single auto-retry is retained — nothing
 * reached the device, so the second execute is a first execution.
 * Exactly two attempts, then the refusal reported as before. */
TEST(test_provable_no_dispatch_retry_retained)
{
    onode_state_t tmp;
    ASSERT_EQ(errobs_setup(&tmp, "R-RETRY", 0xE220000F), 0);

    virp_driver_mock_exec_attempts_reset();
    virp_driver_mock_set_soft_fail("refused before device I/O");
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = 0;
    virp_error_t err = onode_execute(&tmp, "R-RETRY", "show version",
                                     buf, sizeof(buf), &len);
    virp_driver_mock_set_soft_fail(NULL);
    int attempts = virp_driver_mock_exec_attempts_reset();
    ASSERT_OK(err);

    /* Refusal on a proven-undispatched command retries exactly once. */
    ASSERT_EQ(attempts, 2);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(buf, len, &tmp.okey, &hdr));
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(buf + VIRP_HEADER_SIZE,
                                     len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));
    ASSERT_EQ(obs.obs_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(strstr((const char *)data, "refused before device I/O")
                != NULL);
    /* Refusal stays a refusal — not mislabeled UNKNOWN */
    ASSERT_TRUE(strstr((const char *)data, "outcome UNKNOWN") == NULL);

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
        "      \"node_id\":    \"0A0000FF\",\n"
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

    /* A valid node_id is REQUIRED (0 is refused, see
     * test_load_devices_refuses_absent_node_id), so this device carries a
     * real one; it must be parsed from the hex string. */
    ASSERT_EQ(tmp.devices[0].node_id, 0x0A0000FFu);
    /* Wrong-type fields must be treated as absent — zeroed by memset. */
    ASSERT_EQ((int)tmp.devices[0].enable_password[0], 0);  /* "enable": int */
    ASSERT_EQ((int)tmp.devices[0].api_token[0], 0);        /* "api_token": bool */
    ASSERT_EQ((int)tmp.devices[0].vdom[0], 0);             /* "vdom": int */
    ASSERT_EQ((int)tmp.devices[0].verify_tls, 0);          /* "verify_tls": str */

    onode_destroy(&tmp);
    virp_context_destroy(tmp.ctx);
    unlink(WRONG_TYPE_CFG);
}

/* A device whose node_id is absent/null/unparseable resolves to 0, which
 * onode_add_device refuses: node_id is the SIGNED identity an approval
 * binds to and 0 is not unique. The WHOLE config is refused (fail closed),
 * not the device silently dropped, and the null value must not crash the
 * loader. */
TEST(test_load_devices_refuses_absent_node_id)
{
    FILE *f = fopen(WRONG_TYPE_CFG, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f,
        "{\n"
        "  \"devices\": [\n"
        "    { \"hostname\": \"R-NONODE\", \"host\": \"10.0.0.77\",\n"
        "      \"vendor\": \"mock\", \"node_id\": null }\n"
        "  ]\n"
        "}\n");
    fclose(f);

    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0007, NULL,
                         "/tmp/virp-onode-nonode.sock"));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);

    ASSERT_EQ(load_devices(&tmp, WRONG_TYPE_CFG), -1);   /* refused, no crash */
    ASSERT_EQ(tmp.device_count, 0);

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

/*
 * Issue #14: a cisco_asa entry with no "enable" credential is refused
 * at load, not loaded to churn. The ASA driver's health check needs
 * enable mode; without a credential the watchdog connects, fails the
 * check, drops and reconnects on every backoff for the life of the
 * daemon. The refusal is per entry: the two ASA entries here (one with
 * no "enable" key, one with the issue-#7 wrong-type "enable": 0) must
 * be skipped, the ASA with a credential and the mock device must load.
 */
TEST(test_load_devices_refuses_asa_without_enable)
{
    FILE *f = fopen(WRONG_TYPE_CFG, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f,
        "{\n"
        "  \"devices\": [\n"
        "    { \"hostname\": \"ASA-NOENABLE\", \"host\": \"10.0.0.61\",\n"
        "      \"vendor\": \"cisco_asa\", \"username\": \"u\", \"password\": \"p\",\n"
        "      \"node_id\": \"0A000061\" },\n"
        "    { \"hostname\": \"ASA-BADTYPE\", \"host\": \"10.0.0.62\",\n"
        "      \"vendor\": \"cisco_asa\", \"username\": \"u\", \"password\": \"p\",\n"
        "      \"enable\": 0, \"node_id\": \"0A000062\" },\n"
        "    { \"hostname\": \"ASA-OK\", \"host\": \"10.0.0.63\",\n"
        "      \"vendor\": \"cisco_asa\", \"username\": \"u\", \"password\": \"p\",\n"
        "      \"enable\": \"s\", \"node_id\": \"0A000063\" },\n"
        "    { \"hostname\": \"R-MOCK\", \"host\": \"10.0.0.64\", \"vendor\": \"mock\",\n"
        "      \"node_id\": \"0A000064\" },\n"
        "    { \"hostname\": \"ASA-AUTOEN\", \"host\": \"10.0.0.65\",\n"
        "      \"vendor\": \"cisco_asa\", \"username\": \"u\", \"password\": \"p\",\n"
        "      \"asa_auto_enable\": true, \"node_id\": \"0A000065\" }\n"
        "  ]\n"
        "}\n");
    fclose(f);

    onode_state_t tmp;
    const char *tmp_sock = "/tmp/virp-onode-asaenable.sock";
    ASSERT_OK(onode_init(&tmp, 0xDEAD0004, NULL, tmp_sock));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);

    int loaded = load_devices(&tmp, WRONG_TYPE_CFG);
    ASSERT_EQ(loaded, 3);
    ASSERT_EQ(tmp.device_count, 3);
    /* Load order is preserved: the two refused entries leave no gap. */
    ASSERT_EQ(strcmp(tmp.devices[0].hostname, "ASA-OK"), 0);
    ASSERT_EQ((int)tmp.devices[0].vendor, (int)VIRP_VENDOR_CISCO_ASA);
    ASSERT_EQ(strcmp(tmp.devices[0].enable_password, "s"), 0);
    ASSERT_EQ(strcmp(tmp.devices[1].hostname, "R-MOCK"), 0);
    /* The declared auto-enable ASA loads without a credential. */
    ASSERT_EQ(strcmp(tmp.devices[2].hostname, "ASA-AUTOEN"), 0);
    ASSERT_TRUE(tmp.devices[2].asa_auto_enable);
    ASSERT_EQ(tmp.devices[2].enable_password[0], '\0');

    /* The refusals outlive the log line: both live in state, with the
     * reason, and the fleet listing reports them. */
    ASSERT_EQ(tmp.rejected_count, 2);
    ASSERT_EQ(strcmp(tmp.rejected[0].hostname, "ASA-NOENABLE"), 0);
    ASSERT_EQ(strcmp(tmp.rejected[1].hostname, "ASA-BADTYPE"), 0);
    ASSERT_TRUE(strstr(tmp.rejected[0].reason, "#14") != NULL);
    ASSERT_EQ((int)tmp.rejected[1].vendor, (int)VIRP_VENDOR_CISCO_ASA);

    onode_destroy(&tmp);
    virp_context_destroy(tmp.ctx);
    unlink(WRONG_TYPE_CFG);
}

/* =========================================================================
 * Duplicate device identities — hostname, node_id, and device_id are
 * each an authorization-binding key (request routing, approval device
 * binding, v2 observation identity). A collision in any of them lets
 * one device's evidence read as another's, so onode_add_device refuses
 * them and both loaders refuse the whole config, fail closed.
 * ========================================================================= */

static void dup_dev(virp_device_t *d, const char *hostname,
                    uint32_t node_id, uint64_t device_id)
{
    memset(d, 0, sizeof(*d));
    snprintf(d->hostname, sizeof(d->hostname), "%s", hostname);
    snprintf(d->host, sizeof(d->host), "10.9.9.9");
    d->port = 22;
    d->vendor = VIRP_VENDOR_MOCK;
    d->node_id = node_id;
    d->device_id = device_id;
    d->enabled = true;
}

TEST(test_add_device_rejects_duplicate_identities)
{
    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0004, NULL,
                         "/tmp/virp-onode-dup.sock"));

    virp_device_t d;
    dup_dev(&d, "R-DUP1", 0xD0000001, 0);   /* device_id derived */
    ASSERT_OK(onode_add_device(&tmp, &d));

    /* Duplicate hostname (everything else differs). */
    dup_dev(&d, "R-DUP1", 0xD0000002, 0);
    ASSERT_EQ(onode_add_device(&tmp, &d), VIRP_ERR_DUPLICATE_DEVICE);

    /* Duplicate node_id (hostname differs). */
    dup_dev(&d, "R-DUP2", 0xD0000001, 0);
    ASSERT_EQ(onode_add_device(&tmp, &d), VIRP_ERR_DUPLICATE_DEVICE);

    /* Duplicate device_id: explicit id colliding with the first
     * device's DERIVED id — the post-derivation check. */
    dup_dev(&d, "R-DUP3", 0xD0000003,
            virp_device_id_from_hostname("R-DUP1"));
    ASSERT_EQ(onode_add_device(&tmp, &d), VIRP_ERR_DUPLICATE_DEVICE);

    /* A rejected device must not occupy a slot. */
    ASSERT_EQ(tmp.device_count, 1);

    /* Fully unique device still loads. */
    dup_dev(&d, "R-DUP4", 0xD0000004, 0);
    ASSERT_OK(onode_add_device(&tmp, &d));
    ASSERT_EQ(tmp.device_count, 2);

    /* A device with node_id 0 (absent/empty/unparseable config value) is
     * REJECTED. node_id is the SIGNED identity an approval binds to and 0
     * is not unique: historically two node_id-0 devices were allowed to
     * coexist, which — with the unsigned hostname in the approval record —
     * made an approval fungible between them. Fail closed at load. */
    dup_dev(&d, "R-DUP5", 0, 0);
    ASSERT_EQ(onode_add_device(&tmp, &d), VIRP_ERR_DUPLICATE_DEVICE);
    dup_dev(&d, "R-DUP6", 0, 0);
    ASSERT_EQ(onode_add_device(&tmp, &d), VIRP_ERR_DUPLICATE_DEVICE);
    ASSERT_EQ(tmp.device_count, 2);   /* both rejected, count unchanged */

    onode_destroy(&tmp);
}

#define DUP_CFG "/tmp/virp-onode-dupcfg.json"

static int dup_load(const char *json)
{
    FILE *f = fopen(DUP_CFG, "w");
    if (!f) return -99;
    fputs(json, f);
    fclose(f);

    onode_state_t tmp;
    if (onode_init(&tmp, 0xDEAD0005, NULL,
                   "/tmp/virp-onode-dupcfg.sock") != VIRP_OK)
        return -98;
    int loaded = load_devices(&tmp, DUP_CFG);
    onode_destroy(&tmp);
    unlink(DUP_CFG);
    return loaded;
}

TEST(test_load_devices_duplicate_identities_fatal)
{
    /* Duplicate hostname → whole config refused, not one device kept. */
    ASSERT_EQ(dup_load(
        "{ \"devices\": ["
        " { \"hostname\": \"R-A\", \"host\": \"10.1.1.1\", \"vendor\": \"mock\", \"node_id\": \"0a000001\" },"
        " { \"hostname\": \"R-A\", \"host\": \"10.1.1.2\", \"vendor\": \"mock\", \"node_id\": \"0a000002\" }"
        "] }"), -1);

    /* Duplicate node_id → refused. */
    ASSERT_EQ(dup_load(
        "{ \"devices\": ["
        " { \"hostname\": \"R-A\", \"host\": \"10.1.1.1\", \"vendor\": \"mock\", \"node_id\": \"0a000001\" },"
        " { \"hostname\": \"R-B\", \"host\": \"10.1.1.2\", \"vendor\": \"mock\", \"node_id\": \"0a000001\" }"
        "] }"), -1);

    /* Duplicate explicit device_id → refused. */
    ASSERT_EQ(dup_load(
        "{ \"devices\": ["
        " { \"hostname\": \"R-A\", \"host\": \"10.1.1.1\", \"vendor\": \"mock\", \"node_id\": \"0a000001\", \"device_id\": \"deadbeef00000001\" },"
        " { \"hostname\": \"R-B\", \"host\": \"10.1.1.2\", \"vendor\": \"mock\", \"node_id\": \"0a000002\", \"device_id\": \"deadbeef00000001\" }"
        "] }"), -1);

    /* Unique config still loads both. */
    ASSERT_EQ(dup_load(
        "{ \"devices\": ["
        " { \"hostname\": \"R-A\", \"host\": \"10.1.1.1\", \"vendor\": \"mock\", \"node_id\": \"0a000001\" },"
        " { \"hostname\": \"R-B\", \"host\": \"10.1.1.2\", \"vendor\": \"mock\", \"node_id\": \"0a000002\" }"
        "] }"), 2);
}

/* =========================================================================
 * Autopilot hard exclusions — 10.0.10.1 / 10.0.10.10 must never load
 *
 * The text scan is boundary-aware: the LibreNMS host 10.0.10.12 and a
 * hypothetical 10.0.10.100 must NOT trip the assertion, while either
 * blocked address anywhere in the file (host field, spare key, comment)
 * must refuse the whole config.
 * ========================================================================= */

TEST(test_blocked_address_text_scan)
{
    /* Hits */
    ASSERT_TRUE(virp_config_blocked_address("\"host\": \"10.0.10.1\"") != NULL);
    ASSERT_TRUE(virp_config_blocked_address("\"host\": \"10.0.10.10\"") != NULL);
    ASSERT_TRUE(virp_config_blocked_address("x 10.0.10.1 y") != NULL);
    ASSERT_TRUE(virp_config_blocked_address("10.0.10.10") != NULL);
    /* Non-hits: neighbors that merely share the prefix */
    ASSERT_TRUE(virp_config_blocked_address("\"host\": \"10.0.10.12\"") == NULL);
    ASSERT_TRUE(virp_config_blocked_address("\"host\": \"10.0.10.100\"") == NULL);
    ASSERT_TRUE(virp_config_blocked_address("\"host\": \"110.0.10.1\"") == NULL);
    ASSERT_TRUE(virp_config_blocked_address("\"host\": \"210.0.10.10\"") == NULL);
    ASSERT_TRUE(virp_config_blocked_address("") == NULL);
    ASSERT_TRUE(virp_config_blocked_address(NULL) == NULL);
}

#define EXCLUSION_CFG "/tmp/virp-onode-exclusion.json"

TEST(test_load_devices_refuses_blocked_address)
{
    /* A config that is VALID in every respect except the blocked host:
     * the refusal must be the exclusion, not a parse error, and it must
     * refuse the WHOLE config (no skip-and-continue). */
    FILE *f = fopen(EXCLUSION_CFG, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f,
        "{\n"
        "  \"devices\": [\n"
        "    { \"hostname\": \"ok-device\", \"host\": \"10.0.10.12\", \"vendor\": \"mock\" },\n"
        "    { \"hostname\": \"edge-fw\", \"host\": \"10.0.10.1\", \"vendor\": \"mock\" }\n"
        "  ]\n"
        "}\n");
    fclose(f);

    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0004, NULL,
                         "/tmp/virp-onode-exclusion.sock"));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);

    int loaded = load_devices(&tmp, EXCLUSION_CFG);
    ASSERT_EQ(loaded, -1);
    ASSERT_EQ(tmp.device_count, 0);

    onode_destroy(&tmp);
    virp_context_destroy(tmp.ctx);
    unlink(EXCLUSION_CFG);
}

TEST(test_load_devices_allows_neighbor_addresses)
{
    /* The boundary rule: 10.0.10.12 (LibreNMS) and 10.0.10.100 load
     * fine — only the two exact addresses are excluded. */
    FILE *f = fopen(EXCLUSION_CFG, "w");
    ASSERT_TRUE(f != NULL);
    fprintf(f,
        "{\n"
        "  \"devices\": [\n"
        "    { \"hostname\": \"librenms\", \"host\": \"10.0.10.12\", \"vendor\": \"mock\", \"node_id\": \"0A000A0C\" },\n"
        "    { \"hostname\": \"far-host\", \"host\": \"10.0.10.100\", \"vendor\": \"mock\", \"node_id\": \"0A000A64\" }\n"
        "  ]\n"
        "}\n");
    fclose(f);

    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0005, NULL,
                         "/tmp/virp-onode-exclusion.sock"));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);

    int loaded = load_devices(&tmp, EXCLUSION_CFG);
    ASSERT_EQ(loaded, 2);
    ASSERT_EQ(tmp.device_count, 2);

    onode_destroy(&tmp);
    virp_context_destroy(tmp.ctx);
    unlink(EXCLUSION_CFG);
}

/* =========================================================================
 * Gate-reason RETENTION (2026-07-30)
 *
 * A gate_rejection entry used to store sha256(reason) and NO body, so an
 * evidence report could prove a block happened and commit to its reason
 * but could not show the reason from the chain alone — the text lived
 * only in the daemon journal. The daemon now stores a structured reason
 * body (schema gate_rejection/1) under the same artifact_id the entry
 * names, still committed to by artifact_hash.
 *
 * This test blocks a command against a chain-enabled state, then reads
 * the chain BACK and asserts:
 *   - a gate_rejection entry exists,
 *   - its body is present in the artifact store,
 *   - sha256(body) equals the entry's committed artifact_hash,
 *   - the body carries the command, tiers and human-readable message.
 * The readback goes through SQLite directly because the chain exposes a
 * store API but no body-read API — a reader is exactly what an evidence
 * report is, so the test reads the way a report does.
 * ========================================================================= */

/* Declared again here: the shared extern below sits further down the
 * file, after this test. */
extern virp_error_t onode_setup_chain_and_approvals(onode_state_t *state,
                                                    uint32_t node_id,
                                                    const char *chain_db_path,
                                                    const char *chain_key_path,
                                                    const char *approval_dir,
                                                    const char *approvers_path);

#define GR_CHAIN_DB  "/tmp/virp-onode-test-grchain.db"
#define GR_CHAIN_KEY "/tmp/virp-onode-test-grchain.key"

static void gr_cleanup(void)
{
    unlink(GR_CHAIN_DB);
    unlink(GR_CHAIN_DB "-wal");
    unlink(GR_CHAIN_DB "-shm");
    unlink(GR_CHAIN_KEY);
}

/* sha256 hex of a NUL-terminated string, mirroring gate_sha256_hex(). */
static void gr_sha256_hex(const char *s, char out[65])
{
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_Digest(s, strlen(s), md, &mdlen, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", md[i]);
}

TEST(test_gate_rejection_reason_body_is_retained_and_matches_commitment)
{
    gr_cleanup();

    virp_signing_key_t ck;
    ASSERT_OK(virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN));
    ASSERT_OK(virp_key_save_file(&ck, GR_CHAIN_KEY));
    virp_key_destroy(&ck);

    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0007, NULL,
                         "/tmp/virp-onode-grchain.sock"));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);
    /* ENFORCE at YELLOW: an unclassified command is blocked and the
     * rejection is persisted (the branch is dormant under SHADOW). */
    tmp.gate_default_mode = GATE_MODE_ENFORCE;
    tmp.gate_max_tier = VIRP_TIER_YELLOW;

    /* Chain enabled, approval mode OFF: the paths must be non-NULL, but
     * a registry that does not exist enrolls zero keys and leaves the
     * flow disabled (fail safe), so no proposal is filed and the
     * rejection-persistence path is what is under test. */
    ASSERT_OK(onode_setup_chain_and_approvals(&tmp, 0xDEAD0007,
                                              GR_CHAIN_DB, GR_CHAIN_KEY,
                                              "/tmp/virp-onode-test-grapprovals",
                                              "/tmp/virp-onode-test-no-registry"));
    ASSERT_EQ((int)tmp.chain_enabled, 1);
    ASSERT_EQ((int)tmp.approvers_loaded, 0);

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "R-REASON");
    snprintf(dev.host, sizeof(dev.host), "10.0.0.97");
    dev.port = 22;
    dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0BADF00D;
    dev.enabled = true;
    ASSERT_OK(onode_add_device(&tmp, &dev));

    const char *blocked = "frobnicate the flux capacitor";
    uint8_t obs_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t obs_len = 0;
    ASSERT_OK(onode_execute(&tmp, "R-REASON", blocked,
                            obs_buf, sizeof(obs_buf), &obs_len));

    /* The response is a signed ERROR observation — nothing executed. */
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs_buf, obs_len, &tmp.okey, &hdr));

    onode_destroy(&tmp);            /* flush + close the chain */
    virp_context_destroy(tmp.ctx);

    /* ── read the chain back the way an evidence report does ── */
    sqlite3 *db = NULL;
    ASSERT_EQ(sqlite3_open(GR_CHAIN_DB, &db), SQLITE_OK);

    sqlite3_stmt *st = NULL;
    ASSERT_EQ(sqlite3_prepare_v2(db,
        "SELECT e.artifact_id, e.artifact_hash, a.artifact_content "
        "FROM chain_entries e "
        "LEFT JOIN artifacts a ON a.artifact_id = e.artifact_id "
        "WHERE e.artifact_type = 'gate_rejection' "
        "ORDER BY e.id DESC LIMIT 1", -1, &st, NULL), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);

    const char *aid  = (const char *)sqlite3_column_text(st, 0);
    const char *ahash = (const char *)sqlite3_column_text(st, 1);
    const char *abody = (const char *)sqlite3_column_text(st, 2);

    ASSERT_TRUE(aid != NULL && strncmp(aid, "gatereject-", 11) == 0);
    ASSERT_TRUE(ahash != NULL && strlen(ahash) == 64);

    /* The body must be PRESENT — this is the whole point. */
    ASSERT_TRUE(abody != NULL);
    ASSERT_TRUE(abody[0] != '\0');

    /* …and it must hash to the entry's commitment. */
    char recomputed[65];
    gr_sha256_hex(abody, recomputed);
    ASSERT_EQ(strcmp(recomputed, ahash), 0);

    /* …and it must actually carry the reason, not just be non-empty. */
    ASSERT_TRUE(strstr(abody, "\"schema\":\"gate_rejection/1\"") != NULL);
    ASSERT_TRUE(strstr(abody, blocked) != NULL);
    ASSERT_TRUE(strstr(abody, "\"device\":\"R-REASON\"") != NULL);
    ASSERT_TRUE(strstr(abody, "\"classified_tier\":\"UNCLASSIFIED\"") != NULL);
    ASSERT_TRUE(strstr(abody, "\"gate_max_tier\":\"YELLOW\"") != NULL);
    ASSERT_TRUE(strstr(abody, "tier gate blocked") != NULL);
    /* executed=no is literal: an ERROR observation means it never ran. */
    ASSERT_TRUE(strstr(abody, "\"executed\":false") != NULL);

    sqlite3_finalize(st);
    sqlite3_close(db);
    gr_cleanup();
}

/* Regression (2026-08-18): a gate_rejection/1 body must record the ceiling
 * that ACTUALLY fired, not only the node-wide max. The live Nexus
 * reconciliation found a YELLOW-classified command (show running-config)
 * refused under uid 993's per-uid GREEN ceiling while the chain body recorded
 * only gate_max_tier=YELLOW — which misreads as "should have passed". Here a
 * YELLOW command ("clear counters" — YELLOW in both the mock and the real
 * cisco classifier, the same YELLOW-under-GREEN decision shape as
 * running-config) is refused under a per-uid GREEN ceiling; the body must now
 * carry effective_max_tier=GREEN and ceiling_source=per-uid, with the
 * node-wide gate_max_tier=YELLOW retained for continuity. */
TEST(test_gate_rejection_records_per_uid_effective_ceiling)
{
    gr_cleanup();

    virp_signing_key_t ck;
    ASSERT_OK(virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN));
    ASSERT_OK(virp_key_save_file(&ck, GR_CHAIN_KEY));
    virp_key_destroy(&ck);

    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0008, NULL, "/tmp/virp-onode-grceil.sock"));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);
    tmp.gate_default_mode = GATE_MODE_ENFORCE;
    tmp.gate_max_tier = VIRP_TIER_YELLOW;              /* node-wide */

    ASSERT_OK(onode_setup_chain_and_approvals(&tmp, 0xDEAD0008,
                                              GR_CHAIN_DB, GR_CHAIN_KEY,
                                              "/tmp/virp-onode-test-grceilappr",
                                              "/tmp/virp-onode-test-no-registry"));
    ASSERT_EQ((int)tmp.chain_enabled, 1);

    /* Cap a uid at GREEN, below the node-wide YELLOW (the netclaw shape). */
    const uid_t capped = 4993;
    uid_t cu[1] = { capped };
    virp_trust_tier_t ct[1] = { VIRP_TIER_GREEN };
    ASSERT_OK(onode_set_uid_ceilings(&tmp, cu, ct, 1));

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "R-CEIL-REC");
    snprintf(dev.host, sizeof(dev.host), "10.0.0.98");
    dev.port = 22;
    dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0BADCEE1;
    dev.enabled = true;
    ASSERT_OK(onode_add_device(&tmp, &dev));

    uint8_t obs_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t obs_len = 0;
    ASSERT_OK(onode_execute_obs_ex(&tmp, "R-CEIL-REC", "clear counters",
                                   1, NULL, capped,
                                   obs_buf, sizeof(obs_buf), &obs_len));
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs_buf, obs_len, &tmp.okey, &hdr));

    onode_destroy(&tmp);
    virp_context_destroy(tmp.ctx);

    sqlite3 *db = NULL;
    ASSERT_EQ(sqlite3_open(GR_CHAIN_DB, &db), SQLITE_OK);
    sqlite3_stmt *st = NULL;
    ASSERT_EQ(sqlite3_prepare_v2(db,
        "SELECT a.artifact_content FROM chain_entries e "
        "LEFT JOIN artifacts a ON a.artifact_id = e.artifact_id "
        "WHERE e.artifact_type = 'gate_rejection' "
        "ORDER BY e.id DESC LIMIT 1", -1, &st, NULL), SQLITE_OK);
    ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    const char *body = (const char *)sqlite3_column_text(st, 0);
    ASSERT_TRUE(body != NULL && body[0] != '\0');

    /* The command is YELLOW and the node-wide max is YELLOW — so gate_max_tier
     * alone would say "allow". The refusal is only explained by the per-uid
     * GREEN ceiling, which the record must now name as the binding one. */
    ASSERT_TRUE(strstr(body, "\"classified_tier\":\"YELLOW\"") != NULL);
    ASSERT_TRUE(strstr(body, "\"gate_max_tier\":\"YELLOW\"") != NULL);
    ASSERT_TRUE(strstr(body, "\"effective_max_tier\":\"GREEN\"") != NULL);
    ASSERT_TRUE(strstr(body, "\"ceiling_source\":\"per-uid\"") != NULL);

    sqlite3_finalize(st);
    sqlite3_close(db);
    gr_cleanup();
}

/* =========================================================================
 * GREEN auto-execution RECORDS (2026-08-12)
 *
 * The chain used to be a complete record of what the gate REFUSED and a
 * blank on what it ALLOWED. GREEN executes with no human in the loop, so
 * that blank covered exactly the actions nobody approved. The daemon now
 * writes a gate_execution entry for every auto-executed action, in the
 * same chain and the same "gate-enforce:<device>" session as the
 * rejections, so executions and refusals interleave under one continuous
 * prev-hash linkage.
 *
 * The entry commits to a DIGEST of the device response, never the
 * response itself: GREEN output can carry credential material and the
 * chain is tamper-evident and therefore not scrubbable, so storing bodies
 * would make the ledger a secret store. These tests assert that property
 * directly rather than trusting the code comment — a device response
 * carrying a token-shaped string must reach the caller and must not reach
 * the chain, while its digest must.
 *
 * As in the gate-reason test above, readback goes through SQLite: a
 * reader is exactly what an evidence report is.
 * ========================================================================= */

#define GX_CHAIN_DB  "/tmp/virp-onode-test-gxchain.db"
#define GX_CHAIN_KEY "/tmp/virp-onode-test-gxchain.key"
#define GX_SESSION   "gate-enforce:PVE-LAB"
#define GX_MAX_ROWS  12

extern void virp_driver_mock_set_output(const char *text);

static void gx_cleanup(void)
{
    unlink(GX_CHAIN_DB);
    unlink(GX_CHAIN_DB "-wal");
    unlink(GX_CHAIN_DB "-shm");
    unlink(GX_CHAIN_KEY);
}

typedef struct {
    long long seq;
    char type[24];
    char id[80];
    char ahash[65];      /* entry's commitment            */
    char ehash[65];      /* this entry's hash             */
    char prev[65];       /* previous entry's hash         */
    char body[4096];     /* stored artifact body, if any  */
    int  have_body;
} gx_row_t;

static void gx_copy(char *dst, size_t cap, const unsigned char *src)
{
    snprintf(dst, cap, "%s", src ? (const char *)src : "");
}

/* Every entry of a session in sequence order, joined to its stored body.
 * The join is on (artifact_id, artifact_hash) — the artifacts table's real
 * key — so a row can never pick up a body belonging to a different
 * commitment that happens to share an id. */
static int gx_read_session(const char *session, gx_row_t *rows, int max)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(GX_CHAIN_DB, &db) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "SELECT e.sequence, e.artifact_type, e.artifact_id, "
            "       e.artifact_hash, e.chain_entry_hash, "
            "       e.previous_entry_hash, a.artifact_content "
            "FROM chain_entries e "
            "LEFT JOIN artifacts a "
            "       ON a.artifact_id = e.artifact_id "
            "      AND a.artifact_hash = e.artifact_hash "
            "WHERE e.session_id = ? "
            "ORDER BY e.sequence ASC", -1, &st, NULL) != SQLITE_OK) {
        sqlite3_close(db);
        return -1;
    }
    sqlite3_bind_text(st, 1, session, -1, SQLITE_TRANSIENT);

    int n = 0;
    while (n < max && sqlite3_step(st) == SQLITE_ROW) {
        gx_row_t *r = &rows[n];
        memset(r, 0, sizeof(*r));
        r->seq = sqlite3_column_int64(st, 0);
        gx_copy(r->type,  sizeof(r->type),  sqlite3_column_text(st, 1));
        gx_copy(r->id,    sizeof(r->id),    sqlite3_column_text(st, 2));
        gx_copy(r->ahash, sizeof(r->ahash), sqlite3_column_text(st, 3));
        gx_copy(r->ehash, sizeof(r->ehash), sqlite3_column_text(st, 4));
        gx_copy(r->prev,  sizeof(r->prev),  sqlite3_column_text(st, 5));
        const unsigned char *b = sqlite3_column_text(st, 6);
        if (b) {
            r->have_body = 1;
            gx_copy(r->body, sizeof(r->body), b);
        }
        n++;
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return n;
}

static int gx_bytes_contain(const void *hay, size_t hlen, const char *needle)
{
    return memmem(hay, hlen, needle, strlen(needle)) != NULL;
}

/* 1 = present, 0 = absent, -1 = file too big to scan. The -1 matters: a
 * secret-absence assertion must never pass because the scan quietly gave
 * up. */
static int gx_file_contains(const char *path, const char *needle)
{
    static char buf[1 << 20];
    FILE *f = fopen(path, "rb");
    if (!f) return 0;                    /* -wal/-shm may not exist */
    size_t n = fread(buf, 1, sizeof(buf), f);
    int overflow = !feof(f);
    fclose(f);
    if (overflow) return -1;
    return (n > 0 && memmem(buf, n, needle, strlen(needle)) != NULL) ? 1 : 0;
}

/* ENFORCE at GREEN with the chain on and approvals off — the pve-lab
 * posture. The approver registry path does not exist, so zero keys enroll,
 * approval_dir stays empty and no proposals are filed: the session holds
 * gate verdicts and nothing else. */
static virp_error_t gx_setup(onode_state_t *st)
{
    gx_cleanup();

    virp_signing_key_t ck;
    virp_error_t e = virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN);
    if (e != VIRP_OK) return e;
    e = virp_key_save_file(&ck, GX_CHAIN_KEY);
    virp_key_destroy(&ck);
    if (e != VIRP_OK) return e;

    e = onode_init(st, 0xDEAD0008, NULL, "/tmp/virp-onode-gxchain.sock");
    if (e != VIRP_OK) return e;
    st->ctx = virp_context_new();
    if (!st->ctx) return VIRP_ERR_NULL_PTR;
    st->gate_default_mode = GATE_MODE_ENFORCE;
    st->gate_max_tier = VIRP_TIER_GREEN;

    e = onode_setup_chain_and_approvals(st, 0xDEAD0008,
                                        GX_CHAIN_DB, GX_CHAIN_KEY,
                                        "/tmp/virp-onode-test-gxapprovals",
                                        "/tmp/virp-onode-test-no-registry");
    if (e != VIRP_OK) return e;
    if (!st->chain_enabled) return VIRP_ERR_CHAIN_DB;
    if (st->approvers_loaded) return VIRP_ERR_INVALID_TYPE;

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "PVE-LAB");
    snprintf(dev.host, sizeof(dev.host), "10.0.0.98");
    dev.port = 22;
    dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0BADCAFE;
    dev.enabled = true;
    return onode_add_device(st, &dev);
}

static void gx_teardown(onode_state_t *st)
{
    virp_context_t *ctx = st->ctx;
    onode_destroy(st);              /* flush + close the chain */
    virp_context_destroy(ctx);
}

extern void virp_driver_mock_set_refusal_with_body(const char *body_text);
extern void virp_driver_mock_set_declared_refusal(const char *body_text);

/*
 * STEP 1 — proves the routing clause added in step 1 actually fires.
 *
 * A refusal that DECLARES non-dispatch (no_dispatch + NOT_SENT) must be
 * routed to VIRP_OBS_ERROR even though it wrote a non-empty body. Before
 * step 1 the branch required output_len == 0, so a declared refusal
 * carrying a banner still fell through to DEVICE_OUTPUT.
 *
 * This test PASSES on step 1 alone. Its two siblings above stay red until
 * step 2 teaches the real drivers to declare — the split is deliberate:
 * this one covers the routing, they cover the signal.
 */
TEST(test_declared_refusal_with_body_routes_to_error)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));

    virp_driver_mock_set_declared_refusal(
        "PVE-LAB#show version\nBLACK tier: command forbidden");

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    virp_error_t err = onode_execute(&st, "PVE-LAB", "show version",
                                     obs, sizeof(obs), &olen);
    virp_driver_mock_set_declared_refusal(NULL);
    ASSERT_OK(err);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    virp_observation_t o;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(obs + VIRP_HEADER_SIZE,
                                     olen - VIRP_HEADER_SIZE,
                                     &o, &data, &data_len));

    uint8_t got_type = o.obs_type;
    int echoed = (strstr((const char *)data, "PVE-LAB#") != NULL);

    gx_teardown(&st);
    gx_cleanup();

    ASSERT_EQ(got_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(!echoed);
}


/*
 * STEP 0 — DEFECT DEMONSTRATION (Defect B, execution truth).
 *
 * A driver-level policy refusal that writes its reason into
 * result->output must NOT be recorded as an execution.
 *
 * This is the shape five production drivers actually emit
 * (driver_asa.c:1027, driver_cisco.c:1078, driver_juniper.c:684,
 * driver_juniper.c:996, driver_fortigate.c:802): VIRP_OK,
 * success=false, a NON-EMPTY output body, and no no_dispatch /
 * disposition signal.
 *
 * Both onode refusal filters (virp_onode.c:1892 and :1940) require
 * output_len == 0, so this shape defeats both, falls through to the
 * success path at :1984, and is recorded "executed":true and signed as
 * DEVICE_OUTPUT.
 *
 * The existing guard test_error_obs_driver_refusal_is_error_not_output
 * asserts this same contract but drives the mock through
 * set_soft_fail, which sets no_dispatch=true AND writes no output — the
 * shape where both filters already fire. No test has ever exercised the
 * shape below, which is how a fix that was made, tested and believed
 * complete has been defeated in production ever since.
 *
 * The gate is ENFORCE/GREEN and the command is GREEN, so the gate
 * ADMITS it and the driver's own backstop refuses — classifier
 * disagreement, reachable today without SHADOW.
 *
 * THIS TEST FAILS ON UNFIXED CODE. That is its purpose in Step 0.
 */
TEST(test_refusal_with_body_is_not_an_execution)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));

    /* Exactly what driver_cisco.c:1078 writes into result->output. */
    virp_driver_mock_set_refusal_with_body(
        "PVE-LAB#show version\nBLACK tier: command forbidden");

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    virp_error_t err = onode_execute(&st, "PVE-LAB", "show version",
                                     obs, sizeof(obs), &olen);
    virp_driver_mock_set_refusal_with_body(NULL);
    ASSERT_OK(err);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    virp_observation_t o;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(obs + VIRP_HEADER_SIZE,
                                     olen - VIRP_HEADER_SIZE,
                                     &o, &data, &data_len));

    /* Capture, then release BEFORE asserting. An ASSERT returns from the
     * test, so asserting first would skip gx_teardown/gx_cleanup and leave
     * an open chain handle on a db the next test's gx_setup deletes — the
     * following test then reads zero rows and fails for a reason that has
     * nothing to do with its subject. Teardown-then-assert keeps each
     * failure attributable to its own test. */
    uint8_t  got_obs_type = o.obs_type;
    int      echoed_prompt =
        (strstr((const char *)data, "PVE-LAB#") != NULL);

    gx_teardown(&st);
    gx_cleanup();

    /* (1) A refusal is not device output. Every real consumer branches on
     * obs_type: virp_tool.c:807 derives is_rejection from it and prints
     * gate_decision=allowed / exit 0 for DEVICE_OUTPUT, and
     * api/server.py:567 renders it as something a device said. */
    ASSERT_EQ(got_obs_type, VIRP_OBS_ERROR);

    /* (2) The refusal banner must not go out as though the device spoke
     * it. The device said nothing; it was never asked. */
    ASSERT_TRUE(!echoed_prompt);
}

/*
 * STEP 0 — DEFECT DEMONSTRATION, ledger half.
 *
 * Split from the test above deliberately: an ASSERT returns from the
 * test, so a single test would abort on the obs_type mismatch and never
 * reach the ledger claim. The two halves fail for different reasons and
 * are fixed by different edits (Step 1 routes the observation, Steps 1-2
 * supply the non-dispatch proof), so they report independently.
 *
 * THIS TEST FAILS ON UNFIXED CODE.
 */
TEST(test_refusal_with_body_is_not_recorded_executed)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));

    virp_driver_mock_set_refusal_with_body(
        "PVE-LAB#show version\nBLACK tier: command forbidden");

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    virp_error_t err = onode_execute(&st, "PVE-LAB", "show version",
                                     obs, sizeof(obs), &olen);
    virp_driver_mock_set_refusal_with_body(NULL);
    ASSERT_OK(err);

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    int n = gx_read_session(GX_SESSION, rows, GX_MAX_ROWS);

    /* Same discipline as above: capture the verdicts, release the db, then
     * assert. */
    int is_exec_row  = (n == 1 && strcmp(rows[0].type, "gate_execution") == 0);
    int has_body     = (n == 1 && rows[0].have_body);
    int claims_ran   = (n == 1 && rows[0].have_body &&
                        strstr(rows[0].body, "\"executed\":true") != NULL);

    gx_cleanup();

    ASSERT_EQ(n, 1);
    ASSERT_TRUE(is_exec_row);
    ASSERT_TRUE(has_body);

    /* The ledger must not assert that a refused command ran. This is the
     * fabricated FACT, as distinct from the fabricated string: 40,388
     * gate_execution entries carry this field. */
    ASSERT_TRUE(!claims_ran);
}

/*
 * A GREEN auto-execution leaves a signed, chained, prev-hash-linked
 * gate_execution entry — the thing that was missing. The rejection filed
 * first is what the execution must link to: same chain, same session.
 */
TEST(test_green_execution_chains_signed_observation)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;

    /* Refused RED command, so the execution below has a prior entry. */
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "reload now",
                            obs, sizeof(obs), &olen));

    /* The GREEN auto-execution under test. */
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "show version",
                            obs, sizeof(obs), &olen));

    /* The caller still gets its O-Key-signed observation, unchanged. */
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    /* The whole session verifies: per-entry HMAC, continuous linkage, and
     * the signed head record. */
    virp_chain_verify_result_t vr;
    ASSERT_OK(virp_chain_verify_session(&st.chain, GX_SESSION, &vr));
    ASSERT_TRUE(vr.valid);

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    int n = gx_read_session(GX_SESSION, rows, GX_MAX_ROWS);
    ASSERT_EQ(n, 2);

    ASSERT_EQ(strcmp(rows[0].type, "gate_rejection"), 0);
    ASSERT_EQ(strcmp(rows[1].type, "gate_execution"), 0);

    /* Interleaved in one chain with unbroken linkage. */
    ASSERT_EQ((int)rows[1].seq, (int)rows[0].seq + 1);
    ASSERT_EQ(strcmp(rows[1].prev, rows[0].ehash), 0);

    /* Body retained and bound to the entry's commitment. */
    ASSERT_TRUE(rows[1].have_body);
    ASSERT_TRUE(rows[1].body[0] != '\0');
    char recomputed[65];
    gr_sha256_hex(rows[1].body, recomputed);
    ASSERT_EQ(strcmp(recomputed, rows[1].ahash), 0);

    ASSERT_TRUE(strncmp(rows[1].id, "gateexec-", 9) == 0);
    ASSERT_TRUE(strstr(rows[1].body,
                       "\"schema\":\"gate_execution/1\"") != NULL);
    ASSERT_TRUE(strstr(rows[1].body, "\"device\":\"PVE-LAB\"") != NULL);
    ASSERT_TRUE(strstr(rows[1].body, "\"driver\":\"mock\"") != NULL);
    ASSERT_TRUE(strstr(rows[1].body,
                       "\"command\":\"show version\"") != NULL);
    ASSERT_TRUE(strstr(rows[1].body,
                       "\"classified_tier\":\"GREEN\"") != NULL);
    ASSERT_TRUE(strstr(rows[1].body,
                       "\"decision\":\"auto-execute\"") != NULL);
    ASSERT_TRUE(strstr(rows[1].body, "\"gate_mode\":\"ENFORCE\"") != NULL);
    ASSERT_TRUE(strstr(rows[1].body, "\"executed\":true") != NULL);
    ASSERT_TRUE(strstr(rows[1].body, "\"success\":true") != NULL);
    ASSERT_TRUE(strstr(rows[1].body, "\"response_sha256\":\"") != NULL);

    gx_cleanup();
}

/*
 * THE SECRET-SAFETY PROPERTY, asserted directly.
 *
 * A GREEN device response carrying a token-shaped string does NOT appear
 * anywhere in the chain — not in the entry, not in the artifact body,
 * not anywhere in the database file. Its sha256 commitment does.
 *
 * S-1 upgraded this property: scrub-at-capture now redacts the token
 * BEFORE the observation is signed, so the secret is absent from the
 * signed observation too — the caller receives the marker, and the
 * response_sha256 commitment is over the SCRUBBED bytes (the redacted
 * form IS the artifact; there is no unredacted original anywhere).
 * The pre-S-1 form of this test asserted the caller still received the
 * raw token; that assertion is deliberately inverted now.
 */
TEST(test_execution_record_commits_to_digest_not_response_body)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));

    static const char TOKEN[] = "sk-live-DEADBEEFCAFEBABE0123456789";
    char response[512];
    snprintf(response, sizeof(response),
             "root@pve-lab:~# qm status 100\n"
             "status: stopped\n"
             "PVE_API_TOKEN=%s\n", TOKEN);
    virp_driver_mock_set_output(response);

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "show status",
                            obs, sizeof(obs), &olen));
    virp_driver_mock_set_output(NULL);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    /* S-1: the caller receives the REDACTED body — marker present,
     * token absent, non-secret lines intact. */
    ASSERT_TRUE(!gx_bytes_contain(obs, olen, TOKEN));
    ASSERT_TRUE(gx_bytes_contain(obs, olen, "PVE_API_TOKEN=[REDACTED: token]"));
    ASSERT_TRUE(gx_bytes_contain(obs, olen, "status: stopped"));

    /* The commitment must be over the scrubbed bytes the observation
     * actually carries — recompute independently. */
    static char scrubbed[VIRP_OUTPUT_MAX];
    size_t scrubbed_len = 0;
    unsigned nred = 0;
    ASSERT_OK(virp_scrub_body(response, strlen(response), scrubbed,
                              sizeof(scrubbed), &scrubbed_len, &nred));
    scrubbed[scrubbed_len] = '\0';
    ASSERT_EQ((int)nred, 1);

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    int n = gx_read_session(GX_SESSION, rows, GX_MAX_ROWS);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(strcmp(rows[0].type, "gate_execution"), 0);
    ASSERT_TRUE(rows[0].have_body);

    /* The token is absent from every field of the chained entry… */
    ASSERT_TRUE(strstr(rows[0].body,  TOKEN) == NULL);
    ASSERT_TRUE(strstr(rows[0].id,    TOKEN) == NULL);
    ASSERT_TRUE(strstr(rows[0].ahash, TOKEN) == NULL);

    /* …and so is the rest of the response body: the entry does not store
     * a scrubbed response, it stores no response. */
    ASSERT_TRUE(strstr(rows[0].body, "status: stopped") == NULL);
    ASSERT_TRUE(strstr(rows[0].body, "PVE_API_TOKEN") == NULL);

    /* …and it is nowhere in the database at all. */
    ASSERT_EQ(gx_file_contains(GX_CHAIN_DB, TOKEN), 0);
    ASSERT_EQ(gx_file_contains(GX_CHAIN_DB "-wal", TOKEN), 0);

    /* What IS committed is the digest of the SCRUBBED response — the
     * only response bytes that exist anywhere after S-1. */
    char digest[65];
    gr_sha256_hex(scrubbed, digest);
    char want[128];
    snprintf(want, sizeof(want), "\"response_sha256\":\"%s\"", digest);
    ASSERT_TRUE(strstr(rows[0].body, want) != NULL);

    /* …along with the length of the bytes that digest covers. */
    char want_len[64];
    snprintf(want_len, sizeof(want_len), "\"response_len\":%zu",
             scrubbed_len);
    ASSERT_TRUE(strstr(rows[0].body, want_len) != NULL);

    /* The command IS retained — an execution record that omits what was
     * executed is not a record. */
    ASSERT_TRUE(strstr(rows[0].body, "\"command\":\"show status\"") != NULL);

    /* And the body still binds to its commitment. */
    char recomputed[65];
    gr_sha256_hex(rows[0].body, recomputed);
    ASSERT_EQ(strcmp(recomputed, rows[0].ahash), 0);

    gx_cleanup();
}

/*
 * An executed action that ERRORED still lands in the chain. A gap here
 * would be the worst kind: the actions most worth auditing are the ones
 * that went wrong, and a driver error is no proof the command never
 * reached the device — so the record says executed=true and flags that
 * the driver could not report what happened.
 */
TEST(test_errored_execution_still_chains_no_gap)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));

    virp_driver_mock_set_forced_error(VIRP_ERR_CRYPTO);
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "show version",
                            obs, sizeof(obs), &olen));
    virp_driver_mock_set_forced_error(VIRP_OK);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    virp_chain_verify_result_t vr;
    ASSERT_OK(virp_chain_verify_session(&st.chain, GX_SESSION, &vr));
    ASSERT_TRUE(vr.valid);

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    int n = gx_read_session(GX_SESSION, rows, GX_MAX_ROWS);
    ASSERT_EQ(n, 1);                     /* the failure IS recorded */
    ASSERT_EQ(strcmp(rows[0].type, "gate_execution"), 0);
    ASSERT_TRUE(rows[0].have_body);

    ASSERT_TRUE(strstr(rows[0].body, "\"success\":false") != NULL);
    /* No proof of non-dispatch: the record must not claim nothing ran. */
    ASSERT_TRUE(strstr(rows[0].body, "\"executed\":true") != NULL);
    ASSERT_TRUE(strstr(rows[0].body,
                       "\"executed_reported\":false") != NULL);
    ASSERT_TRUE(strstr(rows[0].body, "driver execute failed") != NULL);
    /* A digest is still committed — of the empty capture. */
    ASSERT_TRUE(strstr(rows[0].body, "\"response_sha256\":\"") != NULL);
    ASSERT_TRUE(strstr(rows[0].body, "\"response_len\":0") != NULL);

    char recomputed[65];
    gr_sha256_hex(rows[0].body, recomputed);
    ASSERT_EQ(strcmp(recomputed, rows[0].ahash), 0);

    gx_cleanup();
}

/*
 * REGRESSION: a refused action still chains a gate_rejection, exactly as
 * before — same type, same artifact_id prefix, same schema, same
 * executed=false — and mints no execution record.
 */
TEST(test_refused_action_still_chains_gate_rejection)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "reload now",
                            obs, sizeof(obs), &olen));

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    int n = gx_read_session(GX_SESSION, rows, GX_MAX_ROWS);
    ASSERT_EQ(n, 1);
    ASSERT_EQ(strcmp(rows[0].type, "gate_rejection"), 0);
    ASSERT_TRUE(strncmp(rows[0].id, "gatereject-", 11) == 0);
    ASSERT_TRUE(rows[0].have_body);
    ASSERT_TRUE(strstr(rows[0].body,
                       "\"schema\":\"gate_rejection/1\"") != NULL);
    ASSERT_TRUE(strstr(rows[0].body, "\"command\":\"reload now\"") != NULL);
    ASSERT_TRUE(strstr(rows[0].body,
                       "\"classified_tier\":\"RED\"") != NULL);
    ASSERT_TRUE(strstr(rows[0].body, "\"executed\":false") != NULL);
    ASSERT_TRUE(strstr(rows[0].body, "tier gate blocked") != NULL);
    /* A refusal carries no execution fields. */
    ASSERT_TRUE(strstr(rows[0].body, "response_sha256") == NULL);

    char recomputed[65];
    gr_sha256_hex(rows[0].body, recomputed);
    ASSERT_EQ(strcmp(recomputed, rows[0].ahash), 0);

    gx_cleanup();
}

/*
 * The mixed run: executions and refusals interleaved in one session,
 * every sequence present, every link intact, every body bound.
 */
TEST(test_chain_verify_over_mixed_executions_and_rejections)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;

    ASSERT_OK(onode_execute(&st, "PVE-LAB", "show version",
                            obs, sizeof(obs), &olen));
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "reload now",
                            obs, sizeof(obs), &olen));
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "show interfaces brief",
                            obs, sizeof(obs), &olen));
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "erase startup-config",
                            obs, sizeof(obs), &olen));
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "get status",
                            obs, sizeof(obs), &olen));

    virp_chain_verify_result_t vr;
    ASSERT_OK(virp_chain_verify_session(&st.chain, GX_SESSION, &vr));
    ASSERT_TRUE(vr.valid);
    ASSERT_EQ((int)vr.entries_checked, 5);
    ASSERT_EQ((int)vr.first_broken, -1);
    /* Every entry retains a body that hashes to its commitment — no
     * execution record is unverifiable. */
    ASSERT_EQ((int)vr.artifacts_bound, 5);
    ASSERT_EQ((int)vr.artifacts_unverifiable, 0);

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    int n = gx_read_session(GX_SESSION, rows, GX_MAX_ROWS);
    ASSERT_EQ(n, 5);

    static const char *const want[5] = {
        "gate_execution",   /* show version          — GREEN, executed */
        "gate_rejection",   /* reload now            — RED, refused    */
        "gate_execution",   /* show interfaces brief — GREEN, executed */
        "gate_rejection",   /* erase startup-config  — RED, refused    */
        "gate_execution",   /* get status            — GREEN, executed */
    };
    for (int i = 0; i < 5; i++) {
        ASSERT_EQ(strcmp(rows[i].type, want[i]), 0);
        ASSERT_EQ((int)rows[i].seq, i);
        ASSERT_TRUE(rows[i].have_body);
        char recomputed[65];
        gr_sha256_hex(rows[i].body, recomputed);
        ASSERT_EQ(strcmp(recomputed, rows[i].ahash), 0);
        if (i > 0)
            ASSERT_EQ(strcmp(rows[i].prev, rows[i - 1].ehash), 0);
    }

    gx_cleanup();
}

/* =========================================================================
 * Scrub-at-capture (S-1) gates — G1..G4
 *
 * End-to-end through the REAL capture path: mock device output →
 * onode_execute → scrub → sign → chain, then verified with the
 * existing verifiers at BOTH tiers — the writer-handle HMAC tier and
 * the D-1 pubkey-only Ed25519 tier (virp_chain_open_verifier_ex with
 * ONLY the public key), which is the in-tree form of the
 * CRYPTOGRAPHICALLY-VERIFIED verdict. Every planted secret carries
 * CANARY; the core property is that no CANARY survives into anything
 * signed or stored, while the markers do — visibly, inside the signed
 * bytes.
 * ========================================================================= */

#define GXS_SIGN_SK "/tmp/virp-onode-test-gxsign.sk"
#define GXS_SIGN_PK "/tmp/virp-onode-test-gxsign.pk"

static void gxs_cleanup(void)
{
    gx_cleanup();
    unlink(GXS_SIGN_SK);
    unlink(GXS_SIGN_PK);
}

/* gx_setup + D-1 detached Ed25519 chain signing enabled on the writer
 * handle — the deployed posture this scrub ships into. */
static virp_error_t gxs_setup(onode_state_t *st)
{
    gxs_cleanup();

    virp_chainsign_key_t kp;
    virp_error_t e = virp_chainsign_generate(&kp);
    if (e != VIRP_OK) return e;
    e = virp_chainsign_save(&kp, GXS_SIGN_SK, GXS_SIGN_PK);
    virp_chainsign_destroy(&kp);
    if (e != VIRP_OK) return e;

    e = gx_setup(st);
    if (e != VIRP_OK) return e;
    return virp_chain_enable_signing(&st->chain, GXS_SIGN_SK);
}

/* The pubkey-only D-1 verdict over the gate session: valid, signature
 * tier actually exercised, every entry signed, head authenticated. */
static void gxs_assert_crypto_verified(void)
{
    virp_chain_state_t v;
    ASSERT_OK(virp_chain_open_verifier_ex(&v, GX_CHAIN_DB, NULL,
                                          GXS_SIGN_PK, 0xDEAD0008, "local"));
    virp_chain_verify_result_t r;
    virp_error_t e = virp_chain_verify_session(&v, GX_SESSION, &r);
    if (e != VIRP_OK) { virp_chain_destroy(&v); }
    ASSERT_OK(e);
    ASSERT_TRUE(r.valid);
    ASSERT_TRUE(r.sig_checked);
    ASSERT_EQ((int)r.entries_signed, (int)r.entries_checked);
    ASSERT_TRUE(r.head_authenticated);
    ASSERT_TRUE(r.head_sig_ok);
    virp_chain_destroy(&v);
}

/*
 * G1 — a CLEAN body is untouched by the scrub, and the capture still
 * chains and verifies at the Ed25519 tier. The scrub must be invisible
 * when it has nothing to do: the signed observation carries the exact
 * device bytes and no marker.
 */
TEST(test_scrub_G1_clean_capture_verifies)
{
    onode_state_t st;
    ASSERT_OK(gxs_setup(&st));

    static const char CLEAN[] =
        "Cisco IOS Software, C2900 Software\n"
        "R1 uptime is 3 weeks, 2 days\n"
        "System returned to ROM by power-on\n";
    virp_driver_mock_set_output(CLEAN);

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    virp_error_t err = onode_execute(&st, "PVE-LAB", "show version",
                                     obs, sizeof(obs), &olen);
    virp_driver_mock_set_output(NULL);
    ASSERT_OK(err);

    /* signed observation verifies, body is the exact clean bytes */
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));
    ASSERT_TRUE(gx_bytes_contain(obs, olen, CLEAN));
    ASSERT_TRUE(!gx_bytes_contain(obs, olen, "[REDACTED"));

    /* commitment is over those same clean bytes */
    virp_chain_verify_result_t vr;
    ASSERT_OK(virp_chain_verify_session(&st.chain, GX_SESSION, &vr));
    ASSERT_TRUE(vr.valid);

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    ASSERT_EQ(gx_read_session(GX_SESSION, rows, GX_MAX_ROWS), 1);
    char digest[65], want[128];
    gr_sha256_hex(CLEAN, digest);
    snprintf(want, sizeof(want), "\"response_sha256\":\"%s\"", digest);
    ASSERT_TRUE(strstr(rows[0].body, want) != NULL);

    gxs_assert_crypto_verified();
    gxs_cleanup();
}

/*
 * G2 — planted secrets in a device response are REDACTED in the signed
 * body, the markers are visible, and the scrubbed capture still chains
 * and verifies at the Ed25519 tier — redact-before-sign is coherent.
 */
TEST(test_scrub_G2_planted_secrets_redacted_and_verifies)
{
    onode_state_t st;
    ASSERT_OK(gxs_setup(&st));

    static const char PLANTED[] =
        "Building configuration...\n"
        "hostname R1\n"
        "enable secret 5 $1$abcd$CANARYenablehash\n"
        "snmp-server community CANARYcommunity RO\n"
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "CANARYpemline1\n"
        "CANARYpemline2\n"
        "-----END RSA PRIVATE KEY-----\n"
        "end\n";
    virp_driver_mock_set_output(PLANTED);

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    virp_error_t err = onode_execute(&st, "PVE-LAB", "show running-config",
                                     obs, sizeof(obs), &olen);
    virp_driver_mock_set_output(NULL);
    ASSERT_OK(err);

    /* the signed observation: markers present, secrets absent */
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));
    ASSERT_TRUE(!gx_bytes_contain(obs, olen, "CANARY"));
    ASSERT_TRUE(gx_bytes_contain(obs, olen, "[REDACTED: enable-secret]"));
    ASSERT_TRUE(gx_bytes_contain(obs, olen, "[REDACTED: snmp-community]"));
    ASSERT_TRUE(gx_bytes_contain(obs, olen, "[REDACTED: private-key-block]"));
    /* non-secret structure survives — the body still shows WHAT happened */
    ASSERT_TRUE(gx_bytes_contain(obs, olen, "hostname R1"));

    /* the chain commitment is over the SCRUBBED bytes: recompute the
     * expected scrubbed body independently and match response_sha256 */
    static char expect[VIRP_OUTPUT_MAX];
    size_t expect_len = 0;
    unsigned nred = 0;
    ASSERT_OK(virp_scrub_body(PLANTED, strlen(PLANTED), expect,
                              sizeof(expect), &expect_len, &nred));
    expect[expect_len] = '\0';
    ASSERT_EQ((int)nred, 3);

    virp_chain_verify_result_t vr;
    ASSERT_OK(virp_chain_verify_session(&st.chain, GX_SESSION, &vr));
    ASSERT_TRUE(vr.valid);

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    ASSERT_EQ(gx_read_session(GX_SESSION, rows, GX_MAX_ROWS), 1);
    char digest[65], want[128];
    gr_sha256_hex(expect, digest);
    snprintf(want, sizeof(want), "\"response_sha256\":\"%s\"", digest);
    ASSERT_TRUE(strstr(rows[0].body, want) != NULL);

    /* no secret anywhere in the database, WAL included */
    ASSERT_EQ(gx_file_contains(GX_CHAIN_DB, "CANARY"), 0);
    ASSERT_EQ(gx_file_contains(GX_CHAIN_DB "-wal", "CANARY"), 0);

    gxs_assert_crypto_verified();
    gxs_cleanup();
}

/*
 * G3 — fail-closed at capture: a scrubber failure yields a signed body
 * that is ENTIRELY [REDACTED: scrub-error]. The raw content reaches
 * nothing: not the observation, not the chain commitment, not the DB.
 */
TEST(test_scrub_G3_fail_closed_full_redaction)
{
    onode_state_t st;
    ASSERT_OK(gxs_setup(&st));

    static const char BODY[] =
        "harmless line\nCANARYplainbody would leak if scrub failed open\n";
    virp_driver_mock_set_output(BODY);
    virp_scrub_test_force_error(true);

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    virp_error_t err = onode_execute(&st, "PVE-LAB", "show version",
                                     obs, sizeof(obs), &olen);
    virp_scrub_test_force_error(false);
    virp_driver_mock_set_output(NULL);
    ASSERT_OK(err);

    /* still a valid signed observation — of the marker, nothing else */
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));
    ASSERT_TRUE(gx_bytes_contain(obs, olen, "[REDACTED: scrub-error]"));
    ASSERT_TRUE(!gx_bytes_contain(obs, olen, "CANARY"));
    ASSERT_TRUE(!gx_bytes_contain(obs, olen, "harmless line"));

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    ASSERT_EQ(gx_read_session(GX_SESSION, rows, GX_MAX_ROWS), 1);
    /* the commitment is over exactly the marker */
    char digest[65], want[128];
    gr_sha256_hex("[REDACTED: scrub-error]", digest);
    snprintf(want, sizeof(want), "\"response_sha256\":\"%s\"", digest);
    ASSERT_TRUE(strstr(rows[0].body, want) != NULL);

    ASSERT_EQ(gx_file_contains(GX_CHAIN_DB, "CANARY"), 0);
    ASSERT_EQ(gx_file_contains(GX_CHAIN_DB "-wal", "CANARY"), 0);

    gxs_assert_crypto_verified();
    gxs_cleanup();
}

/*
 * G4 — going-forward only: a scrubbed capture appended to a chain with
 * existing entries leaves every prior entry byte-identical, and the
 * whole session (old + scrubbed) still verifies with unbroken linkage.
 */
TEST(test_scrub_G4_existing_entries_untouched)
{
    onode_state_t st;
    ASSERT_OK(gxs_setup(&st));

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;

    /* the pre-existing entry (clean capture) */
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "show version",
                            obs, sizeof(obs), &olen));

    /* snapshot it BEFORE the scrubbed append, through a separate
     * read-only connection */
    static gx_row_t before[GX_MAX_ROWS];
    ASSERT_EQ(gx_read_session(GX_SESSION, before, GX_MAX_ROWS), 1);

    /* the scrubbed capture */
    virp_driver_mock_set_output("enable secret 5 $1$CANARYg4\n");
    virp_error_t err = onode_execute(&st, "PVE-LAB", "show running-config",
                                     obs, sizeof(obs), &olen);
    virp_driver_mock_set_output(NULL);
    ASSERT_OK(err);

    virp_chain_verify_result_t vr;
    ASSERT_OK(virp_chain_verify_session(&st.chain, GX_SESSION, &vr));
    ASSERT_TRUE(vr.valid);
    ASSERT_EQ((int)vr.entries_checked, 2);

    gx_teardown(&st);

    static gx_row_t after[GX_MAX_ROWS];
    ASSERT_EQ(gx_read_session(GX_SESSION, after, GX_MAX_ROWS), 2);

    /* the pre-existing entry is byte-identical in every field */
    ASSERT_EQ((int)after[0].seq, (int)before[0].seq);
    ASSERT_EQ(strcmp(after[0].type,  before[0].type),  0);
    ASSERT_EQ(strcmp(after[0].id,    before[0].id),    0);
    ASSERT_EQ(strcmp(after[0].ahash, before[0].ahash), 0);
    ASSERT_EQ(strcmp(after[0].ehash, before[0].ehash), 0);
    ASSERT_EQ(strcmp(after[0].prev,  before[0].prev),  0);
    ASSERT_EQ(strcmp(after[0].body,  before[0].body),  0);

    /* and the scrubbed entry links to it, unbroken */
    ASSERT_EQ(strcmp(after[1].prev, after[0].ehash), 0);
    ASSERT_EQ(gx_file_contains(GX_CHAIN_DB, "CANARY"), 0);

    gxs_assert_crypto_verified();
    gxs_cleanup();
}

/* =========================================================================
 * BLACK is unconditional (2026-08-27)
 *
 * BLACK means inexpressible, and inexpressible is not mode-dependent.
 * SHADOW observes what enforcement would have done for GREEN, YELLOW,
 * RED and UNCLASSIFIED — that is its purpose — but it must never turn
 * inexpressible into executable. The gate refuses BLACK BEFORE any mode
 * check (virp_onode.c, "BLACK: refuse, always"), records the refusal
 * with the SAME gate_rejection/1 entry an ENFORCE refusal writes (plus
 * gate_mode naming the mode that refused), and the driver is never
 * invoked.
 *
 * The mock driver classifies "selfdestruct" BLACK and deliberately has
 * NO BLACK backstop in execute(), so these tests probe the gate alone:
 * if the gate ever admits BLACK, the mock executes it and the leak is
 * caught directly instead of being masked by a driver-level belt (the
 * pre-fix production shape: PAN-OS had no backstop either).
 * ========================================================================= */

/* BLACK under ENFORCE: refused at the gate, driver never invoked. */
TEST(test_black_enforce_refused_at_gate)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));
    st.gate_max_tier = VIRP_TIER_RED;    /* even the widest ceiling */

    virp_driver_mock_exec_attempts_reset();

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "selfdestruct now",
                            obs, sizeof(obs), &olen));

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    virp_observation_t o;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(obs + VIRP_HEADER_SIZE,
                                     olen - VIRP_HEADER_SIZE,
                                     &o, &data, &data_len));

    /* Capture, release, then assert (see the teardown discipline in the
     * GX tests above). */
    int attempts   = virp_driver_mock_exec_attempts_reset();
    uint8_t wire_tier = hdr.tier;
    uint8_t got_type  = o.obs_type;
    int blocked = gx_bytes_contain(data, data_len, "tier gate blocked");
    int black   = gx_bytes_contain(data, data_len, "tier=BLACK");

    gx_teardown(&st);
    gx_cleanup();

    ASSERT_EQ(got_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(blocked);
    ASSERT_TRUE(black);
    /* BLACK is untransmittable on the wire: over-reported as RED. */
    ASSERT_EQ(wire_tier, VIRP_TIER_RED);
    ASSERT_EQ(attempts, 0);
}

/*
 * THE INVARIANT TEST: a BLACK-classified command in SHADOW mode is
 * refused, the refusal is recorded in the chain, and the driver is
 * never invoked. (Named so a reader grepping "shadow" and "black" finds
 * the invariant.)
 */
TEST(test_shadow_black_refused_recorded_driver_never_invoked)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));
    st.gate_default_mode = GATE_MODE_SHADOW;
    st.gate_max_tier = VIRP_TIER_YELLOW;

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;

    /* Precondition: this state really is SHADOW-permissive — an
     * UNCLASSIFIED command EXECUTES — so the refusal below cannot be
     * ENFORCE quietly doing the work. */
    virp_driver_mock_exec_attempts_reset();
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "frobnicate the widget",
                            obs, sizeof(obs), &olen));
    {
        virp_header_t hdr;
        virp_observation_t o;
        const uint8_t *data;
        uint16_t data_len;
        ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));
        ASSERT_OK(virp_parse_observation(obs + VIRP_HEADER_SIZE,
                                         olen - VIRP_HEADER_SIZE,
                                         &o, &data, &data_len));
        ASSERT_EQ(o.obs_type, VIRP_OBS_DEVICE_OUTPUT);
        ASSERT_EQ(virp_driver_mock_exec_attempts_reset(), 1);
    }

    /* The BLACK command: refused, driver untouched. */
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "selfdestruct now",
                            obs, sizeof(obs), &olen));

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    virp_observation_t o;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(obs + VIRP_HEADER_SIZE,
                                     olen - VIRP_HEADER_SIZE,
                                     &o, &data, &data_len));

    int attempts  = virp_driver_mock_exec_attempts_reset();
    uint8_t got_type = o.obs_type;
    int blocked = gx_bytes_contain(data, data_len, "tier gate blocked");

    gx_teardown(&st);

    /* Recorded: the SHADOW refusal writes the SAME entry shape an
     * ENFORCE refusal writes, with the mode named. Row 0 is the
     * precondition's gate_execution; row 1 is the refusal. A refusal
     * that happened but left no record would be the absence-inferred
     * failure again. */
    static gx_row_t rows[GX_MAX_ROWS];
    int n = gx_read_session(GX_SESSION, rows, GX_MAX_ROWS);

    int is_reject   = (n == 2 && strcmp(rows[1].type, "gate_rejection") == 0);
    int has_body    = (n == 2 && rows[1].have_body);
    int schema_ok   = has_body && strstr(rows[1].body,
                          "\"schema\":\"gate_rejection/1\"") != NULL;
    int cmd_ok      = has_body && strstr(rows[1].body,
                          "\"command\":\"selfdestruct now\"") != NULL;
    int tier_ok     = has_body && strstr(rows[1].body,
                          "\"classified_tier\":\"BLACK\"") != NULL;
    int mode_ok     = has_body && strstr(rows[1].body,
                          "\"gate_mode\":\"SHADOW\"") != NULL;
    int not_run     = has_body && strstr(rows[1].body,
                          "\"executed\":false") != NULL;
    /* BLACK files no proposal: inexpressible has no escalation path. */
    int no_proposal = has_body && strstr(rows[1].body,
                          "proposal_id") == NULL;
    char recomputed[65] = {0};
    if (has_body) gr_sha256_hex(rows[1].body, recomputed);
    int bound = has_body && strcmp(recomputed, rows[1].ahash) == 0;

    gx_cleanup();

    ASSERT_EQ(got_type, VIRP_OBS_ERROR);
    ASSERT_TRUE(blocked);
    ASSERT_EQ(attempts, 0);
    ASSERT_EQ(n, 2);
    ASSERT_TRUE(is_reject);
    ASSERT_TRUE(has_body);
    ASSERT_TRUE(schema_ok);
    ASSERT_TRUE(cmd_ok);
    ASSERT_TRUE(tier_ok);
    ASSERT_TRUE(mode_ok);
    ASSERT_TRUE(not_run);
    ASSERT_TRUE(no_proposal);
    ASSERT_TRUE(bound);
}

/*
 * SHADOW's purpose is UNCHANGED for every other tier: YELLOW (within
 * ceiling, would-allow) and RED (over ceiling, would-block) both
 * proceed, and each leaves a gate_execution record naming SHADOW — the
 * hypothetical verdict stays observable. Pins current behaviour so the
 * BLACK fix cannot silently narrow what SHADOW is for.
 */
TEST(test_shadow_yellow_red_still_proceed_and_are_recorded)
{
    onode_state_t st;
    ASSERT_OK(gx_setup(&st));
    st.gate_default_mode = GATE_MODE_SHADOW;
    st.gate_max_tier = VIRP_TIER_YELLOW;

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = 0;

    /* YELLOW, within the ceiling: would-allow, proceeds. */
    virp_driver_mock_exec_attempts_reset();
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "clear counters",
                            obs, sizeof(obs), &olen));
    ASSERT_EQ(virp_driver_mock_exec_attempts_reset(), 1);

    /* RED, over the ceiling: would-block under ENFORCE, proceeds. */
    ASSERT_OK(onode_execute(&st, "PVE-LAB", "reload now",
                            obs, sizeof(obs), &olen));
    ASSERT_EQ(virp_driver_mock_exec_attempts_reset(), 1);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs, olen, &st.okey, &hdr));

    virp_observation_t o;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(obs + VIRP_HEADER_SIZE,
                                     olen - VIRP_HEADER_SIZE,
                                     &o, &data, &data_len));
    uint8_t got_type = o.obs_type;

    gx_teardown(&st);

    static gx_row_t rows[GX_MAX_ROWS];
    int n = gx_read_session(GX_SESSION, rows, GX_MAX_ROWS);

    int both_exec = (n == 2 &&
                     strcmp(rows[0].type, "gate_execution") == 0 &&
                     strcmp(rows[1].type, "gate_execution") == 0);
    int red_body  = (n == 2 && rows[1].have_body &&
                     strstr(rows[1].body,
                            "\"classified_tier\":\"RED\"") != NULL &&
                     strstr(rows[1].body,
                            "\"gate_mode\":\"SHADOW\"") != NULL &&
                     strstr(rows[1].body,
                            "\"decision\":\"auto-execute\"") != NULL);

    gx_cleanup();

    /* The RED command really executed and came back as device output. */
    ASSERT_EQ(got_type, VIRP_OBS_DEVICE_OUTPUT);
    ASSERT_EQ(n, 2);
    ASSERT_TRUE(both_exec);
    ASSERT_TRUE(red_body);
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
 * Watchdog health_check vs. in-flight execute (finding N3)
 *
 * The watchdog probes a live connection with drv->health_check(). That
 * drives the same channel drv->execute() is reading from, so it must be
 * serialized against execution on the same device by exec_mutex[i]. It
 * previously ran under conn_mutex only — a different lock — so a probe
 * could land inside an in-flight command's read window and its bytes
 * became part of that command's SIGNED observation.
 *
 * The mock's shared-channel hook models exactly that: health_check
 * leaves MOCK_HEALTH_PROBE_MARKER on the channel and execute reads
 * whatever arrived during its window. Runtime is ~10s: the watchdog's
 * first steady-state tick is ONODE_WATCHDOG_INTERVAL_SEC after start,
 * and the execute must still be in flight when it fires.
 * ========================================================================= */

extern void virp_driver_mock_set_shared_channel(bool on);
extern void virp_driver_mock_watch_probes(const char *hostname);
extern int  virp_driver_mock_probe_count(void);

TEST(test_watchdog_health_check_serialized_with_execute)
{
    onode_state_t tmp;
    ASSERT_OK(onode_init(&tmp, 0xDEAD0009, NULL,
                         "/tmp/virp-onode-wdrace.sock"));
    tmp.ctx = virp_context_new();
    ASSERT_TRUE(tmp.ctx != NULL);

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "R-RACE");
    snprintf(dev.host, sizeof(dev.host), "10.0.0.97");
    dev.port = 22;
    dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0BADF00D;
    dev.enabled = true;
    ASSERT_OK(onode_add_device(&tmp, &dev));

    /* Count probes for THIS device only — the suite's served daemon
     * runs its own watchdog against R6 throughout. */
    virp_driver_mock_watch_probes("R-RACE");
    virp_driver_mock_set_shared_channel(true);

    /* Watchdog only — no socket, no accept loop. */
    ASSERT_OK(onode_watchdog_start(&tmp));

    /* Wait for the watchdog's initial connect pass to establish the
     * connection, so the steady-state health-check tick is what races
     * the execute below. */
    bool connected = false;
    for (int i = 0; i < 200 && !connected; i++) {
        pthread_mutex_lock(&tmp.conn_mutex);
        connected = (tmp.connections[0] != NULL);
        pthread_mutex_unlock(&tmp.conn_mutex);
        if (!connected) usleep(25000);
    }
    if (!connected) {
        printf(" [FAIL]\n    watchdog never connected the mock device\n");
        virp_driver_mock_set_shared_channel(false);
        tests_run++; tests_failed++;
        virp_context_destroy(tmp.ctx);
        onode_destroy(&tmp);
        return;
    }

    /*
     * Run one command whose read window spans the watchdog's first
     * steady-state tick (the watchdog sleeps ONODE_WATCHDOG_INTERVAL_SEC
     * before its first probe, so a window of INTERVAL+2 seconds started
     * now contains that tick).
     */
    const int EXEC_MS = (ONODE_WATCHDOG_INTERVAL_SEC + 2) * 1000;
    virp_driver_mock_set_delay(EXEC_MS);

    /* Must be zero: if the watchdog had already probed before the
     * command started, the tick we rely on would not be inside the
     * execute window and a clean body would prove nothing. */
    int probes_before = virp_driver_mock_probe_count();

    uint8_t obs_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t obs_len = 0;
    virp_error_t err = onode_execute(&tmp, "R-RACE", "show version",
                                     obs_buf, sizeof(obs_buf), &obs_len);

    virp_driver_mock_set_delay(0);

    /*
     * The probe must actually have fired. With the fix it is blocked on
     * exec_mutex for the duration of the command and lands just after
     * onode_execute releases it, so poll rather than sampling once.
     */
    int probes = 0;
    for (int i = 0; i < 200; i++) {
        probes = virp_driver_mock_probe_count();
        if (probes > probes_before) break;
        usleep(25000);
    }

    virp_driver_mock_set_shared_channel(false);
    virp_driver_mock_watch_probes(NULL);

    ASSERT_OK(err);

    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(obs_buf, obs_len, &tmp.okey, &hdr));

    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    ASSERT_OK(virp_parse_observation(obs_buf + VIRP_HEADER_SIZE,
                                     obs_len - VIRP_HEADER_SIZE,
                                     &obs, &data, &data_len));

    if (probes_before != 0 || probes < 1) {
        printf(" [FAIL]\n    watchdog probe did not fall inside the execute "
               "window (before=%d after=%d) — test would pass for the "
               "wrong reason\n", probes_before, probes);
        tests_run++; tests_failed++;
        virp_context_destroy(tmp.ctx);
        onode_destroy(&tmp);
        return;
    }

    /* The signed body must be this command's output and nothing else. */
    ASSERT_TRUE(strstr((const char *)data, "R-RACE#show version") != NULL);
    ASSERT_TRUE(strstr((const char *)data,
                       MOCK_HEALTH_PROBE_MARKER) == NULL);
    /* Not merely uncontaminated — the body must start with this
     * command's echo, so foreign bytes cannot have led it. */
    ASSERT_TRUE(strncmp((const char *)data, "R-RACE#show version",
                        strlen("R-RACE#show version")) == 0);

    virp_context_destroy(tmp.ctx);
    onode_destroy(&tmp);
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
 * Audit §4.1 — sign_intent / sign_outcome must not be a signing oracle
 *
 * Both handlers exist to witness a digest the caller already computed,
 * and both documented a "64 hex chars" contract that nothing enforced.
 * req.command is char[1024], so a caller could obtain an
 * O-Key-authenticated GREEN observation over up to 1023 bytes of its own
 * text — i.e. forge something that reads as an observation. That defeats
 * the protocol's central claim, so these tests drive the REAL handlers
 * over the socket rather than only unit-testing the predicate.
 *
 * A rejection is a framed 4-byte error code; an acceptance is a full
 * signed observation. The two are trivially distinguishable by length,
 * and the tests assert the specific error code as well.
 * ========================================================================= */

extern bool onode_is_sha256_hex(const char *s);

/* Build {"action": "<act>", "command": "<payload>"} and send it. */
static ssize_t sign_request(const char *action, const char *payload,
                            uint8_t *resp, size_t resp_cap)
{
    char json[1400];
    snprintf(json, sizeof(json),
             "{\"action\": \"%s\", \"command\": \"%s\"}", action, payload);
    return client_request(json, resp, resp_cap);
}

/* Decode a framed 4-byte error payload. */
static int32_t resp_error_code(const uint8_t *resp)
{
    uint32_t net;
    memcpy(&net, resp, 4);
    return (int32_t)ntohl(net);
}

TEST(test_sign_intent_predicate)
{
    char valid[65];
    memset(valid, 'a', 64); valid[64] = '\0';

    ASSERT_TRUE(onode_is_sha256_hex(valid));
    ASSERT_TRUE(onode_is_sha256_hex(
        "0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdef0123"));

    ASSERT_TRUE(!onode_is_sha256_hex(NULL));
    ASSERT_TRUE(!onode_is_sha256_hex(""));
    /* 63 and 65 chars — length must be exact, not a minimum. */
    char short_hex[64]; memset(short_hex, 'a', 63); short_hex[63] = '\0';
    ASSERT_TRUE(!onode_is_sha256_hex(short_hex));
    char long_hex[66]; memset(long_hex, 'a', 65); long_hex[65] = '\0';
    ASSERT_TRUE(!onode_is_sha256_hex(long_hex));
    /* Right length, wrong alphabet — including a trailing non-hex byte,
     * which a strspn-without-length check would happily accept. */
    char sneaky[65]; memset(sneaky, 'a', 64); sneaky[63] = 'z'; sneaky[64] = '\0';
    ASSERT_TRUE(!onode_is_sha256_hex(sneaky));
    ASSERT_TRUE(!onode_is_sha256_hex(
        "not-a-digest-but-exactly-sixty-four-characters-long-padded!!!!!!!"));
}

TEST(test_sign_intent_rejects_oversized)
{
    /* The oracle in its clearest form: attacker-authored prose. */
    char payload[600];
    memset(payload, 'A', sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = '\0';

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = sign_request("sign_intent", payload, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);                                  /* error, not an observation */
    ASSERT_EQ(resp_error_code(resp), VIRP_ERR_INVALID_LENGTH);
}

TEST(test_sign_intent_rejects_non_hex)
{
    /* Exactly 64 chars so only the alphabet check can catch it. */
    const char *payload =
        "The quick brown fox jumps over the lazy dog and then some more!!";
    ASSERT_EQ((int)strlen(payload), 64);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = sign_request("sign_intent", payload, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(resp_error_code(resp), VIRP_ERR_INVALID_LENGTH);
}

TEST(test_sign_intent_accepts_valid_digest)
{
    const char *digest =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = sign_request("sign_intent", digest, resp, sizeof(resp));

    /* Still a real, valid, signed observation — the fix must not break
     * the legitimate path. */
    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr));
}

TEST(test_sign_outcome_rejects_oversized)
{
    char payload[600];
    memset(payload, 'B', sizeof(payload) - 1);
    payload[sizeof(payload) - 1] = '\0';

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = sign_request("sign_outcome", payload, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(resp_error_code(resp), VIRP_ERR_INVALID_LENGTH);
}

TEST(test_sign_outcome_accepts_valid_digest)
{
    const char *digest =
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = sign_request("sign_outcome", digest, resp, sizeof(resp));

    ASSERT_TRUE(n > (ssize_t)VIRP_HEADER_SIZE);
    virp_header_t hdr;
    ASSERT_OK(virp_validate_message(resp, (size_t)n, &g_state.okey, &hdr));
}

/* =========================================================================
 * CHAIN_APPEND is not a signing oracle for arbitrary artifacts
 * (adversarial audit 2026-08-06)
 *
 * The external append path validated only that four strings were
 * non-empty and passed them straight to the chain writer, which copied
 * the CALLER's artifact_hash into the canonical object, SHA-256'd it and
 * HMAC'd it with K_chain. A socket client holding no K_chain could
 * therefore induce a K_chain-authenticated entry that no chain reader
 * can distinguish from a daemon-minted record. Three attacks, all
 * reproduced against the pre-fix code:
 *
 *   1. body/hash mismatch — declare a hash that is not sha256(body)
 *   2. reserved type      — claim artifact_type "outcome" / "approval"
 *   3. invented type      — claim a type the daemon has never minted
 *
 * These tests need their OWN chain-enabled daemon: the shared g_state
 * instance runs without a chain, where chain_append fails early for an
 * unrelated reason and proves nothing.
 * ========================================================================= */

#define CA_SOCKET    "/tmp/virp-onode-test-cappend.sock"
#define CA_CHAIN_DB  "/tmp/virp-onode-test-cappend.db"
#define CA_CHAIN_KEY "/tmp/virp-onode-test-cappend.key"

static onode_state_t ca_state;
static pthread_t ca_thread_id;

static void ca_cleanup_files(void)
{
    unlink(CA_CHAIN_DB);
    unlink(CA_CHAIN_DB "-wal");
    unlink(CA_CHAIN_DB "-shm");
    unlink(CA_CHAIN_KEY);
    unlink(CA_SOCKET);
}

static void *ca_thread(void *arg)
{
    (void)arg;
    onode_start(&ca_state);
    return NULL;
}

/* Start a chain-enabled daemon on its own socket. Returns 0 on success. */
static int ca_start(void)
{
    ca_cleanup_files();

    virp_signing_key_t ck;
    if (virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN) != VIRP_OK) return -1;
    if (virp_key_save_file(&ck, CA_CHAIN_KEY) != VIRP_OK) return -1;
    virp_key_destroy(&ck);

    if (onode_init(&ca_state, 0x00000042, NULL, CA_SOCKET) != VIRP_OK)
        return -1;
    ca_state.ctx = virp_context_new();
    if (!ca_state.ctx) return -1;
    if (onode_setup_chain_and_approvals(&ca_state, 0x00000042,
                                        CA_CHAIN_DB, CA_CHAIN_KEY,
                                        "/tmp/virp-onode-test-ca-approvals",
                                        "/tmp/virp-onode-test-no-registry")
            != VIRP_OK)
        return -1;
    if (!ca_state.chain_enabled) return -1;
    if (pthread_create(&ca_thread_id, NULL, ca_thread, NULL) != 0) return -1;
    usleep(200000);
    return 0;
}

static void ca_stop(void)
{
    onode_shutdown(&ca_state);
    pthread_join(ca_thread_id, NULL);
    onode_destroy(&ca_state);
    virp_context_destroy(ca_state.ctx);
    ca_state.ctx = NULL;
}

/* Same framing as client_request(), against the chain-enabled socket. */
static ssize_t ca_request(const char *json, uint8_t *resp, size_t resp_cap)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CA_SOCKET);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    size_t json_len = strlen(json);
    uint32_t frame_len = htonl((uint32_t)(1 + json_len));
    send(fd, &frame_len, 4, 0);
    uint8_t version = VIRP_FRAME_VERSION;
    send(fd, &version, 1, 0);
    send(fd, json, json_len, 0);
    usleep(50000);

    uint32_t net_rlen;
    if (recv(fd, &net_rlen, 4, 0) != 4) { close(fd); return -1; }
    uint32_t rlen = ntohl(net_rlen);
    if (rlen > resp_cap) { close(fd); return -1; }
    size_t got = 0;
    while (got < rlen) {
        ssize_t n = recv(fd, resp + got, rlen - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    return (ssize_t)got;
}

static void ca_sha256_hex(const char *s, char out[65])
{
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_Digest(s, strlen(s), md, &mdlen, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", md[i]);
}

/* Ask the chain-enabled daemon to append. Returns the response length;
 * a 4-byte response is a typed error (rejection). */
static ssize_t ca_append(const char *session, const char *type,
                         const char *aid, const char *hash,
                         const char *content, uint8_t *resp, size_t cap)
{
    char json[2048];
    if (content) {
        /* The bodies under test are themselves JSON. Escaping them into
         * the request is not cosmetic: an unescaped quote makes the
         * REQUEST malformed, the daemon rejects the parse, and the test
         * passes for entirely the wrong reason — it never reaches the
         * append path it claims to attack. */
        char esc[1024];
        size_t o = 0;
        for (const char *p = content; *p && o + 2 < sizeof(esc); p++) {
            if (*p == '"' || *p == '\\') esc[o++] = '\\';
            esc[o++] = *p;
        }
        esc[o] = '\0';
        snprintf(json, sizeof(json),
                 "{\"action\":\"chain_append\",\"session_id\":\"%s\","
                 "\"artifact_type\":\"%s\",\"artifact_id\":\"%s\","
                 "\"artifact_hash\":\"%s\",\"artifact_content\":\"%s\"}",
                 session, type, aid, hash, esc);
    }
    else {
        snprintf(json, sizeof(json),
                 "{\"action\":\"chain_append\",\"session_id\":\"%s\","
                 "\"artifact_type\":\"%s\",\"artifact_id\":\"%s\","
                 "\"artifact_hash\":\"%s\"}",
                 session, type, aid, hash);
    }
    return ca_request(json, resp, cap);
}

/* Count entries with the given artifact_id in the chain database. The
 * daemon holds the db open in WAL mode; a second connection sees
 * committed rows. */
static int ca_count_entries(const char *artifact_id)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(CA_CHAIN_DB, &db) != SQLITE_OK) return -1;
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM chain_entries WHERE artifact_id = ?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, artifact_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return n;
}

/* Count artifact BODY rows for an artifact_id. Distinct from
 * ca_count_entries: an entry proves an append was accepted, a body row
 * proves bytes were retained — GATE 5's subject is the latter. */
static int ca_count_artifact_rows(const char *artifact_id)
{
    sqlite3 *db = NULL;
    if (sqlite3_open(CA_CHAIN_DB, &db) != SQLITE_OK) return -1;
    sqlite3_stmt *st = NULL;
    int n = -1;
    if (sqlite3_prepare_v2(db,
            "SELECT COUNT(*) FROM artifacts WHERE artifact_id = ?",
            -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, artifact_id, -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW)
            n = sqlite3_column_int(st, 0);
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return n;
}

/* ATTACK 1: the declared hash is not sha256(the submitted body). The
 * daemon must recompute over the received bytes and refuse. */
TEST(test_chain_append_rejects_body_hash_mismatch)
{
    const char *body = "{\"success\":true,\"note\":\"not what the hash says\"}";
    char wrong[65];
    ca_sha256_hex("entirely different bytes", wrong);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("attack:mismatch", "observation",
                          "attack-mismatch-1", wrong, body,
                          resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("attack-mismatch-1"), 0);
}

/* ATTACK 2: a reserved, daemon-only semantic type submitted from the
 * external socket path. Hash and body agree here, so ONLY the type
 * namespace check can catch it. */
TEST(test_chain_append_rejects_reserved_type_outcome)
{
    const char *body =
        "{\"proposal_id\":\"deadbeef\",\"device\":\"R5\",\"success\":true}";
    char h[65];
    ca_sha256_hex(body, h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("approval:R5", "outcome", "outcome:deadbeef", h,
                          body, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("outcome:deadbeef"), 0);
}

TEST(test_chain_append_rejects_reserved_type_approval)
{
    const char *body =
        "{\"proposal_id\":\"deadbeef\",\"operator\":\"mallory\"}";
    char h[65];
    ca_sha256_hex(body, h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("approval:R5", "approval", "approval:deadbeef", h,
                          body, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("approval:deadbeef"), 0);
}

/* ATTACK 3: a type the daemon has never minted and no client is known to
 * send. Unknown types are refused rather than recorded as if meaningful. */
TEST(test_chain_append_rejects_invented_type)
{
    const char *body = "{\"anything\":\"at all\"}";
    char h[65];
    ca_sha256_hex(body, h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("attack:invent", "audit_passed",
                          "invented-1", h, body, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("invented-1"), 0);
}

/* ---- GATE 3 helpers: mint a REAL signed observation ---------------- */

static void ca_sha256_hex_bin(const uint8_t *b, size_t n, char out[65])
{
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_Digest(b, n, md, &mdlen, EVP_sha256(), NULL);
    for (int i = 0; i < 32; i++)
        snprintf(out + i * 2, 3, "%02x", md[i]);
}

static void ca_b64_body(const uint8_t *in, size_t len, char *out, size_t cap)
{
    static const char T[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t o = (size_t)snprintf(out, cap, "base64:");
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i + 1 < len) v |= (uint32_t)in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        if (o + 4 >= cap) break;
        out[o++] = T[(v >> 18) & 0x3F];
        out[o++] = T[(v >> 12) & 0x3F];
        out[o++] = (i + 1 < len) ? T[(v >> 6) & 0x3F] : '=';
        out[o++] = (i + 2 < len) ? T[v & 0x3F] : '=';
    }
    out[o] = '\0';
}

/* A genuine v1 observation, signed with the daemon's own O-Key — the
 * exact shape autopilot registers today. */
static size_t ca_mint_v1_obs(uint8_t *buf, size_t cap, uint64_t seq)
{
    size_t len = 0;
    /* ca_state, not g_state: the chain-append battery runs its OWN
     * daemon instance (node 0x42, CA_SOCKET) with its own generated
     * O-Key. Signing with the other instance's key would make the
     * legitimate case fail for a reason that has nothing to do with
     * the gate under test. */
    virp_error_t e = virp_build_observation_tiered(
        buf, cap, &len, 0x00000042u, (uint32_t)seq,
        VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL, VIRP_TIER_GREEN,
        (const uint8_t *)"GigabitEthernet0/1 up/up", 24, &ca_state.okey);
    return (e == VIRP_OK) ? len : 0;
}

/* GUARD: the legitimate external append — a genuinely signed v1
 * observation, the only format in the production chain — must still be
 * accepted, or the gate has simply broken chain registration. */
TEST(test_chain_append_accepts_signed_v1_observation)
{
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9001);
    ASSERT_TRUE(olen > 0);

    char h[65];  ca_sha256_hex_bin(obs, olen, h);
    char body[2048]; ca_b64_body(obs, olen, body, sizeof(body));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("autopilot:legit", "observation",
                          "obs-legit-1", h, body, resp, sizeof(resp));

    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("obs-legit-1"), 1);
}

/* ATTACK 4 (GATE 3): a body that hashes to its commitment but is not a
 * signed observation at all. This is what the chain accepted before the
 * signature gate existed — arbitrary JSON recorded as "observation" and
 * stamped with a K_chain HMAC no reader could distinguish from a
 * daemon-minted entry. */
TEST(test_chain_append_rejects_unsigned_observation_body)
{
    const char *body = "{\"device\":\"R5\",\"output\":\"up/up\"}";
    char h[65];
    ca_sha256_hex(body, h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("attack:unsigned", "observation",
                          "obs-unsigned-1", h, body, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("obs-unsigned-1"), 0);
}

/* ATTACK 5 (GATE 3): a REAL observation with one payload byte flipped,
 * and the declared hash recomputed over the tampered bytes so GATE 2 is
 * satisfied. Only the signature check can catch this — it proves the
 * rejection comes from GATE 3, not from hash binding. */
TEST(test_chain_append_rejects_tampered_v1_observation)
{
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9002);
    ASSERT_TRUE(olen > 0);

    obs[olen - 1] ^= 0x01;                 /* flip a signed payload byte */

    char h[65];  ca_sha256_hex_bin(obs, olen, h);   /* honest hash */
    char body[2048]; ca_b64_body(obs, olen, body, sizeof(body));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("attack:tamper", "observation",
                          "obs-tampered-1", h, body, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("obs-tampered-1"), 0);
}

/* ATTACK 6 (GATE 3): dispatch must be explicit. An unknown version byte
 * is refused, never guessed at or waved through. */
TEST(test_chain_append_rejects_unknown_obs_version)
{
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9003);
    ASSERT_TRUE(olen > 0);

    obs[0] = 0x09;                          /* not 1, 2 or 3 */

    char h[65];  ca_sha256_hex_bin(obs, olen, h);
    char body[2048]; ca_b64_body(obs, olen, body, sizeof(body));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("attack:version", "observation",
                          "obs-badver-1", h, body, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("obs-badver-1"), 0);
}

/* ATTACK 7 (GATE 3): a v3-labelled body when the daemon holds no
 * observation-signing key. Fail CLOSED — refuse it rather than record an
 * Ed25519 observation nobody checked. */
TEST(test_chain_append_rejects_v3_without_obskey)
{
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9004);
    ASSERT_TRUE(olen > 0);

    /* Long enough to clear VIRP_OBS_V3_MIN_SIZE, labelled v3. */
    if (olen < VIRP_OBS_V3_MIN_SIZE) olen = VIRP_OBS_V3_MIN_SIZE;
    obs[0] = VIRP_VERSION_3;

    char h[65];  ca_sha256_hex_bin(obs, olen, h);
    char body[2048]; ca_b64_body(obs, olen, body, sizeof(body));

    ASSERT_TRUE(!ca_state.obskey_loaded);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("attack:v3", "observation",
                          "obs-v3-nokey-1", h, body, resp, sizeof(resp));

    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("obs-v3-nokey-1"), 0);
}

/* Hand-roll a v3 observation signed by `kp`. Built byte-wise rather
 * than via virp_build_observation_ed25519 because that requires an
 * ACTIVE session for the HMAC trailer, and the public-key gate does not
 * read the HMAC — it only has to be present and inside the signed
 * span. */
static size_t ca_mint_v3_obs(uint8_t *buf, size_t cap,
                             const virp_obskey_t *kp, uint64_t seq)
{
    const char *PAY = "GigabitEthernet0/2 up/up";
    size_t P = strlen(PAY);
    size_t total = VIRP_OBS_V2_HEADER_SIZE + P + VIRP_OBS_V2_SIG_SIZE +
                   VIRP_OBS_ED25519_SIG_SIZE;
    if (cap < total) return 0;

    virp_obs_header_v2_t h;
    memset(&h, 0, sizeof(h));
    h.version = VIRP_VERSION_3;
    h.channel = VIRP_CHANNEL_OBS;
    h.tier    = VIRP_TIER_GREEN;
    h.node_id = 0x00000042u;
    h.device_id = 0x1122334455667788ULL;
    h.seq_num = seq;
    h.timestamp_ns = 1754582400ULL * 1000000000ULL;
    memset(h.session_id, 0x21, 16);
    memset(h.command_hash, 0x37, 32);
    h.payload_len = (uint32_t)P;
    if (virp_obs_header_v2_serialize(&h, buf, cap) != VIRP_OK) return 0;

    memcpy(buf + VIRP_OBS_V2_HEADER_SIZE, PAY, P);
    size_t hmac_span = VIRP_OBS_V2_HEADER_SIZE + P;
    memset(buf + hmac_span, 0x5A, VIRP_OBS_V2_SIG_SIZE);   /* not read */
    size_t sig_span = hmac_span + VIRP_OBS_V2_SIG_SIZE;
    if (crypto_sign_detached(buf + sig_span, NULL, buf, sig_span,
                             kp->secret_key) != 0) return 0;
    return total;
}

/* GATE 3, v3 POSITIVE: with the observation-signing key loaded, a
 * genuinely Ed25519-signed observation registers. Without this the v3
 * arm would only ever be proved to say no. */
TEST(test_chain_append_accepts_signed_v3_observation)
{
    virp_obskey_t kp;
    ASSERT_OK(virp_obskey_generate(&kp));
    ca_state.obskey = kp;
    ca_state.obskey_loaded = true;

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v3_obs(obs, sizeof(obs), &kp, 9101);
    ASSERT_TRUE(olen > 0);

    char h[65];  ca_sha256_hex_bin(obs, olen, h);
    char body[2048]; ca_b64_body(obs, olen, body, sizeof(body));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("autopilot:v3", "observation",
                          "obs-v3-good-1", h, body, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("obs-v3-good-1"), 1);

    /* ...and the same body signed by a DIFFERENT key is refused. */
    virp_obskey_t other;
    ASSERT_OK(virp_obskey_generate(&other));
    size_t olen2 = ca_mint_v3_obs(obs, sizeof(obs), &other, 9102);
    ASSERT_TRUE(olen2 > 0);
    char h2[65]; ca_sha256_hex_bin(obs, olen2, h2);
    char body2[2048]; ca_b64_body(obs, olen2, body2, sizeof(body2));
    ssize_t n2 = ca_append("autopilot:v3", "observation",
                           "obs-v3-wrongkey-1", h2, body2, resp, sizeof(resp));
    ASSERT_EQ((int)n2, 4);
    ASSERT_EQ(ca_count_entries("obs-v3-wrongkey-1"), 0);

    ca_state.obskey_loaded = false;      /* restore for later tests */
}

/* GATE 3, v2: the daemon holds one session at a time. With no ACTIVE
 * session there is no key to check a v2 body under, so it is refused
 * rather than recorded unverified. */
TEST(test_chain_append_rejects_v2_without_active_session)
{
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9201);
    ASSERT_TRUE(olen > 0);
    if (olen < VIRP_OBS_V2_MIN_SIZE) olen = VIRP_OBS_V2_MIN_SIZE;
    obs[0] = VIRP_VERSION_2;

    char h[65];  ca_sha256_hex_bin(obs, olen, h);
    char body[2048]; ca_b64_body(obs, olen, body, sizeof(body));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("attack:v2", "observation",
                          "obs-v2-nosession-1", h, body, resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("obs-v2-nosession-1"), 0);
}

/* ===================================================================
 * Q1 — commitment-only observations. THE production question.
 *
 * virp_autopilot.py omits artifact_content entirely when the encoded
 * body would reach the daemon's 8192-byte field, which is roughly half
 * of LibreNMS every five-minute cycle. If GATE 3 demanded a body, all
 * of those would fail closed at the first restart after deploy.
 *
 * DECIDED, not incidental: no body means the entry commits to the hash
 * ALONE and GATE 3 does not run — there are no bytes to verify. See
 * src/virp_onode.c:2484, where the whole GATE 2 + GATE 3 block is
 * conditioned on `req.artifact_content[0] != '\0'`.
 *
 * Why that is not a signature bypass: the attacker's reward for
 * registering a hash-only entry is an entry with no body, and every
 * reader grades a body-less observation UNVERIFIABLE rather than
 * verified (report/verify.py, "no signed message body is stored").
 * It buys an unverifiable row, not a forged observation.
 * =================================================================== */

/* The autopilot oversized path exactly: no artifact_content key. */
TEST(test_chain_append_commitment_only_observation_accepted)
{
    char h[65];
    ca_sha256_hex("an oversized librenms body the chain will not hold", h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("autopilot:librenms", "observation",
                          "obs-oversized-1", h, NULL, resp, sizeof(resp));

    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("obs-oversized-1"), 1);
}

/* The same decision for a PRESENT-but-empty artifact_content, which is
 * the other way a client can express "no body". */
TEST(test_chain_append_commitment_only_empty_body_accepted)
{
    char h[65];
    ca_sha256_hex("another oversized body", h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("autopilot:librenms", "observation",
                          "obs-oversized-2", h, "", resp, sizeof(resp));

    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("obs-oversized-2"), 1);
}

/* ===================================================================
 * Q3 — the INDIRECT types must still register. They commit to a signed
 * observation the chain does not retain and submit verdict JSON as the
 * body, so sha256(body) != declared hash BY DESIGN. The comparator is
 * the cross-node tamper-detection layer and runs on a short cycle; a
 * silent rejection here is a real loss of coverage.
 * =================================================================== */

TEST(test_chain_append_accepts_comparator_verdict)
{
    const char *body = "{\"verdict\":\"MATCH\",\"peer\":\"node-b\"}";
    char h[65];
    /* Deliberately NOT sha256(body): commits to the signed observation. */
    ca_sha256_hex("the signed observation this verdict is about", h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("comparator:2026", "comparator_verdict",
                          "cmp-1", h, body, resp, sizeof(resp));

    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("cmp-1"), 1);
}

TEST(test_chain_append_accepts_chainwalk_summary)
{
    const char *body = "{\"walked\":412,\"breaks\":0}";
    char h[65];
    ca_sha256_hex("the signed observation this summary is about", h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("chainwalk:2026", "chainwalk_summary",
                          "walk-1", h, body, resp, sizeof(resp));

    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("walk-1"), 1);
}

/* ===================================================================
 * Q4 — version confusion across the dispatch boundary. Dispatch is on
 * byte 0 (src/virp_onode.c chain_append_verify_observation), so the
 * question is whether a body genuinely signed under one format can be
 * relabelled into another arm and survive it. Each arm re-checks the
 * version byte inside its own verifier, and the version byte is inside
 * every format's signed span, so a relabel invalidates the signature it
 * is trying to reuse. Both directions, exhaustively over the arms.
 * =================================================================== */
TEST(test_chain_append_version_confusion_all_arms)
{
    virp_obskey_t kp;
    ASSERT_OK(virp_obskey_generate(&kp));
    ca_state.obskey = kp;
    ca_state.obskey_loaded = true;

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    char h[65], body[2048], aid[64];
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    int caseno = 0;

    /* A genuine v1 observation, relabelled into each other arm. */
    const uint8_t relabel_from_v1[] = { VIRP_VERSION_2, VIRP_VERSION_3 };
    for (size_t i = 0; i < sizeof(relabel_from_v1); i++) {
        size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9300 + i);
        ASSERT_TRUE(olen > 0);
        if (olen < VIRP_OBS_V3_MIN_SIZE) olen = VIRP_OBS_V3_MIN_SIZE;
        obs[0] = relabel_from_v1[i];
        ca_sha256_hex_bin(obs, olen, h);
        ca_b64_body(obs, olen, body, sizeof(body));
        snprintf(aid, sizeof(aid), "obs-confuse-v1-%d", caseno++);
        ssize_t n = ca_append("attack:confusion", "observation", aid, h,
                              body, resp, sizeof(resp));
        ASSERT_EQ((int)n, 4);
        ASSERT_EQ(ca_count_entries(aid), 0);
    }

    /* A genuine v3 observation, relabelled into each other arm. */
    const uint8_t relabel_from_v3[] = { VIRP_VERSION, VIRP_VERSION_2 };
    for (size_t i = 0; i < sizeof(relabel_from_v3); i++) {
        size_t olen = ca_mint_v3_obs(obs, sizeof(obs), &kp, 9400 + i);
        ASSERT_TRUE(olen > 0);
        obs[0] = relabel_from_v3[i];
        ca_sha256_hex_bin(obs, olen, h);
        ca_b64_body(obs, olen, body, sizeof(body));
        snprintf(aid, sizeof(aid), "obs-confuse-v3-%d", caseno++);
        ssize_t n = ca_append("attack:confusion", "observation", aid, h,
                              body, resp, sizeof(resp));
        ASSERT_EQ((int)n, 4);
        ASSERT_EQ(ca_count_entries(aid), 0);
    }

    /* And a genuine v3 kept as v3 still registers, so the sweep above
     * is rejecting relabelling and not simply everything. */
    size_t olen = ca_mint_v3_obs(obs, sizeof(obs), &kp, 9500);
    ASSERT_TRUE(olen > 0);
    ca_sha256_hex_bin(obs, olen, h);
    ca_b64_body(obs, olen, body, sizeof(body));
    ssize_t ok = ca_append("autopilot:v3", "observation", "obs-confuse-ctl",
                           h, body, resp, sizeof(resp));
    ASSERT_TRUE(ok > 4);
    ASSERT_EQ(ca_count_entries("obs-confuse-ctl"), 1);

    ca_state.obskey_loaded = false;
}

/* Q2 — artifact_hash commits to the FULL message bytes, so every byte
 * of a submitted observation must be bound by something. The signed
 * span covers all of it except the trailing 64-byte signature; this
 * pins that last region at the handler boundary. The declared hash is
 * recomputed over the tampered bytes so GATE 2 is satisfied and only
 * the signature check can reject. */
TEST(test_chain_append_binds_the_signature_region_too)
{
    virp_obskey_t kp;
    ASSERT_OK(virp_obskey_generate(&kp));
    ca_state.obskey = kp;
    ca_state.obskey_loaded = true;

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    char h[65], body[2048], aid[64];
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];

    /* First, last and a middle byte of the Ed25519 signature region. */
    const int offs[] = { 0, 31, 63 };
    for (size_t i = 0; i < sizeof(offs)/sizeof(offs[0]); i++) {
        size_t olen = ca_mint_v3_obs(obs, sizeof(obs), &kp, 9600 + i);
        ASSERT_TRUE(olen > 0);
        obs[olen - VIRP_OBS_ED25519_SIG_SIZE + offs[i]] ^= 0x01;
        ca_sha256_hex_bin(obs, olen, h);          /* honest hash */
        ca_b64_body(obs, olen, body, sizeof(body));
        snprintf(aid, sizeof(aid), "obs-sigregion-%zu", i);
        ssize_t n = ca_append("attack:sigregion", "observation", aid, h,
                              body, resp, sizeof(resp));
        ASSERT_EQ((int)n, 4);
        ASSERT_EQ(ca_count_entries(aid), 0);
    }

    ca_state.obskey_loaded = false;
}

/* ===================================================================
 * O-Key rotation grace window.
 *
 * The failure it closes: registration is a separate round-trip from
 * collection, so an observation minted under the old key and submitted
 * after a rotation is refused by GATE 3 and LOST — no client retries.
 *
 * These tests rotate ca_state's live key underneath the running daemon,
 * which is the whole point: an observation signed under the key that
 * was live a moment ago must still register while the window is open,
 * and must stop registering once it is not.
 * =================================================================== */

/* Sign a v1 observation under an ARBITRARY key, not the daemon's. */
static size_t ca_mint_v1_obs_with(uint8_t *buf, size_t cap,
                                  virp_signing_key_t *k, uint64_t seq)
{
    size_t len = 0;
    virp_error_t e = virp_build_observation_tiered(
        buf, cap, &len, 0x00000042u, (uint32_t)seq,
        VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL, VIRP_TIER_GREEN,
        (const uint8_t *)"GigabitEthernet0/3 up/up", 24, k);
    return (e == VIRP_OK) ? len : 0;
}

static ssize_t ca_register_obs(const uint8_t *obs, size_t olen,
                               const char *aid, uint8_t *resp, size_t cap)
{
    char h[65], body[2048];
    ca_sha256_hex_bin(obs, olen, h);
    ca_b64_body(obs, olen, body, sizeof(body));
    return ca_append("autopilot:rotation", "observation", aid, h, body,
                     resp, cap);
}

TEST(test_rotation_grace_window_saves_in_flight_observation)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];

    /* An observation minted under the key that is live RIGHT NOW. */
    virp_signing_key_t old_key = ca_state.okey;
    size_t olen = ca_mint_v1_obs_with(obs, sizeof(obs), &old_key, 9700);
    ASSERT_TRUE(olen > 0);

    /* Rotate: a brand-new live key, old one kept for verification. */
    virp_signing_key_t new_key;
    ASSERT_OK(virp_key_generate(&new_key, VIRP_KEY_TYPE_OKEY));
    ca_state.okey = new_key;

    /* Without the window, this in-flight observation is simply lost. */
    ca_state.prev_okey_loaded = false;
    ssize_t lost = ca_register_obs(obs, olen, "obs-rot-lost", resp,
                                   sizeof(resp));
    ASSERT_EQ((int)lost, 4);
    ASSERT_EQ(ca_count_entries("obs-rot-lost"), 0);

    /* With the window open, the same bytes register. */
    ca_state.prev_okey = old_key;
    ca_state.prev_okey_loaded = true;
    ca_state.prev_okey_accepts = 0;
    {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        ca_state.prev_okey_deadline_ns =
            (uint64_t)now.tv_sec * 1000000000ULL +
            (uint64_t)now.tv_nsec + 300ULL * 1000000000ULL;
    }
    ssize_t saved = ca_register_obs(obs, olen, "obs-rot-saved", resp,
                                    sizeof(resp));
    ASSERT_TRUE(saved > 4);
    ASSERT_EQ(ca_count_entries("obs-rot-saved"), 1);
    ASSERT_EQ((int)ca_state.prev_okey_accepts, 1);

    /* Restore. */
    ca_state.okey = old_key;
    ca_state.prev_okey_loaded = false;
}

/* The window must CLOSE. A grace period that never expires is a second
 * live key. Deadline in the past => the same bytes are refused again. */
TEST(test_rotation_grace_window_expires)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];

    virp_signing_key_t old_key = ca_state.okey;
    size_t olen = ca_mint_v1_obs_with(obs, sizeof(obs), &old_key, 9701);
    ASSERT_TRUE(olen > 0);

    virp_signing_key_t new_key;
    ASSERT_OK(virp_key_generate(&new_key, VIRP_KEY_TYPE_OKEY));
    ca_state.okey = new_key;

    ca_state.prev_okey = old_key;
    ca_state.prev_okey_loaded = true;
    ca_state.prev_okey_accepts = 0;
    {   /* deadline one second in the PAST */
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        ca_state.prev_okey_deadline_ns =
            (uint64_t)now.tv_sec * 1000000000ULL +
            (uint64_t)now.tv_nsec - 1000000000ULL;
    }
    ssize_t n = ca_register_obs(obs, olen, "obs-rot-expired", resp,
                                sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("obs-rot-expired"), 0);
    ASSERT_EQ((int)ca_state.prev_okey_accepts, 0);

    ca_state.okey = old_key;
    ca_state.prev_okey_loaded = false;
}

/* The window widens acceptance to exactly ONE extra key, not to
 * anything. A body signed under a third key is still refused while the
 * window is wide open. */
TEST(test_rotation_grace_window_does_not_accept_a_third_key)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];

    virp_signing_key_t old_key = ca_state.okey;
    virp_signing_key_t attacker;
    ASSERT_OK(virp_key_generate(&attacker, VIRP_KEY_TYPE_OKEY));
    size_t olen = ca_mint_v1_obs_with(obs, sizeof(obs), &attacker, 9702);
    ASSERT_TRUE(olen > 0);

    ca_state.prev_okey = old_key;      /* window open, wrong key though */
    ca_state.prev_okey_loaded = true;
    ca_state.prev_okey_accepts = 0;
    {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        ca_state.prev_okey_deadline_ns =
            (uint64_t)now.tv_sec * 1000000000ULL +
            (uint64_t)now.tv_nsec + 300ULL * 1000000000ULL;
    }
    ssize_t n = ca_register_obs(obs, olen, "obs-rot-thirdkey", resp,
                                sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(ca_count_entries("obs-rot-thirdkey"), 0);
    ASSERT_EQ((int)ca_state.prev_okey_accepts, 0);

    ca_state.prev_okey_loaded = false;
}

/* onode_set_previous_okey refuses the two ways an operator can think
 * they have a window when they do not. */
TEST(test_previous_okey_loader_refuses_bad_configurations)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/virp-prev-okey-test.bin");
    unlink(path);

    /* Write the CURRENT key out, so the file is valid but identical. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ASSERT_TRUE(fd >= 0);
    ASSERT_EQ((int)write(fd, ca_state.okey.key.key, VIRP_KEY_SIZE),
              VIRP_KEY_SIZE);
    close(fd);

    /* Zero window is refused outright. */
    ASSERT_TRUE(onode_set_previous_okey(&ca_state, path, 0) != VIRP_OK);
    ASSERT_TRUE(!ca_state.prev_okey_loaded);

    /* Same key as the live one is refused. */
    ASSERT_TRUE(onode_set_previous_okey(&ca_state, path, 300) != VIRP_OK);
    ASSERT_TRUE(!ca_state.prev_okey_loaded);

    unlink(path);
}

/* The -W deadline is anchored to KEY-LOAD TIME (process start in the
 * daemon), not to the rotation event, and it is memory-only. This pins
 * both halves: the deadline lands at now+W when loaded, and loading
 * again — which is what an unrelated restart does — RE-OPENS a full
 * window rather than continuing the old one. That is why the runbook
 * says to remove -K after the drain instead of waiting for expiry. */
TEST(test_previous_okey_window_anchors_to_load_time_and_resets)
{
    char path[256];
    snprintf(path, sizeof(path), "/tmp/virp-prev-anchor-test.bin");
    unlink(path);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    ASSERT_TRUE(fd >= 0);
    uint8_t k[VIRP_KEY_SIZE];
    for (size_t i = 0; i < sizeof(k); i++) k[i] = (uint8_t)(0xA0 + i);
    ASSERT_EQ((int)write(fd, k, sizeof(k)), (int)sizeof(k));
    close(fd);

    struct timespec t0;
    clock_gettime(CLOCK_REALTIME, &t0);
    uint64_t before = (uint64_t)t0.tv_sec * 1000000000ULL + t0.tv_nsec;

    ASSERT_OK(onode_set_previous_okey(&ca_state, path, 300));
    ASSERT_TRUE(ca_state.prev_okey_loaded);
    uint64_t d1 = ca_state.prev_okey_deadline_ns;

    /* Anchored at load: deadline sits within a second of now + 300s. */
    ASSERT_TRUE(d1 >= before + 299ULL * 1000000000ULL);
    ASSERT_TRUE(d1 <= before + 301ULL * 1000000000ULL);

    /* Re-loading (what a restart does) moves the deadline FORWARD to a
     * fresh full window — it does not continue the previous one. */
    ASSERT_OK(onode_set_previous_okey(&ca_state, path, 300));
    ASSERT_TRUE(ca_state.prev_okey_deadline_ns >= d1);

    ca_state.prev_okey_loaded = false;
    unlink(path);
}

/* GUARD: a non-observation external type is NOT put through the
 * signature gate — evidence_item and friends are JSON bodies by design
 * and must keep registering. */
TEST(test_chain_append_still_accepts_json_evidence_item)
{
    const char *body = "{\"item\":\"pkg-list\",\"sha\":\"abc\"}";
    char h[65];
    ca_sha256_hex(body, h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("evidence:2026", "evidence_item",
                          "evi-legit-1", h, body, resp, sizeof(resp));

    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("evi-legit-1"), 1);
}

/* GUARD: a commitment-only append (no body at all) stays legal — the
 * caller may choose to register a hash commitment without the bytes. */
/* Defined with the Item 8 battery further down; the GATE 4 tests below
 * assert on the typed error, not merely on the absence of an entry, so
 * they need it here. */
static int32_t typed_error_of(const uint8_t *resp, ssize_t n);

/* Federation-bridge provenance (2026-08-09): federated_request and
 * federated_outcome are externally-submittable commitment types, so the
 * bridge's three-part record (request → observation → outcome) lands in
 * full. The reserved daemon type "outcome" stays refused from a socket
 * client — blessing the federation namespace must not open the daemon's.
 *
 * Rewritten 2026-08-16. This test used to append fed_request and then
 * fed_outcome with a stub body carrying no observation_sha256, which
 * meant the suite's idea of "the three-part record lands in full" never
 * exercised the middle part at all. That blind spot is why the live
 * regression ran five days unseen: the outcome landing was checked, the
 * body it cites was not. The middle append is now real — a genuinely
 * signed observation stored as fed_observation — and the outcome cites
 * its hash, so the assertion covers the link rather than assuming it. */
TEST(test_chain_append_accepts_federated_provenance)
{
    const char *req_body = "{\"schema\":\"federated_request/1\",\"peer\":\"netclaw\"}";
    char hr[65];
    ca_sha256_hex(req_body, hr);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n1 = ca_append("ncfed-netclaw-t1", "fed_request",
                           "ncfed-req-t1", hr, req_body, resp, sizeof(resp));
    ASSERT_TRUE(n1 > 4);
    ASSERT_EQ(ca_count_entries("ncfed-req-t1"), 1);

    /* the signed body the outcome will point at */
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9101);
    ASSERT_TRUE(olen > 0);
    char hobs[65];   ca_sha256_hex_bin(obs, olen, hobs);
    char obs_body[2048]; ca_b64_body(obs, olen, obs_body, sizeof(obs_body));

    ssize_t n2 = ca_append("ncfed-netclaw-t1", "fed_observation",
                           "ncfed-obs-t1", hobs, obs_body, resp, sizeof(resp));
    ASSERT_TRUE(n2 > 4);
    ASSERT_EQ(ca_count_entries("ncfed-obs-t1"), 1);

    char out_body[512];
    snprintf(out_body, sizeof(out_body),
             "{\"schema\":\"federated_outcome/1\",\"outcome\":\"refused\","
             "\"observation_sha256\":\"%s\"}", hobs);
    char ho[65];
    ca_sha256_hex(out_body, ho);

    ssize_t n3 = ca_append("ncfed-netclaw-t1", "fed_outcome",
                           "ncfed-out-t1", ho, out_body, resp, sizeof(resp));
    ASSERT_TRUE(n3 > 4);
    ASSERT_EQ(ca_count_entries("ncfed-out-t1"), 1);
}

/* GATE 4: an outcome citing a body the chain does not hold is refused.
 * This is the exact live failure — the fed_observation append is skipped
 * (as the Item 8 narrowing used to force) and the outcome names a hash
 * nothing resolves. Before GATE 4 the outcome landed and the chain
 * recorded evidence it could not produce. */
TEST(test_chain_append_refuses_fed_outcome_citing_unstored_observation)
{
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9102);
    ASSERT_TRUE(olen > 0);
    char hobs[65];  ca_sha256_hex_bin(obs, olen, hobs);
    /* deliberately NOT appended */

    char out_body[512];
    snprintf(out_body, sizeof(out_body),
             "{\"schema\":\"federated_outcome/1\",\"outcome\":\"executed\","
             "\"observation_sha256\":\"%s\"}", hobs);
    char ho[65];
    ca_sha256_hex(out_body, ho);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("ncfed-dangling-t1", "fed_outcome",
                          "ncfed-out-dangling-1", ho, out_body,
                          resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    ASSERT_EQ(ca_count_entries("ncfed-out-dangling-1"), 0);
}

/* GATE 4: an outcome citing a COMMITMENT-ONLY observation must LAND.
 *
 * This is the 2026-08-18 live-federation regression. A GREEN command whose
 * observation exceeds the daemon's 8192-byte inline body field is chained
 * commitment-only (the bridge omits artifact_content, exactly as the
 * autopilot oversized path does — see
 * test_chain_append_commitment_only_observation_accepted). The chain DOES
 * commit to that observation: a signed fed_observation entry whose
 * artifact_hash equals the cited observation_sha256 exists. It is NOT an
 * unbacked claim — only the body bytes were not retained, which every
 * reader already grades UNVERIFIABLE, not PASS. GATE 4 required the BODY to
 * be in artifacts, so it wrongly refused the outcome and left request +
 * observation chained with no outcome (correlations 42b7b9dc / c5373129).
 * The gate must accept when the chain commits to the observation, and
 * still refuse a truly dangling cite (the test above). */
TEST(test_chain_append_accepts_fed_outcome_for_commitment_only_observation)
{
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9103);
    ASSERT_TRUE(olen > 0);
    char hobs[65];  ca_sha256_hex_bin(obs, olen, hobs);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    /* Commitment-only: NULL artifact_content — the oversized-observation
     * path. Entry lands, body is NOT stored in artifacts. */
    ssize_t n2 = ca_append("ncfed-oversized-t1", "fed_observation",
                           "ncfed-obs-oversized-1", hobs, NULL,
                           resp, sizeof(resp));
    ASSERT_TRUE(n2 > 4);
    ASSERT_EQ(ca_count_entries("ncfed-obs-oversized-1"), 1);

    /* The outcome cites the commitment-only observation. The chain commits
     * to it, so the outcome must be accepted and the triple completed. */
    char out_body[512];
    snprintf(out_body, sizeof(out_body),
             "{\"schema\":\"federated_outcome/1\",\"outcome\":\"executed\","
             "\"observation_sha256\":\"%s\"}", hobs);
    char ho[65];  ca_sha256_hex(out_body, ho);

    ssize_t n3 = ca_append("ncfed-oversized-t1", "fed_outcome",
                           "ncfed-out-oversized-1", ho, out_body,
                           resp, sizeof(resp));
    ASSERT_TRUE(n3 > 4);
    ASSERT_EQ(ca_count_entries("ncfed-out-oversized-1"), 1);
}

/* GATE 4: citing nothing is refused too. Sixteen rows on the live chain
 * carry observation_sha256: null — an outcome asserting a result while
 * naming no evidence at all is the unbacked claim in its purest form. */
TEST(test_chain_append_refuses_fed_outcome_without_observation_hash)
{
    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];

    const char *no_field = "{\"schema\":\"federated_outcome/1\",\"outcome\":\"ok\"}";
    char h1[65];  ca_sha256_hex(no_field, h1);
    ssize_t n = ca_append("ncfed-nocite-t1", "fed_outcome",
                          "ncfed-out-nocite-1", h1, no_field,
                          resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    ASSERT_EQ(ca_count_entries("ncfed-out-nocite-1"), 0);

    const char *null_field = "{\"schema\":\"federated_outcome/1\","
                             "\"observation_sha256\":null}";
    char h2[65];  ca_sha256_hex(null_field, h2);
    n = ca_append("ncfed-nocite-t1", "fed_outcome",
                  "ncfed-out-null-1", h2, null_field, resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    ASSERT_EQ(ca_count_entries("ncfed-out-null-1"), 0);
}

/* GATE 3 covers fed_observation exactly as it covers observation. The
 * new type is a namespace for a restricted principal, not an exemption:
 * arbitrary JSON that hashes to its own commitment is still not a signed
 * observation and must not be storable as evidence under any name. */
TEST(test_chain_append_fed_observation_must_be_signed)
{
    const char *forged = "{\"device\":\"R1\",\"output\":\"all clear\"}";
    char h[65];
    ca_sha256_hex(forged, h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ca_append("ncfed-forge-t1", "fed_observation",
              "ncfed-obs-forged-1", h, forged, resp, sizeof(resp));
    ASSERT_EQ(ca_count_entries("ncfed-obs-forged-1"), 0);
}

/* GATE 5: a federation append may not reuse an artifact_id the store
 * already holds under a DIFFERENT body hash. The live signature this
 * closes: the bridge requeued unacknowledged submissions daily and
 * re-serialized the body each attempt (fresh timestamp → new hash), so
 * one correlation accumulated up to seven distinct "request" bodies —
 * self-consistent pairs GATE 2 rightly passed, provenance nobody can
 * read back as one event. A correlation id names ONE request, ONE
 * observation, ONE outcome; a retry that cannot resend the identical
 * bytes must mint a new correlation instead. */
TEST(test_chain_append_refuses_fed_retry_with_different_bytes)
{
    const char *b1 = "{\"schema\":\"federated_request/1\",\"attempt\":1}";
    char h1[65];
    ca_sha256_hex(b1, h1);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("ncfed-g5-t1", "fed_request", "ncfed-req-g5-1",
                          h1, b1, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);

    /* The retry signature: same correlation id, re-serialized body. The
     * pair is self-consistent, so GATE 2 passes it — only GATE 5 can
     * tell it apart from a first submission. */
    const char *b2 = "{\"schema\":\"federated_request/1\",\"attempt\":2}";
    char h2[65];
    ca_sha256_hex(b2, h2);
    n = ca_append("ncfed-g5-t1", "fed_request", "ncfed-req-g5-1",
                  h2, b2, resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_DUPLICATE_MISMATCH);
    ASSERT_EQ(ca_count_entries("ncfed-req-g5-1"), 1);
    ASSERT_EQ(ca_count_artifact_rows("ncfed-req-g5-1"), 1);
}

/* GATE 5 covers fed_outcome too — and the refusal must be its own code,
 * not GATE 4's: the outcome below cites a body that IS stored, so GATE 4
 * has nothing to say, yet the outcome's own bytes changed under a reused
 * correlation. */
TEST(test_chain_append_refuses_fed_outcome_retry_with_different_bytes)
{
    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9105);
    ASSERT_TRUE(olen > 0);
    char hobs[65];   ca_sha256_hex_bin(obs, olen, hobs);
    char obs_body[2048]; ca_b64_body(obs, olen, obs_body, sizeof(obs_body));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("ncfed-g5-t2", "fed_observation",
                          "ncfed-obs-g5-2", hobs, obs_body,
                          resp, sizeof(resp));
    ASSERT_TRUE(n > 4);

    char out1[512];
    snprintf(out1, sizeof(out1),
             "{\"schema\":\"federated_outcome/1\",\"outcome\":\"executed\","
             "\"observation_sha256\":\"%s\"}", hobs);
    char ho1[65];
    ca_sha256_hex(out1, ho1);
    n = ca_append("ncfed-g5-t2", "fed_outcome", "ncfed-out-g5-2",
                  ho1, out1, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);

    /* Re-serialized outcome (field order shifted), same correlation,
     * same VALID citation — GATE 4 passes it, GATE 5 must not. */
    char out2[512];
    snprintf(out2, sizeof(out2),
             "{\"observation_sha256\":\"%s\","
             "\"schema\":\"federated_outcome/1\",\"outcome\":\"executed\"}",
             hobs);
    char ho2[65];
    ca_sha256_hex(out2, ho2);
    n = ca_append("ncfed-g5-t2", "fed_outcome", "ncfed-out-g5-2",
                  ho2, out2, resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_DUPLICATE_MISMATCH);
    ASSERT_EQ(ca_count_entries("ncfed-out-g5-2"), 1);
    ASSERT_EQ(ca_count_artifact_rows("ncfed-out-g5-2"), 1);
}

/* GATE 5, positive half: a BYTE-IDENTICAL resubmission is a legitimate
 * retry — the bridge resends because the success frame was lost, and
 * its retry loop needs that frame, not an error to special-case as
 * success. The store is a no-op (ON CONFLICT DO NOTHING keeps one body
 * row); the chain records a second entry, the honest trace that a retry
 * happened; the caller gets a normal success reply. */
TEST(test_chain_append_accepts_byte_identical_fed_retry)
{
    const char *body = "{\"schema\":\"federated_request/1\",\"held\":true}";
    char h[65];
    ca_sha256_hex(body, h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("ncfed-g5-t3", "fed_request", "ncfed-req-g5-3",
                          h, body, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);

    n = ca_append("ncfed-g5-t3", "fed_request", "ncfed-req-g5-3",
                  h, body, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("ncfed-req-g5-3"), 2);
    ASSERT_EQ(ca_count_artifact_rows("ncfed-req-g5-3"), 1);
}

/* GUARD: GATE 5 is scoped to the federation types. For everything else
 * a colliding artifact_id with distinct bodies stays side-by-side
 * storage BY DESIGN — the 2026-08-03 production audit: two distinct
 * observations minted the same second-resolution id in one second, and
 * losing either body would have destroyed evidence. Daemon-minted and
 * autopilot types keep that tolerance; only correlation-keyed
 * federation ids promise one-id-one-body. */
TEST(test_chain_append_non_fed_colliding_id_still_stores_both)
{
    const char *b1 = "{\"item\":\"pkg-list\",\"epoch\":1}";
    char h1[65];
    ca_sha256_hex(b1, h1);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("evidence:2026", "evidence_item",
                          "evi-collide-1", h1, b1, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);

    const char *b2 = "{\"item\":\"pkg-list\",\"epoch\":2}";
    char h2[65];
    ca_sha256_hex(b2, h2);
    n = ca_append("evidence:2026", "evidence_item",
                  "evi-collide-1", h2, b2, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("evi-collide-1"), 2);
    ASSERT_EQ(ca_count_artifact_rows("evi-collide-1"), 2);
}

/* ==========================================================================
 * GATE 5 — the COMMITMENT-ONLY blind spot (external review of 9bd54e53).
 *
 * GATE 5's conflict query read the artifacts table (body storage). A
 * commitment-only fed_observation — a GREEN observation past the 8192-byte
 * inline limit, which the bridge chains as a hash commitment with NO body
 * (the common oversized path) — inserts no artifacts row. So the same
 * correlation id resubmitted with a DIFFERENT hash found nothing in
 * artifacts and appended a second entry: one correlation, two committed
 * observations, exactly what GATE 5 exists to refuse. The fix makes the
 * query's authority the chain (chain_entries), where every append lands
 * regardless of body retention. Same body-stored-vs-chain-committed
 * conflation as the GATE 4 (-50) fix, in the opposite direction.
 *
 * Tests 1-2 are RED before the fix (the second hash lands); tests 3-4 are
 * retention/no-regression guards (green both ways).
 * ========================================================================== */

/* 1. Sequential: same correlation id, two commitment-only observations with
 * DIFFERENT hashes → the second is refused VIRP_ERR_DUPLICATE_MISMATCH and
 * the chain keeps exactly one. */
TEST(test_chain_append_refuses_commitment_only_fed_retry_with_different_bytes)
{
    char h1[65]; ca_sha256_hex("g5c-observation-alpha", h1);
    char h2[65]; ca_sha256_hex("g5c-observation-beta",  h2);
    ASSERT_TRUE(strcmp(h1, h2) != 0);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    /* Commitment-only: NULL artifact_content, so no artifacts row lands and
     * (per onode GATE 2/3, gated on body presence) no signature is required
     * of the bare commitment. */
    ssize_t n = ca_append("ncfed-g5c-1", "fed_observation",
                          "ncfed-obs-g5c-1", h1, NULL, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("ncfed-obs-g5c-1"), 1);
    ASSERT_EQ(ca_count_artifact_rows("ncfed-obs-g5c-1"), 0);   /* no body */

    n = ca_append("ncfed-g5c-1", "fed_observation",
                  "ncfed-obs-g5c-1", h2, NULL, resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_DUPLICATE_MISMATCH);
    ASSERT_EQ(ca_count_entries("ncfed-obs-g5c-1"), 1);         /* still ONE */
}

/* 2. Concurrent barrier: N writers race the same correlation id, each a
 * commitment-only observation with a DISTINCT hash. Exactly one wins; the
 * chain holds exactly one entry. The bodies are absent, so the entry count
 * — not an artifacts-row count — is the ground truth here. */
#define G5C_THREADS  8
#define G5C_ROUNDS   20

typedef struct {
    int round;
    int tid;
    pthread_barrier_t *barrier;
    int success;
    int wrong_error;
    int transport;
} g5c_arg_t;

static void *g5c_worker(void *p)
{
    g5c_arg_t *a = (g5c_arg_t *)p;

    /* Distinct, valid 64-hex commitment per (round,tid); no body sent. */
    char h[65];
    snprintf(h, sizeof(h), "%064x", (unsigned)(a->round * 1000 + a->tid + 1));

    char json[512];
    snprintf(json, sizeof(json),
             "{\"action\":\"chain_append\",\"session_id\":\"g5crace:%d\","
             "\"artifact_type\":\"fed_observation\","
             "\"artifact_id\":\"g5crace-r%03d\","
             "\"artifact_hash\":\"%s\"}",
             a->round, a->round, h);

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { a->transport++; return NULL; }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CA_SOCKET);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd); a->transport++;
        pthread_barrier_wait(a->barrier);
        return NULL;
    }

    pthread_barrier_wait(a->barrier);

    size_t json_len = strlen(json);
    uint32_t frame_len = htonl((uint32_t)(1 + json_len));
    send(fd, &frame_len, 4, 0);
    uint8_t version = VIRP_FRAME_VERSION;
    send(fd, &version, 1, 0);
    send(fd, json, json_len, 0);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    uint32_t net_rlen;
    if (recv(fd, &net_rlen, 4, 0) != 4) { close(fd); a->transport++; return NULL; }
    uint32_t rlen = ntohl(net_rlen);
    if (rlen > sizeof(resp)) { close(fd); a->transport++; return NULL; }
    size_t got = 0;
    while (got < rlen) {
        ssize_t n = recv(fd, resp + got, rlen - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);

    if (got != rlen) {
        a->transport++;
    } else if (rlen > 4) {
        a->success = 1;
    } else if (typed_error_of(resp, (ssize_t)rlen)
               != (int32_t)VIRP_ERR_DUPLICATE_MISMATCH) {
        a->wrong_error = 1;
    }
    return NULL;
}

TEST(test_chain_append_concurrent_commitment_only_fed_conflict_is_atomic)
{
    for (int round = 0; round < G5C_ROUNDS; round++) {
        pthread_barrier_t barrier;
        ASSERT_EQ(pthread_barrier_init(&barrier, NULL, G5C_THREADS), 0);

        pthread_t th[G5C_THREADS];
        g5c_arg_t args[G5C_THREADS];
        memset(args, 0, sizeof(args));
        for (int i = 0; i < G5C_THREADS; i++) {
            args[i].round = round;
            args[i].tid = i;
            args[i].barrier = &barrier;
            ASSERT_EQ(pthread_create(&th[i], NULL, g5c_worker, &args[i]), 0);
        }

        int successes = 0, wrong_error = 0, transport = 0;
        for (int i = 0; i < G5C_THREADS; i++) {
            pthread_join(th[i], NULL);
            successes   += args[i].success;
            wrong_error += args[i].wrong_error;
            transport   += args[i].transport;
        }
        pthread_barrier_destroy(&barrier);

        char id[64];
        snprintf(id, sizeof(id), "g5crace-r%03d", round);

        ASSERT_EQ(transport, 0);
        ASSERT_EQ(wrong_error, 0);
        /* Commitment-only: no artifacts rows exist, so the ENTRY count is the
         * ground truth. A second success would be a second entry. */
        ASSERT_EQ(successes, 1);
        ASSERT_EQ(ca_count_entries(id), 1);
        ASSERT_EQ(ca_count_artifact_rows(id), 0);
    }
}

/* 3. GUARD (retention): a BYTE-IDENTICAL commitment-only retry — same id,
 * same hash — is a legitimate lost-ack retry and must still be accepted,
 * recording a second entry (the honest trace). Green before and after; the
 * fix must not turn same-hash retries into a conflict. */
TEST(test_chain_append_accepts_commitment_only_byte_identical_fed_retry)
{
    char h[65]; ca_sha256_hex("g5c-identical-retry", h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("ncfed-g5c-2", "fed_observation",
                          "ncfed-obs-g5c-2", h, NULL, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    n = ca_append("ncfed-g5c-2", "fed_observation",
                  "ncfed-obs-g5c-2", h, NULL, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);                                        /* accepted */
    ASSERT_EQ(ca_count_entries("ncfed-obs-g5c-2"), 2);        /* retry trace */
    ASSERT_EQ(ca_count_artifact_rows("ncfed-obs-g5c-2"), 0);
}

/* 4. GUARD (scope): GATE 5 is federation-only. A NON-federation commitment-
 * only append with a colliding id and different hashes must STILL store both
 * — the 2026-08-03 side-by-side tolerance. Green before and after; proves the
 * chain_entries query did not widen the gate to non-federation types (which
 * also write chain_entries rows). */
TEST(test_chain_append_non_fed_commitment_only_colliding_id_stores_both)
{
    char h1[65]; ca_sha256_hex("g5c-nonfed-one", h1);
    char h2[65]; ca_sha256_hex("g5c-nonfed-two", h2);
    ASSERT_TRUE(strcmp(h1, h2) != 0);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("evidence:2026", "observation",
                          "obs-collide-g5c", h1, NULL, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    n = ca_append("evidence:2026", "observation",
                  "obs-collide-g5c", h2, NULL, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);                                        /* NOT refused */
    ASSERT_EQ(ca_count_entries("obs-collide-g5c"), 2);        /* both land */
}

/* GUARD: the reserved daemon type "outcome" is STILL refused from a
 * socket client — the federation types did not widen the daemon namespace. */
TEST(test_chain_append_still_refuses_reserved_outcome_type)
{
    const char *body = "{\"forged\":\"daemon outcome\"}";
    char h[65];
    ca_sha256_hex(body, h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ca_append("attack:reserved", "outcome", "forged-outcome-1", h, body,
              resp, sizeof(resp));
    /* Refused → no entry lands. */
    ASSERT_EQ(ca_count_entries("forged-outcome-1"), 0);
}

TEST(test_chain_append_accepts_commitment_without_body)
{
    char h[65];
    ca_sha256_hex("bytes the chain will not hold", h);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    ssize_t n = ca_append("autopilot:legit", "observation",
                          "obs-commitment-1", h, NULL, resp, sizeof(resp));

    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("obs-commitment-1"), 1);
}

/* =========================================================================
 * Concurrency regressions (external review 2026-08-17)
 *
 * Two findings, both in the evidence path, both only reachable when
 * more than one connection worker is inside CHAIN_APPEND at once —
 * which is exactly how the daemon runs (thread-per-connection, up to
 * ONODE_MAX_WORKERS). A serial test cannot catch either; these drive
 * real concurrent requests through real sockets.
 * ========================================================================= */

/* Same framing as ca_request(), minus its 50ms settling sleep: these
 * tests need requests IN FLIGHT together, and recv() blocks until the
 * daemon replies anyway. */
static ssize_t car_request(const char *json, uint8_t *resp, size_t resp_cap)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CA_SOCKET);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    size_t json_len = strlen(json);
    uint32_t frame_len = htonl((uint32_t)(1 + json_len));
    send(fd, &frame_len, 4, 0);
    uint8_t version = VIRP_FRAME_VERSION;
    send(fd, &version, 1, 0);
    send(fd, json, json_len, 0);

    uint32_t net_rlen;
    if (recv(fd, &net_rlen, 4, 0) != 4) { close(fd); return -1; }
    uint32_t rlen = ntohl(net_rlen);
    if (rlen > resp_cap) { close(fd); return -1; }
    size_t got = 0;
    while (got < rlen) {
        ssize_t n = recv(fd, resp + got, rlen - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);
    return (ssize_t)got;
}

/* -------------------------------------------------------------------------
 * Regression 1: GATE 3 must verify each request's OWN bytes.
 *
 * chain_append_verify_observation() decoded every submitted body into
 * ONE function-static 64KB buffer. Two workers in the gate at once and
 * worker A's signature check runs over whatever worker B last decoded:
 * a tampered body gets accepted because a concurrent VALID body
 * overwrote it between decode and verify, and a valid body gets
 * refused because concurrent bytes tore under its HMAC. Both directions
 * are asserted here: every genuinely signed submission must be
 * accepted, every tampered one refused, under sustained concurrency.
 *
 * The payload is large (4KB) on purpose — it widens the window between
 * "decoded into the buffer" and "verified out of the buffer" that the
 * shared static leaves open.
 * ------------------------------------------------------------------------- */

#define RACE_THREADS  10
#define RACE_ITERS    120
#define RACE_PAYLOAD  4096

typedef struct {
    int tid;
    int valid_rejected;     /* genuinely signed, refused — must stay 0 */
    int tampered_accepted;  /* tampered, accepted       — must stay 0 */
    int transport_errors;   /* connect/frame failures   — must stay 0 */
} race_arg_t;

static size_t race_mint_obs(uint8_t *buf, size_t cap, int tid, int iter)
{
    /* Distinct payload bytes per (thread, iteration): if verification
     * ever runs over another request's bytes, they are NEVER the same
     * bytes this request submitted. */
    uint8_t payload[RACE_PAYLOAD];
    int hdr = snprintf((char *)payload, sizeof(payload),
                       "{\"race\":\"t%02d-i%03d\",\"fill\":\"", tid, iter);
    for (size_t i = (size_t)hdr; i < sizeof(payload); i++)
        payload[i] = (uint8_t)('a' + ((i + (size_t)tid * 7u
                                         + (size_t)iter * 13u) % 26u));

    size_t len = 0;
    virp_error_t e = virp_build_observation_tiered(
        buf, cap, &len, 0x00000042u,
        200000u + (uint32_t)tid * 1000u + (uint32_t)iter,
        VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL, VIRP_TIER_GREEN,
        payload, (uint16_t)sizeof(payload), &ca_state.okey);
    return (e == VIRP_OK) ? len : 0;
}

static void *race_worker(void *p)
{
    race_arg_t *a = (race_arg_t *)p;

    for (int i = 0; i < RACE_ITERS; i++) {
        uint8_t obs[8192];
        size_t olen = race_mint_obs(obs, sizeof(obs), a->tid, i);
        if (olen == 0) { a->transport_errors++; continue; }

        int tamper = (i & 1);
        if (tamper)
            obs[olen - 1] ^= 0x01;   /* break the signature, not the hash */

        /* Honest hash over the bytes actually sent, tampered or not:
         * GATE 2 must pass so GATE 3 — the gate under test — decides. */
        char h[65];
        ca_sha256_hex_bin(obs, olen, h);
        char body[12288];
        ca_b64_body(obs, olen, body, sizeof(body));

        char id[64];
        snprintf(id, sizeof(id), "race-t%02d-i%03d-%s",
                 a->tid, i, tamper ? "bad" : "ok");

        char json[16384];
        snprintf(json, sizeof(json),
                 "{\"action\":\"chain_append\",\"session_id\":\"race:%02d\","
                 "\"artifact_type\":\"observation\",\"artifact_id\":\"%s\","
                 "\"artifact_hash\":\"%s\",\"artifact_content\":\"%s\"}",
                 a->tid, id, h, body);

        uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
        ssize_t n = car_request(json, resp, sizeof(resp));
        if (n < 4)            a->transport_errors++;
        else if (tamper && n > 4)   a->tampered_accepted++;
        else if (!tamper && n == 4) a->valid_rejected++;
    }
    return NULL;
}

TEST(test_chain_append_concurrent_verify_uses_own_bytes)
{
    pthread_t th[RACE_THREADS];
    race_arg_t args[RACE_THREADS];
    memset(args, 0, sizeof(args));

    for (int i = 0; i < RACE_THREADS; i++) {
        args[i].tid = i;
        ASSERT_EQ(pthread_create(&th[i], NULL, race_worker, &args[i]), 0);
    }

    int valid_rejected = 0, tampered_accepted = 0, transport = 0;
    for (int i = 0; i < RACE_THREADS; i++) {
        pthread_join(th[i], NULL);
        valid_rejected    += args[i].valid_rejected;
        tampered_accepted += args[i].tampered_accepted;
        transport         += args[i].transport_errors;
    }

    ASSERT_EQ(transport, 0);
    ASSERT_EQ(tampered_accepted, 0);
    ASSERT_EQ(valid_rejected, 0);
}

/* -------------------------------------------------------------------------
 * Regression 2 (F4): GATE 5 is check-then-act across the transaction
 * boundary.
 *
 * The conflict probe ran OUTSIDE the append transaction: N concurrent
 * submissions of the SAME federation artifact_id with DIFFERENT bytes
 * could all pass the probe before the first append committed, then all
 * commit — one correlation id stored under several hashes, the exact
 * bridge-requeue corruption GATE 5 exists to refuse. The check must run
 * inside the same BEGIN IMMEDIATE transaction as the append.
 *
 * Two tests. The first drives the daemon's exact call sequence —
 * virp_chain_artifact_id_conflict() then
 * virp_chain_append_with_artifact() — from N threads with a barrier
 * BETWEEN the probe and the append, the adversarial schedule the
 * daemon does nothing to forbid: every thread passes the probe before
 * any thread appends. It is deterministic in both directions — the
 * old code stores all N bodies every time; with the check inside the
 * append's own transaction exactly one wins, no matter the schedule.
 * (This runs against ca_state.chain in-process, the same store the
 * daemon threads use; the chain mutex makes that legal.)
 *
 * The second releases rounds of pre-connected socket clients through
 * a barrier: end-to-end confirmation that under real concurrent
 * submissions exactly ONE body wins and every loser is refused with
 * VIRP_ERR_DUPLICATE_MISMATCH, nothing else. It is a REGRESSION GUARD,
 * not a race detector: it cannot force the daemon's internal
 * probe->append interleaving, and measured on pre-fix 38938761
 * (2026-08-17, two clean sequential runs, 40 rounds total) it never
 * caught the race — the old out-of-txn probe happened to win every
 * schedule and the test passed. Only the barrier test above goes red
 * on the old code. If THIS test fails, the one-winner/-51 contract is
 * broken outright; do not read a pass as TOCTOU coverage.
 * ------------------------------------------------------------------------- */

#define G5_THREADS  8
#define G5_ROUNDS   20

typedef struct {
    int tid;
    pthread_barrier_t *start;    /* everyone probes together            */
    pthread_barrier_t *checked;  /* nobody appends until ALL have probed */
    virp_error_t probe_rc;
    int probe_conflict;
    virp_error_t append_rc;      /* VIRP_OK only for the one winner     */
} g5lib_arg_t;

static void *g5lib_worker(void *p)
{
    g5lib_arg_t *a = (g5lib_arg_t *)p;

    char body[96];
    snprintf(body, sizeof(body),
             "{\"schema\":\"federated_request/1\",\"writer\":%d}", a->tid);
    char h[65];
    ca_sha256_hex(body, h);

    pthread_barrier_wait(a->start);

    bool conflict = false;
    a->probe_rc = virp_chain_artifact_id_conflict(&ca_state.chain,
                                                  "g5lib-race-1", h,
                                                  &conflict);
    a->probe_conflict = conflict;

    /* The daemon holds no lock across this boundary — any schedule is
     * fair game, including this worst case. */
    pthread_barrier_wait(a->checked);

    if (a->probe_rc == VIRP_OK && !conflict) {
        virp_chain_entry_t e;
        a->append_rc = virp_chain_append_with_artifact(
                           &ca_state.chain, "g5lib:race", "fed_request",
                           "g5lib-race-1", h, body, &e);
    } else {
        a->append_rc = VIRP_ERR_DUPLICATE_MISMATCH; /* refused pre-append */
    }
    return NULL;
}

TEST(test_chain_fed_id_conflict_check_is_inside_append_txn)
{
    pthread_barrier_t start, checked;
    ASSERT_EQ(pthread_barrier_init(&start, NULL, G5_THREADS), 0);
    ASSERT_EQ(pthread_barrier_init(&checked, NULL, G5_THREADS), 0);

    pthread_t th[G5_THREADS];
    g5lib_arg_t args[G5_THREADS];
    memset(args, 0, sizeof(args));
    for (int i = 0; i < G5_THREADS; i++) {
        args[i].tid = i;
        args[i].start = &start;
        args[i].checked = &checked;
        ASSERT_EQ(pthread_create(&th[i], NULL, g5lib_worker, &args[i]), 0);
    }

    int winners = 0, losers_wrong_code = 0;
    for (int i = 0; i < G5_THREADS; i++) {
        pthread_join(th[i], NULL);
        if (args[i].append_rc == VIRP_OK)
            winners++;
        else if (args[i].append_rc != VIRP_ERR_DUPLICATE_MISMATCH)
            losers_wrong_code++;
    }
    pthread_barrier_destroy(&start);
    pthread_barrier_destroy(&checked);

    ASSERT_EQ(winners, 1);
    ASSERT_EQ(losers_wrong_code, 0);
    ASSERT_EQ(ca_count_artifact_rows("g5lib-race-1"), 1);
    ASSERT_EQ(ca_count_entries("g5lib-race-1"), 1);
}

typedef struct {
    int round;
    int tid;
    pthread_barrier_t *barrier;
    int success;       /* append accepted */
    int wrong_error;   /* refused with anything but DUPLICATE_MISMATCH */
    int transport;
} g5_arg_t;

static void *g5_worker(void *p)
{
    g5_arg_t *a = (g5_arg_t *)p;

    char body[128];
    snprintf(body, sizeof(body),
             "{\"schema\":\"federated_request/1\",\"round\":%d,"
             "\"writer\":%d}", a->round, a->tid);
    char h[65];
    ca_sha256_hex(body, h);

    /* Escape the body into the request, same as ca_append(): an
     * unescaped quote makes the REQUEST malformed and the daemon
     * refuses the parse — the test would then pass without ever
     * reaching the gate under attack. */
    char esc[256];
    size_t o = 0;
    for (const char *p = body; *p && o + 2 < sizeof(esc); p++) {
        if (*p == '"' || *p == '\\') esc[o++] = '\\';
        esc[o++] = *p;
    }
    esc[o] = '\0';

    char json[768];
    snprintf(json, sizeof(json),
             "{\"action\":\"chain_append\",\"session_id\":\"g5race:%d\","
             "\"artifact_type\":\"fed_request\","
             "\"artifact_id\":\"g5race-r%03d\","
             "\"artifact_hash\":\"%s\",\"artifact_content\":\"%s\"}",
             a->round, a->round, h, esc);

    /* Connect first, THEN barrier, THEN send: the daemon's worker is
     * already blocked in its frame read, so the sends land as close to
     * simultaneously as the scheduler allows. */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { a->transport++; return NULL; }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", CA_SOCKET);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        a->transport++;
        pthread_barrier_wait(a->barrier);
        return NULL;
    }

    pthread_barrier_wait(a->barrier);

    size_t json_len = strlen(json);
    uint32_t frame_len = htonl((uint32_t)(1 + json_len));
    send(fd, &frame_len, 4, 0);
    uint8_t version = VIRP_FRAME_VERSION;
    send(fd, &version, 1, 0);
    send(fd, json, json_len, 0);

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    uint32_t net_rlen;
    if (recv(fd, &net_rlen, 4, 0) != 4) {
        close(fd);
        a->transport++;
        return NULL;
    }
    uint32_t rlen = ntohl(net_rlen);
    if (rlen > sizeof(resp)) { close(fd); a->transport++; return NULL; }
    size_t got = 0;
    while (got < rlen) {
        ssize_t n = recv(fd, resp + got, rlen - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
    }
    close(fd);

    if (got != rlen) {
        a->transport++;
    } else if (rlen > 4) {
        a->success = 1;
    } else if (typed_error_of(resp, (ssize_t)rlen)
               != (int32_t)VIRP_ERR_DUPLICATE_MISMATCH) {
        a->wrong_error = 1;
    }
    return NULL;
}

TEST(test_chain_append_concurrent_fed_id_conflict_is_atomic)
{
    for (int round = 0; round < G5_ROUNDS; round++) {
        pthread_barrier_t barrier;
        ASSERT_EQ(pthread_barrier_init(&barrier, NULL, G5_THREADS), 0);

        pthread_t th[G5_THREADS];
        g5_arg_t args[G5_THREADS];
        memset(args, 0, sizeof(args));
        for (int i = 0; i < G5_THREADS; i++) {
            args[i].round = round;
            args[i].tid = i;
            args[i].barrier = &barrier;
            ASSERT_EQ(pthread_create(&th[i], NULL, g5_worker, &args[i]), 0);
        }

        int successes = 0, wrong_error = 0, transport = 0;
        for (int i = 0; i < G5_THREADS; i++) {
            pthread_join(th[i], NULL);
            successes   += args[i].success;
            wrong_error += args[i].wrong_error;
            transport   += args[i].transport;
        }
        pthread_barrier_destroy(&barrier);

        char id[64];
        snprintf(id, sizeof(id), "g5race-r%03d", round);

        ASSERT_EQ(transport, 0);
        ASSERT_EQ(wrong_error, 0);
        /* ONE winner. All bodies differ, so a second success would have
         * stored a second row — the store itself is the ground truth. */
        ASSERT_EQ(successes, 1);
        ASSERT_EQ(ca_count_artifact_rows(id), 1);
        ASSERT_EQ(ca_count_entries(id), 1);
    }
}

/* =========================================================================
 * Item 8 (2026-08-11): per-uid action allowlist + list_fleet
 *
 * socket_uid_action_allow maps a SO_PEERCRED uid to the ONLY actions it
 * may request. A uid absent from the map is completely unchanged. A uid
 * present in the map is additionally type-narrowed on chain_append to
 * the three federation types. The tests set the map for the
 * test process's OWN uid (SO_PEERCRED on the test socket) to stand in
 * for the federated identity, then clear it.
 * ========================================================================= */

static int32_t typed_error_of(const uint8_t *resp, ssize_t n)
{
    if (n != 4) return 0;
    uint32_t v = ((uint32_t)resp[0] << 24) | ((uint32_t)resp[1] << 16) |
                 ((uint32_t)resp[2] << 8) | (uint32_t)resp[3];
    return (int32_t)v;
}

static const onode_action_t FED_ACTIONS[4] = {
    ONODE_ACTION_LIST_FLEET, ONODE_ACTION_HEALTH,
    ONODE_ACTION_CHAIN_VERIFY, ONODE_ACTION_CHAIN_APPEND,
};

/* M1 (2026-08-18): a failed second SO_PEERCRED read in the worker used to
 * yield (uid_t)-1, which is absent from socket_uid_action_allow and so
 * SKIPPED the per-uid map — the request then took the node-wide ceiling
 * and the full action switch. That was fail-OPEN relative to per-uid
 * controls. The uid is now threaded from accept (no second read) and an
 * unknown identity is REFUSED outright by onode_uid_request_refused().
 * A real getsockopt(SO_PEERCRED) failure cannot be forced on a connected
 * socket, so the regression drives the decision function directly. */
TEST(test_uid_request_refused_rejects_unknown_identity)
{
    onode_clear_uid_actions(&ca_state);
    /* A restricted principal (like virp-netclaw uid 993): federation
     * actions only. */
    ASSERT_OK(onode_set_uid_actions(&ca_state, 993, FED_ACTIONS, 4));

    /* THE FIX: unknown identity (uid == -1) is refused for ANY action,
     * never the node-wide fall-through. Pre-fix this returned false and the
     * request reached node-wide policy plus the whole action switch. */
    ASSERT_TRUE(onode_uid_request_refused(&ca_state, (uid_t)-1,
                                          ONODE_ACTION_EXECUTE));
    ASSERT_TRUE(onode_uid_request_refused(&ca_state, (uid_t)-1,
                                          ONODE_ACTION_SHUTDOWN));

    /* The restricted uid: a listed action is allowed, an unlisted one is
     * refused (unchanged behaviour, proves the map still applies). */
    ASSERT_TRUE(!onode_uid_request_refused(&ca_state, 993,
                                           ONODE_ACTION_HEALTH));   /* listed */
    ASSERT_TRUE(onode_uid_request_refused(&ca_state, 993,
                                          ONODE_ACTION_EXECUTE));   /* unlisted */

    /* A uid absent from the map is unrestricted — existing principals are
     * not newly restricted. */
    ASSERT_TRUE(!onode_uid_request_refused(&ca_state, 4242,
                                           ONODE_ACTION_EXECUTE));

    onode_clear_uid_actions(&ca_state);
}

TEST(test_uid_action_allowlist_blocks_unlisted_actions)
{
    ASSERT_OK(onode_set_uid_actions(&ca_state, getuid(), FED_ACTIONS, 4));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];

    /* shutdown → policy refusal, and the daemon STAYS UP */
    ssize_t n = ca_request("{\"action\": \"shutdown\"}", resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    n = ca_request("{\"action\": \"list_fleet\"}", resp, sizeof(resp));
    ASSERT_TRUE(n > 4);   /* alive — the refusal did not kill it */

    /* health is IN the allowed set: it must pass the policy gate and
     * reach its handler. This daemon has no devices, so the handler
     * answers with a SIGNED ERROR OBSERVATION (device not found) —
     * anything but the 4-byte policy refusal proves the gate admitted
     * the action. */
    n = ca_request("{\"action\": \"health\", \"device\": \"R5\"}",
                   resp, sizeof(resp));
    ASSERT_TRUE(n > 4);

    /* unlisted actions are refused with the same typed policy error */
    n = ca_request("{\"action\": \"execute\", \"device\": \"R5\","
                   " \"command\": \"show clock\"}", resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    n = ca_request("{\"action\": \"list_devices\"}", resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    n = ca_request("{\"action\": \"sign_intent\", \"command\":"
                   " \"0000000000000000000000000000000000000000000000000000000000000000\"}",
                   resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);

    /* the allowed set answers: list_fleet, chain_verify (health above).
     * chain_verify reaches its handler and returns a JSON verify result
     * — never the 4-byte policy refusal. */
    n = ca_request("{\"action\": \"list_fleet\"}", resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    n = ca_request("{\"action\": \"chain_verify\","
                   " \"session_id\": \"evidence:2026\"}", resp, sizeof(resp));
    ASSERT_TRUE(typed_error_of(resp, n) != (int32_t)VIRP_ERR_ACTION_FORBIDDEN);

    onode_clear_uid_actions(&ca_state);
}

TEST(test_uid_action_allowlist_narrows_chain_append_types)
{
    ASSERT_OK(onode_set_uid_actions(&ca_state, getuid(), FED_ACTIONS, 4));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];

    /* the federation provenance path stays open — all THREE appends.
     * fed_observation is in the restricted set as of 2026-08-16; while
     * it was not, this uid could file an outcome but not the body that
     * outcome cited, which is precisely the regression. */
    const char *req_body = "{\"schema\":\"federated_request/1\",\"peer\":\"netclaw\"}";
    char hr[65];
    ca_sha256_hex(req_body, hr);
    ssize_t n = ca_append("ncfed-item8-t1", "fed_request",
                          "item8-fed-req-1", hr, req_body, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("item8-fed-req-1"), 1);

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t olen = ca_mint_v1_obs(obs, sizeof(obs), 9103);
    ASSERT_TRUE(olen > 0);
    char hobs[65];   ca_sha256_hex_bin(obs, olen, hobs);
    char obs_body[2048]; ca_b64_body(obs, olen, obs_body, sizeof(obs_body));
    n = ca_append("ncfed-item8-t1", "fed_observation",
                  "item8-fed-obs-1", hobs, obs_body, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("item8-fed-obs-1"), 1);

    char out_body[512];
    snprintf(out_body, sizeof(out_body),
             "{\"schema\":\"federated_outcome/1\",\"outcome\":\"ok\","
             "\"observation_sha256\":\"%s\"}", hobs);
    char ho[65];
    ca_sha256_hex(out_body, ho);
    n = ca_append("ncfed-item8-t1", "fed_outcome",
                  "item8-fed-out-1", ho, out_body, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("item8-fed-out-1"), 1);

    /* any OTHER type from the restricted uid is refused — including the
     * commitment-only observation form that is legal for everyone else */
    char h[65];
    ca_sha256_hex("bytes the chain will not hold", h);
    n = ca_append("ncfed-item8-t1", "observation",
                  "item8-obs-refused-1", h, NULL, resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    ASSERT_EQ(ca_count_entries("item8-obs-refused-1"), 0);

    const char *evi = "{\"item\":\"pkg-list\",\"sha\":\"abc\"}";
    char he[65];
    ca_sha256_hex(evi, he);
    n = ca_append("evidence:item8", "evidence_item",
                  "item8-evi-refused-1", he, evi, resp, sizeof(resp));
    ASSERT_EQ((int)n, 4);
    ASSERT_EQ(typed_error_of(resp, n), (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    ASSERT_EQ(ca_count_entries("item8-evi-refused-1"), 0);

    onode_clear_uid_actions(&ca_state);

    /* map cleared → the same observation commitment lands again */
    n = ca_append("autopilot:item8", "observation",
                  "item8-obs-unrestricted-1", h, NULL, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("item8-obs-unrestricted-1"), 1);
}

TEST(test_uid_action_map_absent_uid_fully_unchanged)
{
    /* A DIFFERENT uid is mapped; ours is absent — nothing may change.
     * This is the assertion that the allowlist cannot silently lock
     * out an existing principal (operator, autopilot). */
    ASSERT_OK(onode_set_uid_actions(&ca_state, getuid() + 40001,
                                    FED_ACTIONS, 4));

    uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    /* health reaches its handler (device-not-found here, never the
     * policy refusal — this daemon has no devices) */
    ssize_t n = ca_request("{\"action\": \"health\", \"device\": \"R5\"}",
                           resp, sizeof(resp));
    ASSERT_TRUE(typed_error_of(resp, n) != (int32_t)VIRP_ERR_ACTION_FORBIDDEN);
    n = ca_request("{\"action\": \"list_devices\"}", resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    n = ca_request("{\"action\": \"sign_intent\", \"command\":"
                   " \"1111111111111111111111111111111111111111111111111111111111111111\"}",
                   resp, sizeof(resp));
    ASSERT_TRUE(n > 4);

    /* full chain_append reach retained, observation type included */
    char h[65];
    ca_sha256_hex("absent uid keeps full append reach", h);
    n = ca_append("autopilot:item8b", "observation",
                  "item8-absent-obs-1", h, NULL, resp, sizeof(resp));
    ASSERT_TRUE(n > 4);
    ASSERT_EQ(ca_count_entries("item8-absent-obs-1"), 1);

    onode_clear_uid_actions(&ca_state);
}

/* Shutdown for an absent uid must still work — proven on a dedicated
 * daemon instance whose map names only a foreign uid, so the socket
 * shutdown below exercises the exact absent-uid dispatch path. */
#define SD_SOCKET "/tmp/virp-onode-test-item8-sd.sock"

static onode_state_t sd_state;

static void *sd_thread(void *arg)
{
    (void)arg;
    onode_start(&sd_state);
    return NULL;
}

TEST(test_uid_action_map_foreign_uid_keeps_shutdown)
{
    unlink(SD_SOCKET);
    ASSERT_OK(onode_init(&sd_state, 0x00000043, NULL, SD_SOCKET));
    ASSERT_OK(onode_set_uid_actions(&sd_state, getuid() + 40001,
                                    FED_ACTIONS, 4));
    pthread_t th;
    ASSERT_EQ(pthread_create(&th, NULL, sd_thread, NULL), 0);
    usleep(200000);

    /* our (absent) uid asks for shutdown — must be honored */
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_TRUE(fd >= 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", SD_SOCKET);
    ASSERT_EQ(connect(fd, (struct sockaddr *)&addr, sizeof(addr)), 0);
    const char *json = "{\"action\": \"shutdown\"}";
    uint32_t fl = htonl((uint32_t)(1 + strlen(json)));
    send(fd, &fl, 4, 0);
    uint8_t ver = VIRP_FRAME_VERSION;
    send(fd, &ver, 1, 0);
    send(fd, json, strlen(json), 0);
    usleep(200000);
    close(fd);

    /* The accept loop re-checks `running` on select() activity or the
     * 30 s heartbeat tick — poke it with one throwaway connection so
     * the test does not wait out a heartbeat interval. */
    int poke = socket(AF_UNIX, SOCK_STREAM, 0);
    if (poke >= 0) {
        (void)connect(poke, (struct sockaddr *)&addr, sizeof(addr));
        close(poke);
    }

    struct timespec dl;
    clock_gettime(CLOCK_REALTIME, &dl);
    dl.tv_sec += 15;
    ASSERT_EQ(pthread_timedjoin_np(th, NULL, &dl), 0);  /* it shut down */
    onode_destroy(&sd_state);
    unlink(SD_SOCKET);
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
    RUN_TEST(test_load_devices_refuses_absent_node_id);
    RUN_TEST(test_load_devices_skips_missing_required_fields);
    RUN_TEST(test_load_devices_refuses_asa_without_enable);
    RUN_TEST(test_add_device_rejects_duplicate_identities);
    RUN_TEST(test_load_devices_duplicate_identities_fatal);

    printf("\n[Autopilot hard exclusions (10.0.10.1 / 10.0.10.10)]\n");
    RUN_TEST(test_blocked_address_text_scan);
    RUN_TEST(test_load_devices_refuses_blocked_address);
    RUN_TEST(test_load_devices_allows_neighbor_addresses);

    printf("\n[Gate-reason retention (chain body recoverable)]\n");
    RUN_TEST(test_gate_rejection_reason_body_is_retained_and_matches_commitment);
    RUN_TEST(test_gate_rejection_records_per_uid_effective_ceiling);

    printf("\n[GREEN auto-execution records (chain covers what was allowed)]\n");
    RUN_TEST(test_declared_refusal_with_body_routes_to_error);
    /* PENDING until the /2 three-valued work. Steps 1-2 fixed the five
     * production drivers, which now DECLARE non-dispatch; these two drive
     * a mock that deliberately reproduces the pre-step-2 shape (refusal
     * with a body, no declaration) to hold the O-Node itself to account.
     * It still records that shape as executed. No shipping driver emits
     * it — driver twelve will. */
    PENDING_TEST(test_refusal_with_body_is_not_an_execution,
                 "gate_execution/2 three-valued executed (EXECUTED / REFUSED / UNKNOWN): an undeclared !success result must resolve to UNKNOWN, never EXECUTED, and must not be signed as DEVICE_OUTPUT");
    PENDING_TEST(test_refusal_with_body_is_not_recorded_executed,
                 "gate_execution/2 three-valued executed (EXECUTED / REFUSED / UNKNOWN): an undeclared !success result must resolve to UNKNOWN, never EXECUTED, and must not be signed as DEVICE_OUTPUT");
    RUN_TEST(test_green_execution_chains_signed_observation);
    RUN_TEST(test_execution_record_commits_to_digest_not_response_body);
    RUN_TEST(test_errored_execution_still_chains_no_gap);
    RUN_TEST(test_refused_action_still_chains_gate_rejection);
    RUN_TEST(test_chain_verify_over_mixed_executions_and_rejections);

    printf("\n  -- Scrub-at-capture (S-1) gates G1-G4 --\n");
    RUN_TEST(test_scrub_G1_clean_capture_verifies);
    RUN_TEST(test_scrub_G2_planted_secrets_redacted_and_verifies);
    RUN_TEST(test_scrub_G3_fail_closed_full_redaction);
    RUN_TEST(test_scrub_G4_existing_entries_untouched);

    printf("\n[BLACK unconditional (inexpressible in every mode)]\n");
    RUN_TEST(test_black_enforce_refused_at_gate);
    RUN_TEST(test_shadow_black_refused_recorded_driver_never_invoked);
    RUN_TEST(test_shadow_yellow_red_still_proceed_and_are_recorded);

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
    RUN_TEST(test_over_tier_enforce_refused_without_connecting);

    printf("\n[Multi-Command Gate Bypass (layer 1)]\n");
    RUN_TEST(test_separator_policy_accepts_single_commands);
    RUN_TEST(test_separator_policy_rejects_every_class);
    RUN_TEST(test_separator_policy_escapes_control_bytes_in_reason);
    RUN_TEST(test_multicommand_newline_is_blocked);
    RUN_TEST(test_multicommand_newline_is_blocked_batch);
    RUN_TEST(test_multicommand_batch_rejects_per_item_not_whole_batch);
    RUN_TEST(test_shadow_default_mode_still_refuses_separator_command);
    RUN_TEST(test_shadow_driver_override_still_refuses_separator_command);
    RUN_TEST(test_execute_v2_without_session_fails);
    RUN_TEST(test_execute_v2_session_bound_roundtrip);
    RUN_TEST(test_execute_show_bgp_summary);
    RUN_TEST(test_execute_different_devices);
    RUN_TEST(test_device_not_found);
    RUN_TEST(test_heartbeat);
    RUN_TEST(test_list_devices);
    RUN_TEST(test_list_fleet_names_class_and_status_only);
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
    RUN_TEST(test_send_all_survives_partial_writes_and_eintr);
    RUN_TEST(test_send_all_reports_dead_peer);
    RUN_TEST(test_send_framed_short_write_no_desync);

    printf("\n[Worker Pool / Concurrency Tests]\n");
    RUN_TEST(test_concurrent_clients_no_head_of_line);

    printf("\n[SIGPIPE Close-Before-Read Tests]\n");
    RUN_TEST(test_close_before_read_does_not_kill_daemon);
    RUN_TEST(test_v1_reject_close_before_read_does_not_kill_daemon);
    RUN_TEST(test_close_before_read_800_call_storm);

    printf("\n[Signed Error Observation Tests]\n");
    RUN_TEST(test_driver_error_returns_signed_observation);
    RUN_TEST(test_error_obs_connect_failure_is_error_with_true_tier);
    RUN_TEST(test_error_obs_driver_refusal_is_error_not_output);
    RUN_TEST(test_unprovable_dispatch_unknown_not_retried);
    RUN_TEST(test_provable_no_dispatch_retry_retained);
    RUN_TEST(test_error_obs_gate_block_logs_as_error_not_change);
    RUN_TEST(test_per_uid_ceiling_caps_yellow_but_not_uncapped);

    printf("\n--- Watchdog / execute serialization (finding N3) ---\n");
    RUN_TEST(test_watchdog_health_check_serialized_with_execute);

    printf("\n[SO_PEERCRED Allowlist Tests]\n");
    RUN_TEST(test_peer_uid_allowed);
    RUN_TEST(test_peer_uid_rejected);

    printf("\n  -- Audit 2026-08-06: CHAIN_APPEND artifact forgery --\n");
    if (ca_start() == 0) {
        RUN_TEST(test_chain_append_rejects_body_hash_mismatch);
        RUN_TEST(test_chain_append_rejects_reserved_type_outcome);
        RUN_TEST(test_chain_append_rejects_reserved_type_approval);
        RUN_TEST(test_chain_append_rejects_invented_type);
        RUN_TEST(test_chain_append_accepts_signed_v1_observation);
        RUN_TEST(test_chain_append_rejects_unsigned_observation_body);
        RUN_TEST(test_chain_append_rejects_tampered_v1_observation);
        RUN_TEST(test_chain_append_rejects_unknown_obs_version);
        RUN_TEST(test_chain_append_rejects_v3_without_obskey);
        RUN_TEST(test_chain_append_accepts_signed_v3_observation);
        RUN_TEST(test_chain_append_rejects_v2_without_active_session);
        RUN_TEST(test_chain_append_commitment_only_observation_accepted);
        RUN_TEST(test_chain_append_commitment_only_empty_body_accepted);
        RUN_TEST(test_chain_append_accepts_comparator_verdict);
        RUN_TEST(test_chain_append_accepts_chainwalk_summary);
        RUN_TEST(test_chain_append_version_confusion_all_arms);
        RUN_TEST(test_chain_append_binds_the_signature_region_too);
        RUN_TEST(test_rotation_grace_window_saves_in_flight_observation);
        RUN_TEST(test_rotation_grace_window_expires);
        RUN_TEST(test_rotation_grace_window_does_not_accept_a_third_key);
        RUN_TEST(test_previous_okey_loader_refuses_bad_configurations);
        RUN_TEST(test_previous_okey_window_anchors_to_load_time_and_resets);
        RUN_TEST(test_chain_append_still_accepts_json_evidence_item);
        RUN_TEST(test_chain_append_accepts_federated_provenance);
        RUN_TEST(test_chain_append_refuses_fed_outcome_citing_unstored_observation);
        RUN_TEST(test_chain_append_accepts_fed_outcome_for_commitment_only_observation);
        RUN_TEST(test_chain_append_refuses_fed_outcome_without_observation_hash);
        RUN_TEST(test_chain_append_fed_observation_must_be_signed);
        RUN_TEST(test_chain_append_refuses_fed_retry_with_different_bytes);
        RUN_TEST(test_chain_append_refuses_fed_outcome_retry_with_different_bytes);
        RUN_TEST(test_chain_append_accepts_byte_identical_fed_retry);
        RUN_TEST(test_chain_append_non_fed_colliding_id_still_stores_both);
        RUN_TEST(test_chain_append_refuses_commitment_only_fed_retry_with_different_bytes);
        RUN_TEST(test_chain_append_concurrent_commitment_only_fed_conflict_is_atomic);
        RUN_TEST(test_chain_append_accepts_commitment_only_byte_identical_fed_retry);
        RUN_TEST(test_chain_append_non_fed_commitment_only_colliding_id_stores_both);
        RUN_TEST(test_chain_append_still_refuses_reserved_outcome_type);
        RUN_TEST(test_chain_append_accepts_commitment_without_body);

        printf("\n  -- Concurrency regressions (external review 2026-08-17) --\n");
        RUN_TEST(test_chain_append_concurrent_verify_uses_own_bytes);
        RUN_TEST(test_chain_fed_id_conflict_check_is_inside_append_txn);
        RUN_TEST(test_chain_append_concurrent_fed_id_conflict_is_atomic);

        printf("\n  -- Item 8: per-uid action allowlist --\n");
        RUN_TEST(test_uid_request_refused_rejects_unknown_identity);
        RUN_TEST(test_uid_action_allowlist_blocks_unlisted_actions);
        RUN_TEST(test_uid_action_allowlist_narrows_chain_append_types);
        RUN_TEST(test_uid_action_map_absent_uid_fully_unchanged);
        RUN_TEST(test_uid_action_map_foreign_uid_keeps_shutdown);
        ca_stop();
        ca_cleanup_files();
    } else {
        printf("  *** chain-enabled test daemon failed to start\n");
        tests_run++; tests_failed++;
    }

    printf("\n  -- Audit §4.1: sign_intent/sign_outcome signing oracle --\n");
    RUN_TEST(test_sign_intent_predicate);
    RUN_TEST(test_sign_intent_rejects_oversized);
    RUN_TEST(test_sign_intent_rejects_non_hex);
    RUN_TEST(test_sign_intent_accepts_valid_digest);
    RUN_TEST(test_sign_outcome_rejects_oversized);
    RUN_TEST(test_sign_outcome_accepts_valid_digest);

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
    if (tests_pending > 0)
        printf("  (%d PENDING)", tests_pending);
    printf("\n");

    /* A pending test must never let this read as a clean run. The word
     * "PENDING" is on the results line above, and the suite says plainly
     * that it is not clean rather than leaving a reader to notice a
     * count. */
    if (tests_pending > 0) {
        printf("\n  ****  SUITE IS NOT CLEAN: %d PENDING test(s)  ****\n",
               tests_pending);
        printf("  Known-failing by design. They are NOT counted as passes\n");
        printf("  and they are NOT skipped — they ran and they failed.\n");
        printf("  Each names its acceptance criterion above.\n");
    }
    if (pending_unexpected_pass > 0) {
        printf("\n  ****  %d PENDING test(s) UNEXPECTEDLY PASSED  ****\n",
               pending_unexpected_pass);
        printf("  Remove the marker in the commit that satisfied it.\n");
    }
    printf("================================================================\n\n");

    return (tests_failed > 0) ? 1 : 0;
}
