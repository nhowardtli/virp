/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — evidence-required outcome-append failure (LAB-ONLY, fault-injected)
 *
 * Sep 1 review, Phase 1 item 3 / 1.3. The one durability window the
 * pre-execution intent cannot close is BETWEEN the two chain appends,
 * across the device I/O: the intent commits, the device acts, and then the
 * closer append (gate_execution) fails. This test injects exactly that —
 * evidence_fail_closer_once, a field that exists ONLY under
 * -DVIRP_FAULT_INJECT, the same discipline as the VIRP_FI() crash points
 * (include/virp_fault_inject.h) — and asserts the required behaviour:
 *
 *   - the caller receives a signed ERROR citing unchained-execution and
 *     the open intent (never a silent DEVICE_OUTPUT),
 *   - the daemon latches evidence-degraded and refuses the NEXT dispatch
 *     at the intent step (nothing reaches the device),
 *   - the session still VERIFIES and reports exactly one OPEN execution
 *     (the closer that never landed) alongside the one that closed.
 *
 * Built only by `make test-evidence-fi` against build-fi/libvirp.a. The
 * production binary has neither the field nor the check.
 *
 * RED PROOF: delete the `if (state->evidence_required && intent && xerr...)`
 * marker return in src/virp_onode.c and this test FAILS at the obs_type
 * assertion (the caller gets DEVICE_OUTPUT). Restore it; passes.
 */
#define _POSIX_C_SOURCE 200809L

#include "virp_onode.h"
#include "virp_chain.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

static const char *DB  = "/tmp/virp-evfi-chain.db";
static const char *WAL = "/tmp/virp-evfi-chain.db-wal";
static const char *SHM = "/tmp/virp-evfi-chain.db-shm";
static const char *KEY = "/tmp/virp-evfi-chain.key";
static const char *SESSION = "gate-enforce:EVFI-DEV";

static int failures;
#define CHECK(cond, msg) do {                                          \
    if (!(cond)) { printf("    FAIL: %s\n", (msg)); failures++; }       \
} while (0)

static void cleanup(void) { unlink(DB); unlink(WAL); unlink(SHM); unlink(KEY); }

/* Parse the observation type + payload out of a signed message buffer. */
static int obs_of(onode_state_t *st, const uint8_t *buf, size_t len,
                  uint8_t *type, char *payload, size_t pcap)
{
    virp_header_t hdr;
    if (virp_validate_message(buf, len, &st->okey, &hdr) != VIRP_OK) return -1;
    virp_observation_t o; const uint8_t *data; uint16_t dl;
    if (virp_parse_observation(buf + VIRP_HEADER_SIZE, len - VIRP_HEADER_SIZE,
                               &o, &data, &dl) != VIRP_OK) return -1;
    *type = o.obs_type;
    size_t n = dl < pcap - 1 ? dl : pcap - 1;
    memcpy(payload, data, n); payload[n] = '\0';
    return 0;
}

int main(void)
{
    printf("\n=== VIRP evidence-required outcome-fail (FI) ===\n");
    cleanup();
    virp_driver_mock_init();

    onode_state_t st;
    if (onode_init(&st, 0xE71F0001, NULL, "/tmp/virp-evfi.sock") != VIRP_OK) {
        printf("    FAIL: onode_init\n"); return 1;
    }
    st.ctx = virp_context_new();
    virp_signing_key_t ck;
    virp_key_generate(&ck, VIRP_KEY_TYPE_CHAIN);
    virp_key_save_file(&ck, KEY);
    virp_key_destroy(&ck);
    if (virp_chain_init(&st.chain, DB, KEY, 0xE71F0001, "local") != VIRP_OK) {
        printf("    FAIL: chain_init\n"); return 1;
    }
    st.chain_enabled = true;
    st.evidence_required = true;
    st.gate_max_tier = VIRP_TIER_GREEN;

    virp_device_t dev;
    memset(&dev, 0, sizeof(dev));
    snprintf(dev.hostname, sizeof(dev.hostname), "EVFI-DEV");
    snprintf(dev.host, sizeof(dev.host), "10.255.7.7");
    dev.port = 22; dev.vendor = VIRP_VENDOR_MOCK;
    dev.node_id = 0x0EF10001; dev.enabled = true;
    if (onode_add_device(&st, &dev) != VIRP_OK) {
        printf("    FAIL: add_device\n"); return 1;
    }

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE]; size_t len = 0;
    uint8_t type; char payload[600];

    /* 1. One clean execution: a normal intent+closer pair. */
    (void)virp_driver_mock_exec_attempts_reset();
    onode_execute(&st, "EVFI-DEV", "show version", buf, sizeof(buf), &len);

    /* 2. Arm the closer-append fault. The intent commits, the device runs,
     * the gate_execution append fails. */
    pthread_mutex_lock(&st.state_mutex);
    st.evidence_fail_closer_once = true;
    pthread_mutex_unlock(&st.state_mutex);
    (void)virp_driver_mock_exec_attempts_reset();
    onode_execute(&st, "EVFI-DEV", "show version", buf, sizeof(buf), &len);
    int ran = virp_driver_mock_exec_attempts_reset();
    CHECK(ran == 1, "the device DID act (execute attempted)");
    CHECK(obs_of(&st, buf, len, &type, payload, sizeof(payload)) == 0, "parse");
    CHECK(type == VIRP_OBS_ERROR, "caller gets ERROR, not DEVICE_OUTPUT");
    CHECK(strstr(payload, "unchained-execution") != NULL,
          "payload cites unchained-execution");
    CHECK(strstr(payload, "evidence-degraded") != NULL,
          "payload says the daemon is now degraded");

    /* 3. Degraded: the next dispatch refuses at the intent step. */
    CHECK(st.evidence_degraded, "daemon latched degraded");
    (void)virp_driver_mock_exec_attempts_reset();
    onode_execute(&st, "EVFI-DEV", "show version", buf, sizeof(buf), &len);
    int ran2 = virp_driver_mock_exec_attempts_reset();
    CHECK(ran2 == 0, "nothing dispatched while degraded");
    CHECK(obs_of(&st, buf, len, &type, payload, sizeof(payload)) == 0, "parse2");
    CHECK(type == VIRP_OBS_ERROR, "degraded dispatch refused with ERROR");
    CHECK(strstr(payload, "evidence-unavailable") != NULL,
          "degraded refusal cites evidence-unavailable");

    /* 4. The session verifies; one OPEN (the lost closer) + one CLOSED. */
    virp_chain_verify_result_t vr;
    memset(&vr, 0, sizeof(vr));
    virp_chain_verify_session(&st.chain, SESSION, &vr);
    CHECK(vr.valid, "session VALID — not a broken chain");
    CHECK(vr.first_broken == -1, "no broken link");
    CHECK(vr.executions_open == 1, "one open execution (lost closer)");
    CHECK(vr.executions_closed == 1, "one closed execution");

    virp_context_t *ctx = st.ctx;
    onode_destroy(&st);
    virp_context_destroy(ctx);
    cleanup();

    if (failures == 0) { printf("=== Results: all FI checks passed ===\n"); return 0; }
    printf("=== Results: %d FI checks FAILED ===\n", failures);
    return 1;
}
