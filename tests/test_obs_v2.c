/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — v2 observation signing/verification negative tests
 *
 * These are the tests that convert the review's ASSERTED security
 * properties into DEMONSTRATED ones. Every claim has its negative:
 *
 *   C5  replay        → VIRP_ERR_REPLAY_DETECTED
 *   C6  staleness     → VIRP_ERR_STALE_OBSERVATION (mocked clock)
 *   C7  substitution  → command_hash / device_id mismatch rejection
 *   C8  session bind  → cross-session replay rejection
 *   C16 wire format   → explicit serialization, no struct padding
 *
 * The verifier clock is injected via the now_ns parameter of
 * virp_verify_observation_v2(), so staleness is tested without
 * touching the system clock.
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_session.h"
#include "virp_context.h"
#include "virp_handshake.h"
#include "virp_transcript.h"
#include "virp_seqstore.h"

static const uint8_t test_master_key[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
};

#define TEST_NODE_ID    0x0A0000D3ULL
#define TEST_DEVICE_ID  0x1122334455667788ULL
#define OTHER_DEVICE_ID 0x8877665544332211ULL
#define SEQSTORE_FILE   "/tmp/virp-test-seqstore.txt"

/* Drive a context through HELLO → BIND → derive → ACTIVE. */
static void activate_session(virp_context_t *ctx, uint8_t nonce_byte)
{
    virp_session_hello_t h;
    memset(&h, 0, sizeof(h));
    h.msg_type = VIRP_MSG_SESSION_HELLO;
    memcpy(h.client_id, "obs-v2-test", 11);
    h.versions[0] = 2; h.versions[1] = 1; h.version_count = 2;
    h.algorithms[0] = VIRP_ALG_HMAC_SHA256; h.algorithm_count = 1;
    memset(h.client_nonce, nonce_byte, 8);

    virp_session_hello_ack_t ack;
    assert(virp_handle_hello(ctx, &h, &ack) == VIRP_OK);

    virp_session_bind_t bind;
    memset(&bind, 0, sizeof(bind));
    bind.msg_type = VIRP_MSG_SESSION_BIND;
    memcpy(bind.session_id,   ack.session_id,   16);
    memcpy(bind.client_nonce, ack.client_nonce,  8);
    memcpy(bind.server_nonce, ack.server_nonce,  8);
    assert(virp_handle_session_bind(ctx, &bind) == VIRP_OK);
    assert(virp_session_derive_key(ctx, test_master_key) == VIRP_OK);
    assert(virp_session_state(ctx) == VIRP_SESSION_ACTIVE);
}

/* Build a signed v2 wire message for `command` on TEST_DEVICE_ID. */
static size_t build_obs(virp_context_t *ctx, uint64_t seq,
                        const char *command, uint8_t *buf, size_t buf_len)
{
    static const uint8_t payload[] = "interface Gi0/1 is up";
    size_t out_len = 0;
    virp_error_t err = virp_build_observation_v2(
        ctx, TEST_NODE_ID, TEST_DEVICE_ID, VIRP_TIER_GREEN, seq, command,
        payload, sizeof(payload) - 1, buf, buf_len, &out_len);
    assert(err == VIRP_OK);
    return out_len;
}

/* ── C16: wire format ──────────────────────────────────────────────── */

static void test_serialization_roundtrip_and_layout(void)
{
    printf("  test_serialization_roundtrip_and_layout... ");

    virp_obs_header_v2_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version      = VIRP_VERSION_2;
    hdr.channel      = VIRP_CHANNEL_OBS;
    hdr.tier         = VIRP_TIER_YELLOW;
    hdr.node_id      = 0x0102030405060708ULL;
    hdr.timestamp_ns = 0x1112131415161718ULL;
    hdr.seq_num      = 0x2122232425262728ULL;
    memset(hdr.session_id, 0xAB, 16);
    hdr.device_id    = 0x3132333435363738ULL;
    memset(hdr.command_hash, 0xCD, 32);
    hdr.payload_len  = 0x41424344;

    uint8_t buf[VIRP_OBS_V2_HEADER_SIZE];
    assert(virp_obs_header_v2_serialize(&hdr, buf, sizeof(buf)) == VIRP_OK);

    /* Golden offsets: the wire layout is fixed and big-endian,
     * independent of the in-memory struct's padding. */
    assert(buf[0] == VIRP_VERSION_2);
    assert(buf[1] == VIRP_CHANNEL_OBS);
    assert(buf[2] == VIRP_TIER_YELLOW);
    assert(buf[3] == 0x00);
    assert(buf[4] == 0x01 && buf[11] == 0x08);   /* node_id BE */
    assert(buf[12] == 0x11 && buf[19] == 0x18);  /* timestamp BE */
    assert(buf[20] == 0x21 && buf[27] == 0x28);  /* seq BE */
    assert(buf[28] == 0xAB && buf[43] == 0xAB);  /* session_id */
    assert(buf[44] == 0x31 && buf[51] == 0x38);  /* device_id BE */
    assert(buf[52] == 0xCD && buf[83] == 0xCD);  /* command_hash */
    assert(buf[84] == 0x41 && buf[87] == 0x44);  /* payload_len BE */

    virp_obs_header_v2_t back;
    assert(virp_obs_header_v2_deserialize(&back, buf, sizeof(buf)) == VIRP_OK);
    assert(back.version == hdr.version);
    assert(back.node_id == hdr.node_id);
    assert(back.timestamp_ns == hdr.timestamp_ns);
    assert(back.seq_num == hdr.seq_num);
    assert(memcmp(back.session_id, hdr.session_id, 16) == 0);
    assert(back.device_id == hdr.device_id);
    assert(memcmp(back.command_hash, hdr.command_hash, 32) == 0);
    assert(back.payload_len == hdr.payload_len);

    /* Nonzero reserved must not serialize */
    hdr._reserved = 1;
    assert(virp_obs_header_v2_serialize(&hdr, buf, sizeof(buf)) ==
           VIRP_ERR_RESERVED_NONZERO);

    printf("PASS\n");
}

/* ── happy path baseline (a negative test means nothing if the
 *    positive path doesn't work) ─────────────────────────────────── */

static void test_verify_accepts_valid_observation(void)
{
    printf("  test_verify_accepts_valid_observation... ");
    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xA1);

    uint8_t msg[1024];
    size_t n = build_obs(ctx, 1, "show ip route", msg, sizeof(msg));

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);

    virp_obs_header_v2_t hdr;
    const uint8_t *payload;
    uint32_t payload_len;
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show ip route",
                                      msg, n, 0, &store,
                                      &hdr, &payload, &payload_len) == VIRP_OK);
    assert(payload_len == strlen("interface Gi0/1 is up"));
    assert(memcmp(payload, "interface Gi0/1 is up", payload_len) == 0);

    /* command canonicalization: extra whitespace must not break the
     * binding — same canonical form, same hash */
    size_t n2 = build_obs(ctx, 2, "show   ip   route", msg, sizeof(msg));
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "  show ip route ",
                                      msg, n2, 0, &store,
                                      NULL, NULL, NULL) == VIRP_OK);

    virp_seqstore_destroy(&store);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

/* ── C5: replay ────────────────────────────────────────────────────── */

static void test_replay_same_sequence_rejected(void)
{
    printf("  test_replay_same_sequence_rejected... ");
    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xA2);

    uint8_t msg[1024];
    size_t n = build_obs(ctx, 7, "show version", msg, sizeof(msg));

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);

    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) == VIRP_OK);

    /* Capture-and-replay: byte-identical message, same sequence */
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_REPLAY_DETECTED);

    virp_seqstore_destroy(&store);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_non_monotonic_sequence_rejected(void)
{
    printf("  test_non_monotonic_sequence_rejected... ");
    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xA3);

    uint8_t msg5[1024], msg4[1024];
    size_t n5 = build_obs(ctx, 5, "show version", msg5, sizeof(msg5));
    size_t n4 = build_obs(ctx, 4, "show version", msg4, sizeof(msg4));

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);

    /* seq 5 accepted; a validly-signed but older seq 4 must then be
     * rejected — high-water, not set-membership */
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg5, n5, 0, &store,
                                      NULL, NULL, NULL) == VIRP_OK);
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg4, n4, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_REPLAY_DETECTED);

    virp_seqstore_destroy(&store);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_replay_rejected_across_store_restart(void)
{
    printf("  test_replay_rejected_across_store_restart... ");
    unlink(SEQSTORE_FILE);

    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xA4);

    uint8_t msg[1024];
    size_t n = build_obs(ctx, 9, "show version", msg, sizeof(msg));

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, SEQSTORE_FILE) == VIRP_OK);
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) == VIRP_OK);
    virp_seqstore_destroy(&store);

    /* Simulated verifier restart: fresh store object, same state file.
     * The replayed capture must STILL be rejected. */
    virp_seqstore_t store2;
    assert(virp_seqstore_init(&store2, SEQSTORE_FILE) == VIRP_OK);
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store2,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_REPLAY_DETECTED);

    virp_seqstore_destroy(&store2);
    virp_context_destroy(ctx);
    unlink(SEQSTORE_FILE);
    printf("PASS\n");
}

/* ── C6: staleness (mocked verifier clock) ─────────────────────────── */

static void test_stale_observation_rejected(void)
{
    printf("  test_stale_observation_rejected... ");
    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xA5);

    uint8_t msg[1024];
    size_t n = build_obs(ctx, 1, "show version", msg, sizeof(msg));

    /* Recover the signed timestamp so the mock clock is relative to it */
    virp_obs_header_v2_t hdr;
    assert(virp_obs_header_v2_deserialize(&hdr, msg, n) == VIRP_OK);

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);

    /* Just inside the window: accepted */
    uint64_t now_ok = hdr.timestamp_ns + VIRP_OBS_V2_FRESHNESS_WINDOW_NS - 1;
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, now_ok, &store,
                                      NULL, NULL, NULL) == VIRP_OK);

    /* Past the window: stale. (Fresh store — replay must not mask it.) */
    virp_seqstore_t store2;
    assert(virp_seqstore_init(&store2, NULL) == VIRP_OK);
    uint64_t now_late = hdr.timestamp_ns + VIRP_OBS_V2_FRESHNESS_WINDOW_NS + 1;
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, now_late, &store2,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_STALE_OBSERVATION);

    /* Timestamp far in the verifier's FUTURE is equally invalid */
    uint64_t now_early = hdr.timestamp_ns - VIRP_OBS_V2_FRESHNESS_WINDOW_NS - 1;
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, now_early, &store2,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_STALE_OBSERVATION);

    /* Staleness is judged on the SIGNED timestamp: tampering the header
     * timestamp to look fresh breaks the HMAC instead */
    uint8_t tampered[1024];
    memcpy(tampered, msg, n);
    uint64_t fake_ts = now_late;  /* pretend it was signed "now" */
    uint8_t be[8];
    for (int i = 0; i < 8; i++) be[i] = (uint8_t)(fake_ts >> (56 - 8 * i));
    memcpy(tampered + 12, be, 8);
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      tampered, n, now_late, &store2,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_HMAC_FAILED);

    virp_seqstore_destroy(&store);
    virp_seqstore_destroy(&store2);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

/* ── C7: substitution ──────────────────────────────────────────────── */

static void test_command_substitution_rejected(void)
{
    printf("  test_command_substitution_rejected... ");
    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xA6);

    /* O-Node validly signs an observation for command B... */
    uint8_t msg[1024];
    size_t n = build_obs(ctx, 1, "show clock", msg, sizeof(msg));

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);

    /* ...but the requester asked for command A. Reject. */
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID,
                                      "show running-config",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_CONTEXT_MISMATCH);

    virp_seqstore_destroy(&store);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_device_substitution_rejected(void)
{
    printf("  test_device_substitution_rejected... ");
    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xA7);

    /* Validly signed observation from device A, request targeted B */
    uint8_t msg[1024];
    size_t n = build_obs(ctx, 1, "show version", msg, sizeof(msg));

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);

    assert(virp_verify_observation_v2(ctx, OTHER_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_CONTEXT_MISMATCH);

    virp_seqstore_destroy(&store);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

/* ── C8: session binding ───────────────────────────────────────────── */

static void test_cross_session_replay_rejected(void)
{
    printf("  test_cross_session_replay_rejected... ");

    /* Sign in session S1 */
    virp_context_t *s1 = virp_context_new();
    virp_session_init(s1, "onode-test");
    activate_session(s1, 0xB1);
    uint8_t msg[1024];
    size_t n = build_obs(s1, 1, "show version", msg, sizeof(msg));

    /* Replay into S2: different transcript → different HKDF key, so
     * the signature itself must already fail */
    virp_context_t *s2 = virp_context_new();
    virp_session_init(s2, "onode-test");
    activate_session(s2, 0xB2);

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);
    assert(virp_verify_observation_v2(s2, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_HMAC_FAILED);

    /*
     * Defense in depth: even under a hypothetical key collision the
     * session_id binding must reject. Simulate by giving S1's context a
     * different active session_id while keeping the key that signed the
     * message — the HMAC then passes and the session_id check must be
     * the one that rejects.
     */
    uint8_t saved_sid[16];
    memcpy(saved_sid, s1->session.session_id, 16);
    s1->session.session_id[0] ^= 0xFF;
    assert(virp_verify_observation_v2(s1, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_SESSION_INVALID);
    memcpy(s1->session.session_id, saved_sid, 16);

    virp_seqstore_destroy(&store);
    virp_context_destroy(s1);
    virp_context_destroy(s2);
    printf("PASS\n");
}

/* ── forgery + tamper ──────────────────────────────────────────────── */

static void test_master_key_signature_rejected(void)
{
    printf("  test_master_key_signature_rejected... ");
    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xC1);

    uint8_t msg[1024];
    size_t n = build_obs(ctx, 1, "show version", msg, sizeof(msg));

    /* Re-sign the same bytes with the MASTER key instead of the session
     * key — a v1-style signer must not be able to mint v2 observations */
    virp_hmac_sha256(test_master_key, msg, n - VIRP_OBS_V2_SIG_SIZE,
                     msg + (n - VIRP_OBS_V2_SIG_SIZE));

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_HMAC_FAILED);

    virp_seqstore_destroy(&store);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_payload_tamper_rejected(void)
{
    printf("  test_payload_tamper_rejected... ");
    virp_context_t *ctx = virp_context_new();
    virp_session_init(ctx, "onode-test");
    activate_session(ctx, 0xC2);

    uint8_t msg[1024];
    size_t n = build_obs(ctx, 1, "show version", msg, sizeof(msg));

    msg[VIRP_OBS_V2_HEADER_SIZE] ^= 0x01;    /* flip one payload bit */

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);
    assert(virp_verify_observation_v2(ctx, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_HMAC_FAILED);

    virp_seqstore_destroy(&store);
    virp_context_destroy(ctx);
    printf("PASS\n");
}

static void test_verify_requires_active_session(void)
{
    printf("  test_verify_requires_active_session... ");
    virp_context_t *signer = virp_context_new();
    virp_session_init(signer, "onode-test");
    activate_session(signer, 0xC3);

    uint8_t msg[1024];
    size_t n = build_obs(signer, 1, "show version", msg, sizeof(msg));

    /* Verifier context with no session */
    virp_context_t *cold = virp_context_new();
    virp_session_init(cold, "onode-test");

    virp_seqstore_t store;
    assert(virp_seqstore_init(&store, NULL) == VIRP_OK);
    assert(virp_verify_observation_v2(cold, TEST_DEVICE_ID, "show version",
                                      msg, n, 0, &store,
                                      NULL, NULL, NULL) ==
           VIRP_ERR_SESSION_INVALID);

    virp_seqstore_destroy(&store);
    virp_context_destroy(signer);
    virp_context_destroy(cold);
    printf("PASS\n");
}

/* ── seqstore hardening ────────────────────────────────────────────── */

static void test_seqstore_eviction_never_hits_own_session(void)
{
    printf("  test_seqstore_eviction_never_hits_own_session... ");
    virp_seqstore_t st;
    assert(virp_seqstore_init(&st, NULL) == VIRP_OK);

    uint8_t live_sid[16], dead_sid[16];
    memset(live_sid, 0x11, 16);
    memset(dead_sid, 0x22, 16);

    /* One dead-session mark, then fill the rest with the live session */
    assert(virp_seqstore_accept(&st, dead_sid, 9999, 1) == VIRP_OK);
    for (uint64_t n = 0; n < VIRP_SEQSTORE_MAX_ENTRIES - 1; n++)
        assert(virp_seqstore_accept(&st, live_sid, n, 10) == VIRP_OK);

    /* Table full. A new live-session pair must evict the DEAD entry,
     * never one of the live session's own marks... */
    assert(virp_seqstore_accept(&st, live_sid, 100000, 10) == VIRP_OK);

    /* ...so every live mark still enforces replay */
    for (uint64_t n = 0; n < VIRP_SEQSTORE_MAX_ENTRIES - 1; n++)
        assert(virp_seqstore_accept(&st, live_sid, n, 10) ==
               VIRP_ERR_REPLAY_DETECTED);
    assert(virp_seqstore_accept(&st, live_sid, 100000, 10) ==
           VIRP_ERR_REPLAY_DETECTED);

    /* And with the table now 100% live-session, a further new pair
     * fails closed instead of silently evicting a live mark */
    assert(virp_seqstore_accept(&st, live_sid, 200000, 10) ==
           VIRP_ERR_MESSAGE_TOO_LARGE);

    virp_seqstore_destroy(&st);
    printf("PASS\n");
}

static void test_seqstore_persist_failure_does_not_poison_mark(void)
{
    printf("  test_seqstore_persist_failure_does_not_poison_mark... ");
    unlink(SEQSTORE_FILE);

    virp_seqstore_t st;
    assert(virp_seqstore_init(&st, SEQSTORE_FILE) == VIRP_OK);

    uint8_t sid[16];
    memset(sid, 0x33, 16);
    assert(virp_seqstore_accept(&st, sid, 1, 5) == VIRP_OK);

    /* Simulate disk failure: point the store at an unwritable path */
    char good_path[VIRP_SEQSTORE_PATH_MAX];
    memcpy(good_path, st.path, sizeof(good_path));
    snprintf(st.path, sizeof(st.path), "/nonexistent-dir/seqstore.txt");

    /* Update of an existing pair fails to persist → error, and the
     * in-memory mark must roll back... */
    assert(virp_seqstore_accept(&st, sid, 1, 6) == VIRP_ERR_CHAIN_DB);
    /* ...as must a brand-new pair appended during the failure */
    assert(virp_seqstore_accept(&st, sid, 2, 1) == VIRP_ERR_CHAIN_DB);

    /* Disk "recovers": the same seqs must now be accepted — a poisoned
     * mark would report VIRP_ERR_REPLAY_DETECTED here */
    memcpy(st.path, good_path, sizeof(st.path));
    assert(virp_seqstore_accept(&st, sid, 1, 6) == VIRP_OK);
    assert(virp_seqstore_accept(&st, sid, 2, 1) == VIRP_OK);

    /* And replay is still enforced after recovery */
    assert(virp_seqstore_accept(&st, sid, 1, 6) == VIRP_ERR_REPLAY_DETECTED);

    virp_seqstore_destroy(&st);
    unlink(SEQSTORE_FILE);
    printf("PASS\n");
}

int main(void)
{
    printf("=== VIRP v2 Observation Negative Tests ===\n");
    test_serialization_roundtrip_and_layout();
    test_verify_accepts_valid_observation();
    test_replay_same_sequence_rejected();
    test_non_monotonic_sequence_rejected();
    test_replay_rejected_across_store_restart();
    test_stale_observation_rejected();
    test_command_substitution_rejected();
    test_device_substitution_rejected();
    test_cross_session_replay_rejected();
    test_master_key_signature_rejected();
    test_payload_tamper_rejected();
    test_verify_requires_active_session();
    test_seqstore_eviction_never_hits_own_session();
    test_seqstore_persist_failure_does_not_poison_mark();
    printf("=== All 14 v2 observation tests passed ===\n");
    return 0;
}
