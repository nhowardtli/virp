/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — the forge-resistance contrast (Ed25519 vs HMAC observations)
 *
 * THIS FILE IS THE EVIDENCE for what the Ed25519 observation scheme
 * buys and what it does not. Three tests, deliberately side by side:
 *
 *   1. HMAC CEILING (reproduced, not fixed): a holder of the symmetric
 *      HMAC verify key CAN mint a valid-verifying observation of a
 *      result no device ever produced. Verify key == forge key. This
 *      is the BGP-test finding (a clean-VALID fake route) as a unit
 *      test, documenting the ceiling the asymmetric scheme removes.
 *
 *   2. ED25519 FORGE-RESISTANCE (the point): the SAME forgery
 *      attempted with only the Ed25519 PUBLIC key fails verification
 *      for every signature a public-key holder can compute — zeroed,
 *      random, spliced from a genuine observation, or made with a
 *      key the attacker generated. Only the private-key holder signs.
 *
 *   3. TAMPER: a genuine Ed25519-signed observation with any covered
 *      byte flipped fails public-key verification.
 *
 * Scope held precisely: these tests prove CONSUMER/AUDITOR
 * non-forgeability. They do not — cannot — prove daemon-compromise
 * resistance: the daemon holds the signing secret because the daemon
 * is the attester. See SECURITY.md "Ed25519 Observation Signing".
 *
 * WHY TEST 1 USES v1 AND TESTS 2-3 USE v3 (pre-empting the
 * apples-to-apples objection, review finding P2-4). Test 1
 * reproduces the ceiling on the v1 O-Key format deliberately: v1 is
 * the DEPLOYED scheme the original BGP-test finding was filed
 * against, so reproducing it there documents the exact defect that
 * motivated this work, not a constructed analogue. The contrast is
 * still apples-to-apples because the property under test is a
 * property of the SCHEME (symmetric: verify key == forge key;
 * asymmetric: public key cannot sign), not of the wire version — and
 * the attested content class is identical on both sides (a signed
 * device-output observation of a never-received result). The v2
 * session-HMAC has the SAME ceiling as v1 for any session-key holder;
 * v1 is simply the cleanest reproduction of the filed finding. A
 * v2-on-v2 forge would add nothing the scheme-level argument does not
 * already cover.
 */

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sodium.h>

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_session.h"
#include "virp_context.h"
#include "virp_handshake.h"
#include "virp_transcript.h"
#include "virp_obskey.h"

static const uint8_t test_master_key[32] = {
    0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
    0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,
    0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
    0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F,0x20,
};

#define TEST_NODE_ID    0x0A0000D3ULL
#define TEST_DEVICE_ID  0x1122334455667788ULL

/* The fake result: a BGP route the device never announced. The exact
 * shape of the finding this file exists to document. */
static const char FAKE_ROUTE[] =
    "B   198.51.100.0/24 [20/0] via 192.0.2.66, AS64500 — NEVER RECEIVED";

static int tests_run = 0, tests_passed = 0;

#define RUN_TEST(fn) do { \
        tests_run++; \
        printf("  %-58s", #fn); \
        fflush(stdout); \
        fn(); \
        tests_passed++; \
        printf("[PASS]\n"); \
    } while (0)

static void activate_session(virp_context_t *ctx, uint8_t nonce_byte)
{
    virp_session_hello_t h;
    memset(&h, 0, sizeof(h));
    h.msg_type = VIRP_MSG_SESSION_HELLO;
    memcpy(h.client_id, "forge-test", 10);
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

/* ── 1. The HMAC ceiling ─────────────────────────────────────────────
 * The "attacker" here is any party GIVEN the verify key so they can
 * check observations — a report consumer, an auditor, a dashboard.
 * With HMAC those are the same bytes the O-Node signs with, so the
 * consumer can mint. This test FORGES and then VERIFIES CLEAN. */
static void test_hmac_verify_key_holder_can_forge(void)
{
    virp_signing_key_t okey;
    assert(virp_key_generate(&okey, VIRP_KEY_TYPE_OKEY) == VIRP_OK);
    /* okey now plays both roles at once — that is the defect. */

    /* Forge: build a v1 observation of the never-received route,
     * exactly as the O-Node would, but by the CONSUMER. */
    uint8_t forged[VIRP_MAX_MESSAGE_SIZE];
    size_t forged_len = 0;
    assert(virp_build_observation_tiered(
               forged, sizeof(forged), &forged_len,
               (uint32_t)TEST_NODE_ID, /*seq*/ 424242,
               VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL, VIRP_TIER_GREEN,
               (const uint8_t *)FAKE_ROUTE, sizeof(FAKE_ROUTE) - 1,
               &okey) == VIRP_OK);

    /* Verify with the same key any consumer was given: CLEAN VALID.
     * Nothing distinguishes this from a genuine observation. */
    virp_header_t hdr;
    assert(virp_validate_message(forged, forged_len, &okey, &hdr)
           == VIRP_OK);
    assert(hdr.type == VIRP_MSG_OBSERVATION);

    /* This is the ceiling: with the symmetric scheme, "signature
     * VALID" proves only that SOME holder of the shared secret built
     * the message — and the verifier is a holder. */
    virp_key_destroy(&okey);
}

/* ── 2. Ed25519 forge-resistance ─────────────────────────────────────
 * Same forgery attempt, but the attacker holds ONLY the public key.
 * They can format a perfect v3 observation; what they cannot do is
 * produce a signature over it that verifies. */
static void test_ed25519_public_key_holder_cannot_forge(void)
{
    /* The real O-Node keypair. The attacker will see public_key only. */
    virp_obskey_t onode_key;
    assert(virp_obskey_generate(&onode_key) == VIRP_OK);
    const uint8_t *pub = onode_key.public_key;

    /* A genuine observation signed by the real daemon — the attacker
     * may possess this too (observations are distributed). */
    virp_context_t *ctx = virp_context_new();
    assert(ctx && virp_session_init(ctx, "onode") == VIRP_OK);
    activate_session(ctx, 0x41);
    uint8_t genuine[VIRP_MAX_MESSAGE_SIZE];
    size_t genuine_len = 0;
    assert(virp_build_observation_ed25519(
               ctx, &onode_key, TEST_NODE_ID, TEST_DEVICE_ID,
               VIRP_TIER_GREEN, 7, "show ip bgp", NULL,
               (const uint8_t *)"legit output", 12,
               genuine, sizeof(genuine), &genuine_len) == VIRP_OK);
    /* Sanity: the genuine observation verifies, so every failure
     * below is the signature's doing, not a broken verifier. */
    assert(virp_verify_observation_ed25519(pub, genuine, genuine_len,
                                           NULL, NULL, NULL) == VIRP_OK);

    /* The attacker constructs the forged observation body: a
     * perfectly-formatted v3 header + the fake route. Formatting is
     * not the barrier — the signature is. */
    virp_obs_header_v2_t fh;
    memset(&fh, 0, sizeof(fh));
    fh.version      = VIRP_VERSION_3;
    fh.channel      = VIRP_CHANNEL_OBS;
    fh.tier         = VIRP_TIER_GREEN;
    fh.node_id      = TEST_NODE_ID;
    fh.device_id    = TEST_DEVICE_ID;
    fh.seq_num      = 8;                       /* plausibly-next */
    fh.timestamp_ns = 1754582400ULL * 1000000000ULL;
    memset(fh.session_id, 0x22, 16);
    memset(fh.command_hash, 0x33, 32);
    fh.payload_len  = sizeof(FAKE_ROUTE) - 1;

    size_t hmac_span = VIRP_OBS_V2_HEADER_SIZE + fh.payload_len;
    size_t sig_span  = hmac_span + VIRP_OBS_V2_SIG_SIZE;
    size_t total     = sig_span + VIRP_OBS_ED25519_SIG_SIZE;
    uint8_t forged[VIRP_MAX_MESSAGE_SIZE];
    assert(virp_obs_header_v2_serialize(&fh, forged,
                                        sizeof(forged)) == VIRP_OK);
    memcpy(forged + VIRP_OBS_V2_HEADER_SIZE, FAKE_ROUTE,
           fh.payload_len);
    /* HMAC trailer: attacker has no session key either; garbage. The
     * public-key verifier never READS it, but it is inside the signed
     * span, so it must be present before the signature is computed. */
    memset(forged + hmac_span, 0x44, VIRP_OBS_V2_SIG_SIZE);
    uint8_t *sig = forged + sig_span;

    /* Attempt (a): zero signature. */
    memset(sig, 0x00, VIRP_OBS_ED25519_SIG_SIZE);
    assert(virp_verify_observation_ed25519(pub, forged, total,
                                           NULL, NULL, NULL)
           == VIRP_ERR_OBS_SIG_INVALID);

    /* Attempt (b): random signatures. Ed25519's security is
     * computational; 64 random tries stand in for "guessing". */
    for (int i = 0; i < 64; i++) {
        randombytes_buf(sig, VIRP_OBS_ED25519_SIG_SIZE);
        assert(virp_verify_observation_ed25519(pub, forged, total,
                                               NULL, NULL, NULL)
               == VIRP_ERR_OBS_SIG_INVALID);
    }

    /* Attempt (c): splice the REAL signature off the genuine
     * observation the attacker possesses. It is a valid signature by
     * the right key — over different bytes; it must not transfer. */
    memcpy(sig, genuine + genuine_len - VIRP_OBS_ED25519_SIG_SIZE,
           VIRP_OBS_ED25519_SIG_SIZE);
    assert(virp_verify_observation_ed25519(pub, forged, total,
                                           NULL, NULL, NULL)
           == VIRP_ERR_OBS_SIG_INVALID);

    /* Attempt (d): sign with a keypair the attacker generated. A
     * perfectly valid Ed25519 signature — under the wrong key. */
    virp_obskey_t attacker_key;
    assert(virp_obskey_generate(&attacker_key) == VIRP_OK);
    assert(crypto_sign_detached(sig, NULL, forged, sig_span,
                                attacker_key.secret_key) == 0);
    assert(virp_verify_observation_ed25519(pub, forged, total,
                                           NULL, NULL, NULL)
           == VIRP_ERR_OBS_SIG_INVALID);

    /* And the contrast that is the point of this file: under HMAC the
     * same capability set (verify material only) minted CLEAN VALID;
     * under Ed25519 every attempt failed. Only the private-key holder
     * produced a verifying observation (the sanity check above). */

    virp_obskey_destroy(&attacker_key);
    virp_obskey_destroy(&onode_key);
    virp_context_destroy(ctx);
}

/* ── 3. Tamper ───────────────────────────────────────────────────────
 * A genuine v3 observation with any covered byte flipped must fail
 * public-key verification — header (version, tier, ids, command hash,
 * every field) and payload alike. */
static void test_tamper_any_covered_byte_fails(void)
{
    virp_obskey_t onode_key;
    assert(virp_obskey_generate(&onode_key) == VIRP_OK);

    virp_context_t *ctx = virp_context_new();
    assert(ctx && virp_session_init(ctx, "onode") == VIRP_OK);
    activate_session(ctx, 0x42);

    uint8_t obs[VIRP_MAX_MESSAGE_SIZE];
    size_t obs_len = 0;
    static const uint8_t payload[] = "interface Gi0/1 is up, line up";
    assert(virp_build_observation_ed25519(
               ctx, &onode_key, TEST_NODE_ID, TEST_DEVICE_ID,
               VIRP_TIER_YELLOW, 9, "show interface Gi0/1", NULL,
               payload, sizeof(payload) - 1,
               obs, sizeof(obs), &obs_len) == VIRP_OK);
    assert(virp_verify_observation_ed25519(onode_key.public_key,
                                           obs, obs_len,
                                           NULL, NULL, NULL) == VIRP_OK);

    size_t sig_span = obs_len - VIRP_OBS_ED25519_SIG_SIZE;
    size_t hmac_off = sig_span - VIRP_OBS_V2_SIG_SIZE;

    /* Every covered byte: header + payload + the HMAC trailer. */
    for (size_t i = 0; i < sig_span; i++) {
        obs[i] ^= 0x01;
        assert(virp_verify_observation_ed25519(onode_key.public_key,
                                               obs, obs_len,
                                               NULL, NULL, NULL)
               != VIRP_OK);
        obs[i] ^= 0x01;
    }

    /* Every byte of the signature itself. */
    for (size_t i = obs_len - VIRP_OBS_ED25519_SIG_SIZE; i < obs_len; i++) {
        obs[i] ^= 0x01;
        assert(virp_verify_observation_ed25519(onode_key.public_key,
                                               obs, obs_len,
                                               NULL, NULL, NULL)
               == VIRP_ERR_OBS_SIG_INVALID);
        obs[i] ^= 0x01;
    }

    /* Intact again after both sweeps: verifier still accepts. */
    assert(virp_verify_observation_ed25519(onode_key.public_key,
                                           obs, obs_len,
                                           NULL, NULL, NULL) == VIRP_OK);

    /* The HMAC trailer IS covered (changed 2026-08-08). It is still
     * only the session holder who can CHECK the HMAC — a public-key
     * consumer cannot — but the signature BINDS it, so a relay holding
     * neither key cannot rewrite those 32 bytes and keep the message
     * verifying. Until this changed, it could: same attested content,
     * unlimited distinct byte strings and artifact hashes. */
    obs[hmac_off] ^= 0x01;    /* first HMAC byte */
    assert(virp_verify_observation_ed25519(onode_key.public_key,
                                           obs, obs_len,
                                           NULL, NULL, NULL)
           == VIRP_ERR_OBS_SIG_INVALID);
    obs[hmac_off] ^= 0x01;

    virp_obskey_destroy(&onode_key);
    virp_context_destroy(ctx);
}

int main(void)
{
    printf("=== VIRP Forge-Resistance Contrast: HMAC ceiling vs Ed25519 ===\n");

    RUN_TEST(test_hmac_verify_key_holder_can_forge);
    RUN_TEST(test_ed25519_public_key_holder_cannot_forge);
    RUN_TEST(test_tamper_any_covered_byte_fails);

    printf("=== All %d forge-contrast tests passed (%d/%d) ===\n"
           "    HMAC verify-key holder FORGED a clean-VALID observation;\n"
           "    Ed25519 public-key holder COULD NOT. Consumer forge\n"
           "    capability is removed; daemon compromise is NOT addressed\n"
           "    (the daemon holds the signing key — it is the attester).\n",
           tests_run, tests_passed, tests_run);
    return 0;
}
