/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — libFuzzer harness for the v3 public-key observation verifier
 *
 * Build: make fuzz-obs-ed25519 (requires clang; builds libvirp with
 * fuzzer-no-link+ASan+UBSan instrumentation into build-fuzz/).
 * Run:   ./build-fuzz/fuzz_obs_ed25519 [corpus_dir]
 *
 * virp_verify_observation_ed25519() is the most exposed surface in the
 * tree: public key + attacker-controlled byte buffer, no secret, meant
 * to be run by third parties on untrusted bytes. It must never crash,
 * read out of bounds, or return VIRP_OK for anything but a genuinely
 * signed, exactly-framed v3 observation.
 *
 * The keypair is DETERMINISTIC (fixed seed) so a seed corpus of
 * genuinely-signed observations can be generated offline with the same
 * seed and remains valid across runs — without it the fuzzer would
 * almost never reach the post-signature code.
 */

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_obskey.h"
#include <sodium.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

static uint8_t fuzz_pk[VIRP_OBSKEY_PK_SIZE];
static uint8_t fuzz_sk[VIRP_OBSKEY_SK_SIZE];
static int initialized = 0;

static const uint8_t FUZZ_SEED[32] = {
    'V','I','R','P','-','f','u','z','z','-','o','b','s','-','v','3',
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF
};

static void ensure_init(void)
{
    if (initialized) return;
    if (sodium_init() < 0) abort();
    if (crypto_sign_seed_keypair(fuzz_pk, fuzz_sk, FUZZ_SEED) != 0) abort();
    initialized = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ensure_init();

    virp_obs_header_v2_t hdr;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;

    virp_error_t err = virp_verify_observation_ed25519(
        fuzz_pk, data, size, &hdr, &payload, &payload_len);

    if (err == VIRP_OK) {
        /* Acceptance invariants: anything the verifier vouches for
         * must be internally consistent. A violation here is a bug
         * even if no memory error occurred. */
        if (hdr.version != VIRP_VERSION_3) abort();
        if (hdr.channel != VIRP_CHANNEL_OBS) abort();
        if (hdr._reserved != 0) abort();
        if (hdr.tier == VIRP_TIER_BLACK || hdr.tier > VIRP_TIER_RED) abort();
        if (payload != data + VIRP_OBS_V2_HEADER_SIZE) abort();
        if ((size_t)payload_len !=
            size - VIRP_OBS_V2_HEADER_SIZE - VIRP_OBS_V2_SIG_SIZE -
            VIRP_OBS_ED25519_SIG_SIZE) abort();
        /* Touch every accepted payload byte so ASan patrols the span
         * the verifier claims is valid. */
        volatile uint8_t sink = 0;
        for (uint32_t i = 0; i < payload_len; i++) sink ^= payload[i];
        (void)sink;
    }

    return 0;
}
