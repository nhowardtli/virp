/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Fuzz tester — the parser must NEVER crash, regardless of input
 *
 * Three fuzzing modes:
 *   1. Random: completely random bytes
 *   2. Mutation: valid messages with random byte flips
 *   3. Boundary: edge case lengths and field values
 */

#define _POSIX_C_SOURCE 199309L

#include "virp.h"
#include "virp_crypto.h"
#include "virp_context.h"
#include "virp_message.h"
#include "virp_onode.h"  /* onode_parse_request_fuzz */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FUZZ_ROUNDS     100000
#define MAX_FUZZ_SIZE   (VIRP_MAX_MESSAGE_SIZE + 64)

static virp_signing_key_t okey, rkey;

static uint8_t rand8(void)
{
    return (uint8_t)(rand() & 0xFF);
}

/* =========================================================================
 * Random fuzzing — completely random bytes
 * ========================================================================= */

static int fuzz_random(int rounds)
{
    uint8_t buf[MAX_FUZZ_SIZE];
    virp_header_t hdr;
    int crashes = 0;

    printf("  Random fuzzing: %d rounds... ", rounds);
    fflush(stdout);

    for (int i = 0; i < rounds; i++) {
        /* Random length between 0 and MAX_FUZZ_SIZE */
        size_t len = rand() % MAX_FUZZ_SIZE;

        /* Fill with random bytes */
        for (size_t j = 0; j < len; j++)
            buf[j] = rand8();

        /* These must not crash — return value doesn't matter */
        virp_header_deserialize(&hdr, buf, len);
        virp_header_validate(&hdr);
        virp_validate_message(buf, len, &okey, &hdr);
        virp_validate_message(buf, len, &rkey, &hdr);

        /* Try parsing payloads on random data */
        if (len > VIRP_HEADER_SIZE) {
            virp_observation_t obs;
            const uint8_t *data;
            uint16_t data_len;
            virp_parse_observation(buf + VIRP_HEADER_SIZE,
                                   len - VIRP_HEADER_SIZE,
                                   &obs, &data, &data_len);

            virp_heartbeat_t hb;
            virp_parse_heartbeat(buf + VIRP_HEADER_SIZE,
                                 len - VIRP_HEADER_SIZE, &hb);

            virp_approval_t approval;
            virp_parse_approval(buf + VIRP_HEADER_SIZE,
                                len - VIRP_HEADER_SIZE, &approval);

            virp_hello_t hello;
            virp_parse_hello(buf + VIRP_HEADER_SIZE,
                             len - VIRP_HEADER_SIZE, &hello);

            virp_proposal_t prop;
            const virp_obs_ref_t *refs;
            const uint8_t *prop_data;
            uint16_t prop_data_len;
            virp_parse_proposal(buf + VIRP_HEADER_SIZE,
                                len - VIRP_HEADER_SIZE,
                                &prop, &refs, &prop_data, &prop_data_len);
        }
    }

    printf("[OK] no crashes\n");
    return crashes;
}

/* =========================================================================
 * Mutation fuzzing — flip random bits in valid messages
 * ========================================================================= */

static int fuzz_mutation(int rounds)
{
    uint8_t original[512];
    uint8_t mutated[512];
    size_t orig_len;
    virp_header_t hdr;

    printf("  Mutation fuzzing: %d rounds... ", rounds);
    fflush(stdout);

    /* Build a valid observation */
    uint8_t data[] = "R6#show ip bgp summary\nBGP router identifier 6.6.6.6";
    virp_error_t err = virp_build_observation(original, sizeof(original),
                                              &orig_len,
                                              0x06060606, 1,
                                              VIRP_OBS_DEVICE_OUTPUT,
                                              VIRP_SCOPE_LOCAL,
                                              data, sizeof(data), &okey);
    if (err != VIRP_OK) {
        printf("[SETUP FAILED]\n");
        return 1;
    }

    for (int i = 0; i < rounds; i++) {
        memcpy(mutated, original, orig_len);

        /* Flip 1-8 random bytes */
        int flips = 1 + (rand() % 8);
        for (int f = 0; f < flips; f++) {
            size_t pos = rand() % orig_len;
            mutated[pos] ^= (1 << (rand() % 8));
        }

        /* Must not crash */
        virp_validate_message(mutated, orig_len, &okey, &hdr);

        /* Also try with truncated length */
        size_t trunc_len = rand() % (orig_len + 1);
        virp_validate_message(mutated, trunc_len, &okey, &hdr);
    }

    printf("[OK] no crashes\n");
    return 0;
}

/* =========================================================================
 * Boundary fuzzing — edge case field values
 * ========================================================================= */

static int fuzz_boundary(void)
{
    virp_header_t hdr;
    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];

    printf("  Boundary fuzzing... ");
    fflush(stdout);

    /* Zero-length buffer */
    virp_header_deserialize(&hdr, buf, 0);
    virp_validate_message(buf, 0, &okey, &hdr);

    /* Exactly header size, all zeros */
    memset(buf, 0, VIRP_HEADER_SIZE);
    virp_header_deserialize(&hdr, buf, VIRP_HEADER_SIZE);
    virp_validate_message(buf, VIRP_HEADER_SIZE, &okey, &hdr);

    /* All 0xFF */
    memset(buf, 0xFF, sizeof(buf));
    virp_header_deserialize(&hdr, buf, sizeof(buf));
    virp_validate_message(buf, sizeof(buf), &okey, &hdr);

    /* Valid header but every invalid channel value */
    for (int ch = 0; ch <= 255; ch++) {
        memset(&hdr, 0, sizeof(hdr));
        hdr.version = VIRP_VERSION;
        hdr.type = VIRP_MSG_OBSERVATION;
        hdr.length = VIRP_HEADER_SIZE;
        hdr.channel = (uint8_t)ch;
        hdr.tier = VIRP_TIER_GREEN;
        virp_header_validate(&hdr);
    }

    /* Every invalid tier value */
    for (int t = 0; t <= 255; t++) {
        memset(&hdr, 0, sizeof(hdr));
        hdr.version = VIRP_VERSION;
        hdr.type = VIRP_MSG_OBSERVATION;
        hdr.length = VIRP_HEADER_SIZE;
        hdr.channel = VIRP_CHANNEL_OC;
        hdr.tier = (uint8_t)t;
        virp_header_validate(&hdr);
    }

    /* Every invalid message type */
    for (int mt = 0; mt <= 255; mt++) {
        memset(&hdr, 0, sizeof(hdr));
        hdr.version = VIRP_VERSION;
        hdr.type = (uint8_t)mt;
        hdr.length = VIRP_HEADER_SIZE;
        hdr.channel = VIRP_CHANNEL_OC;
        hdr.tier = VIRP_TIER_GREEN;
        virp_header_validate(&hdr);
    }

    /* Header with length=0 */
    memset(buf, 0, VIRP_HEADER_SIZE);
    buf[0] = VIRP_VERSION;
    buf[1] = VIRP_MSG_OBSERVATION;
    /* length bytes at 2-3 already zero */
    virp_validate_message(buf, VIRP_HEADER_SIZE, &okey, &hdr);

    /* Header with length=65535 but only 56 bytes of data */
    buf[2] = 0xFF;
    buf[3] = 0xFF;
    virp_validate_message(buf, VIRP_HEADER_SIZE, &okey, &hdr);

    /* Signing with NULL key */
    virp_sign(NULL, buf, VIRP_HEADER_SIZE, NULL);
    virp_verify(NULL, buf, VIRP_HEADER_SIZE, NULL);

    /* Build with zero-length data */
    size_t out_len;
    virp_build_observation(buf, sizeof(buf), &out_len,
                           1, 1, VIRP_OBS_DEVICE_OUTPUT,
                           VIRP_SCOPE_LOCAL, NULL, 0, &okey);

    /* Build into tiny buffer */
    uint8_t tiny[4];
    virp_build_observation(tiny, sizeof(tiny), &out_len,
                           1, 1, VIRP_OBS_DEVICE_OUTPUT,
                           VIRP_SCOPE_LOCAL, (const uint8_t *)"x", 1, &okey);

    /* TLV parsing on garbage */
    virp_tlv_t tlv;
    const uint8_t *val;
    virp_tlv_parse(buf, 0, 0, &tlv, &val);
    virp_tlv_parse(buf, 2, 0, &tlv, &val);
    virp_tlv_parse(buf, sizeof(buf), 0, &tlv, &val);

    printf("[OK] no crashes\n");
    return 0;
}

/* =========================================================================
 * parse_request fuzzing — JSON-shaped inputs, pure random bytes, and
 * structural mutations of a valid request. The parser must never
 * crash; returning false for garbage is the expected happy path.
 * ========================================================================= */

static const char *const SEED_REQUESTS[] = {
    "{\"action\":\"heartbeat\"}",
    "{\"action\":\"execute\",\"device\":\"R1\",\"command\":\"show ver\"}",
    "{\"action\":\"chain_verify\",\"session_id\":\"abcd\","
        "\"from_sequence\":0,\"to_sequence\":1000}",
    "{\"action\":\"intent_store\",\"intent_id\":\"x\","
        "\"intent_hash\":\"deadbeef\",\"expires_at_ns\":123,"
        "\"max_commands\":5}",
    "{\"action\":\"session_hello\",\"client_id\":\"c\","
        "\"client_nonce\":\"0011223344556677\","
        "\"versions\":\"2,1\",\"algorithms\":\"1\","
        "\"supported_channels\":3}",
    "[\"not\",\"an\",\"object\"]",
    "\"bare string\"",
    "42",
    "",
    "{",
};

static int fuzz_parse_request(int rounds)
{
    uint8_t buf[4096];
    int crashes = 0;

    printf("  parse_request fuzzing: %d rounds... ", rounds);
    fflush(stdout);

    /* Pass 1: feed seed inputs verbatim so the parser always sees
     * well-formed + a few deliberately malformed examples. */
    const size_t nseeds = sizeof(SEED_REQUESTS) / sizeof(SEED_REQUESTS[0]);
    for (size_t i = 0; i < nseeds; i++) {
        const char *s = SEED_REQUESTS[i];
        onode_parse_request_fuzz((const uint8_t *)s, strlen(s));
    }

    /* Pass 2: random bytes of random length. */
    for (int i = 0; i < rounds; i++) {
        size_t len = (size_t)(rand() % (int)sizeof(buf));
        for (size_t j = 0; j < len; j++)
            buf[j] = rand8();
        onode_parse_request_fuzz(buf, len);
    }

    /* Pass 3: seed + bit-flip mutations. A valid JSON object with
     * random byte corruptions stresses the error paths more than
     * uniform random bytes, which mostly fail at cJSON_Parse. */
    for (int i = 0; i < rounds; i++) {
        const char *seed = SEED_REQUESTS[rand() % (int)nseeds];
        size_t len = strlen(seed);
        if (len >= sizeof(buf)) continue;
        memcpy(buf, seed, len);

        int n_flips = 1 + (rand() % 5);
        for (int f = 0; f < n_flips && len > 0; f++) {
            size_t pos = (size_t)(rand()) % len;
            buf[pos] ^= (uint8_t)(1 << (rand() % 8));
        }
        onode_parse_request_fuzz(buf, len);
    }

    printf("OK (no crashes)\n");
    return crashes;
}

/* =========================================================================
 * Main
 * ========================================================================= */

int main(int argc, char **argv)
{
    int rounds = FUZZ_ROUNDS;
    if (argc > 1)
        rounds = atoi(argv[1]);

    printf("\n");
    printf("================================================================\n");
    printf("  VIRP — Fuzz Testing\n");
    printf("  %d rounds per mode\n", rounds);
    printf("  Copyright (c) 2026 Third Level IT LLC\n");
    printf("================================================================\n\n");

    srand((unsigned)time(NULL));

    virp_key_generate(&okey, VIRP_KEY_TYPE_OKEY);
    virp_key_generate(&rkey, VIRP_KEY_TYPE_RKEY);

    int failures = 0;
    failures += fuzz_random(rounds);
    failures += fuzz_mutation(rounds);
    failures += fuzz_boundary();
    failures += fuzz_parse_request(rounds);

    printf("\n================================================================\n");
    if (failures == 0)
        printf("  ALL FUZZ TESTS PASSED — parser is crash-proof\n");
    else
        printf("  %d FAILURES DETECTED\n", failures);
    printf("================================================================\n\n");

    virp_key_destroy(&okey);
    virp_key_destroy(&rkey);

    return failures;
}
