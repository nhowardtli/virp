/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — libFuzzer harness for the O-Node's socket-facing parsers.
 *
 * Three targets, one source file, selected at compile time with
 * -DFUZZ_ONODE_TARGET=<n>:
 *
 *   1  request      onode_parse_request_fuzz        parse_request()
 *   2  batch        onode_parse_batch_fuzz          parse_batch_commands()
 *   3  fed_outcome  onode_fed_outcome_citation_fuzz fed_outcome_citation()
 *
 * These are the three functions that read attacker-controlled JSON
 * before any policy has been applied: the request every action arrives
 * as, the batch command array (a second, independent parse of the same
 * frame), and the fed_outcome body GATE 4 reads to decide whether an
 * outcome is backed by evidence. Each entry point lives beside its
 * parser in src/virp_onode.c and abort()s if the parser's result breaks
 * its own postcondition, so the fuzzer hunts logic errors as well as
 * memory errors.
 *
 * No keys, no devices, no sockets, no chain.
 *
 * Build and run (clang, libFuzzer + ASan + UBSan):
 *     make fuzz-onode-parsers
 *     ./build-fuzz-onode/fuzz_onode_request     -max_total_time=60
 *     ./build-fuzz-onode/fuzz_onode_batch       -max_total_time=60
 *     ./build-fuzz-onode/fuzz_onode_fed_outcome -max_total_time=60
 *
 * Without clang: `make fuzz-onode-parsers-smoke` builds the same harness
 * with gcc + ASan + UBSan and -DVIRP_FUZZ_STANDALONE, which supplies a
 * main() that replays the seed corpus below and then a fixed number of
 * deterministic mutations of it. That is a regression smoke test, not a
 * fuzzing campaign — it exists so the harness itself is exercised on
 * every machine, including ones with no fuzzing toolchain.
 */
#include "virp_onode.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef FUZZ_ONODE_TARGET
#define FUZZ_ONODE_TARGET 1
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
#if FUZZ_ONODE_TARGET == 1
    (void)onode_parse_request_fuzz(data, size);
#elif FUZZ_ONODE_TARGET == 2
    (void)onode_parse_batch_fuzz(data, size);
#elif FUZZ_ONODE_TARGET == 3
    (void)onode_fed_outcome_citation_fuzz(data, size);
#else
#error "FUZZ_ONODE_TARGET must be 1 (request), 2 (batch) or 3 (fed_outcome)"
#endif
    return 0;
}

#ifdef VIRP_FUZZ_STANDALONE
#include <stdio.h>

/* Seeds: one well-formed input per shape the parser distinguishes, plus
 * the specific malformed shapes the security review fixed — so each of
 * those stays in the corpus a mutation starts from. */
#define H64 "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
static const char *const SEEDS[] = {
#if FUZZ_ONODE_TARGET == 1
    "{\"action\":\"heartbeat\"}",
    "{\"action\":\"execute\",\"device\":\"R1\",\"command\":\"show version\"}",
    "{\"action\":\"execute\",\"proposal_id\":\"0123456789abcdef0123456789abcdef\"}",
    "{\"action\":\"chain_append\",\"session_id\":\"s\",\"artifact_type\":\"observation\","
        "\"artifact_id\":\"a\",\"artifact_hash\":\"" H64 "\",\"artifact_content\":\"base64:AAAA\"}",
    "{\"action\":\"chain_verify\",\"session_id\":\"s\",\"from_sequence\":\"0\","
        "\"to_sequence\":\"9223372036854775807\"}",
    "{\"action\":\"intent_store\",\"intent_id\":\"i\",\"intent_hash\":\"" H64 "\","
        "\"intent_json\":\"{}\",\"confidence\":\"high\",\"max_commands\":3,"
        "\"proposed_actions\":\"[]\",\"constraints\":\"{}\"}",
    "{\"action\":\"session_hello\",\"client_id\":\"c\",\"client_nonce\":\"0011223344556677\","
        "\"versions\":\"2,1\",\"algorithms\":\"1\",\"supported_channels\":3}",
    "{\"action\":\"approval_submit\",\"proposal_id\":\"0123456789abcdef0123456789abcdef\","
        "\"key_id\":\"0123456789abcdef0123456789abcdef\",\"signature\":\"" H64 H64 "\"}",
    /* M1: trailing value, duplicate key */
    "{\"action\":\"heartbeat\"}{\"action\":\"shutdown\"}",
    "{\"action\":\"heartbeat\",\"action\":\"shutdown\"}",
    /* encoded NUL, malformed escape */
    "{\"action\":\"execute\",\"device\":\"R1\",\"command\":\"a\\u0000b\"}",
    "{\"action\":\"execute\",\"device\":\"R1\",\"command\":\"a\\u00\"}",
    /* M3: non-canonical device */
    "{\"action\":\"health\",\"device\":\"R1\\\"x\"}",
    "[]", "\"x\"", "{", "",
#elif FUZZ_ONODE_TARGET == 2
    "{\"action\":\"batch_execute\",\"commands\":[{\"device\":\"R1\",\"command\":\"show version\"}]}",
    "{\"commands\":[{\"device\":\"R1\",\"command\":\"a\"},{\"device\":\"R2\",\"command\":\"b\"}]}",
    "{\"commands\":[{\"device\":\"R1\",\"command\":\"a\",\"proposal_id\":\"x\"}]}",
    "{\"commands\":[{\"device\":\"R1\",\"command\":\"a\",\"command\":\"b\"}]}",
    "{\"commands\":[{\"device\":\"R1\\\"\",\"command\":\"a\"}]}",
    "{\"commands\":[{\"device\":\"\",\"command\":\"a\"}]}",
    "{\"commands\":[false]}", "{\"commands\":{}}", "{\"commands\":[]}",
    "{\"commands\":[{\"device\":\"R1\",\"command\":\"a\"}]}{\"commands\":[]}",
    "{\"commands\":[{\"device\":\"R1\",\"command\":\"a\\u0000b\"}]}",
    "[]", "{", "",
#else
    "{\"observation_sha256\":\"" H64 "\"}",
    "{\"error_sha256\":\"" H64 "\",\"executed\":false}",
    "{\"observation_sha256\":\"" H64 "\",\"executed\":true}",
    "{\"observation_sha256\":\"" H64 "\",\"error_sha256\":\"" H64 "\"}",
    "{\"observation_sha256\":\"" H64 "\",\"observation_sha256\":\"" H64 "\"}",
    /* H2: ambiguous or mistyped executed */
    "{\"error_sha256\":\"" H64 "\",\"executed\":false,\"executed\":true}",
    "{\"error_sha256\":\"" H64 "\",\"executed\":1}",
    "{\"error_sha256\":\"" H64 "\",\"executed\":\"true\"}",
    "{\"observation_sha256\":null}",
    "{\"detail\":{\"observation_sha256\":\"" H64 "\"}}",
    "{\"observation_sha256\":\"" "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef" "\"}",
    "[]", "{", "",
#endif
};

int main(void)
{
    static uint8_t input[4096];
    uint32_t rng = 0x9e3779b9u;
    size_t runs = 0;

    for (size_t s = 0; s < sizeof(SEEDS) / sizeof(SEEDS[0]); s++) {
        size_t n = strlen(SEEDS[s]);
        LLVMFuzzerTestOneInput((const uint8_t *)SEEDS[s], n);
        runs++;

        /* Deterministic mutations of this seed: byte flips, truncations,
         * an inserted NUL, a doubled tail. xorshift, fixed start — the
         * same inputs on every run and every machine. */
        for (int round = 0; round < 2000; round++) {
            size_t len = n < sizeof(input) / 2 ? n : sizeof(input) / 2;
            memcpy(input, SEEDS[s], len);
            rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
            switch (rng % 5) {
            case 0:                                   /* flip one byte   */
                if (len) input[(rng >> 8) % len] ^= (uint8_t)(1u << ((rng >> 4) % 8));
                break;
            case 1:                                   /* truncate        */
                if (len) len = (rng >> 8) % (len + 1);
                break;
            case 2:                                   /* raw NUL inside  */
                if (len) input[(rng >> 8) % len] = 0;
                break;
            case 3:                                   /* random byte     */
                if (len) input[(rng >> 8) % len] = (uint8_t)(rng >> 16);
                break;
            default:                                  /* double the tail */
                if (len) {
                    size_t from = (rng >> 8) % len;
                    memcpy(input + len, input + from, len - from);
                    len += len - from;
                }
                break;
            }
            LLVMFuzzerTestOneInput(input, len);
            runs++;
        }
    }
    printf("fuzz_onode_parsers target %d: %zu inputs, no crash, no "
           "postcondition violation\n", FUZZ_ONODE_TARGET, runs);
    return 0;
}
#endif /* VIRP_FUZZ_STANDALONE */
