/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — libFuzzer harness for message parsing
 *
 * Build: make fuzz-libfuzzer (requires clang with -fsanitize=fuzzer)
 *
 * Exercises virp_validate_message and virp_parse_* with arbitrary input.
 * The parser must NEVER crash, regardless of input.
 */

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static virp_signing_key_t okey;
static int initialized = 0;

static void ensure_init(void)
{
    if (initialized) return;
    uint8_t key_bytes[32];
    memset(key_bytes, 0x42, sizeof(key_bytes));
    virp_key_init(&okey, VIRP_KEY_TYPE_OKEY, key_bytes);
    initialized = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ensure_init();

    /* Try to validate as a VIRP message */
    virp_header_t hdr;
    virp_validate_message(data, size, &okey, &hdr);

    /* Try to parse observation payload if large enough */
    if (size >= VIRP_HEADER_SIZE) {
        char output[65536];
        size_t output_len = 0;
        virp_parse_observation(data, size, output, sizeof(output), &output_len);
    }

    return 0;
}
