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

    /* Try the payload parsers if large enough. These take the payload
     * after the 56-byte header and must reject any embedded length or
     * ref count that overruns the buffer. (This call previously used a
     * stale pre-refactor signature and the harness did not compile.) */
    if (size > VIRP_HEADER_SIZE) {
        const uint8_t *payload = data + VIRP_HEADER_SIZE;
        size_t payload_len = size - VIRP_HEADER_SIZE;

        virp_observation_t obs;
        const uint8_t *odata;
        uint16_t odata_len;
        virp_parse_observation(payload, payload_len, &obs, &odata, &odata_len);

        virp_proposal_t prop;
        const virp_obs_ref_t *refs;
        const uint8_t *pdata;
        uint16_t pdata_len;
        virp_parse_proposal(payload, payload_len, &prop, &refs,
                            &pdata, &pdata_len);
    }

    return 0;
}
