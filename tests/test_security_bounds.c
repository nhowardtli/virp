/* Regression cases from the 2026-09-20 security review. */
#include "virp.h"
#include "virp_message.h"
#include "virp_crypto.h"
#include "virp_scrub.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    static uint8_t data[UINT16_MAX], wire[VIRP_MAX_MESSAGE_SIZE];
    memset(data, 'x', sizeof(data));
    virp_signing_key_t key;
    assert(virp_key_generate(&key, VIRP_KEY_TYPE_OKEY) == VIRP_OK);
    const size_t lengths[] = {VIRP_OBS_V1_MAX_DATA-1, VIRP_OBS_V1_MAX_DATA,
                              VIRP_OBS_V1_MAX_DATA+1, 65530, UINT16_MAX};
    for (size_t i = 0; i < sizeof(lengths)/sizeof(lengths[0]); i++) {
        size_t n = 0;
        virp_error_t rc = virp_build_observation(wire, sizeof(wire), &n,
            1, 1, VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
            data, (uint16_t)lengths[i], &key);
        if (lengths[i] > VIRP_OBS_V1_MAX_DATA) {
            assert(rc == VIRP_ERR_MESSAGE_TOO_LARGE);
            assert(n == 0);
        } else {
            virp_header_t header;
            assert(rc == VIRP_OK && n == VIRP_HEADER_SIZE+4+lengths[i]);
            assert(virp_validate_message(wire, n, &key, &header) == VIRP_OK);
            assert(header.length == n);
        }
    }
    virp_key_destroy(&key);
    virp_exec_result_t result;
    memset(&result, 0, sizeof(result));
    strcpy(result.output, "sensitive-device-text");
    result.output_len = sizeof(result.output) + 1000;
    virp_scrub_exec_result(&result);
    assert(result.output_len < sizeof(result.output));
    assert(result.output_truncated && !result.success);
    assert(strstr(result.output, "sensitive-device-text") == NULL);
    puts("security bounds: 5 wire boundaries + malformed driver length PASS");
    return 0;
}
