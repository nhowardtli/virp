/* Hostile device bytes through scrub, REST filter and prompt framing.
 * Build with libFuzzer+ASan+UBSan; no keys, devices or network sockets. */
#include "virp_scrub.h"
#include "virp_body_filter.h"
#include "virp_ssh_io.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef struct { const uint8_t *data; size_t size, offset; } memory_io;
static ssize_t read_bytes(void *ctx, char *out, size_t cap)
{
    memory_io *m = ctx;
    size_t n = m->size - m->offset;
    if (n > cap) n = cap;
    if (n > 1024) n = 1024;
    memcpy(out, m->data + m->offset, n); m->offset += n;
    return (ssize_t)n; /* EOF when exhausted, never sleeps on a fake channel. */
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size >= VIRP_OUTPUT_MAX) return 0;
    virp_exec_result_t result = {0};
    memcpy(result.output, data, size); result.output_len = size;
    virp_scrub_exec_result(&result);
    assert(result.output_len < sizeof(result.output));
    memcpy(result.output, data, size); result.output[size] = 0;
    result.output_len = size;
    (void)virp_body_filter_apply("librenms", "GET /api/v0/devices", &result);
    assert(result.output_len < sizeof(result.output));
    char output[VIRP_OUTPUT_MAX]; size_t n = 0;
    memory_io m = {data, size, 0};
    virp_ssh_io_t io = {.ctx=&m, .read=read_bytes, .write=NULL};
    virp_ssh_prompt_t prompt = {.prompt="lab#", .prompt_len=4, .learned=true};
    (void)virp_ssh_read_until_prompt(&io, &prompt, output, sizeof(output),
                                   &n, 5, "fuzz");
    assert(n < sizeof(output));
    return 0;
}

#ifdef VIRP_FUZZ_STANDALONE
int main(void)
{
    static uint8_t input[VIRP_OUTPUT_MAX];
    uint32_t rng = 0x12345678;
    const char *seeds[] = {"password secret\nlab#", "{\"devices\":[{\"community\":\"secret\"}]}",
                           "-----BEGIN PRIVATE KEY-----\nx\n", "lab#"};
    for (size_t i = 0; i < sizeof(seeds)/sizeof(seeds[0]); i++)
        LLVMFuzzerTestOneInput((const uint8_t *)seeds[i], strlen(seeds[i]));
    for (size_t round = 0; round < 2000; round++) {
        size_t n = round < 10 ? VIRP_OUTPUT_MAX-1-round : round % 8192;
        for (size_t i = 0; i < n; i++) {
            rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
            input[i] = (uint8_t)rng;
        }
        LLVMFuzzerTestOneInput(input, n);
    }
    return 0;
}
#endif
