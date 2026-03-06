/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP -- C/Go interop test helper
 *
 * Modes:
 *   generate <keyfile> <outfile>   — build messages with key, write to file
 *   validate <keyfile> <infile>    — read messages from file, validate with key
 *
 * File format: sequence of [4-byte big-endian length][message bytes]
 */

#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

static void write_msg(FILE *f, const uint8_t *msg, size_t len)
{
    uint32_t len_n = htonl((uint32_t)len);
    fwrite(&len_n, 4, 1, f);
    fwrite(msg, 1, len, f);
}

static int read_msg(FILE *f, uint8_t *buf, size_t buf_len, size_t *out_len)
{
    uint32_t len_n;
    if (fread(&len_n, 4, 1, f) != 1) return -1;
    *out_len = ntohl(len_n);
    if (*out_len > buf_len) return -1;
    if (fread(buf, 1, *out_len, f) != *out_len) return -1;
    return 0;
}

static int do_generate(const char *keyfile, const char *outfile)
{
    virp_signing_key_t okey;
    if (virp_key_load_file(&okey, VIRP_KEY_TYPE_OKEY, keyfile) != VIRP_OK) {
        fprintf(stderr, "Failed to load key from %s\n", keyfile);
        return 1;
    }

    FILE *f = fopen(outfile, "wb");
    if (!f) { perror("fopen"); return 1; }

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t out_len;
    virp_error_t err;

    /* Message 1: OBSERVATION with device output */
    err = virp_build_observation(buf, sizeof(buf), &out_len,
                                  0x00000211, 1,
                                  VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
                                  (const uint8_t *)"C-built observation payload", 27,
                                  &okey);
    if (err != VIRP_OK) {
        fprintf(stderr, "build observation: %s\n", virp_error_str(err));
        fclose(f);
        return 1;
    }
    write_msg(f, buf, out_len);
    fprintf(stderr, "[C-generate] OBSERVATION: %zu bytes, seq=1\n", out_len);

    /* Message 2: HEARTBEAT */
    err = virp_build_heartbeat(buf, sizeof(buf), &out_len,
                                0x00000211, 2,
                                3600, 1, 1, 42, 0,
                                &okey);
    if (err != VIRP_OK) {
        fprintf(stderr, "build heartbeat: %s\n", virp_error_str(err));
        fclose(f);
        return 1;
    }
    write_msg(f, buf, out_len);
    fprintf(stderr, "[C-generate] HEARTBEAT: %zu bytes, seq=2\n", out_len);

    /* Message 3: HELLO */
    virp_signing_key_t rkey;
    virp_key_generate(&rkey, VIRP_KEY_TYPE_RKEY);
    err = virp_build_hello(buf, sizeof(buf), &out_len,
                            0x00000211, 3,
                            VIRP_NODE_HYBRID, VIRP_TIER_RED,
                            &okey, &rkey);
    if (err != VIRP_OK) {
        fprintf(stderr, "build hello: %s\n", virp_error_str(err));
        fclose(f);
        return 1;
    }
    write_msg(f, buf, out_len);
    fprintf(stderr, "[C-generate] HELLO: %zu bytes, seq=3\n", out_len);

    /* Message 4: TEARDOWN */
    err = virp_build_teardown(buf, sizeof(buf), &out_len,
                               0x00000211, 4,
                               VIRP_CHANNEL_OC,
                               "interop test teardown",
                               &okey);
    if (err != VIRP_OK) {
        fprintf(stderr, "build teardown: %s\n", virp_error_str(err));
        fclose(f);
        return 1;
    }
    write_msg(f, buf, out_len);
    fprintf(stderr, "[C-generate] TEARDOWN: %zu bytes, seq=4\n", out_len);

    fclose(f);
    fprintf(stderr, "[C-generate] Wrote 4 messages to %s\n", outfile);
    return 0;
}

static int do_validate(const char *keyfile, const char *infile)
{
    virp_signing_key_t okey;
    if (virp_key_load_file(&okey, VIRP_KEY_TYPE_OKEY, keyfile) != VIRP_OK) {
        fprintf(stderr, "Failed to load key from %s\n", keyfile);
        return 1;
    }

    FILE *f = fopen(infile, "rb");
    if (!f) { perror("fopen"); return 1; }

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t msg_len;
    int count = 0;
    int failures = 0;

    while (read_msg(f, buf, sizeof(buf), &msg_len) == 0) {
        count++;
        virp_header_t hdr;
        virp_error_t err = virp_validate_message(buf, msg_len, &okey, &hdr);
        if (err != VIRP_OK) {
            fprintf(stderr, "[C-validate] Message %d: FAIL — %s\n",
                    count, virp_error_str(err));
            failures++;
        } else {
            fprintf(stderr, "[C-validate] Message %d: OK — %s on %s, "
                    "node=0x%08x seq=%u\n",
                    count,
                    virp_msg_type_str(hdr.type),
                    virp_channel_str(hdr.channel),
                    hdr.node_id, hdr.seq_num);
        }
    }

    fclose(f);
    fprintf(stderr, "[C-validate] %d messages, %d passed, %d failed\n",
            count, count - failures, failures);

    return failures > 0 ? 1 : 0;
}

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "Usage: %s generate|validate <keyfile> <msgfile>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "generate") == 0)
        return do_generate(argv[2], argv[3]);
    else if (strcmp(argv[1], "validate") == 0)
        return do_validate(argv[2], argv[3]);
    else {
        fprintf(stderr, "Unknown mode: %s\n", argv[1]);
        return 1;
    }
}
