/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * CLI Tool — key generation, message inspection, test message building
 *
 * Usage:
 *   virp-tool keygen  <okey|rkey> <output_file>
 *   virp-tool inspect <message_file> <key_file> <okey|rkey>
 *   virp-tool build   <observation|heartbeat|proposal> [options]
 *   virp-tool hexdump <message_file>
 */

#define _POSIX_C_SOURCE 199309L

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* =========================================================================
 * Hex dump utility
 * ========================================================================= */

static void hex_dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        printf("  %04zx  ", i);

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }

        printf(" |");

        /* ASCII */
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 0x20 && c <= 0x7e) ? c : '.');
        }

        printf("|\n");
    }
}

static void print_hmac(const uint8_t hmac[VIRP_HMAC_SIZE])
{
    for (int i = 0; i < VIRP_HMAC_SIZE; i++)
        printf("%02x", hmac[i]);
}

/* =========================================================================
 * keygen — generate O-Key or R-Key
 * ========================================================================= */

static int cmd_keygen(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: virp-tool keygen <okey|rkey> <output_file>\n");
        return 1;
    }

    const char *type_str = argv[0];
    const char *path = argv[1];

    virp_key_type_t type;
    if (strcmp(type_str, "okey") == 0)
        type = VIRP_KEY_TYPE_OKEY;
    else if (strcmp(type_str, "rkey") == 0)
        type = VIRP_KEY_TYPE_RKEY;
    else {
        fprintf(stderr, "Error: key type must be 'okey' or 'rkey'\n");
        return 1;
    }

    virp_signing_key_t sk;
    virp_error_t err = virp_key_generate(&sk, type);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error generating key: %s\n", virp_error_str(err));
        return 1;
    }

    err = virp_key_save_file(&sk, path);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error saving key: %s\n", virp_error_str(err));
        virp_key_destroy(&sk);
        return 1;
    }

    printf("Generated %s-Key: %s\n",
           type == VIRP_KEY_TYPE_OKEY ? "O" : "R", path);
    printf("Fingerprint: ");
    print_hmac(sk.fingerprint);
    printf("\n");
    printf("Permissions: 0600 (owner read/write only)\n");

    virp_key_destroy(&sk);
    return 0;
}

/* =========================================================================
 * inspect — parse and display a VIRP message
 * ========================================================================= */

static int cmd_inspect(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: virp-tool inspect <message_file> <key_file> <okey|rkey>\n");
        return 1;
    }

    const char *msg_path = argv[0];
    const char *key_path = argv[1];
    const char *type_str = argv[2];

    virp_key_type_t type;
    if (strcmp(type_str, "okey") == 0)
        type = VIRP_KEY_TYPE_OKEY;
    else if (strcmp(type_str, "rkey") == 0)
        type = VIRP_KEY_TYPE_RKEY;
    else {
        fprintf(stderr, "Error: key type must be 'okey' or 'rkey'\n");
        return 1;
    }

    /* Load key */
    virp_signing_key_t sk;
    virp_error_t err = virp_key_load_file(&sk, type, key_path);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error loading key: %s\n", virp_error_str(err));
        return 1;
    }

    /* Read message file */
    FILE *f = fopen(msg_path, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open %s\n", msg_path);
        virp_key_destroy(&sk);
        return 1;
    }

    uint8_t msg[VIRP_MAX_MESSAGE_SIZE];
    size_t msg_len = fread(msg, 1, sizeof(msg), f);
    fclose(f);

    if (msg_len < VIRP_HEADER_SIZE) {
        fprintf(stderr, "Error: file too small (%zu bytes, need at least %d)\n",
                msg_len, VIRP_HEADER_SIZE);
        virp_key_destroy(&sk);
        return 1;
    }

    /* Validate */
    virp_header_t hdr;
    err = virp_validate_message(msg, msg_len, &sk, &hdr);

    printf("\n");
    printf("┌─────────────────────────────────────────────┐\n");
    printf("│           VIRP Message Inspector             │\n");
    printf("└─────────────────────────────────────────────┘\n\n");

    printf("  File:       %s (%zu bytes)\n", msg_path, msg_len);
    printf("  Version:    %d\n", hdr.version);
    printf("  Type:       0x%02x (%s)\n", hdr.type, virp_msg_type_str(hdr.type));
    printf("  Length:     %d bytes\n", hdr.length);
    printf("  Node ID:    0x%08x\n", hdr.node_id);
    printf("  Channel:    0x%02x (%s)\n", hdr.channel, virp_channel_str(hdr.channel));
    printf("  Tier:       0x%02x (%s)\n", hdr.tier, virp_tier_str(hdr.tier));
    printf("  Seq Num:    %u\n", hdr.seq_num);
    printf("  Timestamp:  %lu ns\n", (unsigned long)hdr.timestamp_ns);
    printf("  HMAC:       ");
    print_hmac(hdr.hmac);
    printf("\n");

    if (err == VIRP_OK) {
        printf("\n  Signature:  ✓ VALID\n");
    } else {
        printf("\n  Signature:  ✗ %s\n", virp_error_str(err));
    }

    /* Parse payload based on type */
    if (err == VIRP_OK && msg_len > VIRP_HEADER_SIZE) {
        const uint8_t *payload = msg + VIRP_HEADER_SIZE;
        size_t payload_len = msg_len - VIRP_HEADER_SIZE;

        printf("\n  --- Payload ---\n");

        switch (hdr.type) {
        case VIRP_MSG_OBSERVATION: {
            virp_observation_t obs;
            const uint8_t *data;
            uint16_t data_len;
            if (virp_parse_observation(payload, payload_len,
                                       &obs, &data, &data_len) == VIRP_OK) {
                printf("  Obs Type:   0x%02x (%s)\n", obs.obs_type,
                       virp_obs_type_str(obs.obs_type));
                printf("  Scope:      0x%02x\n", obs.obs_scope);
                printf("  Data Len:   %u bytes\n", data_len);
                if (data && data_len > 0) {
                    printf("  Data:\n");
                    hex_dump(data, data_len);
                }
            }
            break;
        }
        case VIRP_MSG_HEARTBEAT: {
            virp_heartbeat_t hb;
            if (virp_parse_heartbeat(payload, payload_len, &hb) == VIRP_OK) {
                printf("  Uptime:     %u seconds\n", hb.uptime_seconds);
                printf("  O-Node:     %s\n", hb.onode_ok ? "OK" : "DOWN");
                printf("  R-Node:     %s\n", hb.rnode_ok ? "OK" : "DOWN");
                printf("  Active Obs: %u\n", hb.active_observations);
                printf("  Active Prop: %u\n", hb.active_proposals);
            }
            break;
        }
        case VIRP_MSG_APPROVAL: {
            virp_approval_t approval;
            if (virp_parse_approval(payload, payload_len, &approval) == VIRP_OK) {
                printf("  Proposal:   %u\n", approval.proposal_id);
                printf("  Approver:   0x%08x\n", approval.approver_node_id);
                printf("  Decision:   0x%02x\n", approval.approval_type);
                printf("  Class:      0x%02x\n", approval.approver_class);
            }
            break;
        }
        case VIRP_MSG_HELLO: {
            virp_hello_t hello;
            if (virp_parse_hello(payload, payload_len, &hello) == VIRP_OK) {
                printf("  Magic:      0x%08x %s\n", hello.magic,
                       hello.magic == VIRP_MAGIC ? "(VIRP)" : "(INVALID)");
                printf("  Node Type:  0x%02x\n", hello.node_type);
                printf("  Max Tier:   %s\n", virp_tier_str(hello.max_tier));
                printf("  O-Key FP:   ");
                print_hmac(hello.okey_fingerprint);
                printf("\n");
                printf("  R-Key FP:   ");
                print_hmac(hello.rkey_fingerprint);
                printf("\n");
            }
            break;
        }
        default:
            printf("  Raw payload:\n");
            hex_dump(payload, payload_len);
            break;
        }
    }

    printf("\n");
    virp_key_destroy(&sk);
    return (err == VIRP_OK) ? 0 : 1;
}

/* =========================================================================
 * hexdump — raw hex dump of a message file
 * ========================================================================= */

static int cmd_hexdump(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: virp-tool hexdump <message_file>\n");
        return 1;
    }

    FILE *f = fopen(argv[0], "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open %s\n", argv[0]);
        return 1;
    }

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    printf("\n  %s (%zu bytes):\n\n", argv[0], len);
    hex_dump(buf, len);
    printf("\n");

    return 0;
}

/* =========================================================================
 * build — create test messages and write to file
 * ========================================================================= */

static int cmd_build(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: virp-tool build <observation|heartbeat|proposal> [options]\n\n");
        fprintf(stderr, "  observation <key_file> <node_id_hex> <seq> <data_string> <output_file>\n");
        fprintf(stderr, "  heartbeat   <key_file> <node_id_hex> <seq> <uptime> <output_file>\n");
        fprintf(stderr, "  proposal    <rkey_file> <node_id_hex> <seq> <prop_id> <ref_node:ref_seq> <data> <output_file>\n");
        return 1;
    }

    const char *msg_type = argv[0];

    if (strcmp(msg_type, "observation") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Usage: virp-tool build observation <key_file> <node_id_hex> <seq> <data_string> <output_file>\n");
            return 1;
        }

        virp_signing_key_t okey;
        virp_error_t err = virp_key_load_file(&okey, VIRP_KEY_TYPE_OKEY, argv[1]);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error loading key: %s\n", virp_error_str(err));
            return 1;
        }

        uint32_t node_id = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t seq = (uint32_t)strtoul(argv[3], NULL, 10);
        const char *data = argv[4];
        const char *out_path = argv[5];

        uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
        size_t out_len;

        err = virp_build_observation(buf, sizeof(buf), &out_len,
                                     node_id, seq,
                                     VIRP_OBS_DEVICE_OUTPUT,
                                     VIRP_SCOPE_LOCAL,
                                     (const uint8_t *)data, (uint16_t)strlen(data),
                                     &okey);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error building observation: %s\n", virp_error_str(err));
            virp_key_destroy(&okey);
            return 1;
        }

        FILE *f = fopen(out_path, "wb");
        if (!f) {
            fprintf(stderr, "Error: cannot open %s for writing\n", out_path);
            virp_key_destroy(&okey);
            return 1;
        }
        fwrite(buf, 1, out_len, f);
        fclose(f);

        printf("Built OBSERVATION: %zu bytes → %s\n", out_len, out_path);
        printf("  Node: 0x%08x  Seq: %u  Data: %zu bytes\n",
               node_id, seq, strlen(data));

        virp_key_destroy(&okey);
        return 0;

    } else if (strcmp(msg_type, "heartbeat") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Usage: virp-tool build heartbeat <key_file> <node_id_hex> <seq> <uptime> <output_file>\n");
            return 1;
        }

        virp_signing_key_t okey;
        virp_error_t err = virp_key_load_file(&okey, VIRP_KEY_TYPE_OKEY, argv[1]);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error loading key: %s\n", virp_error_str(err));
            return 1;
        }

        uint32_t node_id = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t seq = (uint32_t)strtoul(argv[3], NULL, 10);
        uint32_t uptime = (uint32_t)strtoul(argv[4], NULL, 10);
        const char *out_path = argv[5];

        uint8_t buf[256];
        size_t out_len;

        err = virp_build_heartbeat(buf, sizeof(buf), &out_len,
                                   node_id, seq, uptime,
                                   true, true, 0, 0, &okey);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error building heartbeat: %s\n", virp_error_str(err));
            virp_key_destroy(&okey);
            return 1;
        }

        FILE *f = fopen(out_path, "wb");
        if (!f) {
            fprintf(stderr, "Error: cannot open %s for writing\n", out_path);
            virp_key_destroy(&okey);
            return 1;
        }
        fwrite(buf, 1, out_len, f);
        fclose(f);

        printf("Built HEARTBEAT: %zu bytes → %s\n", out_len, out_path);
        printf("  Node: 0x%08x  Seq: %u  Uptime: %us\n", node_id, seq, uptime);

        virp_key_destroy(&okey);
        return 0;

    } else if (strcmp(msg_type, "proposal") == 0) {
        if (argc < 8) {
            fprintf(stderr, "Usage: virp-tool build proposal <rkey_file> <node_id_hex> <seq> <prop_id> <ref_node_hex:ref_seq> <data> <output_file>\n");
            return 1;
        }

        virp_signing_key_t rkey;
        virp_error_t err = virp_key_load_file(&rkey, VIRP_KEY_TYPE_RKEY, argv[1]);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error loading key: %s\n", virp_error_str(err));
            return 1;
        }

        uint32_t node_id = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t seq = (uint32_t)strtoul(argv[3], NULL, 10);
        uint32_t prop_id = (uint32_t)strtoul(argv[4], NULL, 10);

        /* Parse ref as node_hex:seq_num */
        char ref_str[64];
        strncpy(ref_str, argv[5], sizeof(ref_str) - 1);
        ref_str[sizeof(ref_str) - 1] = '\0';

        char *colon = strchr(ref_str, ':');
        if (!colon) {
            fprintf(stderr, "Error: ref format must be node_hex:seq_num\n");
            virp_key_destroy(&rkey);
            return 1;
        }
        *colon = '\0';

        virp_obs_ref_t ref;
        ref.node_id = (uint32_t)strtoul(ref_str, NULL, 16);
        ref.seq_num = (uint32_t)strtoul(colon + 1, NULL, 10);

        const char *data = argv[6];
        const char *out_path = argv[7];

        uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
        size_t out_len;

        err = virp_build_proposal(buf, sizeof(buf), &out_len,
                                  node_id, seq, prop_id,
                                  VIRP_PROP_CONFIG_APPLY, 1,
                                  &ref, 1,
                                  (const uint8_t *)data, (uint16_t)strlen(data),
                                  &rkey);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error building proposal: %s\n", virp_error_str(err));
            virp_key_destroy(&rkey);
            return 1;
        }

        FILE *f = fopen(out_path, "wb");
        if (!f) {
            fprintf(stderr, "Error: cannot open %s for writing\n", out_path);
            virp_key_destroy(&rkey);
            return 1;
        }
        fwrite(buf, 1, out_len, f);
        fclose(f);

        printf("Built PROPOSAL: %zu bytes → %s\n", out_len, out_path);
        printf("  Node: 0x%08x  Seq: %u  PropID: %u\n", node_id, seq, prop_id);
        printf("  Evidence: node 0x%08x seq %u\n", ref.node_id, ref.seq_num);

        virp_key_destroy(&rkey);
        return 0;

    } else {
        fprintf(stderr, "Unknown message type: %s\n", msg_type);
        return 1;
    }
}

/* =========================================================================
 * Main
 * ========================================================================= */

static void usage(void)
{
    printf("\n");
    printf("VIRP Tool — Verified Infrastructure Response Protocol\n");
    printf("Copyright (c) 2026 Third Level IT LLC\n\n");
    printf("Commands:\n");
    printf("  keygen   <okey|rkey> <output_file>       Generate signing key\n");
    printf("  inspect  <msg_file> <key_file> <type>    Inspect and verify message\n");
    printf("  build    <type> [options]                 Build test message\n");
    printf("  hexdump  <msg_file>                       Raw hex dump\n");
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "keygen") == 0)
        return cmd_keygen(argc - 2, argv + 2);
    else if (strcmp(cmd, "inspect") == 0)
        return cmd_inspect(argc - 2, argv + 2);
    else if (strcmp(cmd, "build") == 0)
        return cmd_build(argc - 2, argv + 2);
    else if (strcmp(cmd, "hexdump") == 0)
        return cmd_hexdump(argc - 2, argv + 2);
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0)
        usage();
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return 1;
    }

    return 0;
}
